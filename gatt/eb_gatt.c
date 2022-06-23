#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "eb_gatt.h"
#include "eb_att.h"
#include "eb_config_int.h"
#include "eb_memory.h"
#include "eb_debug.h"

#define EB_GATT_DEF_MTU        23
#define EB_GATT_MAX_MTU        1024

#define EB_GATT_INVALID_CONN_IDX 0xF
#define EB_GATT_ATT_OPCODE_NONE  0

#define EB_GATT_ERROR(exp, n)         EB_ERROR("[GATT] ", exp, n)
#define EB_GATT_WARNING(exp, n)       EB_WARNING("[GATT] ", exp, n)
#define EB_GATT_INFO(fmt, ...)        EB_INFO("[GATT] ", fmt, ##__VA_ARGS__)
#define EB_GATT_DUMP(msg, buf, len)   EB_DUMP("[GATT] ", msg, buf, len)

#define EB_GATT_ENV_MALLOC(size)      EB_MALLOC(size, EB_MALLOC_PRIO_CRITICAL)
#define EB_GATT_RSP_MALLOC(size)      gatt->cbs->msg_malloc(size, EB_MALLOC_PRIO_HIGH)
#define EB_GATT_REQ_MALLOC(size)      gatt->cbs->msg_malloc(size, EB_MALLOC_PRIO_MEDIUM)
#define EB_GATT_FREE(p)               gatt->cbs->msg_free(p)

#undef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#undef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))

enum req_status {
    ST_NO_RESPONSE = 0,
    ST_AUTO_RESPONSE,
    ST_PENDING_RESPONSE,
};

struct eb_gatt_conn {
    uint16_t mtu;
    uint8_t conn_idx  : 4;
    uint8_t sec_level : 4; // @ref enum eb_gatt_sec_level
    uint8_t server_pending_st : 4; // pending state @ref enum req_status
    uint8_t client_pending_st : 4; // pending state @ref enum req_status
    uint8_t server_pending_op; // pending att opcode
    uint8_t client_pending_op;
    uint16_t server_pending_hdl; // pending att handle
    uint16_t client_pending_hdl;
    uint16_t client_pending_offset; // pending gattc blob read offset
    const struct eb_att_db *custom_db;
    uint8_t *write_cache;
    uint8_t write_cache_handle;
    uint8_t write_cache_len;
};

struct eb_gatt {
    const struct eb_gatt_callbacks *cbs;
    void *default_db;
    uint16_t max_mtu;
    uint16_t max_connection;
    uint16_t max_write_cache;
    struct eb_gatt_conn conn[0];
};

struct eb_gatt *eb_gatt_init(struct eb_gatt_param *param)
{
    EB_GATT_ERROR(param, 0);
    EB_GATT_ERROR(param->cbs->send, 0);
    EB_GATT_ERROR(param->cbs->connected, 0);
    EB_GATT_ERROR(param->cbs->disconnected, 0);
    EB_GATT_ERROR(param->cbs->proc, 0);
    struct eb_gatt *gatt = EB_GATT_ENV_MALLOC(sizeof(struct eb_gatt) + param->max_connection * sizeof(struct eb_gatt_conn));
    EB_GATT_ERROR(gatt, 0);
    gatt->cbs = param->cbs;
    gatt->default_db = eb_att_db_init(param->max_serv_num);
    EB_GATT_ERROR(gatt->default_db, 0);
    gatt->max_connection = param->max_connection;
    gatt->max_mtu = param->max_mtu;
    gatt->max_write_cache = param->max_write_cache;
    int i;
    for (i = 0; i < gatt->max_connection; i++) {
        memset(&gatt->conn[i], 0, sizeof(struct eb_gatt_conn));
        gatt->conn[i].conn_idx = EB_GATT_INVALID_CONN_IDX;
        if (gatt->max_write_cache) {
            gatt->conn[i].write_cache = (uint8_t *)EB_GATT_ENV_MALLOC(gatt->max_write_cache);
            EB_GATT_ERROR(gatt->conn[i].write_cache, 0);
            memset(gatt->conn[i].write_cache, 0, gatt->max_write_cache);
        }
    }
    return gatt;
}

static struct eb_gatt *eb_gatt_get_by_conn(struct eb_gatt_conn *conn)
{
    conn -= conn->conn_idx;
    return (struct eb_gatt *)((size_t)conn - offsetof(struct eb_gatt, conn));
}

static struct eb_gatt_conn *eb_gatt_get_by_conn_idx(struct eb_gatt *gatt, uint16_t conn_idx)
{
    int i;
    for (i = 0; i < gatt->max_connection; i++) {
        if (gatt->conn[i].conn_idx == conn_idx) {
            return &gatt->conn[i];
        }
    }
    return NULL;
}

void eb_gatts_set_custom_db(struct eb_gatt *gatt, uint16_t conn_idx, const void *att_db)
{
    struct eb_gatt_conn *conn = eb_gatt_get_by_conn_idx(gatt, conn_idx);
    if (conn) {
        conn->custom_db = att_db;
    }
}

int eb_gatts_add_service(struct eb_gatt *gatt, const struct eb_att_serv *att_serv)
{
    return eb_att_db_add(gatt->default_db, att_serv);
}

uint32_t eb_gatts_pending_request(struct eb_gatt *gatt, uint16_t conn_idx)
{
    struct eb_gatt_conn *conn = eb_gatt_get_by_conn_idx(gatt, conn_idx);
    if (!conn) {
        return EB_GATT_ERR_NO_CONNECTION;
    }
    if (conn->server_pending_st == ST_AUTO_RESPONSE) {
        conn->server_pending_st = ST_PENDING_RESPONSE;
    } else {
        return EB_GATT_ERR_INVALID_STATE;
    }
    return EB_GATT_ERR_NO_ERROR;
}

static int gatt_error_rsp(struct eb_gatt *gatt, uint8_t *rsp_buf, uint16_t conn_idx, uint8_t req_code, uint16_t handle,
                          uint16_t err_code)
{
    struct att_error_rsp *rsp;
    if (rsp_buf) {
        rsp = (struct att_error_rsp *)rsp_buf;
    } else {
        rsp = EB_GATT_RSP_MALLOC(sizeof(struct att_error_rsp));
    }
    rsp->opcode = ATT_ERROR_RSP;
    rsp->req_opcode = req_code;
    rsp->handle = handle;
    rsp->error_code = err_code;
    gatt->cbs->send(conn_idx, (uint8_t *)rsp, sizeof(struct att_error_rsp), 0);
    return EB_GATT_ERR_NO_ERROR;
}

uint32_t eb_gatts_read_response(struct eb_gatt *gatt, uint16_t conn_idx, uint8_t att_state, uint8_t *data, uint16_t len)
{
    struct eb_gatt_conn *conn = eb_gatt_get_by_conn_idx(gatt, conn_idx);
    if (!conn) {
        return EB_GATT_ERR_NO_CONNECTION;
    }
    if (conn->server_pending_st != ST_NO_RESPONSE) {
        if (conn->server_pending_op != ATT_READ_REQ && conn->server_pending_op != ATT_READ_BLOB_REQ) {
            // Pending opcode not read or blob read
            EB_GATT_WARNING(0, 0);
            return EB_GATT_ERR_INVALID_STATE;
        }
        if (len > conn->mtu - sizeof(struct att_read_rsp)) {
            // Response length can NOT excceed mtu - 1
            len = conn->mtu - sizeof(struct att_read_rsp);
        }
        conn->server_pending_st = ST_NO_RESPONSE;
        if (att_state == ATT_ERR_NO_ERROR) {
            const int malloc_len = MAX(sizeof(struct att_read_rsp), sizeof(struct att_read_blob_rsp)) + len;
            struct att_packet *p = EB_GATT_REQ_MALLOC(malloc_len);
            if (!p) {
                return EB_GATT_ERR_INSUFFICIENT_RESOURCES;
            }
            int rsp_len;
            if (conn->server_pending_op == ATT_READ_REQ) {
                p->read_rsp.opcode = ATT_READ_RSP;
                memcpy(p->read_rsp.data, data, len);
                rsp_len = sizeof(struct att_read_rsp) + len;
            } else {
                p->read_blob_rsp.opcode = ATT_READ_BLOB_RSP;
                memcpy(p->read_blob_rsp.data, data, len);
                rsp_len = sizeof(struct att_read_blob_rsp) + len;
            }
            gatt->cbs->send(conn_idx, (uint8_t *)p, rsp_len, 0);
        } else {
            return gatt_error_rsp(gatt, NULL, conn_idx, conn->server_pending_op, conn->server_pending_hdl, att_state);
        }
    } else {
        // No read request pending
        return EB_GATT_ERR_INVALID_STATE;
    }
    return EB_GATT_ERR_NO_ERROR;
}

uint32_t eb_gatts_write_response(struct eb_gatt *gatt, uint16_t conn_idx, uint8_t att_state)
{
    struct eb_gatt_conn *conn = eb_gatt_get_by_conn_idx(gatt, conn_idx);
    if (!conn) {
        return EB_GATT_ERR_NO_CONNECTION;
    }
    if (conn->server_pending_st != ST_NO_RESPONSE) {
        conn->server_pending_st = ST_NO_RESPONSE;
        if (att_state == ATT_ERR_NO_ERROR) {
            uint16_t rsp_len, opcode;
            if (conn->server_pending_op == ATT_WRITE_REQ) {
                opcode = ATT_WRITE_RSP;
                rsp_len = sizeof(struct att_write_rsp);
            } else if (conn->server_pending_op == ATT_EXECUTE_WRITE_REQ) {
                opcode = ATT_EXECUTE_WRITE_RSP;
                rsp_len = sizeof(struct att_execute_write_rsp);
            } else {
                EB_GATT_WARNING(0, 0);
                return EB_GATT_ERR_UNSPEC;
            }
            struct att_write_rsp *rsp = EB_GATT_REQ_MALLOC(sizeof(struct att_write_rsp));
            rsp->opcode = opcode;
            gatt->cbs->send(conn_idx, (uint8_t *)rsp, rsp_len, 0);
        } else {
            return gatt_error_rsp(gatt, NULL, conn_idx, conn->server_pending_op, conn->server_pending_hdl, att_state);
        }
    } else {
        // No write request pending
        return EB_GATT_ERR_INVALID_STATE;
    }
    return EB_GATT_ERR_NO_ERROR;
}

uint32_t eb_gatts_send_event(struct eb_gatt *gatt, struct eb_gatts_event *evt)
{
    struct eb_gatt_conn *conn = eb_gatt_get_by_conn_idx(gatt, evt->conn_idx);
    if (!conn) {
        return EB_GATT_ERR_NO_CONNECTION;
    }
    int send_len = sizeof(struct att_handle_value_ntf) + evt->len;
    struct att_packet *att = EB_GATT_REQ_MALLOC(send_len);
    if (!att) {
        return EB_GATT_ERR_INSUFFICIENT_RESOURCES;
    }
    att->opcode = evt->type != EB_GATT_NOTIFY ? ATT_HANDLE_VALUE_NTF : ATT_HANDLE_VALUE_IND;
    att->handle_value_ntf.handle = evt->att_hdl;
    memcpy(att->handle_value_ntf.data, evt->data, evt->len);
    gatt->cbs->send(evt->conn_idx, (uint8_t *)att, send_len, (evt->seq_num & ACL_SEQ_NUM_MASK) | GATT_SEQ_NUM_BASE);
    return EB_GATT_ERR_NO_ERROR;
}

uint32_t eb_gattc_mtu_req(struct eb_gatt *gatt, uint16_t conn_idx)
{
    struct eb_gatt_conn *conn = eb_gatt_get_by_conn_idx(gatt, conn_idx);
    if (!conn) {
        return EB_GATT_ERR_NO_CONNECTION;
    }
    struct att_exchange_mtu_req *att = EB_GATT_REQ_MALLOC(sizeof(struct att_exchange_mtu_req));
    att->opcode = ATT_EXCHANGE_MTU_REQ;
    att->mtu = gatt->max_mtu;
    gatt->cbs->send(conn_idx, (uint8_t *)att, sizeof(struct att_exchange_mtu_req), 0);
    return EB_GATT_ERR_NO_ERROR;
}

uint32_t eb_gattc_find_service(struct eb_gatt *gatt, uint16_t conn_idx, uint16_t start_handl, uint16_t end_handle,
                               struct eb_uuid *uuid)
{
    struct eb_gatt_conn *conn = eb_gatt_get_by_conn_idx(gatt, conn_idx);
    if (!conn) {
        return EB_GATT_ERR_NO_CONNECTION;
    }
    return EB_GATT_ERR_NO_ERROR;
    return EB_GATT_ERR_NO_CONNECTION;
}

uint32_t eb_gattc_find_characteristic(struct eb_gatt *gatt, uint16_t conn_idx, uint16_t start_handl,
                                      uint16_t end_handle,
                                      struct eb_uuid *uuid)
{
    struct eb_gatt_conn *conn = eb_gatt_get_by_conn_idx(gatt, conn_idx);
    if (!conn) {
        return EB_GATT_ERR_NO_CONNECTION;
    }
    return EB_GATT_ERR_NO_ERROR;
    return EB_GATT_ERR_NO_CONNECTION;
}

uint32_t eb_gattc_find_descriptor(struct eb_gatt *gatt, uint16_t conn_idx, uint16_t start_handl, uint16_t end_handle)
{
    struct eb_gatt_conn *conn = eb_gatt_get_by_conn_idx(gatt, conn_idx);
    if (!conn) {
        return EB_GATT_ERR_NO_CONNECTION;
    }
    return EB_GATT_ERR_NO_ERROR;
    return EB_GATT_ERR_NO_CONNECTION;
}

uint32_t eb_gattc_read(struct eb_gatt *gatt, uint16_t conn_idx, uint16_t att_hdl, uint16_t offset)
{
    struct eb_gatt_conn *conn = eb_gatt_get_by_conn_idx(gatt, conn_idx);
    if (!conn) {
        return EB_GATT_ERR_NO_CONNECTION;
    }
    return EB_GATT_ERR_NO_ERROR;
    return EB_GATT_ERR_NO_CONNECTION;
}

uint32_t eb_gattc_write(struct eb_gatt *gatt, uint16_t conn_idx, uint16_t att_hdl, uint8_t type, const uint8_t *data,
                        int len)
{
    struct eb_gatt_conn *conn = eb_gatt_get_by_conn_idx(gatt, conn_idx);
    if (!conn) {
        return EB_GATT_ERR_NO_CONNECTION;
    }
    // TODO: gatt->cbs->send(evt->conn_idx, data, sizeof(struct att_handle_value_ntf) + evt->len, (evt->seq_num & ACL_SEQ_NUM_MASK) | GATT_SEQ_NUM_BASE);
    return EB_GATT_ERR_NO_ERROR;
    return EB_GATT_ERR_NO_CONNECTION;
}

uint32_t eb_gattc_ind_cfm(struct eb_gatt *gatt, uint16_t conn_idx, uint16_t att_hdl)
{
    struct eb_gatt_conn *conn = eb_gatt_get_by_conn_idx(gatt, conn_idx);
    if (!conn) {
        return EB_GATT_ERR_NO_CONNECTION;
    }
    return EB_GATT_ERR_NO_ERROR;
    return EB_GATT_ERR_NO_CONNECTION;
}

static bool att_error_rsp_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    // TODO
    return false;
}
static bool att_exchange_mtu_req_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    struct eb_gatt *gatt = eb_gatt_get_by_conn(conn);
    struct att_exchange_mtu_rsp *rsp = EB_GATT_RSP_MALLOC(sizeof(struct att_exchange_mtu_rsp));
    if (!rsp) {
        EB_GATT_WARNING(rsp, 0);
        return false;
    }
    struct att_exchange_mtu_req *req = (struct att_exchange_mtu_req *)payload;
    rsp->mtu = gatt->max_mtu;
    rsp->opcode = ATT_EXCHANGE_MTU_RSP;
    gatt->cbs->send(conn->conn_idx, (uint8_t *)rsp, sizeof(struct att_exchange_mtu_rsp), 0);
    conn->mtu = MIN(rsp->mtu, req->mtu);
    struct gatt_param param = {
        .evt_id = EB_GATT_MTU_CHANGED_IND,
        .status = ATT_ERR_NO_ERROR,
        .mtu_changed.mtu = conn->mtu,
    };
    gatt->cbs->proc(conn->conn_idx, &param);
    return true;
}
static bool att_exchange_mtu_rsp_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    struct att_packet *rsp_att = (struct att_packet *)payload;
    struct eb_gatt *gatt = eb_gatt_get_by_conn(conn);
    conn->mtu = MIN(gatt->max_mtu, rsp_att->exchange_mtu_rsp.mtu);
    struct gatt_param param = {
        .evt_id = EB_GATT_MTU_CHANGED_IND,
        .status = ATT_ERR_NO_ERROR,
        .mtu_changed.mtu = conn->mtu,
    };
    gatt->cbs->proc(conn->conn_idx, &param);
    return true;
}
static int gatt_find_info_req_cb(uint16_t handle, const struct eb_att_serv *serv, const struct eb_att_item *item,
                                 void *usr_data)
{
    if (!item) {
        return EB_ATT_SEARCH_CONTINUE;
    }
    struct {
        struct att_find_information_req *req;
        struct att_find_information_rsp *rsp;
        uint16_t mtu;
        uint16_t data_len;
    } *p = usr_data;
    struct att_find_information_rsp *rsp = p->rsp;
    if (handle > p->req->end_handle) {
        return EB_ATT_SEARCH_EXIT;
    }
    if (rsp->format == 0xFF) {
        rsp->format = item->uuid->uuid_len == 2 ? ATT_FORMAT_16_BIT_UUID : ATT_FORMAT_128_BIT_UUID;
    }
    int info_len = rsp->format == ATT_FORMAT_16_BIT_UUID ? 4 : 20;
    if (info_len == sizeof(uint16_t) + item->uuid->uuid_len) { // handle + length of uuid
        uint8_t *d = (uint8_t *)rsp->info_16bit + info_len * (p->data_len / info_len);
        *d++ = (handle >> 0) & 0xFF;
        *d++ = (handle >> 8) & 0xFF;
        memcpy(d, item->uuid->uuid, item->uuid->uuid_len);
        p->data_len += info_len;
    } else {
        return EB_ATT_SEARCH_EXIT;
    }
    if (p->data_len + info_len > p->mtu) {
        return EB_ATT_SEARCH_EXIT;
    }
    return EB_ATT_SEARCH_CONTINUE;
}
static bool att_find_information_req_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    struct eb_gatt *gatt = eb_gatt_get_by_conn(conn);
    struct att_find_information_rsp *rsp = EB_GATT_RSP_MALLOC(conn->mtu);
    if (!rsp) {
        EB_GATT_WARNING(rsp, 0);
        return false;
    }
    struct {
        struct att_find_information_req *req;
        struct att_find_information_rsp *rsp;
        uint16_t mtu;
        uint16_t data_len;
    } p = { (struct att_find_information_req *)payload, rsp, conn->mtu, 2, };
    struct att_packet *att = (struct att_packet *)payload;
    rsp->opcode = ATT_FIND_INFORMATION_RSP;
    rsp->format = 0xFF; // mark as known length of uuid
    eb_att_db_iter(conn->custom_db, att->find_information_req.start_handle, gatt_find_info_req_cb, &p);
    if (p.data_len > 2) {
        gatt->cbs->send(conn->conn_idx, (uint8_t *)p.rsp, p.data_len, 0);
    } else {
        gatt_error_rsp(gatt, (uint8_t *)rsp, conn->conn_idx, ATT_FIND_INFORMATION_REQ,
                              att->find_information_req.start_handle, ATT_ERR_ATTRIBUTE_NOT_FOUND);
    }
    return true;
}
static bool att_find_information_rsp_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}
static bool att_find_by_type_value_req_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}
static bool att_find_by_type_value_rsp_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}
static int gatt_read_by_type_req_cb(uint16_t handle, const struct eb_att_serv *serv, const struct eb_att_item *item,
                                    void *usr_data)
{
    struct {
        struct att_read_by_type_req *req;
        struct att_read_by_type_rsp *rsp;
        uint16_t mtu;
        uint16_t data_len;
        int req_uuid_len;
    } *p = usr_data;
    struct att_read_by_type_rsp *rsp = p->rsp;
    if (handle > p->req->end_handle) {
        return EB_ATT_SEARCH_EXIT;
    }
    if (item && p->req_uuid_len == item->uuid->uuid_len && !memcmp(item->uuid->uuid, p->req->uuid, p->req_uuid_len)) {
        if (!EB_UUID_CMP(item->uuid, &eb_att_incl_def)) {
            // TODO
            return EB_ATT_SEARCH_EXIT;
        } else if (!EB_UUID_CMP(item->uuid, &eb_att_char_def)) {
            const struct eb_uuid *value_uuid = (item + 1)->uuid;
            if (rsp->length == 0) {
                rsp->length = 5 + value_uuid->uuid_len;
            }
            if (rsp->length == 5 + value_uuid->uuid_len) {
                uint8_t *d = rsp->data + rsp->length * (p->data_len / rsp->length);
                *d++ = (handle >> 0) & 0xFF;
                *d++ = (handle >> 8) & 0xFF;
                *d++ = (item + 1)->att_prop;
                *d++ = ((handle + 1) >> 0) & 0xFF;
                *d++ = ((handle + 1) >> 8) & 0xFF;
                memcpy(d, value_uuid->uuid, value_uuid->uuid_len);
                p->data_len += rsp->length;
            } else {
                return EB_ATT_SEARCH_EXIT;
            }
            if (p->data_len + rsp->length > p->mtu) {
                return EB_ATT_SEARCH_EXIT;
            }
        } else {
            // TODO: read data
            return EB_ATT_SEARCH_EXIT;
        }
    }
    return EB_ATT_SEARCH_CONTINUE;
}
static bool att_read_by_type_req_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    struct eb_gatt *gatt = eb_gatt_get_by_conn(conn);
    struct att_read_by_type_rsp *rsp = EB_GATT_RSP_MALLOC(conn->mtu);
    if (!rsp) {
        EB_GATT_WARNING(rsp, 0);
        return false;
    }
    struct att_read_by_type_req *req = (struct att_read_by_type_req *)payload;
    struct {
        struct att_read_by_type_req *req;
        struct att_read_by_type_rsp *rsp;
        uint16_t mtu;
        uint16_t data_len;
        int req_uuid_len;
    } p = {
        req, rsp, conn->mtu, 2, datalen - offsetof(struct att_read_by_type_req, uuid),
    };
    rsp->opcode = ATT_READ_BY_TYPE_RSP;
    rsp->length = 0;
    eb_att_db_iter(conn->custom_db, req->start_handle, gatt_read_by_type_req_cb, &p);

    if (p.data_len > 2) {
        gatt->cbs->send(conn->conn_idx, (uint8_t *)rsp, p.data_len, 0);
    } else {
        gatt_error_rsp(gatt, (uint8_t *)rsp, conn->conn_idx, ATT_READ_BY_TYPE_REQ,
                              req->start_handle, ATT_ERR_ATTRIBUTE_NOT_FOUND);
    }
    return true;
}
static bool att_read_by_type_rsp_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}

static uint8_t gatt_perm_check(const struct eb_gatt_conn *conn, const struct eb_att_item *item, uint8_t req_opcode)
{
    if (!item && req_opcode != ATT_READ_REQ) {
        return ATT_ERR_READ_NOT_PERMITTED;
    }
    if (ATT_FIND_BY_TYPE_VALUE_REQ <= req_opcode && req_opcode <= ATT_READ_MULTIPLE_REQ && !(req_opcode & 1)) {
        // ATT_FIND_BY_TYPE_VALUE_REQ, ATT_READ_BY_TYPE_REQ, ATT_READ_REQ, ATT_READ_BLOB_REQ, ATT_READ_MULTIPLE_REQ,
        if (!(item->att_prop & ATT_PROP_READ)) {
            return ATT_ERR_READ_NOT_PERMITTED;
        }
    } else if (ATT_WRITE_REQ <= req_opcode && req_opcode <= ATT_EXECUTE_WRITE_RSP && !(req_opcode & 1)) {
        // ATT_WRITE_REQ, ATT_PREPARE_WRITE_REQ, ATT_EXECUTE_WRITE_REQ,
        if (!(item->att_prop & ATT_PROP_WRITE)) {
            return ATT_ERR_WRITE_NOT_PERMITTED;
        }
    } else if (req_opcode == ATT_WRITE_CMD && !(item->att_prop & ATT_PROP_WRITE_CMD)) {
        // ATT_WRITE_CMD
        return ATT_ERR_WRITE_NOT_PERMITTED;
    } else if (req_opcode == ATT_SIGNED_WRITE_CMD && !(item->att_prop & ATT_PROP_WRITE_SIG)) {
        // ATT_SIGNED_WRITE_CMD
        return ATT_ERR_WRITE_NOT_PERMITTED;
    }
    if (conn->sec_level < item->att_perm_write) {
        return ATT_ERR_INSUFFICIENT_AUTHENTICATION;
    }
    return ATT_ERR_NO_ERROR;
}

static int perm_check_by_handle_cb(uint16_t handle, const struct eb_att_serv *serv, const struct eb_att_item *item,
                                   void *usr_data)
{
    struct {
        const struct eb_gatt_conn *conn;
        uint16_t req_handle;
        uint16_t req_opcode;
        uint16_t err_code;
    } *p = usr_data;
    if (handle == p->req_handle) {
        p->err_code = gatt_perm_check(p->conn, item, p->req_opcode);
    } else {
        p->err_code = ATT_ERR_ATTRIBUTE_NOT_FOUND;
    }
    return EB_ATT_SEARCH_EXIT;
}
static uint8_t gatt_perm_check_by_handle(const struct eb_gatt_conn *conn, uint16_t att_hdl, uint8_t req_opcode)
{
    struct {
        const struct eb_gatt_conn *conn;
        uint16_t req_handle;
        uint16_t req_opcode;
        uint16_t err_code;
    } p = { conn, att_hdl, req_opcode, ATT_ERR_NO_ERROR };
    eb_att_db_iter(conn->custom_db, att_hdl, perm_check_by_handle_cb, &p);
    return p.err_code;
}

static int gatt_read_req_cb(uint16_t handle, const struct eb_att_serv *serv, const struct eb_att_item *item,
                            void *usr_data)
{
    struct {
        struct eb_gatt *gatt;
        struct eb_gatt_conn *conn;
        struct att_packet *att;
        uint16_t conn_idx;
    } *p = usr_data;
    uint16_t req_handle, req_offset;
    if (p->att->opcode == ATT_READ_BLOB_REQ) {
        req_handle = p->att->read_blob_req.handle;
        req_offset = p->att->read_blob_req.offset;
    } else {
        req_handle = p->att->read_req.handle;
        req_offset = 0;
    }
    if (handle == req_handle) {
        // check permission
        uint8_t err = gatt_perm_check(p->conn, item, p->att->opcode);
        if (err != ATT_ERR_NO_ERROR) {
            gatt_error_rsp(p->gatt, NULL, p->conn_idx, p->att->opcode, req_handle, err);
            return EB_ATT_SEARCH_EXIT;
        }
        if (p->conn->server_pending_st != ST_NO_RESPONSE) {
            // GATT client request when other opcode pending !
            EB_GATT_WARNING(0, 0);
        }
        p->conn->server_pending_st = ST_AUTO_RESPONSE;
        p->conn->server_pending_op = p->att->opcode;
        p->conn->server_pending_hdl = req_handle;
        struct gatt_param param = {
            .evt_id = EB_GATTS_READ_REQ,
            .status = ATT_ERR_NO_ERROR,
            .read_req.att_hdl = req_handle,
            .read_req.offset = req_offset,
        };
        // Up layer callback..
        p->gatt->cbs->proc(p->conn_idx, &param);
        // Check if need auto response
        if (p->conn->server_pending_st == ST_AUTO_RESPONSE) {
            if (0) {
                // TODO: response service & characterisic & ...
            } else {
                eb_gatts_read_response(p->gatt, p->conn_idx, ATT_ERR_NO_ERROR, NULL, 0);
            }
        }
    } else {
        gatt_error_rsp(p->gatt, NULL, p->conn_idx, p->att->opcode, req_handle, ATT_ERR_ATTRIBUTE_NOT_FOUND);
    }
    return EB_ATT_SEARCH_EXIT;
}
static bool att_read_req_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    struct att_packet *att = (struct att_packet *)payload;
    struct eb_gatt *gatt = eb_gatt_get_by_conn(conn);
    struct {
        struct eb_gatt *gatt;
        struct eb_gatt_conn *conn;
        struct att_packet *att;
        uint16_t conn_idx;
    } p = { gatt, conn, att, conn->conn_idx };
    eb_att_db_iter(conn->custom_db, att->read_req.handle, gatt_read_req_cb, &p);
    return true;
}
static bool att_read_rsp_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}
static bool att_read_blob_req_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    struct att_packet *att = (struct att_packet *)payload;
    struct eb_gatt *gatt = eb_gatt_get_by_conn(conn);
    struct {
        struct eb_gatt *gatt;
        struct eb_gatt_conn *conn;
        struct att_packet *att;
        uint16_t conn_idx;
    } p = { gatt, conn, att, conn->conn_idx };
    eb_att_db_iter(conn->custom_db, att->read_req.handle, gatt_read_req_cb, &p);
    return true;
}
static bool att_read_blob_rsp_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}
static bool att_read_multiple_req_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}
static bool att_read_multiple_rsp_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}
static int gatt_read_by_group_type_cb(uint16_t handle, const struct eb_att_serv *serv, const struct eb_att_item *item,
                                      void *usr_data)
{
    struct {
        struct att_read_by_group_type_req *req;
        struct att_read_by_group_type_rsp *rsp;
        uint16_t mtu;
        uint16_t data_len;
    } *p = usr_data;
    struct att_read_by_group_type_rsp *rsp = p->rsp;
    if (handle > p->req->end_handle || handle == EB_ATT_INVALID_HANDLE) {
        return EB_ATT_SEARCH_EXIT;
    }
    if (item == NULL) {
        if (rsp->length == 0xFF) {
            rsp->length = 2 * sizeof(uint16_t) + serv->serv_uuid->uuid_len;
        }
        if (rsp->length == 2 * sizeof(uint16_t) + serv->serv_uuid->uuid_len && p->data_len + rsp->length < p->mtu) {
            if (rsp->length == 20) {
                int i = p->data_len / sizeof(struct att_list_128bit);
                struct att_list_128bit *uuid = &rsp->list_128bit[i];
                uuid->start_handle = handle;
                uuid->end_handle = handle + serv->att_num;
                memcpy(uuid->uuid, serv->serv_uuid->uuid, serv->serv_uuid->uuid_len);
                p->data_len += rsp->length;
            } else if (rsp->length == 6) {
                int i = p->data_len / sizeof(struct att_list_16bit);
                struct att_list_16bit *uuid = &rsp->list_16bit[i];
                uuid->start_handle = handle;
                uuid->end_handle = handle + serv->att_num;
                memcpy(&uuid->uuid, serv->serv_uuid->uuid, serv->serv_uuid->uuid_len);
                p->data_len += rsp->length;
            }
        } else {
            return EB_ATT_SEARCH_EXIT;
        }
    }
    return EB_ATT_SEARCH_SKIP_SERV;
}
static bool att_read_by_group_type_req_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    struct eb_gatt *gatt = eb_gatt_get_by_conn(conn);
    struct att_read_by_group_type_rsp *rsp = EB_GATT_RSP_MALLOC(conn->mtu);
    if (!rsp) {
        EB_GATT_WARNING(rsp, 0);
        return false;
    }
    struct {
        struct att_read_by_group_type_req *req;
        struct att_read_by_group_type_rsp *rsp;
        uint16_t mtu;
        uint16_t data_len;
    } p = {
        (struct att_read_by_group_type_req *)payload, rsp, conn->mtu, 2,
    };
    struct att_packet *att = (struct att_packet *)payload;
    rsp->opcode = ATT_READ_BY_GROUP_TYPE_RSP;
    rsp->length = 0xFF; // mark as known length of uuid
    eb_att_db_iter(conn->custom_db, att->read_by_group_type_req.start_handle, gatt_read_by_group_type_cb, &p);
    if (p.data_len > 2) {
        gatt->cbs->send(conn->conn_idx, (uint8_t *)rsp, p.data_len, 0);
    } else {
        gatt_error_rsp(gatt, (uint8_t *)rsp, conn->conn_idx, ATT_READ_BY_GROUP_TYPE_REQ,
                       att->read_by_group_type_req.start_handle, ATT_ERR_ATTRIBUTE_NOT_FOUND);
    }
    return true;
}
static bool att_read_by_group_type_rsp_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}

static int gatt_write_req_cb(uint16_t handle, const struct eb_att_serv *serv, const struct eb_att_item *item,
                             void *usr_data)
{
    struct {
        struct eb_gatt *gatt;
        struct eb_gatt_conn *conn;
        struct att_packet *att;
        uint16_t att_pack_len;
        uint16_t conn_idx;
    } *p = usr_data;
    uint16_t req_handle = p->att->write_req.handle;
    if (handle == req_handle) {
        // check permission
        uint8_t err = gatt_perm_check(p->conn, item, p->att->opcode);
        if (err != ATT_ERR_NO_ERROR) {
            if (p->att->opcode != ATT_WRITE_CMD) {
                gatt_error_rsp(p->gatt, NULL, p->conn_idx, p->att->opcode, req_handle, err);
            }
            return EB_ATT_SEARCH_EXIT;
        }
        if (p->att->opcode == ATT_WRITE_REQ) {
            if (p->conn->server_pending_st != ST_NO_RESPONSE) {
                // GATT client request when other opcode pending !
                EB_GATT_WARNING(0, 0);
            }
            p->conn->server_pending_st = ST_AUTO_RESPONSE;
            p->conn->server_pending_op = p->att->opcode;
            p->conn->server_pending_hdl = req_handle;
        }
        struct gatt_param param = {
            .evt_id = EB_GATTS_WRITE_REQ,
            .status = ATT_ERR_NO_ERROR,
            .write_req.att_hdl = req_handle,
            .write_req.type = p->att->opcode,
            .write_req.data = p->att->write_req.value,
            .write_req.len = p->att_pack_len - sizeof(struct att_write_req),
        };
        // Up layer callback..
        p->gatt->cbs->proc(p->conn_idx, &param);
        // Check if need auto response
        if (p->conn->server_pending_st == ST_AUTO_RESPONSE) {
            EB_GATT_ERROR(p->att->opcode == ATT_WRITE_REQ, p->att->opcode);
            eb_gatts_write_response(p->gatt, p->conn_idx, ATT_ERR_NO_ERROR);
        }
    } else {
        gatt_error_rsp(p->gatt, NULL, p->conn_idx, p->att->opcode, req_handle, ATT_ERR_ATTRIBUTE_NOT_FOUND);
    }
    return EB_ATT_SEARCH_EXIT;
}
static bool att_write_req_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    struct att_packet *att = (struct att_packet *)payload;
    struct eb_gatt *gatt = eb_gatt_get_by_conn(conn);
    struct {
        struct eb_gatt *gatt;
        struct eb_gatt_conn *conn;
        struct att_packet *att;
        uint16_t att_pack_len;
        uint16_t conn_idx;
    } p = { gatt, conn, att, datalen, conn->conn_idx };
    eb_att_db_iter(conn->custom_db, att->read_req.handle, gatt_write_req_cb, &p);
    return true;
}
static bool att_write_rsp_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}
static bool att_write_cmd_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    struct att_packet *att = (struct att_packet *)payload;
    struct eb_gatt *gatt = eb_gatt_get_by_conn(conn);
    struct {
        struct eb_gatt *gatt;
        struct eb_gatt_conn *conn;
        struct att_packet *att;
        uint16_t att_pack_len;
        uint16_t conn_idx;
    } p = { gatt, conn, att, datalen, conn->conn_idx };
    eb_att_db_iter(conn->custom_db, att->read_req.handle, gatt_write_req_cb, &p);
    return true;
}
static bool att_prepare_write_req_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    struct att_prepare_write_req *req = (struct att_prepare_write_req *)payload;
    struct eb_gatt *gatt = eb_gatt_get_by_conn(conn);
    uint8_t err_code = gatt_perm_check_by_handle(conn, req->handle, ATT_PREPARE_WRITE_REQ);
    if (err_code == ATT_ERR_NO_ERROR) {
        uint16_t write_offset = req->offset;
        uint16_t write_len = datalen - sizeof(struct att_prepare_write_req);
        if (write_offset + write_len <= gatt->max_write_cache) {
            conn->write_cache_handle = req->handle;
            memcpy(&conn->write_cache[write_offset], req->value, write_len);
            conn->write_cache_len = MAX(conn->write_cache_len, write_offset + write_len);

            struct att_prepare_write_rsp *rsp = EB_GATT_RSP_MALLOC(datalen);
            if (!rsp) {
                EB_GATT_WARNING(rsp, 0);
                return false;
            }
            memcpy(rsp, payload, datalen);
            rsp->opcode = ATT_PREPARE_WRITE_RSP;
            gatt->cbs->send(conn->conn_idx, (uint8_t *)rsp, datalen, 0);
            return true;
        } else {
            // excceed max data cache length
            err_code = ATT_ERR_INVALID_ATTRIBUTE_VALUE_LENGTH;
        }
    }
    gatt_error_rsp(gatt, NULL, conn->conn_idx, req->opcode, req->handle, err_code);
    return true;
}
static bool att_prepare_write_rsp_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}
static bool att_execute_write_req_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    struct att_packet *att = (struct att_packet *)payload;
    struct eb_gatt *gatt = eb_gatt_get_by_conn(conn);
    if (conn->server_pending_st != ST_NO_RESPONSE) {
        // GATT client request when other opcode pending !
        EB_GATT_WARNING(0, 0);
    }
    conn->server_pending_st = ST_AUTO_RESPONSE;
    conn->server_pending_op = att->opcode;
    conn->server_pending_hdl = conn->write_cache_handle;
    if (att->execute_write_req.flags == ATT_EXEX_FLAGS_WRITE) {
        struct gatt_param param = {
            .evt_id = EB_GATTS_WRITE_REQ,
            .status = ATT_ERR_NO_ERROR,
            .write_req.att_hdl = conn->write_cache_handle,
            .write_req.type = att->opcode,
            .write_req.data = conn->write_cache,
            .write_req.len = conn->write_cache_len,
        };
        // Up layer callback..
        gatt->cbs->proc(conn->conn_idx, &param);
    }
    // Check if need auto response
    if (conn->server_pending_st == ST_AUTO_RESPONSE) {
        struct att_execute_write_rsp *rsp = EB_GATT_RSP_MALLOC(sizeof(struct att_execute_write_rsp));
        if (!rsp) {
            EB_GATT_WARNING(rsp, 0);
            return false;
        }
        EB_GATT_ERROR(att->opcode == ATT_EXECUTE_WRITE_REQ, att->opcode);
        rsp->opcode = ATT_EXECUTE_WRITE_RSP;
        gatt->cbs->send(conn->conn_idx, (uint8_t *)&rsp, sizeof(struct att_execute_write_rsp), 0);
        conn->server_pending_st = ST_NO_RESPONSE;
    }
    // Clear prepare write cache
    memset(conn->write_cache, 0, conn->write_cache_len);
    conn->write_cache_handle = 0x0;
    conn->write_cache_len = 0;
    return true;
}
static bool att_execute_write_rsp_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}
static bool att_read_multiple_variable_req_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}
static bool att_read_multiple_variable_rsp_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}
static bool att_multiple_handle_value_ntf_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}
static bool att_handle_value_ntf_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}
static bool att_handle_value_ind_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}
static bool att_handle_value_cfm_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}
static bool att_signed_write_cmd_proc(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}

const static struct {
    uint8_t opcode;
    bool(*cb)(struct eb_gatt_conn *conn, const uint8_t *payload, uint16_t datalen);
} att_proc_handler[] = {
    {                  ATT_ERROR_RSP,                  att_error_rsp_proc },
    {           ATT_EXCHANGE_MTU_REQ,           att_exchange_mtu_req_proc },
    {           ATT_EXCHANGE_MTU_RSP,           att_exchange_mtu_rsp_proc },
    {       ATT_FIND_INFORMATION_REQ,       att_find_information_req_proc },
    {       ATT_FIND_INFORMATION_RSP,       att_find_information_rsp_proc },
    {     ATT_FIND_BY_TYPE_VALUE_REQ,     att_find_by_type_value_req_proc },
    {     ATT_FIND_BY_TYPE_VALUE_RSP,     att_find_by_type_value_rsp_proc },
    {           ATT_READ_BY_TYPE_REQ,           att_read_by_type_req_proc },
    {           ATT_READ_BY_TYPE_RSP,           att_read_by_type_rsp_proc },
    {                   ATT_READ_REQ,                   att_read_req_proc },
    {                   ATT_READ_RSP,                   att_read_rsp_proc },
    {              ATT_READ_BLOB_REQ,              att_read_blob_req_proc },
    {              ATT_READ_BLOB_RSP,              att_read_blob_rsp_proc },
    {          ATT_READ_MULTIPLE_REQ,          att_read_multiple_req_proc },
    {          ATT_READ_MULTIPLE_RSP,          att_read_multiple_rsp_proc },
    {     ATT_READ_BY_GROUP_TYPE_REQ,     att_read_by_group_type_req_proc },
    {     ATT_READ_BY_GROUP_TYPE_RSP,     att_read_by_group_type_rsp_proc },
    {                  ATT_WRITE_REQ,                  att_write_req_proc },
    {                  ATT_WRITE_RSP,                  att_write_rsp_proc },
    {                  ATT_WRITE_CMD,                  att_write_cmd_proc },
    {          ATT_PREPARE_WRITE_REQ,          att_prepare_write_req_proc },
    {          ATT_PREPARE_WRITE_RSP,          att_prepare_write_rsp_proc },
    {          ATT_EXECUTE_WRITE_REQ,          att_execute_write_req_proc },
    {          ATT_EXECUTE_WRITE_RSP,          att_execute_write_rsp_proc },
    { ATT_READ_MULTIPLE_VARIABLE_REQ, att_read_multiple_variable_req_proc },
    { ATT_READ_MULTIPLE_VARIABLE_RSP, att_read_multiple_variable_rsp_proc },
    {  ATT_MULTIPLE_HANDLE_VALUE_NTF,  att_multiple_handle_value_ntf_proc },
    {           ATT_HANDLE_VALUE_NTF,           att_handle_value_ntf_proc },
    {           ATT_HANDLE_VALUE_IND,           att_handle_value_ind_proc },
    {           ATT_HANDLE_VALUE_CFM,           att_handle_value_cfm_proc },
    {           ATT_SIGNED_WRITE_CMD,           att_signed_write_cmd_proc },
};

void eb_pgatt_received(struct eb_gatt *gatt, uint16_t conn_idx, uint8_t *payload, uint16_t datalen)
{
    struct att_packet *att = (struct att_packet *)payload;
    struct eb_gatt_conn *conn = eb_gatt_get_by_conn_idx(gatt, conn_idx);
    if (conn) {
        size_t i;
        for (i = 0; i < sizeof(att_proc_handler) / sizeof(att_proc_handler[0]); i++) {
            if (att_proc_handler[i].opcode == att->opcode) {
                if (att_proc_handler[i].cb && att_proc_handler[i].cb(conn, payload, datalen)) {
                    return; // processed
                }
                break;
            }
        }
        // Not support
        gatt_error_rsp(gatt, NULL, conn_idx, att->opcode, 0x0000, ATT_ERR_REQUEST_NOT_SUPPORTED);
    }
}

void eb_pgatt_connected(struct eb_gatt *gatt, uint16_t conn_idx)
{
    if (!eb_gatt_get_by_conn_idx(gatt, conn_idx)) {
        int i;
        for (i = 0; i < gatt->max_connection; i++) {
            if (gatt->conn[i].conn_idx == EB_GATT_INVALID_CONN_IDX) {
                gatt->conn[i].conn_idx = conn_idx;
                gatt->conn[i].mtu = EB_GATT_DEF_MTU;
                gatt->conn[i].sec_level = EB_GATT_SEC_NO_SEC;
                gatt->conn[i].server_pending_st = ST_NO_RESPONSE;
                gatt->conn[i].server_pending_op = EB_GATT_ATT_OPCODE_NONE;
                gatt->conn[i].client_pending_op = EB_GATT_ATT_OPCODE_NONE;
                gatt->conn[i].custom_db = gatt->default_db;
                memset(gatt->conn[i].write_cache, 0, gatt->max_write_cache);
                gatt->conn[i].write_cache_handle = 0x0;
                gatt->conn[i].write_cache_len = 0;
                gatt->cbs->connected(conn_idx);
                break;
            }
        }
    }
}

void eb_pgatt_disconnected(struct eb_gatt *gatt, uint16_t conn_idx)
{
    struct eb_gatt_conn *conn = eb_gatt_get_by_conn_idx(gatt, conn_idx);
    if (conn) {
        conn->conn_idx = EB_GATT_INVALID_CONN_IDX;
        gatt->cbs->disconnected(conn_idx);
    }
}

void eb_pgatt_sec_changed(struct eb_gatt *gatt, uint16_t conn_idx, uint8_t sec_lvl)
{
    struct eb_gatt_conn *conn = eb_gatt_get_by_conn_idx(gatt, conn_idx);
    if (conn) {
        conn->sec_level = sec_lvl;
    }
}

void eb_pgatt_send_done(struct eb_gatt *gatt, uint16_t conn_idx, struct att_packet *packet, uint8_t seq_num)
{
    if (packet->opcode == ATT_HANDLE_VALUE_NTF) {
        // TODO: Notify callback
    } else if (packet->opcode == ATT_WRITE_CMD) {
        // TODO: Write command callback
    }
    EB_GATT_FREE(packet);
}

