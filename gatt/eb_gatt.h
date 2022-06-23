#ifndef __EB_GATT_H__
#define __EB_GATT_H__

#include <stdint.h>
#include "eb_config.h"
#include "eb_att.h"

#define EB_GATT_INVALID_HANDLE  0x0000

enum EB_GATT_ERR {
    EB_GATT_ERR_NO_ERROR                           = 0x0000,
    EB_GATT_ERR_NO_CONNECTION                      = 0x0001,
    EB_GATT_ERR_INVALID_STATE                      = 0x0002,
    EB_GATT_ERR_INSUFFICIENT_RESOURCES             = 0x0003,
    EB_GATT_ERR_UNSPEC                             = 0x000F,

    EB_GATT_ERR_ATT_INVALID_HANDLE                 = 0x0401,
    EB_GATT_ERR_ATT_READ_NOT_PERMITTED             = 0x0402,
    EB_GATT_ERR_ATT_WRITE_NOT_PERMITTED            = 0x0403,
    EB_GATT_ERR_ATT_INVALID_PDU                    = 0x0404,
    EB_GATT_ERR_ATT_INSUFFICIENT_AUTHENTICATION    = 0x0405,
    EB_GATT_ERR_ATT_REQUEST_NOT_SUPPORTED          = 0x0406,
    EB_GATT_ERR_ATT_INVALID_OFFSET                 = 0x0407,
    EB_GATT_ERR_ATT_INSUFFICIENT_AUTHORIZATION     = 0x0408,
    EB_GATT_ERR_ATT_PREPARE_QUEUE_FULL             = 0x0409,
    EB_GATT_ERR_ATT_ATTRIBUTE_NOT_FOUND            = 0x040A,
    EB_GATT_ERR_ATT_ATTRIBUTE_NOT_LONG             = 0x040B,
    EB_GATT_ERR_ATT_ENCRYPTION_KEY_SIZE_TOO_SHORT  = 0x040C,
    EB_GATT_ERR_ATT_INVALID_ATTRIBUTE_VALUE_LENGTH = 0x040D,
    EB_GATT_ERR_ATT_UNLIKELY_ERROR                 = 0x040E,
    EB_GATT_ERR_ATT_INSUFFICIENT_ENCRYPTION        = 0x040F,
    EB_GATT_ERR_ATT_UNSUPPORTED_GROUP_TYPE         = 0x0410,
    EB_GATT_ERR_ATT_INSUFFICIENT_RESOURCES         = 0x0411,
    EB_GATT_ERR_ATT_DATABASE_OUT_OF_SYNC           = 0x0412,
    EB_GATT_ERR_ATT_VALUE_NOT_ALLOWED              = 0x0413,
};

enum eb_gatt_sec_level {
    EB_GATT_SEC_NO_SEC,
    EB_GATT_SEC_ENCRYPTED,
};

enum eb_gatt_evt_id {
    EB_GATT_MTU_CHANGED_IND,
    EB_GATTS_READ_REQ,
    EB_GATTS_WRITE_REQ,
    EB_GATTS_EVENT_RSP,

    EB_GATTC_FIND_SERV_RSP,
    EB_GATTC_FIND_CHAR_RSP,
    EB_GATTC_FIND_DESC_RSP,
    EB_GATTC_READ_RSP,
    EB_GATTC_WRITE_RSP,
    EB_GATTC_EVENT_IND,
};

struct gatt_param {
    uint8_t evt_id; // @ref enum eb_gatt_evt_id
    uint8_t status; // @ref enum att_error
    union {
        struct {
            uint8_t att_opcode; // @ref enum att_opcode
            uint8_t seq_num;
        } complete;
        struct {
            uint16_t mtu;
        } mtu_changed;
        struct {
            uint16_t att_hdl;
            uint16_t offset;
        } read_req;
        struct {
            uint16_t att_hdl;
            uint8_t type;
            uint8_t *data;
            int len;
        } write_req;
        struct {
            void *TODO;
        } find_serv_ind;
        struct {
            void *TODO;
        } find_char_ind;
        struct {
            void *TODO;
        } find_desc_ind;
        struct {
            uint16_t att_hdl;
            uint16_t offset;
            uint8_t *data;
            int len;
        } read_rsp;
    };
};

struct eb_gatt_param {
    void (*send)(uint16_t conn_idx, uint8_t *data, int len, uint8_t seq_num); // seq_num: 0~15
    void (*proc)(uint16_t conn_idx, struct gatt_param *param);
    void (*connected)(uint16_t conn_idx);
    void (*disconnected)(uint16_t conn_idx);
    void *(*send_malloc)(size_t size, uint8_t priority);
    void (*send_free)(void *p);
    void *default_db; // inited by eb_att_db_init
    uint16_t max_write_cache; // 0 means use write offset
    uint16_t max_mtu;
    uint16_t max_connection;
};

struct eb_gatt;

void *eb_gatt_init(struct eb_gatt*gatt, struct eb_gatt_param *param);

struct eb_gatt_cfg;
extern const struct eb_gatt_cfg *eb_gatt_cfg_none;
extern const struct eb_gatt_cfg *eb_gatt_cfg_client_only;
extern const struct eb_gatt_cfg *eb_gatt_cfg_server_only;
extern const struct eb_gatt_cfg *eb_gatt_cfg_server_client;
void eb_gatt_configure(const struct eb_gatt_cfg *cfg); // select a const configuration

/*******************************************************************************
 * Set custom att database, ONLY can be called in connected callback
 * @prarm    att_db       att database created by eb_att_db_init
 ******************************************************************************/
void eb_gatts_set_custom_db(struct eb_gatt*gatt, uint16_t conn_idx, const void *att_db);

/*******************************************************************************
 * Add att service to default database
 * @prarm    att_serv @ref struct eb_att_serv
 * @reutrn   start handle of the added service
 * @warning  att_serv and it's related items MUST be static variables
 ******************************************************************************/
int eb_gatts_add_service(struct eb_gatt*gatt, const struct eb_att_serv *att_serv);

/*******************************************************************************
 * Don't response the client request(etc. read, write)
 ******************************************************************************/
uint32_t eb_gatts_pending_request(struct eb_gatt *gatt, uint16_t conn_idx);

/*******************************************************************************
 * Send notify or indicate to GATT client
 * @prarm    evt  event
 ******************************************************************************/
enum eb_gatt_evt_type {
    EB_GATT_NOTIFY,
    EB_GATT_INDICATE,
};
struct eb_gatts_event {
    uint8_t type; // @ref enum eb_gatt_evt_type
    uint16_t conn_idx;
    uint16_t att_hdl;
    uint8_t *data;
    int len;
    uint8_t seq_num;
};
uint32_t eb_gatts_send_event(struct eb_gatt*gatt, struct eb_gatts_event *evt);
uint32_t eb_gatts_read_response(struct eb_gatt*gatt, uint16_t conn_idx, uint8_t att_state, uint8_t *data, uint16_t len);
uint32_t eb_gatts_write_response(struct eb_gatt*gatt, uint16_t conn_idx, uint8_t att_state);
uint32_t eb_gattc_mtu_req(struct eb_gatt*gatt, uint16_t conn_idx);
uint32_t eb_gattc_find_service(struct eb_gatt*gatt, uint16_t conn_idx, uint16_t start_handl, uint16_t end_handle,
                           struct eb_uuid *uuid);
uint32_t eb_gattc_find_characteristic(struct eb_gatt*gatt, uint16_t conn_idx, uint16_t start_handl, uint16_t end_handle,
                                  struct eb_uuid *uuid);
uint32_t eb_gattc_find_descriptor(struct eb_gatt*gatt, uint16_t conn_idx, uint16_t start_handl, uint16_t end_handle);
uint32_t eb_gattc_read(struct eb_gatt*gatt, uint16_t conn_idx, uint16_t att_hdl, uint16_t offset);
uint32_t eb_gattc_write(struct eb_gatt*gatt, uint16_t conn_idx, uint16_t att_hdl, uint8_t type, const uint8_t *data,
                    int len);
uint32_t eb_gattc_ind_cfm(struct eb_gatt*gatt, uint16_t conn_idx, uint16_t att_hdl);

// porting
void eb_pgatt_received(struct eb_gatt*gatt, uint16_t conn_idx, uint8_t *payload, uint16_t datalen);
void eb_pgatt_connected(struct eb_gatt*gatt, uint16_t conn_idx);
void eb_pgatt_disconnected(struct eb_gatt*gatt, uint16_t conn_idx);
void eb_pgatt_sec_changed(struct eb_gatt*gatt, uint16_t conn_idx, uint8_t sec_lvl);
void eb_pgatt_send_done(struct eb_gatt*gatt, uint16_t conn_idx, struct att_packet *packet, uint8_t seq_num);

#endif /* __EB_GATT_H__ */

