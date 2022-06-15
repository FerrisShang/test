#include <stdio.h>
#include <string.h>
#include "eb_smp.h"
#include "eb_smp_rand.h"
#include "eb_smp_alg.h"

#ifdef SMP_DEBUG
#define SMP_PRINT(fmt, ...) printf(fmt, ##__VA_ARGS__)
#define SMP_LOG(fmt, ...) SMP_PRINT("[SMP]"fmt, ##__VA_ARGS__)
#define SMP_DUMP(msg,d,l) \
    do { \
        SMP_PRINT("[SMP]%s: ", msg); \
        int i; \
        for (i = 0; i < l; i++) \
        { \
            if(!(i%16)&&i){ \
                SMP_PRINT("\n"); \
            } \
            SMP_PRINT("%02X ", ((uint8_t *)d)[i]); \
        } \
        SMP_PRINT("\n"); \
    } while (0)
#else
#define SMP_PRINT(fmt, ...)
#define SMP_LOG(fmt, ...)
#define SMP_DUMP(msg,d,l)
#endif

#define EB_SMP_DEF_CONN_NUM   0x4
#define EB_SMP_MAX_CONN_NUM   0x8

#define EB_SMP_INVALID_CONN_HDL 0xFFFF
#define EB_SMP_CODE_NONE  0

enum key_pending {
    KEY_NO_PENDING,
    KEY_INPUT_PENDING,  // wait for user input key(passkey/oob/yes_no)
    KEY_CFM_PENDING,
};

struct dist_pending {
    uint8_t enc        : 1;
    uint8_t master_id  : 1;
    uint8_t id_info    : 1;
    uint8_t id_addr    : 1;
};

struct eb_smp_conn {
    uint16_t conn_hdl;  // conneciton handle
    uint8_t conn_idx;
    uint8_t pending_code;
    uint8_t pending_ltk;
    uint8_t io_cap; // @ref enum smp_io_capability
    uint8_t device_role; // @ref enum smp_role
    uint8_t init_addr_type;
    uint8_t init_addr[6];
    uint8_t resp_addr_type;
    uint8_t resp_addr[6];

    uint32_t passkey;
    uint8_t tk[16];
    uint8_t local_cfm[16];
    uint8_t remote_cfm[16];
    uint8_t remote_rand[16];
    union { // not use at the same time
        uint8_t local_rand[16];
        uint8_t stk[16];
        uint8_t ltk[16];
    };
    struct smp_pairing_request pairing_req;
    struct smp_pairing_response pairing_rsp;
    uint8_t key_pending; // @ref enum key_pending
    struct dist_pending local_dist;
    struct dist_pending remote_dist;
    // secure connection
    uint8_t pka[64];
    uint8_t na[16];
    uint8_t nb[16];
};

struct eb_smp {
    void (*send)(uint16_t conn_hdl, uint8_t *data, int len, void *usr_data);
    void (*connected)(uint16_t conn_hdl, uint8_t role, void *usr_data);
    void (*disconnected)(uint16_t conn_hdl, void *usr_data);
    void (*proc)(uint16_t conn_hdl, struct smp_param *param, void *usr_data);
    void (*ltk_resp)(uint16_t conn_hdl, uint8_t *key, void *usr_data);
    void *usr_data;
    uint16_t max_connection;
    struct eb_smp_conn conn[0];
};

enum key_gen_method {
    KG_METHOD_OOB,
    KG_METHOD_JUST,
    KG_METHOD_DISP,
    KG_METHOD_INPUT,
    KG_METHOD_COMP,
};

const static uint8_t zeros[16] = {0};

// LE Legacy Mapping of IO capabilities to key generation method
const static uint8_t key_gen_map[2][5][5] = { //[Role][Initiator][Responder]
    // EB_SMP_ROLE_MASTER
    {
        {KG_METHOD_JUST, KG_METHOD_JUST, KG_METHOD_DISP, KG_METHOD_JUST, KG_METHOD_DISP},
        {KG_METHOD_JUST, KG_METHOD_JUST, KG_METHOD_DISP, KG_METHOD_JUST, KG_METHOD_DISP},
        {KG_METHOD_INPUT, KG_METHOD_INPUT, KG_METHOD_INPUT, KG_METHOD_JUST, KG_METHOD_INPUT},
        {KG_METHOD_JUST, KG_METHOD_JUST, KG_METHOD_JUST, KG_METHOD_JUST, KG_METHOD_JUST},
        {KG_METHOD_INPUT, KG_METHOD_INPUT, KG_METHOD_DISP, KG_METHOD_JUST, KG_METHOD_DISP},
    },
    // EB_SMP_ROLE_SLAVE
    {
        {KG_METHOD_JUST, KG_METHOD_JUST, KG_METHOD_INPUT, KG_METHOD_JUST, KG_METHOD_INPUT},
        {KG_METHOD_JUST, KG_METHOD_JUST, KG_METHOD_INPUT, KG_METHOD_JUST, KG_METHOD_INPUT},
        {KG_METHOD_DISP, KG_METHOD_DISP, KG_METHOD_INPUT, KG_METHOD_JUST, KG_METHOD_DISP},
        {KG_METHOD_JUST, KG_METHOD_JUST, KG_METHOD_JUST, KG_METHOD_JUST, KG_METHOD_JUST},
        {KG_METHOD_DISP, KG_METHOD_DISP, KG_METHOD_INPUT, KG_METHOD_JUST, KG_METHOD_INPUT},
    },
};

struct eb_smp *eb_smp_init(struct eb_smp_cfg *cfg, void *usr_data)
{
    EB_SMP_ASSERT(cfg);
    EB_SMP_ASSERT(cfg->send);
    EB_SMP_ASSERT(cfg->connected);
    EB_SMP_ASSERT(cfg->disconnected);
    EB_SMP_ASSERT(cfg->proc);
    EB_SMP_ASSERT(cfg->ltk_resp);
    int max_connection = cfg->max_connection ? cfg->max_connection : EB_SMP_DEF_CONN_NUM;
    max_connection = max_connection < EB_SMP_MAX_CONN_NUM ? max_connection : EB_SMP_MAX_CONN_NUM;
    struct eb_smp *smp = (struct eb_smp *)EB_SMP_MALLOC(sizeof(struct eb_smp) +
                                                        sizeof(struct eb_smp_conn) * max_connection);
    smp->send = cfg->send;
    smp->connected = cfg->connected;
    smp->disconnected = cfg->disconnected;
    smp->proc = cfg->proc;
    smp->ltk_resp = cfg->ltk_resp;
    smp->max_connection = max_connection;
    int i;
    for (i = 0; i < smp->max_connection; i++) {
        memset(&smp->conn[i], 0, sizeof(struct eb_smp_conn));
        smp->conn[i].conn_hdl = EB_SMP_INVALID_CONN_HDL;
        smp->conn[i].conn_idx = i;
    }
    return smp;
}

static struct eb_smp *eb_smp_get_by_conn(struct eb_smp_conn *conn)
{
    conn -= conn->conn_idx;
    return (struct eb_smp *)((size_t)conn - offsetof(struct eb_smp, conn));
}

static struct eb_smp_conn *eb_smp_get_by_conn_hdl(struct eb_smp *smp, uint16_t conn_hdl)
{
    int i;
    for (i = 0; i < smp->max_connection; i++) {
        if (smp->conn[i].conn_hdl == conn_hdl) {
            return &smp->conn[i];
        }
    }
    return NULL;
}

static uint8_t keygen_method(uint8_t role, struct smp_pairing_request *req, struct smp_pairing_response *rsp)
{
    if ((req->authreq & rsp->authreq & SMP_AUTH_FLAGS_SC)) {
        if (req->oob_data_flag || rsp->oob_data_flag) {
            return KG_METHOD_OOB;
        }
    } else {
        if (req->oob_data_flag && rsp->oob_data_flag) {
            return KG_METHOD_OOB;
        }
    }
    if ((req->authreq | rsp->authreq) & SMP_AUTH_FLAGS_MITM) {
        return key_gen_map[role][req->io_capability][rsp->io_capability];
    } else {
        return KG_METHOD_JUST;
    }
}

bool smp_is_pairing(struct eb_smp_conn *conn)
{
    return memcmp((uint8_t *)&conn->pairing_req, zeros, 7);
}

static void smp_error_rsp(struct eb_smp *smp, uint16_t conn_hdl, uint8_t reason)
{
    struct eb_smp_conn *conn = eb_smp_get_by_conn_hdl(smp, conn_hdl);
    if (conn) {
        conn->pending_code = EB_SMP_CODE_NONE;
        struct smp_pairing_failed pairing_failed = { SMP_PAIRING_FAILED, reason };
        smp->send(conn_hdl, (uint8_t *)&pairing_failed, sizeof(struct smp_pairing_failed), smp->usr_data);
    }
}

void eb_smp_pairing_request(struct eb_smp *smp, uint16_t conn_hdl, struct smp_pairing_request *req)
{
    // TODO
}

void eb_smp_pairing_abort(struct eb_smp *smp, uint16_t conn_hdl, uint8_t reason)
{
    smp_error_rsp(smp, conn_hdl, reason);
}

void eb_smp_pairing_response(struct eb_smp *smp, uint16_t conn_hdl, struct smp_pairing_response *rsp)
{
    struct eb_smp_conn *conn = eb_smp_get_by_conn_hdl(smp, conn_hdl);
    if (conn->device_role != EB_SMP_ROLE_SLAVE) {
        return;
    }
    if (conn && conn->pending_code == SMP_PAIRING_REQUEST) {
        // Fix parameters
        rsp->code = SMP_PAIRING_RESPONSE;
        if (rsp->maximum_encryption_key_size < 7) {
            rsp->maximum_encryption_key_size = 16;
        }
        rsp->initiator_key_distribution &= conn->pairing_req.initiator_key_distribution;
        rsp->responder_key_distribution &= conn->pairing_req.responder_key_distribution;
        rsp->responder_key_distribution &= ~(SMP_LE_KEY_DIST_SIGNKEY | SMP_LE_KEY_DIST_LINKKEY);
        // save data
        conn->pairing_rsp = *rsp;
        // send smp data
        smp->send(conn_hdl, (uint8_t *)rsp, sizeof(struct smp_pairing_response), smp->usr_data);
        uint8_t m = keygen_method(conn->device_role, &conn->pairing_req, &conn->pairing_rsp);
        const static uint8_t pending_map[5] = {
            EB_SMP_KEY_TYPE_OOB, EB_SMP_KEY_TYPE_NONE, EB_SMP_KEY_TYPE_DIS,
            EB_SMP_KEY_TYPE_PSK, EB_SMP_KEY_TYPE_YN,
        };
        m = pending_map[m];
        if (m != EB_SMP_KEY_TYPE_NONE) {
            memset(conn->tk, 0x5F, 16);
            // TODO: to uplayer.. wait for key input
        } else {
            memset(conn->tk, 0, 16);
            // do nothing.. wait for confirm value.
        }
    }
}

static bool smp_pairing_request_proc(struct eb_smp_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    struct eb_smp *smp = eb_smp_get_by_conn(conn);
    if (conn->device_role == EB_SMP_ROLE_SLAVE) {
        struct smp_pairing_request *req = (struct smp_pairing_request *)payload;
        conn->pairing_req = *req;
        if (conn->pairing_req.io_capability > KeyboardDisplay) {
            smp_error_rsp(smp, conn->conn_hdl, SMP_ERR_INVALID_PARAMETERS);
        }
        struct smp_param param = {
            .evt_id = EB_SMP_PAIRING_REQ,
            .pairing_req = req,
        };
        smp->proc(conn->conn_hdl, &param, smp->usr_data);
    }
    return true;
}

static bool smp_pairing_response_proc(struct eb_smp_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    if (conn->device_role == EB_SMP_ROLE_MASTER) {
        struct smp_pairing_response *param = (struct smp_pairing_response *)payload;
        conn->pairing_rsp = *param;
        // TODO
    }
    return true;
}

static void gen_confirm_value_cb(uint8_t *confirm_value, void *p)
{
    struct eb_smp_conn *conn = (struct eb_smp_conn *)p;
    if (conn->conn_hdl == EB_SMP_INVALID_CONN_HDL) {
        return;
    }
    if (conn->pending_code != SMP_PAIRING_CONFIRM) {
        // Unexcepted state
        return;
    }
    struct smp_pairing_confirm confirm_msg;
    confirm_msg.code = SMP_PAIRING_CONFIRM;
    memcpy(confirm_msg.value, confirm_value, 16);
    struct eb_smp *smp = eb_smp_get_by_conn(conn);
    conn->pending_code = EB_SMP_CODE_NONE;
    smp->send(conn->conn_hdl, (uint8_t *)&confirm_msg, sizeof(struct smp_pairing_confirm), smp->usr_data);
}

static void gen_pairing_rand_cb(uint8_t *rand128, void *p)
{
    struct eb_smp_conn *conn = (struct eb_smp_conn *)p;
    if (conn->conn_hdl == EB_SMP_INVALID_CONN_HDL) {
        return;
    }
    memcpy(&conn->local_rand, rand128, 16);
    smp_alg_c1(conn->tk, rand128, (uint8_t *)&conn->pairing_req, (uint8_t *)&conn->pairing_rsp,
               conn->init_addr_type, conn->resp_addr_type, conn->init_addr, conn->resp_addr,
               gen_confirm_value_cb, p);
}

static bool smp_pairing_confirm_proc(struct eb_smp_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    struct smp_pairing_confirm *param = (struct smp_pairing_confirm *)payload;
    memcpy(conn->remote_cfm, param->value, 16);
    if (conn->device_role == EB_SMP_ROLE_MASTER) {
        // TODO
    } else {
        // generate random
        memset(conn->local_rand, 0, 16);
        eb_smp_rand(gen_pairing_rand_cb, conn);
    }
    return true;
}

static void gen_stk_cb(uint8_t *stk, void *p)
{
    struct eb_smp_conn *conn = (struct eb_smp_conn *)p;
    memcpy(conn->stk, stk, 16);

    struct dist_pending init_dist = {0, 0, 0, 0};
    struct dist_pending resp_dist = {0, 0, 0, 0};;
    if (conn->pairing_rsp.initiator_key_distribution & SMP_LE_KEY_DIST_ENCKEY) {
        init_dist.enc = true;
        init_dist.master_id = true;
    }
    if (conn->pairing_rsp.initiator_key_distribution & SMP_LE_KEY_DIST_IDKEY) {
        init_dist.id_addr = true;
        init_dist.id_info = true;
    }
    if (conn->pairing_rsp.responder_key_distribution & SMP_LE_KEY_DIST_ENCKEY) {
        resp_dist.enc = true;
        resp_dist.master_id = true;
    }
    if (conn->pairing_rsp.responder_key_distribution & SMP_LE_KEY_DIST_IDKEY) {
        resp_dist.id_addr = true;
        resp_dist.id_info = true;
    }
    if (conn->device_role == EB_SMP_ROLE_MASTER) {
        conn->local_dist = init_dist;
        conn->remote_dist = resp_dist;
    } else {
        conn->local_dist = resp_dist;
        conn->remote_dist = init_dist;
    }
    if (conn->pending_ltk) {
        struct eb_smp *smp = eb_smp_get_by_conn(conn);
        smp->ltk_resp(conn->conn_hdl, conn->stk, smp->usr_data);
        conn->pending_ltk = false;
    } else {
        conn->pending_ltk = true;
    }
}

static void legacy_check_confirm_value_cb(uint8_t *confirm_value, void *p)
{
    struct eb_smp_conn *conn = (struct eb_smp_conn *)p;
    if (conn->conn_hdl == EB_SMP_INVALID_CONN_HDL) {
        return;
    }
    if (conn->pending_code != SMP_PAIRING_RANDOM) {
        // Unexcepted state
        return;
    }
    struct eb_smp *smp = eb_smp_get_by_conn(conn);
    if (!memcmp(conn->remote_cfm, confirm_value, 16)) {
        // Send Pairing Random
        struct smp_pairing_random rand_msg;
        rand_msg.code = SMP_PAIRING_RANDOM;
        memcpy(rand_msg.value, conn->local_rand, 16);
        conn->pending_code = EB_SMP_CODE_NONE;
        smp->send(conn->conn_hdl, (uint8_t *)&rand_msg, sizeof(struct smp_pairing_random), smp->usr_data);
        // Generate STK
        uint8_t *init_rand, *resp_rand;
        if (conn->device_role == EB_SMP_ROLE_MASTER) {
            init_rand = conn->local_rand;
            resp_rand = conn->remote_rand;
        } else {
            init_rand = conn->remote_rand;
            resp_rand = conn->local_rand;
        }
        smp_alg_s1(conn->tk, init_rand, resp_rand, gen_stk_cb, conn);
    } else {
        SMP_LOG("Confirm value check failed\n");
        SMP_DUMP(" REM", conn->remote_cfm, 16);
        SMP_DUMP(" CAL", confirm_value, 16);
        smp_error_rsp(smp, conn->conn_hdl, SMP_ERR_CONFIRM_VALUE_FAILED);
    }
}

static bool smp_pairing_random_proc(struct eb_smp_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    struct smp_pairing_random *param = (struct smp_pairing_random *)payload;
    if (conn->device_role == EB_SMP_ROLE_MASTER) {
        // TODO
    } else {
        memcpy(conn->remote_rand, param->value, 16);
        // check peer random & confirm value
        smp_alg_c1(conn->tk, param->value, (uint8_t *)&conn->pairing_req, (uint8_t *)&conn->pairing_rsp,
                   conn->init_addr_type, conn->resp_addr_type, conn->init_addr, conn->resp_addr,
                   legacy_check_confirm_value_cb, conn);
    }
    return true;
}

static bool smp_pairing_failed_proc(struct eb_smp_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}

static bool smp_encryption_information_proc(struct eb_smp_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return true;
}

static bool smp_central_identification_proc(struct eb_smp_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return true;
}

static bool smp_identity_information_proc(struct eb_smp_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return true;
}

static bool smp_identity_addr_info_proc(struct eb_smp_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return true;
}

static bool smp_signing_information_proc(struct eb_smp_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return true;
}

static bool smp_security_request_proc(struct eb_smp_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}

static bool smp_pairing_public_key_proc(struct eb_smp_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}

static bool smp_pairing_dhkey_check_proc(struct eb_smp_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}

static bool smp_pairing_key_notify_proc(struct eb_smp_conn *conn, const uint8_t *payload, uint16_t datalen)
{
    return false;
}

const static struct {
    uint8_t code;
    bool(*cb)(struct eb_smp_conn *conn, const uint8_t *payload, uint16_t datalen);
} smp_proc_handler[] = {
    { SMP_PAIRING_REQUEST,        smp_pairing_request_proc        },
    { SMP_PAIRING_RESPONSE,       smp_pairing_response_proc       },
    { SMP_PAIRING_CONFIRM,        smp_pairing_confirm_proc        },
    { SMP_PAIRING_RANDOM,         smp_pairing_random_proc         },
    { SMP_PAIRING_FAILED,         smp_pairing_failed_proc         },
    { SMP_ENCRYPTION_INFORMATION, smp_encryption_information_proc },
    { SMP_CENTRAL_IDENTIFICATION, smp_central_identification_proc },
    { SMP_IDENTITY_INFORMATION,   smp_identity_information_proc   },
    { SMP_IDENTITY_ADDR_INFO,     smp_identity_addr_info_proc     },
    { SMP_SIGNING_INFORMATION,    smp_signing_information_proc    },
    { SMP_SECURITY_REQUEST,       smp_security_request_proc       },
    { SMP_PAIRING_PUBLIC_KEY,     smp_pairing_public_key_proc     },
    { SMP_PAIRING_DHKEY_CHECK,    smp_pairing_dhkey_check_proc    },
    { SMP_PAIRING_KEY_NOTIFY,     smp_pairing_key_notify_proc     },
};

void eb_smp_security_req(struct eb_smp *smp, uint16_t conn_hdl, uint8_t auth)
{
    struct eb_smp_conn *conn = eb_smp_get_by_conn_hdl(smp, conn_hdl);
    if (conn) {
        struct smp_security_request param = { SMP_SECURITY_REQUEST, auth };
        smp->send(conn_hdl, (uint8_t *)&param, sizeof(struct smp_security_request), smp->usr_data);
    }
}

void eb_smpp_received(struct eb_smp *smp, uint16_t conn_hdl, uint8_t *payload, uint16_t datalen)
{
    struct smp_packet *smp_packet = (struct smp_packet *)payload;
    struct eb_smp_conn *conn = eb_smp_get_by_conn_hdl(smp, conn_hdl);
    if (conn) {
        size_t i;
        for (i = 0; i < sizeof(smp_proc_handler) / sizeof(smp_proc_handler[0]); i++) {
            if (smp_proc_handler[i].code == smp_packet->code) {
                conn->pending_code = smp_packet->code;
                if (smp_proc_handler[i].cb && smp_proc_handler[i].cb(conn, payload, datalen)) {
                    return; // processed
                }
                break;
            }
        }
        // Not support
        smp_error_rsp(smp, conn_hdl, SMP_ERR_COMMAND_NOT_SUPPORTED);
    }
}

void eb_smpp_connected(struct eb_smp *smp, uint16_t conn_hdl, uint8_t role,
                       uint8_t *peer_addr, uint8_t peer_addr_type, uint8_t *local_addr, uint8_t local_addr_type)
{
    SMP_LOG(" Connected. peer type=%d, local type=%d\n", peer_addr_type, local_addr_type);
    SMP_DUMP("  Peer addr", peer_addr, 6);
    SMP_DUMP(" Local addr", local_addr, 6);
    if (!eb_smp_get_by_conn_hdl(smp, conn_hdl)) {
        int i;
        for (i = 0; i < smp->max_connection; i++) {
            struct eb_smp_conn *conn = (struct eb_smp_conn *)&smp->conn[i];
            if (conn->conn_hdl == EB_SMP_INVALID_CONN_HDL) {
                SMP_LOG(" conn index = %d\n", i);
                memset(conn, 0, sizeof(struct eb_smp_conn));
                conn->conn_idx = i;
                conn->conn_hdl = conn_hdl;
                conn->device_role = role;
                if (role == EB_SMP_ROLE_MASTER) {
                    memcpy(conn->init_addr, local_addr, 6);
                    conn->init_addr_type = local_addr_type;
                    memcpy(conn->resp_addr, peer_addr, 6);
                    conn->resp_addr_type = peer_addr_type;
                } else {
                    memcpy(conn->init_addr, peer_addr, 6);
                    conn->init_addr_type = peer_addr_type;
                    memcpy(conn->resp_addr, local_addr, 6);
                    conn->resp_addr_type = local_addr_type;
                }
                smp->connected(conn_hdl, role, smp->usr_data);
                break;
            }
        }
    }
}

void eb_smpp_disconnected(struct eb_smp *smp, uint16_t conn_hdl)
{
    struct eb_smp_conn *conn = eb_smp_get_by_conn_hdl(smp, conn_hdl);
    SMP_LOG(" Disconnected. conn index = %d\n", conn ? conn->conn_idx : -1);
    if (conn) {
        conn->conn_hdl = EB_SMP_INVALID_CONN_HDL;
        smp->disconnected(conn_hdl, smp->usr_data);
    }
}

void eb_smpp_ltk_request(struct eb_smp *smp, uint16_t conn_hdl, uint8_t *rand, uint16_t ediv)
{
    struct eb_smp_conn *conn = eb_smp_get_by_conn_hdl(smp, conn_hdl);
    if (conn) {
        if (smp_is_pairing(conn)) {
            if (conn->pending_ltk) {
                smp->ltk_resp(conn->conn_hdl, conn->stk, smp->usr_data);
                conn->pending_ltk = false;
            } else {
                conn->pending_ltk = true;
            }
        } else {
            // TODO: master reconnection, Remote request LTK.
        }
    }
}

void eb_smpp_encrypt_changed(struct eb_smp *smp, uint16_t conn_hdl, uint8_t enabled, uint8_t key_size)
{
    struct eb_smp_conn *conn = eb_smp_get_by_conn_hdl(smp, conn_hdl);
    if (conn) {
        // TODO: send to uplayer
        if (conn->local_dist.enc) {
            conn->local_dist.enc = false;
            struct smp_encryption_information param = {
                SMP_ENCRYPTION_INFORMATION,
                {0xcd, 0x90, 0x18, 0xbd, 0xc2, 0xe3, 0xd5, 0x22, 0x79, 0xc3, 0x55, 0x4f, 0x07, 0x4b, 0xd8, 0x8d,},
            };
            smp->send(conn_hdl, (uint8_t *)&param, sizeof(struct smp_encryption_information), smp->usr_data);
        }
        if (conn->local_dist.master_id) {
            conn->local_dist.master_id = false;
            struct smp_central_identification param = {
                SMP_CENTRAL_IDENTIFICATION,
                0xf65c,
                {0x29, 0x1e, 0x19, 0x46, 0x04, 0x68, 0x52, 0xe0}
            };
            smp->send(conn_hdl, (uint8_t *)&param, sizeof(struct smp_central_identification), smp->usr_data);
        }
        if (conn->local_dist.id_info) {
            conn->local_dist.id_info = false;
            struct smp_identity_information param = {
                SMP_IDENTITY_INFORMATION,
                {0x5A, 4, 224, 1, 123, 123, 4, 12, 1, 214, 253, 3, 143, 234, 124,},
            };
            smp->send(conn_hdl, (uint8_t *)&param, sizeof(struct smp_identity_information), smp->usr_data);
        }
        if (conn->local_dist.id_addr) {
            conn->local_dist.id_addr = false;
            struct smp_identity_addr_info param = {
                SMP_IDENTITY_ADDR_INFO,
                0x01,
                {0xC0, 11, 10, 10, 11, 0xc0},
            };
            smp->send(conn_hdl, (uint8_t *)&param, sizeof(struct smp_identity_addr_info), smp->usr_data);
        }
    }
}
