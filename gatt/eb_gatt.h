#ifndef __EB_GATT_H__
#define __EB_GATT_H__

#include <stdint.h>
#include "eb_config.h"
#include "eb_att.h"

#define EB_GATT_INVALID_HANDLE  0x0000

enum eb_gatt_sec_level {
    EB_GATT_SEC_NO_SEC,
    EB_GATT_SEC_ENCRYPTED,
};

enum eb_gatt_evt_id {
    EB_GATT_CMP,
    EB_GATT_MTU_CHANGED_IND,
    EB_GATTS_INDICATE_IND,
    EB_GATTS_READ_REQ,
    EB_GATTS_WRITE_REQ,
    EB_GATTC_FIND_SERV_IND,
    EB_GATTC_FIND_CHAR_IND,
    EB_GATTC_FIND_DESC_IND,
    EB_GATTC_READ_RSP,
    EB_GATTC_WRITE_RSP,
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
    void (*send)(uint16_t conn_idx, uint8_t *data, int len, void(*send_done)(void *), void *p);
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

void *eb_gatt_init(void *gatt, struct eb_gatt_param *param);
void eb_gatt_size(uint8_t max_connection, uint16_t max_service_num, uint16_t max_write_cache);

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
void eb_gatts_set_custom_db(void *gatt, uint16_t conn_idx, const void *att_db);

/*******************************************************************************
 * Add att service to default database
 * @prarm    att_serv @ref struct eb_att_serv
 * @reutrn   start handle of the added service
 * @warning  att_serv and it's related items MUST be static variables
 ******************************************************************************/
int eb_gatts_add_service(void *gatt, const struct eb_att_serv *att_serv);

/*******************************************************************************
 * Don't response the client request(etc. read, write)
 ******************************************************************************/
void eb_gatts_pending_request(void *gatt, uint16_t conn_idx);

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
void eb_gatts_send_event(void *gatt, struct eb_gatts_event *evt);
void eb_gatts_read_response(void *gatt, uint16_t conn_idx, uint8_t att_state, uint8_t *data, uint16_t len);
void eb_gatts_write_response(void *gatt, uint16_t conn_idx, uint8_t att_state);
void eb_gattc_mtu_req(void *gatt, uint16_t conn_idx);
void eb_gattc_find_service(void *gatt, uint16_t conn_idx, uint16_t start_handl, uint16_t end_handle,
                           struct eb_uuid *uuid);
void eb_gattc_find_characteristic(void *gatt, uint16_t conn_idx, uint16_t start_handl, uint16_t end_handle,
                                  struct eb_uuid *uuid);
void eb_gattc_find_descriptor(void *gatt, uint16_t conn_idx, uint16_t start_handl, uint16_t end_handle);
void eb_gattc_read(void *gatt, uint16_t conn_idx, uint16_t att_hdl, uint16_t offset);
void eb_gattc_write(void *gatt, uint16_t conn_idx, uint16_t att_hdl, uint8_t type, const uint8_t *data,
                    int len);
void eb_gattc_ind_cfm(void *gatt, uint16_t conn_idx, uint16_t att_hdl);

// porting
void eb_pgatt_received(void *gatt, uint16_t conn_idx, uint8_t *payload, uint16_t datalen);
void eb_pgatt_connected(void *gatt, uint16_t conn_idx);
void eb_pgatt_disconnected(void *gatt, uint16_t conn_idx);
void eb_pgatt_sec_changed(void *gatt, uint16_t conn_idx, uint8_t sec_lvl);

#endif /* __EB_GATT_H__ */

