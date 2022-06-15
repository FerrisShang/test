#ifndef __EB_L2CAP__
#define __EB_L2CAP__

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>

#define EB_L2CAP_MALLOC  malloc
#define EB_L2CAP_FREE    free
#define EB_L2CAP_ASSERT  assert
#define EB_L2CAP_WARNING(x) do{if(!(x)){printf("[L2CAP] Warning: %s@%d\n", __func__, __LINE__);}}while(0)

#define EB_L2CAP_MAX_RECV_LENGTH 1024
#define EB_L2CAP_SEND_BUF_LENGTH 8192

#define EB_L2CAP_CID_ATT 0x04
#define EB_L2CAP_CID_SIG 0x05
#define EB_L2CAP_CID_SMP 0x06

enum {
    EB_L2CAP_AST_NO_ERR = 0,
};

struct eb_l2cap;

/*******************************************************************************
 * Structure of l2cap module
 * @param send         callback for processing data send
 * @param proc         callback for processing data received
 * @param connected    callback for processing connected, role: 0-Central, 1-Peripheral
 * @param disconnected callback for processing disconnected
 * @param acl_data_packet_length         max length of acl data in controller
 * @param total_num_le_acl_data_packets  max number of acl data in controller
 * @param max_connection                 max number of connection can be support
 ******************************************************************************/
struct eb_l2cap_cfg {
    void (*send)(uint8_t *data, int len, void *usr_data);
    void (*proc)(uint16_t conn_hdl, uint16_t cid, void *payload, int len, void *usr_data);
    void (*connected)(uint16_t conn_hdl, uint8_t role, uint8_t *peer_addr, uint8_t peer_addr_type,
                      uint8_t *local_addr, uint8_t local_addr_type, void *usr_data);
    void (*disconnected)(uint16_t conn_hdl, void *usr_data);
    int acl_data_packet_length;
    int total_num_le_acl_data_packets;
    int max_connection;
};

int eb_l2cap_size(int max_connection);
struct eb_l2cap *eb_l2cap_init(struct eb_l2cap *l2cap, struct eb_l2cap_cfg *cfg, void *usr_data);

/*******************************************************************************
 * Upper layer use this api to send data to l2cap buffer
 * @param ...
 * @return avalable number of l2cap data that upper layer can send
 ******************************************************************************/
struct eb_l2cap_send_data {
    uint16_t conn_hdl;
    uint16_t cid;
    uint8_t *payload;
    int length;
    void (*sent_cb)(void *usr_data);
    void *usr_data;
};
int eb_l2cap_send(struct eb_l2cap *l2cap, struct eb_l2cap_send_data *data);

struct eb_l2cap_func {
    void (*xx)(void);
};
int eb_l2cap_func_cfg(const struct eb_l2cap_func*cfg);

void eb_l2cap_received(struct eb_l2cap *l2cap, uint16_t hdl_flags, uint16_t datalen, uint8_t *payload);
void eb_l2cap_connected(struct eb_l2cap *l2cap, uint16_t conn_hdl, uint8_t role,
                        uint8_t *peer_addr, uint8_t peer_addr_type, uint8_t *local_addr, uint8_t local_addr_type);
void eb_l2cap_disconnected(struct eb_l2cap *l2cap, uint16_t conn_hdl);
void eb_l2cap_acl_cfg(struct eb_l2cap *l2cap, uint16_t pkg_size, int pkg_num);
void eb_l2cap_packets_completed(struct eb_l2cap *l2cap, uint16_t conn_hdl, int pkg_num);

/*******************************************************************************
 * schedule once for sending buffer data to controller
 * @param l2cap module of l2cap
 * @return avalable number of l2cap data that upper layer can send
 ******************************************************************************/
int eb_l2cap_sche_flush_once(struct eb_l2cap *l2cap);

#endif /* __EB_L2CAP__ */
