#ifndef __EB_L2CAP__
#define __EB_L2CAP__

/*********************************************
 *
 *
 * 所有的conn_idx 都是 0 ~ max_conn - 1, 0xFF 表示INVALID INDEX
 *
 *
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>

#define EB_L2CAP_ERROR(exp, err)     assert(exp)
#define EB_L2CAP_WARNING(exp, err)   do{if(!(exp)){printf("[L2CAP] Warning: %s@%d\n", __func__, __LINE__);}}while(0)
#define EB_L2CAP_INFO(fmt, ...)      do{printf("[L2CAP] Info: " fmt, ##__VA_ARGS__);}while(0)

#define EB_L2CAP_CID_ATT 0x04
#define EB_L2CAP_CID_SIG 0x05
#define EB_L2CAP_CID_SMP 0x06

enum {
    EB_L2CAP_DBG_NO_ERR = 0,
    EB_L2CAP_DBG_ERR_PARAM,
    EB_L2CAP_DBG_ERR_NO_CONN,
    EB_L2CAP_DBG_ERR_UNSPE,
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

struct eb_l2cap_callbacks {
    void (*send_cb)(uint8_t *data, int len);
    void (*proc_cb)(uint8_t conn_idx, uint16_t cid, void *payload, int len);
    void (*connected_cb)(uint8_t conn_idx, uint8_t role, uint8_t *peer_addr, uint8_t peer_addr_type,
                         uint8_t *local_addr, uint8_t local_addr_type);
    void (*disconnected_cb)(uint8_t conn_idx);
    void (*free_send_pkg)(void *package);
};
struct eb_l2cap_cfg {
    const struct eb_l2cap_callbacks *cb;
    uint16_t acl_data_packet_length;
    uint8_t total_num_le_acl_data_packets : 4;
    uint8_t max_connection : 4;
    uint16_t max_recv_buf_len; // 必须4字节对齐
};
struct eb_l2cap *eb_l2cap_init(struct eb_l2cap *l2cap, struct eb_l2cap_cfg *cfg);

/*******************************************************************************
 * 返回初始化 struct eb_l2cap 结构体的长度
 * @param max_connection         max number of connection can be support
 * @param max_recv_buf_len       max buffer length for receiving, 组包后的最大长度，即MTU长度
 ******************************************************************************/
int eb_l2cap_size(int max_connection, int max_recv_buf_len);

/*******************************************************************************
 * Upper layer use this api to send data to l2cap buffer
 * @param ...
 * @return avalable number of l2cap data that upper layer can send
 ******************************************************************************/
struct eb_l2cap_send_data {
    uint8_t conn_idx;
    uint16_t cid;
    uint8_t *payload;
    int length;
    uint16_t seq_num; // 0 means no callback
};

int eb_l2cap_send(struct eb_l2cap *l2cap, struct eb_l2cap_send_data *data);


// 只能注册一次，需要静态初始化回调链表
struct eb_l2cap_send_cb {
    int num_cbs;
    void (*cbs[])(uint8_t conn_idx, uint16_t seq_num);
};
void eb_l2cap_reg_send_cb(struct eb_l2cap *l2cap, const struct eb_l2cap_send_cb *cb);


struct eb_l2cap_func {
    void (*xx)(void);
};
extern const struct eb_l2cap_func *eb_l2cap_cfg_acl_reasm_multi_link;
extern const struct eb_l2cap_func *eb_l2cap_cfg_acl_noreasm_multi_link;
extern const struct eb_l2cap_func *eb_l2cap_cfg_acl_reasm_single_link;
extern const struct eb_l2cap_func *eb_l2cap_cfg_acl_noreasm_single_link;
int eb_l2cap_func_cfg(const struct eb_l2cap_func *cfg); // select a const configuration


void eb_pl2cap_received(struct eb_l2cap *l2cap, uint16_t hdl_flags, uint16_t datalen, uint8_t *payload);
void eb_pl2cap_connected(struct eb_l2cap *l2cap, uint8_t conn_idx, uint8_t role,
                         uint8_t *peer_addr, uint8_t peer_addr_type, uint8_t *local_addr, uint8_t local_addr_type);
void eb_pl2cap_disconnected(struct eb_l2cap *l2cap, uint8_t conn_idx);
void eb_pl2cap_acl_cfg(struct eb_l2cap *l2cap, uint16_t pkg_size, int pkg_num);
void eb_pl2cap_packets_completed(struct eb_l2cap *l2cap, uint8_t conn_idx, int pkg_num);

/*******************************************************************************
 * schedule once for sending buffer data to controller
 * @param l2cap module of l2cap
 * @return avalable number of l2cap data that upper layer can send
 ******************************************************************************/
int eb_l2cap_sche_flush_once(struct eb_l2cap *l2cap);

#endif /* __EB_L2CAP__ */
