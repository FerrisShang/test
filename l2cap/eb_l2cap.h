#ifndef __EB_L2CAP__
#define __EB_L2CAP__

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include "eb_config.h"

#define EB_L2CAP_RESERVED_SIZE             16
#define EB_L2CAP_MALLOC_SIZE(payload_len)  (sizeof(struct eb_l2cap_send_data) + payload_len + EB_L2CAP_RESERVED_SIZE)
#define EB_L2CAP_ERROR(exp, err)           assert(exp)
#define EB_L2CAP_WARNING(exp, err)         do{if(!(exp)){printf("[L2CAP] Warning: %s@%d\n", __func__, __LINE__);}}while(0)
#define EB_L2CAP_INFO(fmt, ...)            do{printf("[L2CAP] Info: " fmt, ##__VA_ARGS__);}while(0)

#define EB_L2CAP_CID_ATT 0x04
#define EB_L2CAP_CID_SIG 0x05
#define EB_L2CAP_CID_SMP 0x06

enum {
    EB_L2CAP_DBG_NO_ERR = 0,
    EB_L2CAP_DBG_ERR_PARAM,
    EB_L2CAP_DBG_ERR_NO_CONN,
    EB_L2CAP_DBG_ERR_RECV_OVERFLOW,
    EB_L2CAP_DBG_ERR_RECV_TOO_LONG,
    EB_L2CAP_DBG_ERR_STATUS,
    EB_L2CAP_DBG_ERR_PKT_CNT,
    EB_L2CAP_DBG_ERR_UNSPE,
};

struct eb_l2cap_send_data {
    uint8_t conn_idx;
    uint8_t seq_num; // 0 means no callback
    uint16_t length;
    uint16_t cid;
    uint8_t payload[0];
};

enum eb_l2cap_send_done {
    EB_L2CAP_SD_SUCCESS,
    EB_L2CAP_SD_NO_CONN,
    EB_L2CAP_SD_DISCONNECT,
};

struct eb_l2cap_callbacks {
    void (*send_cb)(uint8_t *data, int len);
    void (*send_done_cb)(struct eb_l2cap_send_data *data, uint8_t status); // status @ref enum eb_l2cap_send_done
    void (*proc_cb)(uint8_t conn_idx, uint16_t cid, void *payload, int len);
    void (*connected_cb)(uint8_t conn_idx, uint8_t role, uint8_t *peer_addr, uint8_t peer_addr_type,
                         uint8_t *local_addr, uint8_t local_addr_type);
    void (*disconnected_cb)(uint8_t conn_idx);
};
struct eb_l2cap_param {
    const struct eb_l2cap_callbacks *cb;
    uint16_t acl_data_packet_length;
    uint8_t total_num_le_acl_data_packets; // 1~16
    uint8_t max_connection; // 1~16
    uint16_t max_recv_buf_len; // 必须4字节对齐
};
void eb_l2cap_init(void *l2cap, struct eb_l2cap_param *cfg);

/*******************************************************************************
 * 返回初始化 struct eb_l2cap 结构体所需的长度
 * @param max_connection         max number of connection can be support
 * @param max_recv_buf_len       max buffer length for receiving, 组包后的最大长度，即MTU长度
 ******************************************************************************/
int eb_l2cap_size(int max_connection, int max_recv_buf_len);

/*******************************************************************************
 * 发送数据
 * @data data由上层分配内存，且必须在该地址前保留12字节可写空间，
 * data在使用完成后可以在send_done_cb回调函数中释放
 ******************************************************************************/
void eb_l2cap_send(void *l2cap, struct eb_l2cap_send_data *data);

struct eb_l2cap_cfg;
extern const struct eb_l2cap_cfg *eb_l2cap_cfg_acl_reasm_multi_link;
extern const struct eb_l2cap_cfg *eb_l2cap_cfg_acl_noreasm_multi_link;
extern const struct eb_l2cap_cfg *eb_l2cap_cfg_acl_reasm_single_link;
extern const struct eb_l2cap_cfg *eb_l2cap_cfg_acl_noreasm_single_link;
void eb_l2cap_configure(const struct eb_l2cap_cfg *cfg); // select a const configuration

void eb_pl2cap_received(void *l2cap, uint8_t conn_idx, uint16_t hdl_flags, uint16_t datalen, uint8_t *payload);
void eb_pl2cap_connected(void *l2cap, uint8_t conn_idx, uint16_t conn_hdl, uint8_t role,
                         uint8_t *peer_addr, uint8_t peer_addr_type, uint8_t *local_addr, uint8_t local_addr_type);
void eb_pl2cap_disconnected(void *l2cap, uint8_t conn_idx);
void eb_pl2cap_acl_cfg(void *l2cap, uint16_t pkg_size, int pkg_num);
void eb_pl2cap_packets_completed(void *l2cap, uint8_t conn_idx, int pkg_num);

/*******************************************************************************
 * schedule once for sending buffer data to controller
 * @param l2cap module of l2cap
 ******************************************************************************/
void eb_l2cap_sche_once(void *l2cap);

#endif /* __EB_L2CAP__ */

