#include <string.h>
#include "eb_l2cap.h"
#include "eb_config_int.h"
#include "eb_queue.h"

#define EB_L2CAP_INVALID_HDL    0xFF
#define EB_L2CAP_DEF_CONN_NUM   0x4
#define EB_L2CAP_MAX_CONN_NUM   0x8

#define EB_L2CAP_HANDLE_MASK 0x0FFF
#define EB_L2CAP_PB_FNFP     0x0000
#define EB_L2CAP_PB_CF       0x1000
#define EB_L2CAP_PB_FAFP     0x2000

struct eb_l2cap_cfg {
};

static const struct eb_l2cap_cfg *l2cap_cfg;

struct eb_l2cap_send_data_internal {
    struct eb_queue_item *next;
    uint8_t conn_idx;
    uint8_t seq_num;
    uint32_t reserved;
    struct eb_l2cap_send_data data;
};

/**************************************************************
 * l2cap connection block
 * @param   conn_idx              index of connection
 * @param   pending_acl_packets   还未回复num_packet_complete的acl数据包数量
 * @param   rx_buf                数据接收缓存(接收数据可能分包)
 * @param   rx_idx                已接收数据的长度
 * @param   rx_remain_len         还需要接收数据的长度
 **************************************************************/
struct eb_l2cap_conn {
    struct eb_queue_header tx_list;
    uint8_t *rx_buf;
    uint16_t rx_idx;
    uint16_t rx_remain_len;
    uint16_t tx_idx;
    uint16_t tx_len;
    uint16_t conn_hdl;
    uint8_t conn_idx;
    uint8_t pending_acl_packets;
};

/**************************************************************
 * l2cap module block
 * @param send_cb                 发送回调
 * @param proc_cb                 接收回调
 * @param connected_cb            连接回调
 * @param disconnected_cb         断开回调
 * @param acl_data_packet_length           Controller支持的ACL数据包最大长度
 * @param total_num_le_acl_data_packets    Controller支持的ACL数据包最大数量
 * @param max_connection                   该模块支持的最大连接数
 * @param num_le_acl_data_packets          当前可发送给controller的数据包数量
 * @param block_ringbuf send_ringbuf       发送循环队列
 * @param tx_buf[EB_L2CAP_SEND_BUF_LENGTH] 发送缓存区
 * @param tx_available                     上层用户还能发给l2cap的数据包数量
 * @param conn_sent_idx                    The connection index of last packet sent
 * @param eb_l2cap_conn conn[n]            连接记录 @ref struct eb_l2cap_conn
 **************************************************************/

struct eb_l2cap {
    const struct eb_l2cap_callbacks *cb;
    uint16_t acl_data_packet_length;
    uint8_t total_num_le_acl_data_packets : 4;
    uint8_t num_le_acl_data_packets       : 4;
    uint8_t max_connection                : 4;
    uint8_t conn_sent_idx                 : 4;
    uint16_t max_recv_buf_len;
    struct eb_l2cap_conn conn[0];
};

void eb_l2cap_init(void *l2cap_buf, struct eb_l2cap_param *param)
{
    struct eb_l2cap *l2cap = (struct eb_l2cap *)l2cap_buf;
    EB_L2CAP_ERROR(param, EB_L2CAP_DBG_ERR_PARAM);
    EB_L2CAP_ERROR(l2cap, EB_L2CAP_DBG_ERR_PARAM);
    memset(l2cap, 0, sizeof(struct eb_l2cap));
    l2cap->cb = param->cb;
    l2cap->acl_data_packet_length = param->acl_data_packet_length;
    l2cap->total_num_le_acl_data_packets = param->total_num_le_acl_data_packets;
    l2cap->num_le_acl_data_packets = param->total_num_le_acl_data_packets;
    l2cap->max_connection = param->max_connection;
    l2cap->max_recv_buf_len = param->max_recv_buf_len;
    // init conn rx buffer
    int i;
    for (i = 0; i < param->max_connection; i++) {
        memset(&l2cap->conn[i], 0, sizeof(struct eb_l2cap_conn));
        eb_queue_init(&l2cap->conn[i].tx_list);
        l2cap->conn[i].conn_hdl = EB_L2CAP_INVALID_HDL;
        l2cap->conn[i].rx_buf = (uint8_t *)l2cap + sizeof(struct eb_l2cap_conn) * param->max_connection +
                                i * param->max_recv_buf_len;
    }
}

int eb_l2cap_size(int max_connection, int max_recv_buf_len)
{
    return sizeof(struct eb_l2cap) + max_connection * (max_recv_buf_len + sizeof(struct eb_l2cap_conn));
}

static struct eb_l2cap_conn *get_l2cap_by_idx(void *l2cap_buf, uint8_t conn_idx)
{
    struct eb_l2cap *l2cap = (struct eb_l2cap *)l2cap_buf;
    EB_L2CAP_ERROR(l2cap, EB_L2CAP_DBG_ERR_PARAM);
    EB_L2CAP_ERROR(conn_idx < l2cap->max_connection, EB_L2CAP_DBG_ERR_PARAM);
    struct eb_l2cap_conn *conn = &l2cap->conn[conn_idx];
    if (conn->conn_hdl != EB_L2CAP_INVALID_HDL) {
        return conn;
    } else {
        return NULL;
    }
}

static struct eb_l2cap_conn *set_l2cap_by_idx(void *l2cap_buf, uint8_t conn_idx, uint16_t conn_hdl)
{
    struct eb_l2cap *l2cap = (struct eb_l2cap *)l2cap_buf;
    EB_L2CAP_ERROR(l2cap, EB_L2CAP_DBG_ERR_PARAM);
    EB_L2CAP_ERROR(conn_idx < l2cap->max_connection, EB_L2CAP_DBG_ERR_PARAM);
    struct eb_l2cap_conn *conn = &l2cap->conn[conn_idx];
    if (conn->conn_hdl == EB_L2CAP_INVALID_HDL) {
        conn->conn_hdl = conn_hdl;
        return conn;
    } else {
        return NULL;
    }
}

#define L2CAP_RSV_LEN offsetof(struct eb_l2cap_send_data_internal, data)

void eb_l2cap_send(void *l2cap_buf, struct eb_l2cap_send_data *data)
{
    struct eb_l2cap *l2cap = (struct eb_l2cap *)l2cap_buf;
    struct eb_l2cap_conn *conn = get_l2cap_by_idx(l2cap, data->conn_idx);
    if (conn) {  // save in queue;
        struct eb_l2cap_send_data_internal *int_data =
            (struct eb_l2cap_send_data_internal *)((uint8_t *)data - L2CAP_RSV_LEN);
        eb_queue_push(&conn->tx_list, (struct eb_queue_item *)int_data);
    } else {
        l2cap->cb->send_done_cb(data, EB_L2CAP_SD_NO_CONN);
    }
}

void eb_pl2cap_received(void *l2cap_buf, uint8_t conn_idx, uint16_t hdl_flags, uint16_t datalen,
                        uint8_t *payload)
{
    struct eb_l2cap *l2cap = (struct eb_l2cap *)l2cap_buf;
    EB_L2CAP_ERROR(l2cap, EB_L2CAP_DBG_ERR_PARAM);
    const int l2cap_header_len = 4; // len(LENGTH) + len(CID) = 4
    struct eb_l2cap_conn *conn = get_l2cap_by_idx(l2cap, conn_idx);
    if (conn) {
        if ((hdl_flags & EB_L2CAP_PB_FAFP) == EB_L2CAP_PB_FAFP) { // First packet
            uint16_t l2cap_len = *payload + (*(payload + 1) << 8);
            if (l2cap_len + l2cap_header_len > l2cap->max_recv_buf_len ||
                    conn->rx_idx + datalen > l2cap->max_recv_buf_len) {
                // Exceed L2cap buffer capability
                EB_L2CAP_WARNING(0, EB_L2CAP_DBG_ERR_RECV_OVERFLOW);
                return;
            }
            memcpy(conn->rx_buf, payload, datalen);
            conn->rx_idx = datalen;
            if (l2cap_len + l2cap_header_len > datalen) {
                // Data need reassemble
                conn->rx_remain_len = l2cap_len - (datalen - l2cap_header_len);
            } else {
                conn->rx_remain_len = 0;
                if (l2cap_len + l2cap_header_len < datalen) {
                    // Data too long
                    EB_L2CAP_WARNING(0, EB_L2CAP_DBG_ERR_RECV_TOO_LONG);
                }
            }
        } else if ((hdl_flags & EB_L2CAP_PB_CF) == EB_L2CAP_PB_CF) { // Continue packet
            if (conn->rx_remain_len >= datalen) {
                memcpy(&conn->rx_buf[conn->rx_idx], payload, datalen);
                conn->rx_idx += datalen;
                conn->rx_remain_len -= datalen;
            } else { // Data too long
                EB_L2CAP_WARNING(0, EB_L2CAP_DBG_ERR_RECV_OVERFLOW);
                conn->rx_idx = 0;
                conn->rx_remain_len = 0;
            }
        } else {
            // Unexpected PB flags
            EB_L2CAP_WARNING(0, EB_L2CAP_DBG_ERR_UNSPE);
        }
        if (conn->rx_remain_len == 0 && conn->rx_idx) { // Data reassembled, callback then
            uint8_t *p = conn->rx_buf;
            p += sizeof(uint16_t); // Skip ACL length
            uint16_t cid = *p + (*(p + 1) << 8);
            p += sizeof(uint16_t); // Skip CID
            l2cap->cb->proc_cb(conn_idx, cid, p, conn->rx_idx);
        }
    } else {
        // Recevie data from invalid connection
        EB_L2CAP_WARNING(0, EB_L2CAP_DBG_ERR_NO_CONN);
    }
}

void eb_pl2cap_connected(void *l2cap_buf, uint8_t conn_idx, uint16_t conn_hdl, uint8_t role,
                         uint8_t *peer_addr, uint8_t peer_addr_type, uint8_t *local_addr, uint8_t local_addr_type)
{
    struct eb_l2cap *l2cap = (struct eb_l2cap *)l2cap_buf;
    EB_L2CAP_ERROR(l2cap, EB_L2CAP_DBG_ERR_PARAM);
    struct eb_l2cap_conn *conn = set_l2cap_by_idx(l2cap, conn_idx, conn_hdl);
    EB_L2CAP_WARNING(conn, EB_L2CAP_DBG_ERR_NO_CONN);
    if (conn) {
        conn->rx_remain_len = 0;
        conn->pending_acl_packets = 0;
        l2cap->cb->connected_cb(conn_idx, role, peer_addr, peer_addr_type, local_addr, local_addr_type);
    }
}

void eb_pl2cap_disconnected(void *l2cap_buf, uint8_t conn_idx)
{
    struct eb_l2cap *l2cap = (struct eb_l2cap *)l2cap_buf;
    EB_L2CAP_ERROR(l2cap, EB_L2CAP_DBG_ERR_PARAM);
    struct eb_l2cap_conn *conn = get_l2cap_by_idx(l2cap, conn_idx);
    EB_L2CAP_WARNING(conn, EB_L2CAP_DBG_ERR_NO_CONN);
    if (conn) {
        l2cap->num_le_acl_data_packets += conn->pending_acl_packets;
        // release tx buffer
        struct eb_l2cap_send_data_internal *int_data = (struct eb_l2cap_send_data_internal *)eb_queue_pop(&conn->tx_list);
        while (int_data) {
            struct eb_l2cap_send_data *p = &int_data->data;
            int_data = (struct eb_l2cap_send_data_internal *)int_data->next;
            l2cap->cb->send_done_cb(p, EB_L2CAP_SD_DISCONNECT);
        }
        memset(conn, 0, sizeof(struct eb_l2cap_conn));
        conn->conn_hdl = EB_L2CAP_INVALID_HDL;
        l2cap->cb->disconnected_cb(conn_idx);
    }
}

void eb_pl2cap_acl_cfg(void *l2cap_buf, uint16_t pkg_size, int pkg_num)
{
    struct eb_l2cap *l2cap = (struct eb_l2cap *)l2cap_buf;
    int i;
    for (i = 0; i < l2cap->max_connection; i++) {
        EB_L2CAP_WARNING(!get_l2cap_by_idx(l2cap, i), EB_L2CAP_DBG_ERR_STATUS);
    }
    l2cap->acl_data_packet_length = pkg_size;
    l2cap->num_le_acl_data_packets = pkg_num;
    l2cap->total_num_le_acl_data_packets = pkg_num;
}

void eb_pl2cap_packets_completed(void *l2cap_buf, uint8_t conn_idx, int pkg_num)
{
    struct eb_l2cap *l2cap = (struct eb_l2cap *)l2cap_buf;
    EB_L2CAP_ERROR(l2cap, EB_L2CAP_DBG_ERR_PARAM);
    struct eb_l2cap_conn *conn = get_l2cap_by_idx(l2cap, conn_idx);
    if (conn) {
        l2cap->num_le_acl_data_packets += pkg_num;
        conn->pending_acl_packets -= pkg_num;
        if (l2cap->num_le_acl_data_packets > l2cap->total_num_le_acl_data_packets) {
            l2cap->num_le_acl_data_packets = l2cap->total_num_le_acl_data_packets;
            EB_L2CAP_WARNING(0, EB_L2CAP_DBG_ERR_PKT_CNT); // Unexpected case;
        }
        if (conn->pending_acl_packets < 0) {
            conn->pending_acl_packets = 0;
            EB_L2CAP_WARNING(0, EB_L2CAP_DBG_ERR_PKT_CNT); // Unexpected case;
        }
    } else {
        EB_L2CAP_WARNING(0, EB_L2CAP_DBG_ERR_STATUS);
    }
}

void eb_l2cap_sche_once(void *l2cap_buf)
{
    struct eb_l2cap *l2cap = (struct eb_l2cap *)l2cap_buf;
    EB_L2CAP_ERROR(l2cap, EB_L2CAP_DBG_ERR_PARAM);
    int i;
    for (i = 0; i < l2cap->max_connection; i++) {
        int idx = i + l2cap->conn_sent_idx;
        if (idx >= l2cap->max_connection) {
            idx -= l2cap->max_connection;
        }
        // struct eb_l2cap_conn *conn = &l2cap->conn[idx];
        struct eb_l2cap_conn *conn = get_l2cap_by_idx(l2cap, idx);
        int send_flag = false;
        while (l2cap->num_le_acl_data_packets) {
            if (conn) {
                struct eb_l2cap_send_data_internal *p = (struct eb_l2cap_send_data_internal *)eb_queue_peek(&conn->tx_list);
                if (p) {
                    const int l2cap_header_len = 4; // len(LENGTH) + len(CID) = 4
                    int acl_len;
                    uint16_t hdl_flags;
                    uint16_t data_send_len;
                    uint8_t *ps = p->data.payload + conn->tx_idx;
                    if (conn->tx_idx == 0) {
                        // init param
                        p->conn_idx = p->data.conn_idx;
                        p->seq_num = p->data.seq_num;

                        hdl_flags = conn->conn_hdl | EB_L2CAP_PB_FNFP;
                        conn->tx_len = p->data.length;
                        // L2CAP Header + Length of Data > ACL packet length
                        if ((l2cap_header_len + p->data.length) > l2cap->acl_data_packet_length) {
                            acl_len = l2cap->acl_data_packet_length;
                        } else {
                            acl_len = l2cap_header_len + p->data.length;
                        }
                        ps -= sizeof(uint16_t); // skip cid
                        ps -= sizeof(uint16_t); // skip l2cap length
                        data_send_len = acl_len - l2cap_header_len;
                    } else {
                        hdl_flags = conn->conn_hdl | EB_L2CAP_PB_CF;
                        if ((p->data.length - conn->tx_idx) >
                                l2cap->acl_data_packet_length) { // L2CAP Header + Length of Data > ACL packet length
                            acl_len = l2cap->acl_data_packet_length;
                        } else {
                            acl_len = p->data.length - conn->tx_idx;
                        }
                        data_send_len = acl_len - 0;
                    }
                    *--ps = (acl_len >> 8) & 0xFF;
                    *--ps = (acl_len >> 0) & 0xFF;
                    *--ps = (hdl_flags >> 8) & 0xFF;
                    *--ps = (hdl_flags >> 0) & 0xFF;
                    *--ps = 0x02; // Add ACL Mark
                    conn->tx_idx += data_send_len;
                    conn->pending_acl_packets++;
                    l2cap->num_le_acl_data_packets--;
                    // pre_len = "0x02" + size(hdl_flags) + size(acl_len) = 5
                    const int pre_len = sizeof(uint8_t) + sizeof(uint16_t) * 2;
                    l2cap->cb->send_cb(ps, pre_len + acl_len);
                    if (conn->tx_idx >= conn->tx_len) {
                        EB_L2CAP_ERROR(conn->tx_idx == conn->tx_len, EB_L2CAP_DBG_ERR_UNSPE);
                        conn->tx_idx = 0;
                        eb_queue_pop(&conn->tx_list);
                        p->data.conn_idx = p->conn_idx;
                        p->data.seq_num = p->seq_num;
                        l2cap->cb->send_done_cb(&p->data, EB_L2CAP_SD_SUCCESS);
                        send_flag = true;
                    }
                    continue;
                }
            }
            break;
        }
        if (l2cap->num_le_acl_data_packets == 0) {
            if (send_flag) {
                l2cap->conn_sent_idx = idx + 1;
                if (l2cap->conn_sent_idx >= l2cap->max_connection) {
                    l2cap->conn_sent_idx = 0;
                }
            }
            break;
        }
    }
}

void eb_l2cap_configure(const struct eb_l2cap_cfg *cfg)
{
    l2cap_cfg = cfg;
}

