#include <string.h>
#include "eb_l2cap.h"
#include "block_ringbuf.h"

#define EB_L2CAP_INVALID_HANDLE 0xFFFF
#define EB_L2CAP_DEF_CONN_NUM   0x4
#define EB_L2CAP_MAX_CONN_NUM   0x8

#define EB_L2CAP_HANDLE_MASK 0x0FFF
#define EB_L2CAP_PB_FNFP 0x0000
#define EB_L2CAP_PB_CF   0x1000
#define EB_L2CAP_PB_FAFP 0x2000

/**************************************************************
 * l2cap connection block
 * @param   conn_hdl              handle of connection
 * @param   pending_acl_packets   还未回复num_packet_complete的acl数据包数量
 * @param   rx_buf                数据接收缓存(接收数据可能分包)
 * @param   rx_len                已接收数据的长度
 * @param   rx_remain_len         还需要接收数据的长度
 **************************************************************/
struct eb_l2cap_conn {
    struct block_ringbuf send_ringbuf;
    uint8_t tx_buf[EB_L2CAP_SEND_BUF_LENGTH];
    uint8_t rx_buf[EB_L2CAP_MAX_RECV_LENGTH];
    int pending_acl_packets;
    uint16_t conn_hdl;
    uint16_t rx_len;
    uint16_t rx_remain_len;
};

/**************************************************************
 * l2cap module block
 * @param send_cb                 发送回调
 * @param proc_cb                 接收回调
 * @param connected_cb            连接回调
 * @param disconnected_cb         断开回调
 * @param usr_data                用户数据
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
    void (*send_cb)(uint8_t *data, int len, void *usr_data);
    void (*proc_cb)(uint16_t conn_hdl, uint16_t cid, void *payload, int len, void *usr_data);
    void (*connected_cb)(uint16_t conn_hdl, uint8_t role, uint8_t *peer_addr, uint8_t peer_addr_type,
                         uint8_t *local_addr, uint8_t local_addr_type, void *usr_data);
    void (*disconnected_cb)(uint16_t conn_hdl, void *usr_data);
    void *usr_data;
    int acl_data_packet_length;
    int total_num_le_acl_data_packets;
    int max_connection;
    int num_le_acl_data_packets;
    int tx_available;
    int conn_sent_idx;
    struct eb_l2cap_conn conn[0];
};

struct eb_l2cap *eb_l2cap_init(struct eb_l2cap_cfg *cfg, void *usr_data)
{
    EB_L2CAP_ASSERT(cfg);
    EB_L2CAP_ASSERT(cfg->send);
    EB_L2CAP_ASSERT(cfg->proc);
    EB_L2CAP_ASSERT(cfg->acl_data_packet_length);
    EB_L2CAP_ASSERT(cfg->total_num_le_acl_data_packets);
    int max_connection = cfg->max_connection ? cfg->max_connection : EB_L2CAP_DEF_CONN_NUM;
    max_connection = max_connection < EB_L2CAP_MAX_CONN_NUM ? max_connection : EB_L2CAP_MAX_CONN_NUM;
    struct eb_l2cap *l2cap = (struct eb_l2cap *)EB_L2CAP_MALLOC(sizeof(struct eb_l2cap) +
                                                                sizeof(struct eb_l2cap_conn) * max_connection);
    EB_L2CAP_ASSERT(l2cap);
    memset(l2cap, 0, sizeof(struct eb_l2cap));
    int i;
    for (i = 0; i < max_connection; i++) {
        l2cap->conn[i].conn_hdl = EB_L2CAP_INVALID_HANDLE;
    }
    l2cap->send_cb = cfg->send;
    l2cap->proc_cb = cfg->proc;
    l2cap->connected_cb = cfg->connected;
    l2cap->disconnected_cb = cfg->disconnected;
    l2cap->acl_data_packet_length = cfg->acl_data_packet_length;
    l2cap->total_num_le_acl_data_packets = cfg->total_num_le_acl_data_packets;
    l2cap->num_le_acl_data_packets = cfg->total_num_le_acl_data_packets;
    l2cap->tx_available = l2cap->total_num_le_acl_data_packets;
    l2cap->max_connection = cfg->max_connection ? cfg->max_connection : EB_L2CAP_DEF_CONN_NUM;
    l2cap->usr_data = usr_data;
    l2cap->conn_sent_idx = 0;
    return l2cap;
}

static struct eb_l2cap_conn *get_l2cap_by_handle(struct eb_l2cap *l2cap, uint16_t conn_hdl)
{
    EB_L2CAP_ASSERT(l2cap);
    int i;
    for (i = 0; i < l2cap->max_connection; i++) {
        if (l2cap->conn[i].conn_hdl == conn_hdl) {
            return &l2cap->conn[i];
        }
    }
    return NULL;
}

static struct eb_l2cap_conn *set_l2cap_by_handle(struct eb_l2cap *l2cap, uint16_t conn_hdl)
{
    EB_L2CAP_ASSERT(l2cap);
    int i;
    if (get_l2cap_by_handle(l2cap, conn_hdl)) {
        return NULL; // Already exist
    }
    for (i = 0; i < l2cap->max_connection; i++) {
        if (l2cap->conn[i].conn_hdl == EB_L2CAP_INVALID_HANDLE) {
            l2cap->conn[i].conn_hdl = conn_hdl;
            return &l2cap->conn[i];
        }
    }
    return NULL;
}

int eb_l2cap_send(struct eb_l2cap *l2cap, struct eb_l2cap_send_data *data)
{
    EB_L2CAP_ASSERT(l2cap);

    int l2cap_header_len = 4; // len(LENGTH) + len(CID) = 4
    int offset = 0;
    struct eb_l2cap_conn *conn = get_l2cap_by_handle(l2cap, data->conn_hdl);
    if (!conn) {
        return -1; // not connected
    }
    while (offset < data->length) {
        int acl_len;
        if (l2cap_header_len + (data->length - offset) >
                l2cap->acl_data_packet_length) { // L2CAP Header + Length of Data > ACL packet length
            acl_len = l2cap->acl_data_packet_length - l2cap_header_len;
        } else {
            acl_len = l2cap_header_len + data->length - offset;
        }
        // callback + usr_data + ACL Header + ACL Data
        int buf_len = sizeof(data->sent_cb) + sizeof(data->usr_data) + sizeof(uint16_t) * 2 + acl_len;
        uint8_t *p = block_queue_push_peek(&conn->send_ringbuf, buf_len);
        size_t *d = (size_t *)p;
        EB_L2CAP_ASSERT(p); // No buffer cause Assert
        uint16_t hdl_flags;
        if (offset == 0) {
            *d++ = (size_t)data->sent_cb;
            *d++ = (size_t)data->usr_data;
            hdl_flags = data->conn_hdl | EB_L2CAP_PB_FNFP;
        } else {
            *d++ = (size_t)NULL;
            *d++ = (size_t)0x5F5F5F5F;
            hdl_flags = data->conn_hdl | EB_L2CAP_PB_CF;
        }
        p += sizeof(data->sent_cb) + sizeof(data->usr_data);
        *p++ = (hdl_flags >> 0) & 0xFF;
        *p++ = (hdl_flags >> 8) & 0xFF;
        *p++ = (acl_len >> 0) & 0xFF;
        *p++ = (acl_len >> 8) & 0xFF;
        if (offset == 0) {
            *p++ = (data->length >> 0) & 0xFF;
            *p++ = (data->length >> 8) & 0xFF;
            *p++ = (data->cid >> 0) & 0xFF;
            *p++ = (data->cid >> 8) & 0xFF;
        }
        memcpy(p, data->payload, data->length);
        block_queue_push(&conn->send_ringbuf);
        l2cap->tx_available--;
        offset += acl_len;
    }
    return l2cap->tx_available;
}

void eb_l2cap_received(struct eb_l2cap *l2cap, uint16_t hdl_flags, uint16_t datalen, uint8_t *payload)
{
    EB_L2CAP_ASSERT(l2cap);
    const int l2cap_header_len = 4; // len(LENGTH) + len(CID) = 4
    uint16_t conn_hdl = hdl_flags & EB_L2CAP_HANDLE_MASK;
    struct eb_l2cap_conn *conn = get_l2cap_by_handle(l2cap, conn_hdl);
    if (conn) {
        if ((hdl_flags & EB_L2CAP_PB_FAFP) == EB_L2CAP_PB_FAFP) { // First packet
            uint8_t *p = payload;
            uint16_t l2cap_len = *p + (*(p + 1) << 8);
            p += sizeof(uint16_t); // Skip ACL length
            p += sizeof(uint16_t); // Skip CID
            if (l2cap_len + l2cap_header_len > EB_L2CAP_MAX_RECV_LENGTH) {
                // Exceed L2cap buffer capability
                EB_L2CAP_WARNING(0);
                return;
            }
            memcpy(conn->rx_buf, payload, datalen);
            conn->rx_len = datalen;
            if (l2cap_len + l2cap_header_len > datalen) {
                // Data need reassemble
                conn->rx_remain_len = l2cap_len - (datalen - l2cap_header_len);
            } else {
                conn->rx_remain_len = 0;
                if (l2cap_len + l2cap_header_len < datalen) {
                    // Data too long
                    EB_L2CAP_WARNING(0);
                }
            }
        } else if ((hdl_flags & EB_L2CAP_PB_CF) == EB_L2CAP_PB_CF) { // Continue packet
            if (conn->rx_remain_len >= datalen) {
                memcpy(&conn->rx_buf[conn->rx_len], payload, datalen);
                conn->rx_len += datalen;
                conn->rx_remain_len -= datalen;
            } else {
                memcpy(&conn->rx_buf[conn->rx_len], payload, conn->rx_remain_len);
                conn->rx_len += conn->rx_remain_len;
                conn->rx_remain_len = 0;
                // Data too long
                EB_L2CAP_WARNING(0);
            }
        } else {
            // Unexpected PB flags
            EB_L2CAP_WARNING(0);
        }
        if (conn->rx_remain_len == 0) { // Data reassembled, callback then
            uint8_t *p = conn->rx_buf;
            uint16_t l2cap_len = *p + (*(p + 1) << 8);
            p += sizeof(uint16_t); // Skip ACL length
            uint16_t cid = *p + (*(p + 1) << 8);
            p += sizeof(uint16_t); // Skip CID
            l2cap->proc_cb(conn_hdl, cid, p, l2cap_len, l2cap->usr_data);
        }
    } else {
        // Recevie data from invalid connection handle
        EB_L2CAP_WARNING(0);
    }
}

void eb_l2cap_connected(struct eb_l2cap *l2cap, uint16_t conn_hdl, uint8_t role,
                        uint8_t *peer_addr, uint8_t peer_addr_type, uint8_t *local_addr, uint8_t local_addr_type)
{
    EB_L2CAP_ASSERT(l2cap);
    struct eb_l2cap_conn *conn = set_l2cap_by_handle(l2cap, conn_hdl);
    EB_L2CAP_ASSERT(conn);
    conn->pending_acl_packets = 0;
    block_queue_create(&conn->send_ringbuf, conn->tx_buf, EB_L2CAP_SEND_BUF_LENGTH);
    if (l2cap->connected_cb) {
        l2cap->connected_cb(conn_hdl, role, peer_addr, peer_addr_type, local_addr, local_addr_type, l2cap->usr_data);
    }
}

void eb_l2cap_disconnected(struct eb_l2cap *l2cap, uint16_t conn_hdl)
{
    EB_L2CAP_ASSERT(l2cap);
    struct eb_l2cap_conn *conn = get_l2cap_by_handle(l2cap, conn_hdl);
    EB_L2CAP_ASSERT(conn);
    l2cap->num_le_acl_data_packets += conn->pending_acl_packets;
    memset(conn, 0, sizeof(struct eb_l2cap_conn));
    conn->conn_hdl = EB_L2CAP_INVALID_HANDLE;
    if (l2cap->disconnected_cb) {
        l2cap->disconnected_cb(conn_hdl, l2cap->usr_data);
    }
}

void eb_l2cap_acl_cfg(struct eb_l2cap *l2cap, uint16_t pkg_size, int pkg_num)
{
    int i;
    for (i = 0; i < l2cap->max_connection; i++) {
        EB_L2CAP_ASSERT(l2cap->conn[i].conn_hdl == EB_L2CAP_INVALID_HANDLE);
    }
    l2cap->acl_data_packet_length = pkg_size;
    l2cap->num_le_acl_data_packets = pkg_num;
    l2cap->total_num_le_acl_data_packets = pkg_num;
    l2cap->tx_available = pkg_num;
}

void eb_l2cap_packets_completed(struct eb_l2cap *l2cap, uint16_t conn_hdl, int pkg_num)
{
    EB_L2CAP_ASSERT(l2cap);
    struct eb_l2cap_conn *conn = get_l2cap_by_handle(l2cap, conn_hdl);
    if (conn) {
        l2cap->num_le_acl_data_packets += pkg_num;
        conn->pending_acl_packets -= pkg_num;
        if (l2cap->num_le_acl_data_packets > l2cap->total_num_le_acl_data_packets) {
            l2cap->num_le_acl_data_packets = l2cap->total_num_le_acl_data_packets;
            EB_L2CAP_WARNING(0); // Unexpected case;
        }
        if (conn->pending_acl_packets < 0) {
            conn->pending_acl_packets = 0;
            EB_L2CAP_WARNING(0); // Unexpected case;
        }
    }
}

int eb_l2cap_sche_flush_once(struct eb_l2cap *l2cap)
{
    EB_L2CAP_ASSERT(l2cap);
    int finish_conn_idx = l2cap->conn_sent_idx - 1;
    if (finish_conn_idx < 0) {
        finish_conn_idx += l2cap->max_connection;
    }
    while (l2cap->num_le_acl_data_packets) {
        if (l2cap->conn_sent_idx >= l2cap->max_connection) {
            l2cap->conn_sent_idx = 0;
        }
        if (finish_conn_idx == l2cap->conn_sent_idx) {
            break;
        }
        struct eb_l2cap_conn *conn = &l2cap->conn[l2cap->conn_sent_idx];
        if (conn) {
            br_size_t size;
            uint8_t *p = block_queue_pop_peek(&conn->send_ringbuf, &size);
            if (p) {
                size_t *d = (size_t *)p;
                void(*sent_cb)(void *) = (void(*)(void *)) * d++;
                void *usr_data = (void *)*d++;
                p += 2 * sizeof(size_t);
                size -= 2 * sizeof(size_t);
                uint16_t hdl_flags = (*p + (*(p + 1) << 8));
                uint16_t conn_hdl = hdl_flags & EB_L2CAP_HANDLE_MASK;
                EB_L2CAP_ASSERT(conn->conn_hdl == conn_hdl);
                *--p = 0x02; // Add ACL Mark
                conn->pending_acl_packets++;
                l2cap->num_le_acl_data_packets--;
                l2cap->send_cb(p, size + 1, l2cap->usr_data);
                block_queue_pop(&conn->send_ringbuf);
                l2cap->tx_available++;
                finish_conn_idx = l2cap->conn_sent_idx;
                if (sent_cb) {
                    sent_cb(usr_data);
                }
            }
        }
        l2cap->conn_sent_idx++;
    }
    return l2cap->tx_available;
}

