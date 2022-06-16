#include <stdio.h>
#include <string.h>
#include "eb_l2cap.h"

void send_cb(uint8_t *data, int len)
{
    printf("%s@%d len:0x%02X %d\n", __func__, __LINE__, len, len);
}

void send_done_cb(uint8_t conn_idx, uint8_t seq_num)
{
    printf("%s@%d conn_idx:0x%02X seq_num:0x%02X\n", __func__, __LINE__, conn_idx, seq_num);
}

void proc_cb(uint8_t conn_idx, uint16_t cid, void *payload, int len)
{
    printf("%s@%d\n", __func__, __LINE__);
}

void connected_cb(uint8_t conn_idx, uint8_t role, uint8_t *peer_addr, uint8_t peer_addr_type,
        uint8_t *local_addr, uint8_t local_addr_type)
{
    printf("%s@%d\n", __func__, __LINE__);
}

void disconnected_cb(uint8_t conn_idx)
{
    printf("%s@%d\n", __func__, __LINE__);
}

void *malloc_pkg_cb(int size)
{
    return malloc(size);
}

void free_pkg_cb(void *package)
{
    free(package);
}

uint8_t l2cap_buf[1024];
struct eb_l2cap const *l2cap = (struct eb_l2cap *)l2cap_buf;

int main(void)
{
    struct eb_l2cap_callbacks l2cap_cbs = {
        send_cb,
        send_done_cb,
        proc_cb,
        connected_cb,
        disconnected_cb,
        malloc_pkg_cb,
        free_pkg_cb,
    };
    struct eb_l2cap_cfg l2cap_cfg = {
        .cb = &l2cap_cbs,
        .acl_data_packet_length = 27,
        .total_num_le_acl_data_packets = 4,
        .max_connection = 4,
        .max_recv_buf_len = 256,
    };
    eb_l2cap_init((struct eb_l2cap *)l2cap, &l2cap_cfg);
    eb_pl2cap_connected((struct eb_l2cap *)l2cap, 0, 0x0040, 0, NULL, 0, NULL, 0);
    eb_pl2cap_disconnected((struct eb_l2cap *)l2cap, 1);

    struct eb_l2cap_send_data *data = eb_l2cap_malloc((struct eb_l2cap *)l2cap, 10);
    data->conn_idx = 0;
    data->seq_num = 0;
    data->length = 10;
    memcpy(data->payload, "a12345678a", 10);
    eb_l2cap_send((struct eb_l2cap *)l2cap, data);
    eb_pl2cap_disconnected((struct eb_l2cap *)l2cap, 0);
}

