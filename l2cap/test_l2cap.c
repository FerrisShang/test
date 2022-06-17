#include <stdio.h>
#include <string.h>
#include "eb_l2cap.h"

#define DUMP_AVA_PKG() printf("ava_pkg=0x%02X\n", *((uint8_t*)l2cap+sizeof(void*)+2))

uint8_t l2cap_buf[1024];
struct eb_l2cap const *l2cap = (struct eb_l2cap *)l2cap_buf;

void send_cb(uint8_t *data, int len)
{
    printf("%s@%d len:0x%02X %d\n", __func__, __LINE__, len, len);
    while (len-- > 0) {
        printf("%02X ", *data++);
    }
    printf("\n");
}

void send_done_cb(struct eb_l2cap_send_data *data, uint8_t status)
{
    printf("%s@%d st:%d, conn_idx:0x%02X seq_num:0x%02X\n", __func__, __LINE__, status, data->conn_idx, data->seq_num);
    free((uint8_t*)data-EB_L2CAP_RESERVED_SIZE);
}

void proc_cb(uint8_t conn_idx, uint16_t cid, void *payload, int len)
{
    printf("%s@%d\n", __func__, __LINE__);
}

void connected_cb(uint8_t conn_idx, uint8_t role, uint8_t *peer_addr, uint8_t peer_addr_type,
                  uint8_t *local_addr, uint8_t local_addr_type)
{
    printf("%s@%d,idx=%d\n", __func__, __LINE__, conn_idx);
}

void disconnected_cb(uint8_t conn_idx)
{
    printf("%s@%d,idx=%d\n", __func__, __LINE__, conn_idx);
}

void *eb_l2cap_malloc(void *p, int size)
{
    uint8_t *r = malloc(EB_L2CAP_MALLOC_SIZE(size));
    return r + EB_L2CAP_RESERVED_SIZE;
}
int main(void)
{
    struct eb_l2cap_callbacks l2cap_cbs = {
        send_cb,
        send_done_cb,
        proc_cb,
        connected_cb,
        disconnected_cb,
    };
    struct eb_l2cap_cfg l2cap_cfg = {
        .cb = &l2cap_cbs,
        .acl_data_packet_length = 27,
        .total_num_le_acl_data_packets = 4,
        .max_connection = 4,
        .max_recv_buf_len = 256,
    };
    eb_l2cap_init((struct eb_l2cap *)l2cap, &l2cap_cfg);
    eb_pl2cap_connected((struct eb_l2cap *)l2cap, 3, 0x0040, 0, NULL, 0, NULL, 0);
    eb_pl2cap_disconnected((struct eb_l2cap *)l2cap, 1);
    {
        struct eb_l2cap_send_data *data = eb_l2cap_malloc((struct eb_l2cap *)l2cap, 60);
        data->conn_idx = 3;
        data->seq_num = 0x5F;
        data->length = 52;
        data->cid = 0x04;
        memcpy(data->payload, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 52);
        eb_l2cap_send((struct eb_l2cap *)l2cap, data);
    }
    {
        struct eb_l2cap_send_data *data = eb_l2cap_malloc((struct eb_l2cap *)l2cap, 23);
        data->conn_idx = 3;
        data->seq_num = 0xF5;
        data->cid = 0x05;
        data->length = 23;
        memcpy(data->payload, "12345678901234567890123", 23);
        eb_l2cap_send((struct eb_l2cap *)l2cap, data);
    }
    {
        struct eb_l2cap_send_data *data = eb_l2cap_malloc((struct eb_l2cap *)l2cap, 23);
        data->conn_idx = 3;
        data->seq_num = 0x11;
        data->cid = 0x06;
        data->length = 23;
        memcpy(data->payload, "00000000000000000000000", 23);
        eb_l2cap_send((struct eb_l2cap *)l2cap, data);
    }
    {
        struct eb_l2cap_send_data *data = eb_l2cap_malloc((struct eb_l2cap *)l2cap, 23);
        data->conn_idx = 0;
        data->seq_num = 0x11;
        data->cid = 0x06;
        data->length = 23;
        memcpy(data->payload, "00000000000000000000000", 23);
        eb_l2cap_send((struct eb_l2cap *)l2cap, data);
    }

    eb_l2cap_sche_once((struct eb_l2cap *)l2cap);
    eb_pl2cap_packets_completed((struct eb_l2cap *)l2cap, 3, 4);
    eb_l2cap_sche_once((struct eb_l2cap *)l2cap);
    DUMP_AVA_PKG(); // 4 - 5 + 4 = 3
    {
        struct eb_l2cap_send_data *data = eb_l2cap_malloc((struct eb_l2cap *)l2cap, 23);
        data->conn_idx = 3;
        data->seq_num = 0xD1;
        data->cid = 0x06;
        data->length = 23;
        memcpy(data->payload, "00000000000000000000000", 23);
        eb_l2cap_send((struct eb_l2cap *)l2cap, data);
    }
    eb_pl2cap_disconnected((struct eb_l2cap *)l2cap, 3);
    DUMP_AVA_PKG(); // auto add pending(1) = 4
    // multi connection
    {
        printf("\n--- Multi connection debug ---\n");
        for (int i = 0; i < 3; i++) {
            eb_pl2cap_connected((struct eb_l2cap *)l2cap, i, 0x0040 + i, 0, NULL, 0, NULL, 0);
            for (int j = 0; j < 3; j++) {
                struct eb_l2cap_send_data *data = eb_l2cap_malloc((struct eb_l2cap *)l2cap, 52);
                data->conn_idx = i;
                data->seq_num = 0x50 + (i << 4) + j;
                data->length = 52;
                data->cid = (i << 4) + j;
                memcpy(data->payload, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 52);
                eb_l2cap_send((struct eb_l2cap *)l2cap, data);
            }
        }
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 3; j++) {
                eb_l2cap_sche_once((struct eb_l2cap *)l2cap);
                eb_pl2cap_packets_completed((struct eb_l2cap *)l2cap, i, 3);
            }
        }
        eb_pl2cap_packets_completed((struct eb_l2cap *)l2cap, 0, 1);
        for (int i = 0; i < 3; i++) {
            eb_pl2cap_disconnected((struct eb_l2cap *)l2cap, i);
        }
    }
}

