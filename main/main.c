#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include "eb_schedule.h"
#include "eb_h4tl.h"
#include "eb_hci.h"
#include "eb_l2cap.h"
#include "eb_smp.h"
#include "eb_smp_aes.h"
#include "eb_gatt.h"
#include "eb_att.h"
#include "eb_memory.h"
#include "linux_udp_client.h"

#define HCI_UDP

#ifdef HCI_UDP
#define IP "127.0.0.1"
#define PORT 60000
#else
#include "linux_usb_hci.h"
struct linux_usb_hci *usb_hci;
#endif

#define DUMP(d,l) do{int i;for(i=0;i<(int)l;i++)printf("%02X ", ((uint8_t*)d)[i]); puts("");}while(0)

#define LOCAL_RAND_ADDR {0xC0, 11, 10, 10, 11, 0xC0}
struct linux_udp_client *udp_hci;
struct eb_h4tl *h4tl;
struct eb_hci *hci;
struct eb_l2cap *l2cap;
int le_acl_data_packet_length = 27;
int total_num_le_acl_data_packets = 8;
struct eb_gatt *gatt;
struct eb_smp *smp;
struct eb_sche *sche;

static eb_sche_timer_t timer;
static eb_sche_timer_t timer_sample;
bool scan_flag;

void att_db_init(void)
{
    static const struct eb_uuid_16bit serv1 = {0x02, { 0x00, 0x18}};
    static const struct eb_uuid_16bit serv2 = {0x02, { 0x01, 0x18}};
    static const struct eb_uuid_16bit char1 = {0x02, { 0x00, 0x2a}};
    static const struct eb_uuid_16bit char2 = {0x02, { 0x01, 0x2a}};
    static const struct eb_uuid_16bit char3 = {0x02, { 0x05, 0x2a}};
    static const struct eb_uuid_16bit serv3 = {0x02, { 0xcd, 0xab}};
    static const struct eb_uuid_16bit char4 = {0x02, { 0xef, 0xcd}};

    static const struct eb_att_item serv1_atts[] = {
        { (struct eb_uuid *) &eb_att_char_def, 0x02, },
        { (struct eb_uuid *) &char1,           0x02, 0, 0},
        { (struct eb_uuid *) &eb_att_char_def, 0x02, },
        { (struct eb_uuid *) &char2,           0x02, },
    };
    static const struct eb_att_serv att_serv1 = {
        (struct eb_uuid *) &serv1, serv1_atts, sizeof(serv1_atts) / sizeof(serv1_atts[0])
    };
    static const struct eb_att_item serv2_atts[] = {
        { (struct eb_uuid *) &eb_att_char_def, 0x02, },
        { (struct eb_uuid *) &char3,           ATT_PROP_INDICATE},
        { (struct eb_uuid *) &eb_att_cccd_def, 0x0A, },
    };
    static const struct eb_att_serv att_serv2 = {
        (struct eb_uuid *) &serv2, serv2_atts, sizeof(serv2_atts) / sizeof(serv2_atts[0])
    };
    static const struct eb_att_item serv3_atts[] = {
        { (struct eb_uuid *) &eb_att_char_def, 0x02, },
        { (struct eb_uuid *) &char4,           0x1A, 1, 1},
        { (struct eb_uuid *) &eb_att_cccd_def, 0x0A, 1, 0},
        { (struct eb_uuid *) &eb_att_char_def, 0x02, },
        { (struct eb_uuid *) &char4,           0x1A, 0, 0},
        { (struct eb_uuid *) &eb_att_cccd_def, 0x0A, },
    };
    static const struct eb_att_serv att_serv3 = {
        (struct eb_uuid *) &serv3, serv3_atts, sizeof(serv3_atts) / sizeof(serv3_atts[0])
    };
    eb_gatts_add_service(gatt, &att_serv1);
    eb_gatts_add_service(gatt, &att_serv2);
    eb_gatts_add_service(gatt, &att_serv3);
}

void hci_recv_cb(uint8_t *data, int len, void *p)
{
    eb_h4tl_received(h4tl, data, len);
    eb_sche_event_set(sche, EB_EVENT_MAIN);
}

void h4tl_send_cb(uint8_t *data, size_t len, void *p)
{
    #ifdef HCI_UDP
    udp_client_send(udp_hci, data, len);
    #else
    usb_hci_send(usb_hci, data, len);
    #endif
}

void h4tl_recv_cb(uint8_t *data, size_t len, void *p)
{
    if (*data == 0x04) {
        eb_evt_received(hci, data[1], data + 3, len - 3);
    } else if (*data == 0x02) {
        eb_pl2cap_received(l2cap, 0, data[1] + (data[2] << 8), len - 5, data + 5);
    } else {
        assert(0);
    }
}

void main_callback(void *p)
{
    bool active;
    do {
        active = eb_h4tl_sche_once(h4tl);
        active |= eb_l2cap_sche_once(l2cap);
    } while (active);
}

static void hci_send(uint8_t *data, int len, void *usr_data)
{
    eb_h4tl_send(h4tl, data, len);
}

static void timer_sample_handler(void *p)
{
    static int timer_cnt;
    if (!(timer_cnt % 100)) {
        printf("%s@%03d: %d\n", __func__, __LINE__, timer_cnt);
    }
    timer_cnt++;
    eb_sche_timer_set(sche, &timer_sample, 1000, timer_sample_handler, &timer_cnt);
}

static void hci_proc_cmp(uint16_t opcode, void *payload, int len, void *usr_data)
{
    if (opcode == HCI_RESET_CMP) {
        eb_hci_cmd_send(hci, HCI_LE_READ_BUFFER_SIZE_V1, NULL);
        eb_sche_timer_set(sche, &timer_sample, 100, timer_sample_handler, NULL);
    } else if (opcode == HCI_LE_READ_BUFFER_SIZE_V1) {
        struct hci_le_read_buffer_size_v1_cmp *b = (struct hci_le_read_buffer_size_v1_cmp *)payload;
        le_acl_data_packet_length = b->le_acl_data_packet_length;
        total_num_le_acl_data_packets = b->total_num_le_acl_data_packets;
        eb_pl2cap_acl_cfg(l2cap, le_acl_data_packet_length, total_num_le_acl_data_packets);
        struct hci_set_event_mask p = {
            {
                0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF
            }
        };
        eb_hci_cmd_send(hci, HCI_SET_EVENT_MASK, &p);
    } else if (opcode == HCI_SET_EVENT_MASK) {
        struct hci_le_set_random_address p = { LOCAL_RAND_ADDR };
        eb_hci_cmd_send(hci, HCI_LE_SET_RANDOM_ADDRESS, &p);
    } else if (opcode == HCI_LE_SET_RANDOM_ADDRESS) {
        struct hci_le_set_advertising_parameters p = {
            0x20, 0x40, 0, 1, 0, {0}, 0x07, 0
        };
        eb_hci_cmd_send(hci, HCI_LE_SET_ADVERTISING_PARAMETERS, &p);
    } else if (opcode == HCI_LE_SET_ADVERTISING_PARAMETERS) {
        struct hci_le_set_advertising_data p = { 6, {2, 1, 6, 2, 9, 0x5F}};
        eb_hci_cmd_send(hci, HCI_LE_SET_ADVERTISING_DATA, &p);
    } else if (opcode == HCI_LE_SET_ADVERTISING_DATA) {
        struct hci_le_set_scan_response_data p = { 0 };
        eb_hci_cmd_send(hci, HCI_LE_SET_SCAN_RESPONSE_DATA, &p);
    } else if (opcode == HCI_LE_SET_SCAN_RESPONSE_DATA) {
        struct hci_le_set_advertising_enable p = { 1 };
        eb_hci_cmd_send(hci, HCI_LE_SET_ADVERTISING_ENABLE, &p);
        // struct hci_le_set_scan_enable s = { 1 };
        // eb_hci_cmd_send(hci, HCI_LE_SET_SCAN_ENABLE, &s);
    } else if (opcode == HCI_LE_SET_SCAN_ENABLE) {
        scan_flag = true;
    } else if (opcode == HCI_LE_ENCRYPT_CMP) {
        #ifdef SMP_ALG_HCI_ENC
        struct hci_le_encrypt_cmp *p = (struct hci_le_encrypt_cmp *)payload;
        eb_smp_aes128_encrypted(p->encrypted_data);
        #endif
    }
}

static void hci_proc_evt(uint8_t evt_code, void *payload, int len, void *usr_data)
{
    if (evt_code == HCI_DISCONNECTION_COMPLETE) {
        struct hci_disconnection_complete *p = payload;
        eb_pl2cap_disconnected(l2cap, p->connection_handle);
        eb_hci_cmd_send(hci, HCI_RESET, NULL);
        printf("Disconnected reason: 0x%02X\n", p->reason);
    } else if (evt_code == HCI_READ_REMOTE_VERSION_INFORMATION_COMPLETE) {
        struct hci_read_remote_version_information_complete *p = payload;

        char *manu = eb_get_manufacturer_name(p->manufacturer_name);
        char *version = eb_get_version_name(p->version);
        printf("Manufacturer: %s\nVer: %s\nSubVer: 0x%02X\n", manu, version, p->subversion);
    } else if (evt_code == HCI_NUMBER_OF_COMPLETED_PACKETS) {
        struct hci_number_of_completed_packets *p = payload;
        int i;
        for (i = 0; i < p->num_handles; i++) {
            eb_pl2cap_packets_completed(l2cap, p->params[i].connection_handle, p->params[i].num_completed_packets);
        }
    } else if (evt_code == HCI_ENCRYPTION_CHANGE_V1) {
        struct hci_encryption_change_v1 *p = payload;
        // eb_smpp_encrypt_changed(smp, p->connection_handle, p->encryption_enabled, 16);
        eb_pgatt_sec_changed(gatt, p->connection_handle, EB_GATT_SEC_ENCRYPTED);
    }
}

static void l2cap_send(uint8_t *data, int len)
{
    eb_h4tl_send(h4tl, data, len);
}

static void l2cap_send_done_cb(struct eb_l2cap_send_data *data, uint8_t status)
{
    switch (data->cid) {
        case EB_L2CAP_CID_ATT:
            eb_pgatt_send_done(gatt, data->conn_idx, (struct att_packet *)data->payload, data->seq_num);
            break;
        case EB_L2CAP_CID_SIG:
            // TODO
            break;
        case EB_L2CAP_CID_SMP:
            // TODO
            break;
    }
}

static void l2cap_proc(uint8_t conn_idx, uint16_t cid, void *payload, int len)
{
    if (cid == EB_L2CAP_CID_ATT) {
        eb_pgatt_received(gatt, conn_idx, payload, len);
    } else if (cid == EB_L2CAP_CID_SMP) {
        // eb_smpp_received(smp, conn_hdl, payload, len);
    }
}

static void l2cap_connected(uint8_t conn_idx, uint8_t role, uint8_t *peer_addr, uint8_t peer_addr_type,
                            uint8_t *local_addr, uint8_t local_addr_type)
{
    // eb_smpp_connected(smp, conn_hdl, role, peer_addr, peer_addr_type, local_addr, local_addr_type);
    eb_pgatt_connected(gatt, conn_idx);
    // eb_smp_security_req(smp, conn_hdl, SMP_AUTH_FLAGS_BONDING);
}

static void l2cap_disconnected(uint8_t conn_idx)
{
    // eb_smpp_disconnected(smp, conn_hdl);
    eb_pgatt_disconnected(gatt, conn_idx);
}

static void timer_callback(void *p)
{
    struct hci_le_set_scan_enable cmd = { 0, 0 };
    eb_hci_cmd_send(hci, HCI_LE_SET_SCAN_ENABLE, &cmd);
}

static void hci_proc_le_evt(uint8_t subcode, void *payload, int len, void *usr_data)
{
    if (subcode == HCI_LE_ADVERTISING_REPORT) {
        struct hci_le_advertising_report *p = payload;
        if (scan_flag && p->params[0].event_type == 0x00 && p->params[0].rssi > -50) {
            scan_flag = false;
            eb_sche_timer_set(sche, &timer, 1, timer_callback, NULL);
            struct hci_le_advertising_report *p = payload;
            struct hci_le_create_connection cmd = {
                0x40, 0x30, 0, p->params[0].address_type, {0},
                0, 0x20, 40, 0, 200, 0x0000, 0x8000
            };
            memcpy(cmd.peer_address, p->params[0].address, 6);
            eb_hci_cmd_send(hci, HCI_LE_CREATE_CONNECTION, &cmd);
        }
    } else if (subcode == HCI_LE_CONNECTION_COMPLETE) {
        struct hci_le_connection_complete *p = payload;
        size_t i;
        for (i = 0; i < 6; i++) {
            printf("%02X ", p->peer_address[i]);
        }
        printf("  <-MAC == Connected\n");
        uint8_t local_addr[] = LOCAL_RAND_ADDR;
        eb_pl2cap_connected(l2cap, 0, p->connection_handle, p->role, p->peer_address, p->peer_address_type, local_addr, 1);
        struct hci_read_remote_version_information r = { p->connection_handle };
        eb_hci_cmd_send(hci, HCI_READ_REMOTE_VERSION_INFORMATION, &r);
    } else if (subcode == HCI_LE_LONG_TERM_KEY_REQUEST) {
        // struct hci_le_long_term_key_request *p = payload;
        // eb_smpp_ltk_request(smp, p->connection_handle, p->random_number, p->encrypted_diversifier);
    }
}

static void gatt_send_cb(uint8_t conn_idx, uint8_t *data, int len, uint8_t seq_num)
{
    struct eb_l2cap_send_data *l2cap_data = (struct eb_l2cap_send_data *)
                                            (data - offsetof(struct eb_l2cap_send_data, payload));
    l2cap_data->conn_idx = conn_idx;
    l2cap_data->seq_num = seq_num;
    l2cap_data->length = len;
    l2cap_data->cid = EB_L2CAP_CID_ATT;
    eb_l2cap_send(l2cap, l2cap_data);
}
static void gatt_conn_cb(uint8_t conn_idx)
{
}
static void gatt_disconn_cb(uint8_t conn_idx)
{
}

void *gatt_msg_malloc_cb(size_t size, uint8_t priority)
{
    const int offset = sizeof(struct eb_l2cap_send_data) + EB_L2CAP_RESERVED_SIZE;
    uint8_t *p = EB_MALLOC(EB_L2CAP_MALLOC_SIZE(size), priority);
    return p + offset;
}
void gatt_msg_free_cb(void *p)
{
    const int offset = sizeof(struct eb_l2cap_send_data) + EB_L2CAP_RESERVED_SIZE;
    EB_FREE((uint8_t *)p - offset);
}
static void gatt_proc_cb(uint8_t conn_idx, struct gatt_param *param)
{
    if (param->evt_id == EB_GATT_MTU_CHANGED_IND) {
        printf("EB_GATT_MTU_CHANGED_IND: %d\n", param->mtu_changed.mtu);
    } else if (param->evt_id == EB_GATTS_READ_REQ) {
        printf("EB_GATTS_READ_REQ handle:0x%04X, offset:0x%04X\n",
               param->read_req.att_hdl, param->read_req.offset);
        eb_gatts_pending_request(gatt, conn_idx);
        eb_gatts_read_response(gatt, conn_idx, ATT_ERR_NO_ERROR, (uint8_t *)"\x31\x31\x36", 3);
    } else if (param->evt_id == EB_GATTS_WRITE_REQ) {
        printf("EB_GATTS_WRITE_REQ handle:0x%04X, type:0x%04X\n\t", param->write_req.att_hdl, param->write_req.type);
        DUMP(param->write_req.data, param->write_req.len);
        eb_gatts_pending_request(gatt, conn_idx);
        eb_gatts_write_response(gatt, conn_idx, ATT_ERR_NO_ERROR);
    }
}

#if 0
static void smp_send_cb(uint16_t conn_hdl, uint8_t *data, int len, void *usr_data)
{
    struct eb_l2cap_send_data l2cap_data = {
        conn_hdl, EB_L2CAP_CID_SMP, data, len
    };
    eb_l2cap_send(l2cap, &l2cap_data);
}
static void smp_conn_cb(uint16_t conn_hdl, uint8_t role, void *usr_data)
{
}
static void smp_disconn_cb(uint16_t conn_hdl, void *usr_data)
{
}
static void smp_proc_cb(uint16_t conn_hdl, struct smp_param *param, void *usr_data)
{
    switch (param->evt_id) {
        case EB_SMP_PAIRING_REQ: {
            struct smp_pairing_response rsp = {
                0, 3, 0, 5, 16, 3, 0
            };
            eb_smp_pairing_response(smp, conn_hdl, &rsp);
            break;
        }
    }
}
#endif
static void smp_ltk_resp_cb(uint16_t conn_hdl, uint8_t *key, void *usr_data)
{
    struct hci_le_long_term_key_request_reply p;
    p.connection_handle = conn_hdl;
    memcpy(p.long_term_key, key, 16);
    eb_hci_cmd_send(hci, HCI_LE_LONG_TERM_KEY_REQUEST_REPLY, &p);
}

#ifdef SMP_ALG_HCI_ENC
void encrypt_data(const uint8_t *key, const uint8_t *plaintext, void *p)
{
    struct hci_le_encrypt e;
    memcpy(e.key, key, 16);
    memcpy(e.plaintext_data, plaintext, 16);
    eb_hci_cmd_send(hci, HCI_LE_ENCRYPT, &e);
}
#endif

int main(void)
{
    sche = eb_schedule_create();
    eb_sche_event_callback_set(sche, EB_EVENT_MAIN, main_callback, NULL);
    #ifdef HCI_UDP
    udp_hci = udp_client_create(IP, PORT, hci_recv_cb, NULL);
    #else
    usb_hci = usb_hci_create(0x0a5c, 0x21ec, hci_recv_cb, NULL);
    #endif

    h4tl = eb_h4tl_create(h4tl_send_cb, h4tl_recv_cb, NULL, NULL);
    struct eb_hci_cfg hci_cfg = { hci_send, hci_proc_cmp, hci_proc_evt, hci_proc_le_evt, NULL };
    hci = eb_hci_init(&hci_cfg, NULL);
    const struct eb_l2cap_callbacks l2cap_cbs = {
        l2cap_send, l2cap_send_done_cb, l2cap_proc, l2cap_connected, l2cap_disconnected,
    };
    struct eb_l2cap_param l2cap_param = {
        &l2cap_cbs, le_acl_data_packet_length, total_num_le_acl_data_packets, 4, 300
    };
    l2cap = eb_l2cap_init(&l2cap_param);

    struct eb_gatt_callbacks gatt_cbs = {
        gatt_send_cb, gatt_proc_cb, gatt_conn_cb, gatt_disconn_cb, gatt_msg_malloc_cb, gatt_msg_free_cb,
    };
    struct eb_gatt_param gatt_param = {
        &gatt_cbs, 30, 517, 8, 4
    };
    gatt = eb_gatt_init(&gatt_param);
    att_db_init();

    // struct eb_smp_cfg smp_cfg = {
    //     smp_send_cb, smp_conn_cb, smp_disconn_cb, smp_proc_cb, smp_ltk_resp_cb, 4, NULL
    // };
    // smp = eb_smp_init(&smp_cfg, NULL);

    #ifdef SMP_ALG_HCI_ENC
    eb_smp_aes128_init(encrypt_data, NULL);
    #endif

    eb_hci_cmd_send(hci, HCI_RESET, NULL);
    eb_schedule(sche);

    return 0;
}

