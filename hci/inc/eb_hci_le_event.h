#ifndef __EB_HCI_LE_EVENT_H__
#define __EB_HCI_LE_EVENT_H__

#include <stdint.h>
#include "eb_compile.h"

#define HCI_LE_CONNECTION_COMPLETE                             0x01
#define HCI_LE_ADVERTISING_REPORT                              0x02
#define HCI_LE_CONNECTION_UPDATE_COMPLETE                      0x03
#define HCI_LE_READ_REMOTE_FEATURES_COMPLETE                   0x04
#define HCI_LE_LONG_TERM_KEY_REQUEST                           0x05
#define HCI_LE_REMOTE_CONNECTION_PARAMETER_REQUEST             0x06
#define HCI_LE_DATA_LENGTH_CHANGE                              0x07
#define HCI_LE_READ_LOCAL_P_256_PUBLIC_KEY_COMPLETE            0x08
#define HCI_LE_GENERATE_DHKEY_COMPLETE                         0x09
#define HCI_LE_ENHANCED_CONNECTION_COMPLETE                    0x0A
#define HCI_LE_DIRECTED_ADVERTISING_REPORT                     0x0B
#define HCI_LE_PHY_UPDATE_COMPLETE                             0x0C
#define HCI_LE_EXTENDED_ADVERTISING_REPORT                     0x0D
#define HCI_LE_PERIODIC_ADVERTISING_SYNC_ESTABLISHED           0x0E
#define HCI_LE_PERIODIC_ADVERTISING_REPORT                     0x0F
#define HCI_LE_PERIODIC_ADVERTISING_SYNC_LOST                  0x10
#define HCI_LE_SCAN_TIMEOUT                                    0x11
#define HCI_LE_ADVERTISING_SET_TERMINATED                      0x12
#define HCI_LE_SCAN_REQUEST_RECEIVED                           0x13
#define HCI_LE_CHANNEL_SELECTION_ALGORITHM                     0x14
#define HCI_LE_CONNECTIONLESS_IQ_REPORT                        0x15
#define HCI_LE_CONNECTION_IQ_REPORT                            0x16
#define HCI_LE_CTE_REQUEST_FAILED                              0x17
#define HCI_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER_RECEIVED     0x18
#define HCI_LE_CIS_ESTABLISHED                                 0x19
#define HCI_LE_CIS_REQUEST                                     0x1A
#define HCI_LE_CREATE_BIG_COMPLETE                             0x1B
#define HCI_LE_TERMINATE_BIG_COMPLETE                          0x1C
#define HCI_LE_BIG_SYNC_ESTABLISHED                            0x1D
#define HCI_LE_BIG_SYNC_LOST                                   0x1E
#define HCI_LE_REQUEST_PEER_SCA_COMPLETE                       0x1F
#define HCI_LE_PATH_LOSS_THRESHOLD                             0x20
#define HCI_LE_TRANSMIT_POWER_REPORTING                        0x21
#define HCI_LE_BIGINFO_ADVERTISING_REPORT                      0x22
#define HCI_LE_SUBRATE_CHANGE                                  0x23

// 7.7.65.1 HCI_LE_Connection_Complete 0x01
struct hci_le_connection_complete {
    uint8_t subevent_code;
    uint8_t status;
    uint16_t connection_handle;
    uint8_t role;
    uint8_t peer_address_type;
    uint8_t peer_address[6];
    uint16_t connection_interval;
    uint16_t peripheral_latency;
    uint16_t supervision_timeout;
    uint8_t central_clock_accuracy;
} __PACKED;

// 7.7.65.2 HCI_LE_Advertising_Report 0x02
struct hci_le_advertising_report {
    uint8_t subevent_code;
    uint8_t num_reports;
    struct {
        uint8_t event_type;
        uint8_t address_type;
        uint8_t address[6];
        uint8_t data_length;
        uint8_t *data;
        int8_t rssi;
    } __PACKED params[0];
} __PACKED;

// 7.7.65.3 HCI_LE_Connection_Update_Complete 0x03
struct hci_le_connection_update_complete {
    uint8_t subevent_code;
    uint8_t status;
    uint16_t connection_handle;
    uint16_t connection_interval;
    uint16_t peripheral_latency;
    uint16_t supervision_timeout;
} __PACKED;

// 7.7.65.4 HCI_LE_Read_Remote_Features_Complete 0x04
struct hci_le_read_remote_features_complete {
    uint8_t subevent_code;
    uint8_t status;
    uint16_t connection_handle;
    uint8_t le_features[8];
} __PACKED;

// 7.7.65.5 HCI_LE_Long_Term_Key_Request 0x05
struct hci_le_long_term_key_request {
    uint8_t subevent_code;
    uint16_t connection_handle;
    uint8_t random_number[8];
    uint16_t encrypted_diversifier;
} __PACKED;

// 7.7.65.6 HCI_LE_Remote_Connection_Parameter_Request 0x06
struct hci_le_remote_connection_parameter_request {
    uint8_t subevent_code;
    uint16_t connection_handle;
    uint16_t interval_min;
    uint16_t interval_max;
    uint16_t max_latency;
    uint16_t timeout;
} __PACKED;

// 7.7.65.7 HCI_LE_Data_Length_Change 0x07
struct hci_le_data_length_change {
    uint8_t subevent_code;
    uint16_t connection_handle;
    uint16_t max_tx_octets;
    uint16_t max_tx_time;
    uint16_t max_rx_octets;
    uint16_t max_rx_time;
} __PACKED;

// 7.7.65.8 HCI_LE_Read_Local_P_256_Public_Key_Complete 0x08
struct hci_le_read_local_p_256_public_key_complete {
    uint8_t subevent_code;
    uint8_t status;
    uint8_t key_x_coordinate[32];
    uint8_t key_y_coordinate[32];
} __PACKED;

// 7.7.65.9 HCI_LE_Generate_DHKey_Complete 0x09
struct hci_le_generate_dhkey_complete {
    uint8_t subevent_code;
    uint8_t status;
    uint8_t dh_key[32];
} __PACKED;

// 7.7.65.10 HCI_LE_Enhanced_Connection_Complete 0x0A
struct hci_le_enhanced_connection_complete {
    uint8_t subevent_code;
    uint8_t status;
    uint16_t connection_handle;
    uint8_t role; // 0-Central, 1-Peripheral
    uint8_t peer_address_type;
    uint8_t peer_address[6];
    uint8_t local_resolvable_private_address[6];
    uint8_t peer_resolvable_private_address[6];
    uint16_t connection_interval;
    uint16_t peripheral_latency;
    uint16_t supervision_timeout;
    uint8_t central_clock_accuracy;
} __PACKED;

// 7.7.65.11 HCI_LE_Directed_Advertising_Report 0x0B
struct hci_le_directed_advertising_report {
    uint8_t subevent_code;
    uint8_t num_reports;
    struct {
        uint8_t event_type;
        uint8_t address_type;
        uint8_t address[6];
        uint8_t direct_address_type;
        uint8_t direct_address[6];
        uint8_t rssi;
    } __PACKED params[0];
} __PACKED;

// 7.7.65.12 HCI_LE_PHY_Update_Complete 0x0C
struct hci_le_phy_update_complete {
    uint8_t subevent_code;
    uint8_t status;
    uint16_t connection_handle;
    uint8_t tx_phy;
    uint8_t rx_phy;
} __PACKED;

// 7.7.65.13 HCI_LE_Extended_Advertising_Report 0x0D
struct hci_le_extended_advertising_report {
    uint8_t subevent_code;
    uint8_t num_reports;
    struct {
        uint16_t ext_event_type;
        uint8_t address_type;
        uint8_t address[6];
        uint8_t primary_phy;
        uint8_t secondary_phy;
        uint8_t advertising_sid;
        uint8_t tx_power;
        uint8_t rssi;
        uint16_t periodic_advertising_interval;
        uint8_t direct_address_type;
        uint8_t direct_address[6];
        uint8_t data_length;
        uint8_t *data;
    } __PACKED params[0];
} __PACKED;

// 7.7.65.14 HCI_LE_Periodic_Advertising_Sync_Established 0x0E
struct hci_le_periodic_advertising_sync_established {
    uint8_t subevent_code;
    uint8_t status;
    uint16_t sync_handle;
    uint8_t advertising_sid;
    uint8_t advertiser_address_type;
    uint8_t advertiser_address[6];
    uint8_t advertiser_phy;
    uint16_t periodic_advertising_interval;
    uint8_t advertiser_clock_accuracy;
} __PACKED;

// 7.7.65.15 HCI_LE_Periodic_Advertising_Report 0x0F
struct hci_le_periodic_advertising_report {
    uint8_t subevent_code;
    uint16_t sync_handle;
    uint8_t tx_power;
    uint8_t rssi;
    uint8_t cte_type;
    uint8_t data_status;
    uint8_t data_length;
    uint8_t data;
} __PACKED;

// 7.7.65.16 HCI_LE_Periodic_Advertising_Sync_Lost 0x10
struct hci_le_periodic_advertising_sync_lost {
    uint8_t subevent_code;
    uint16_t sync_handle;
} __PACKED;

// 7.7.65.17 HCI_LE_Scan_Timeout 0x11
struct hci_le_scan_timeout {
    uint8_t subevent_code;
} __PACKED;

// 7.7.65.18 HCI_LE_Advertising_Set_Terminated 0x12
struct hci_le_advertising_set_terminated {
    uint8_t subevent_code;
    uint8_t status;
    uint8_t advertising_handle;
    uint16_t connection_handle;
    uint8_t num_completed_extended_advertising_events;
} __PACKED;

// 7.7.65.19 HCI_LE_Scan_Request_Received 0x13
struct hci_le_scan_request_received {
    uint8_t subevent_code;
    uint8_t advertising_handle;
    uint8_t scanner_address_type;
    uint8_t scanner_address[6];
} __PACKED;

// 7.7.65.20 HCI_LE_Channel_Selection_Algorithm 0x14
struct hci_le_channel_selection_algorithm {
    uint8_t subevent_code;
    uint16_t connection_handle;
    uint8_t channel_selection_algorithm;
} __PACKED;

// 7.7.65.21 HCI_LE_Connectionless_IQ_Report 0x15
struct hci_le_connectionless_iq_report {
    uint8_t subevent_code;
    uint16_t sync_handle;
    uint8_t channel_index;
    uint8_t rssi;
    uint8_t rssi_antenna_id;
    uint8_t cte_type;
    uint8_t slot_durations;
    uint8_t packet_status;
    uint16_t periodic_event_counter;
    uint8_t sample_count;
    struct {
        uint8_t i_sample;
        uint8_t q_sample;
    } __PACKED params[0];
} __PACKED;

// 7.7.65.22 HCI_LE_Connection_IQ_Report 0x16
struct hci_le_connection_iq_report {
    uint8_t subevent_code;
    uint16_t connection_handle;
    uint8_t rx_phy;
    uint8_t data_channel_index;
    uint8_t rssi;
    uint8_t rssi_antenna_id;
    uint8_t cte_type;
    uint8_t slot_durations;
    uint8_t packet_status;
    uint16_t connection_event_counter;
    uint8_t sample_count;
    struct {
        uint8_t i_sample;
        uint8_t q_sample;
    } __PACKED params[0];
} __PACKED;

// 7.7.65.23 HCI_LE_CTE_Request_Failed 0x17
struct hci_le_cte_request_failed {
    uint8_t subevent_code;
    uint8_t status;
    uint16_t connection_handle;
} __PACKED;

// 7.7.65.24 HCI_LE_Periodic_Advertising_Sync_Transfer_Received 0x18
struct hci_le_periodic_advertising_sync_transfer_received {
    uint8_t subevent_code;
    uint8_t status;
    uint16_t connection_handle;
    uint16_t service_data;
    uint16_t sync_handle;
    uint8_t advertising_sid;
    uint8_t advertiser_address_type;
    uint8_t advertiser_address[6];
    uint8_t advertiser_phy;
    uint16_t periodic_advertising_interval;
    uint8_t advertiser_clock_accuracy;
} __PACKED;

// 7.7.65.25 HCI_LE_CIS_Established 0x19
struct hci_le_cis_established {
    uint8_t subevent_code;
    uint8_t status;
    uint64_t connection_handle: 16;
    uint64_t cig_sync_delay: 24;
    uint64_t cis_sync_delay: 24;
    uint64_t transport_latency_c_to_p: 24;
    uint64_t transport_latency_p_to_c: 24;
    uint64_t phy_c_to_p: 8;
    uint64_t phy_p_to_c: 8;
    uint8_t nse;
    uint8_t bn_c_to_p;
    uint8_t bn_p_to_c;
    uint8_t ft_c_to_p;
    uint8_t ft_p_to_c;
    uint16_t max_pdu_c_to_p;
    uint16_t max_pdu_p_to_c;
    uint16_t iso_interval;
} __PACKED;

// 7.7.65.26 HCI_LE_CIS_Request 0x1A
struct hci_le_cis_request {
    uint8_t subevent_code;
    uint16_t acl_connection_handle;
    uint16_t cis_connection_handle;
    uint8_t cig_id;
    uint8_t cis_id;
} __PACKED;

// 7.7.65.27 HCI_LE_Create_BIG_Complete 0x1B
struct hci_le_create_big_complete {
    uint8_t subevent_code;
    uint8_t status;
    uint32_t big_handle: 8;
    uint32_t big_sync_delay: 24;
    uint32_t transport_latency_big: 24;
    uint32_t phy: 8;
    uint8_t nse;
    uint8_t bn;
    uint8_t pto;
    uint8_t irc;
    uint16_t max_pdu;
    uint16_t iso_interval;
    uint8_t num_bis;
    uint16_t connection_handle[0];
} __PACKED;

// 7.7.65.28 HCI_LE_Terminate_BIG_Complete 0x1C
struct hci_le_terminate_big_complete {
    uint8_t subevent_code;
    uint8_t big_handle;
    uint8_t reason;
} __PACKED;

// 7.7.65.29 HCI_LE_BIG_Sync_Established 0x1D
struct hci_le_big_sync_established {
    uint8_t subevent_code;
    uint8_t status;
    uint32_t big_handle: 8;
    uint32_t transport_latency_big: 24;
    uint8_t nse;
    uint8_t bn;
    uint8_t pto;
    uint8_t irc;
    uint16_t max_pdu;
    uint16_t iso_interval;
    uint8_t num_bis;
    uint16_t connection_handle[0];
} __PACKED;

// 7.7.65.30 HCI_LE_BIG_Sync_Lost 0x1E
struct hci_le_big_sync_lost {
    uint8_t subevent_code;
    uint8_t big_handle;
    uint8_t reason;
} __PACKED;

// 7.7.65.31 HCI_LE_Request_Peer_SCA_Complete 0x1F
struct hci_le_request_peer_sca_complete {
    uint8_t subevent_code;
    uint8_t status;
    uint16_t connection_handle;
    uint8_t peer_clock_accuracy;
} __PACKED;

// 7.7.65.32 HCI_LE_Path_Loss_Threshold 0x20
struct hci_le_path_loss_threshold {
    uint8_t subevent_code;
    uint16_t connection_handle;
    uint8_t current_path_loss;
    uint8_t zone_entered;
} __PACKED;

// 7.7.65.33 HCI_LE_Transmit_Power_Reporting 0x21
struct hci_le_transmit_power_reporting {
    uint8_t subevent_code;
    uint8_t status;
    uint16_t connection_handle;
    uint8_t reason;
    uint8_t phy;
    uint8_t tx_power_level;
    uint8_t tx_power_level_flag;
    uint8_t delta;
} __PACKED;

// 7.7.65.34 HCI_LE_BIGInfo_Advertising_Report 0x22
struct hci_le_biginfo_advertising_report {
    uint8_t subevent_code;
    uint16_t sync_handle;
    uint8_t num_bis;
    uint8_t nse;
    uint16_t iso_interval;
    uint8_t bn;
    uint8_t pto;
    uint8_t irc;
    uint16_t max_pdu;
    uint64_t sdu_interval: 24;
    uint64_t max_sdu: 16;
    uint64_t phy: 8;
    uint64_t framing: 8;
    uint64_t encryption: 8;
} __PACKED;

// 7.7.65.35 HCI_LE_Subrate_Change 0x23
struct hci_le_subrate_change {
    uint8_t subevent_code;
    uint8_t status;
    uint16_t connection_handle;
    uint16_t subrate_factor;
    uint16_t peripheral_latency;
    uint16_t continuation_number;
    uint16_t supervision_timeout;
} __PACKED;

#endif /* __EB_HCI_LE_EVENT_H__ */

