#ifndef __EB_HCI_COMMAND_H__
#define __EB_HCI_COMMAND_H__

#include <stdint.h>
#include "eb_compile.h"

#define HCI_DISCONNECT                                                   0x0406
#define HCI_READ_REMOTE_VERSION_INFORMATION                              0x041D
#define HCI_SET_EVENT_MASK                                               0x0C01
#define HCI_RESET                                                        0x0C03
#define HCI_SET_EVENT_FILTER                                             0x0C05
#define HCI_READ_LE_HOST_SUPPORT                                         0x0C6C
#define HCI_WRITE_LE_HOST_SUPPORT                                        0x0C6D
#define HCI_READ_LOCAL_VERSION_INFORMATION                               0x1001
#define HCI_READ_LOCAL_SUPPORTED_COMMANDS                                0x1002
#define HCI_READ_LOCAL_SUPPORTED_FEATURES                                0x1003
#define HCI_READ_LOCAL_EXTENDED_FEATURES                                 0x1004
#define HCI_READ_BUFFER_SIZE                                             0x1005
#define HCI_READ_BD_ADDR                                                 0x1009
#define HCI_READ_LOCAL_SUPPORTED_CODEC_CAPABILITIES                      0x100E
#define HCI_READ_LOCAL_SUPPORTED_CONTROLLER_DELAY                        0x100F
#define HCI_READ_RSSI                                                    0x1405
#define HCI_LE_SET_EVENT_MASK                                            0x2001
#define HCI_LE_READ_BUFFER_SIZE_V2                                       0x2060
#define HCI_LE_READ_BUFFER_SIZE_V1                                       0x2002
#define HCI_LE_READ_LOCAL_SUPPORTED_FEATURES                             0x2003
#define HCI_LE_SET_RANDOM_ADDRESS                                        0x2005
#define HCI_LE_SET_ADVERTISING_PARAMETERS                                0x2006
#define HCI_LE_READ_ADVERTISING_CHANNEL_TX_POWER                         0x2007
#define HCI_LE_SET_ADVERTISING_DATA                                      0x2008
#define HCI_LE_SET_SCAN_RESPONSE_DATA                                    0x2009
#define HCI_LE_SET_ADVERTISING_ENABLE                                    0x200A
#define HCI_LE_SET_SCAN_PARAMETERS                                       0x200B
#define HCI_LE_SET_SCAN_ENABLE                                           0x200C
#define HCI_LE_CREATE_CONNECTION                                         0x200D
#define HCI_LE_CREATE_CONNECTION_CANCEL                                  0x200E
#define HCI_LE_READ_FILTER_ACCEPT_LIST_SIZE                              0x200F
#define HCI_LE_CLEAR_FILTER_ACCEPT_LIST                                  0x2010
#define HCI_LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST                          0x2011
#define HCI_LE_REMOVE_DEVICE_FROM_FILTER_ACCEPT_LIST                     0x2012
#define HCI_LE_CONNECTION_UPDATE                                         0x2013
#define HCI_LE_SET_HOST_CHANNEL_CLASSIFICATION                           0x2014
#define HCI_LE_READ_CHANNEL_MAP                                          0x2015
#define HCI_LE_READ_REMOTE_FEATURES                                      0x2016
#define HCI_LE_ENCRYPT                                                   0x2017
#define HCI_LE_RAND                                                      0x2018
#define HCI_LE_ENABLE_ENCRYPTION                                         0x2019
#define HCI_LE_LONG_TERM_KEY_REQUEST_REPLY                               0x201A
#define HCI_LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY                      0x201B
#define HCI_LE_READ_SUPPORTED_STATES                                     0x201C
#define HCI_LE_RECEIVER_TEST_V3                                          0x204F
#define HCI_LE_RECEIVER_TEST_V2                                          0x2033
#define HCI_LE_RECEIVER_TEST_V1                                          0x201D
#define HCI_LE_TRANSMITTER_TEST_V4                                       0x207B
#define HCI_LE_TRANSMITTER_TEST_V3                                       0x2050
#define HCI_LE_TRANSMITTER_TEST_V2                                       0x2034
#define HCI_LE_TRANSMITTER_TEST_V1                                       0x201E
#define HCI_LE_TEST_END                                                  0x201F
#define HCI_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY                 0x2020
#define HCI_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY        0x2021
#define HCI_LE_SET_DATA_LENGTH                                           0x2022
#define HCI_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH                        0x2023
#define HCI_LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH                       0x2024
#define HCI_LE_READ_LOCAL_P_256_PUBLIC_KEY                               0x2025
#define HCI_LE_GENERATE_DHKEY_V2                                         0x205E
#define HCI_LE_GENERATE_DHKEY_V1                                         0x2026
#define HCI_LE_ADD_DEVICE_TO_RESOLVING_LIST                              0x2027
#define HCI_LE_REMOVE_DEVICE_FROM_RESOLVING_LIST                         0x2028
#define HCI_LE_CLEAR_RESOLVING_LIST                                      0x2029
#define HCI_LE_READ_RESOLVING_LIST_SIZE                                  0x202A
#define HCI_LE_READ_PEER_RESOLVABLE_ADDRESS                              0x202B
#define HCI_LE_READ_LOCAL_RESOLVABLE_ADDRESS                             0x202C
#define HCI_LE_SET_ADDRESS_RESOLUTION_ENABLE                             0x202D
#define HCI_LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT                    0x202E
#define HCI_LE_READ_MAXIMUM_DATA_LENGTH                                  0x202F
#define HCI_LE_READ_PHY                                                  0x2030
#define HCI_LE_SET_DEFAULT_PHY                                           0x2031
#define HCI_LE_SET_PHY                                                   0x2032
#define HCI_LE_SET_ADVERTISING_SET_RANDOM_ADDRESS                        0x2035
#define HCI_LE_SET_EXTENDED_ADVERTISING_PARAMETERS                       0x2036
#define HCI_LE_SET_EXTENDED_ADVERTISING_DATA                             0x2037
#define HCI_LE_SET_EXTENDED_SCAN_RESPONSE_DATA                           0x2038
#define HCI_LE_SET_EXTENDED_ADVERTISING_ENABLE                           0x2039
#define HCI_LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH                      0x203A
#define HCI_LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS                 0x203B
#define HCI_LE_REMOVE_ADVERTISING_SET                                    0x203C
#define HCI_LE_CLEAR_ADVERTISING_SETS                                    0x203D
#define HCI_LE_SET_PERIODIC_ADVERTISING_PARAMETERS                       0x203E
#define HCI_LE_SET_PERIODIC_ADVERTISING_DATA                             0x203F
#define HCI_LE_SET_PERIODIC_ADVERTISING_ENABLE                           0x2040
#define HCI_LE_SET_EXTENDED_SCAN_PARAMETERS                              0x2041
#define HCI_LE_SET_EXTENDED_SCAN_ENABLE                                  0x2042
#define HCI_LE_EXTENDED_CREATE_CONNECTION                                0x2043
#define HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC                          0x2044
#define HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL                   0x2045
#define HCI_LE_PERIODIC_ADVERTISING_TERMINATE_SYNC                       0x2046
#define HCI_LE_ADD_DEVICE_TO_PERIODIC_ADVERTISER_LIST                    0x2047
#define HCI_LE_REMOVE_DEVICE_FROM_PERIODIC_ADVERTISER_LIST               0x2048
#define HCI_LE_CLEAR_PERIODIC_ADVERTISER_LIST                            0x2049
#define HCI_LE_READ_PERIODIC_ADVERTISER_LIST_SIZE                        0x204A
#define HCI_LE_READ_TRANSMIT_POWER                                       0x204B
#define HCI_LE_READ_RF_PATH_COMPENSATION                                 0x204C
#define HCI_LE_WRITE_RF_PATH_COMPENSATION                                0x204D
#define HCI_LE_SET_PRIVACY_MODE                                          0x204E
#define HCI_LE_SET_CONNECTIONLESS_CTE_TRANSMIT_PARAMETERS                0x2051
#define HCI_LE_SET_CONNECTIONLESS_CTE_TRANSMIT_ENABLE                    0x2052
#define HCI_LE_SET_CONNECTIONLESS_IQ_SAMPLING_ENABLE                     0x2053
#define HCI_LE_SET_CONNECTION_CTE_RECEIVE_PARAMETERS                     0x2054
#define HCI_LE_SET_CONNECTION_CTE_TRANSMIT_PARAMETERS                    0x2055
#define HCI_LE_CONNECTION_CTE_REQUEST_ENABLE                             0x2056
#define HCI_LE_CONNECTION_CTE_RESPONSE_ENABLE                            0x2057
#define HCI_LE_READ_ANTENNA_INFORMATION                                  0x2058
#define HCI_LE_SET_PERIODIC_ADVERTISING_RECEIVE_ENABLE                   0x2059
#define HCI_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER                        0x205A
#define HCI_LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER                    0x205B
#define HCI_LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS         0x205C
#define HCI_LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS 0x205D
#define HCI_LE_MODIFY_SLEEP_CLOCK_ACCURACY                               0x205F
#define HCI_LE_READ_ISO_TX_SYNC                                          0x2061
#define HCI_LE_SET_CIG_PARAMETERS                                        0x2062
#define HCI_LE_SET_CIG_PARAMETERS_TEST                                   0x2063
#define HCI_LE_CREATE_CIS                                                0x2064
#define HCI_LE_REMOVE_CIG                                                0x2065
#define HCI_LE_ACCEPT_CIS_REQUEST                                        0x2066
#define HCI_LE_REJECT_CIS_REQUEST                                        0x2067
#define HCI_LE_CREATE_BIG                                                0x2068
#define HCI_LE_CREATE_BIG_TEST                                           0x2069
#define HCI_LE_TERMINATE_BIG                                             0x206A
#define HCI_LE_BIG_CREATE_SYNC                                           0x206B
#define HCI_LE_BIG_TERMINATE_SYNC                                        0x206C
#define HCI_LE_REQUEST_PEER_SCA                                          0x206D
#define HCI_LE_SETUP_ISO_DATA_PATH                                       0x206E
#define HCI_LE_REMOVE_ISO_DATA_PATH                                      0x206F
#define HCI_LE_ISO_TRANSMIT_TEST                                         0x2070
#define HCI_LE_ISO_RECEIVE_TEST                                          0x2071
#define HCI_LE_ISO_READ_TEST_COUNTERS                                    0x2072
#define HCI_LE_ISO_TEST_END                                              0x2073
#define HCI_LE_SET_HOST_FEATURE                                          0x2074
#define HCI_LE_READ_ISO_LINK_QUALITY                                     0x2075
#define HCI_LE_ENHANCED_READ_TRANSMIT_POWER_LEVEL                        0x2076
#define HCI_LE_READ_REMOTE_TRANSMIT_POWER_LEVEL                          0x2077
#define HCI_LE_SET_PATH_LOSS_REPORTING_PARAMETERS                        0x2078
#define HCI_LE_SET_PATH_LOSS_REPORTING_ENABLE                            0x2079
#define HCI_LE_SET_TRANSMIT_POWER_REPORTING_ENABLE                       0x207A
#define HCI_LE_SET_DATA_RELATED_ADDRESS_CHANGES                          0x207C
#define HCI_LE_SET_DEFAULT_SUBRATE                                       0x207D
#define HCI_LE_SUBRATE_REQUEST                                           0x207E

// 7.1.6 HCI_Disconnect 0x0406
struct hci_disconnect {
    uint16_t connection_handle;
    uint8_t reason;
} __PACKED;

// 7.1.23 Read Remote Version Information command 0x041D
struct hci_read_remote_version_information {
    uint16_t connection_handle;
} __PACKED;

// 7.3.1 HCI_Set_Event_Mask 0x0C01
struct hci_set_event_mask {
    uint8_t event_mask[8];
} __PACKED;

// 7.3.2 HCI_Reset 0x0C03
struct hci_reset {
    uint8_t dummy[0];
};

// 7.3.3 HCI_Set_Event_Filter 0x0C05
struct hci_set_event_filter {
    uint8_t filter_type;
    uint8_t filter_condition_type;
    uint8_t condition;
} __PACKED;

// 7.3.78 HCI_Read_LE_Host_Support 0x0C6C
struct hci_read_le_host_support {
    uint8_t dummy[0];
};

// 7.3.79 HCI_Write_LE_Host_Support 0x0C6D
struct hci_write_le_host_support {
    uint8_t le_supported_host;
    uint8_t unused;
} __PACKED;

// 7.4.1 HCI_Read_Local_Version_Information 0x1001
struct hci_read_local_version_information {
    uint8_t dummy[0];
};

// 7.4.2 HCI_Read_Local_Supported_Commands 0x1002
struct hci_read_local_supported_commands {
    uint8_t dummy[0];
};

// 7.4.3 HCI_Read_Local_Supported_Features 0x1003
struct hci_read_local_supported_features {
    uint8_t dummy[0];
};

// 7.4.4 HCI_Read_Local_Extended_Features 0x1004
struct hci_read_local_extended_features {
    uint8_t page_number;
} __PACKED;

// 7.4.5 HCI_Read_Buffer_Size 0x1005
struct hci_read_buffer_size {
    uint8_t dummy[0];
};

// 7.4.6 HCI_Read_BD_ADDR 0x1009
struct hci_read_bd_addr {
    uint8_t dummy[0];
};

// 7.4.10 HCI_Read_Local_Supported_Codec_Capabilities 0x100E
struct hci_read_local_supported_codec_capabilities {
    uint8_t codec_id[5];
    uint8_t logical_transport_type;
    uint8_t direction;
} __PACKED;

// 7.4.11 HCI_Read_Local_Supported_Controller_Delay 0x100F
struct hci_read_local_supported_controller_delay {
    uint8_t codec_id[5];
    uint8_t logical_transport_type;
    uint8_t direction;
    uint8_t codec_configuration_length;
    uint8_t codec_configuration[128];
};

// 7.5.4 Read RSSI command 0x1405
struct hci_read_rssi {
    uint16_t connection_handle;
} __PACKED;

// 7.8.1 HCI_LE_Set_Event_Mask 0x2001
struct hci_le_set_event_mask {
    uint8_t le_event_mask[8];
} __PACKED;

// 7.8.2 HCI_LE_Read_Buffer_Size[v2] 0x2060
struct hci_le_read_buffer_size_v2 {
    uint8_t dummy[0];
};

// 7.8.2 HCI_LE_Read_Buffer_Size[v1] 0x2002
struct hci_le_read_buffer_size_v1 {
    uint8_t dummy[0];
};

// 7.8.3 HCI_LE_Read_Local_Supported_Features 0x2003
struct hci_le_read_local_supported_features {
    uint8_t dummy[0];
};

// 7.8.4 HCI_LE_Set_Random_Address 0x2005
struct hci_le_set_random_address {
    uint8_t random_address[6];
} __PACKED;

// 7.8.5 HCI_LE_Set_Advertising_Parameters 0x2006
struct hci_le_set_advertising_parameters {
    uint16_t advertising_interval_min;
    uint16_t advertising_interval_max;
    uint8_t advertising_type;
    uint8_t own_address_type;
    uint8_t peer_address_type;
    uint8_t peer_address[6];
    uint8_t advertising_channel_map;
    uint8_t advertising_filter_policy;
} __PACKED;

// 7.8.6 HCI_LE_Read_Advertising_Channel_Tx_Power 0x2007
struct hci_le_read_advertising_channel_tx_power {
    uint8_t dummy[0];
};

// 7.8.7 HCI_LE_Set_Advertising_Data 0x2008
struct hci_le_set_advertising_data {
    uint8_t advertising_data_length;
    uint8_t advertising_data[31];
} __PACKED;

// 7.8.8 HCI_LE_Set_Scan_Response_Data 0x2009
struct hci_le_set_scan_response_data {
    uint8_t scan_response_data_length;
    uint8_t scan_response_data[31];
} __PACKED;

// 7.8.9 HCI_LE_Set_Advertising_Enable 0x200A
struct hci_le_set_advertising_enable {
    uint8_t advertising_enable;
} __PACKED;

// 7.8.10 HCI_LE_Set_Scan_Parameters 0x200B
struct hci_le_set_scan_parameters {
    uint8_t le_scan_type;
    uint16_t le_scan_interval;
    uint16_t le_scan_window;
    uint8_t own_address_type;
    uint8_t scanning_filter_policy;
} __PACKED;

// 7.8.11 HCI_LE_Set_Scan_Enable 0x200C
struct hci_le_set_scan_enable {
    uint8_t le_scan_enable;
    uint8_t filter_duplicates;
} __PACKED;

// 7.8.12 HCI_LE_Create_Connection 0x200D
struct hci_le_create_connection {
    uint16_t le_scan_interval;
    uint16_t le_scan_window;
    uint8_t initiator_filter_policy;
    uint8_t peer_address_type;
    uint8_t peer_address[6];
    uint8_t own_address_type;
    uint16_t connection_interval_min;
    uint16_t connection_interval_max;
    uint16_t max_latency;
    uint16_t supervision_timeout;
    uint16_t min_ce_length;
    uint16_t max_ce_length;
} __PACKED;

// 7.8.13 HCI_LE_Create_Connection_Cancel 0x200E
struct hci_le_create_connection_cancel {
    uint8_t dummy[0];
};

// 7.8.14 HCI_LE_Read_Filter_Accept_List_Size 0x200F
struct hci_le_read_filter_accept_list_size {
    uint8_t dummy[0];
};

// 7.8.15 HCI_LE_Clear_Filter_Accept_List 0x2010
struct hci_le_clear_filter_accept_list {
    uint8_t dummy[0];
};

// 7.8.16 HCI_LE_Add_Device_To_Filter_Accept_List 0x2011
struct hci_le_add_device_to_filter_accept_list {
    uint8_t address_type;
    uint8_t address[6];
} __PACKED;

// 7.8.17 HCI_LE_Remove_Device_From_Filter_Accept_List 0x2012
struct hci_le_remove_device_from_filter_accept_list {
    uint8_t address_type;
    uint8_t address[6];
} __PACKED;

// 7.8.18 HCI_LE_Connection_Update 0x2013
struct hci_le_connection_update {
    uint16_t connection_handle;
    uint16_t connection_interval_min;
    uint16_t connection_interval_max;
    uint16_t max_latency;
    uint16_t supervision_timeout;
    uint16_t min_ce_length;
    uint16_t max_ce_length;
} __PACKED;

// 7.8.19 HCI_LE_Set_Host_Channel_Classification 0x2014
struct hci_le_set_host_channel_classification {
    uint8_t channel_map[5];
} __PACKED;

// 7.8.20 HCI_LE_Read_Channel_Map 0x2015
struct hci_le_read_channel_map {
    uint16_t connection_handle;
} __PACKED;

// 7.8.21 HCI_LE_Read_Remote_Features 0x2016
struct hci_le_read_remote_features {
    uint16_t connection_handle;
} __PACKED;

// 7.8.22 HCI_LE_Encrypt 0x2017
struct hci_le_encrypt {
    uint8_t key[16];
    uint8_t plaintext_data[16];
} __PACKED;

// 7.8.23 HCI_LE_Rand 0x2018
struct hci_le_rand {
    uint8_t dummy[0];
};

// 7.8.24 HCI_LE_Enable_Encryption 0x2019
struct hci_le_enable_encryption {
    uint16_t connection_handle;
    uint8_t random_number[8];
    uint16_t encrypted_diversifier;
    uint8_t long_term_key[16];
} __PACKED;

// 7.8.25 HCI_LE_Long_Term_Key_Request_Reply 0x201A
struct hci_le_long_term_key_request_reply {
    uint16_t connection_handle;
    uint8_t long_term_key[16];
} __PACKED;

// 7.8.26 HCI_LE_Long_Term_Key_Request_Negative_Reply 0x201B
struct hci_le_long_term_key_request_negative_reply {
    uint16_t connection_handle;
} __PACKED;

// 7.8.27 HCI_LE_Read_Supported_States 0x201C
struct hci_le_read_supported_states {
    uint8_t dummy[0];
};

// 7.8.28 HCI_LE_Receiver_Test[v3] 0x204F
struct hci_le_receiver_test_v3 {
    uint8_t rx_channel;
    uint8_t phy;
    uint8_t modulation_index;
    uint8_t expected_cte_length;
    uint8_t expected_cte_type;
    uint8_t slot_durations;
    uint8_t switching_pattern_length;
    uint8_t antenna_ids[32];
} __PACKED;

// 7.8.28 HCI_LE_Receiver_Test[v2] 0x2033
struct hci_le_receiver_test_v2 {
    uint8_t rx_channel;
    uint8_t phy;
    uint8_t modulation_index;
} __PACKED;

// 7.8.28 HCI_LE_Receiver_Test[v1] 0x201D
struct hci_le_receiver_test_v1 {
    uint8_t rx_channel;
} __PACKED;

// 7.8.29 HCI_LE_Transmitter_Test[v4] 0x207B (CUSTOM)
struct hci_le_transmitter_test_v4 {
    uint8_t tx_channel;
    uint8_t test_data_length;
    uint8_t packet_payload;
    uint8_t phy;
    uint8_t cte_length;
    uint8_t cte_type;
    uint8_t switching_pattern_length;
    uint8_t tx_power_level;
    uint8_t antenna_ids[32];
} __PACKED;

// 7.8.29 HCI_LE_Transmitter_Test[v3] 0x2050
struct hci_le_transmitter_test_v3 {
    uint8_t tx_channel;
    uint8_t test_data_length;
    uint8_t packet_payload;
    uint8_t phy;
    uint8_t cte_length;
    uint8_t cte_type;
    uint8_t switching_pattern_length;
    uint8_t antenna_ids[32];
} __PACKED;

// 7.8.29 HCI_LE_Transmitter_Test[v2] 0x2034
struct hci_le_transmitter_test_v2 {
    uint8_t tx_channel;
    uint8_t test_data_length;
    uint8_t packet_payload;
    uint8_t phy;
} __PACKED;

// 7.8.29 HCI_LE_Transmitter_Test[v1] 0x201E
struct hci_le_transmitter_test_v1 {
    uint8_t tx_channel;
    uint8_t test_data_length;
    uint8_t packet_payload;
} __PACKED;

// 7.8.30 HCI_LE_Test_End 0x201F
struct hci_le_test_end {
    uint8_t dummy[0];
};

// 7.8.31 HCI_LE_Remote_Connection_Parameter_Request_Reply 0x2020
struct hci_le_remote_connection_parameter_request_reply {
    uint16_t connection_handle;
    uint16_t interval_min;
    uint16_t interval_max;
    uint16_t max_latency;
    uint16_t timeout;
    uint16_t min_ce_length;
    uint16_t max_ce_length;
} __PACKED;

// 7.8.32 HCI_LE_Remote_Connection_Parameter_Request_Negative_Reply 0x2021
struct hci_le_remote_connection_parameter_request_negative_reply {
    uint16_t connection_handle;
    uint8_t reason;
} __PACKED;

// 7.8.33 HCI_LE_Set_Data_Length 0x2022
struct hci_le_set_data_length {
    uint16_t connection_handle;
    uint16_t tx_octets;
    uint16_t tx_time;
} __PACKED;

// 7.8.34 HCI_LE_Read_Suggested_Default_Data_Length 0x2023
struct hci_le_read_suggested_default_data_length {
    uint8_t dummy[0];
};

// 7.8.35 HCI_LE_Write_Suggested_Default_Data_Length 0x2024
struct hci_le_write_suggested_default_data_length {
    uint16_t suggested_max_tx_octets;
    uint16_t suggested_max_tx_time;
} __PACKED;

// 7.8.36 HCI_LE_Read_Local_P_256_Public_Key 0x2025
struct hci_le_read_local_p_256_public_key {
    uint8_t dummy[0];
};

// 7.8.37 HCI_LE_Generate_DHKey[v2] 0x205E
struct hci_le_generate_dhkey_v2 {
    uint8_t key_x_coordinate[32];
    uint8_t key_y_coordinate[32];
    uint8_t key_type;
} __PACKED;

// 7.8.37 HCI_LE_Generate_DHKey[v1] 0x2026
struct hci_le_generate_dhkey_v1 {
    uint8_t key_x_coordinate[32];
    uint8_t key_y_coordinate[32];
} __PACKED;

// 7.8.38 HCI_LE_Add_Device_To_Resolving_List 0x2027
struct hci_le_add_device_to_resolving_list {
    uint8_t peer_identity_address_type;
    uint8_t peer_identity_address[6];
    uint8_t peer_irk[16];
    uint8_t local_irk[16];
} __PACKED;

// 7.8.39 HCI_LE_Remove_Device_From_Resolving_List 0x2028
struct hci_le_remove_device_from_resolving_list {
    uint8_t peer_identity_address_type;
    uint8_t peer_identity_address[6];
} __PACKED;

// 7.8.40 HCI_LE_Clear_Resolving_List 0x2029
struct hci_le_clear_resolving_list {
    uint8_t dummy[0];
};

// 7.8.41 HCI_LE_Read_Resolving_List_Size 0x202A
struct hci_le_read_resolving_list_size {
    uint8_t dummy[0];
};

// 7.8.42 HCI_LE_Read_Peer_Resolvable_Address 0x202B
struct hci_le_read_peer_resolvable_address {
    uint8_t peer_identity_address_type;
    uint8_t peer_identity_address[6];
} __PACKED;

// 7.8.43 HCI_LE_Read_Local_Resolvable_Address 0x202C
struct hci_le_read_local_resolvable_address {
    uint8_t peer_identity_address_type;
    uint8_t peer_identity_address[6];
} __PACKED;

// 7.8.44 HCI_LE_Set_Address_Resolution_Enable 0x202D
struct hci_le_set_address_resolution_enable {
    uint8_t address_resolution_enable;
} __PACKED;

// 7.8.45 HCI_LE_Set_Resolvable_Private_Address_Timeout 0x202E
struct hci_le_set_resolvable_private_address_timeout {
    uint16_t rpa_timeout;
} __PACKED;

// 7.8.46 HCI_LE_Read_Maximum_Data_Length 0x202F
struct hci_le_read_maximum_data_length {
    uint8_t dummy[0];
};

// 7.8.47 HCI_LE_Read_PHY 0x2030
struct hci_le_read_phy {
    uint16_t connection_handle;
} __PACKED;

// 7.8.48 HCI_LE_Set_Default_PHY 0x2031
struct hci_le_set_default_phy {
    uint8_t all_phys;
    uint8_t tx_phys;
    uint8_t rx_phys;
} __PACKED;

// 7.8.49 HCI_LE_Set_PHY 0x2032
struct hci_le_set_phy {
    uint16_t connection_handle;
    uint8_t all_phys;
    uint8_t tx_phys;
    uint8_t rx_phys;
    uint16_t phy_options;
} __PACKED;

// 7.8.52 HCI_LE_Set_Advertising_Set_Random_Address 0x2035
struct hci_le_set_advertising_set_random_address {
    uint8_t advertising_handle;
    uint8_t random_address[6];
} __PACKED;

// 7.8.53 HCI_LE_Set_Extended_Advertising_Parameters 0x2036
struct hci_le_set_extended_advertising_parameters {
    uint8_t advertising_handle;
    uint64_t advertising_event_properties: 16;
    uint64_t primary_advertising_interval_min: 24;
    uint64_t primary_advertising_interval_max: 24;
    uint8_t primary_advertising_channel_map;
    uint8_t own_address_type;
    uint8_t peer_address_type;
    uint8_t peer_address[6];
    uint8_t advertising_filter_policy;
    uint8_t advertising_tx_power;
    uint8_t primary_advertising_phy;
    uint8_t secondary_advertising_max_skip;
    uint8_t secondary_advertising_phy;
    uint8_t advertising_sid;
    uint8_t scan_request_notification_enable;
} __PACKED;

// 7.8.54 HCI_LE_Set_Extended_Advertising_Data 0x2037
struct hci_le_set_extended_advertising_data {
    uint8_t advertising_handle;
    uint8_t operation;
    uint8_t fragment_preference;
    uint8_t advertising_data_length;
    uint8_t advertising_data[31];
} __PACKED;

// 7.8.55 HCI_LE_Set_Extended_Scan_Response_Data 0x2038
struct hci_le_set_extended_scan_response_data {
    uint8_t advertising_handle;
    uint8_t operation;
    uint8_t fragment_preference;
    uint8_t scan_response_data_length;
    uint8_t scan_response_data[31];
} __PACKED;

// 7.8.56 HCI_LE_Set_Extended_Advertising_Enable 0x2039
struct hci_le_set_extended_advertising_enable {
    uint8_t enable;
    uint8_t num_sets;
    struct {
        uint8_t advertising_handle;
        uint16_t duration;
        uint8_t max_extended_advertising_events;
    } __PACKED params[8];
} __PACKED;

// 7.8.57 HCI_LE_Read_Maximum_Advertising_Data_Length 0x203A
struct hci_le_read_maximum_advertising_data_length {
    uint8_t dummy[0];
};

// 7.8.58 HCI_LE_Read_Number_of_Supported_Advertising_Sets 0x203B
struct hci_le_read_number_of_supported_advertising_sets {
    uint8_t dummy[0];
};

// 7.8.59 HCI_LE_Remove_Advertising_Set 0x203C
struct hci_le_remove_advertising_set {
    uint8_t advertising_handle;
} __PACKED;

// 7.8.60 HCI_LE_Clear_Advertising_Sets 0x203D
struct hci_le_clear_advertising_sets {
    uint8_t dummy[0];
};

// 7.8.61 HCI_LE_Set_Periodic_Advertising_Parameters 0x203E
struct hci_le_set_periodic_advertising_parameters {
    uint8_t advertising_handle;
    uint16_t periodic_advertising_interval_min;
    uint16_t periodic_advertising_interval_max;
    uint16_t periodic_advertising_properties;
} __PACKED;

// 7.8.62 HCI_LE_Set_Periodic_Advertising_Data 0x203F
struct hci_le_set_periodic_advertising_data {
    uint8_t advertising_handle;
    uint8_t operation;
    uint8_t advertising_data_length;
    uint8_t advertising_data[252];
} __PACKED;

// 7.8.63 HCI_LE_Set_Periodic_Advertising_Enable 0x2040
struct hci_le_set_periodic_advertising_enable {
    uint8_t enable;
    uint8_t advertising_handle;
} __PACKED;

// 7.8.64 HCI_LE_Set_Extended_Scan_Parameters 0x2041 (CUSTOM)
struct hci_le_set_extended_scan_parameters {
    uint8_t own_address_type;
    uint8_t scanning_filter_policy;
    uint8_t scanning_phys;
    struct {
        uint8_t scan_type;
        uint16_t scan_interval;
        uint16_t scan_window;
    } __PACKED phy_1m;
    struct {
        uint8_t scan_type;
        uint16_t scan_interval;
        uint16_t scan_window;
    } __PACKED phy_coded;
} __PACKED;

// 7.8.65 HCI_LE_Set_Extended_Scan_Enable 0x2042
struct hci_le_set_extended_scan_enable {
    uint8_t enable;
    uint8_t filter_duplicates;
    uint16_t duration;
    uint16_t period;
} __PACKED;

// 7.8.66 HCI_LE_Extended_Create_Connection 0x2043 (CUSTOM)
struct hci_le_extended_create_connection {
    uint8_t initiator_filter_policy;
    uint8_t own_address_type;
    uint8_t peer_address_type;
    uint8_t peer_address[6];
    uint8_t initiating_phys;
    struct {
        uint16_t scan_interval;
        uint16_t scan_window;
        uint16_t connection_interval_min;
        uint16_t connection_interval_max;
        uint16_t max_latency;
        uint16_t supervision_timeout;
        uint16_t min_ce_length;
        uint16_t max_ce_length;
    } __PACKED phy_1m;
    struct {
        uint16_t scan_interval;
        uint16_t scan_window;
        uint16_t connection_interval_min;
        uint16_t connection_interval_max;
        uint16_t max_latency;
        uint16_t supervision_timeout;
        uint16_t min_ce_length;
        uint16_t max_ce_length;
    } __PACKED phy_2m;
    struct {
        uint16_t scan_interval;
        uint16_t scan_window;
        uint16_t connection_interval_min;
        uint16_t connection_interval_max;
        uint16_t max_latency;
        uint16_t supervision_timeout;
        uint16_t min_ce_length;
        uint16_t max_ce_length;
    } __PACKED phy_coded;
} __PACKED;

// 7.8.67 HCI_LE_Periodic_Advertising_Create_Sync 0x2044
struct hci_le_periodic_advertising_create_sync {
    uint8_t options;
    uint8_t advertising_sid;
    uint8_t advertiser_address_type;
    uint8_t advertiser_address[6];
    uint16_t skip;
    uint16_t sync_timeout;
    uint8_t sync_cte_type;
} __PACKED;

// 7.8.68 HCI_LE_Periodic_Advertising_Create_Sync_Cancel 0x2045
struct hci_le_periodic_advertising_create_sync_cancel {
    uint8_t dummy[0];
};

// 7.8.69 HCI_LE_Periodic_Advertising_Terminate_Sync 0x2046
struct hci_le_periodic_advertising_terminate_sync {
    uint16_t sync_handle;
} __PACKED;

// 7.8.70 HCI_LE_Add_Device_To_Periodic_Advertiser_List 0x2047
struct hci_le_add_device_to_periodic_advertiser_list {
    uint8_t advertiser_address_type;
    uint8_t advertiser_address[6];
    uint8_t advertising_sid;
} __PACKED;

// 7.8.71 HCI_LE_Remove_Device_From_Periodic_Advertiser_List 0x2048
struct hci_le_remove_device_from_periodic_advertiser_list {
    uint8_t advertiser_address_type;
    uint8_t advertiser_address[6];
    uint8_t advertising_sid;
} __PACKED;

// 7.8.72 HCI_LE_Clear_Periodic_Advertiser_List 0x2049
struct hci_le_clear_periodic_advertiser_list {
    uint8_t dummy[0];
};

// 7.8.73 HCI_LE_Read_Periodic_Advertiser_List_Size 0x204A
struct hci_le_read_periodic_advertiser_list_size {
    uint8_t dummy[0];
};

// 7.8.74 HCI_LE_Read_Transmit_Power 0x204B
struct hci_le_read_transmit_power {
    uint8_t dummy[0];
};

// 7.8.75 HCI_LE_Read_RF_Path_Compensation 0x204C
struct hci_le_read_rf_path_compensation {
    uint8_t dummy[0];
};

// 7.8.76 HCI_LE_Write_RF_Path_Compensation 0x204D
struct hci_le_write_rf_path_compensation {
    uint16_t rf_tx_path_compensation_value;
    uint16_t rf_rx_path_compensation_value;
} __PACKED;

// 7.8.77 HCI_LE_Set_Privacy_Mode 0x204E
struct hci_le_set_privacy_mode {
    uint8_t peer_identity_address_type;
    uint8_t peer_identity_address[6];
    uint8_t privacy_mode;
} __PACKED;

// 7.8.80 HCI_LE_Set_Connectionless_CTE_Transmit_Parameters 0x2051
struct hci_le_set_connectionless_cte_transmit_parameters {
    uint8_t advertising_handle;
    uint8_t cte_length;
    uint8_t cte_type;
    uint8_t cte_count;
    uint8_t switching_pattern_length;
    uint8_t antenna_ids[32];
} __PACKED;

// 7.8.81 HCI_LE_Set_Connectionless_CTE_Transmit_Enable 0x2052
struct hci_le_set_connectionless_cte_transmit_enable {
    uint8_t advertising_handle;
    uint8_t cte_enable;
} __PACKED;

// 7.8.82 HCI_LE_Set_Connectionless_IQ_Sampling_Enable 0x2053
struct hci_le_set_connectionless_iq_sampling_enable {
    uint16_t sync_handle;
    uint8_t sampling_enable;
    uint8_t slot_durations;
    uint8_t max_sampled_ctes;
    uint8_t switching_pattern_length;
    uint8_t antenna_ids[32];
} __PACKED;

// 7.8.83 HCI_LE_Set_Connection_CTE_Receive_Parameters 0x2054
struct hci_le_set_connection_cte_receive_parameters {
    uint16_t connection_handle;
    uint8_t sampling_enable;
    uint8_t slot_durations;
    uint8_t switching_pattern_length;
    uint8_t antenna_ids[32];
} __PACKED;

// 7.8.84 HCI_LE_Set_Connection_CTE_Transmit_Parameters 0x2055
struct hci_le_set_connection_cte_transmit_parameters {
    uint16_t connection_handle;
    uint8_t cte_types;
    uint8_t switching_pattern_length;
    uint8_t antenna_ids[32];
} __PACKED;

// 7.8.85 HCI_LE_Connection_CTE_Request_Enable 0x2056
struct hci_le_connection_cte_request_enable {
    uint16_t connection_handle;
    uint8_t enable;
    uint16_t cte_request_interval;
    uint8_t requested_cte_length;
    uint8_t requested_cte_type;
} __PACKED;

// 7.8.86 HCI_LE_Connection_CTE_Response_Enable 0x2057
struct hci_le_connection_cte_response_enable {
    uint16_t connection_handle;
    uint8_t enable;
} __PACKED;

// 7.8.87 HCI_LE_Read_Antenna_Information 0x2058
struct hci_le_read_antenna_information {
    uint8_t dummy[0];
};

// 7.8.88 HCI_LE_Set_Periodic_Advertising_Receive_Enable 0x2059
struct hci_le_set_periodic_advertising_receive_enable {
    uint16_t sync_handle;
    uint8_t enable;
} __PACKED;

// 7.8.89 HCI_LE_Periodic_Advertising_Sync_Transfer 0x205A
struct hci_le_periodic_advertising_sync_transfer {
    uint16_t connection_handle;
    uint16_t service_data;
    uint16_t sync_handle;
} __PACKED;

// 7.8.90 HCI_LE_Periodic_Advertising_Set_Info_Transfer 0x205B
struct hci_le_periodic_advertising_set_info_transfer {
    uint16_t connection_handle;
    uint16_t service_data;
    uint8_t advertising_handle;
} __PACKED;

// 7.8.91 HCI_LE_Set_Periodic_Advertising_Sync_Transfer_Parameters 0x205C
struct hci_le_set_periodic_advertising_sync_transfer_parameters {
    uint16_t connection_handle;
    uint8_t mode;
    uint16_t skip;
    uint16_t sync_timeout;
    uint8_t cte_type;
} __PACKED;

// 7.8.92 HCI_LE_Set_Default_Periodic_Advertising_Sync_Transfer_Parameters 0x205D
struct hci_le_set_default_periodic_advertising_sync_transfer_parameters {
    uint8_t mode;
    uint16_t skip;
    uint16_t sync_timeout;
    uint8_t cte_type;
} __PACKED;

// 7.8.94 HCI_LE_Modify_Sleep_Clock_Accuracy 0x205F
struct hci_le_modify_sleep_clock_accuracy {
    uint8_t action;
} __PACKED;

// 7.8.96 HCI_LE_Read_ISO_TX_Sync 0x2061
struct hci_le_read_iso_tx_sync {
    uint16_t connection_handle;
} __PACKED;

// 7.8.97 HCI_LE_Set_CIG_Parameters 0x2062
struct hci_le_set_cig_parameters {
    uint32_t cig_id: 8;
    uint32_t sdu_interval_c_to_p: 24;
    uint32_t sdu_interval_p_to_c: 24;
    uint32_t worst_case_sca: 8;
    uint8_t packing;
    uint8_t framing;
    uint16_t max_transport_latency_c_to_p;
    uint16_t max_transport_latency_p_to_c;
    uint8_t cis_count;
    struct {
        uint8_t cis_id;
        uint16_t max_sdu_c_to_p;
        uint16_t max_sdu_p_to_c;
        uint8_t phy_c_to_p;
        uint8_t phy_p_to_c;
        uint8_t rtn_c_to_p;
        uint8_t rtn_p_to_c;
    } __PACKED params[16];
} __PACKED;

// 7.8.98 HCI_LE_Set_CIG_Parameters_Test 0x2063
struct hci_le_set_cig_parameters_test {
    uint32_t cig_id: 8;
    uint32_t sdu_interval_c_to_p: 24;
    uint32_t sdu_interval_p_to_c: 24;
    uint32_t ft_c_to_p: 8;
    uint8_t ft_p_to_c;
    uint16_t iso_interval;
    uint8_t worst_case_sca;
    uint8_t packing;
    uint8_t framing;
    uint8_t cis_count;
    struct {
        uint8_t cis_id;
        uint8_t nse;
        uint16_t max_sdu_c_to_p;
        uint16_t max_sdu_p_to_c;
        uint16_t max_pdu_c_to_p;
        uint16_t max_pdu_p_to_c;
        uint8_t phy_c_to_p;
        uint8_t phy_p_to_c;
        uint8_t bn_c_to_p;
        uint8_t bn_p_to_c;
    } __PACKED params[8];
} __PACKED;

// 7.8.99 HCI_LE_Create_CIS 0x2064
struct hci_le_create_cis {
    uint8_t cis_count;
    struct {
        uint16_t cis_connection_handle;
        uint16_t acl_connection_handle;
    } __PACKED params[16];
} __PACKED;

// 7.8.100 HCI_LE_Remove_CIG 0x2065
struct hci_le_remove_cig {
    uint8_t cig_id;
} __PACKED;

// 7.8.101 HCI_LE_Accept_CIS_Request 0x2066
struct hci_le_accept_cis_request {
    uint16_t connection_handle;
} __PACKED;

// 7.8.102 HCI_LE_Reject_CIS_Request 0x2067
struct hci_le_reject_cis_request {
    uint16_t connection_handle;
    uint8_t reason;
} __PACKED;

// 7.8.103 HCI_LE_Create_BIG 0x2068
struct hci_le_create_big {
    uint8_t big_handle;
    uint8_t advertising_handle;
    uint32_t num_bis: 8;
    uint32_t sdu_interval: 24;
    uint16_t max_sdu;
    uint16_t max_transport_latency;
    uint8_t rtn;
    uint8_t phy;
    uint8_t packing;
    uint8_t framing;
    uint8_t encryption;
    uint8_t broadcast_code[16];
} __PACKED;

// 7.8.104 HCI_LE_Create_BIG_Test 0x2069
struct hci_le_create_big_test {
    uint8_t big_handle;
    uint8_t advertising_handle;
    uint32_t num_bis: 8;
    uint32_t sdu_interval: 24;
    uint16_t iso_interval;
    uint8_t nse;
    uint16_t max_sdu;
    uint16_t max_pdu;
    uint8_t phy;
    uint8_t packing;
    uint8_t framing;
    uint8_t bn;
    uint8_t irc;
    uint8_t pto;
    uint8_t encryption;
    uint8_t broadcast_code[16];
} __PACKED;

// 7.8.105 HCI_LE_Terminate_BIG 0x206A
struct hci_le_terminate_big {
    uint8_t big_handle;
    uint8_t reason;
} __PACKED;

// 7.8.106 HCI_LE_BIG_Create_Sync 0x206B
struct hci_le_big_create_sync {
    uint8_t big_handle;
    uint16_t sync_handle;
    uint8_t encryption;
    uint8_t broadcast_code[16];
    uint8_t mse;
    uint16_t big_sync_timeout;
    uint8_t num_bis;
    uint8_t bis[16];
} __PACKED;

// 7.8.107 HCI_LE_BIG_Terminate_Sync 0x206C
struct hci_le_big_terminate_sync {
    uint8_t big_handle;
} __PACKED;

// 7.8.108 HCI_LE_Request_Peer_SCA 0x206D
struct hci_le_request_peer_sca {
    uint16_t connection_handle;
} __PACKED;

// 7.8.109 HCI_LE_Setup_ISO_Data_Path 0x206E
struct hci_le_setup_iso_data_path {
    uint16_t connection_handle;
    uint8_t data_path_direction;
    uint8_t data_path_id;
    uint8_t codec_id[5];
    uint32_t controller_delay: 24;
    uint32_t codec_configuration_length: 8;
    uint8_t codec_configuration[128];
} __PACKED;

// 7.8.110 HCI_LE_Remove_ISO_Data_Path 0x206F
struct hci_le_remove_iso_data_path {
    uint16_t connection_handle;
    uint8_t data_path_direction;
} __PACKED;

// 7.8.111 HCI_LE_ISO_Transmit_Test 0x2070
struct hci_le_iso_transmit_test {
    uint16_t connection_handle;
    uint8_t payload_type;
} __PACKED;

// 7.8.112 HCI_LE_ISO_Receive_Test 0x2071
struct hci_le_iso_receive_test {
    uint16_t connection_handle;
    uint8_t payload_type;
} __PACKED;

// 7.8.113 HCI_LE_ISO_Read_Test_Counters 0x2072
struct hci_le_iso_read_test_counters {
    uint16_t connection_handle;
} __PACKED;

// 7.8.114 HCI_LE_ISO_Test_End 0x2073
struct hci_le_iso_test_end {
    uint16_t connection_handle;
} __PACKED;

// 7.8.115 HCI_LE_Set_Host_Feature 0x2074
struct hci_le_set_host_feature {
    uint8_t bit_number;
    uint8_t bit_value;
} __PACKED;

// 7.8.116 HCI_LE_Read_ISO_Link_Quality 0x2075
struct hci_le_read_iso_link_quality {
    uint16_t connection_handle;
} __PACKED;

// 7.8.117 HCI_LE_Enhanced_Read_Transmit_Power_Level 0x2076
struct hci_le_enhanced_read_transmit_power_level {
    uint16_t connection_handle;
    uint8_t phy;
} __PACKED;

// 7.8.118 HCI_LE_Read_Remote_Transmit_Power_Level 0x2077
struct hci_le_read_remote_transmit_power_level {
    uint16_t connection_handle;
    uint8_t phy;
} __PACKED;

// 7.8.119 HCI_LE_Set_Path_Loss_Reporting_Parameters 0x2078
struct hci_le_set_path_loss_reporting_parameters {
    uint16_t connection_handle;
    uint8_t high_threshold;
    uint8_t high_hysteresis;
    uint8_t low_threshold;
    uint8_t low_hysteresis;
    uint16_t min_time_spent;
} __PACKED;

// 7.8.120 HCI_LE_Set_Path_Loss_Reporting_Enable 0x2079
struct hci_le_set_path_loss_reporting_enable {
    uint16_t connection_handle;
    uint8_t enable;
} __PACKED;

// 7.8.121 HCI_LE_Set_Transmit_Power_Reporting_Enable 0x207A
struct hci_le_set_transmit_power_reporting_enable {
    uint16_t connection_handle;
    uint8_t local_enable;
    uint8_t remote_enable;
} __PACKED;

// 7.8.122 HCI_LE_Set_Data_Related_Address_Changes 0x207C
struct hci_le_set_data_related_address_changes {
    uint8_t advertising_handle;
    uint8_t change_reasons;
} __PACKED;

// 7.8.123 HCI_LE_Set_Default_Subrate 0x207D
struct hci_le_set_default_subrate {
    uint16_t subrate_min;
    uint16_t subrate_max;
    uint16_t max_latency;
    uint16_t continuation_number;
    uint16_t supervision_timeout;
} __PACKED;

// 7.8.124 HCI_LE_Subrate_Request 0x207E
struct hci_le_subrate_request {
    uint16_t connection_handle;
    uint16_t subrate_min;
    uint16_t subrate_max;
    uint16_t max_latency;
    uint16_t continuation_number;
    uint16_t supervision_timeout;
} __PACKED;

#endif /* __EB_HCI_COMMAND_H__ */

