#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include "eb_hci.h"
// pack

struct eb_hci {
    struct eb_hci_cfg cfg;
    void *usr_data;
};

struct hci_pack {
    uint16_t opcode;
    uint16_t length;
    uint16_t custom_pack;
    uint8_t pack_len; // 0-fix pack, >0-zero array
    uint8_t pack_max;
};

struct evt_unpack {
    uint16_t evt_code;
    uint16_t length;
    uint16_t custom_unpack;
    uint16_t unpack_len; // 0-fix pack, >0-zero array
};

struct none {
    uint8_t dummy[0];
};

enum {
    NOR, // normal
    CUS, // custom
};

#define HCI_PACK(opcode, pack_type, pack_len, pack_max, type) { opcode, sizeof(struct type), pack_type, pack_len, pack_max }
#define EVT_UNPACK(evt_code, unpack_type, unpack_len, type) { evt_code, sizeof(struct type), unpack_type, unpack_len }
#define EVT_CMP_UNPACK(evt_code, unpack_type, unpack_len, type) { evt_code, sizeof(struct type), unpack_type, unpack_len }

const static struct hci_pack cmd_pack[] = {
    HCI_PACK(0x0406, NOR,   0,   0, hci_disconnect),
    HCI_PACK(0x041D, NOR,   0,   0, hci_read_remote_version_information),
    HCI_PACK(0x0C01, NOR,   0,   0, hci_set_event_mask),
    HCI_PACK(0x0C03, NOR,   0,   0, hci_reset),
    HCI_PACK(0x0C05, NOR,   0,   0, hci_set_event_filter),
    HCI_PACK(0x100E, NOR,   0,   0, hci_read_local_supported_codec_capabilities),
    HCI_PACK(0x100F, NOR,   1, 128, hci_read_local_supported_controller_delay),
    HCI_PACK(0x1405, NOR,   0,   0, hci_read_rssi),
    HCI_PACK(0x2001, NOR,   0,   0, hci_le_set_event_mask),
    HCI_PACK(0x2060, NOR,   0,   0, hci_le_read_buffer_size_v2),
    HCI_PACK(0x2002, NOR,   0,   0, hci_le_read_buffer_size_v1),
    HCI_PACK(0x2003, NOR,   0,   0, hci_le_read_local_supported_features),
    HCI_PACK(0x2005, NOR,   0,   0, hci_le_set_random_address),
    HCI_PACK(0x2006, NOR,   0,   0, hci_le_set_advertising_parameters),
    HCI_PACK(0x2007, NOR,   0,   0, hci_le_read_advertising_channel_tx_power),
    HCI_PACK(0x2008, NOR,   0,   0, hci_le_set_advertising_data),
    HCI_PACK(0x2009, NOR,   0,   0, hci_le_set_scan_response_data),
    HCI_PACK(0x200A, NOR,   0,   0, hci_le_set_advertising_enable),
    HCI_PACK(0x200B, NOR,   0,   0, hci_le_set_scan_parameters),
    HCI_PACK(0x200C, NOR,   0,   0, hci_le_set_scan_enable),
    HCI_PACK(0x200D, NOR,   0,   0, hci_le_create_connection),
    HCI_PACK(0x200E, NOR,   0,   0, hci_le_create_connection_cancel),
    HCI_PACK(0x200F, NOR,   0,   0, hci_le_read_filter_accept_list_size),
    HCI_PACK(0x2010, NOR,   0,   0, hci_le_clear_filter_accept_list),
    HCI_PACK(0x2011, NOR,   0,   0, hci_le_add_device_to_filter_accept_list),
    HCI_PACK(0x2012, NOR,   0,   0, hci_le_remove_device_from_filter_accept_list),
    HCI_PACK(0x2013, NOR,   0,   0, hci_le_connection_update),
    HCI_PACK(0x2014, NOR,   0,   0, hci_le_set_host_channel_classification),
    HCI_PACK(0x2015, NOR,   0,   0, hci_le_read_channel_map),
    HCI_PACK(0x2016, NOR,   0,   0, hci_le_read_remote_features),
    HCI_PACK(0x2017, NOR,   0,   0, hci_le_encrypt),
    HCI_PACK(0x2018, NOR,   0,   0, hci_le_rand),
    HCI_PACK(0x2019, NOR,   0,   0, hci_le_enable_encryption),
    HCI_PACK(0x201A, NOR,   0,   0, hci_le_long_term_key_request_reply),
    HCI_PACK(0x201B, NOR,   0,   0, hci_le_long_term_key_request_negative_reply),
    HCI_PACK(0x201C, NOR,   0,   0, hci_le_read_supported_states),
    HCI_PACK(0x204F, NOR,   1,  32, hci_le_receiver_test_v3),
    HCI_PACK(0x2033, NOR,   0,   0, hci_le_receiver_test_v2),
    HCI_PACK(0x201D, NOR,   0,   0, hci_le_receiver_test_v1),
    HCI_PACK(0x207B, CUS,   0,   0, hci_le_transmitter_test_v4),
    HCI_PACK(0x2050, NOR,   1,  32, hci_le_transmitter_test_v3),
    HCI_PACK(0x2034, NOR,   0,   0, hci_le_transmitter_test_v2),
    HCI_PACK(0x201E, NOR,   0,   0, hci_le_transmitter_test_v1),
    HCI_PACK(0x201F, NOR,   0,   0, hci_le_test_end),
    HCI_PACK(0x2020, NOR,   0,   0, hci_le_remote_connection_parameter_request_reply),
    HCI_PACK(0x2021, NOR,   0,   0, hci_le_remote_connection_parameter_request_negative_reply),
    HCI_PACK(0x2022, NOR,   0,   0, hci_le_set_data_length),
    HCI_PACK(0x2023, NOR,   0,   0, hci_le_read_suggested_default_data_length),
    HCI_PACK(0x2024, NOR,   0,   0, hci_le_write_suggested_default_data_length),
    HCI_PACK(0x2025, NOR,   0,   0, hci_le_read_local_p_256_public_key),
    HCI_PACK(0x205E, NOR,   0,   0, hci_le_generate_dhkey_v2),
    HCI_PACK(0x2026, NOR,   0,   0, hci_le_generate_dhkey_v1),
    HCI_PACK(0x2027, NOR,   0,   0, hci_le_add_device_to_resolving_list),
    HCI_PACK(0x2028, NOR,   0,   0, hci_le_remove_device_from_resolving_list),
    HCI_PACK(0x2029, NOR,   0,   0, hci_le_clear_resolving_list),
    HCI_PACK(0x202A, NOR,   0,   0, hci_le_read_resolving_list_size),
    HCI_PACK(0x202B, NOR,   0,   0, hci_le_read_peer_resolvable_address),
    HCI_PACK(0x202C, NOR,   0,   0, hci_le_read_local_resolvable_address),
    HCI_PACK(0x202D, NOR,   0,   0, hci_le_set_address_resolution_enable),
    HCI_PACK(0x202E, NOR,   0,   0, hci_le_set_resolvable_private_address_timeout),
    HCI_PACK(0x202F, NOR,   0,   0, hci_le_read_maximum_data_length),
    HCI_PACK(0x2030, NOR,   0,   0, hci_le_read_phy),
    HCI_PACK(0x2031, NOR,   0,   0, hci_le_set_default_phy),
    HCI_PACK(0x2032, NOR,   0,   0, hci_le_set_phy),
    HCI_PACK(0x2035, NOR,   0,   0, hci_le_set_advertising_set_random_address),
    HCI_PACK(0x2036, NOR,   0,   0, hci_le_set_extended_advertising_parameters),
    HCI_PACK(0x2037, NOR,   0,   0, hci_le_set_extended_advertising_data),
    HCI_PACK(0x2038, NOR,   0,   0, hci_le_set_extended_scan_response_data),
    HCI_PACK(0x2039, NOR,   4,   8, hci_le_set_extended_advertising_enable),
    HCI_PACK(0x203A, NOR,   0,   0, hci_le_read_maximum_advertising_data_length),
    HCI_PACK(0x203B, NOR,   0,   0, hci_le_read_number_of_supported_advertising_sets),
    HCI_PACK(0x203C, NOR,   0,   0, hci_le_remove_advertising_set),
    HCI_PACK(0x203D, NOR,   0,   0, hci_le_clear_advertising_sets),
    HCI_PACK(0x203E, NOR,   0,   0, hci_le_set_periodic_advertising_parameters),
    HCI_PACK(0x203F, NOR,   1, 252, hci_le_set_periodic_advertising_data),
    HCI_PACK(0x2040, NOR,   0,   0, hci_le_set_periodic_advertising_enable),
    HCI_PACK(0x2041, CUS,   0,   0, hci_le_set_extended_scan_parameters),
    HCI_PACK(0x2042, NOR,   0,   0, hci_le_set_extended_scan_enable),
    HCI_PACK(0x2043, CUS,   0,   0, hci_le_extended_create_connection),
    HCI_PACK(0x2044, NOR,   0,   0, hci_le_periodic_advertising_create_sync),
    HCI_PACK(0x2045, NOR,   0,   0, hci_le_periodic_advertising_create_sync_cancel),
    HCI_PACK(0x2046, NOR,   0,   0, hci_le_periodic_advertising_terminate_sync),
    HCI_PACK(0x2047, NOR,   0,   0, hci_le_add_device_to_periodic_advertiser_list),
    HCI_PACK(0x2048, NOR,   0,   0, hci_le_remove_device_from_periodic_advertiser_list),
    HCI_PACK(0x2049, NOR,   0,   0, hci_le_clear_periodic_advertiser_list),
    HCI_PACK(0x204A, NOR,   0,   0, hci_le_read_periodic_advertiser_list_size),
    HCI_PACK(0x204B, NOR,   0,   0, hci_le_read_transmit_power),
    HCI_PACK(0x204C, NOR,   0,   0, hci_le_read_rf_path_compensation),
    HCI_PACK(0x204D, NOR,   0,   0, hci_le_write_rf_path_compensation),
    HCI_PACK(0x204E, NOR,   0,   0, hci_le_set_privacy_mode),
    HCI_PACK(0x2051, NOR,   1,  32, hci_le_set_connectionless_cte_transmit_parameters),
    HCI_PACK(0x2052, NOR,   0,   0, hci_le_set_connectionless_cte_transmit_enable),
    HCI_PACK(0x2053, NOR,   1,  32, hci_le_set_connectionless_iq_sampling_enable),
    HCI_PACK(0x2054, NOR,   1,  32, hci_le_set_connection_cte_receive_parameters),
    HCI_PACK(0x2055, NOR,   1,  32, hci_le_set_connection_cte_transmit_parameters),
    HCI_PACK(0x2056, NOR,   0,   0, hci_le_connection_cte_request_enable),
    HCI_PACK(0x2057, NOR,   0,   0, hci_le_connection_cte_response_enable),
    HCI_PACK(0x2058, NOR,   0,   0, hci_le_read_antenna_information),
    HCI_PACK(0x2059, NOR,   0,   0, hci_le_set_periodic_advertising_receive_enable),
    HCI_PACK(0x205A, NOR,   0,   0, hci_le_periodic_advertising_sync_transfer),
    HCI_PACK(0x205B, NOR,   0,   0, hci_le_periodic_advertising_set_info_transfer),
    HCI_PACK(0x205C, NOR,   0,   0, hci_le_set_periodic_advertising_sync_transfer_parameters),
    HCI_PACK(0x205D, NOR,   0,   0, hci_le_set_default_periodic_advertising_sync_transfer_parameters),
    HCI_PACK(0x205F, NOR,   0,   0, hci_le_modify_sleep_clock_accuracy),
    HCI_PACK(0x2061, NOR,   0,   0, hci_le_read_iso_tx_sync),
    HCI_PACK(0x2062, NOR,   9,  16, hci_le_set_cig_parameters),
    HCI_PACK(0x2063, NOR,  14,   8, hci_le_set_cig_parameters_test),
    HCI_PACK(0x2064, NOR,   4,  16, hci_le_create_cis),
    HCI_PACK(0x2065, NOR,   0,   0, hci_le_remove_cig),
    HCI_PACK(0x2066, NOR,   0,   0, hci_le_accept_cis_request),
    HCI_PACK(0x2067, NOR,   0,   0, hci_le_reject_cis_request),
    HCI_PACK(0x2068, NOR,   0,   0, hci_le_create_big),
    HCI_PACK(0x2069, NOR,   0,   0, hci_le_create_big_test),
    HCI_PACK(0x206A, NOR,   0,   0, hci_le_terminate_big),
    HCI_PACK(0x206B, NOR,   1,  16, hci_le_big_create_sync),
    HCI_PACK(0x206C, NOR,   0,   0, hci_le_big_terminate_sync),
    HCI_PACK(0x206D, NOR,   0,   0, hci_le_request_peer_sca),
    HCI_PACK(0x206E, NOR,   1, 128, hci_le_setup_iso_data_path),
    HCI_PACK(0x206F, NOR,   0,   0, hci_le_remove_iso_data_path),
    HCI_PACK(0x2070, NOR,   0,   0, hci_le_iso_transmit_test),
    HCI_PACK(0x2071, NOR,   0,   0, hci_le_iso_receive_test),
    HCI_PACK(0x2072, NOR,   0,   0, hci_le_iso_read_test_counters),
    HCI_PACK(0x2073, NOR,   0,   0, hci_le_iso_test_end),
    HCI_PACK(0x2074, NOR,   0,   0, hci_le_set_host_feature),
    HCI_PACK(0x2075, NOR,   0,   0, hci_le_read_iso_link_quality),
    HCI_PACK(0x2076, NOR,   0,   0, hci_le_enhanced_read_transmit_power_level),
    HCI_PACK(0x2077, NOR,   0,   0, hci_le_read_remote_transmit_power_level),
    HCI_PACK(0x2078, NOR,   0,   0, hci_le_set_path_loss_reporting_parameters),
    HCI_PACK(0x2079, NOR,   0,   0, hci_le_set_path_loss_reporting_enable),
    HCI_PACK(0x207A, NOR,   0,   0, hci_le_set_transmit_power_reporting_enable),
    HCI_PACK(0x207C, NOR,   0,   0, hci_le_set_data_related_address_changes),
    HCI_PACK(0x207D, NOR,   0,   0, hci_le_set_default_subrate),
    HCI_PACK(0x207E, NOR,   0,   0, hci_le_subrate_request),
};

const static struct evt_unpack   evt_unpack[] = {
    EVT_UNPACK(0x05, NOR,  0, hci_disconnection_complete),
    EVT_UNPACK(0x0C, NOR,  0, hci_read_remote_version_information_complete),
    EVT_UNPACK(0x59, NOR,  0, hci_encryption_change_v2),
    EVT_UNPACK(0x08, NOR,  0, hci_encryption_change_v1),
    EVT_UNPACK(0x0E, CUS,  0, hci_command_complete),
    EVT_UNPACK(0x0F, NOR,  0, hci_command_status),
    EVT_UNPACK(0x10, NOR,  0, hci_hardware_error),
    EVT_UNPACK(0x13, NOR,  0, hci_number_of_completed_packets),
    EVT_UNPACK(0x30, NOR,  0, hci_encryption_key_refresh_complete),
    EVT_UNPACK(0x3E, CUS,  0, none),
};

const static struct evt_unpack   cmd_cmp_unpack[] = {
    EVT_CMP_UNPACK(0x0C01, NOR,  0, hci_set_event_mask_cmp),
    EVT_CMP_UNPACK(0x0C03, NOR,  0, hci_reset_cmp),
    EVT_CMP_UNPACK(0x100E, NOR,  0, hci_read_local_supported_codec_capabilities_cmp),
    EVT_CMP_UNPACK(0x100F, NOR,  0, hci_read_local_supported_controller_delay_cmp),
    EVT_CMP_UNPACK(0x1405, NOR,  0, hci_read_rssi_cmp),
    EVT_CMP_UNPACK(0x2001, NOR,  0, hci_le_set_event_mask_cmp),
    EVT_CMP_UNPACK(0x2060, NOR,  0, hci_le_read_buffer_size_v2_cmp),
    EVT_CMP_UNPACK(0x2002, NOR,  0, hci_le_read_buffer_size_v1_cmp),
    EVT_CMP_UNPACK(0x2003, NOR,  0, hci_le_read_local_supported_features_cmp),
    EVT_CMP_UNPACK(0x2005, NOR,  0, hci_le_set_random_address_cmp),
    EVT_CMP_UNPACK(0x2006, NOR,  0, hci_le_set_advertising_parameters_cmp),
    EVT_CMP_UNPACK(0x2007, NOR,  0, hci_le_read_advertising_channel_tx_power_cmp),
    EVT_CMP_UNPACK(0x2008, NOR,  0, hci_le_set_advertising_data_cmp),
    EVT_CMP_UNPACK(0x2009, NOR,  0, hci_le_set_scan_response_data_cmp),
    EVT_CMP_UNPACK(0x200A, NOR,  0, hci_le_set_advertising_enable_cmp),
    EVT_CMP_UNPACK(0x200B, NOR,  0, hci_le_set_scan_parameters_cmp),
    EVT_CMP_UNPACK(0x200C, NOR,  0, hci_le_set_scan_enable_cmp),
    EVT_CMP_UNPACK(0x200E, NOR,  0, hci_le_create_connection_cancel_cmp),
    EVT_CMP_UNPACK(0x200F, NOR,  0, hci_le_read_filter_accept_list_size_cmp),
    EVT_CMP_UNPACK(0x2010, NOR,  0, hci_le_clear_filter_accept_list_cmp),
    EVT_CMP_UNPACK(0x2011, NOR,  0, hci_le_add_device_to_filter_accept_list_cmp),
    EVT_CMP_UNPACK(0x2012, NOR,  0, hci_le_remove_device_from_filter_accept_list_cmp),
    EVT_CMP_UNPACK(0x2014, NOR,  0, hci_le_set_host_channel_classification_cmp),
    EVT_CMP_UNPACK(0x2015, NOR,  0, hci_le_read_channel_map_cmp),
    EVT_CMP_UNPACK(0x2017, NOR,  0, hci_le_encrypt_cmp),
    EVT_CMP_UNPACK(0x2018, NOR,  0, hci_le_rand_cmp),
    EVT_CMP_UNPACK(0x201A, NOR,  0, hci_le_long_term_key_request_reply_cmp),
    EVT_CMP_UNPACK(0x201B, NOR,  0, hci_le_long_term_key_request_negative_reply_cmp),
    EVT_CMP_UNPACK(0x201C, NOR,  0, hci_le_read_supported_states_cmp),
    EVT_CMP_UNPACK(0x204F, NOR,  0, hci_le_receiver_test_v3_cmp),
    EVT_CMP_UNPACK(0x2033, NOR,  0, hci_le_receiver_test_v2_cmp),
    EVT_CMP_UNPACK(0x201D, NOR,  0, hci_le_receiver_test_v1_cmp),
    EVT_CMP_UNPACK(0x207B, NOR,  0, hci_le_transmitter_test_v4_cmp),
    EVT_CMP_UNPACK(0x2050, NOR,  0, hci_le_transmitter_test_v3_cmp),
    EVT_CMP_UNPACK(0x2034, NOR,  0, hci_le_transmitter_test_v2_cmp),
    EVT_CMP_UNPACK(0x201E, NOR,  0, hci_le_transmitter_test_v1_cmp),
    EVT_CMP_UNPACK(0x201F, NOR,  0, hci_le_test_end_cmp),
    EVT_CMP_UNPACK(0x2020, NOR,  0, hci_le_remote_connection_parameter_request_reply_cmp),
    EVT_CMP_UNPACK(0x2021, NOR,  0, hci_le_remote_connection_parameter_request_negative_reply_cmp),
    EVT_CMP_UNPACK(0x2022, NOR,  0, hci_le_set_data_length_cmp),
    EVT_CMP_UNPACK(0x2023, NOR,  0, hci_le_read_suggested_default_data_length_cmp),
    EVT_CMP_UNPACK(0x2024, NOR,  0, hci_le_write_suggested_default_data_length_cmp),
    EVT_CMP_UNPACK(0x2027, NOR,  0, hci_le_add_device_to_resolving_list_cmp),
    EVT_CMP_UNPACK(0x2028, NOR,  0, hci_le_remove_device_from_resolving_list_cmp),
    EVT_CMP_UNPACK(0x2029, NOR,  0, hci_le_clear_resolving_list_cmp),
    EVT_CMP_UNPACK(0x202A, NOR,  0, hci_le_read_resolving_list_size_cmp),
    EVT_CMP_UNPACK(0x202B, NOR,  0, hci_le_read_peer_resolvable_address_cmp),
    EVT_CMP_UNPACK(0x202C, NOR,  0, hci_le_read_local_resolvable_address_cmp),
    EVT_CMP_UNPACK(0x202D, NOR,  0, hci_le_set_address_resolution_enable_cmp),
    EVT_CMP_UNPACK(0x202E, NOR,  0, hci_le_set_resolvable_private_address_timeout_cmp),
    EVT_CMP_UNPACK(0x202F, NOR,  0, hci_le_read_maximum_data_length_cmp),
    EVT_CMP_UNPACK(0x2030, NOR,  0, hci_le_read_phy_cmp),
    EVT_CMP_UNPACK(0x2031, NOR,  0, hci_le_set_default_phy_cmp),
    EVT_CMP_UNPACK(0x2035, NOR,  0, hci_le_set_advertising_set_random_address_cmp),
    EVT_CMP_UNPACK(0x2036, NOR,  0, hci_le_set_extended_advertising_parameters_cmp),
    EVT_CMP_UNPACK(0x2037, NOR,  0, hci_le_set_extended_advertising_data_cmp),
    EVT_CMP_UNPACK(0x2038, NOR,  0, hci_le_set_extended_scan_response_data_cmp),
    EVT_CMP_UNPACK(0x2039, NOR,  0, hci_le_set_extended_advertising_enable_cmp),
    EVT_CMP_UNPACK(0x203A, NOR,  0, hci_le_read_maximum_advertising_data_length_cmp),
    EVT_CMP_UNPACK(0x203B, NOR,  0, hci_le_read_number_of_supported_advertising_sets_cmp),
    EVT_CMP_UNPACK(0x203C, NOR,  0, hci_le_remove_advertising_set_cmp),
    EVT_CMP_UNPACK(0x203D, NOR,  0, hci_le_clear_advertising_sets_cmp),
    EVT_CMP_UNPACK(0x203E, NOR,  0, hci_le_set_periodic_advertising_parameters_cmp),
    EVT_CMP_UNPACK(0x203F, NOR,  0, hci_le_set_periodic_advertising_data_cmp),
    EVT_CMP_UNPACK(0x2040, NOR,  0, hci_le_set_periodic_advertising_enable_cmp),
    EVT_CMP_UNPACK(0x2041, NOR,  0, hci_le_set_extended_scan_parameters_cmp),
    EVT_CMP_UNPACK(0x2042, NOR,  0, hci_le_set_extended_scan_enable_cmp),
    EVT_CMP_UNPACK(0x2045, NOR,  0, hci_le_periodic_advertising_create_sync_cancel_cmp),
    EVT_CMP_UNPACK(0x2046, NOR,  0, hci_le_periodic_advertising_terminate_sync_cmp),
    EVT_CMP_UNPACK(0x2047, NOR,  0, hci_le_add_device_to_periodic_advertiser_list_cmp),
    EVT_CMP_UNPACK(0x2048, NOR,  0, hci_le_remove_device_from_periodic_advertiser_list_cmp),
    EVT_CMP_UNPACK(0x2049, NOR,  0, hci_le_clear_periodic_advertiser_list_cmp),
    EVT_CMP_UNPACK(0x204A, NOR,  0, hci_le_read_periodic_advertiser_list_size_cmp),
    EVT_CMP_UNPACK(0x204B, NOR,  0, hci_le_read_transmit_power_cmp),
    EVT_CMP_UNPACK(0x204C, NOR,  0, hci_le_read_rf_path_compensation_cmp),
    EVT_CMP_UNPACK(0x204D, NOR,  0, hci_le_write_rf_path_compensation_cmp),
    EVT_CMP_UNPACK(0x204E, NOR,  0, hci_le_set_privacy_mode_cmp),
    EVT_CMP_UNPACK(0x2051, NOR,  0, hci_le_set_connectionless_cte_transmit_parameters_cmp),
    EVT_CMP_UNPACK(0x2052, NOR,  0, hci_le_set_connectionless_cte_transmit_enable_cmp),
    EVT_CMP_UNPACK(0x2053, NOR,  0, hci_le_set_connectionless_iq_sampling_enable_cmp),
    EVT_CMP_UNPACK(0x2054, NOR,  0, hci_le_set_connection_cte_receive_parameters_cmp),
    EVT_CMP_UNPACK(0x2055, NOR,  0, hci_le_set_connection_cte_transmit_parameters_cmp),
    EVT_CMP_UNPACK(0x2056, NOR,  0, hci_le_connection_cte_request_enable_cmp),
    EVT_CMP_UNPACK(0x2057, NOR,  0, hci_le_connection_cte_response_enable_cmp),
    EVT_CMP_UNPACK(0x2058, NOR,  0, hci_le_read_antenna_information_cmp),
    EVT_CMP_UNPACK(0x2059, NOR,  0, hci_le_set_periodic_advertising_receive_enable_cmp),
    EVT_CMP_UNPACK(0x205A, NOR,  0, hci_le_periodic_advertising_sync_transfer_cmp),
    EVT_CMP_UNPACK(0x205B, NOR,  0, hci_le_periodic_advertising_set_info_transfer_cmp),
    EVT_CMP_UNPACK(0x205C, NOR,  0, hci_le_set_periodic_advertising_sync_transfer_parameters_cmp),
    EVT_CMP_UNPACK(0x205D, NOR,  0, hci_le_set_default_periodic_advertising_sync_transfer_parameters_cmp),
    EVT_CMP_UNPACK(0x205F, NOR,  0, hci_le_modify_sleep_clock_accuracy_cmp),
    EVT_CMP_UNPACK(0x2061, NOR,  0, hci_le_read_iso_tx_sync_cmp),
    EVT_CMP_UNPACK(0x2062, NOR,  0, hci_le_set_cig_parameters_cmp),
    EVT_CMP_UNPACK(0x2063, NOR,  0, hci_le_set_cig_parameters_test_cmp),
    EVT_CMP_UNPACK(0x2065, NOR,  0, hci_le_remove_cig_cmp),
    EVT_CMP_UNPACK(0x2067, NOR,  0, hci_le_reject_cis_request_cmp),
    EVT_CMP_UNPACK(0x206C, NOR,  0, hci_le_big_terminate_sync_cmp),
    EVT_CMP_UNPACK(0x206E, NOR,  0, hci_le_setup_iso_data_path_cmp),
    EVT_CMP_UNPACK(0x206F, NOR,  0, hci_le_remove_iso_data_path_cmp),
    EVT_CMP_UNPACK(0x2070, NOR,  0, hci_le_iso_transmit_test_cmp),
    EVT_CMP_UNPACK(0x2071, NOR,  0, hci_le_iso_receive_test_cmp),
    EVT_CMP_UNPACK(0x2072, NOR,  0, hci_le_iso_read_test_counters_cmp),
    EVT_CMP_UNPACK(0x2073, NOR,  0, hci_le_iso_test_end_cmp),
    EVT_CMP_UNPACK(0x2074, NOR,  0, hci_le_set_host_feature_cmp),
    EVT_CMP_UNPACK(0x2075, NOR,  0, hci_le_read_iso_link_quality_cmp),
    EVT_CMP_UNPACK(0x2076, NOR,  0, hci_le_enhanced_read_transmit_power_level_cmp),
    EVT_CMP_UNPACK(0x2078, NOR,  0, hci_le_set_path_loss_reporting_parameters_cmp),
    EVT_CMP_UNPACK(0x2079, NOR,  0, hci_le_set_path_loss_reporting_enable_cmp),
    EVT_CMP_UNPACK(0x207A, NOR,  0, hci_le_set_transmit_power_reporting_enable_cmp),
    EVT_CMP_UNPACK(0x207C, NOR,  0, hci_le_set_data_related_address_changes_cmp),
    EVT_CMP_UNPACK(0x207D, NOR,  0, hci_le_set_default_subrate_cmp),
};

const static struct evt_unpack   le_evt_unpack[] = {
    EVT_UNPACK(0x01, NOR,  0, hci_le_connection_complete),
    EVT_UNPACK(0x02, CUS,  0, hci_le_advertising_report),
    EVT_UNPACK(0x03, NOR,  0, hci_le_connection_update_complete),
    EVT_UNPACK(0x04, NOR,  0, hci_le_read_remote_features_complete),
    EVT_UNPACK(0x05, NOR,  0, hci_le_long_term_key_request),
    EVT_UNPACK(0x06, NOR,  0, hci_le_remote_connection_parameter_request),
    EVT_UNPACK(0x07, NOR,  0, hci_le_data_length_change),
    EVT_UNPACK(0x08, NOR,  0, hci_le_read_local_p_256_public_key_complete),
    EVT_UNPACK(0x09, NOR,  0, hci_le_generate_dhkey_complete),
    EVT_UNPACK(0x0A, NOR,  0, hci_le_enhanced_connection_complete),
    EVT_UNPACK(0x0B, NOR, 16, hci_le_directed_advertising_report),
    EVT_UNPACK(0x0C, NOR,  0, hci_le_phy_update_complete),
    EVT_UNPACK(0x0D, CUS,  0, hci_le_extended_advertising_report),
    EVT_UNPACK(0x0E, NOR,  0, hci_le_periodic_advertising_sync_established),
    EVT_UNPACK(0x0F, NOR,  0, hci_le_periodic_advertising_report),
    EVT_UNPACK(0x10, NOR,  0, hci_le_periodic_advertising_sync_lost),
    EVT_UNPACK(0x11, NOR,  0, hci_le_scan_timeout),
    EVT_UNPACK(0x12, NOR,  0, hci_le_advertising_set_terminated),
    EVT_UNPACK(0x13, NOR,  0, hci_le_scan_request_received),
    EVT_UNPACK(0x14, NOR,  0, hci_le_channel_selection_algorithm),
    EVT_UNPACK(0x15, NOR,  2, hci_le_connectionless_iq_report),
    EVT_UNPACK(0x16, NOR,  2, hci_le_connection_iq_report),
    EVT_UNPACK(0x17, NOR,  0, hci_le_cte_request_failed),
    EVT_UNPACK(0x18, NOR,  0, hci_le_periodic_advertising_sync_transfer_received),
    EVT_UNPACK(0x19, NOR,  0, hci_le_cis_established),
    EVT_UNPACK(0x1A, NOR,  0, hci_le_cis_request),
    EVT_UNPACK(0x1B, NOR,  2, hci_le_create_big_complete),
    EVT_UNPACK(0x1C, NOR,  0, hci_le_terminate_big_complete),
    EVT_UNPACK(0x1D, NOR,  2, hci_le_big_sync_established),
    EVT_UNPACK(0x1E, NOR,  0, hci_le_big_sync_lost),
    EVT_UNPACK(0x1F, NOR,  0, hci_le_request_peer_sca_complete),
    EVT_UNPACK(0x20, NOR,  0, hci_le_path_loss_threshold),
    EVT_UNPACK(0x21, NOR,  0, hci_le_transmit_power_reporting),
    EVT_UNPACK(0x22, NOR,  0, hci_le_biginfo_advertising_report),
    EVT_UNPACK(0x23, NOR,  0, hci_le_subrate_change),
};

// custom pack/unpack function define
static uint8_t *cus_pack_hci_le_transmitter_test_v4(uint16_t opcode, void *in, int *out_len);
static uint8_t *cus_pack_hci_le_set_extended_scan_parameters(uint16_t opcode, void *in, int *out_len);
static uint8_t *cus_pack_hci_le_extended_create_connection(uint16_t opcode, void *in, int *out_len);
static void cus_proc_hci_command_complete(struct eb_hci *hci, uint16_t evt_code, uint8_t *payload, int length);
static void cus_proc_le_event(struct eb_hci *hci, uint16_t evt_code, uint8_t *payload, int length);
static void cus_proc_hci_read_local_supported_codec_capabilities_cmp(struct eb_hci *hci, uint16_t opcode,
        uint8_t *payload, int length);
static void cus_proc_hci_le_advertising_report(struct eb_hci *hci, uint16_t evt_code, uint8_t *payload, int length);
static void cus_proc_hci_le_extended_advertising_report(struct eb_hci *hci, uint16_t evt_code, uint8_t *payload,
                                                        int length);

#define CUS_FUN(code, fun_name) \
    { code, fun_name }
struct {
    uint16_t opcode;
    uint8_t *(*pack)(uint16_t opcode, void *in, int *out_len);
} custom_pack_function [] = {
    CUS_FUN(0x207B, cus_pack_hci_le_transmitter_test_v4),
    CUS_FUN(0x2041, cus_pack_hci_le_set_extended_scan_parameters),
    CUS_FUN(0x2043, cus_pack_hci_le_extended_create_connection),
};

struct {
    uint16_t evt_code;
    void (*proc)(struct eb_hci *hci, uint16_t evt_code, uint8_t *payload, int length);
} custom_unpack_proc [] = {
    CUS_FUN(0x0E, cus_proc_hci_command_complete),
    CUS_FUN(0x3E, cus_proc_le_event),
};

struct {
    uint16_t opcode;
    void (*proc)(struct eb_hci *hci, uint16_t opcode, uint8_t *payload, int length);
} custom_cmd_cmp_proc [] = {
    CUS_FUN(0x100E, cus_proc_hci_read_local_supported_codec_capabilities_cmp),
};

struct {
    uint16_t evt_code;
    void (*proc)(struct eb_hci *hci, uint16_t evt_code, uint8_t *payload, int length);
} custom_le_unpack_proc [] = {
    CUS_FUN(0x02, cus_proc_hci_le_advertising_report),
    CUS_FUN(0x0D, cus_proc_hci_le_extended_advertising_report),
};

struct eb_hci *eb_hci_init(struct eb_hci_cfg *cfg, void *usr_data)
{
    EB_HCI_ASSERT(cfg);
    EB_HCI_ASSERT(cfg->send);
    EB_HCI_ASSERT(cfg->hci_proc_evt);
    EB_HCI_ASSERT(cfg->hci_proc_cmp);
    EB_HCI_ASSERT(cfg->hci_proc_le_evt);
    struct eb_hci *hci = EB_HCI_MALLOC(sizeof(struct eb_hci));
    EB_HCI_ASSERT(hci);
    hci->usr_data = usr_data;
    hci->cfg = *cfg;
    return hci;
}

static const struct hci_pack *get_cmd_pack(uint16_t opcode)
{
    size_t i;
    for (i = 0; i < sizeof(cmd_pack) / sizeof(cmd_pack[0]); i++) {
        if (cmd_pack[i].opcode == opcode) {
            return &cmd_pack[i];
        }
    }
    return NULL;
}

static uint8_t *custom_cmd_pack(const struct hci_pack *cmd_pack, void *payload, int *length)
{
    size_t i;
    for (i = 0; i < sizeof(custom_pack_function) / sizeof(custom_pack_function[0]); i++) {
        if (custom_pack_function[i].opcode == cmd_pack->opcode) {
            EB_HCI_ASSERT(custom_pack_function[i].pack);
            return custom_pack_function[i].pack(cmd_pack->opcode, payload, length);
        }
    }
    EB_HCI_ASSERT(0);
    return NULL;
}

static void eb_hci_send(struct eb_hci *hci, uint16_t opcode, uint8_t *data, int len)
{
    int payload_len = 4 + len;
    uint8_t *p = EB_HCI_MALLOC(payload_len);
    if (p) {
        uint8_t *payload = p;
        *payload++ = 0x01;
        *payload++ = (opcode >> 0) & 0xFF;
        *payload++ = (opcode >> 8) & 0xFF;
        *payload++ = len;
        memcpy(payload, data, len);
        hci->cfg.send(p, payload_len, hci->usr_data);
        EB_HCI_FREE(p);
    } else {
        EB_HCI_ASSERT(0);
    }
}

void eb_hci_cmd_send(struct eb_hci *hci,  uint16_t opcode, void *payload)
{
    const struct hci_pack *cmd_pack = get_cmd_pack(opcode);
    EB_HCI_ASSERT(cmd_pack);
    if (cmd_pack->custom_pack) {
        int payload_len;
        uint8_t *p = custom_cmd_pack(cmd_pack, payload, &payload_len);
        eb_hci_send(hci, opcode, p, payload_len);
        EB_HCI_FREE(p);
    } else {
        int payload_len;
        if (cmd_pack->pack_len) {
            uint8_t num_pack = *((uint8_t *)payload + cmd_pack->length - cmd_pack->pack_len * cmd_pack->pack_max - 1);
            EB_HCI_ASSERT(cmd_pack->pack_max >= num_pack);
            payload_len = cmd_pack->length - (cmd_pack->pack_max - num_pack) * cmd_pack->pack_len;
        } else {
            payload_len = cmd_pack->length;
        }
        EB_HCI_ASSERT(payload_len < (1 << (8 * sizeof(uint8_t))));
        eb_hci_send(hci, opcode, payload, payload_len);
    }
}

void eb_hci_vendor_send(struct eb_hci *hci, uint16_t opcode, uint8_t *data, int len)
{
    eb_hci_send(hci, opcode, data, len);
}
static const struct evt_unpack *get_unpack(uint16_t evt_code, const struct evt_unpack *unpack_list, size_t unpack_len)
{
    size_t i;
    for (i = 0; i < unpack_len; i++) {
        if (unpack_list[i].evt_code == evt_code) {
            return &unpack_list[i];
        }
    }
    return NULL;
}

void eb_evt_received(struct eb_hci *hci,  uint8_t evt_code, uint8_t *payload, int len)
{
    size_t unpack_len = sizeof(evt_unpack) / sizeof(evt_unpack[0]);
    const struct evt_unpack *unpack = get_unpack(evt_code, evt_unpack, unpack_len);
    if (unpack) {
        if (unpack->custom_unpack) {
            size_t i;
            for (i = 0; i < sizeof(custom_unpack_proc) / sizeof(custom_unpack_proc[0]); i++) {
                if (custom_unpack_proc[i].evt_code == unpack->evt_code) {
                    EB_HCI_ASSERT(custom_unpack_proc[i].proc);
                    custom_unpack_proc[i].proc(hci, unpack->evt_code, payload, len);
                    return;
                }
            }
            EB_HCI_ASSERT(0);
        } else {
            hci->cfg.hci_proc_evt(evt_code, payload, len, hci->usr_data);
            return;
        }
    } else if (hci->cfg.vendor_proc_list) {
        struct vendor_hci_evt_proc *proc = hci->cfg.vendor_proc_list;
        while (proc->vendor_proc) {
            if (proc->evt_code == evt_code) {
                proc->vendor_proc(evt_code, payload, len, hci->usr_data);
                return;
            }
            proc++;
        }
        EB_HCI_ASSERT(0);
    } else {
        // Event code not processed
        EB_HCI_ASSERT(0);
    }
}

// custom pack/unpack functin declear

static uint8_t *cus_pack_hci_le_transmitter_test_v4(uint16_t opcode, void *in, int *out_len)
{
    EB_HCI_ASSERT(0); // TODO
    return NULL;
}

static uint8_t *cus_pack_hci_le_set_extended_scan_parameters(uint16_t opcode, void *in, int *out_len)
{
    EB_HCI_ASSERT(0); // TODO
    return NULL;
}

static uint8_t *cus_pack_hci_le_extended_create_connection(uint16_t opcode, void *in, int *out_len)
{
    EB_HCI_ASSERT(0); // TODO
    return NULL;
}

static void cus_proc_hci_command_complete(struct eb_hci *hci, uint16_t evt_code, uint8_t *payload, int length)
{
    payload++;
    uint16_t opcode = *payload + (*(payload + 1) << 8);
    payload += 2;
    length -= 3;
    size_t unpack_len = sizeof(cmd_cmp_unpack) / sizeof(cmd_cmp_unpack[0]);
    const struct evt_unpack *unpack = get_unpack(opcode, cmd_cmp_unpack, unpack_len);
    if (unpack) {
        if (unpack->custom_unpack) {
            size_t i;
            for (i = 0; i < sizeof(custom_cmd_cmp_proc) / sizeof(custom_cmd_cmp_proc[0]); i++) {
                if (custom_cmd_cmp_proc[i].opcode == unpack->evt_code) {
                    EB_HCI_ASSERT(custom_cmd_cmp_proc[i].proc);
                    custom_cmd_cmp_proc[i].proc(hci, cmd_pack->opcode, payload, length);
                    return;
                }
            }
            EB_HCI_ASSERT(0);
            return;
        } else {
            hci->cfg.hci_proc_cmp(opcode, payload, length, hci->usr_data);
            return;
        }
    }
    EB_HCI_ASSERT(0);
}

static void cus_proc_le_event(struct eb_hci *hci, uint16_t evt_code, uint8_t *payload, int length)
{
    uint8_t subcode = *payload;
    size_t unpack_len = sizeof(le_evt_unpack) / sizeof(le_evt_unpack[0]);
    const struct evt_unpack *unpack = get_unpack(subcode, le_evt_unpack, unpack_len);
    if (unpack) {
        if (unpack->custom_unpack) {
            size_t i;
            for (i = 0; i < sizeof(custom_le_unpack_proc) / sizeof(custom_le_unpack_proc[0]); i++) {
                if (custom_le_unpack_proc[i].evt_code == unpack->evt_code) {
                    EB_HCI_ASSERT(custom_le_unpack_proc[i].proc);
                    custom_le_unpack_proc[i].proc(hci, subcode, payload, length);
                    return;
                }
            }
            EB_HCI_ASSERT(0);
            return;
        } else {
            hci->cfg.hci_proc_le_evt(subcode, payload, length, hci->usr_data);
            return;
        }
    }
    EB_HCI_ASSERT(0);
}

static void cus_proc_hci_read_local_supported_codec_capabilities_cmp(struct eb_hci *hci, uint16_t opcode,
        uint8_t *payload, int length)
{
    EB_HCI_ASSERT(0); // TODO
}

static void cus_proc_hci_le_advertising_report(struct eb_hci *hci, uint16_t evt_code, uint8_t *payload, int length)
{
    struct hci_le_advertising_report *report = (struct hci_le_advertising_report *)payload;
    EB_HCI_ASSERT(report->num_reports == 1);
    int cus_report_len = offsetof(struct hci_le_advertising_report, params[1]) + report->params[0].data_length;
    struct hci_le_advertising_report *cus_report = (struct hci_le_advertising_report *)EB_HCI_MALLOC(cus_report_len);
    EB_HCI_ASSERT(cus_report);
    cus_report->subevent_code = report->subevent_code;
    cus_report->num_reports = report->num_reports;
    cus_report->params[0].event_type = report->params[0].event_type;
    cus_report->params[0].address_type = report->params[0].address_type;
    memcpy(cus_report->params[0].address, report->params[0].address, 6);
    cus_report->params[0].data_length = report->params[0].data_length;
    uint8_t *adv_data = (uint8_t *)cus_report + offsetof(struct hci_le_advertising_report, params[1]);
    cus_report->params[0].data = adv_data;
    memcpy(adv_data, &report->params[0].data, report->params[0].data_length);
    cus_report->params[0].rssi = *((int8_t *)&report->params[0].data + report->params[0].data_length);
    hci->cfg.hci_proc_le_evt(evt_code, cus_report, cus_report_len, hci->usr_data);
    EB_HCI_FREE(cus_report);
}

static void cus_proc_hci_le_extended_advertising_report(struct eb_hci *hci, uint16_t evt_code, uint8_t *payload,
                                                        int length)
{
    EB_HCI_ASSERT(0); // TODO
}

char *eb_get_manufacturer_name(uint16_t id)
{
    const static struct {
        uint16_t id;
        char *name;
    } name_list[] = BLUETOOTH_MANU_NAME_DEFINE;
    size_t i;
    for (i = 0; i < sizeof(name_list) / sizeof(name_list[0]); i++) {
        if (name_list[i].id == id) {
            return name_list[i].name;
        }
    }
    return "Unknown Manufacturer Name";
}

char *eb_get_version_name(uint8_t ver)
{
    const static struct {
        uint8_t ver;
        char *name;
    } name_list[] = BLUETOOTH_VER_DEFINE;
    size_t i;
    for (i = 0; i < sizeof(name_list) / sizeof(name_list[0]); i++) {
        if (name_list[i].ver == ver) {
            return name_list[i].name;
        }
    }
    return "Unknown Bluetooth Version";
}

