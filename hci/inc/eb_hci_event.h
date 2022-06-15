#ifndef __EB_HCI_EVENT_H__
#define __EB_HCI_EVENT_H__

#include <stdint.h>
#include "eb_compile.h"

#define HCI_DISCONNECTION_COMPLETE                   0x05
#define HCI_READ_REMOTE_VERSION_INFORMATION_COMPLETE 0x0C
#define HCI_ENCRYPTION_CHANGE_V2                     0x59
#define HCI_ENCRYPTION_CHANGE_V1                     0x08
#define HCI_COMMAND_COMPLETE                         0x0E
#define HCI_COMMAND_STATUS                           0x0F
#define HCI_HARDWARE_ERROR                           0x10
#define HCI_NUMBER_OF_COMPLETED_PACKETS              0x13
#define HCI_ENCRYPTION_KEY_REFRESH_COMPLETE          0x30

// 7.7.5 HCI_Disconnection_Complete 0x05
struct hci_disconnection_complete {
    uint8_t status;
    uint16_t connection_handle;
    uint8_t reason;
} __PACKED;

struct hci_read_remote_version_information_complete {
    uint8_t status;
    uint16_t connection_handle;
    uint8_t version;
    uint16_t manufacturer_name;
    uint16_t subversion;
} __PACKED;

// 7.7.8 HCI_Encryption_Change[v2] 0x59
struct hci_encryption_change_v2 {
    uint8_t status;
    uint16_t connection_handle;
    uint8_t encryption_enabled;
    uint8_t encryption_key_size;
} __PACKED;

// 7.7.8 HCI_Encryption_Change[v1] 0x08
struct hci_encryption_change_v1 {
    uint8_t status;
    uint16_t connection_handle;
    uint8_t encryption_enabled;
} __PACKED;

// 7.7.14 HCI_Command_Complete 0x0E
struct hci_command_complete {
    uint8_t num_hci_command_packets;
    uint16_t command_opcode;
    uint8_t return_parameters[0];
} __PACKED;

// 7.7.15 HCI_Command_Status 0x0F
struct hci_command_status {
    uint8_t status;
    uint8_t num_hci_command_packets;
    uint16_t command_opcode;
} __PACKED;

// 7.7.16 HCI_Hardware_Error 0x10
struct hci_hardware_error {
    uint8_t hardware_code;
} __PACKED;

// 7.7.19 HCI_Number_Of_Completed_Packets 0x13
struct hci_number_of_completed_packets {
    uint8_t num_handles;
    struct {
        uint16_t connection_handle;
        uint16_t num_completed_packets;
    } __PACKED params[0];
} __PACKED;

// 7.7.39 HCI_Encryption_Key_Refresh_Complete 0x30
struct hci_encryption_key_refresh_complete {
    uint8_t status;
    uint16_t connection_handle;
} __PACKED;

#endif /* __EB_HCI_EVENT_H__ */

