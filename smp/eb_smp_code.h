#ifndef __EB_SMP_CODE_H__
#define __EB_SMP_CODE_H__

#include <stdint.h>
#include "eb_compile.h"

enum smp_code {
    SMP_PAIRING_REQUEST           = 0x01,
    SMP_PAIRING_RESPONSE          = 0x02,
    SMP_PAIRING_CONFIRM           = 0x03,
    SMP_PAIRING_RANDOM            = 0x04,
    SMP_PAIRING_FAILED            = 0x05,
    SMP_ENCRYPTION_INFORMATION    = 0x06,
    SMP_CENTRAL_IDENTIFICATION    = 0x07,
    SMP_IDENTITY_INFORMATION      = 0x08,
    SMP_IDENTITY_ADDR_INFO        = 0x09,
    SMP_SIGNING_INFORMATION       = 0x0A,
    SMP_SECURITY_REQUEST          = 0x0B,
    SMP_PAIRING_PUBLIC_KEY        = 0x0C,
    SMP_PAIRING_DHKEY_CHECK       = 0x0D,
    SMP_PAIRING_KEY_NOTIFY        = 0x0E,
};

enum smp_err_reason {
    SMP_ERR_NO_ERR                          = 0x00,
    SMP_ERR_PASSKEY_ENTRY_FAILED            = 0x01,
    SMP_ERR_OOB_NOT_AVAILABLE               = 0x02,
    SMP_ERR_AUTHENTICATION_REQUIREMENTS     = 0x03,
    SMP_ERR_CONFIRM_VALUE_FAILED            = 0x04,
    SMP_ERR_PAIRING_NOT_SUPPORTED           = 0x05,
    SMP_ERR_ENCRYPTION_KEY_SIZE             = 0x06,
    SMP_ERR_COMMAND_NOT_SUPPORTED           = 0x07,
    SMP_ERR_UNSPECIFIED_REASON              = 0x08,
    SMP_ERR_REPEATED_ATTEMPTS               = 0x09,
    SMP_ERR_INVALID_PARAMETERS              = 0x0A,
    SMP_ERR_DHKEY_CHECK_FAILED              = 0x0B,
    SMP_ERR_NUMERIC_COMPARISON_FAILED       = 0x0C,
    SMP_ERR_BR_EDR_PAIRING_IN_PROGRESS      = 0x0D,
    SMP_ERR_CROSS_TRANSPORT_KEY_NOT_ALLOWED = 0x0E,
    SMP_ERR_KEY_REJECTED                    = 0x0F,
};

enum smp_io_capability {
    DisplayOnly     = 0x00,
    DisplayYesNo    = 0x01,
    KeyboardOnly    = 0x02,
    NoInputNoOutput = 0x03,
    KeyboardDisplay = 0x04,
};

enum smp_oob_data_flag {
    OOB_AUTH_DATA_NOT_PRESENT = 0x00,
    OOB_AUTH_DATA_FROM_REMOTE_DEVICE_PRESENT,
};

enum smp_auth_flags {
    SMP_AUTH_FLAGS_BONDING  = 0x01,
    SMP_AUTH_FLAGS_MITM     = 0x04,
    SMP_AUTH_FLAGS_SC       = 0x08,
    SMP_AUTH_FLAGS_KEYPRESS = 0x10,
    SMP_AUTH_FLAGS_CT2      = 0x20,
};

enum smp_le_key_dist {
    SMP_LE_KEY_DIST_ENCKEY  = 0x01,
    SMP_LE_KEY_DIST_IDKEY   = 0x02,
    SMP_LE_KEY_DIST_SIGNKEY = 0x04,
    SMP_LE_KEY_DIST_LINKKEY = 0x08,
};

enum smp_keypress_type {
    PASSKEY_ENTRY_STARTED   = 0,
    PASSKEY_DIGIT_ENTERED   = 1,
    PASSKEY_DIGIT_ERASED    = 2,
    PASSKEY_CLEARED         = 3,
    PASSKEY_ENTRY_COMPLETED = 4,
};

struct smp_pairing_request {
    uint8_t code;
    uint8_t io_capability; // @ref enum smp_io_capability
    uint8_t oob_data_flag; // @ref enum smp_oob_data_flag
    uint8_t authreq;       // @ref enum smp_auth_flags
    uint8_t maximum_encryption_key_size;
    uint8_t initiator_key_distribution; // @ref enum smp_le_key_dist
    uint8_t responder_key_distribution; // @ref enum smp_le_key_dist
};

struct smp_pairing_response {
    uint8_t code;
    uint8_t io_capability; // @ref enum smp_io_capability
    uint8_t oob_data_flag; // @ref enum smp_oob_data_flag
    uint8_t authreq;       // @ref enum smp_auth_flags
    uint8_t maximum_encryption_key_size;
    uint8_t initiator_key_distribution; // @ref enum smp_le_key_dist
    uint8_t responder_key_distribution; // @ref enum smp_le_key_dist
};

struct smp_pairing_confirm {
    uint8_t code;
    uint8_t value[16];
};

struct smp_pairing_random {
    uint8_t code;
    uint8_t value[16];
};

struct smp_pairing_failed {
    uint8_t code;
    uint8_t reason; // @ref smp_err_reason
};


struct smp_encryption_information {
    uint8_t code;
    uint8_t ltk[16];
};

struct smp_central_identification {
    uint8_t code;
    uint16_t ediv;
    uint8_t rand[8];
} __PACKED;

struct smp_identity_information {
    uint8_t code;
    uint8_t irk[16];
};

struct smp_identity_addr_info {
    uint8_t code;
    uint8_t addr_type;
    uint8_t address[6];
};

struct smp_signing_information {
    uint8_t code;
    uint8_t sign_key[8];
};

struct smp_security_request {
    uint8_t code;
    uint8_t authreq; // @ref enum smp_auth_flags
};

struct smp_pairing_public_key {
    uint8_t code;
    uint8_t x[16];
    uint8_t y[16];
};

struct smp_pairing_dhkey_check {
    uint8_t code;
    uint8_t key[16];
};

struct smp_pairing_key_notify {
    uint8_t code;
    uint8_t type; // @ref smp_keypress_type
};

struct smp_packet {
    union {
        uint8_t code;
        struct smp_pairing_request         pairing_req;
        struct smp_pairing_response        pairing_rsp;
        struct smp_pairing_confirm         pairing_conf;
        struct smp_pairing_random          pairing_rand;
        struct smp_pairing_failed          pairing_failed;
        struct smp_encryption_information  enc_info;
        struct smp_central_identification  cen_id;
        struct smp_identity_information    id_info;
        struct smp_identity_addr_info      id_addr_info;
        struct smp_signing_information     sign_info;
        struct smp_security_request        sec_req;
        struct smp_pairing_public_key      public_key;
        struct smp_pairing_dhkey_check     dhkey_check;
        struct smp_pairing_key_notify      key_notify;
    } __PACKED;
} __PACKED;

#endif /* __EB_SMP_CODE_H__ */


