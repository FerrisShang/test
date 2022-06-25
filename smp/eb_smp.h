#ifndef __EB_SMP_H__
#define __EB_SMP_H__

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include "eb_smp_code.h"

#define SMP_DEBUG 1

enum smp_role {
    EB_SMP_ROLE_MASTER  = 0,
    EB_SMP_ROLE_SLAVE   = 1,
};

struct eb_smp;

enum eb_smp_key_type {
    EB_SMP_KEY_TYPE_NONE, // No key
    EB_SMP_KEY_TYPE_OOB,  // OOB
    EB_SMP_KEY_TYPE_YN,   // Yes/no
    EB_SMP_KEY_TYPE_PSK,  // Passkey
    EB_SMP_KEY_TYPE_DIS,  // Display
};

enum eb_smp_evt_id {
    EB_SMP_PAIRING_REQ,
    EB_SMP_PAIRING_DONE,
};

struct smp_param {
    uint8_t evt_id; // @ref enum eb_smp_evt_id
    union {
        struct smp_pairing_request *pairing_req;
    };
};

enum EB_SMP_ERR {
    EB_SMP_ERR_NO_ERROR                        = 0x0000,
    EB_SMP_ERR_NO_CONNECTION                   = 0x0001,
    EB_SMP_ERR_INVALID_STATE                   = 0x0002,
    EB_SMP_ERR_INSUFFICIENT_RESOURCES          = 0x0003,
    EB_SMP_ERR_UNSPEC                          = 0x000F,

    EB_SMP_ERR_PASSKEY_ENTRY_FAILED            = 0x0501,
    EB_SMP_ERR_OOB_NOT_AVAILABLE               = 0x0502,
    EB_SMP_ERR_AUTHENTICATION_REQUIREMENTS     = 0x0503,
    EB_SMP_ERR_CONFIRM_VALUE_FAILED            = 0x0504,
    EB_SMP_ERR_PAIRING_NOT_SUPPORTED           = 0x0505,
    EB_SMP_ERR_ENCRYPTION_KEY_SIZE             = 0x0506,
    EB_SMP_ERR_COMMAND_NOT_SUPPORTED           = 0x0507,
    EB_SMP_ERR_UNSPECIFIED_REASON              = 0x0508,
    EB_SMP_ERR_REPEATED_ATTEMPTS               = 0x0509,
    EB_SMP_ERR_INVALID_PARAMETERS              = 0x050A,
    EB_SMP_ERR_DHKEY_CHECK_FAILED              = 0x050B,
    EB_SMP_ERR_NUMERIC_COMPARISON_FAILED       = 0x050C,
    EB_SMP_ERR_BR_EDR_PAIRING_IN_PROGRESS      = 0x050D,
    EB_SMP_ERR_CROSS_TRANSPORT_KEY_NOT_ALLOWED = 0x050E,
    EB_SMP_ERR_KEY_REJECTED                    = 0x050F,
};

struct eb_smp_callbacks {
    void (*send)(uint8_t conn_idx, uint8_t *data, int len, void *usr_data);
    void (*connected)(uint8_t conn_idx, uint8_t role, void *usr_data);
    void (*disconnected)(uint8_t conn_idx, void *usr_data);
    void (*proc)(uint8_t conn_idx, struct smp_param *param, void *usr_data);
    void (*ltk_resp)(uint8_t conn_idx, uint8_t *key, void *usr_data);
};

struct eb_smp_cfg {
    const struct eb_smp_callbacks *cbs;
    uint16_t max_connection;
    void *usr_data;
};

struct eb_smp *eb_smp_init(struct eb_smp_cfg *cfg, void *usr_data);

/****************************************************************************************
 * Custom pairing failed procedure
 * @param[in] reason  @ref enum smp_err_reason
 */
uint32_t eb_smp_pairing_abort(struct eb_smp *smp, uint8_t conn_idx, uint8_t reason);

/****************************************************************************************
 * Distribute Key
 * @param[in] key_type  @ref enum smp_code 0x06~0x0A;
 * @param[in] key       data structure base on key_type
 */
uint32_t eb_smp_distribute_key(struct eb_smp *smp, uint8_t key_type, void *key);

/****************************************************************************************
 * SMP Pairing Request, central(master) role only
 * @param[in] req @ref smp_pairing_request
 */
uint32_t eb_smp_pairing_request(struct eb_smp *smp, uint8_t conn_idx, struct smp_pairing_request *req);

/****************************************************************************************
 * Encript link, central(master) role only
 * @param[in] cen_id   @ref smp_central_identification
 * @param[in] enc_info @ref smp_encryption_information
 */
uint32_t eb_smp_encrypt(struct eb_smp *smp, struct smp_central_identification *cen_id,
                    struct smp_encryption_information *enc_info);

/****************************************************************************************
 * SMP Pairing Request, peripheral(slave) role only
 * @param[in] rsp @ref smp_pairing_response
 */
uint32_t eb_smp_pairing_response(struct eb_smp *smp, uint8_t conn_idx, struct smp_pairing_response *rsp);

struct eb_smp_key {
    uint8_t type; // @ref enum eb_smp_key_type
    union {
        uint8_t oob[16];
        bool yes_no;
        uint32_t passkey;
        uint32_t display;
    };
};
uint32_t eb_smp_key_response(struct eb_smp *smp, struct eb_smp_key *key);
/****************************************************************************************
 * SMP Pairing Request, peripheral(slave) role only
 * @param[in] auth @ref enum smp_auth_flags
 */
uint32_t eb_smp_security_req(struct eb_smp *smp, uint8_t conn_idx, uint8_t auth);

// porting
void eb_psmp_received(struct eb_smp *smp, uint8_t conn_idx, uint8_t *payload, uint16_t datalen);
void eb_psmp_connected(struct eb_smp *smp, uint8_t conn_idx, uint8_t role,
                       uint8_t *peer_addr, uint8_t peer_addr_type, uint8_t *local_addr, uint8_t local_addr_type);
void eb_psmp_disconnected(struct eb_smp *smp, uint8_t conn_idx);
void eb_psmp_ltk_request(struct eb_smp *smp, uint8_t conn_idx, uint8_t *rand, uint16_t ediv);
void eb_psmp_encrypt_changed(struct eb_smp *smp, uint8_t conn_idx, uint8_t enabled, uint8_t key_size);
void eb_psmp_key_refresh(struct eb_smp *smp, uint8_t conn_idx);

#endif /* __EB_SMP_H__ */

