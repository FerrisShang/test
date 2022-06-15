#ifndef __EB_SMP_H__
#define __EB_SMP_H__

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include "eb_smp_code.h"

// #define SMP_DEBUG
#define EB_SMP_MALLOC  malloc
#define EB_SMP_FREE    free
#define EB_SMP_ASSERT  assert
#define EB_SMP_WARNING(x) do{if(!(x)){printf("Warning: %s@%d\n", __func__, __LINE__);}}while(0)

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

struct eb_smp_cfg {
    void (*send)(uint16_t conn_hdl, uint8_t *data, int len, void *usr_data);
    void (*connected)(uint16_t conn_hdl, uint8_t role, void *usr_data); // role: 0-Central, 1-Peripheral
    void (*disconnected)(uint16_t conn_hdl, void *usr_data);
    void (*proc)(uint16_t conn_hdl, struct smp_param *param, void *usr_data);
    void (*ltk_resp)(uint16_t conn_hdl, uint8_t *key, void *usr_data);
    uint16_t max_connection;
    void *usr_data;
};

struct eb_smp *eb_smp_init(struct eb_smp_cfg *cfg, void *usr_data);

/****************************************************************************************
 * Custom pairing failed procedure
 * @param[in] reason  @ref enum smp_err_reason
 */
void eb_smp_pairing_abort(struct eb_smp *smp, uint16_t conn_hdl, uint8_t reason);

/****************************************************************************************
 * Distribute Key
 * @param[in] key_type  @ref enum smp_code 0x06~0x0A;
 * @param[in] key       data structure base on key_type
 */
void eb_smp_distribute_key(struct eb_smp *smp, uint8_t key_type, void *key);

/****************************************************************************************
 * SMP Pairing Request, central(master) role only
 * @param[in] req @ref smp_pairing_request
 */
void eb_smp_pairing_request(struct eb_smp *smp, uint16_t conn_hdl, struct smp_pairing_request *req);

/****************************************************************************************
 * Encript link, central(master) role only
 * @param[in] cen_id   @ref smp_central_identification
 * @param[in] enc_info @ref smp_encryption_information
 */
void eb_smp_encrypt(struct eb_smp *smp, struct smp_central_identification *cen_id,
                    struct smp_encryption_information *enc_info);

/****************************************************************************************
 * SMP Pairing Request, peripheral(slave) role only
 * @param[in] rsp @ref smp_pairing_response
 */
void eb_smp_pairing_response(struct eb_smp *smp, uint16_t conn_hdl, struct smp_pairing_response *rsp);

struct eb_smp_key {
    uint8_t type; // @ref enum eb_smp_key_type
    union {
        uint8_t oob[16];
        bool yes_no;
        uint32_t passkey;
        uint32_t display;
    };
};
void eb_smp_key_response(struct eb_smp *smp, struct eb_smp_key *key);
/****************************************************************************************
 * SMP Pairing Request, peripheral(slave) role only
 * @param[in] auth @ref enum smp_auth_flags
 */
void eb_smp_security_req(struct eb_smp *smp, uint16_t conn_hdl, uint8_t auth);

// porting
void eb_smpp_received(struct eb_smp *smp, uint16_t conn_hdl, uint8_t *payload, uint16_t datalen);
void eb_smpp_connected(struct eb_smp *smp, uint16_t conn_hdl, uint8_t role,
                       uint8_t *peer_addr, uint8_t peer_addr_type, uint8_t *local_addr, uint8_t local_addr_type);
void eb_smpp_disconnected(struct eb_smp *smp, uint16_t conn_hdl);
void eb_smpp_ltk_request(struct eb_smp *smp, uint16_t conn_hdl, uint8_t *rand, uint16_t ediv);
void eb_smpp_encrypt_changed(struct eb_smp *smp, uint16_t conn_hdl, uint8_t enabled, uint8_t key_size);
void eb_smpp_key_refresh(struct eb_smp *smp, uint16_t conn_hdl);

#endif /* __EB_SMP_H__ */

