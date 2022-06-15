#ifndef __EB_SMP_AES_H__
#define __EB_SMP_AES_H__

#include <stdint.h>

// Big endian in & out
void eb_smp_aes128(uint8_t *in, const uint8_t *key, void (*cb)(uint8_t *out, void *p), void *usr_data);
#ifdef SMP_ALG_HCI_ENC
void eb_smp_aes128_init(void (*encrypt)(const uint8_t *key, const uint8_t *plaintext, void *p), void *usr_data);
void eb_smp_aes128_encrypted(uint8_t *enc_data);
#endif

#endif /* __EB_SMP_AES_H__ */
