#include "eb_smp_aes.h"
#include "smp_aes.h"

static void (*enc_encrypt)(const uint8_t *key, const uint8_t *plaintext, void *p);
static void *enc_usr_data;
static void (*enc_done_cb)(uint8_t *out, void *p);
static void *enc_done_usr_data;

void eb_smp_aes128_init(void (*encrypt)(const uint8_t *key, const uint8_t *plaintext, void *p), void *usr_data)
{
    enc_encrypt = encrypt;
    enc_usr_data = usr_data;
}

void eb_smp_aes128_encrypted(uint8_t *enc_data)
{
    enc_done_cb(enc_data, enc_done_usr_data);
}

void eb_smp_aes128(uint8_t *in, const uint8_t *key, void (*cb)(uint8_t *out, void *p), void *usr_data)
{
    enc_done_cb = cb;
    enc_done_usr_data = usr_data;
    enc_encrypt(key, in, enc_usr_data);
}
