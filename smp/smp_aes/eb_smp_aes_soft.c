#include "eb_smp_aes.h"
#include "smp_aes.h"

static void memcpy_inv(uint8_t *dst, const uint8_t *src, size_t len)
{
    src += len;
    while (len--) {
        *dst++ = *--src;
    }
}

void eb_smp_aes128(uint8_t *in, const uint8_t *key, void (*cb)(uint8_t *out, void *p), void *usr_data)
{
    struct AES_ctx ctx;
    uint8_t in_out[16], key_inv[16];
    memcpy_inv(key_inv, key, 16);
    memcpy_inv(in_out, in, 16);
    SMP_AES_init_ctx(&ctx, key_inv);
    SMP_AES_ECB_encrypt(&ctx, in_out);
    memcpy_inv(in, in_out, 16);
    cb(in, usr_data);
}
