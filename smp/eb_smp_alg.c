#include <stdio.h>
#include <string.h>
#include "eb_smp_alg.h"

#ifdef SMP_ALG_DEBUG
#define SMP_ALG_PRINT(fmt, ...) printf(fmt, ##__VA_ARGS__)
#define SMP_ALG_LOG(fmt, ...) SMP_ALG_PRINT("[ALG]"fmt, ##__VA_ARGS__)
#define SMP_ALG_DUMP(msg,d,l) \
    do { \
        SMP_ALG_PRINT("[ALG]%s: ", msg); \
        int i; \
        for (i = 0; i < l; i++) \
        { \
            if(!(i%16)&&i){ \
                SMP_ALG_PRINT("\n"); \
            } \
            SMP_ALG_PRINT("%02X ", ((uint8_t *)d)[i]); \
        } \
        SMP_ALG_PRINT("\n"); \
    } while (0)
#else
#define SMP_ALG_PRINT(fmt, ...)
#define SMP_ALG_LOG(fmt, ...)
#define SMP_ALG_DUMP(msg,d,l)
#endif

struct data_c1 {
    const uint8_t *tk;
    const uint8_t *init_addr;
    const uint8_t *resp_addr;
    void (*cb)(uint8_t *confirm_value, void *data);
    void *usr_data;
};

struct data_s1 {
    void (*cb)(uint8_t *result, void *data);
    void *usr_data;
};

static void xor_block(uint8_t *in_out, const uint8_t *data)
{
    int i;
    for (i = 0; i < 16; i++) {
        in_out[i] = in_out[i] ^ data[i];
    }
}

static void c1_parse2_cb(uint8_t *out, void *p)
{
    struct data_c1 *param = (struct data_c1 *)p;
    SMP_ALG_DUMP("[c1] res out", out, 16);
    SMP_ALG_PRINT("\n");
    param->cb(out, param->usr_data);
    if (p) {
        EB_SMP_ALG_FREE(param);
    }
}

static void c1_parse1_cb(uint8_t *out, void *p)
{
    // p2 = padding || ia || ra
    uint8_t p2[16];
    struct data_c1 *param = (struct data_c1 *)p;
    SMP_ALG_DUMP("[c1] aes out", out, 16);
    memset(&p2[0], 0x00, 16);
    SMP_ALG_DUMP("[c1]   iaddr", param->init_addr, 6);
    SMP_ALG_DUMP("[c1]   raddr", param->resp_addr, 6);
    memcpy(&p2[6], param->init_addr, 6);
    memcpy(&p2[0], param->resp_addr, 6);
    /* p2' = C1 XOR p2 */
    SMP_ALG_DUMP("[c1]  XOR in", p2, 16);
    xor_block(p2, out);
    SMP_ALG_DUMP("[c1] XOR out", p2, 16);
    SMP_ALG_DUMP("[c1]  aes in", param->tk, 16);
    SMP_ALG_DUMP("[c1]  aes in", p2, 16);
    eb_smp_aes128(p2, param->tk, c1_parse2_cb, param);
}

void smp_alg_c1(const uint8_t tk[16], const uint8_t rand[16], const uint8_t preq[7], const uint8_t prsp[7],
                uint8_t iat, uint8_t rat, const uint8_t ia[6], const uint8_t ra[6],
                void (*cb)(uint8_t *confirm_value, void *p), void *usr_data)
{
    uint8_t p1[16];
    struct data_c1 *param = EB_SMP_ALG_MALLOC(sizeof(struct data_c1));
    EB_SMP_ALG_ASSERT(param);
    param->tk = tk;
    param->init_addr = ia;
    param->resp_addr = ra;
    param->cb = cb;
    param->usr_data = usr_data;
    SMP_ALG_DUMP("[c1]      tk", tk, 16);
    SMP_ALG_DUMP("[c1]    rand", rand, 16);
    SMP_ALG_DUMP("[c1]    preq", preq, 7);
    SMP_ALG_DUMP("[c1]    prsp", prsp, 7);
    SMP_ALG_LOG("[c1] iat=%d rat=%d\n", iat, rat);
    // p1 = pres || preq || rat' || iat'
    p1[0] = iat;
    p1[1] = rat;
    memcpy(&p1[2], preq, 7);
    memcpy(&p1[9], prsp, 7);
    SMP_ALG_DUMP("[c1]  XOR in", p1, 16);
    // p1' = p1 XOR rand
    xor_block(p1, rand);
    SMP_ALG_DUMP("[c1] XOR out", p1, 16);
    SMP_ALG_DUMP("[c1]  aes in", tk, 16);
    SMP_ALG_DUMP("[c1]  aes in", p1, 16);
    eb_smp_aes128(p1, tk, c1_parse1_cb, param);
}

static void s1_cb(uint8_t *out, void *p)
{
    struct data_s1 *param = (struct data_s1 *)p;
    SMP_ALG_DUMP("[s1] aes out", out, 16);
    SMP_ALG_PRINT("\n");
    param->cb(out, param->usr_data);
    if (p) {
        EB_SMP_ALG_FREE(p);
    }
}

void smp_alg_s1(const uint8_t tk[16], const uint8_t *init_rand, const uint8_t *resp_rand,
                void (*cb)(uint8_t *confirm_value, void *p), void *usr_data)
{
    uint8_t tmp[16];
    struct data_s1 *param = (struct data_s1 *)EB_SMP_ALG_MALLOC(sizeof(struct data_s1));
    param->cb = cb;
    param->usr_data = usr_data;

    memcpy(&tmp[0], init_rand, 8);
    memcpy(&tmp[8], resp_rand, 8);
    SMP_ALG_DUMP("[s1]      tk", tk, 16);
    SMP_ALG_DUMP("[s1]   irand", init_rand, 16);
    SMP_ALG_DUMP("[s1]   rrand", resp_rand, 16);
    SMP_ALG_DUMP("[s1]  aes in", tk, 16);
    SMP_ALG_DUMP("[s1]  aes in", tmp, 16);
    eb_smp_aes128(tmp, tk, s1_cb, param);
}

