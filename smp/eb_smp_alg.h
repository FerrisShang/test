#ifndef __EB_SMP_ALG_H__
#define __EB_SMP_ALG_H__


#include <stdlib.h>
#include <assert.h>
#include "eb_memory.h"
#include "eb_debug.h"
#include "eb_smp_aes.h"

// #define SMP_ALG_DEBUG

#define EB_SMP_ALG_MALLOC  EB_MALLOC
#define EB_SMP_ALG_FREE    EB_FREE
#define EB_SMP_ALG_ASSERT  EB_ASSERT

// Big endian(same as byte order received from hci)
void smp_alg_c1(
    const uint8_t tk[16],
    const uint8_t rand[16],
    const uint8_t preq[7],
    const uint8_t prsp[7],
    uint8_t iat,
    uint8_t rat,
    const uint8_t ia[6],
    const uint8_t ra[6],
    void (*cb)(uint8_t *confirm_value, void *p),
    void *usr_data
);

void smp_alg_s1(const uint8_t tk[16], const uint8_t *init_rand, const uint8_t *resp_rand,
                void (*cb)(uint8_t *confirm_value, void *p), void *usr_data);

#endif /* __EB_SMP_ALG_H__ */
