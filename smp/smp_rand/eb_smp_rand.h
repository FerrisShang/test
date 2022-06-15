#ifndef __EB_SMP_RAND_H__
#define __EB_SMP_RAND_H__

#include <stdint.h>

void eb_smp_rand(void (*cb)(uint8_t *rand128, void *p), void *usr_data);

#endif /* __EB_SMP_RAND_H__ */
