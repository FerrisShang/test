#include <stdlib.h>
#include "eb_smp_rand.h"

void eb_smp_rand(void (*cb)(uint8_t *rand128, void *p), void *usr_data)
{
    size_t i;
    int data[16 / sizeof(int)];
    for (i = 0; i < 16 / sizeof(int); i++) {
        ((int *)data)[i] = rand();
    }
    cb((uint8_t *)data, usr_data);
}
