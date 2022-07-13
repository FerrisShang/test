#ifndef __EB_MEMORY_H__
#define __EB_MEMORY_H__

#include "eb_debug.h"
#include <stdint.h>

void *rw_ke_malloc(uintptr_t size, uint8_t type);
void rw_ke_free(void *mem_ptr);

#define EB_MALLOC(size)            rw_ke_malloc(size, 0)
#define EB_FREE(p)                 rw_ke_free(p)

#endif /* __EB_MEMORY_H__ */

