#ifndef __EB_MEMORY_H__
#define __EB_MEMORY_H__

#include "eb_debug.h"

#define EB_MALLOC(size, priority)  malloc(size)
#define EB_FREE(p)                 free(p)

#endif /* __EB_MEMORY_H__ */

