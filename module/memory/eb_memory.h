#ifndef __EB_MEMORY_H__
#define __EB_MEMORY_H__

#include "eb_debug.h"

#define EB_RB_MALLOC  malloc
#define EB_RB_FREE    free

#define EB_ENV_MALLOC  malloc // Assert if malloc failed, init as 0
#define EB_ENV_FREE    free

#endif /* __EB_MEMORY_H__ */

