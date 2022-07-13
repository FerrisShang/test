#ifndef __EB_TIMER_H__
#define __EB_TIMER_H__

#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include "eb_memory.h"
#include "eb_debug.h"

#define EB_TIMER_MALLOC EB_MALLOC
#define EB_TIMER_FREE   EB_FREE
#define EB_TIMER_ASSERT EB_ASSERT

#define EB_TIMER_MAX    EB_ALARM_MAX

struct eb_timer;

typedef struct eb_time_item {
    size_t target_time;
    void (*timeout_callback)(void *p);
    void *usr_data;
    struct eb_time_item *next;
} eb_timer_t;

/*******************************************************************************
 * Create timer module
 * @param   alarm_irq_handler  alarm callback. (in other thread)
 * @param   usr_data           user data
 * @return  pointer of timer module
 ******************************************************************************/
struct eb_timer *eb_timer_create(void alarm_irq_handler(void *p), void *usr_data);

/*******************************************************************************
 * Set timer, call this function will replace the same timer
 * @param   timer       pointer of timer module
 * @param   timer_item  timer_item used for store internal data, not need to init
 * @param   delay_10ms  the timeout from now on, unit 10ms
 * @param   callback    callback  processed when timeout
 * @param   usr_data    user data
 * @return  the latest timeout in all timers, unit 10ms
 * @warning timer_item MUST be a global/static variable
 ******************************************************************************/
size_t eb_timer_set(struct eb_timer *timer, eb_timer_t *timer_item, size_t delay_10ms,
                    void(*callback)(void *p), void *usr_data);

/*******************************************************************************
 * Delete timer
 * @param   timer       pointer of timer module
 * @param   timer_item  timer_item used for store internal data
 * @warning timer_item MUST be a global/static variable
 * @return  the latest timeout in all timers, unit 10ms
 ******************************************************************************/
size_t eb_timer_del(struct eb_timer *timer, eb_timer_t *timer_item);

/*******************************************************************************
 * Check timeout once, specified callback will be execute if timeout
 * @param   timer       pointer of timer module
 * @warning timer_item MUST be a global/static variable
 * @return  true if at lease one timer has timed out
 ******************************************************************************/
bool eb_timer_schedule_once(struct eb_timer *timer);

#endif /* __EB_TIMER_H__ */

