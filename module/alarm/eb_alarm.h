#ifndef __EB_ALARM_H__
#define __EB_ALARM_H__

#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include "eb_memory.h"
#include "eb_debug.h"

#define EB_ALARM_MALLOC EB_MALLOC
#define EB_ALARM_FREE   EB_FREE
#define EB_ALARM_ASSERT EB_ASSERT

#define EB_ALARM_MAX 0x1000000

struct eb_alarm;

/*******************************************************************************
 * Create alarm module, will callback when timeout
 * @prarm    callback  processed when timeout
 * @prarm    usr_data  user data
 * @return   pointer of alarm module
 ******************************************************************************/
struct eb_alarm *eb_alarm_create(void(*callback)(void *p), void *usr_data);

/*******************************************************************************
 * Set an alarm, MAX alarm delay = (EB_ALARM_MAX >> 1) seconds, about 97 days
 * @prarm    alarm        pointer of alarm module
 * @prarm    delay_10ms   the timeout from now on, unit 10ms
 ******************************************************************************/
void eb_alarm_set(struct eb_alarm *alarm, size_t delay_10ms);

/*******************************************************************************
 * Cancel an alarm
 * @prarm    alarm        pointer of alarm module
 ******************************************************************************/
void eb_alarm_del(struct eb_alarm *alarm);

/*******************************************************************************
 * Get now time
 * @return  absolute time, unit 10ms
 ******************************************************************************/
size_t eb_alarm_get_10ms(void);

/*******************************************************************************
 * Get diff time
 * @prarm    now       time now
 * @prarm    target    time target
 * @return   diff time = target - now, unit 10ms
 ******************************************************************************/
size_t eb_alarm_diff_10ms(size_t now, size_t target);

/*******************************************************************************
 * Check if reached target time
 * @prarm    target_time_10ms  absolute target time, unit 10ms
 * @return   true if target time reached or passed else false
 ******************************************************************************/
bool eb_alarm_ring(size_t target_time_10ms);


#endif /* __EB_ALARM_H__ */
