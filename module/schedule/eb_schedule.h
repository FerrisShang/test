#ifndef __EB_SCHEDULE_H__
#define __EB_SCHEDULE_H__

#include <stddef.h>
#include <stdint.h>
#include "eb_schedule_config.h"
#include "eb_timer.h"

#define EB_SCHE_MALLOC malloc
#define EB_SCHE_ASSERT assert

typedef eb_timer_t eb_sche_timer_t;
struct eb_sche;

/*******************************************************************************
 * Create schedule module, schedule module impolement event & timer
 * @return  pointer of schedule module
 ******************************************************************************/
struct eb_sche *eb_schedule_create(void);

/*******************************************************************************
 * Schedule once, event & timer maybe execute specified callbacks
 ******************************************************************************/
void eb_schedule(struct eb_sche *sche);

/*******************************************************************************
 * Set timer, call this function will replace the same timer
 * @param   sche        pointer of schedule module
 * @param   timer       timer item used for store internal data, not need to init
 * @param   delay_10ms  the timeout from now on, unit 10ms
 * @param   callback    callback  processed when timeout
 * @param   usr_data    user data
 * @warning timer MUST be a global/static variable
 ******************************************************************************/
void eb_sche_timer_set(struct eb_sche *sche, eb_sche_timer_t *timer, size_t delay_10ms, void(*callback)(void *p),
                       void *usr_data);

/*******************************************************************************
 * Delete timer
 * @param   sche        pointer of schedule module
 * @param   timer       timer item used for store internal data, not need to init
 * @warning timer MUST be a global/static variable
 ******************************************************************************/
void eb_sche_timer_del(struct eb_sche *sche, eb_sche_timer_t *timer);

/*******************************************************************************
 * Set callback of specified event_id
 * @param   sche      Pointer of schedule module
 * @param   event_id  The index of event
 * @param   callback  The function for event callback
 * @param   usr_data  user data for callback
 ******************************************************************************/
void eb_sche_event_callback_set(struct eb_sche *sche, uint8_t event_id, void (*p_callback)(void *p), void *usr_data);

/*******************************************************************************
 * Set event as active, The specified callback will be executed when schedule
 * @param   sche        pointer of schedule module
 * @param   event_id  The index of event
 * @note    This function can be call in other thread
 ******************************************************************************/
void eb_sche_event_set(struct eb_sche *sche, uint8_t event_id);

#endif /* __EB_SCHEDULE_H__ */
