#ifndef __EB_EVENT__
#define __EB_EVENT__

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include "eb_memory.h"
#include "eb_debug.h"

#define EB_EVENT_MALLOC EB_MALLOC
#define EB_EVENT_FREE   EB_FREE
#define EB_EVENT_ASSERT EB_ASSERT

struct eb_event;
typedef void (*eb_event_cb_t)(void *p);

/*******************************************************************************
 * Create event module
 * @param   id_max  The max number of events
 * @return  pointer of event module
 ******************************************************************************/
struct eb_event *eb_event_create(uint8_t id_max);

/*******************************************************************************
 * Set callback of specified event_id
 * @param   evt       The pointer of event module
 * @param   event_id  The index of event
 * @param   callback  The function for event callback
 * @param   usr_data  user data for callback
 ******************************************************************************/
void eb_event_callback_set(struct eb_event *evt, uint8_t event_id, eb_event_cb_t p_callback, void *usr_data);

/*******************************************************************************
 * Set event as active, The specified callback will be executed when event schedule
 * @param   evt       The pointer of event module
 * @param   event_id  The max number of events
 * @note    This function can be call in other thread
 ******************************************************************************/
void eb_event_set(struct eb_event *evt, uint8_t event_id);

/*******************************************************************************
 * Schedule once, check active event and process the specified callback
 * @param   evt       The pointer of event module
 * @return  true if at least one event triggered, else false
 ******************************************************************************/
bool eb_event_sche_once(struct eb_event *evt);

#endif /* __EB_EVENT__ */
