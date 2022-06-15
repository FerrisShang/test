#include <stdint.h>
#include <stdbool.h>
#include "eb_pending.h"
#include "eb_schedule.h"
#include "eb_event.h"

struct eb_sche {
    struct eb_timer *timer;
    struct eb_event *event;
    struct eb_pending *pending;
};

static void alarm_callback(void *p)
{
    struct eb_sche *sche = (struct eb_sche *)p;
    eb_pending_trigger(sche->pending);
}

static void eb_schedule_once(struct eb_sche *sche)
{
    bool active_flag;
    do {
        active_flag = eb_event_sche_once(sche->event);
        if (!active_flag) {
            active_flag = eb_timer_schedule_once(sche->timer);
        }
    } while (active_flag);
}

struct eb_sche *eb_schedule_create(void)
{
    struct eb_sche *sche = EB_SCHE_MALLOC(sizeof(struct eb_sche));
    EB_SCHE_ASSERT(sche);
    sche->timer = eb_timer_create(alarm_callback, sche);
    EB_SCHE_ASSERT(sche->timer);
    sche->event = eb_event_create(EB_EVENT_MAX);
    EB_SCHE_ASSERT(sche->event);
    sche->pending = eb_pending_create();
    EB_SCHE_ASSERT(sche->pending);
    return sche;
}

void eb_schedule(struct eb_sche *sche)
{
    while (1) {
        eb_pending_wait(sche->pending);
        eb_schedule_once(sche);
    }
}

void eb_sche_timer_set(struct eb_sche *sche, eb_sche_timer_t *timer, size_t delay_10ms,
                       void(*callback)(void *p), void *usr_data)
{
    eb_timer_set(sche->timer, timer, delay_10ms, callback, usr_data);
}

void eb_sche_timer_del(struct eb_sche *sche, eb_sche_timer_t *timer)
{
    eb_timer_del(sche->timer, timer);
}

void eb_sche_event_callback_set(struct eb_sche *sche, uint8_t event_id, void (*p_callback)(void *p), void *usr_data)
{
    eb_event_callback_set(sche->event, event_id, p_callback, usr_data);
}

void eb_sche_event_set(struct eb_sche *sche, uint8_t event_id)
{
    eb_event_set(sche->event, event_id);
    eb_pending_trigger(sche->pending);
}

