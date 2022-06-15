#include <string.h>
#include "eb_alarm.h"
#include "eb_timer.h"

struct eb_timer {
    struct eb_alarm *alarm;
    eb_timer_t *items;
};

struct eb_timer *eb_timer_create(void alarm_irq_handler(void *p), void *usr_data)
{
    struct eb_timer *timer = (struct eb_timer *)EB_TIMER_MALLOC(sizeof(struct eb_timer));
    EB_TIMER_ASSERT(timer);
    timer->alarm = eb_alarm_create(alarm_irq_handler, usr_data);
    timer->items = NULL;
    EB_TIMER_ASSERT(timer->alarm);
    return timer;
}

size_t eb_timer_set(struct eb_timer *timer, eb_timer_t *timer_item, size_t delay_10ms,
                    void(*callback)(void *p), void *usr_data)
{
    EB_TIMER_ASSERT(timer_item);
    size_t now = eb_alarm_get_10ms();
    size_t latest_10ms = EB_TIMER_MAX;

    timer_item->target_time = now + delay_10ms;
    timer_item->timeout_callback = callback;
    EB_TIMER_ASSERT(timer_item->timeout_callback);
    timer_item->usr_data = usr_data;

    eb_timer_t *t = timer->items;
    while (t) {
        if (t == timer_item) {
            break;
        }
        t = t->next;
    }
    if (t != timer_item) {
        // timer_item not in the list, insert a new one
        timer_item->next = timer->items;
        timer->items = timer_item;
    }
    // calculate latest time in timer list, unit 10ms
    t = timer->items;
    while (t) {
        size_t diff = eb_alarm_diff_10ms(now, t->target_time);
        latest_10ms = latest_10ms < diff ? latest_10ms : diff;
        t = t->next;
    }

    if (latest_10ms != EB_TIMER_MAX) {
        eb_alarm_set(timer->alarm, latest_10ms);
    }
    return latest_10ms;
}

size_t eb_timer_del(struct eb_timer *timer, eb_timer_t *timer_item)
{
    size_t now = eb_alarm_get_10ms();
    size_t latest_10ms = EB_TIMER_MAX;
    eb_timer_t *prev = NULL, *t = timer->items;
    while (t) {
        if (t == timer_item) {
            if (prev) {
                prev->next = t->next;
            } else {
                timer->items = t->next;
            }
            memset(timer_item, 0, sizeof(eb_timer_t));
        } else {
            size_t diff = eb_alarm_diff_10ms(now, t->target_time);
            latest_10ms = latest_10ms < diff ? latest_10ms : diff;
        }
        prev = t;
        t = t->next;
    }

    if (latest_10ms != EB_TIMER_MAX) {
        eb_alarm_set(timer->alarm, latest_10ms);
    } else {
        eb_alarm_del(timer->alarm);
    }
    return latest_10ms;
}

bool eb_timer_schedule_once(struct eb_timer *timer)
{
    EB_TIMER_ASSERT(timer);
    eb_timer_t *t = timer->items;
    void (*timeout_callback)(void *p) = NULL;
    void *usr_data;
    while (t) {
        if (eb_alarm_ring(t->target_time)) {
            break;
        }
        t = t->next;
    }
    if (t) {
        timeout_callback = t->timeout_callback;
        usr_data = t->usr_data;
        eb_timer_del(timer, t);
        timeout_callback(usr_data);
        return true;
    }
    return false;
}

