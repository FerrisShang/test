#include <time.h>
#include <unistd.h>
#include "eb_alarm.h"

struct eb_alarm {
    void(*callback)(void *p);
    void *usr_data;
    size_t target_time;
};

size_t eb_alarm_get_10ms(void)
{
    size_t ms = 0;
    return ms & (EB_ALARM_MAX - 1);
}

size_t eb_alarm_diff_10ms(size_t now, size_t target)
{
    if (target != EB_ALARM_MAX) {
        return (target - now) & ((EB_ALARM_MAX >> 1) - 1);
    }
    return EB_ALARM_MAX;
}

struct eb_alarm *eb_alarm_create(void(*callback)(void *p), void *usr_data)
{
    struct eb_alarm *alarm = (struct eb_alarm *)EB_ALARM_MALLOC(sizeof(struct eb_alarm));
    EB_ALARM_ASSERT(alarm);
    alarm->callback = callback;
    EB_ALARM_ASSERT(alarm->callback);
    alarm->usr_data = usr_data;
    alarm->target_time = EB_ALARM_MAX;
    return alarm;
}

void eb_alarm_set(struct eb_alarm *alarm, size_t delay_10ms)
{
    EB_ALARM_ASSERT(alarm);
    EB_ALARM_ASSERT(delay_10ms < (EB_ALARM_MAX >> 1));
    size_t now = eb_alarm_get_10ms();
    alarm->target_time = (now + delay_10ms) & (EB_ALARM_MAX - 1);
}

void eb_alarm_del(struct eb_alarm *alarm)
{
    EB_ALARM_ASSERT(alarm);
    alarm->target_time = EB_ALARM_MAX;
}

bool eb_alarm_ring(size_t target_time_10ms)
{
    if (target_time_10ms != EB_ALARM_MAX) {
        size_t now = eb_alarm_get_10ms();
        return (((now - target_time_10ms) & (EB_ALARM_MAX - 1)) < (EB_ALARM_MAX >> 1));
    }
    return false;
}
