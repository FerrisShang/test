#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include "eb_alarm.h"

struct eb_alarm {
    void(*callback)(void *p);
    void *usr_data;
    size_t target_time;
    pthread_t thread;
    pthread_mutex_t mutex;
};

size_t eb_alarm_get_10ms(void)
{
    size_t ms;
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    ms = spec.tv_sec * 100 + spec.tv_nsec / 10000000;
    return ms & (EB_ALARM_MAX - 1);
}

size_t eb_alarm_diff_10ms(size_t now, size_t target)
{
    if (target != EB_ALARM_MAX) {
        return (target - now) & ((EB_ALARM_MAX >> 1) - 1);
    }
    return EB_ALARM_MAX;
}

static void *alarm_thread(void *p)
{
    struct eb_alarm *alarm = (struct eb_alarm *)p;
    while (1) {
        usleep(5000);
        if (alarm->target_time == EB_ALARM_MAX) {
            continue;
        }
        pthread_mutex_lock(&alarm->mutex);
        if (eb_alarm_ring(alarm->target_time)) {
            alarm->target_time = EB_ALARM_MAX;
            pthread_mutex_unlock(&alarm->mutex);
            alarm->callback(alarm->usr_data);
        } else {
            pthread_mutex_unlock(&alarm->mutex);
        }
    }
    return NULL;
}

struct eb_alarm *eb_alarm_create(void(*callback)(void *p), void *usr_data)
{
    struct eb_alarm *alarm = (struct eb_alarm *)EB_ALARM_MALLOC(sizeof(struct eb_alarm));
    EB_ALARM_ASSERT(alarm);
    alarm->callback = callback;
    EB_ALARM_ASSERT(alarm->callback);
    alarm->usr_data = usr_data;
    alarm->target_time = EB_ALARM_MAX;
    pthread_mutex_init(&alarm->mutex, NULL);
    pthread_create(&alarm->thread, NULL, alarm_thread, (void *)alarm);
    return alarm;
}

void eb_alarm_set(struct eb_alarm *alarm, size_t delay_10ms)
{
    EB_ALARM_ASSERT(alarm);
    EB_ALARM_ASSERT(delay_10ms < (EB_ALARM_MAX >> 1));
    size_t now = eb_alarm_get_10ms();
    pthread_mutex_lock(&alarm->mutex);
    alarm->target_time = (now + delay_10ms) & (EB_ALARM_MAX - 1);
    pthread_mutex_unlock(&alarm->mutex);
}

void eb_alarm_del(struct eb_alarm *alarm)
{
    EB_ALARM_ASSERT(alarm);
    pthread_mutex_lock(&alarm->mutex);
    alarm->target_time = EB_ALARM_MAX;
    pthread_mutex_unlock(&alarm->mutex);
}

bool eb_alarm_ring(size_t target_time_10ms)
{
    if (target_time_10ms != EB_ALARM_MAX) {
        size_t now = eb_alarm_get_10ms();
        return (((now - target_time_10ms) & (EB_ALARM_MAX - 1)) < (EB_ALARM_MAX >> 1));
    }
    return false;
}
