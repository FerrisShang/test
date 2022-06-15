#include <string.h>
#include "eb_event.h"

struct event {
    eb_event_cb_t callback;
    void *usr_data;
    size_t active;
};

struct eb_event {
    size_t id_max;
    struct event event[0];
};

struct eb_event *eb_event_create(uint8_t id_max)
{
    EB_EVENT_ASSERT(id_max > 0);
    size_t size = sizeof(struct eb_event) + id_max * sizeof(struct event);
    struct eb_event *evt = (struct eb_event *)EB_EVENT_MALLOC(size);
    EB_EVENT_ASSERT(evt);
    memset(evt, 0, size);
    evt->id_max = id_max;
    return evt;
}

void eb_event_callback_set(struct eb_event *evt, uint8_t event_id, eb_event_cb_t p_callback, void *usr_data)
{
    EB_EVENT_ASSERT(evt && event_id < evt->id_max);
    evt->event[event_id].callback = p_callback;
    evt->event[event_id].usr_data = usr_data;
}

void eb_event_set(struct eb_event *evt, uint8_t event_id)
{
    EB_EVENT_ASSERT(evt && event_id < evt->id_max);
    evt->event[event_id].active = true;
}

bool eb_event_sche_once(struct eb_event *evt)
{
    EB_EVENT_ASSERT(evt);
    size_t i;
    uint8_t active, ret = false;
    do {
        active = false;
        for (i = 0; i < evt->id_max; i++) {
            if (evt->event[i].active) {
                evt->event[i].active = false;
                EB_EVENT_ASSERT(evt->event[i].callback);
                evt->event[i].callback(evt->event[i].usr_data);
                ret = true;
                active = true;
            }
        }
    } while (active);
    return ret;
}

