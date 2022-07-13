#include <string.h>
#include <stdbool.h>

struct eb_pending {
    void(*active_cb)(void *p);
    void *usr_data;
};

struct eb_pending *eb_pending_create(void)
{
    struct eb_pending *pending = NULL;
    return pending;
}

void eb_pending_wait(struct eb_pending *pending)
{
}

void eb_pending_trigger(struct eb_pending *pending)
{
}

