#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <semaphore.h>
#include "eb_pending_linux.h"

struct eb_pending {
    sem_t sem;
    void(*active_cb)(void *p);
    void *usr_data;
};

struct eb_pending *eb_pending_create(void)
{
    struct eb_pending *pending = (struct eb_pending *)EB_PENDING_MALLOC(sizeof(struct eb_pending));
    EB_PENDING_ASSERT(pending);
    sem_init(&pending->sem, 1, 0);
    return pending;
}

void eb_pending_wait(struct eb_pending *pending)
{
    sem_wait(&pending->sem);
    while (!sem_trywait(&pending->sem));
}

void eb_pending_trigger(struct eb_pending *pending)
{
    sem_post(&pending->sem);
}

