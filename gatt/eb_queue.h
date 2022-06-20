#ifndef __EB_QUEUE_H__
#define __EB_QUEUE_H__

#include <stdlib.h>
#include <string.h>

struct eb_queue_item {
    struct eb_queue_item *next;
};

struct eb_queue_header {
    struct eb_queue_item *first;
    struct eb_queue_item *last;
};

inline static void eb_queue_init(struct eb_queue_header *header)
{
    memset(header, 0, sizeof(struct eb_queue_header));
}

inline static void eb_queue_push(struct eb_queue_header *header, struct eb_queue_item *p)
{
    if (header->last == NULL) {
        header->first = p;
    } else {
        header->last->next = p;
    }
    header->last = p;
    p->next = NULL;
}

inline static struct eb_queue_item *eb_queue_peek(struct eb_queue_header *header)
{
    return header->first;
}

inline static struct eb_queue_item *eb_queue_pop(struct eb_queue_header *header)
{
    if (header->first == NULL) {
        return NULL;
    } else {
        struct eb_queue_item *p = header->first;
        if (header->first == header->last) {
            header->first = header->last = NULL;
        } else {
            header->first = p->next;
        }
        return p;
    }
}

#endif /* __EB_QUEUE_H__ */

