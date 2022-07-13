#ifndef __BLOCK_RINGBUF_H__
#define __BLOCK_RINGBUF_H__

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include "eb_memory.h"
#include "eb_debug.h"

#define EB_BRINGBUF_MALLOC EB_MALLOC
#define EB_BRINGBUF_ASSERT EB_ASSERT

typedef size_t br_size_t;

struct block_ringbuf {
    size_t size;
    size_t read_index;
    size_t read_mark;
    size_t write_index;
    size_t write_mark;
    br_size_t *buffer;
};

// buffer MUST aligned with br_size_t
void block_queue_create(struct block_ringbuf *br, void *buffer, size_t size);
uint8_t *block_queue_push_peek(struct block_ringbuf *br, br_size_t size);
void block_queue_push(struct block_ringbuf *br);
uint8_t *block_queue_pop_peek(struct block_ringbuf *br, br_size_t *size);
void block_queue_pop(struct block_ringbuf *br);

#endif /* __BLOCK_RINGBUF_H__ */
