#include "block_ringbuf.h"

void block_queue_create(struct block_ringbuf *br, void *buffer, size_t size)
{
    EB_BRINGBUF_ASSERT(br);
    br->size = size & ~((1 << sizeof(br_size_t)) - 1);
    br->buffer = (br_size_t *)buffer;
    br->read_index = 0;
    br->write_index = 0;
}

uint8_t *block_queue_push_peek(struct block_ringbuf *br, size_t size)
{
    size_t read_index = br->read_index;
    size_t buf_cnt = 1 + (size + sizeof(br_size_t) - 1) / sizeof(br_size_t);
    if (br->write_index >= read_index) {
        size_t right_free = br->size / sizeof(br_size_t) - br->write_index;
        if (right_free > buf_cnt) {
            br->buffer[br->write_index] = size;
            br->write_mark = br->write_index + buf_cnt;
            return (uint8_t *)&br->buffer[br->write_index + 1];
        }
        br->buffer[br->write_index] = 0; // Mark right empty buffer is unused
        size_t left_free = read_index;
        if (left_free > buf_cnt) {
            br->buffer[0] = size;
            br->write_mark = buf_cnt;
            return (uint8_t *)&br->buffer[1];
        }
    } else {
        size_t middle_free = read_index - br->write_index - 1;
        if (middle_free > buf_cnt) {
            br->buffer[br->write_index] = size;
            br->write_mark = br->write_index + buf_cnt;
            return (uint8_t *)&br->buffer[br->write_index + 1];
        }
    }
    return NULL;
}

void block_queue_push(struct block_ringbuf *br)
{
    br->write_index = br->write_mark;
}

uint8_t *block_queue_pop_peek(struct block_ringbuf *br, size_t *size)
{
    if (br->write_index == br->read_index) {
        *size = 0;
        return NULL;
    }
    if (br->buffer[br->read_index] == 0) {
        *size = br->buffer[0];
        size_t buf_cnt = 1 + (*size + sizeof(br_size_t) - 1) / sizeof(br_size_t);
        br->read_mark = buf_cnt;
        return (uint8_t *)(br->buffer + 1);
    } else {
        *size = br->buffer[br->read_index];
        size_t buf_cnt = 1 + (*size + sizeof(br_size_t) - 1) / sizeof(br_size_t);
        br->read_mark = br->read_index + buf_cnt;
        return (uint8_t *)&br->buffer[br->read_index + 1];
    }
}

void block_queue_pop(struct block_ringbuf *br)
{
    br->read_index = br->read_mark;
}

