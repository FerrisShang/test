#include <stdlib.h>
#include <string.h>
#include "eb_config.h"
#include "eb_h4tl.h"
#include "block_ringbuf.h"

#if defined(CONFIG_BTSNOOP)
    #include "btsnoop_rec.h"
#endif

struct eb_h4tl {
    void(*send_cb)(uint8_t *data, size_t len, void *usr_data);
    void(*recv_cb)(uint8_t *data, size_t len, void *usr_data);
    void *usr_data;
    struct block_ringbuf ringbuf;
    uint8_t hci_buffer[HCI_BUFFER_SIZE];
    #if defined(CONFIG_BTSNOOP)
    struct btsnoop *btsnoop;
    #endif
};

struct eb_h4tl *eb_h4tl_create(void(*send_cb)(uint8_t *, size_t, void *),
                               void(*recv_cb)(uint8_t *, size_t, void * ), void *usr_data,
                               char *btsnoop_filename)
{
    struct eb_h4tl *h4tl = (struct eb_h4tl *)EB_H4TL_MALLOC(sizeof(struct eb_h4tl));
    EB_H4TL_ASSERT(send_cb && recv_cb);
    h4tl->send_cb = send_cb;
    h4tl->recv_cb = recv_cb;
    h4tl->usr_data = usr_data;
    block_queue_create(&h4tl->ringbuf, h4tl->hci_buffer, HCI_BUFFER_SIZE);
    #if defined(CONFIG_BTSNOOP)
    if (!btsnoop_filename) {
        btsnoop_filename = "./btsnoop_hci.log";
    }
    h4tl->btsnoop = create_btsnoop_rec(btsnoop_filename);
    #endif
    return h4tl;
}

void eb_h4tl_send(struct eb_h4tl *h4tl, uint8_t *data, size_t len)
{
    h4tl->send_cb(data, len, h4tl->usr_data);
    #if defined(CONFIG_BTSNOOP)
    record_btsnoop(h4tl->btsnoop, data, len, DATA_DIR_SEND);
    #endif
}

void eb_h4tl_received(struct eb_h4tl *h4tl, uint8_t *data, size_t len)
{
    #if defined(CONFIG_BTSNOOP)
    record_btsnoop(h4tl->btsnoop, data, len, DATA_DIR_RECV);
    #endif
    uint8_t *p = block_queue_push_peek(&h4tl->ringbuf, len);
    EB_H4TL_ASSERT(p); // Overflow !!
    memcpy(p, data, len);
    block_queue_push(&h4tl->ringbuf);
}

bool eb_h4tl_sche_once(struct eb_h4tl *h4tl)
{
    br_size_t size;
    uint8_t *p = block_queue_pop_peek(&h4tl->ringbuf, &size);
    if (p) {
        h4tl->recv_cb(p, size, h4tl->usr_data);
        block_queue_pop(&h4tl->ringbuf);
    }
    return p != NULL;
}

