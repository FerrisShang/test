#ifndef __EB_H4TL_H__
#define __EB_H4TL_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define EB_H4TL_MALLOC malloc
#define EB_H4TL_ASSERT assert

#define HCI_BUFFER_SIZE 0x1000

struct eb_h4tl;

/*******************************************************************************
 * Create h4tl module, if CONFIG_BTSNOOP defined, a btsnoop file will be created
 * @prarm    send_cb           The callback for sending hci data
 * @prarm    recv_cb           The callback for process received hci data
 * @prarm    usr_data          user data
 * @prarm    btsnoop_filename  btsnoop file name, not use if CONFIG_BTSNOOP not defiend
 * @return   pointer of h4tl module
 ******************************************************************************/
struct eb_h4tl *eb_h4tl_create(void(*send_cb)(uint8_t *data, size_t len, void *p),
                               void(*recv_cb)(uint8_t *data, size_t len, void *p), void *usr_data,
                               char *btsnoop_filename);

/*******************************************************************************
 * send hci data, send_cb in eb_h4tl_create will be called
 * @prarm    h4tl   pointer of h4tl module
 * @prarm    data   data to be sent
 * @prarm    len    length of data
 ******************************************************************************/
void eb_h4tl_send(struct eb_h4tl *h4tl, uint8_t *data, size_t len);

/*******************************************************************************
 * received hci data, recv_cb in eb_h4tl_create will be called when schedule
 * @prarm    h4tl   pointer of h4tl module
 * @prarm    data   data received
 * @prarm    len    length of data
 * @note     This function can be called in other thread, data received can be cached in buffer
 ******************************************************************************/
void eb_h4tl_received(struct eb_h4tl *h4tl, uint8_t *data, size_t len);

/*******************************************************************************
 * Schedule once, received buffer and execute recv_cb
 * @return  true if at least one hci data processed, else false
 ******************************************************************************/
bool eb_h4tl_sche_once(struct eb_h4tl *h4tl);

#endif /* __EB_H4TL_H__ */
