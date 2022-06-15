#ifndef __LINUX_USB_HCI_H__
#define __LINUX_USB_HCI_H__
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#define LINUX_USB_HCI_MALLOC malloc
#define LINUX_USB_HCI_ASSERT assert

struct linux_usb_hci;
struct linux_usb_hci *usb_hci_create(uint16_t vid, uint16_t pid, void (*recv_cb)(uint8_t *, int, void *), void *p);
void usb_hci_send(struct linux_usb_hci *hci, uint8_t *data, int len);

#endif /* __LINUX_USB_HCI_H__ */

