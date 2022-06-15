#include <stdio.h>
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libusb-1.0/libusb.h>
#include "linux_usb_hci.h"

struct linux_usb_hci {
    uint16_t vid;
    uint16_t pid;
    libusb_device_handle *usb_dev;
    void (*recv_cb)(uint8_t *, int, void *);
    void *usr_data;
    pthread_t th_acl;
    pthread_t th_evt;
    pthread_mutex_t callback_lock;
};

// Device endpoint(s)
#define USB_EP_EVT_IN   (0x81)
#define USB_EP_CMD_OUT  (0x01 << 5)
#define USB_EP_ACL_IN   (0x82)
#define USB_EP_ACL_OUT  (0x02)

// Device configuration and interface id.
#define MY_CONFIG 1
#define MY_INTF   0
#define TRAN_TOUT (500)

static libusb_device_handle *get_usb_dev(struct linux_usb_hci *hci);
static void *hci_read_evt_th(void *p);
static void *hci_read_acl_th(void *p);

struct linux_usb_hci *usb_hci_create(uint16_t vid, uint16_t pid, void (*recv_cb)(uint8_t *, int, void *), void *p)
{
    struct linux_usb_hci *hci = LINUX_USB_HCI_MALLOC(sizeof(struct linux_usb_hci));
    LINUX_USB_HCI_ASSERT(hci);
    memset(hci, 0, sizeof(struct linux_usb_hci));
    hci->vid = vid;
    hci->pid = pid;
    hci->recv_cb = recv_cb;
    hci->usr_data = p;

    get_usb_dev(hci);
    pthread_mutex_init(&hci->callback_lock, NULL);

    pthread_create(&hci->th_evt, 0, hci_read_evt_th, (void *)hci);
    pthread_create(&hci->th_acl, 0, hci_read_acl_th, (void *)hci);
    return hci;
}

static libusb_device_handle *open_dev(libusb_context *ctx, uint16_t vid, uint16_t pid)
{
    libusb_device **list;
    libusb_device_handle *dev_handle = NULL;
    libusb_get_device_list(ctx, &list);
    libusb_device *dev;
    int i = 0;
    while ((dev = list[i++]) != NULL) {
        struct libusb_device_descriptor desc;
        int r = libusb_get_device_descriptor(dev, &desc);
        if (r < 0) {
            continue;
        }
        //printf("%04x %04x\n", desc.idVendor, desc.idProduct);
        if (desc.idVendor == vid && desc.idProduct == pid) {
            libusb_open(dev, &dev_handle);
            if (dev_handle) {
                break;
            }
        }
    }
    libusb_free_device_list(list, 0);
    if (dev_handle) {
        libusb_reset_device(dev_handle);
    }
    return dev_handle;
}

static libusb_device_handle *get_usb_dev(struct linux_usb_hci *hci)
{
    if (hci->usb_dev) {
        return hci->usb_dev;
    }
    libusb_context *ctx;
    int r = libusb_init(&ctx);
    if (r < 0) {
        fprintf(stderr, "failed to initialise libusb\n");
        exit(1);
    }
    hci->usb_dev = open_dev(ctx, hci->vid, hci->pid);
    if (!hci->usb_dev) {
        fprintf(stderr, "Could not find/open device\n");
        goto out;
    }
    libusb_detach_kernel_driver(hci->usb_dev, 0);
    r = libusb_set_configuration(hci->usb_dev, MY_CONFIG);
    if (r < 0) {
        printf("error setting config #%d: %s\n", MY_CONFIG, libusb_strerror(r));
        goto out;
    }
    r = libusb_claim_interface(hci->usb_dev, 0);
    if (r < 0) {
        fprintf(stderr, "usb_claim_interface error %d\n", r);
        goto out;
    }
    //printf("claimed interface\n");
    return hci->usb_dev;
out:
    libusb_close(hci->usb_dev);
    libusb_exit(ctx);
    exit(1);
}

void usb_hci_send(struct linux_usb_hci *hci, uint8_t *data, int len)
{
    libusb_device_handle *dev = get_usb_dev(hci);
    assert(len >= 1 && (data[0] == 0x01 || data[0] == 0x02));
    if (data[0] == 0x01) { //cmd
        libusb_control_transfer(dev, USB_EP_CMD_OUT, 0, 0, 0, data + 1, len - 1, TRAN_TOUT);
    } else if (data[0] == 0x02) { //acl
        int recv_len;
        libusb_bulk_transfer(dev, USB_EP_ACL_OUT, data + 1, len - 1, &recv_len, TRAN_TOUT);
    }
}

static int usb_hci_recv(struct linux_usb_hci *hci, uint8_t *data, int len, int endpoint)
{
    assert(len > 0 && (endpoint == USB_EP_EVT_IN || endpoint == USB_EP_ACL_IN));
    int recv_len = -1;
    libusb_device_handle *dev = get_usb_dev(hci);
    libusb_bulk_transfer(dev, endpoint, data + 1, len - 1, &recv_len, TRAN_TOUT);
    if (recv_len > 0) {
        data[0] = endpoint == USB_EP_EVT_IN ? 0x04 : 0x02;
        return recv_len + 1;
    }
    return recv_len;
}

static void *hci_read_evt_th(void *p)
{
    struct linux_usb_hci *hci = (struct linux_usb_hci *)p;
    uint8_t buf[1024];
    while (1) {
        int res = usb_hci_recv(hci, buf, 1024, USB_EP_EVT_IN);
        if (res > 0) {
            pthread_mutex_lock(&hci->callback_lock);
            hci->recv_cb(buf, res, hci->usr_data);
            pthread_mutex_unlock(&hci->callback_lock);
        } else if (res == -10) {
            break;
        } else {
            usleep(1000);
        }
    }
    return NULL;
}

static void *hci_read_acl_th(void *p)
{
    struct linux_usb_hci *hci = (struct linux_usb_hci *)p;
    uint8_t buf[1024];
    while (1) {
        int res = usb_hci_recv((struct linux_usb_hci *)p, buf, 1024, USB_EP_ACL_IN);
        if (res > 0) {
            pthread_mutex_lock(&hci->callback_lock);
            hci->recv_cb(buf, res, hci->usr_data);
            pthread_mutex_unlock(&hci->callback_lock);
        } else if (res == -10) {
            break;
        } else {
            usleep(1000);
        }
    }
    return NULL;
}

