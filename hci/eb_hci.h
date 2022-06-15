#ifndef __EB_HCI_H__
#define __EB_HCI_H__

#include <assert.h>
#include <stdint.h>
#include <stddef.h>

#include "eb_hci_command.h"
#include "eb_hci_event.h"
#include "eb_hci_cmd_cmp.h"
#include "eb_hci_le_event.h"
#include "eb_hci_version.h"
#include "eb_hci_manufacturer_name.h"

#define EB_HCI_MALLOC malloc
#define EB_HCI_FREE   free
#define EB_HCI_ASSERT assert

struct eb_hci;

struct vendor_hci_evt_proc {
    uint8_t evt_code;
    void (*vendor_proc)(uint8_t evt_code, uint8_t *data, int len, void *usr_data);
};

struct eb_hci_cfg {
    void (*send)(uint8_t *data, int len, void *usr_data);
    void (*hci_proc_cmp)(uint16_t opcode, void *payload, int len, void *usr_data); // payload @ref eb_hci_status.h
    void (*hci_proc_evt)(uint8_t evt_code, void *payload, int len, void *usr_data); // payload @ref eb_hci_event.h
    void (*hci_proc_le_evt)(uint8_t subcode, void *payload, int len, void *usr_data); // payload @ref eb_hci_le_event.h
    struct vendor_hci_evt_proc *vendor_proc_list; // End by {0, NULL}
};

struct eb_hci *eb_hci_init(struct eb_hci_cfg *cfg, void *usr_data);
void eb_hci_cmd_send(struct eb_hci *hci,  uint16_t opcode, void *payload); // payload @ref eb_hci_command.h
void eb_hci_vendor_send(struct eb_hci *hci, uint16_t opcode, uint8_t *data, int len);
void eb_evt_received(struct eb_hci *hci,  uint8_t evt_code, uint8_t *payload, int len);

char *eb_get_manufacturer_name(uint16_t id);
char *eb_get_version_name(uint8_t ver);

#endif /* __EB_HCI_H__ */

