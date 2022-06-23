#ifndef __EB_ATT_H__
#define __EB_ATT_H__

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include "eb_config.h"
#include "eb_att_opcode.h"

#define EB_ATT_INVALID_HANDLE  0x0000
#define EB_UUID_CMP(uuid1, uuid2) ((uuid1)->uuid_len != (uuid2)->uuid_len || memcmp((uuid1)->uuid, (uuid2)->uuid, (uuid1)->uuid_len))

struct eb_att_db;

enum eb_att_perm {
    EB_ATT_PERM_NOAUTH = 0,
    EB_ATT_PERM_UNAUTH,
};

struct eb_uuid_128bit {
    uint8_t uuid_len;
    uint8_t uuid[16];
};

struct eb_uuid_16bit {
    uint8_t uuid_len;
    uint8_t uuid[2];
};

struct eb_uuid {
    uint8_t uuid_len;
    uint8_t uuid[0];
};

enum eb_att_prop {
    ATT_PROP_EXT       = 1 << 7,
    ATT_PROP_WRITE_SIG = 1 << 6,
    ATT_PROP_INDICATE  = 1 << 5,
    ATT_PROP_NOTIFY    = 1 << 4,
    ATT_PROP_WRITE     = 1 << 3,
    ATT_PROP_WRITE_CMD = 1 << 2,
    ATT_PROP_READ      = 1 << 1,
    ATT_PROP_BROADCAST = 1 << 0,
};

struct eb_att_item {
    const struct eb_uuid *uuid;
    uint8_t att_prop;       // @ref enum eb_att_prop
    uint8_t att_perm_read;  // @ref enum eb_att_perm
    uint8_t att_perm_write; // @ref enum eb_att_perm
};

struct eb_att_serv {
    const struct eb_uuid *serv_uuid;
    const struct eb_att_item *item;
    uint8_t att_num;
};

extern const struct eb_uuid_16bit eb_att_serv_def;
extern const struct eb_uuid_16bit eb_att_secs_def;
extern const struct eb_uuid_16bit eb_att_incl_def;
extern const struct eb_uuid_16bit eb_att_char_def;
extern const struct eb_uuid_16bit eb_att_cudd_def;
extern const struct eb_uuid_16bit eb_att_cccd_def;
extern const struct eb_uuid_16bit eb_att_rrd_def;

/*******************************************************************************
 * Init att database
 * @prarm    max_serv_num  service can be hold
 * @reutrn   pointer of att_db
 ******************************************************************************/
struct eb_att_db *eb_att_db_init(int max_serv_num);

/*******************************************************************************
 * Add att service to database
 * @prarm    att_db   att database
 * @prarm    att_serv @ref struct eb_att_serv
 * @reutrn   start handle of the added service
 * @warning  att_serv and it's related items MUST be static variables
 ******************************************************************************/
int eb_att_db_add(struct eb_att_db *att_db, const struct eb_att_serv *att_serv);

/*******************************************************************************
 * Callback type for att database searching
 * @prarm    handle    ATT handle
 * @prarm    serv      pointer to current ATT service @ref struct eb_att_serv
 * @prarm    item      pointer to current ATT item @ref struct eb_att_item
 * @prarm    usr_data  user data
 * @reutrn   @ref enum eb_att_search_ret
 ******************************************************************************/
enum eb_att_search_ret {
    EB_ATT_SEARCH_CONTINUE  =  0,
    EB_ATT_SEARCH_SKIP_SERV = -1,
    EB_ATT_SEARCH_EXIT      = -2,
};
typedef int (*eb_att_db_search_cb_t)(uint16_t handle, const struct eb_att_serv *serv, const struct eb_att_item *item,
                                     void *usr_data);

/*******************************************************************************
 * Iterate the ATT database to find the corresponding attribute
 * @prarm    att_db        ATT database
 * @prarm    start_handle  start handle
 * @prarm    cb            callback when attribute found
 * @prarm    usr_data      user data
 * @NOTE     In callback, item == 0 if the attribute is service definition
 ******************************************************************************/
void eb_att_db_iter(const struct eb_att_db *att_db, uint16_t start_handle, eb_att_db_search_cb_t cb, void *usr_data);

/*******************************************************************************
 * Iterate the ATT database to find the corresponding attribute by handle
 * @prarm    att_db        ATT database
 * @prarm    handle        handle to find
 * @prarm    cb            callback when attribute found
 * @prarm    usr_data      user data
 * @NOTE     The return value in callback is unused
 ******************************************************************************/
bool eb_att_db_find_by_handle(const struct eb_att_db *att_db, uint16_t handle, eb_att_db_search_cb_t cb,
                              void *usr_data);

#endif /* __EB_ATT_H__ */

