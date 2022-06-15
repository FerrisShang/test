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

#define EB_ATT_DECLARE(name, type, add_size) \
    uint8_t _##name[sizeof(type)+add_size]; \
    type* name = (type*)_##name;
#define EB_ATT_MALLOC  malloc
#define EB_ATT_FREE    free
#define EB_ATT_ASSERT  assert
#define EB_ATT_WARNING(x) do{if(!(x)){printf("Warning: %s@%d\n", __func__, __LINE__);}}while(0)

#define EB_ATT_MAX_SERV_NUM   32
#define EB_ATT_INVALID_HANDLE 0x0000

#define EB_ATT_DECLARE_UUID_16BIT(name, uuid)         const static struct eb_uuid name = { 2, { (uuid) & 0xFF, ((uuid) >> 8) & 0xFF }} ;
#define EB_ATT_DECLARE_UUID_128BIT(name, u0, u1, u2, u3, u4, u5, u6, u7, u8, u9, u10, u11, u12, u13, u14, u15) \
    const static struct eb_uuid name = { 16, {u0, u1, u2, u3, u4, u5, u6, u7, u8, u9, u10, u11, u12, u13, u14, u15} };
#define EB_UUID_EQ(uuid1, uuid2) ((uuid1)->uuid_len == (uuid2)->uuid_len && !memcmp((uuid1)->uuid, (uuid2)->uuid, (uuid1)->uuid_len))



enum eb_att_perm {
    EB_ATT_PERM_NOAUTH = 0,
    EB_ATT_PERM_UNAUTH,
};

struct eb_uuid {
    uint8_t uuid_len;
    uint8_t uuid[16];
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
    uint8_t att_prop; // @ref enum eb_att_prop
    uint8_t att_perm_read;
    uint8_t att_perm_write;
};

struct eb_att_serv {
    const struct eb_uuid *serv_uuid;
    const struct eb_att_item *item;
    uint8_t att_num;
};

struct eb_att_db {
    uint8_t serv_num;
    const struct eb_att_serv *serv[EB_ATT_MAX_SERV_NUM];
};

extern const struct eb_uuid eb_att_serv_def;
extern const struct eb_uuid eb_att_secs_def;
extern const struct eb_uuid eb_att_incl_def;
extern const struct eb_uuid eb_att_char_def;
extern const struct eb_uuid eb_att_cccd_def;
extern const struct eb_uuid eb_att_cudd_def;
extern const struct eb_uuid eb_att_rrd_def;

void eb_att_db_init(struct eb_att_db *db);

/*******************************************************************************
 * Add att service to database
 * @prarm    db       att database
 * @prarm    att_serv @ref struct eb_att_serv
 * @reutrn   start handle of the added service
 * @warning  att_serv and it's related items MUST be static variables
 ******************************************************************************/
int eb_att_db_add(struct eb_att_db *db, const struct eb_att_serv *att_serv);

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
 * @prarm    db            ATT database
 * @prarm    start_handle  start handle
 * @prarm    cb            callback when attribute found
 * @prarm    usr_data      user data
 * @NOTE     In callback, item == 0 if the attribute is service definition
 ******************************************************************************/
void eb_att_db_iter(const struct eb_att_db *db, uint16_t start_handle, eb_att_db_search_cb_t cb, void *usr_data);

/*******************************************************************************
 * Iterate the ATT database to find the corresponding attribute by handle
 * @prarm    db            ATT database
 * @prarm    handle        handle to find
 * @prarm    cb            callback when attribute found
 * @prarm    usr_data      user data
 * @NOTE     The return value in callback is unused
 ******************************************************************************/
bool eb_att_db_find_by_handle(struct eb_att_db *db, uint16_t handle, eb_att_db_search_cb_t cb, void *usr_data);

#endif /* __EB_ATT_H__ */

