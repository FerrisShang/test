#include <string.h>
#include "eb_att.h"

struct eb_att_db {
    uint8_t max_serv_num;
    uint8_t serv_num;
    const struct eb_att_serv *serv[0];
};

const struct eb_uuid_16bit eb_att_serv_def = { 2, { 0x00, 0x28 } };
const struct eb_uuid_16bit eb_att_secs_def = { 2, { 0x01, 0x28 } };
const struct eb_uuid_16bit eb_att_incl_def = { 2, { 0x02, 0x28 } };
const struct eb_uuid_16bit eb_att_char_def = { 2, { 0x03, 0x28 } };
const struct eb_uuid_16bit eb_att_cudd_def = { 2, { 0x01, 0x29 } };
const struct eb_uuid_16bit eb_att_cccd_def = { 2, { 0x02, 0x29 } };
const struct eb_uuid_16bit eb_att_rrd_def  = { 2, { 0x09, 0x29 } };

int eb_att_db_init(void *att_db, int db_size)
{
    struct eb_att_db *db = (struct eb_att_db*)att_db;
    int serv_size = (db_size - offsetof(struct eb_att_db, serv));
    if(serv_size > 0){
        memset(att_db, 0, db_size);
        db->max_serv_num = serv_size / sizeof(void*);
    } else {
        db->max_serv_num = 0;
    }
    return db->max_serv_num;
}

int eb_att_db_add(void*att_db, const struct eb_att_serv *att_serv)
{
    struct eb_att_db *db = att_db;
    if (db->serv_num >= db->max_serv_num) {
        EB_ATT_WARNING(0);
        return EB_ATT_INVALID_HANDLE;
    }
    int i, start_handle = 1;
    for(i=0;i<db->serv_num;i++){
        start_handle += db->serv[i]->att_num + 1;
    }
    db->serv[db->serv_num++] = att_serv;
    return start_handle;
}

void eb_att_db_iter(const void *att_db, uint16_t start_handle, eb_att_db_search_cb_t cb, void *usr_data)
{
    const struct eb_att_db *db = att_db;
    const struct eb_att_serv *cs = NULL; // current service
    int handle_start = 1; // service handle start
    int si; // service index
    int ret = EB_ATT_SEARCH_CONTINUE;
    EB_ATT_ASSERT(cb);
    for (si = 0; si < db->serv_num; si++) {
        int ii; // att item index
        handle_start += cs ? cs->att_num + 1 : 0;
        cs = db->serv[si];
        if (handle_start + cs->att_num < start_handle) {
            continue;
        }
        if (handle_start >= start_handle) {
            ret = cb(handle_start, cs, NULL, usr_data);
        }
        if (ret == EB_ATT_SEARCH_CONTINUE) {
            for (ii = 0; ii < cs->att_num; ii++) {
                const struct eb_att_item *ci = &cs->item[ii];
                int current_handle = handle_start + 1 + ii;
                if (current_handle < start_handle) {
                    continue;
                }
                ret = cb(current_handle, cs, ci, usr_data);
                if (ret != EB_ATT_SEARCH_CONTINUE) {
                    break;
                }
            }
        }
        if (ret == EB_ATT_SEARCH_EXIT) {
            break;
        }
    }
    if (ret != EB_ATT_SEARCH_EXIT) {
        cb(EB_ATT_INVALID_HANDLE, NULL, NULL, usr_data);
    }
}

struct find_param {
    void *p;
    eb_att_db_search_cb_t cb;
    uint16_t handle;
    uint8_t found;
};
static int find_by_handle_cb(uint16_t handle, const struct eb_att_serv *serv,
                             const struct eb_att_item *item, void *usr_data)
{
    struct find_param *p = (struct find_param *)usr_data;
    if (handle > p->handle) {
        return EB_ATT_SEARCH_EXIT;
    }
    if (handle == p->handle) {
        if (p->cb) {
            p->cb(handle, serv, item, p->p);
        }
        p->found = true;
    }
    return EB_ATT_SEARCH_EXIT;
}
bool eb_att_db_find_by_handle(const void*att_db, uint16_t handle, eb_att_db_search_cb_t cb, void *usr_data)
{
    struct find_param param = { usr_data, cb, handle };
    eb_att_db_iter(att_db, handle, find_by_handle_cb, &param);
    return param.found;
}

