#ifndef __BTSNOOP_REC_H__
#define __BTSNOOP_REC_H__

#include <stdio.h>
#include <stdint.h>
#define DATA_DIR_SEND 0
#define DATA_DIR_RECV 1

struct btsnoop;
struct btsnoop *create_btsnoop_rec(const char *path);
void close_btsnoop_rec(struct btsnoop *btsnoop);
void record_btsnoop(struct btsnoop *btsnoop, uint8_t *hci_data, int data_len, char data_dir);

#endif /* __BTSNOOP_REC_H__ */
