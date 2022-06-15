#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#define BUF_SIZE (1 << 10)
struct btsnoop {
    FILE *fp;
    pthread_t th;
    bool running;
    int fr;
    int ra;
    uint8_t *data[BUF_SIZE];
};

#define TIMEDIFF (0x00dcddb30f2f8000ULL)
#define bswap(dat) _bswap((char*)&dat, sizeof(dat))
static void _bswap(char *dat, int len)
{
    int i;
    char tmp;
    for (i = 0; i < len / 2; i++) {
        tmp = dat[i];
        dat[i] = dat[len - 1 - i];
        dat[len - 1 - i] = tmp;
    }
}

static long long *current_timestamp(void)
{
    static long long milliseconds;
    struct timeval te;
    gettimeofday(&te, NULL);
    milliseconds = te.tv_sec * 1000000LL + te.tv_usec + TIMEDIFF;
    bswap(milliseconds);
    return &milliseconds;
}

static void *recv_th(void *p);
struct btsnoop *create_btsnoop_rec(const char *path)
{
    char *id = (char *)"btsnoop";
    char version[] = {0x00, 0x00, 0x00, 0x01};
    uint8_t type[] = {0x00, 0x00, 0x03, 0xEA};
    struct btsnoop *btsnoop = calloc(1, sizeof(struct btsnoop));
    if (!btsnoop) {
        fprintf(stderr, "[btsnoop_hci.log] malloc failed !\n");
        fflush(stderr);
        return NULL;
    }
    btsnoop->fp = fopen(path, "wb");
    FILE *fp = btsnoop->fp;
    if (fp) {
        fwrite(id, 8, 1, fp);
        fwrite(version, 4, 1, fp);
        fwrite(type, 4, 1, fp);
    }
    pthread_create(&btsnoop->th, NULL, recv_th, btsnoop);
    while (btsnoop->running != true);
    return btsnoop;
}

void close_btsnoop_rec(struct btsnoop *btsnoop)
{
    if (btsnoop->fp == NULL) {
        return;
    }
    fflush(btsnoop->fp);
    fclose(btsnoop->fp);
}

static void _record_btsnoop(struct btsnoop *btsnoop, uint8_t *hci_data, int data_len, char data_dir);
static void *recv_th(void *p)
{
    struct btsnoop *b = (struct btsnoop *)p;
    b->running = true;
    while (b->running) {
        usleep(50000);
        bool changed = false;
        while (b->fr != b->ra) {
            uint16_t len = *(uint16_t *)&b->data[b->fr][0];
            uint16_t dir = *(uint16_t *)&b->data[b->fr][2];
            uint8_t *data = &b->data[b->fr][4];
            _record_btsnoop(b, data, len, dir);
            free(b->data[b->fr]);
            b->fr = ( b->fr + 1) & (BUF_SIZE - 1);
            changed = true;
        }
        if (changed) {
            fflush(b->fp);
        }
    }
    return NULL;
}

void record_btsnoop(struct btsnoop *btsnoop, uint8_t *hci_data, int data_len, char data_dir)
{
    uint8_t *buf = malloc(data_len + sizeof(uint16_t) * 2);
    if (!buf) {
        fprintf(stderr, "Data malloc failed !\n");
        fflush(stderr);
        btsnoop->running = false;
        return;
    }
    *(uint16_t *)&buf[0] = data_len;
    *(uint16_t *)&buf[2] = data_dir;
    memcpy(&buf[4], hci_data, data_len);
    btsnoop->data[btsnoop->ra] = buf;
    btsnoop->ra = (btsnoop->ra + 1) & (BUF_SIZE - 1);
    if (btsnoop->ra == btsnoop->fr) { // assert queue not overflow
        fprintf(stderr, "Data malloc failed !\n");
        fflush(stderr);
        btsnoop->running = false;
        return;
    }
}

static void _record_btsnoop(struct btsnoop *btsnoop, uint8_t *hci_data, int data_len, char data_dir)
{
    int tLen = data_len;
    char drops[4] = {0, 0, 0, 0};
    char flag[4] = {0, 0, 0, 0};
    if (btsnoop == NULL || btsnoop->fp == NULL || hci_data == NULL) {
        return;
    }
    FILE *fp = btsnoop->fp;
    bswap(tLen);
    fwrite(&tLen, 4, 1, fp);
    fwrite(&tLen, 4, 1, fp);
    flag[3] = data_dir & 1;//0 - send; 1 -recv
    if (hci_data[0] == 1 || hci_data[0] == 4) {
        flag[3] |= 0x02;
    }
    fwrite(&flag, 4, 1, fp);
    fwrite(&drops, 4, 1, fp);
    fwrite(current_timestamp(), sizeof(long long), 1, fp);
    fwrite(hci_data, data_len, 1, fp);
}
