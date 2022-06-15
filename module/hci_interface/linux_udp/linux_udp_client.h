#ifndef __LINUX_UDP_CLIENT_H__
#define __LINUX_UDP_CLIENT_H__
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#define LINUX_UDP_CLIENT_MALLOC malloc
#define LINUX_UDP_CLIENT_ASSERT assert
struct linux_udp_client;
struct linux_udp_client *udp_client_create(char *ip, int port, void (*recv_cb)(uint8_t *, int, void *), void *p);
void udp_client_send(struct linux_udp_client *, uint8_t *data, int len);

#endif /* __LINUX_UDP_CLIENT_H__ */

