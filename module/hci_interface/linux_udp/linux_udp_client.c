#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <assert.h>
#include "linux_udp_client.h"

struct linux_udp_client {
    int socket_fd;
    struct sockaddr_in si_other;
    pthread_t recv_th;
    int recv_cb_running_flag;
    void (*recv_callback)(uint8_t *, int, void *);
    void *recv_param;
};

static void *udp_client_cb(void *p)
{
    struct linux_udp_client *client = (struct linux_udp_client *)p;
    client->recv_cb_running_flag = true;
    uint8_t recv_buf[260];
    int slen = sizeof(client->si_other);
    while (client->recv_cb_running_flag) {
        int len = recvfrom(client->socket_fd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *) &client->si_other,
                           (socklen_t *)&slen);
        if (len == -1) {
            perror("recvfrom()");
            LINUX_UDP_CLIENT_ASSERT(0);
        }
        client->recv_callback(recv_buf, len, client->recv_param);
    }
    return NULL;
}

struct linux_udp_client *udp_client_create(char *ip, int port, void (*recv_cb)(uint8_t *, int, void *), void *p)
{
    struct linux_udp_client *client = LINUX_UDP_CLIENT_MALLOC(sizeof(struct linux_udp_client));
    LINUX_UDP_CLIENT_ASSERT(client);
    if ( (client->socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("socket");
        LINUX_UDP_CLIENT_ASSERT(0);
    }

    memset((char *) &client->si_other, 0, sizeof(client->si_other));
    client->si_other.sin_family = AF_INET;
    client->si_other.sin_port = htons(port);

    if (inet_aton(ip, &client->si_other.sin_addr) == 0) {
        fprintf(stderr, "inet_aton() failed\n");
        LINUX_UDP_CLIENT_ASSERT(0);
    }
    client->recv_callback = recv_cb;
    client->recv_param = p;
    pthread_create(&client->recv_th, NULL, udp_client_cb, client);
    while (!client->recv_cb_running_flag);
    return client;
}

void udp_client_send(struct linux_udp_client *client, uint8_t *data, int len)
{
    int slen = sizeof(client->si_other);
    if (sendto(client->socket_fd, data, len, 0, (struct sockaddr *) &client->si_other, slen) == -1) {
        perror("sendto()");
        LINUX_UDP_CLIENT_ASSERT(0);
    }
}

