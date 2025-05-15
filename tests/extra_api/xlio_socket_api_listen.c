/*
 * Copyright © 2019-2024 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* g++ -I./install/include -L./install/lib -L../dpcp/install/lib -o test xlio_socket_api_listen.c -lxlio -lm -lnl-3 -ldpcp -libverbs -lmlx5 -lrdmacm -lnl-route-3 -g3 */
/* LD_LIBRARY_PATH=./install/lib:../dpcp/install/lib ./test */
/* Use `nc <IP> <PORT>` on the remote side */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <mellanox/xlio.h>
#include <infiniband/verbs.h>

#define LISTEN_MAGIC 0xdeadc0de

static bool quit = false;
static bool terminated = false;
static int g_comp_events = 0;
static char sndbuf[256];

static struct ibv_pd *pd = NULL;
static struct ibv_mr *mr_buf;

static unsigned sock_nr = 0;
static unsigned destroyed_sock_nr = 0;
static xlio_socket_t sock_arr[32];

static unsigned short listen_port = 8080;
static const char *listen_ip = "";

static void memory_cb(void *data, size_t size, size_t page_size)
{
    printf("Memory area allocated data=%p size=%zu page_size=%zu\n", data, size, page_size);
}

static void send_single_msg(xlio_socket_t sock, const void *data, size_t len, uintptr_t userdata_op,
                            unsigned flags)
{
    struct xlio_socket_send_attr attr = {
        .flags = flags,
        .mkey = mr_buf->lkey,
        .userdata_op = userdata_op,
    };
    memcpy(sndbuf, data, len);
    int ret = xlio_socket_send(sock, sndbuf, len, &attr);
    assert(ret == 0);
    xlio_socket_flush(sock);
}

static void send_inline_msg(xlio_socket_t sock, const void *data, size_t len, uintptr_t userdata_op,
                            unsigned flags)
{
    struct xlio_socket_send_attr attr = {
        .flags = flags | XLIO_SOCKET_SEND_FLAG_INLINE,
        .mkey = 0,
        .userdata_op = userdata_op,
    };
    int ret = xlio_socket_send(sock, data, len, &attr);
    assert(ret == 0);
    xlio_socket_flush(sock);
}

static void socket_event_cb(xlio_socket_t sock, uintptr_t userdata_sq, int event, int value)
{
    if (event == XLIO_SOCKET_EVENT_ESTABLISHED) {
        printf("Connection established (sock=%lx).\n", userdata_sq);
    } else if (event == XLIO_SOCKET_EVENT_CLOSED) {
        printf("Connection closed passively (sock=%lx).\n", userdata_sq);
    } else if (event == XLIO_SOCKET_EVENT_TERMINATED) {
        printf("Connection terminated (sock=%lx).\n", userdata_sq);
        if (userdata_sq == LISTEN_MAGIC) {
            terminated = true;
        } else {
            ++destroyed_sock_nr;
        }
    } else {
        printf("Event callback: event=%d value=%d (sock=%lx).\n", event, value, userdata_sq);
        if (event == XLIO_SOCKET_EVENT_ERROR) {
            quit = true;
        }
    }
}

static void socket_comp_cb(xlio_socket_t sock, uintptr_t userdata_sq, uintptr_t userdata_op)
{
    const char *reply_msg = "completed\n";

    printf("Completed zcopy buffer userdata_sq=%lx userdata_op=%lx.\n", userdata_sq, userdata_op);
    assert(userdata_sq != 0);
    assert(userdata_op != 0);

    ++g_comp_events;
    if (!quit) {
        /*
         * Don't send data after socket destroy, completions are still possible until
         * XLIO_SOCKET_EVENT_TERMINATED event arrives.
         */
        send_single_msg(sock, reply_msg, strlen(reply_msg), 0, 0);
    }
}

static void socket_rx_cb(xlio_socket_t sock, uintptr_t userdata_sq, void *data, size_t len,
                         struct xlio_buf *buf)
{
    char *msg = (char *)malloc(len + 1);
    memcpy(msg, data, len);
    msg[len] = '\0';
    if (len > 0 && msg[len - 1] == '\n') {
        msg[len - 1] = '\0';
    }
    printf("RECV: %s\n", msg);
    if (strncmp(msg, "quit", 4) == 0 || strncmp(msg, "exit", 4) == 0) {
        quit = true;
    }
    free(msg);

    send_single_msg(sock, data, len, 0xdeadbeef, 0);
    xlio_socket_buf_free(sock, buf);
}

static void socket_accept_cb(xlio_socket_t sock, xlio_socket_t parent_sock,
                             uintptr_t parent_userdata)
{
    struct sockaddr_in6 sa = {};
    socklen_t len = sizeof(sa);
    int rc;
    unsigned short port = 0;
    char buf[64] = "";

    rc = xlio_socket_getpeername(sock, (struct sockaddr *)&sa, &len);
    if (rc != 0) {
        printf("Failed to get peername of an incoming socket.\n");
        // XXX Cannot close the socket in this callback in the current implementation.
        return;
    }

    switch (sa.sin6_family) {
    case AF_INET:
        inet_ntop(AF_INET, &((struct sockaddr_in *)&sa)->sin_addr, buf, sizeof(buf));
        port = ntohs(((struct sockaddr_in *)&sa)->sin_port);
        break;
    case AF_INET6:
        inet_ntop(AF_INET6, &sa.sin6_addr, buf, sizeof(buf));
        port = ntohs(sa.sin6_port);
        break;
    default:
        printf("Unknown AF: %u.\n", sa.sin6_family);
    }

    if (!pd) {
        pd = xlio_socket_get_pd(sock);
        assert(pd != NULL);
        mr_buf = ibv_reg_mr(pd, sndbuf, sizeof(sndbuf), IBV_ACCESS_LOCAL_WRITE);
        assert(mr_buf != NULL);
    }

    sock_arr[sock_nr++] = sock;

    uintptr_t userdata_sq = (uintptr_t)sock_nr;
    rc = xlio_socket_update(sock, 0, userdata_sq);
    if (rc != 0) {
        printf("Failed to update context of an incoming socket.\n");
    }
    printf("Accepted incoming connection from %s:%u userdata_sq=%lx.\n", buf, port, userdata_sq);
}

int main(int argc, char **argv)
{
    xlio_poll_group_t group;
    xlio_socket_t sock;
    int rc;

    struct xlio_init_attr iattr = {
        .flags = 0,
        .memory_cb = &memory_cb,
    };
    struct xlio_poll_group_attr gattr = {
        .socket_event_cb = &socket_event_cb,
        .socket_comp_cb = &socket_comp_cb,
        .socket_rx_cb = &socket_rx_cb,
        .socket_accept_cb = &socket_accept_cb,
    };

    if (argc > 1 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        printf("Usage: %s [IP [PORT]]\n", argv[0]);
        printf("Run 'nc <IP> <PORT>' on the client side.\n");
        printf("Type messages on the nc side.\n");
        printf("Message 'quit' or 'exit' will terminate the server.\n");
        return 0;
    }

    rc = xlio_init_ex(&iattr);
    assert(rc == 0);

    rc = xlio_poll_group_create(&gattr, &group);
    assert(rc == 0);

    printf("Group created.\n");

    struct xlio_socket_attr sattr = {
        .domain = AF_INET,
        .group = group,
        .userdata_sq = LISTEN_MAGIC,
    };

    rc = xlio_socket_create(&sattr, &sock);
    assert(rc == 0);

    printf("Listen socket created.\n");

    if (argc > 1) {
        listen_ip = argv[1];
    }
    if (argc > 2) {
        listen_port = atoi(argv[2]);
    }
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(listen_port);
    if (listen_ip[0] != '\0') {
        rc = inet_aton(argv[1], &addr.sin_addr);
        assert(rc != 0);
    }
    rc = xlio_socket_bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    assert(rc == 0);

    printf("Listen socket bound to %s:%u.\n", listen_ip, listen_port);

    rc = xlio_socket_listen(sock);
    assert(rc == 0);

    printf("Listen.\n");
    printf("Starting polling loop.\n");

    while (!quit) {
        xlio_poll_group_poll(group);
    }

    printf("Quiting...\n");

    rc = xlio_socket_destroy(sock);
    assert(rc == 0);
    for (unsigned i = 0; i < sock_nr; ++i) {
        rc = xlio_socket_destroy(sock_arr[i]);
        assert(rc == 0);
    }
    while (!terminated || destroyed_sock_nr < sock_nr) {
        xlio_poll_group_poll(group);
    }

    printf("All the sockets are destroyed.\n");

    rc = xlio_poll_group_destroy(group);
    assert(rc == 0);

    printf("Zerocopy completion events: %d\n", g_comp_events);

    if (mr_buf) {
        ibv_dereg_mr(mr_buf);
    }
    xlio_exit();

    return 0;
}
