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

/* g++ -I./install/include -L./install/lib -L../dpcp/install/lib -o test xlio_socket_api.c -lxlio -lm -lnl-3 -ldpcp -libverbs -lmlx5 -lrdmacm -lnl-route-3 -g3 */
/* LD_LIBRARY_PATH=./install/lib:../dpcp/install/lib ./test */
/* Use `nc -l 8080` on the remote side */

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

#define TEST_USERDATA_MAGIC 0xfeedbeef
#define FAKE_PORT           65535

static bool quit = false;
static bool terminated = false;
static int g_test_events;
static int g_comp_events = 0;
static char sndbuf[256];
static struct ibv_mr *mr_buf;

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
        terminated = true;
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
    const char *inline_msg = "inline\n";

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
        send_inline_msg(sock, inline_msg, strlen(inline_msg), 0, 0);
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

static void test_event_cb(xlio_socket_t sock, uintptr_t userdata_sq, int event, int value)
{
    (void)sock;
    (void)value;
    assert(userdata_sq = TEST_USERDATA_MAGIC);

    printf("Test event callback: event=%d value=%d.\n", event, value);

    if (event == XLIO_SOCKET_EVENT_ERROR || event == XLIO_SOCKET_EVENT_TERMINATED) {
        ++g_test_events;
    }
}

static void test_comp_cb(xlio_socket_t sock, uintptr_t userdata_sq, uintptr_t userdata_op)
{
    (void)sock;
    (void)userdata_op;
    assert(userdata_sq = TEST_USERDATA_MAGIC);
}

static void test_rx_cb(xlio_socket_t sock, uintptr_t userdata_sq, void *data, size_t len,
                       struct xlio_buf *buf)
{
    (void)data;
    (void)len;
    assert(userdata_sq = TEST_USERDATA_MAGIC);
    xlio_socket_buf_free(sock, buf);
}

static void test_multi_groups(const char *ip)
{
    xlio_poll_group_t group1;
    xlio_poll_group_t group2;
    xlio_poll_group_t group3;
    xlio_socket_t sock1_1;
    xlio_socket_t sock1_2;
    xlio_socket_t sock2;
    xlio_socket_t sock3;
    int rc;

    struct xlio_poll_group_attr gattr = {
        .socket_event_cb = &test_event_cb,
        .socket_comp_cb = &test_comp_cb,
        .socket_rx_cb = &test_rx_cb,
    };

    rc = xlio_poll_group_create(&gattr, &group1);
    assert(rc == 0);
    rc = xlio_poll_group_create(&gattr, &group2);
    assert(rc == 0);

    gattr.flags = XLIO_GROUP_FLAG_SAFE;
    rc = xlio_poll_group_create(&gattr, &group3);
    assert(rc == 0);

    struct xlio_socket_attr sattr = {
        .domain = AF_INET,
        .userdata_sq = TEST_USERDATA_MAGIC,
    };

    sattr.group = group1;
    rc = xlio_socket_create(&sattr, &sock1_1);
    assert(rc == 0);
    rc = xlio_socket_create(&sattr, &sock1_2);
    assert(rc == 0);
    sattr.group = group2;
    rc = xlio_socket_create(&sattr, &sock2);
    assert(rc == 0);
    sattr.group = group3;
    rc = xlio_socket_create(&sattr, &sock3);
    assert(rc == 0);

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(FAKE_PORT);
    rc = inet_aton(ip, &addr.sin_addr);
    assert(rc != 0);

    g_test_events = 0;
    /* Connect will fail, we need it to allocate rings for the checks below. */
    rc = xlio_socket_connect(sock1_1, (struct sockaddr *)&addr, sizeof(addr));
    assert(rc == 0);
    rc = xlio_socket_connect(sock1_2, (struct sockaddr *)&addr, sizeof(addr));
    assert(rc == 0);
    rc = xlio_socket_connect(sock2, (struct sockaddr *)&addr, sizeof(addr));
    assert(rc == 0);
    rc = xlio_socket_connect(sock3, (struct sockaddr *)&addr, sizeof(addr));
    assert(rc == 0);

    int fd1_1 = xlio_socket_fd(sock1_1);
    int fd1_2 = xlio_socket_fd(sock1_2);
    int fd2 = xlio_socket_fd(sock2);
    int fd3 = xlio_socket_fd(sock3);
    assert(fd1_1 >= 0);
    assert(fd1_2 >= 0);
    assert(fd2 >= 0);
    assert(fd3 >= 0);

    assert(xlio_get_socket_rings_num(fd1_1) == 1);
    assert(xlio_get_socket_rings_num(fd1_2) == 1);
    assert(xlio_get_socket_rings_num(fd2) == 1);
    assert(xlio_get_socket_rings_num(fd3) == 1);

    int ring1_1;
    int ring1_2;
    int ring2;
    int ring3;

    rc = xlio_get_socket_rings_fds(fd1_1, &ring1_1, 1);
    assert(rc == 1);
    rc = xlio_get_socket_rings_fds(fd1_2, &ring1_2, 1);
    assert(rc == 1);
    rc = xlio_get_socket_rings_fds(fd2, &ring2, 1);
    assert(rc == 1);
    rc = xlio_get_socket_rings_fds(fd3, &ring3, 1);
    assert(rc == 1);

    assert(ring1_1 == ring1_2);
    assert(ring1_1 != ring2);
    assert(ring1_1 != ring3);
    assert(ring2 != ring3);

    /* Wait for ERROR events (ECONREFUSED). */
    while (g_test_events < 4) {
        xlio_poll_group_poll(group1);
        xlio_poll_group_poll(group2);
        xlio_poll_group_poll(group3);
    }

    g_test_events = 0;
    xlio_socket_destroy(sock1_1);
    xlio_socket_destroy(sock1_2);
    xlio_socket_destroy(sock2);
    xlio_socket_destroy(sock3);

    /* Wait for TERMINATED events. */
    while (g_test_events < 4) {
        xlio_poll_group_poll(group1);
        xlio_poll_group_poll(group2);
        xlio_poll_group_poll(group3);
    }

    xlio_poll_group_destroy(group1);
    xlio_poll_group_destroy(group2);
    xlio_poll_group_destroy(group3);

    printf("Multi group test done.\n");
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
    };

    if (argc < 2) {
        printf("Usage: %s <IP>\n", argv[0]);
        printf("Run 'nc -l 8080' on the server with the <IP> address.\n");
        printf("Type messages on the nc side.\n");
        printf("Message 'quit' or 'exit' will terminate the client.\n");
        return 1;
    }

    rc = xlio_init_ex(&iattr);
    assert(rc == 0);

    test_multi_groups(argv[1]);

    rc = xlio_poll_group_create(&gattr, &group);
    assert(rc == 0);

    printf("Group created.\n");

    struct xlio_socket_attr sattr = {
        .domain = AF_INET,
        .group = group,
        .userdata_sq = 0xdeadc0de,
    };

    rc = xlio_socket_create(&sattr, &sock);
    assert(rc == 0);

    printf("Socket created, connecting to %s:8080.\n", argv[1]);

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    rc = inet_aton(argv[1], &addr.sin_addr);
    assert(rc != 0);

    rc = xlio_socket_connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    assert(rc == 0);

    struct ibv_pd *pd = xlio_socket_get_pd(sock);
    assert(pd != NULL);
    mr_buf = ibv_reg_mr(pd, sndbuf, sizeof(sndbuf), IBV_ACCESS_LOCAL_WRITE);
    assert(mr_buf != NULL);

    printf("Starting polling loop.\n");

    while (!quit) {
        xlio_poll_group_poll(group);
    }

    printf("Quiting...\n");

    rc = xlio_socket_destroy(sock);
    assert(rc == 0);

    while (!terminated) {
        xlio_poll_group_poll(group);
    }

    rc = xlio_poll_group_destroy(group);
    assert(rc == 0);

    printf("Zerocopy completion events: %d\n", g_comp_events);

    ibv_dereg_mr(mr_buf);
    xlio_exit();

    return 0;
}
