/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2024-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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
#include <pthread.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>

#include <mellanox/xlio.h>
#include <infiniband/verbs.h>

#define LISTEN_MAGIC 0xdeadc0de
#define MIGRATE_GROUP_CMD "mg"

static bool quit = false;
static bool terminated = false;
static int g_comp_events = 0;
static int g1_comp_events = 0;
static int g2_comp_events = 0;
static size_t g1_rx_bytes = 0;
static size_t g2_rx_bytes = 0;
static char     sndbuf[256];

static struct ibv_pd *pd = NULL;
static struct ibv_mr *mr_buf;

static unsigned sock_nr = 0;
static unsigned destroyed_sock_nr = 0;

typedef enum {
    NORMAL = 1,
    WANT_TO_MIGRATE,
    MOVE_TO_GROUP2,
    MOVE_TO_GROUP1
} socket_phase_t;

typedef struct {
    xlio_socket_t sock;
    socket_phase_t phase;
    xlio_poll_group_t current_group;
    time_t detach_time;  // Timestamp when socket was detached
} socket_info_t;

static socket_info_t sock_arr[32] = {0};
static pthread_mutex_t sock_arr_mutex = PTHREAD_MUTEX_INITIALIZER;


static unsigned short listen_port = 8080;
static const char *listen_ip = "";
static int jitter_seconds = 0;  // New global variable for jitter control

static xlio_poll_group_t group_1;
static xlio_poll_group_t group_2;
static pthread_t thread_2;

static void log_print(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    fflush(stdout);
    fflush(stderr);
}

static void memory_cb(void *data, size_t size, size_t page_size)
{
    log_print("Memory area allocated data=%p size=%zu page_size=%zu\n", data, size, page_size);
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

static void send_single_msg_with_prefix(xlio_socket_t sock, const char *msg, size_t len, uintptr_t userdata_op, unsigned flags)
{
    char prefixed_msg[256];
    prefixed_msg[0] = '>';
    prefixed_msg[1] = ' ';
    memcpy(prefixed_msg + 2, msg, len);
    send_single_msg(sock, prefixed_msg, len + 2, userdata_op, flags);
}

static void socket_event_cb(xlio_socket_t sock, uintptr_t userdata_sq, int event, int value)
{
    if (event == XLIO_SOCKET_EVENT_ESTABLISHED) {
        log_print("Connection established (sock=%lx).\n", sock);
    } else if (event == XLIO_SOCKET_EVENT_CLOSED) {
        log_print("Connection closed passively (sock=%lx).\n", sock);
    } else if (event == XLIO_SOCKET_EVENT_TERMINATED) {
        log_print("Connection terminated (sock=%lx).\n", sock);
        if (userdata_sq == LISTEN_MAGIC) {
            terminated = true;
        } else {
            ++destroyed_sock_nr;
        }
    } else {
        log_print("Event callback: event=%d value=%d (sock=%lx).\n", event, value, userdata_sq);
        if (event == XLIO_SOCKET_EVENT_ERROR) {
            quit = true;
        }
    }
}

static inline int find_socket_index(xlio_socket_t sock)
{
    for (unsigned i = 0; i < sock_nr; i++) {
        if (sock_arr[i].sock == sock) {
            return i;
        }
    }
    return -1;
}

static void socket_comp_cb(xlio_socket_t sock, uintptr_t userdata_sq, uintptr_t userdata_op)
{
    const char *reply_msg = "> comp_cb\n";

    log_print("Completed zcopy buffer userdata_sq=%lx userdata_op=%lx.\n", userdata_sq, userdata_op);
    assert(userdata_sq != 0);
    assert(userdata_op != 0);

    ++g_comp_events;
    int idx = find_socket_index(sock);
    if (idx >= 0) {
        if (sock_arr[idx].current_group == group_1) {
            ++g1_comp_events;
        } else if (sock_arr[idx].current_group == group_2) {
            ++g2_comp_events;
        }
    }
}

static void handle_quit_exit_and_migrategroup(xlio_socket_t sock, const char *msg, uintptr_t userdata_sq)
{
    if (strstr(msg, "quit") || strstr(msg, "exit")) {
        quit = true;
        return;
    }
    
    if (strstr(msg, MIGRATE_GROUP_CMD)) {
        int idx = find_socket_index(sock);
        if (idx >= 0) {
            sock_arr[idx].phase = WANT_TO_MIGRATE;
            log_print("Socket %d marked for migration\n",idx);
        }
    }
}

static inline void mem_copy_and_add_nl(const void *data, size_t len, char *msg)
{
    memcpy(msg, data, len);
    msg[len] = '\0';
    if (len > 0 && msg[len - 1] == '\n') {
        msg[len - 1] = '\0';
    }
}

static void socket_rx_cb(xlio_socket_t sock, uintptr_t userdata_sq, void *data, size_t len,
                         struct xlio_buf *buf)
{
    int idx = find_socket_index(sock);
    if (idx >= 0) {
        if (sock_arr[idx].current_group == group_1) {
            g1_rx_bytes += len;
        } else if (sock_arr[idx].current_group == group_2) {
            g2_rx_bytes += len;
        }
    }
    
    char *msg = (char *)malloc(len + 1);
    mem_copy_and_add_nl(data, len, msg);

    handle_quit_exit_and_migrategroup(sock, msg, userdata_sq);
    free(msg);
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
        log_print("Failed to get peername of an incoming socket.\n");
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
        log_print("Unknown AF: %u.\n", sa.sin6_family);
    }

    sock_arr[sock_nr].sock = sock;
    sock_arr[sock_nr].phase = NORMAL;
    sock_arr[sock_nr].current_group = group_1;
    sock_nr++;

    uintptr_t userdata_sq = (uintptr_t)sock_nr;
    rc = xlio_socket_update(sock, 0, userdata_sq);
    if (rc != 0) {
        log_print("Failed to update context of an incoming socket.\n");
    }

    if (!pd) {
        pd = xlio_socket_get_pd(sock);
        assert(pd != NULL);
        mr_buf = ibv_reg_mr(pd, sndbuf, sizeof(sndbuf), IBV_ACCESS_LOCAL_WRITE);
        assert(mr_buf != NULL);
    }

    log_print("Accepted incoming connection from %s:%u userdata_sq=%lx.\n", buf, port, userdata_sq);

    const char* reply_msg = "Connected to group1\n";
}

static inline void handle_socket_want_to_migrate(xlio_poll_group_t group, unsigned i)
{
    log_print("Detaching socket %d from group%d\n", i, (group == group_1) ? 1 : 2);
    int rc = xlio_socket_detach_group(sock_arr[i].sock);
    assert(rc == 0);
    sock_arr[i].phase = (group == group_1) ? MOVE_TO_GROUP2 : MOVE_TO_GROUP1;
    sock_arr[i].current_group = 0;
    sock_arr[i].detach_time = time(NULL);  // Set detach_time when we actually detach
}

static void check_if_socket_want_to_migrate(xlio_poll_group_t group)
{
    for (unsigned i = 0; i < sock_nr; i++) {
        if (sock_arr[i].current_group == group && sock_arr[i].phase == WANT_TO_MIGRATE) {
            handle_socket_want_to_migrate(group, i);
        }
    }
}

static inline void update_pd_and_mr(xlio_socket_t sock)
{
    struct ibv_pd *new_pd = xlio_socket_get_pd(sock);
    if (new_pd->handle != pd->handle) {
        ibv_dereg_mr(mr_buf);
        pd = new_pd;
        mr_buf = ibv_reg_mr(pd, sndbuf, sizeof(sndbuf), IBV_ACCESS_LOCAL_WRITE);
        assert(mr_buf != NULL);
    }
}

static void handle_socket_migration_to_us(xlio_poll_group_t group, unsigned i)
{
    time_t current_time = time(NULL);
    time_t elapsed = current_time - sock_arr[i].detach_time;
    
    if (jitter_seconds > 0 && elapsed < jitter_seconds) {
        // Not enough time has passed, skip this socket for now
        return;
    }

    log_print("Socket %d: Attaching to group%d after %ld seconds delay (detached at: %ld, attaching at: %ld)\n", 
             i, (group == group_1) ? 1 : 2, elapsed, sock_arr[i].detach_time, current_time);
    int rc = xlio_socket_attach_group(sock_arr[i].sock, group);
    assert(rc == 0);
    sock_arr[i].phase = NORMAL;
    sock_arr[i].current_group = group;
    
    update_pd_and_mr(sock_arr[i].sock);
    
    const char* msg = (group == group_1) ? "Migrated to group1\n" : "Migrated to group2\n";

}

static void check_if_some_socket_want_to_migrate_to_us(xlio_poll_group_t group)
{
    for (unsigned i = 0; i < sock_nr; i++) {
        if ((group == group_1 && sock_arr[i].phase == MOVE_TO_GROUP1) ||
            (group == group_2 && sock_arr[i].phase == MOVE_TO_GROUP2)) {
            handle_socket_migration_to_us(group, i);
        }
    }
}

static void *thread_group2_func(void *arg)
{
    while (!quit) {
        xlio_poll_group_poll(group_2);
        check_if_socket_want_to_migrate(group_2);
        check_if_some_socket_want_to_migrate_to_us(group_2);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    xlio_socket_t sock;
    int rc;

    struct xlio_init_attr iattr = {
        .flags = 0,
        .memory_cb = &memory_cb,
    };
    struct xlio_poll_group_attr gattr = {
        .flags = 0,
        .socket_event_cb = &socket_event_cb,
        .socket_comp_cb = &socket_comp_cb,
        .socket_rx_cb = &socket_rx_cb,
        .socket_accept_cb = &socket_accept_cb,
    };

    if (argc > 1 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        log_print("Usage: %s [--jitter SECONDS] [IP [PORT]]\n", argv[0]);
        log_print("Run 'nc <IP> <PORT>' on the client side.\n");
        log_print("Type messages on the nc side.\n");
        log_print("Message 'quit' or 'exit' will terminate the server.\n");
        log_print("Message 'mg' will migrate the socket between groups.\n");
        log_print("--jitter SECONDS: Add delay between detach and attach operations\n");
        return 0;
    }

    // Check for jitter
    int arg_offset = 1;
    if (argc > arg_offset && strcmp(argv[arg_offset], "--jitter") == 0) {
        if (argc <= arg_offset + 1) {
            log_print("Error: --jitter requires a value in seconds\n");
            return 1;
        }
        jitter_seconds = atoi(argv[arg_offset + 1]);
        if (jitter_seconds < 0) {
            log_print("Error: jitter value must be non-negative\n");
            return 1;
        }
        arg_offset += 2;
    }

    rc = xlio_init_ex(&iattr);
    assert(rc == 0);

    rc = xlio_poll_group_create(&gattr, &group_1);
    assert(rc == 0);
    log_print("Group_1 created.\n");
    rc = xlio_poll_group_create(&gattr, &group_2);
    assert(rc == 0);
    log_print("Group_2 created.\n");

    struct xlio_socket_attr sattr = {
        .domain = AF_INET,
        .group = group_1,
        .userdata_sq = LISTEN_MAGIC,
    };

    rc = xlio_socket_create(&sattr, &sock);
    assert(rc == 0);

    log_print("Listen socket created.\n");

    if (argc > arg_offset) {
        listen_ip = argv[arg_offset];
    }
    if (argc > arg_offset + 1) {
        listen_port = atoi(argv[arg_offset + 1]);
    }
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(listen_port);
    if (listen_ip[0] != '\0') {
        rc = inet_aton(argv[arg_offset], &addr.sin_addr);
        assert(rc != 0);
    }
    rc = xlio_socket_bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    assert(rc == 0);

    log_print("Listen socket bound to %s:%u.\n", listen_ip, listen_port);
    rc = xlio_socket_listen(sock);
    assert(rc == 0);

    log_print("Listen.\n");
    log_print("Starting polling loop.\n");

    // Create only thread2 for group2
    pthread_create(&thread_2, NULL, thread_group2_func, NULL);

    // Main thread handles group1 polling
    while (!quit) {
        xlio_poll_group_poll(group_1);
        check_if_socket_want_to_migrate(group_1);
        check_if_some_socket_want_to_migrate_to_us(group_1);
    }

    log_print("Quiting...\n");

    // Wait for thread2 to finish
    pthread_join(thread_2, NULL);

    rc = xlio_socket_destroy(sock);
    assert(rc == 0);
    for (unsigned i = 0; i < sock_nr; ++i) {
        rc = xlio_socket_destroy(sock_arr[i].sock);
        assert(rc == 0);
    }
    while (!terminated || destroyed_sock_nr < sock_nr) {
        xlio_poll_group_poll(group_1);
        xlio_poll_group_poll(group_2);
    }

    log_print("All the sockets are destroyed.\n");

    rc = xlio_poll_group_destroy(group_1);
    assert(rc == 0);
    rc = xlio_poll_group_destroy(group_2);
    assert(rc == 0);

    log_print("Total zerocopy completion events: %d\n", g_comp_events);
    log_print("Group1 zerocopy completion events: %d\n", g1_comp_events);
    log_print("Group2 zerocopy completion events: %d\n", g2_comp_events);
    log_print("Group1 received bytes: %zu\n", g1_rx_bytes);
    log_print("Group2 received bytes: %zu\n", g2_rx_bytes);
    log_print("Total received bytes: %zu\n", g1_rx_bytes + g2_rx_bytes);

    if (mr_buf) {
        ibv_dereg_mr(mr_buf);
    }
    pthread_mutex_destroy(&sock_arr_mutex);
    xlio_exit();

    return 0;
}
