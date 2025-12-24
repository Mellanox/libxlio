/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2024-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/* gcc -o test tests/extra_api/xlio_ultra_api_migrate.c -libverbs -g */
/* sudo LD_PRELOAD=libxlio.so ./test [IP [PORT]] */
/* Use `nc <IP> <PORT>` on the remote side, the default port is 5555 */
/* Send 'mg' to migrate, 'quit' or 'exit' to terminate */

#include <assert.h>
#include <stdbool.h>
#include <stdatomic.h>
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

#include <mellanox/xlio_extra.h>
#include <infiniband/verbs.h>

#define MIGRATE_GROUP_CMD "mg"
#define LISTEN_MAGIC      0xdeadc0de
#define SEND_OP_MAGIC     0xfeedbeef
#define BUF_SIZE          256
#define MAX_SOCKETS       32

static struct xlio_api_t *xlio_api = NULL;

static bool quit = false;
static bool terminated = false;
static int g1_comp_events = 0;
static int g2_comp_events = 0;
static size_t g1_rx_bytes = 0;
static size_t g2_rx_bytes = 0;
static char *sndbuf = NULL;
static size_t page_size = 0;

/* sock_nr doesn't have to be atomic because it's protected by sock_arr_mutex */
static unsigned sock_nr = 0;
static atomic_uint destroyed_sock_nr = 0;

typedef enum { NORMAL = 1, WANT_TO_MIGRATE, MOVE_TO_GROUP2, MOVE_TO_GROUP1 } socket_phase_t;

typedef struct {
    xlio_socket_t sock;
    socket_phase_t phase;
    xlio_poll_group_t current_group;
    time_t detach_time; // Timestamp when socket was detached
    struct ibv_pd *pd;
    struct ibv_mr *mr_buf;
} socket_info_t;

static socket_info_t sock_arr[MAX_SOCKETS] = {};
static pthread_mutex_t sock_arr_mutex = PTHREAD_MUTEX_INITIALIZER;

static unsigned short listen_port = 5555;
static const char *listen_ip = "";
static int jitter_seconds = 0; // New global variable for jitter control

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

static inline int find_socket_index(xlio_socket_t sock)
{
    for (unsigned i = 0; i < sock_nr; i++) {
        if (sock_arr[i].sock == sock) {
            return i;
        }
    }
    return -1;
}

/* Update or initialize pd and mr_buf for a socket. Must be called under sock_arr_mutex */
static inline void update_pd_and_mr(unsigned i)
{
    struct ibv_pd *new_pd = xlio_api->xlio_socket_get_pd(sock_arr[i].sock);
    assert(new_pd != NULL);
    if (sock_arr[i].pd == NULL || new_pd->handle != sock_arr[i].pd->handle) {
        if (sock_arr[i].mr_buf != NULL) {
            ibv_dereg_mr(sock_arr[i].mr_buf);
        }
        sock_arr[i].pd = new_pd;
        sock_arr[i].mr_buf = ibv_reg_mr(new_pd, sndbuf, BUF_SIZE, IBV_ACCESS_LOCAL_WRITE);
        assert(sock_arr[i].mr_buf != NULL);
    }
}

static void send_single_msg(xlio_socket_t sock, const void *data, size_t len, uintptr_t userdata_op,
                            unsigned flags)
{
    pthread_mutex_lock(&sock_arr_mutex);
    int idx = find_socket_index(sock);
    assert(idx >= 0);
    uint32_t lkey = sock_arr[idx].mr_buf->lkey;
    pthread_mutex_unlock(&sock_arr_mutex);

    struct xlio_socket_send_attr attr = {
        .flags = flags,
        .mkey = lkey,
        .userdata_op = userdata_op,
    };
    memcpy(sndbuf, data, len);
    int ret = xlio_api->xlio_socket_send(sock, sndbuf, len, &attr);
    assert(ret == 0);
    xlio_api->xlio_socket_flush(sock);
}

static void send_single_msg_with_prefix(xlio_socket_t sock, const char *msg, size_t len,
                                        uintptr_t userdata_op, unsigned flags)
{
    char prefixed_msg[BUF_SIZE];
    prefixed_msg[0] = '>';
    prefixed_msg[1] = ' ';
    len = len > BUF_SIZE - 3 ? BUF_SIZE - 3 : len;
    memcpy(prefixed_msg + 2, msg, len);
    prefixed_msg[2 + len] = '\n';
    send_single_msg(sock, prefixed_msg, len + 3, userdata_op, flags);
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
            atomic_fetch_add(&destroyed_sock_nr, 1);
        }
    } else {
        log_print("Event callback: event=%d value=%d (sock=%lx).\n", event, value, userdata_sq);
        if (event == XLIO_SOCKET_EVENT_ERROR) {
            quit = true;
        }
    }
}

static void socket_comp_cb(xlio_socket_t sock, uintptr_t userdata_sq, uintptr_t userdata_op)
{
    log_print("Completed zcopy buffer userdata_sq=%lx userdata_op=%lx.\n", userdata_sq,
              userdata_op);
    assert(userdata_sq != 0);
    assert(userdata_op != 0);

    pthread_mutex_lock(&sock_arr_mutex);
    int idx = find_socket_index(sock);
    if (idx >= 0) {
        if (sock_arr[idx].current_group == group_1) {
            ++g1_comp_events;
        } else if (sock_arr[idx].current_group == group_2) {
            ++g2_comp_events;
        }
    }
    pthread_mutex_unlock(&sock_arr_mutex);
}

static void handle_rx_message(xlio_socket_t sock, const char *msg)
{
    if (strstr(msg, "quit") || strstr(msg, "exit")) {
        quit = true;
        return;
    }

    if (strstr(msg, MIGRATE_GROUP_CMD)) {
        pthread_mutex_lock(&sock_arr_mutex);
        int idx = find_socket_index(sock);
        if (idx >= 0) {
            sock_arr[idx].phase = WANT_TO_MIGRATE;
            log_print("Socket %d marked for migration\n", idx);
        }
        pthread_mutex_unlock(&sock_arr_mutex);
    } else {
        send_single_msg_with_prefix(sock, msg, strlen(msg), SEND_OP_MAGIC, 0);
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
    (void)userdata_sq;

    pthread_mutex_lock(&sock_arr_mutex);
    int idx = find_socket_index(sock);
    if (idx >= 0) {
        if (sock_arr[idx].current_group == group_1) {
            g1_rx_bytes += len;
        } else if (sock_arr[idx].current_group == group_2) {
            g2_rx_bytes += len;
        }
    }
    pthread_mutex_unlock(&sock_arr_mutex);

    char *msg = (char *)malloc(len + 1);
    mem_copy_and_add_nl(data, len, msg);

    handle_rx_message(sock, msg);
    free(msg);
    xlio_api->xlio_socket_buf_free(sock, buf);
}

static void socket_accept_cb(xlio_socket_t sock, xlio_socket_t parent_sock,
                             uintptr_t parent_userdata)
{
    struct sockaddr_in6 sa = {};
    socklen_t len = sizeof(sa);
    int rc;
    unsigned short port = 0;
    char buf[64] = "";

    (void)parent_sock;
    (void)parent_userdata;

    rc = xlio_api->xlio_socket_getpeername(sock, (struct sockaddr *)&sa, &len);
    if (rc != 0) {
        log_print("Failed to get peername of an incoming socket.\n");
        xlio_api->xlio_socket_destroy(sock);
        quit = true;
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

    pthread_mutex_lock(&sock_arr_mutex);
    if (sock_nr >= MAX_SOCKETS) {
        pthread_mutex_unlock(&sock_arr_mutex);
        log_print("Too many connections (%u), closing connection from %s:%u.\n", sock_nr, buf,
                  port);
        xlio_api->xlio_socket_destroy(sock);
        return;
    }
    unsigned idx = sock_nr;
    sock_arr[idx].sock = sock;
    sock_arr[idx].phase = NORMAL;
    sock_arr[idx].current_group = group_1;
    sock_arr[idx].pd = NULL;
    sock_arr[idx].mr_buf = NULL;
    update_pd_and_mr(idx);
    sock_nr++;
    uintptr_t userdata_sq = (uintptr_t)sock_nr;
    pthread_mutex_unlock(&sock_arr_mutex);

    rc = xlio_api->xlio_socket_update(sock, 0, userdata_sq);
    if (rc != 0) {
        log_print("Failed to update context of an incoming socket.\n");
    }

    log_print("Accepted incoming connection from %s:%u userdata_sq=%lx.\n", buf, port, userdata_sq);
}

static inline void handle_socket_want_to_migrate(xlio_poll_group_t group, unsigned i)
{
    log_print("Detaching socket %d from group%d\n", i, (group == group_1) ? 1 : 2);
    int rc = xlio_api->xlio_socket_detach_group(sock_arr[i].sock);
    assert(rc == 0);
    sock_arr[i].phase = (group == group_1) ? MOVE_TO_GROUP2 : MOVE_TO_GROUP1;
    sock_arr[i].current_group = 0;
    sock_arr[i].detach_time = time(NULL); // Set detach_time when we actually detach
}

static void check_if_socket_want_to_migrate(xlio_poll_group_t group)
{
    pthread_mutex_lock(&sock_arr_mutex);
    for (unsigned i = 0; i < sock_nr; i++) {
        if (sock_arr[i].current_group == group && sock_arr[i].phase == WANT_TO_MIGRATE) {
            handle_socket_want_to_migrate(group, i);
        }
    }
    pthread_mutex_unlock(&sock_arr_mutex);
}

static void handle_socket_migration_to_us(xlio_poll_group_t group, unsigned i)
{
    time_t current_time = time(NULL);
    time_t elapsed = current_time - sock_arr[i].detach_time;

    if (jitter_seconds > 0 && elapsed < jitter_seconds) {
        // Not enough time has passed, skip this socket for now
        return;
    }

    log_print("Socket %d: Attaching to group%d after %ld seconds delay (detached at: %ld, "
              "attaching at: %ld)\n",
              i, (group == group_1) ? 1 : 2, elapsed, sock_arr[i].detach_time, current_time);
    int rc = xlio_api->xlio_socket_attach_group(sock_arr[i].sock, group);
    assert(rc == 0);
    sock_arr[i].phase = NORMAL;
    sock_arr[i].current_group = group;

    update_pd_and_mr(i);
}

static void check_if_some_socket_want_to_migrate_to_us(xlio_poll_group_t group)
{
    pthread_mutex_lock(&sock_arr_mutex);
    for (unsigned i = 0; i < sock_nr; i++) {
        if ((group == group_1 && sock_arr[i].phase == MOVE_TO_GROUP1) ||
            (group == group_2 && sock_arr[i].phase == MOVE_TO_GROUP2)) {
            handle_socket_migration_to_us(group, i);
        }
    }
    pthread_mutex_unlock(&sock_arr_mutex);
}

static void *thread_group2_func(void *arg)
{
    (void)arg;

    while (!quit) {
        xlio_api->xlio_poll_group_poll(group_2);
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
        .memory_alloc = NULL,
        .memory_free = NULL,
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

    // Obtain XLIO API pointers
    xlio_api = xlio_get_api();
    if (xlio_api == NULL) {
        log_print("Error: Failed to get XLIO API. Make sure XLIO library is loaded.\n");
        return 1;
    }
    if (!(xlio_api->cap_mask & XLIO_EXTRA_API_XLIO_ULTRA)) {
        log_print("Error: XLIO Ultra API is not supported by this XLIO version.\n");
        return 1;
    }

    rc = xlio_api->xlio_init_ex(&iattr);
    assert(rc == 0);

    /*
     * Allocate send buffer aligned to page size.
     * Memory must be page-aligned because ibv_reg_mr() may call madvise()
     * which requires the address to be aligned to the page boundary.
     */
    page_size = sysconf(_SC_PAGESIZE);
    rc = posix_memalign((void **)&sndbuf, page_size, BUF_SIZE);
    assert(rc == 0 && sndbuf != NULL);

    rc = xlio_api->xlio_poll_group_create(&gattr, &group_1);
    assert(rc == 0);
    log_print("Group_1 created.\n");
    rc = xlio_api->xlio_poll_group_create(&gattr, &group_2);
    assert(rc == 0);
    log_print("Group_2 created.\n");

    struct xlio_socket_attr sattr = {
        .flags = 0,
        .domain = AF_INET,
        .group = group_1,
        .userdata_sq = LISTEN_MAGIC,
    };

    rc = xlio_api->xlio_socket_create(&sattr, &sock);
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
    rc = xlio_api->xlio_socket_bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    assert(rc == 0);

    log_print("Listen socket bound to %s:%u.\n", listen_ip, listen_port);
    rc = xlio_api->xlio_socket_listen(sock);
    assert(rc == 0);

    log_print("Listen.\n");
    log_print("Starting polling loop.\n");

    // Create only thread2 for group2
    pthread_create(&thread_2, NULL, thread_group2_func, NULL);

    // Main thread handles group1 polling
    while (!quit) {
        xlio_api->xlio_poll_group_poll(group_1);
        check_if_socket_want_to_migrate(group_1);
        check_if_some_socket_want_to_migrate_to_us(group_1);
    }

    log_print("Quiting...\n");

    // Wait for thread2 to finish
    pthread_join(thread_2, NULL);

    rc = xlio_api->xlio_socket_destroy(sock);
    assert(rc == 0);
    pthread_mutex_lock(&sock_arr_mutex);
    unsigned local_sock_nr = sock_nr;
    for (unsigned i = 0; i < local_sock_nr; ++i) {
        if (sock_arr[i].mr_buf != NULL) {
            ibv_dereg_mr(sock_arr[i].mr_buf);
            sock_arr[i].mr_buf = NULL;
        }
        rc = xlio_api->xlio_socket_destroy(sock_arr[i].sock);
        assert(rc == 0);
    }
    pthread_mutex_unlock(&sock_arr_mutex);
    while (!terminated || atomic_load(&destroyed_sock_nr) < local_sock_nr) {
        xlio_api->xlio_poll_group_poll(group_1);
        xlio_api->xlio_poll_group_poll(group_2);
    }

    log_print("All the sockets are destroyed.\n");

    rc = xlio_api->xlio_poll_group_destroy(group_1);
    assert(rc == 0);
    rc = xlio_api->xlio_poll_group_destroy(group_2);
    assert(rc == 0);

    log_print("Total zerocopy completion events: %d\n", g1_comp_events + g2_comp_events);
    log_print("Group1 zerocopy completion events: %d\n", g1_comp_events);
    log_print("Group2 zerocopy completion events: %d\n", g2_comp_events);
    log_print("Group1 received bytes: %zu\n", g1_rx_bytes);
    log_print("Group2 received bytes: %zu\n", g2_rx_bytes);
    log_print("Total received bytes: %zu\n", g1_rx_bytes + g2_rx_bytes);
    free(sndbuf);
    pthread_mutex_destroy(&sock_arr_mutex);
    xlio_api->xlio_exit();

    return 0;
}
