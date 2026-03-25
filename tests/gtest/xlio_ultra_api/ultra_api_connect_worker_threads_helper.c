/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/*
 * Smoke-test helper for verifying Ultra API sockets are NOT dispatched
 * to XLIO worker threads.  Exercises the xlio_socket_connect() path with
 * worker_threads=1 configured.  The gtest wrapper asserts that worker-
 * thread dispatch messages (connect_socket_job / "New TCP socket added")
 * are absent from the debug output.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include "xlio_extra.h"

static void dummy_event_cb(xlio_socket_t s, uintptr_t ud, int ev, int val)
{
    (void)s;
    (void)ud;
    (void)ev;
    (void)val;
}

/*
 * Find a non-loopback IPv4 address on this machine.  Returns 0 on success.
 * On RDMA-capable hosts this will typically be an offload-eligible address.
 */
static int find_local_ipv4(struct in_addr *out)
{
    struct ifaddrs *ifa_list, *ifa;

    if (getifaddrs(&ifa_list) != 0) {
        return -1;
    }

    for (ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        if (ifa->ifa_flags & IFF_LOOPBACK) {
            continue;
        }
        *out = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
        freeifaddrs(ifa_list);
        return 0;
    }

    freeifaddrs(ifa_list);
    return -1;
}

int main(int argc, char **argv)
{
    struct xlio_api_t *api = xlio_get_api();
    if (!api) {
        fprintf(stderr, "SKIP: XLIO API not available\n");
        return 0;
    }

    struct xlio_init_attr iattr;
    memset(&iattr, 0, sizeof(iattr));
    if (api->xlio_init_ex(&iattr) != 0) {
        fprintf(stderr, "SKIP: xlio_init_ex failed: %s\n", strerror(errno));
        return 0;
    }

    xlio_poll_group_t group = 0;
    struct xlio_poll_group_attr gattr;
    memset(&gattr, 0, sizeof(gattr));
    gattr.socket_event_cb = dummy_event_cb;
    if (api->xlio_poll_group_create(&gattr, &group) != 0) {
        fprintf(stderr, "FAIL: xlio_poll_group_create: %s\n", strerror(errno));
        api->xlio_exit();
        return 1;
    }

    xlio_socket_t sock = 0;
    struct xlio_socket_attr sattr;
    memset(&sattr, 0, sizeof(sattr));
    sattr.domain = AF_INET;
    sattr.group = group;
    if (api->xlio_socket_create(&sattr, &sock) != 0) {
        fprintf(stderr, "SKIP: xlio_socket_create failed: %s\n", strerror(errno));
        api->xlio_poll_group_destroy(group);
        api->xlio_exit();
        return 0;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1);

    if (argc > 1) {
        inet_pton(AF_INET, argv[1], &addr.sin_addr);
    } else {
        if (find_local_ipv4(&addr.sin_addr) != 0) {
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        }
    }

    /* Connect will likely fail (ECONNREFUSED / timeout) but that is fine.
     * The goal is to exercise the connect code path inside XLIO. */
    api->xlio_socket_connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    for (int i = 0; i < 100; i++) {
        api->xlio_poll_group_poll(group);
    }

    api->xlio_socket_destroy(sock);
    api->xlio_poll_group_destroy(group);
    api->xlio_exit();

    fprintf(stderr, "PASS\n");
    return 0;
}
