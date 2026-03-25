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
#include <netinet/in.h>
#include <sys/socket.h>
#include "xlio_extra.h"

/* Arbitrary unused TCP port -- the connect() is only used to drive the
 * XLIO connect code path, not to actually communicate. */
#define PEER_PORT 1

/* Iterations of xlio_poll_group_poll() to drain pending socket events
 * between connect() and teardown. */
#define POLL_ITERATIONS 100

/* inet_pton() returns 1 for a successful parse, 0 for malformed input,
 * -1 for an unsupported family. */
#define INET_PTON_OK 1

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
    /* Parse the peer address up-front so that sattr.domain can be set
     * correctly, and so a malformed literal short-circuits to SKIP before
     * we touch any XLIO resources.  Three independent cases:
     *   - no argument supplied  -> default to a local IPv4 address;
     *   - argument contains ':' -> parse as IPv6;
     *   - otherwise             -> parse as IPv4.
     */
    const char *arg = (argc > 1) ? argv[1] : NULL;
    struct sockaddr_storage peer;
    socklen_t peer_len;
    sa_family_t family;

    memset(&peer, 0, sizeof(peer));

    if (!arg) {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&peer;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(PEER_PORT);
        if (find_local_ipv4(&s4->sin_addr) != 0) {
            s4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        }
        family = AF_INET;
        peer_len = sizeof(*s4);
    } else if (strchr(arg, ':')) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&peer;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(PEER_PORT);
        if (inet_pton(AF_INET6, arg, &s6->sin6_addr) != INET_PTON_OK) {
            fprintf(stderr, "SKIP: failed to parse peer address '%s'\n", arg);
            return EXIT_SUCCESS;
        }
        family = AF_INET6;
        peer_len = sizeof(*s6);
    } else {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&peer;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(PEER_PORT);
        if (inet_pton(AF_INET, arg, &s4->sin_addr) != INET_PTON_OK) {
            fprintf(stderr, "SKIP: failed to parse peer address '%s'\n", arg);
            return EXIT_SUCCESS;
        }
        family = AF_INET;
        peer_len = sizeof(*s4);
    }

    struct xlio_api_t *api = xlio_get_api();
    if (!api) {
        fprintf(stderr, "SKIP: XLIO API not available\n");
        return EXIT_SUCCESS;
    }

    struct xlio_init_attr iattr;
    memset(&iattr, 0, sizeof(iattr));
    if (api->xlio_init_ex(&iattr) != 0) {
        fprintf(stderr, "SKIP: xlio_init_ex failed: %s\n", strerror(errno));
        return EXIT_SUCCESS;
    }

    xlio_poll_group_t group = 0;
    struct xlio_poll_group_attr gattr;
    memset(&gattr, 0, sizeof(gattr));
    gattr.socket_event_cb = dummy_event_cb;
    if (api->xlio_poll_group_create(&gattr, &group) != 0) {
        fprintf(stderr, "FAIL: xlio_poll_group_create: %s\n", strerror(errno));
        api->xlio_exit();
        return EXIT_FAILURE;
    }

    xlio_socket_t sock = 0;
    struct xlio_socket_attr sattr;
    memset(&sattr, 0, sizeof(sattr));
    sattr.domain = family;
    sattr.group = group;
    if (api->xlio_socket_create(&sattr, &sock) != 0) {
        fprintf(stderr, "SKIP: xlio_socket_create failed: %s\n", strerror(errno));
        api->xlio_poll_group_destroy(group);
        api->xlio_exit();
        return EXIT_SUCCESS;
    }

    /* Connect will likely fail (ECONNREFUSED / timeout) but that is fine.
     * The goal is to exercise the connect code path inside XLIO. */
    api->xlio_socket_connect(sock, (struct sockaddr *)&peer, peer_len);

    for (int i = 0; i < POLL_ITERATIONS; i++) {
        api->xlio_poll_group_poll(group);
    }

    api->xlio_socket_destroy(sock);
    api->xlio_poll_group_destroy(group);
    api->xlio_exit();

    fprintf(stderr, "PASS\n");
    return EXIT_SUCCESS;
}
