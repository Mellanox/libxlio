/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "core/xlio_base.h"

#if defined(EXTRA_API_ENABLED) && (EXTRA_API_ENABLED == 1)

static int connected_counter = 0;
static int terminated_counter = 0;
static std::vector<xlio_socket_t> accepted_sockets;

class zc_api_xlio_socket_listen_connect : public xlio_zc_api_base {
public:
    virtual void SetUp() { errno = EOK; };
    virtual void TearDown() {};
    void create_poll_group(xlio_poll_group_t *group)
    {
        xlio_poll_group_attr gattr = {
            .flags = 0,
            .socket_event_cb = &socket_event_cb,
            .socket_comp_cb = &socket_comp_cb,
            .socket_rx_cb = &socket_rx_cb,
            .socket_accept_cb = &socket_accept_cb,
        };
        base_create_poll_group(&gattr, group);
    }
    void destroy_poll_group(xlio_poll_group_t group) { base_destroy_poll_group(group); }

    void wait_for_delayed_acks(xlio_poll_group_t group)
    {
        struct timespec start_time;
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        struct timespec current_time = {0, 0};
        while (current_time.tv_sec - start_time.tv_sec < 1) {
            xlio_api->xlio_poll_group_poll(group);
            clock_gettime(CLOCK_MONOTONIC, &current_time);
        }
    }

    static void socket_event_cb(xlio_socket_t sock, uintptr_t userdata_sq, int event, int value)
    {
        UNREFERENCED_PARAMETER(sock);
        UNREFERENCED_PARAMETER(userdata_sq);
        UNREFERENCED_PARAMETER(value);
        if (event == XLIO_SOCKET_EVENT_ESTABLISHED) {
            connected_counter++;
        } else if (event == XLIO_SOCKET_EVENT_CLOSED) {
            terminated_counter++;
        } else if (event == XLIO_SOCKET_EVENT_TERMINATED) {
            terminated_counter++;
        }
    }
    static void socket_comp_cb(xlio_socket_t sock, uintptr_t userdata_sq, uintptr_t userdata_op)
    {
        UNREFERENCED_PARAMETER(sock);
        UNREFERENCED_PARAMETER(userdata_sq);
        UNREFERENCED_PARAMETER(userdata_op);
    }

    static void socket_rx_cb(xlio_socket_t sock, uintptr_t userdata_sq, void *data, size_t len,
                             struct xlio_buf *buf)
    {
        UNREFERENCED_PARAMETER(sock);
        UNREFERENCED_PARAMETER(userdata_sq);
        UNREFERENCED_PARAMETER(data);
        UNREFERENCED_PARAMETER(len);
        UNREFERENCED_PARAMETER(buf);
    }

    static void socket_accept_cb(xlio_socket_t sock, xlio_socket_t parent_sock,
                                 uintptr_t parent_userdata)
    {
        UNREFERENCED_PARAMETER(sock);
        UNREFERENCED_PARAMETER(parent_sock);
        UNREFERENCED_PARAMETER(parent_userdata);
        accepted_sockets.push_back(sock);
        connected_counter++;
    }
};

/**
 * @test socket_connect.ti_1
 * @brief
 *    Create TCP socket/listen(target)/connect(initiator)
 * @details
 */
TEST_F(zc_api_xlio_socket_listen_connect, ti_1)
{
    int rc;
    int pid = fork();
    xlio_zc_api_base::SetUp();
    xlio_poll_group_t group;
    xlio_socket_t sock;

    create_poll_group(&group);
    xlio_socket_attr sattr = {
        .flags = 0,
        .domain = server_addr.addr.sa_family,
        .group = group,
        .userdata_sq = 0,
    };

    if (pid == 0) {
        // Child process - server side
        base_create_socket(&sattr, &sock);
        rc = xlio_api->xlio_socket_bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);
        rc = xlio_api->xlio_socket_listen(sock);
        ASSERT_EQ(0, rc);
        barrier_fork(pid, true); // Tell parent that we are listening
        while (connected_counter < 1) {
            xlio_api->xlio_poll_group_poll(group);
        }
        wait_for_delayed_acks(group);
        barrier_fork(pid, true); // Tell parent that we got last ack
        base_destroy_socket(sock);
        while (!accepted_sockets.empty()) {
            base_destroy_socket(accepted_sockets.back());
            accepted_sockets.pop_back();
        }
        while (terminated_counter < 1) {
            xlio_api->xlio_poll_group_poll(group);
        }
        destroy_poll_group(group);
        exit(testing::Test::HasFailure());
    } else {
        // Parent process - client side
        base_create_socket(&sattr, &sock);

        rc = xlio_api->xlio_socket_bind(sock, (struct sockaddr *)&client_addr, sizeof(client_addr));
        ASSERT_EQ(0, rc);

        barrier_fork(pid, true); // Wait for child to listen

        rc = xlio_api->xlio_socket_connect(sock, (struct sockaddr *)&server_addr,
                                           sizeof(server_addr));
        ASSERT_EQ(0, rc);

        while (connected_counter < 1) {
            xlio_api->xlio_poll_group_poll(group);
        }

        wait_for_delayed_acks(group);

        barrier_fork(pid, true); // Wait for child to get last ack

        base_destroy_socket(sock);
        while (terminated_counter < 1) {
            xlio_api->xlio_poll_group_poll(group);
        }

        destroy_poll_group(group);

        wait_fork(pid);
    }
}

#endif /* EXTRA_API_ENABLED */
