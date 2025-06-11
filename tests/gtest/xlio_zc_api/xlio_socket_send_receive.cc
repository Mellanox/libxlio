/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include <infiniband/verbs.h>
#include <pthread.h>
#include <unistd.h>
#include "core/xlio_base.h"

#if defined(EXTRA_API_ENABLED) && (EXTRA_API_ENABLED == 1)

static int connected_counter = 0;
static int terminated_counter = 0;
static int rx_cb_counter = 0;
static int comp_cb_counter = 0;
static const char *data_to_send = "I Love XLIO!";
static struct ibv_pd *pd = NULL;
static struct ibv_mr *mr_buf;
static char sndbuf[256];
static std::vector<xlio_socket_t> accepted_sockets;

class zc_api_xlio_socket_send_receive : public xlio_zc_api_base {
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
    static void send_single_msg(xlio_socket_t sock, const void *data, size_t len,
                                uintptr_t userdata_op, unsigned flags)
    {
        struct xlio_socket_send_attr attr = {
            .flags = flags,
            .mkey = mr_buf->lkey,
            .userdata_op = userdata_op,
        };
        memcpy(sndbuf, data, len);
        int ret = xlio_api->xlio_socket_send(sock, sndbuf, len, &attr);
        ASSERT_EQ(ret, 0);
        xlio_api->xlio_socket_flush(sock);
    }
    static void socket_event_cb(xlio_socket_t sock, uintptr_t userdata_sq, int event, int value)
    {
        UNREFERENCED_PARAMETER(userdata_sq);
        UNREFERENCED_PARAMETER(value);
        if (event == XLIO_SOCKET_EVENT_ESTABLISHED) {
            pd = xlio_api->xlio_socket_get_pd(sock);
            ASSERT_TRUE(pd != NULL);
            mr_buf = ibv_reg_mr(pd, sndbuf, sizeof(sndbuf), IBV_ACCESS_LOCAL_WRITE);
            ASSERT_TRUE(mr_buf != NULL);
            send_single_msg(sock, data_to_send, strlen(data_to_send), 0x1, 0);
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
        comp_cb_counter++;
    }

    static void socket_rx_cb(xlio_socket_t sock, uintptr_t userdata_sq, void *data, size_t len,
                             struct xlio_buf *buf)
    {
        UNREFERENCED_PARAMETER(sock);
        UNREFERENCED_PARAMETER(userdata_sq);
        rx_cb_counter++;
        // Assume that the data_to_send is received in one packet
        if (memcmp(data, data_to_send, len) != 0) {
            GTEST_FAIL();
        }
        xlio_api->xlio_socket_buf_free(sock, buf);
    }

    static void socket_accept_cb(xlio_socket_t sock, xlio_socket_t parent_sock,
                                 uintptr_t parent_userdata)
    {
        UNREFERENCED_PARAMETER(sock);
        UNREFERENCED_PARAMETER(parent_sock);
        UNREFERENCED_PARAMETER(parent_userdata);
        int rc = xlio_api->xlio_socket_update(sock, 0, 0x1);
        ASSERT_EQ(rc, 0);
        accepted_sockets.push_back(sock);
        connected_counter++;
    }
};

/**
 * @test zc_api_xlio_socket_send_receive.ti_1
 * @brief
 *    Create TCP socket/connect/send(initiator)/receive(target)
 * @details
 */
TEST_F(zc_api_xlio_socket_send_receive, ti_1)
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
        base_create_socket(&sattr, &sock);

        rc = xlio_api->xlio_socket_bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        rc = xlio_api->xlio_socket_listen(sock);
        ASSERT_EQ(0, rc);

        barrier_fork(pid, true);

        while (connected_counter < 1 || rx_cb_counter < 1) {
            xlio_api->xlio_poll_group_poll(group);
        }

        wait_for_delayed_acks(group);

        barrier_fork(pid, false); // Wait for parent to receive last ack

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
        base_create_socket(&sattr, &sock);

        rc = xlio_api->xlio_socket_bind(sock, (struct sockaddr *)&client_addr, sizeof(client_addr));
        ASSERT_EQ(0, rc);

        barrier_fork(pid, true); // Wait for child to bind and listen

        rc = xlio_api->xlio_socket_connect(sock, (struct sockaddr *)&server_addr,
                                           sizeof(server_addr));
        ASSERT_EQ(0, rc);

        while (connected_counter < 1 || comp_cb_counter < 1) {
            xlio_api->xlio_poll_group_poll(group);
        }

        wait_for_delayed_acks(group);

        barrier_fork(pid, false);

        base_destroy_socket(sock);
        while (terminated_counter < 1) {
            xlio_api->xlio_poll_group_poll(group);
        }

        destroy_poll_group(group);

        wait_fork(pid);
    }
}

#endif /* EXTRA_API_ENABLED */
