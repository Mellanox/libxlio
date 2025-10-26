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
static unsigned int comp_cb_counter = 0U;
static struct ibv_pd *pd = NULL;
static struct ibv_mr *mr_buf;
static char sndbuf[32];
static std::vector<xlio_socket_t> accepted_sockets;
static unsigned int init_msgs = 10; // Consequent 10 segments should take 4 wqebb

struct xlio_socket_send_attr send_attr = {
    .flags = 0,
    .mkey = 0U,
    .userdata_op = 0x1,
};

class ultra_api_socket_send_receive_full_sq : public ultra_api_base {
public:
    virtual void SetUp()
    {
        errno = EOK;
        // Reset static variables between test runs
        connected_counter = 0;
        terminated_counter = 0;
        rx_cb_counter = 0;
        comp_cb_counter = 0;
        pd = NULL;
        mr_buf = NULL;
        accepted_sockets.clear();
        memset(sndbuf, 'A', sizeof(sndbuf));
    };
    virtual void TearDown()
    {
        // Clean up memory registration if it exists (parent process only)
        if (mr_buf) {
            ibv_dereg_mr(mr_buf);
            mr_buf = NULL;
        }
    };
    void destroy_poll_group(xlio_poll_group_t group) { base_destroy_poll_group(group); }
    static void socket_event_cb(xlio_socket_t sock, uintptr_t userdata_sq, int event, int value)
    {
        UNREFERENCED_PARAMETER(userdata_sq);
        UNREFERENCED_PARAMETER(value);
        if (event == XLIO_SOCKET_EVENT_ESTABLISHED) {
            pd = xlio_api->xlio_socket_get_pd(sock);
            ASSERT_TRUE(pd != NULL);
            mr_buf = ibv_reg_mr(pd, sndbuf, sizeof(sndbuf), IBV_ACCESS_LOCAL_WRITE);
            ASSERT_TRUE(mr_buf != NULL);
            send_attr.mkey = mr_buf->lkey;

            log_trace("Sending initial %u segments to form 4wqebb WQE\n", init_msgs);
            for (auto temp_msg = init_msgs; temp_msg; --temp_msg) {
                ASSERT_EQ(0, xlio_api->xlio_socket_send(sock, sndbuf, sizeof(sndbuf), &send_attr));
            }

            xlio_api->xlio_socket_flush(sock);
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
        UNREFERENCED_PARAMETER(data);
        UNREFERENCED_PARAMETER(len);
        rx_cb_counter++;
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
 * @test ultra_api_socket_send_receive_full_sq.ti_1
 * @brief
 *    Create TCP socket/connect/send(initiator)/receive(target)
 * @details
 */
TEST_F(ultra_api_socket_send_receive_full_sq, ti_1)
{
    int rc;
    int pid = fork();
    ultra_api_base::SetUp();
    xlio_poll_group_t group;
    xlio_socket_t sock;

    base_create_poll_group(&group, &socket_event_cb, &socket_comp_cb, &socket_rx_cb,
                           &socket_accept_cb);
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

        base_wait_for_delayed_acks(group);

        barrier_fork(pid, false); // Wait for parent to receive last ack

        base_destroy_socket(sock);
        base_cleanup_accepted_sockets(accepted_sockets);
        while (terminated_counter < 1) {
            xlio_api->xlio_poll_group_poll(group);
        }

        if (mr_buf) {
            ibv_dereg_mr(mr_buf);
            mr_buf = NULL;
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

        while (connected_counter < 1 || comp_cb_counter < init_msgs) {
            xlio_api->xlio_poll_group_poll(group);
        }

        // At this point we should have a completion for the last WQE of 4 wqebb.
        // Fill SQ with WQEs of 2wqebb size to overwrite on the last signalled space with 2 WQEs.

        unsigned int default_sq_size_wqebb = 32768; // Default SQ size in wqebb
        unsigned int num_wqe_to_send =
            default_sq_size_wqebb / 2; // Default Size of SQ (32768) / 2 (2wqebb per WQE)
        log_trace("Filling full SQ with %u WQEs of 2wqebb size\n", num_wqe_to_send);

        unsigned int num_wqe_to_send_temp = num_wqe_to_send;
        while (num_wqe_to_send_temp-- > 0) {
            ASSERT_EQ(0, xlio_api->xlio_socket_send(sock, sndbuf, sizeof(sndbuf), &send_attr));
            xlio_api->xlio_socket_flush(sock);
        }

        log_trace("Waiting for completions\n");
        while (num_wqe_to_send--) { // More than 2 completions is enough to overpass last signalled.
            xlio_api->xlio_poll_group_poll(group);
        }

        log_trace("Completions received\n");

        base_wait_for_delayed_acks(group);

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
