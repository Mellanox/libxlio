/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef TESTS_GTEST_XLIO_BASE_H_
#define TESTS_GTEST_XLIO_BASE_H_

#include <xlio_extra.h>
#include <xlio_types.h>
#include <vector>
#include <infiniband/verbs.h>
/**
 * To enable xlio tests you need to set below EXTRA_API_ENABLED to 1
 * or you can add the following CPPFLAG during compilation 'make CPPFLAGS="-DEXTRA_API_ENABLED=1"'
 */
#ifndef EXTRA_API_ENABLED
#define EXTRA_API_ENABLED 0
#endif

#define SEC_TO_NSEC(sec) ((sec)*1000000000L)

/**
 * XLIO Base class for tests
 */
class xlio_base : virtual public testing::Test, virtual public test_base {
protected:
    virtual void SetUp();
    virtual void TearDown();

protected:
#if defined(EXTRA_API_ENABLED) && (EXTRA_API_ENABLED == 1)
    static struct xlio_api_t *xlio_api;
#endif /* EXTRA_API_ENABLED */
};

#if defined(EXTRA_API_ENABLED) && (EXTRA_API_ENABLED == 1)
class xlio_ultra_api_base : public xlio_base {
public:
    virtual void SetUp()
    {
        xlio_base::SetUp();
        errno = EOK;
        base_init_xlio_ultra_api();
    };
    void base_create_poll_group(xlio_poll_group_t *group,
                                void (*socket_event_cb)(xlio_socket_t, uintptr_t, int, int),
                                void (*socket_comp_cb)(xlio_socket_t, uintptr_t, uintptr_t),
                                void (*socket_rx_cb)(xlio_socket_t, uintptr_t, void *, size_t,
                                                     struct xlio_buf *),
                                void (*socket_accept_cb)(xlio_socket_t, xlio_socket_t, uintptr_t))
    {
        xlio_poll_group_attr gattr = {
            .flags = 0,
            .socket_event_cb = socket_event_cb,
            .socket_comp_cb = socket_comp_cb,
            .socket_rx_cb = socket_rx_cb,
            .socket_accept_cb = socket_accept_cb,
        };
        int rc = xlio_api->xlio_poll_group_create(&gattr, group);
        ASSERT_TRUE(rc == 0);
    }
    void base_destroy_poll_group(xlio_poll_group_t group)
    {
        int rc;
        rc = xlio_api->xlio_poll_group_destroy(group);
        ASSERT_TRUE(rc == 0);
    }
    void base_create_socket(xlio_socket_attr *attr, xlio_socket_t *sock)
    {

        int rc;
        rc = xlio_api->xlio_socket_create(attr, sock);
        ASSERT_TRUE(rc == 0);
    }
    void base_destroy_socket(xlio_socket_t sock)
    {
        int rc;
        rc = xlio_api->xlio_socket_destroy(sock);
        ASSERT_TRUE(rc == 0);
    }
    void base_wait_for_delayed_acks(xlio_poll_group_t group, int timeout_seconds = 5)
    {
        struct timespec start_time;
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        struct timespec current_time = start_time;
        while (((SEC_TO_NSEC(current_time.tv_sec - start_time.tv_sec)) +
                (current_time.tv_nsec - start_time.tv_nsec)) < SEC_TO_NSEC(timeout_seconds)) {
            xlio_api->xlio_poll_group_poll(group);
            clock_gettime(CLOCK_MONOTONIC, &current_time);
        }
    }
    static void base_send_single_msg(xlio_socket_t sock, const void *data, size_t len,
                                     uintptr_t userdata_op, unsigned flags, struct ibv_mr *mr_buf,
                                     char *sndbuf)
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
    void base_cleanup_accepted_sockets(std::vector<xlio_socket_t> &accepted_sockets)
    {
        while (!accepted_sockets.empty()) {
            base_destroy_socket(accepted_sockets.back());
            accepted_sockets.pop_back();
        }
    }
    void base_init_xlio_ultra_api()
    {
        int rc;
        struct xlio_init_attr iattr = {
            .flags = 0,
            .memory_cb = nullptr,
            .memory_alloc = nullptr,
            .memory_free = nullptr,
        };

        rc = xlio_api->xlio_init_ex(&iattr);
        ASSERT_TRUE(rc == 0);
    };
    void base_cleanup_xlio_ultra_api()
    {
        int rc;
        rc = xlio_api->xlio_exit();
        ASSERT_TRUE(rc == 0);
    };
};
#endif /* EXTRA_API_ENABLED */

#endif /* TESTS_GTEST_XLIO_BASE_H_ */
