/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "core/xlio_base.h"

#include <chrono>
#include <unordered_map>

#if defined(EXTRA_API_ENABLED) && (EXTRA_API_ENABLED == 1)

class ultra_api_socket_metadata {
public:
    bool event_is_triggered(int event) const { return m_events.find(event) != m_events.end(); }
    void event_trigger(int event, int value) { m_events[event] = value; }
    int event_triggered_nr() const { return m_events.size(); }
    int error()
    {
        return event_is_triggered(XLIO_SOCKET_EVENT_ERROR) ? m_events[XLIO_SOCKET_EVENT_ERROR] : -1;
    }

    std::unordered_map<int, int> m_events;
};

class ultra_api_socket : public ultra_api_base {
public:
    void destroy_poll_group(xlio_poll_group_t group) { base_destroy_poll_group(group); }
    static void socket_event_cb(xlio_socket_t sock, uintptr_t userdata_sq, int event, int value)
    {
        UNREFERENCED_PARAMETER(sock);
        UNREFERENCED_PARAMETER(userdata_sq);
        UNREFERENCED_PARAMETER(event);
        UNREFERENCED_PARAMETER(value);
    }

    static void socket_event_cb_metadata(xlio_socket_t sock, uintptr_t userdata_sq, int event,
                                         int value)
    {
        UNREFERENCED_PARAMETER(sock);

        ultra_api_socket_metadata *mdata =
            reinterpret_cast<ultra_api_socket_metadata *>(userdata_sq);
        ASSERT_TRUE(!mdata->event_is_triggered(event));
        mdata->event_trigger(event, value);
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
    }
};

/**
 * @test ultra_api_socket.ti_1
 * @brief
 *    Create TCP socket
 * @details
 */
TEST_F(ultra_api_socket, ti_1)
{
    ultra_api_base::SetUp();
    xlio_poll_group_t group;
    xlio_socket_t sock;

    base_create_poll_group(&group, &socket_event_cb, &socket_comp_cb, &socket_rx_cb,
                           &socket_accept_cb);
    xlio_socket_attr sattr = {
        .flags = 0,
        .domain = client_addr.addr.sa_family,
        .group = group,
        .userdata_sq = 0,
    };
    base_create_socket(&sattr, &sock);

    base_destroy_socket(sock);
    destroy_poll_group(group);
}

/**
 * @test ultra_api_socket.ti_2
 * @brief
 *    Test XLIO_SOCKET_EVENT_TERMINATED for a non-connected socket
 * @details
 */
TEST_F(ultra_api_socket, ti_2)
{
    xlio_poll_group_t group;
    xlio_socket_t sock;
    ultra_api_socket_metadata mdata;

    base_create_poll_group(&group, &socket_event_cb_metadata, &socket_comp_cb, &socket_rx_cb,
                           &socket_accept_cb);
    xlio_socket_attr sattr = {
        .flags = 0,
        .domain = client_addr.addr.sa_family,
        .group = group,
        .userdata_sq = reinterpret_cast<uintptr_t>(&mdata),
    };
    base_create_socket(&sattr, &sock);

    base_destroy_socket(sock);

    // Poll group until the TERMINATED event or timeout.
    auto timeout = std::chrono::microseconds(500);
    auto start_time = std::chrono::steady_clock::now();
    bool timedout = false;
    do {
        xlio_api->xlio_poll_group_poll(group);
        timedout = (std::chrono::steady_clock::now() - start_time > timeout);
    } while (!mdata.event_is_triggered(XLIO_SOCKET_EVENT_TERMINATED) && !timedout);

    ASSERT_TRUE(mdata.event_is_triggered(XLIO_SOCKET_EVENT_TERMINATED));
    ASSERT_EQ(1, mdata.event_triggered_nr());

    destroy_poll_group(group);
}

/**
 * @test ultra_api_socket.ti_3
 * @brief
 *    Test XLIO_SOCKET_EVENT_TERMINATED for a socket with failed connect
 * @details
 */
TEST_F(ultra_api_socket, ti_3)
{
    xlio_poll_group_t group;
    xlio_socket_t sock;
    ultra_api_socket_metadata mdata;
    int rc;

    sockaddr_store_t fake_addr = server_addr;
    sys_set_port((struct sockaddr *)&fake_addr, 65535);

    base_create_poll_group(&group, &socket_event_cb_metadata, &socket_comp_cb, &socket_rx_cb,
                           &socket_accept_cb);
    xlio_socket_attr sattr = {
        .flags = 0,
        .domain = client_addr.addr.sa_family,
        .group = group,
        .userdata_sq = reinterpret_cast<uintptr_t>(&mdata),
    };
    base_create_socket(&sattr, &sock);

    // Set UTO to fail connect ASAP.
    unsigned uto_ms = 1U;
    rc = xlio_api->xlio_socket_setsockopt(sock, IPPROTO_TCP, TCP_USER_TIMEOUT, &uto_ms,
                                          sizeof(uto_ms));
    EXPECT_EQ(0, rc);

    rc = xlio_api->xlio_socket_bind(sock, (struct sockaddr *)&client_addr, sizeof(client_addr));
    ASSERT_EQ(0, rc);
    rc = xlio_api->xlio_socket_connect(sock, (struct sockaddr *)&fake_addr, sizeof(fake_addr));
    ASSERT_EQ(0, rc);

    // We expect socket connect to fail.
    auto timeout = std::chrono::microseconds(1000000);
    auto start_time = std::chrono::steady_clock::now();
    bool timedout = false;
    do {
        xlio_api->xlio_poll_group_poll(group);
        timedout = (std::chrono::steady_clock::now() - start_time > timeout);
    } while (!mdata.event_is_triggered(XLIO_SOCKET_EVENT_ERROR) && !timedout);

    ASSERT_TRUE(mdata.event_is_triggered(XLIO_SOCKET_EVENT_ERROR));
    ASSERT_EQ(1, mdata.event_triggered_nr());
    ASSERT_TRUE(mdata.error() == ETIMEDOUT || mdata.error() == ECONNREFUSED)
        << "Where error is " << mdata.error();

    // TERMINATED event mustn't be triggered before xlio_socket_destroy() is called.
    timeout = std::chrono::microseconds(500);
    start_time = std::chrono::steady_clock::now();
    timedout = false;
    do {
        xlio_api->xlio_poll_group_poll(group);
        timedout = (std::chrono::steady_clock::now() - start_time > timeout);
    } while (!mdata.event_is_triggered(XLIO_SOCKET_EVENT_TERMINATED) && !timedout);

    ASSERT_TRUE(!mdata.event_is_triggered(XLIO_SOCKET_EVENT_TERMINATED));

    base_destroy_socket(sock);

    // Now we destroy failed socket and the TERMINATED event is expected with the next poll.
    timeout = std::chrono::microseconds(500);
    start_time = std::chrono::steady_clock::now();
    timedout = false;
    do {
        xlio_api->xlio_poll_group_poll(group);
        timedout = (std::chrono::steady_clock::now() - start_time > timeout);
    } while (!mdata.event_is_triggered(XLIO_SOCKET_EVENT_TERMINATED) && !timedout);

    ASSERT_TRUE(mdata.event_is_triggered(XLIO_SOCKET_EVENT_TERMINATED));
    ASSERT_EQ(2, mdata.event_triggered_nr());

    destroy_poll_group(group);
}

#endif /* EXTRA_API_ENABLED */
