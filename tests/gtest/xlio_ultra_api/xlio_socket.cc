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

class xlio_ultra_api_socket : public xlio_ultra_api_base {
public:
    void destroy_poll_group(xlio_poll_group_t group) { base_destroy_poll_group(group); }
    static void socket_event_cb(xlio_socket_t sock, uintptr_t userdata_sq, int event, int value)
    {
        UNREFERENCED_PARAMETER(sock);
        UNREFERENCED_PARAMETER(userdata_sq);
        UNREFERENCED_PARAMETER(event);
        UNREFERENCED_PARAMETER(value);
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
 * @test xlio_ultra_api_socket.ti_1
 * @brief
 *    Create TCP socket
 * @details
 */
TEST_F(xlio_ultra_api_socket, ti_1)
{
    xlio_ultra_api_base::SetUp();
    xlio_poll_group_t group;
    xlio_socket_t sock;

    base_create_poll_group(&group, &socket_event_cb, &socket_comp_cb, &socket_rx_cb,
                           &socket_accept_cb);
    xlio_socket_attr sattr = {
        .flags = 0,
        .domain = AF_INET,
        .group = group,
        .userdata_sq = 0,
    };
    base_create_socket(&sattr, &sock);

    base_destroy_socket(sock);

    destroy_poll_group(group);
}

#endif /* EXTRA_API_ENABLED */
