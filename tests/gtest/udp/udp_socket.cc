/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"

#include "udp_base.h"

class udp_socket : public udp_base {};

/**
 * @test udp_socket.ti_1_ipv4
 * @brief
 *    Create IPv4 UDP socket
 * @details
 */
TEST_F(udp_socket, ti_1_ip_socket)
{
    int fd;

    fd = socket(m_family, SOCK_DGRAM, IPPROTO_IP);
    EXPECT_LE(0, fd);
    EXPECT_EQ(errno, EOK);

    close(fd);
}
