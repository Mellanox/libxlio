/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "googletest/include/gtest/gtest.h"

#include "src/core/lwip/tcp.h"

TEST(tcp_cc, initial_cwnd_uses_rfc3390_formula)
{
    EXPECT_EQ(4U * 512U, tcp_calc_initial_cwnd(512));
    EXPECT_EQ(4380U, tcp_calc_initial_cwnd(1460));
    EXPECT_EQ(2U * 8960U, tcp_calc_initial_cwnd(8960));
}

TEST(tcp_cc, initial_ssthresh_is_effectively_unlimited)
{
    EXPECT_EQ(0x7FFFFFFFU, tcp_calc_initial_ssthresh());
}

TEST(tcp_cc, slow_start_caps_stretch_ack_to_two_mss)
{
    EXPECT_EQ(1460U, tcp_calc_slow_start_increment(1460U, 1460));
    EXPECT_EQ(2U * 1460U, tcp_calc_slow_start_increment(64U * 1024U, 1460));
    EXPECT_EQ(100U, tcp_calc_slow_start_increment(100U, 1460));
}
