/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "googletest/include/gtest/gtest.h"

#include "src/core/lwip/tcp.h"

/* Congestion-window-validation gate (RM#5176178, RFC 2861 Section 3): cwnd
 * grows only while the sender is cwnd-limited (in-flight >= cwnd). This is what
 * stops the unbounded cwnd growth that destabilized the loss-free steady state. */
TEST(tcp_cc, cwnd_may_grow_only_when_fully_utilized)
{
    EXPECT_FALSE(tcp_cwnd_may_grow(4096U, 1000000U)); /* in-flight << cwnd: no growth */
    EXPECT_TRUE(tcp_cwnd_may_grow(1000000U, 1000000U)); /* in-flight == cwnd: growth */
    EXPECT_TRUE(tcp_cwnd_may_grow(2000000U, 1000000U)); /* in-flight  > cwnd: growth */
    EXPECT_FALSE(tcp_cwnd_may_grow(0U, 1U)); /* idle: no growth */
}

/* RM#5176178: the gate tests the PRE-ACK in-flight. lwip_ack_received runs after
 * lastack advanced by acked, so tcp_inflight_pre_ack reconstructs the flightsize
 * outstanding when the ACK arrived: (snd_nxt - lastack) + acked. */
TEST(tcp_cc, inflight_pre_ack_reconstructs_flightsize)
{
    /* snd_nxt=10000, 5000 was outstanding, ACK covers 3000 -> lastack now 8000;
     * pre-ACK in-flight was 10000-5000 = 5000. */
    EXPECT_EQ(5000U, tcp_inflight_pre_ack(10000U, 8000U, 3000U));
    /* full drain: everything outstanding is ACKed, so pre-ACK in-flight == acked. */
    EXPECT_EQ(4000U, tcp_inflight_pre_ack(9000U, 9000U, 4000U));
    /* seqno wrap: snd_nxt wrapped past 2^32, lastack advanced across the wrap;
     * unsigned math still yields the small pre-ACK distance (512), not a huge value. */
    EXPECT_EQ(512U, tcp_inflight_pre_ack(0x100U, 0xFFFFFF80U, 0x80U));
}

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
