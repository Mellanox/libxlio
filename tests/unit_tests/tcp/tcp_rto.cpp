/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <gtest/gtest.h>
#include <cstring>

#include "core/lwip/tcp.h"
#include "core/lwip/tcp_impl.h"
#include "core/lwip/tcp_rto.h"

/* Initialize RTT/RTO state without the full lwIP setup. */
static void rto_test_pcb_reset(struct tcp_pcb *pcb)
{
    std::memset(pcb, 0, sizeof(*pcb));
    tcp_rto_pcb_seed(pcb);
    pcb->rtime = -1;
    pcb->ticks_since_data_sent = -1;
}

TEST(tcp_rto, sample_clamp_maps_zero_and_negative_to_one)
{
    EXPECT_EQ(1, tcp_rtt_sample_clamp_us(0));
    EXPECT_EQ(1, tcp_rtt_sample_clamp_us(-1));
    EXPECT_EQ(1, tcp_rtt_sample_clamp_us(-1000000));
    EXPECT_EQ(1, tcp_rtt_sample_clamp_us(1));
    EXPECT_EQ(80, tcp_rtt_sample_clamp_us(80));
    EXPECT_EQ(TCP_RTO_MAX_US, tcp_rtt_sample_clamp_us(TCP_RTO_MAX_US));
    EXPECT_EQ(TCP_RTO_MAX_US, tcp_rtt_sample_clamp_us(TCP_RTO_MAX_US + 1));
    EXPECT_EQ(TCP_RTO_MAX_US, tcp_rtt_sample_clamp_us(TCP_RTO_MAX_US * 1000));
}

TEST(tcp_rto, estimator_clamp_floors_at_one)
{
    /* Zero is reserved for the no-sample sentinel. */
    EXPECT_EQ(1, tcp_estimator_clamp_i32(-1));
    EXPECT_EQ(1, tcp_estimator_clamp_i32(0));
    EXPECT_EQ(1, tcp_estimator_clamp_i32(1));
    EXPECT_EQ(1000, tcp_estimator_clamp_i32(1000));
    EXPECT_EQ(0x7FFFFFFF, tcp_estimator_clamp_i32(0x7FFFFFFFLL));
    EXPECT_EQ(0x7FFFFFFF, tcp_estimator_clamp_i32(0x80000000LL));
    EXPECT_EQ(0x7FFFFFFF, tcp_estimator_clamp_i32(int64_t(1) << 40));
}

TEST(tcp_rto, rto_clamp_pins_to_configured_floor_and_max)
{
    EXPECT_EQ(600000, TCP_RTO_FLOOR_DEFAULT_US);
    EXPECT_EQ(TCP_RTO_FLOOR_DEFAULT_US, tcp_rto_clamp_us(0));
    EXPECT_EQ(TCP_RTO_FLOOR_DEFAULT_US, tcp_rto_clamp_us(TCP_RTO_FLOOR_DEFAULT_US - 1));
    EXPECT_EQ(TCP_RTO_FLOOR_DEFAULT_US, tcp_rto_clamp_us(TCP_RTO_FLOOR_DEFAULT_US));
    EXPECT_EQ(TCP_RTO_FLOOR_DEFAULT_US + 1, tcp_rto_clamp_us(TCP_RTO_FLOOR_DEFAULT_US + 1));
    EXPECT_EQ(TCP_RTO_MAX_US, tcp_rto_clamp_us(TCP_RTO_MAX_US));
    EXPECT_EQ(TCP_RTO_MAX_US, tcp_rto_clamp_us(TCP_RTO_MAX_US + 1));
    EXPECT_EQ(TCP_RTO_MAX_US, tcp_rto_clamp_us(int64_t(1) << 40));
}

TEST(tcp_rto, rto_from_estimator_additive_floor)
{
    EXPECT_EQ(600080, tcp_rto_from_estimator_us(/* 8 * 80us */ 640, /* 4 * 20us */ 80));
    EXPECT_EQ(605000, tcp_rto_from_estimator_us(/* 8 * 5000us */ 40000, /* 4 * 2000us */ 8000));
    EXPECT_EQ(700000, tcp_rto_from_estimator_us(800000, 160000));
    EXPECT_EQ(2000000, tcp_rto_from_estimator_us(8000000, 1000000));
}

TEST(tcp_rto, configured_floor_changes_clamp_and_estimator)
{
    EXPECT_EQ(TCP_RTO_FLOOR_DEFAULT_US, tcp_rto_get_floor_us());

    tcp_rto_set_floor_us(200000);

    EXPECT_EQ(200000, tcp_rto_get_floor_us());
    EXPECT_EQ(200000, tcp_rto_clamp_us(1));
    EXPECT_EQ(205000,
              tcp_rto_from_estimator_us(/* 8 * 5000us */ 40000,
                                        /* 4 * 2000us */ 8000));
    EXPECT_EQ(200000, tcp_rto_seed_from_handshake_us(100));

    tcp_rto_set_floor_us(0);
    EXPECT_EQ(TCP_RTO_FLOOR_MIN_US, tcp_rto_get_floor_us());

    tcp_rto_set_floor_us(TCP_RTO_MAX_US + 1);
    EXPECT_EQ(TCP_RTO_MAX_US, tcp_rto_get_floor_us());

    tcp_rto_set_floor_us(TCP_RTO_FLOOR_DEFAULT_US);
}

TEST(tcp_rto, additive_floor_rides_on_srtt)
{
    EXPECT_EQ(750000, tcp_rto_from_estimator_us(/* 8 * 150ms */ 1200000, /* 4*RTTVAR = 0 */ 1));
    EXPECT_EQ(750000, tcp_rto_from_estimator_us(1200000, /* 4 * 1ms */ 4000));

    EXPECT_EQ(TCP_RTO_FLOOR_DEFAULT_US + 100,
              tcp_rto_from_estimator_us(/* 8 * 100us */ 800, /* 4 * 25us */ 100));

    tcp_rto_set_floor_us(200000);
    EXPECT_EQ(350000, tcp_rto_from_estimator_us(/* 8 * 150ms */ 1200000, /* 4*RTTVAR = 0 */ 1));
    tcp_rto_set_floor_us(TCP_RTO_FLOOR_DEFAULT_US);

    EXPECT_EQ(TCP_RTO_MAX_US, tcp_rto_from_estimator_us(0x7FFFFFFF, 0x7FFFFFFF));
}

TEST(tcp_rto, seed_from_handshake_is_three_r_clamped)
{
    EXPECT_EQ(TCP_RTO_FLOOR_DEFAULT_US, tcp_rto_seed_from_handshake_us(100));
    EXPECT_EQ(900000, tcp_rto_seed_from_handshake_us(300000));
    EXPECT_EQ(TCP_RTO_FLOOR_DEFAULT_US, tcp_rto_seed_from_handshake_us(0));
    EXPECT_EQ(TCP_RTO_FLOOR_DEFAULT_US, tcp_rto_seed_from_handshake_us(-1000000));
    EXPECT_EQ(TCP_RTO_MAX_US, tcp_rto_seed_from_handshake_us(50000000));
    EXPECT_EQ(TCP_RTO_MAX_US, tcp_rto_seed_from_handshake_us(TCP_RTO_MAX_US * 100));
}

TEST(tcp_rto, estimator_first_sample_seeds_state)
{
    struct tcp_pcb pcb;
    rto_test_pcb_reset(&pcb);

    tcp_rtt_estimator_update_us(&pcb, 100);

    EXPECT_EQ(800, pcb.sa_us);
    EXPECT_EQ(200, pcb.sv_us);
    EXPECT_EQ(TCP_RTO_FLOOR_DEFAULT_US + 100, pcb.rto_us);
}

TEST(tcp_rto, estimator_zero_or_negative_sample_clamps_to_one)
{
    struct tcp_pcb pcb;
    rto_test_pcb_reset(&pcb);

    tcp_rtt_estimator_update_us(&pcb, 0);

    EXPECT_EQ(8, pcb.sa_us);
    EXPECT_EQ(2, pcb.sv_us);
    EXPECT_EQ(TCP_RTO_FLOOR_DEFAULT_US + 1, pcb.rto_us);

    rto_test_pcb_reset(&pcb);
    tcp_rtt_estimator_update_us(&pcb, -1000000);
    EXPECT_EQ(8, pcb.sa_us);
    EXPECT_EQ(2, pcb.sv_us);
    EXPECT_EQ(TCP_RTO_FLOOR_DEFAULT_US + 1, pcb.rto_us);
}

TEST(tcp_rto, estimator_huge_sample_clamps_rto_to_max)
{
    struct tcp_pcb pcb;
    rto_test_pcb_reset(&pcb);

    tcp_rtt_estimator_update_us(&pcb, TCP_RTO_MAX_US * 100);

    EXPECT_EQ(TCP_RTO_MAX_US, pcb.rto_us);
}

TEST(tcp_rto, estimator_second_sample_follows_vj_form)
{
    struct tcp_pcb pcb;
    rto_test_pcb_reset(&pcb);

    tcp_rtt_estimator_update_us(&pcb, 1000);
    ASSERT_EQ(8000, pcb.sa_us);
    ASSERT_EQ(2000, pcb.sv_us);

    tcp_rtt_estimator_update_us(&pcb, 2000);
    EXPECT_EQ(9000, pcb.sa_us);
    EXPECT_EQ(2500, pcb.sv_us);
    EXPECT_EQ(TCP_RTO_FLOOR_DEFAULT_US + 1125, pcb.rto_us);
}

TEST(tcp_rto, syn_fallback_rto_value_matches_rfc6298)
{
    EXPECT_EQ(TCP_RTO_FALLBACK_US, tcp_syn_fallback_rto_us());
    EXPECT_EQ(3000000, TCP_RTO_FALLBACK_US);
    EXPECT_EQ(1000000, TCP_RTO_INITIAL_US);
}

TEST(tcp_rto, syn_fallback_first_sample_retains_fallback_variance)
{
    struct tcp_pcb pcb;
    rto_test_pcb_reset(&pcb);

    pcb.rto_us = tcp_syn_fallback_rto_us();
    pcb.sv_us = tcp_syn_fallback_rto_us();

    tcp_rtt_estimator_update_us(&pcb, 100);

    EXPECT_EQ(800, pcb.sa_us);
    EXPECT_EQ(TCP_RTO_FALLBACK_US, pcb.sv_us);
    EXPECT_EQ(TCP_RTO_FALLBACK_US + 100, pcb.rto_us)
        << "a valid sample must use the documented additive formula";
}

TEST(tcp_rto, sample_start_eligibility)
{
    struct tcp_pcb pcb;
    rto_test_pcb_reset(&pcb);

    pcb.snd_nxt = 2000;
    pcb.rttest_us = 0;

    EXPECT_FALSE(tcp_rtt_sample_should_start(&pcb, 1000, 100, false));
    EXPECT_TRUE(tcp_rtt_sample_should_start(&pcb, 2000, 100, false));
    EXPECT_FALSE(tcp_rtt_sample_should_start(&pcb, 2000, 0, false));
    EXPECT_TRUE(tcp_rtt_sample_should_start(&pcb, 2000, 0, true));

    pcb.rttest_us = 12345;
    EXPECT_FALSE(tcp_rtt_sample_should_start(&pcb, 3000, 100, false));
}

TEST(tcp_rto, deadline_elapsed_predicate)
{
    struct tcp_pcb pcb;
    rto_test_pcb_reset(&pcb);

    EXPECT_FALSE(tcp_rto_deadline_elapsed(&pcb, 0));
    EXPECT_FALSE(tcp_rto_deadline_elapsed(&pcb, 1000000));

    struct tcp_seg fake_seg = {};
    pcb.unacked = &fake_seg;
    EXPECT_FALSE(tcp_rto_deadline_elapsed(&pcb, 1000000));

    pcb.rto_deadline_us = 1000000;
    EXPECT_FALSE(tcp_rto_deadline_elapsed(&pcb, 999999));
    EXPECT_TRUE(tcp_rto_deadline_elapsed(&pcb, 1000000));
    EXPECT_TRUE(tcp_rto_deadline_elapsed(&pcb, 2000000));

    pcb.unacked = nullptr;
    EXPECT_TRUE(tcp_rto_deadline_elapsed(&pcb, 2000000));
}

TEST(tcp_rto, timer_helpers_maintain_marker_state)
{
    struct tcp_pcb pcb;
    rto_test_pcb_reset(&pcb);

    tcp_rto_timer_start_if_needed(&pcb, 10000);
    int64_t first_deadline = pcb.rto_deadline_us;
    EXPECT_EQ(10000 + (int64_t)TCP_RTO_INITIAL_US, first_deadline);
    EXPECT_EQ(0, pcb.rtime);
    EXPECT_EQ(0, pcb.ticks_since_data_sent);

    tcp_rto_timer_start_if_needed(&pcb, 20000);
    EXPECT_EQ(first_deadline, pcb.rto_deadline_us);

    tcp_rto_timer_rearm(&pcb, 30000);
    EXPECT_EQ(30000 + (int64_t)TCP_RTO_INITIAL_US, pcb.rto_deadline_us);
    EXPECT_EQ(0, pcb.rtime);

    tcp_rto_timer_stop(&pcb);
    EXPECT_EQ(0, pcb.rto_deadline_us);
    EXPECT_EQ(-1, pcb.rtime);
    EXPECT_EQ(-1, pcb.ticks_since_data_sent);
}

TEST(tcp_rto, sample_update_before_rearm_uses_fresh_rto)
{
    struct tcp_pcb pcb;
    rto_test_pcb_reset(&pcb);

    pcb.rttest_us = 10000;
    pcb.rtseq = 1000;
    pcb.rto_us = (s32_t)TCP_RTO_INITIAL_US;

    tcp_rtt_estimator_update_and_rearm_us(&pcb, 10100, 20000);

    EXPECT_EQ(TCP_RTO_FLOOR_DEFAULT_US + 100, pcb.rto_us);
    EXPECT_EQ(20000 + (int64_t)TCP_RTO_FLOOR_DEFAULT_US + 100, pcb.rto_deadline_us);
    EXPECT_EQ(0, pcb.rttest_us);
}

TEST(tcp_rto, ooseq_timeout_enforces_three_tick_minimum)
{
    const uint64_t slow_interval_us = 20000;

    struct tcp_pcb pcb;
    rto_test_pcb_reset(&pcb);

    pcb.rto_us = 1000;
    EXPECT_EQ(slow_interval_us * TCP_OOSEQ_RTO_MIN_TICKS * TCP_OOSEQ_TIMEOUT,
              tcp_ooseq_timeout_us(&pcb, slow_interval_us));

    pcb.rto_us = 1000000;
    EXPECT_EQ(1000000ULL * TCP_OOSEQ_TIMEOUT, tcp_ooseq_timeout_us(&pcb, slow_interval_us));
}

TEST(xlio_time, batch_guard_restores_prior_timestamp_on_scope_exit)
{
    g_xlio_tls_now_us = 12345;
    {
        xlio_now_us_batch outer_batch;
        EXPECT_FALSE(outer_batch.armed());
        EXPECT_EQ(12345, xlio_now_us());

        const int64_t outer_time_us = outer_batch.refresh();
        EXPECT_TRUE(outer_batch.armed());
        EXPECT_GT(outer_time_us, 0);
        EXPECT_EQ(outer_time_us, xlio_now_us());

        {
            xlio_now_us_batch inner_batch;
            const int64_t inner_time_us = inner_batch.refresh();
            EXPECT_GT(inner_time_us, 0);
            EXPECT_EQ(inner_time_us, xlio_now_us());
        }
        EXPECT_EQ(outer_time_us, xlio_now_us());
    }
    EXPECT_EQ(12345, xlio_now_us());

    g_xlio_tls_now_us = 777;
    {
        xlio_now_us_batch batch;
        EXPECT_FALSE(batch.armed());
    }
    EXPECT_EQ(777, xlio_now_us());

    g_xlio_tls_now_us = 0;
}
