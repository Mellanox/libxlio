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

/* Helper: fresh PCB with the same initial state tcp_pcb_init() leaves
 * behind for the RTT/RTO subset. Avoids pulling in the rest of the
 * lwIP init path (which needs CC, lwip_tcp_mss, etc.).
 */
static void rto_test_pcb_reset(struct tcp_pcb *pcb)
{
    std::memset(pcb, 0, sizeof(*pcb));
    tcp_rto_pcb_seed(pcb);
    pcb->rtime = -1;
    pcb->ticks_since_data_sent = -1;
}

TEST(tcp_rto, sample_clamp_rejects_zero_and_negative)
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

TEST(tcp_rto, estimator_clamp_preserves_one_as_lower_bound)
{
    /* sa_us == 0 is the "no prior sample" sentinel; the clamp must NOT
     * drive a post-sample value to 0 because that would re-trigger the
     * first-sample seed and overwrite a healthy estimator.
     */
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
    /* sa_us is stored as 8 * SRTT, sv_us is stored as 4 * RTTVAR.
     * Additive-floor shape: rto = SRTT + max(4*RTTVAR, TCP_RTO_FLOOR_DEFAULT_US),
     * capped at TCP_RTO_MAX_US. The 600 ms floor rides ON TOP of SRTT; it
     * does not substitute for it.
     *
     * SRTT = 80us, RTTVAR = 20us -> 80 + max(80, 600000) = 600080 us. */
    EXPECT_EQ(600080, tcp_rto_from_estimator_us(/* 8 * 80us */ 640, /* 4 * 20us */ 80));
    /* SRTT = 5ms, RTTVAR = 2ms -> 5000 + max(8000, 600000) = 605000 us. */
    EXPECT_EQ(605000, tcp_rto_from_estimator_us(/* 8 * 5000us */ 40000, /* 4 * 2000us */ 8000));
    /* SRTT = 100ms, RTTVAR = 40ms -> 100000 + max(160000, 600000) = 700000 us. */
    EXPECT_EQ(700000, tcp_rto_from_estimator_us(800000, 160000));
    /* SRTT = 1s, RTTVAR = 250ms -> 1000000 + max(1000000, 600000) = 2000000 us:
     * once the variance term exceeds the floor, the shape matches the legacy
     * candidate exactly. */
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
    /* Default path: SRTT = 150 ms with a small variance yields 750 ms
     * (150 ms path latency + the full 600 ms scheduling allowance). */
    EXPECT_EQ(750000, tcp_rto_from_estimator_us(/* 8 * 150ms */ 1200000, /* 4*RTTVAR = 0 */ 1));
    EXPECT_EQ(750000, tcp_rto_from_estimator_us(1200000, /* 4 * 1ms */ 4000));

    /* Idle path stays near the default 600 ms floor. */
    EXPECT_EQ(TCP_RTO_FLOOR_DEFAULT_US + 100,
              tcp_rto_from_estimator_us(/* 8 * 100us */ 800, /* 4 * 25us */ 100));

    /* Latency-tuned deployments can explicitly retain a 200 ms allowance. */
    tcp_rto_set_floor_us(200000);
    EXPECT_EQ(350000, tcp_rto_from_estimator_us(/* 8 * 150ms */ 1200000, /* 4*RTTVAR = 0 */ 1));
    tcp_rto_set_floor_us(TCP_RTO_FLOOR_DEFAULT_US);

    /* TCP_RTO_MAX cap still applies on top of the additive shape. */
    EXPECT_EQ(TCP_RTO_MAX_US, tcp_rto_from_estimator_us(0x7FFFFFFF, 0x7FFFFFFF));
}

TEST(tcp_rto, seed_from_handshake_is_three_r_clamped)
{
    /* RFC 6298 2.2: RTO from a single sample R is 3R (SRTT=R, RTTVAR=R/2),
     * clamped to [TCP_RTO_FLOOR_DEFAULT_US, TCP_RTO_MAX_US]. */

    /* Tiny handshake RTT (datacenter): 3 * 100us = 300us -> clamps up to the floor. */
    EXPECT_EQ(TCP_RTO_FLOOR_DEFAULT_US, tcp_rto_seed_from_handshake_us(100));

    /* Mid RTT: 3 * 300ms = 900ms, in range -> no clamp. */
    EXPECT_EQ(900000, tcp_rto_seed_from_handshake_us(300000));

    /* Zero / negative raw RTT clamps the sample to 1us first, then to the RTO floor. */
    EXPECT_EQ(TCP_RTO_FLOOR_DEFAULT_US, tcp_rto_seed_from_handshake_us(0));
    EXPECT_EQ(TCP_RTO_FLOOR_DEFAULT_US, tcp_rto_seed_from_handshake_us(-1000000));

    /* Large RTT: 3 * 50s = 150s > MAX -> clamps DOWN to MAX. */
    EXPECT_EQ(TCP_RTO_MAX_US, tcp_rto_seed_from_handshake_us(50000000));

    /* Absurd raw RTT: sample clamps to MAX first, then 3*MAX clamps to MAX. */
    EXPECT_EQ(TCP_RTO_MAX_US, tcp_rto_seed_from_handshake_us(TCP_RTO_MAX_US * 100));
}

TEST(tcp_rto, estimator_first_sample_seeds_state)
{
    /* RTT/RTO test sketch row "first sample":
     * R = 100 us -> sa_us = 800, sv_us = 200,
     * rto_us = 100 + max(200, floor) = floor + 100.
     */
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

    /* First sample of R=1: sa_us = 8, sv_us = 2,
     * rto = 1 + max(2, floor) = floor + 1. */
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

    /* First-sample of an absurd value clamps the SAMPLE to TCP_RTO_MAX_US
     * before seeding. sa_us = 8 * MAX gets clamped by tcp_estimator_clamp_i32
     * (since 8 * MAX = 960e6 > 0x7FFFFFFF? actually 960e6 < 2147e6 so safe).
     * rto_us = ((8*MAX) >> 3) + 2*MAX -> clamped to MAX.
     */
    tcp_rtt_estimator_update_us(&pcb, TCP_RTO_MAX_US * 100);

    EXPECT_EQ(TCP_RTO_MAX_US, pcb.rto_us);
}

TEST(tcp_rto, estimator_second_sample_follows_vj_form)
{
    /* Seed with a first sample of R = 1000 us:
     *   sa_us = 8000, sv_us = 2000,
     *   rto_us = 1000 + max(2000, floor) = floor + 1000.
     * Apply a second sample R = 2000 us:
     *   err = 2000 - (8000 >> 3) = 1000
     *   sa_us = 8000 + 1000 = 9000
     *   |err| = 1000; sv_us = 2000 + (1000 - (2000>>2)) = 2500
     *   rto_us = (9000 >> 3) + max(2500, floor) = 1125 + floor.
     */
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
    EXPECT_EQ(3000000, TCP_RTO_FALLBACK_US); /* opt.h TCP_FALLBACK_RTO_MS = 3000 */
    EXPECT_EQ(1000000, TCP_RTO_INITIAL_US); /* opt.h TCP_INITIAL_RTO_MS = 1000 */
}

TEST(tcp_rto, syn_fallback_first_sample_preserves_fallback_variance)
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

    /* Retransmit (seqno below snd_nxt): excluded by Karn. */
    EXPECT_FALSE(tcp_rtt_sample_should_start(&pcb, 1000, 100, false));
    /* New data carrying payload: eligible. */
    EXPECT_TRUE(tcp_rtt_sample_should_start(&pcb, 2000, 100, false));
    /* Zero-length non-SYN (FIN-only / control-only): excluded. */
    EXPECT_FALSE(tcp_rtt_sample_should_start(&pcb, 2000, 0, false));
    /* Zero-length SYN: eligible (handshake RTT seeds the initial RTO). */
    EXPECT_TRUE(tcp_rtt_sample_should_start(&pcb, 2000, 0, true));

    /* Sample already in flight: excluded regardless of payload/flags. */
    pcb.rttest_us = 12345;
    EXPECT_FALSE(tcp_rtt_sample_should_start(&pcb, 3000, 100, false));
}

TEST(tcp_rto, deadline_elapsed_predicate)
{
    struct tcp_pcb pcb;
    rto_test_pcb_reset(&pcb);

    /* No unacked, no deadline -> not elapsed. */
    EXPECT_FALSE(tcp_rto_deadline_elapsed(&pcb, 0));
    EXPECT_FALSE(tcp_rto_deadline_elapsed(&pcb, 1000000));

    /* unacked set but no deadline -> not elapsed (idempotent invariant). */
    struct tcp_seg fake_seg = {};
    pcb.unacked = &fake_seg;
    EXPECT_FALSE(tcp_rto_deadline_elapsed(&pcb, 1000000));

    /* Deadline armed, timer before deadline -> not elapsed. */
    pcb.rto_deadline_us = 1000000;
    EXPECT_FALSE(tcp_rto_deadline_elapsed(&pcb, 999999));
    EXPECT_TRUE(tcp_rto_deadline_elapsed(&pcb, 1000000));
    EXPECT_TRUE(tcp_rto_deadline_elapsed(&pcb, 2000000));

    /* unacked dropped (empty queue) -> never elapsed even if deadline non-zero. */
    pcb.unacked = nullptr;
    EXPECT_FALSE(tcp_rto_deadline_elapsed(&pcb, 2000000));
}

TEST(tcp_rto, timer_helpers_maintain_marker_state)
{
    struct tcp_pcb pcb;
    rto_test_pcb_reset(&pcb);

    /* tcp_rto_timer_start_if_needed is idempotent: a second call within
     * the same flight does NOT advance the deadline. */
    tcp_rto_timer_start_if_needed(&pcb, 10000);
    int64_t first_deadline = pcb.rto_deadline_us;
    EXPECT_EQ(10000 + (int64_t)TCP_RTO_INITIAL_US, first_deadline);
    EXPECT_EQ(0, pcb.rtime);
    EXPECT_EQ(0, pcb.ticks_since_data_sent);

    tcp_rto_timer_start_if_needed(&pcb, 20000);
    EXPECT_EQ(first_deadline, pcb.rto_deadline_us);

    /* rearm bumps the deadline relative to now and resets the markers. */
    tcp_rto_timer_rearm(&pcb, 30000);
    EXPECT_EQ(30000 + (int64_t)TCP_RTO_INITIAL_US, pcb.rto_deadline_us);
    EXPECT_EQ(0, pcb.rtime);

    /* stop clears deadline AND marker. */
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

    /* Sample = 100 us -> first-sample seed sa = 800, sv = 200;
     * additive floor: rto = 100 + max(200, floor) = floor + 100. */
    EXPECT_EQ(TCP_RTO_FLOOR_DEFAULT_US + 100, pcb.rto_us);
    EXPECT_EQ(20000 + (int64_t)TCP_RTO_FLOOR_DEFAULT_US + 100, pcb.rto_deadline_us);
    EXPECT_EQ(0, pcb.rttest_us);
}

TEST(tcp_rto, ooseq_timeout_preserves_legacy_floor)
{
    /* slow_interval_us assumed = 20 ms (default cadence with
     * tcp_timer_resolution_msec = 10 -> slow_tmr_interval_ms = 20).
     */
    const uint64_t slow_interval_us = 20000;

    struct tcp_pcb pcb;
    rto_test_pcb_reset(&pcb);

    /* Tiny RTO < legacy floor (3 ticks = 60ms) -> legacy floor wins. */
    pcb.rto_us = 1000;
    EXPECT_EQ(slow_interval_us * TCP_RTO_LEGACY_OOSEQ_MIN_TICKS * TCP_OOSEQ_TIMEOUT,
              tcp_ooseq_timeout_us(&pcb, slow_interval_us));

    /* Large RTO above floor -> RTO * TCP_OOSEQ_TIMEOUT. */
    pcb.rto_us = 1000000; /* 1 second */
    EXPECT_EQ(1000000ULL * TCP_OOSEQ_TIMEOUT, tcp_ooseq_timeout_us(&pcb, slow_interval_us));
}

/* The RX-batch guard makes a missed refresh fail-safe: it refreshes on the
 * first packet of a non-empty batch and clears the per-thread cache to 0 on
 * scope exit, so a later read without a same-batch refresh sees the detectable
 * 0 sentinel rather than a stale value from an earlier batch. An unrefreshed
 * (empty-poll) guard must NOT touch the cache, keeping the empty-poll hot path
 * free of TLS writes - it is safe because the previous non-empty batch already
 * cleared the slot on its own scope exit.
 */
TEST(xlio_time, batch_guard_clears_on_scope_exit)
{
    /* Simulate a stale value left in TLS, then a non-empty batch. */
    g_xlio_tls_now_us = 12345;
    {
        xlio_now_us_batch batch;
        EXPECT_FALSE(batch.armed());
        EXPECT_EQ(12345, xlio_now_us()); /* untouched until the first refresh */

        const int64_t t = batch.refresh();
        EXPECT_TRUE(batch.armed());
        EXPECT_GT(t, 0);
        EXPECT_EQ(t, xlio_now_us());
    } /* guard destructs -> clears */
    EXPECT_EQ(0, xlio_now_us()) << "refreshed batch must clear the cache on scope exit";

    /* Empty-poll case: a guard that never refreshes leaves the cache untouched
     * (no TLS write on the hot path). The prior non-empty batch is what zeroes
     * the slot, so this never resurrects a stale RTT into a later sample.
     */
    g_xlio_tls_now_us = 777;
    {
        xlio_now_us_batch batch;
        EXPECT_FALSE(batch.armed());
    }
    EXPECT_EQ(777, xlio_now_us()) << "unrefreshed (empty-poll) batch must not write TLS";

    g_xlio_tls_now_us = 0; /* leave the slot clean for other tests on this thread */
}
