/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <cstring>

#include "core/lwip/tcp.h"
#include "core/lwip/tcp_impl.h"
#include "core/lwip/tcp_rto.h"
#include "core/proto/xlio_time.h"

extern "C" {
int32_t enable_wnd_scale = 0;
u32_t rcv_wnd_scale = 0;
}

namespace {

struct test_segment_storage {
    tcp_seg seg {};
    pbuf p {};
    unsigned char bytes[TCP_HLEN + 16] {};
};

static int g_ip_output_calls;
static int g_error_calls;
static err_t g_last_error;
static int g_seg_free_calls;
static tcp_seg *g_freed_seg;

static void capture_error(void *arg, err_t err)
{
    (void)arg;
    ++g_error_calls;
    g_last_error = err;
}

static void noop_seg_free(void *p_conn, struct tcp_seg *seg)
{
    (void)p_conn;
    (void)seg;
}

static void record_seg_free(void *p_conn, struct tcp_seg *seg)
{
    (void)p_conn;
    ++g_seg_free_calls;
    g_freed_seg = seg;
}

static void noop_tx_pbuf_free(void *p_conn, struct pbuf *p)
{
    (void)p_conn;
    (void)p;
}

static void noop_state_observer(void *p_conn, enum tcp_state state)
{
    (void)p_conn;
    (void)state;
}

struct timer_resolution_guard {
    explicit timer_resolution_guard(u32_t fast_interval_ms)
        : saved_slow_interval_ms(slow_tmr_interval)
    {
        set_tmr_resolution(fast_interval_ms);
    }

    ~timer_resolution_guard() { slow_tmr_interval = saved_slow_interval_ms; }

    u32_t saved_slow_interval_ms;
};

static err_t fail_with_wouldblock(struct pbuf *p, struct tcp_seg *seg, void *pcb, u16_t flags)
{
    (void)p;
    (void)seg;
    (void)pcb;
    (void)flags;
    ++g_ip_output_calls;
    return ERR_WOULDBLOCK;
}

static err_t fail_with_mem(struct pbuf *p, struct tcp_seg *seg, void *pcb, u16_t flags)
{
    (void)p;
    (void)seg;
    (void)pcb;
    (void)flags;
    ++g_ip_output_calls;
    return ERR_MEM;
}

static err_t fail_with_reset(struct pbuf *p, struct tcp_seg *seg, void *pcb, u16_t flags)
{
    (void)p;
    (void)seg;
    (void)pcb;
    (void)flags;
    ++g_ip_output_calls;
    return ERR_RST;
}

static void purge_on_error(void *arg, err_t err)
{
    ++g_error_calls;
    g_last_error = err;
    tcp_pcb_purge(static_cast<tcp_pcb *>(arg));
}

/* First call succeeds; later calls block. */
static err_t succeed_then_wouldblock(struct pbuf *p, struct tcp_seg *seg, void *pcb, u16_t flags)
{
    (void)p;
    (void)seg;
    (void)pcb;
    (void)flags;
    if (g_ip_output_calls++ == 0) {
        return ERR_OK;
    }
    return ERR_WOULDBLOCK;
}

static err_t succeed_always(struct pbuf *p, struct tcp_seg *seg, void *pcb, u16_t flags)
{
    (void)p;
    (void)seg;
    (void)pcb;
    (void)flags;
    ++g_ip_output_calls;
    return ERR_OK;
}

static void init_pcb_for_output(tcp_pcb &pcb)
{
    register_tcp_seg_free(noop_seg_free);
    register_tcp_tx_pbuf_free(noop_tx_pbuf_free);
    register_tcp_state_observer(noop_state_observer);
    std::memset(&pcb, 0, sizeof(pcb));
    tcp_rto_pcb_seed(&pcb);
    pcb.private_state = ESTABLISHED;
    /* Retransmit tests require a valid congestion-control callback. */
    pcb.cc_algo = &none_cc_algo;
    pcb.rtime = -1;
    pcb.ticks_since_data_sent = -1;
    pcb.mss = 1460;
    pcb.cwnd = 1460;
    pcb.snd_wnd = 1460;
    pcb.snd_wnd_max = 1460;
    pcb.lastack = 1000;
    pcb.snd_nxt = 1000;
    pcb.snd_lbb = 1004;
    pcb.rcv_wnd = 65535;
    pcb.rcv_ann_wnd = 65535;
    pcb.ip_output = fail_with_wouldblock;
    pcb.errf = capture_error;
}

static void init_unsent_segment(test_segment_storage &storage, uint32_t seqno, uint32_t len)
{
    storage.seg = {};
    storage.p = {};
    std::memset(storage.bytes, 0, sizeof(storage.bytes));
    storage.p.payload = storage.bytes;
    storage.p.len = TCP_HLEN + len;
    storage.p.tot_len = TCP_HLEN + len;
    storage.p.type = PBUF_RAM;
    storage.p.ref = 1;

    storage.seg.p = &storage.p;
    storage.seg.len = len;
    storage.seg.seqno = seqno;
    storage.seg.tcphdr = reinterpret_cast<tcp_hdr *>(storage.bytes);
    storage.seg.tcphdr->seqno = htonl(seqno);
    TCPH_HDRLEN_FLAGS_SET(storage.seg.tcphdr, TCP_HLEN / 4, 0);
}

} // namespace

TEST(tcp_output, idle_wouldblock_parks_segment_on_unacked_and_arms_timers)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 4);
    pcb.unsent = &storage.seg;
    pcb.last_unsent = &storage.seg;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    g_ip_output_calls = 0;
    const int64_t before_send_us = clock_gettime_monotonic_us();
    err_t rc = tcp_output(&pcb);
    const int64_t after_send_us = clock_gettime_monotonic_us();

    EXPECT_EQ(ERR_OK, rc);
    EXPECT_EQ(1, g_ip_output_calls);
    EXPECT_EQ(nullptr, pcb.unsent);
    EXPECT_EQ(nullptr, pcb.last_unsent);
    EXPECT_EQ(&storage.seg, pcb.unacked);
    EXPECT_EQ(&storage.seg, pcb.last_unacked);
    EXPECT_EQ(1004U, pcb.snd_nxt);
    EXPECT_TRUE(pcb.is_last_seg_dropped);

    /* The local failure must not produce an RTT sample. Parking the segment
     * on unacked must activate RTO and TCP_USER_TIMEOUT timing. */
    EXPECT_EQ(0, pcb.rttest_us);
    EXPECT_GE(pcb.rto_deadline_us, before_send_us + pcb.rto_us);
    EXPECT_LE(pcb.rto_deadline_us, after_send_us + pcb.rto_us);
    EXPECT_EQ(0, pcb.rtime);
    EXPECT_EQ(0, pcb.ticks_since_data_sent);
}

TEST(tcp_output, idle_non_wouldblock_error_parks_segment_on_unacked_and_arms_timers)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.ip_output = fail_with_mem;

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 4);
    pcb.unsent = &storage.seg;
    pcb.last_unsent = &storage.seg;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    g_ip_output_calls = 0;
    EXPECT_EQ(ERR_MEM, tcp_output(&pcb));

    EXPECT_EQ(1, g_ip_output_calls);
    EXPECT_EQ(nullptr, pcb.unsent);
    EXPECT_EQ(nullptr, pcb.last_unsent);
    EXPECT_EQ(&storage.seg, pcb.unacked);
    EXPECT_EQ(&storage.seg, pcb.last_unacked);
    EXPECT_EQ(1004U, pcb.snd_nxt);
    EXPECT_FALSE(pcb.is_last_seg_dropped);
    EXPECT_NE(0, pcb.rto_deadline_us);
    EXPECT_EQ(0, pcb.rtime);
    EXPECT_EQ(0, pcb.ticks_since_data_sent);
}

TEST(tcp_output, idle_syn_non_wouldblock_error_parks_segment_on_unacked)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.private_state = SYN_SENT;
    pcb.ip_output = fail_with_mem;
    pcb.snd_lbb = pcb.snd_nxt;

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 0);
    storage.seg.tcp_flags = TCP_SYN;
    TCPH_SET_FLAG(storage.seg.tcphdr, TCP_SYN);
    pcb.unsent = &storage.seg;
    pcb.last_unsent = &storage.seg;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    g_ip_output_calls = 0;
    EXPECT_EQ(ERR_MEM, tcp_output(&pcb));

    EXPECT_EQ(1, g_ip_output_calls);
    EXPECT_EQ(nullptr, pcb.unsent);
    EXPECT_EQ(nullptr, pcb.last_unsent);
    EXPECT_EQ(&storage.seg, pcb.unacked);
    EXPECT_EQ(&storage.seg, pcb.last_unacked);
    EXPECT_EQ(1001U, pcb.snd_nxt);
    EXPECT_FALSE(pcb.is_last_seg_dropped);
    EXPECT_EQ(0, pcb.rttest_us);
    EXPECT_NE(0, pcb.rto_deadline_us);
    EXPECT_EQ(0, pcb.rtime);
    EXPECT_EQ(0, pcb.ticks_since_data_sent);
}

TEST(tcp_output, fatal_output_error_does_not_requeue_purged_segment)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.private_state = SYN_RCVD;
    pcb.ip_output = fail_with_reset;
    pcb.errf = purge_on_error;
    pcb.my_container = &pcb;

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 0);
    storage.seg.tcp_flags = TCP_SYN;
    TCPH_SET_FLAG(storage.seg.tcphdr, TCP_SYN);
    pcb.unacked = &storage.seg;
    pcb.last_unacked = &storage.seg;
    pcb.snd_nxt++;
    pcb.snd_lbb = pcb.snd_nxt;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    register_tcp_seg_free(record_seg_free);
    g_ip_output_calls = 0;
    g_error_calls = 0;
    g_last_error = ERR_OK;
    g_seg_free_calls = 0;
    g_freed_seg = nullptr;

    tcp_rexmit_rto(&pcb);

    EXPECT_EQ(1, g_ip_output_calls);
    EXPECT_EQ(1, g_error_calls);
    EXPECT_EQ(ERR_RST, g_last_error);
    EXPECT_EQ(1, g_seg_free_calls);
    EXPECT_EQ(&storage.seg, g_freed_seg);
    EXPECT_EQ(nullptr, pcb.unsent);
    EXPECT_EQ(nullptr, pcb.last_unsent);
    EXPECT_EQ(nullptr, pcb.unacked);
    EXPECT_EQ(nullptr, pcb.last_unacked);

    register_tcp_seg_free(noop_seg_free);
}

TEST(tcp_output, reset_notification_without_purge_retains_rto_ownership)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.ip_output = fail_with_reset;

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 4);
    pcb.unacked = &storage.seg;
    pcb.last_unacked = &storage.seg;
    pcb.snd_nxt += storage.seg.len;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    g_ip_output_calls = 0;
    g_error_calls = 0;
    g_last_error = ERR_OK;

    tcp_rexmit_rto(&pcb);

    ASSERT_EQ(1, g_ip_output_calls);
    ASSERT_EQ(1, g_error_calls);
    ASSERT_EQ(ERR_RST, g_last_error);
    ASSERT_EQ(&storage.seg, pcb.unacked);
    ASSERT_EQ(nullptr, pcb.unsent);
    ASSERT_NE(0, pcb.rto_deadline_us);
    ASSERT_EQ(1, pcb.nrtx);

    const int64_t retry_deadline_us = pcb.rto_deadline_us;
    tcp_slowtmr(&pcb, retry_deadline_us);

    EXPECT_EQ(2, g_ip_output_calls);
    EXPECT_EQ(2, g_error_calls);
    EXPECT_EQ(&storage.seg, pcb.unacked);
    EXPECT_EQ(nullptr, pcb.unsent);
    EXPECT_GT(pcb.rto_deadline_us, retry_deadline_us);
    EXPECT_EQ(2, pcb.nrtx);
}

TEST(tcp_output, idle_zero_length_wouldblock_stays_on_unsent)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.snd_lbb = pcb.snd_nxt;

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 0);
    pcb.unsent = &storage.seg;
    pcb.last_unsent = &storage.seg;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    g_ip_output_calls = 0;
    EXPECT_EQ(ERR_OK, tcp_output(&pcb));

    EXPECT_EQ(1, g_ip_output_calls);
    EXPECT_EQ(&storage.seg, pcb.unsent);
    EXPECT_EQ(&storage.seg, pcb.last_unsent);
    EXPECT_EQ(nullptr, pcb.unacked);
    EXPECT_EQ(nullptr, pcb.last_unacked);
    EXPECT_EQ(1000U, pcb.snd_nxt);
    EXPECT_FALSE(pcb.is_last_seg_dropped);
    EXPECT_EQ(0, pcb.rto_deadline_us);
    EXPECT_EQ(-1, pcb.rtime);
    EXPECT_EQ(-1, pcb.ticks_since_data_sent);
}

/* An elapsed deadline with no flight follows the stalled-unsent retry path. */
TEST(tcp_output, elapsed_deadline_without_unacked_redrives_unsent)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.ip_output = succeed_always;

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 4);
    pcb.unsent = &storage.seg;
    pcb.last_unsent = &storage.seg;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    pcb.rto_deadline_us = 1000;
    pcb.rtime = 0;
    pcb.ticks_since_data_sent = 0;
    pcb.cwnd = 20000;
    pcb.ssthresh = 40000;
    const s32_t rto_before_us = pcb.rto_us;

    g_ip_output_calls = 0;
    tcp_slowtmr(&pcb, 2000);

    EXPECT_EQ(rto_before_us, pcb.rto_us);
    EXPECT_EQ(20000U, pcb.cwnd);
    EXPECT_EQ(40000U, pcb.ssthresh);
    EXPECT_EQ(0, pcb.nrtx);
    EXPECT_EQ(1, g_ip_output_calls);
    EXPECT_EQ(&storage.seg, pcb.unacked);
    EXPECT_EQ(nullptr, pcb.unsent);
}

/* A blocked second send must not clear the first segment's RTT sample. */
TEST(tcp_output, karn_failed_second_send_retains_first_call_sample)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.ip_output = succeed_then_wouldblock;

    test_segment_storage seg1, seg2;
    init_unsent_segment(seg1, pcb.snd_nxt, 4);
    init_unsent_segment(seg2, pcb.snd_nxt + 4, 4);
    seg1.seg.next = &seg2.seg;

    pcb.unsent = &seg1.seg;
    pcb.last_unsent = &seg2.seg;
    pcb.snd_lbb = pcb.snd_nxt + 8;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    g_ip_output_calls = 0;
    err_t rc = tcp_output(&pcb);

    EXPECT_EQ(ERR_OK, rc);
    EXPECT_EQ(2, g_ip_output_calls);

    EXPECT_EQ(&seg2.seg, pcb.unsent);
    EXPECT_EQ(&seg1.seg, pcb.unacked);
    EXPECT_EQ(1004U, pcb.snd_nxt);

    EXPECT_NE(0, pcb.rttest_us) << "Karn invariant broken: seg2's failed-send erased seg1's sample";
    EXPECT_EQ(1000U, pcb.rtseq);

    EXPECT_EQ(&seg1.seg, pcb.last_unacked);
    EXPECT_FALSE(pcb.is_last_seg_dropped)
        << "a later blocked segment stays on unsent and must not set the local-failure marker";

    EXPECT_NE(0, pcb.rto_deadline_us);
}

/* A locally rejected idle flight retries at its RTO deadline. */
TEST(tcp_output, wouldblock_first_send_retries_at_rto_deadline)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 4);
    pcb.unsent = &storage.seg;
    pcb.last_unsent = &storage.seg;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    g_ip_output_calls = 0;
    err_t rc = tcp_output(&pcb);

    EXPECT_EQ(ERR_OK, rc);
    EXPECT_EQ(1, g_ip_output_calls);
    EXPECT_EQ(nullptr, pcb.unsent);
    EXPECT_EQ(&storage.seg, pcb.unacked);
    ASSERT_NE(0, pcb.rto_deadline_us);
    EXPECT_TRUE(pcb.is_last_seg_dropped);
    const int64_t first_deadline = pcb.rto_deadline_us;

    pcb.ip_output = succeed_always;
    g_ip_output_calls = 0;
    tcp_slowtmr(&pcb, first_deadline - 1);
    EXPECT_EQ(0, g_ip_output_calls);

    tcp_slowtmr(&pcb, first_deadline);

    EXPECT_EQ(1, g_ip_output_calls);
    EXPECT_EQ(&storage.seg, pcb.unacked);
    EXPECT_EQ(nullptr, pcb.unsent);
    EXPECT_EQ(1004U, pcb.snd_nxt);
    EXPECT_EQ(1, pcb.nrtx);
    EXPECT_GT(pcb.rto_deadline_us, first_deadline);
    EXPECT_FALSE(pcb.is_last_seg_dropped)
        << "a successful RTO retry must clear the local-failure marker";
}

TEST(tcp_output, rto_wouldblock_retains_backoff_until_retry_succeeds)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.ip_output = succeed_always;

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 4);
    pcb.unsent = &storage.seg;
    pcb.last_unsent = &storage.seg;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    g_ip_output_calls = 0;
    ASSERT_EQ(ERR_OK, tcp_output(&pcb));
    ASSERT_EQ(&storage.seg, pcb.unacked);
    ASSERT_EQ(nullptr, pcb.unsent);
    ASSERT_NE(0, pcb.rto_deadline_us);

    const int64_t first_deadline = pcb.rto_deadline_us;
    const s32_t first_rto = pcb.rto_us;

    pcb.ip_output = fail_with_wouldblock;
    g_ip_output_calls = 0;
    tcp_slowtmr(&pcb, first_deadline + 1);

    ASSERT_EQ(1, g_ip_output_calls);
    EXPECT_EQ(&storage.seg, pcb.unacked);
    EXPECT_EQ(nullptr, pcb.unsent);
    EXPECT_EQ(first_rto << 1, pcb.rto_us);
    EXPECT_EQ(1, pcb.nrtx);
    EXPECT_GT(pcb.rto_deadline_us, first_deadline);
    EXPECT_TRUE(pcb.is_last_seg_dropped);
    EXPECT_EQ(0, pcb.rtime);
    EXPECT_EQ(1, pcb.ticks_since_data_sent)
        << "the RTO retry must not reset TCP_USER_TIMEOUT age";

    /* A successful early retry re-arms from its transmit time. */
    pcb.ip_output = succeed_always;
    g_ip_output_calls = 0;
    const int64_t before_send_us = clock_gettime_monotonic_us();
    ASSERT_EQ(ERR_OK, tcp_output(&pcb));
    const int64_t after_send_us = clock_gettime_monotonic_us();

    ASSERT_EQ(1, g_ip_output_calls);
    EXPECT_EQ(&storage.seg, pcb.unacked);
    EXPECT_EQ(nullptr, pcb.unsent);
    EXPECT_FALSE(pcb.is_last_seg_dropped);
    EXPECT_GE(pcb.rto_deadline_us, before_send_us + pcb.rto_us);
    EXPECT_LE(pcb.rto_deadline_us, after_send_us + pcb.rto_us);
}

TEST(tcp_output, permanent_idle_wouldblock_honors_tcp_user_timeout)
{
    timer_resolution_guard timer_guard(100);
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.user_timeout_ms = 5000;

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 4);
    pcb.unsent = &storage.seg;
    pcb.last_unsent = &storage.seg;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    g_ip_output_calls = 0;
    g_error_calls = 0;
    g_last_error = ERR_OK;
    ASSERT_EQ(ERR_OK, tcp_output(&pcb));
    ASSERT_TRUE(pcb.is_last_seg_dropped);

    const int64_t start_us = pcb.rto_deadline_us - pcb.rto_us;
    const u32_t timeout_ticks = tcp_ms_to_ticks(pcb.user_timeout_ms);
    for (u32_t tick = 1; tick <= timeout_ticks; ++tick) {
        /* A busy application or RX path may offer another output opportunity
         * before every timer pass. Repeated local refusal must not restart
         * TCP_USER_TIMEOUT age. */
        ASSERT_EQ(ERR_OK, tcp_output(&pcb));
        tcp_slowtmr(&pcb, start_us + (int64_t)tick * slow_tmr_interval * 1000);
        ASSERT_EQ(ESTABLISHED, get_tcp_state(&pcb)) << "closed before TCP_USER_TIMEOUT";
    }

    tcp_slowtmr(&pcb,
                start_us + (int64_t)(timeout_ticks + 1) * slow_tmr_interval * 1000);

    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
    EXPECT_EQ(1, g_error_calls);
    EXPECT_EQ(ERR_TIMEOUT, g_last_error);
}

TEST(tcp_output, local_retry_blocked_before_ip_output_retains_tcp_user_timeout)
{
    timer_resolution_guard timer_guard(100);
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.user_timeout_ms = 5000;

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 4);
    pcb.unsent = &storage.seg;
    pcb.last_unsent = &storage.seg;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    g_ip_output_calls = 0;
    g_error_calls = 0;
    g_last_error = ERR_OK;
    ASSERT_EQ(ERR_OK, tcp_output(&pcb));
    ASSERT_TRUE(pcb.is_last_seg_dropped);
    ASSERT_EQ(1, g_ip_output_calls);

    /* Close the peer window before the retry reaches ip_output(). */
    pcb.snd_wnd = 0;
    ASSERT_EQ(ERR_OK, tcp_output(&pcb));
    ASSERT_EQ(1, g_ip_output_calls);
    ASSERT_EQ(&storage.seg, pcb.unsent);
    ASSERT_EQ(nullptr, pcb.unacked);
    ASSERT_EQ(0, pcb.rto_deadline_us);
    ASSERT_EQ(-1, pcb.rtime);
    ASSERT_EQ(0, pcb.ticks_since_data_sent)
        << "consuming retry ownership must retain accepted-data age";

    const u32_t timeout_ticks = tcp_ms_to_ticks(pcb.user_timeout_ms);
    for (u32_t tick = 1; tick <= timeout_ticks; ++tick) {
        tcp_slowtmr(&pcb, (int64_t)tick * slow_tmr_interval * 1000);
        ASSERT_EQ(ESTABLISHED, get_tcp_state(&pcb)) << "closed before TCP_USER_TIMEOUT";
    }

    tcp_slowtmr(&pcb, (int64_t)(timeout_ticks + 1) * slow_tmr_interval * 1000);

    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
    EXPECT_EQ(1, g_ip_output_calls);
    EXPECT_EQ(1, g_error_calls);
    EXPECT_EQ(ERR_TIMEOUT, g_last_error);
}

TEST(tcp_output, permanent_idle_wouldblock_reaches_data_retry_limit)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 4);
    pcb.unsent = &storage.seg;
    pcb.last_unsent = &storage.seg;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    g_ip_output_calls = 0;
    g_error_calls = 0;
    g_last_error = ERR_OK;
    ASSERT_EQ(ERR_OK, tcp_output(&pcb));

    for (u32_t retry = 1; retry <= TCP_MAXRTX; ++retry) {
        ASSERT_NE(0, pcb.rto_deadline_us);
        tcp_slowtmr(&pcb, pcb.rto_deadline_us);
        ASSERT_EQ(ESTABLISHED, get_tcp_state(&pcb));
        ASSERT_EQ(retry, pcb.nrtx);
        ASSERT_TRUE(pcb.is_last_seg_dropped);
    }

    tcp_slowtmr(&pcb, pcb.rto_deadline_us);

    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
    EXPECT_EQ(1, g_error_calls);
    EXPECT_EQ(ERR_ABRT, g_last_error);
    EXPECT_EQ(1U + TCP_MAXRTX, (u32_t)g_ip_output_calls);
}

TEST(tcp_output, permanent_idle_syn_wouldblock_reaches_syn_retry_limit)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.private_state = SYN_SENT;

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 0);
    storage.seg.tcp_flags = TCP_SYN;
    TCPH_SET_FLAG(storage.seg.tcphdr, TCP_SYN);
    pcb.unsent = &storage.seg;
    pcb.last_unsent = &storage.seg;
    pcb.snd_lbb = pcb.snd_nxt + 1;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    g_ip_output_calls = 0;
    g_error_calls = 0;
    g_last_error = ERR_OK;
    ASSERT_EQ(ERR_OK, tcp_output(&pcb));
    ASSERT_TRUE(pcb.is_last_seg_dropped);

    for (u32_t retry = 1; retry <= TCP_SYNMAXRTX; ++retry) {
        ASSERT_NE(0, pcb.rto_deadline_us);
        tcp_slowtmr(&pcb, pcb.rto_deadline_us);
        ASSERT_EQ(SYN_SENT, get_tcp_state(&pcb));
        ASSERT_EQ(retry, pcb.nrtx);
        ASSERT_TRUE(pcb.is_last_seg_dropped);
    }

    tcp_slowtmr(&pcb, pcb.rto_deadline_us);

    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
    EXPECT_EQ(1, g_error_calls);
    EXPECT_EQ(ERR_TIMEOUT, g_last_error);
    EXPECT_EQ(1U + TCP_SYNMAXRTX, (u32_t)g_ip_output_calls);
}

TEST(tcp_output, permanent_idle_syn_non_wouldblock_error_reaches_syn_retry_limit)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.private_state = SYN_SENT;
    pcb.ip_output = fail_with_mem;

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 0);
    storage.seg.tcp_flags = TCP_SYN;
    TCPH_SET_FLAG(storage.seg.tcphdr, TCP_SYN);
    pcb.unsent = &storage.seg;
    pcb.last_unsent = &storage.seg;
    pcb.snd_lbb = pcb.snd_nxt + 1;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    g_ip_output_calls = 0;
    g_error_calls = 0;
    g_last_error = ERR_OK;
    ASSERT_EQ(ERR_MEM, tcp_output(&pcb));
    ASSERT_FALSE(pcb.is_last_seg_dropped);

    for (u32_t retry = 1; retry <= TCP_SYNMAXRTX; ++retry) {
        ASSERT_NE(0, pcb.rto_deadline_us);
        tcp_slowtmr(&pcb, pcb.rto_deadline_us);
        ASSERT_EQ(SYN_SENT, get_tcp_state(&pcb));
        ASSERT_EQ(retry, pcb.nrtx);
        ASSERT_FALSE(pcb.is_last_seg_dropped);
    }

    tcp_slowtmr(&pcb, pcb.rto_deadline_us);

    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
    EXPECT_EQ(1, g_error_calls);
    EXPECT_EQ(ERR_TIMEOUT, g_last_error);
    EXPECT_EQ(1U + TCP_SYNMAXRTX, (u32_t)g_ip_output_calls);
}

namespace {

/* Build a FIN-only segment that consumes one sequence number. */
static void make_fin_only_segment(test_segment_storage &storage, tcp_pcb &pcb)
{
    init_unsent_segment(storage, pcb.snd_nxt, 0);
    storage.seg.tcp_flags = TCP_FIN;
    TCPH_SET_FLAG(storage.seg.tcphdr, TCP_FIN);
    pcb.flags |= TF_FIN;
    pcb.unsent = &storage.seg;
    pcb.last_unsent = &storage.seg;
}

} // namespace

/* FIN-only traffic arms RTO without starting an RTT sample. */
TEST(tcp_output, fin_only_from_idle_arms_deadline_and_retransmits)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.ip_output = succeed_always;

    test_segment_storage storage;
    make_fin_only_segment(storage, pcb);

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    g_ip_output_calls = 0;
    err_t rc = tcp_output(&pcb);

    EXPECT_EQ(ERR_OK, rc);
    EXPECT_EQ(1, g_ip_output_calls);
    EXPECT_EQ(&storage.seg, pcb.unacked);
    EXPECT_EQ(nullptr, pcb.unsent);
    EXPECT_EQ(1001U, pcb.snd_nxt);
    EXPECT_EQ(0, pcb.rttest_us);
    EXPECT_NE(0, pcb.rto_deadline_us);
    EXPECT_EQ(0, pcb.nrtx);
    const int64_t deadline0 = pcb.rto_deadline_us;

    g_ip_output_calls = 0;
    tcp_slowtmr(&pcb, deadline0 + 1);

    EXPECT_EQ(1, pcb.nrtx) << "FIN-from-idle RTO deadline did not fire a retransmit";
    EXPECT_EQ(1, g_ip_output_calls) << "retransmit did not re-send the FIN";
    EXPECT_EQ(&storage.seg, pcb.unacked) << "FIN not re-queued on unacked after retransmit";
    EXPECT_EQ(nullptr, pcb.unsent);
    EXPECT_NE(0, pcb.rto_deadline_us);
    EXPECT_GT(pcb.rto_deadline_us, deadline0) << "deadline not re-armed with backoff";
}

TEST(tcp_output, rto_success_rearms_from_timer_pass_time)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.ip_output = succeed_always;

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 4);
    pcb.unacked = &storage.seg;
    pcb.last_unacked = &storage.seg;
    pcb.snd_nxt += storage.seg.len;
    pcb.rtime = 7;
    pcb.ticks_since_data_sent = 7;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    const int64_t timer_now_us = 1000000;
    pcb.rto_deadline_us = timer_now_us;

    g_ip_output_calls = 0;
    tcp_slowtmr(&pcb, timer_now_us);

    ASSERT_EQ(1, g_ip_output_calls);
    ASSERT_EQ(&storage.seg, pcb.unacked);
    ASSERT_EQ(nullptr, pcb.unsent);
    ASSERT_EQ(2000000, pcb.rto_us);
    EXPECT_EQ(timer_now_us + pcb.rto_us, pcb.rto_deadline_us);
    EXPECT_EQ(0, pcb.rtime);
    EXPECT_GT(pcb.ticks_since_data_sent, 7);
}

TEST(tcp_output, rto_wouldblock_rearms_from_timer_pass_time)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 4);
    pcb.unacked = &storage.seg;
    pcb.last_unacked = &storage.seg;
    pcb.snd_nxt += storage.seg.len;
    pcb.rtime = 7;
    pcb.ticks_since_data_sent = 7;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    const int64_t timer_now_us = 1000000;
    pcb.rto_deadline_us = timer_now_us;

    g_ip_output_calls = 0;
    tcp_slowtmr(&pcb, timer_now_us);

    ASSERT_EQ(1, g_ip_output_calls);
    ASSERT_EQ(&storage.seg, pcb.unacked);
    ASSERT_EQ(nullptr, pcb.unsent);
    ASSERT_EQ(2000000, pcb.rto_us);
    EXPECT_TRUE(pcb.is_last_seg_dropped);
    EXPECT_EQ(timer_now_us + pcb.rto_us, pcb.rto_deadline_us);
    EXPECT_EQ(0, pcb.rtime);
    EXPECT_GT(pcb.ticks_since_data_sent, 7);
}

TEST(tcp_output, fast_retransmit_counter_saturates)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);

    test_segment_storage storage;
    init_unsent_segment(storage, 1000, 4);
    pcb.unacked = &storage.seg;
    pcb.last_unacked = &storage.seg;
    pcb.snd_nxt = 1004;
    pcb.nrtx = 0xFF;

    tcp_rexmit(&pcb);

    EXPECT_EQ(0xFF, pcb.nrtx) << "the retry counter must not wrap to zero";
    EXPECT_EQ(&storage.seg, pcb.unsent);
}

TEST(tcp_output, rto_retransmit_counter_saturates)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.ip_output = succeed_always;

    test_segment_storage storage;
    init_unsent_segment(storage, 1000, 4);
    pcb.unacked = &storage.seg;
    pcb.last_unacked = &storage.seg;
    pcb.snd_nxt = 1004;
    pcb.nrtx = 0xFF;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    tcp_rexmit_rto(&pcb);

    EXPECT_EQ(0xFF, pcb.nrtx) << "the retry counter must not wrap to zero";
    EXPECT_EQ(&storage.seg, pcb.unacked);
}

namespace {

/* Control segments (keepalive and persist probes, RST) that tcp_slowtmr() sends. */
static int g_probe_calls;
static int g_rst_calls;
static pbuf g_ctrl_pbuf;
static unsigned char g_ctrl_bytes[128];

static struct pbuf *ctrl_tx_pbuf_alloc(void *p_conn, pbuf_type type, pbuf_desc *desc,
                                       struct pbuf *p_buff)
{
    (void)p_conn;
    (void)type;
    (void)desc;
    (void)p_buff;
    g_ctrl_pbuf = {};
    std::memset(g_ctrl_bytes, 0, sizeof(g_ctrl_bytes));
    /* The caller prepends the TCP header with pbuf_header(), so leave headroom. */
    g_ctrl_pbuf.payload = g_ctrl_bytes + 64;
    return &g_ctrl_pbuf;
}

static err_t record_ctrl_output(struct pbuf *p, struct tcp_seg *seg, void *pcb, u16_t flags)
{
    (void)seg;
    (void)pcb;
    (void)flags;
    ++g_ip_output_calls;
    const tcp_hdr *hdr = static_cast<const tcp_hdr *>(p->payload);
    if (TCPH_FLAGS(hdr) & TCP_RST) {
        ++g_rst_calls;
    } else {
        ++g_probe_calls;
    }
    return ERR_OK;
}

/* Gives each test its own tcp_ticks clock and control-segment allocator. */
struct slowtmr_test_guard {
    slowtmr_test_guard()
        : saved_ticks(tcp_ticks)
        , saved_alloc(external_tcp_tx_pbuf_alloc)
    {
        register_tcp_tx_pbuf_alloc(ctrl_tx_pbuf_alloc);
        g_probe_calls = 0;
        g_rst_calls = 0;
        g_ip_output_calls = 0;
        g_error_calls = 0;
        g_last_error = ERR_OK;
    }

    ~slowtmr_test_guard()
    {
        tcp_ticks = saved_ticks;
        register_tcp_tx_pbuf_alloc(saved_alloc);
    }

    u32_t saved_ticks;
    tcp_tx_pbuf_alloc_fn saved_alloc;
};

/* Peer advertised a zero window; nothing is in flight. */
static void init_zero_window_pcb(tcp_pcb &pcb, enum tcp_state state)
{
    init_pcb_for_output(pcb);
    pcb.private_state = state;
    pcb.ip_output = record_ctrl_output;
    pcb.snd_wnd = 0;
    pcb.tmr = tcp_ticks;
    pcb.last_keepalive_tmr = tcp_ticks;
    pcb.keepalive_rx_tmr = tcp_ticks;
}

/* One slow-timer pass: tcp_ticks advances once per pass, as in xlio_lwip. */
static void slowtmr_tick(tcp_pcb &pcb)
{
    ++tcp_ticks;
    tcp_slowtmr(&pcb, (int64_t)tcp_ticks * slow_tmr_interval * 1000);
}

/* Data waits on unsent for a zero window and the peer is silent. Returns the
 * slow-timer pass that aborts the connection, or 0 if no pass aborts it. */
static u32_t keepalive_abort_tick_with_unsent_data(bool persist_armed)
{
    tcp_pcb pcb;
    init_zero_window_pcb(pcb, ESTABLISHED);
    pcb.so_options |= SOF_KEEPALIVE;
    pcb.keep_idle = 1000;
    pcb.keep_intvl = 400;
    pcb.keep_cnt = 3;
    pcb.persist_backoff = persist_armed ? 1 : 0;
    /* Last receive is older than keep_idle. */
    pcb.keepalive_rx_tmr = tcp_ticks - tcp_ms_to_ticks(pcb.keep_idle) - 1;

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 4);
    pcb.unsent = &storage.seg;
    pcb.last_unsent = &storage.seg;
    EXPECT_EQ(nullptr, pcb.unacked);
    EXPECT_EQ(-1, (int)pcb.rtime);

    u32_t tick = 0;
    while (g_error_calls == 0 && tick < 100) {
        slowtmr_tick(pcb);
        ++tick;
    }

    EXPECT_EQ(1, g_error_calls) << "no abort after " << tick << " slow-timer passes";
    EXPECT_EQ(ERR_TIMEOUT, g_last_error);
    EXPECT_EQ(1, g_rst_calls);
    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
    return g_error_calls != 0 ? tick : 0;
}

} // namespace

/* A zero window in the SYN-ACK leaves data on unsent with neither the RTO nor
 * the persist timer armed. Keepalive must still probe and abort a dead peer. */
TEST(tcp_slowtmr, keepalive_aborts_dead_peer_with_unsent_data_outside_persist)
{
    timer_resolution_guard timer_guard(100);
    slowtmr_test_guard test_guard;

    EXPECT_NE(0U, keepalive_abort_tick_with_unsent_data(false));
    EXPECT_EQ(3, g_probe_calls) << "keep_cnt keepalive probes sent";
}

/* The persist timer does not stop keepalive: the keepalive probes and abort run
 * on the same schedule as without persist, and persist probes go out as well. */
TEST(tcp_slowtmr, keepalive_aborts_dead_peer_with_persist_armed)
{
    timer_resolution_guard timer_guard(100);
    u32_t abort_tick_without_persist = 0;
    {
        slowtmr_test_guard test_guard;
        abort_tick_without_persist = keepalive_abort_tick_with_unsent_data(false);
    }
    ASSERT_NE(0U, abort_tick_without_persist);

    slowtmr_test_guard test_guard;
    EXPECT_EQ(abort_tick_without_persist, keepalive_abort_tick_with_unsent_data(true));
    EXPECT_GT(g_probe_calls, 3) << "persist probes and keep_cnt keepalive probes sent";
}

/* Fresh data on unacked and a last receive older than user_timeout, with a
 * keepalive probe still out: keepalive must not abort the connection. The user
 * timeout runs from the send. The RTO deadline is far ahead, so no
 * retransmission occurs in this test. */
TEST(tcp_slowtmr, keepalive_skips_connection_with_unacked_data)
{
    timer_resolution_guard timer_guard(100);
    slowtmr_test_guard test_guard;
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.ip_output = record_ctrl_output;
    pcb.so_options |= SOF_KEEPALIVE;
    pcb.keep_idle = 1000;
    pcb.keep_intvl = 1000;
    pcb.keep_cnt = 3;
    pcb.user_timeout_ms = 5000;
    const u32_t timeout_ticks = tcp_ms_to_ticks(pcb.user_timeout_ms);
    pcb.keepalive_rx_tmr = tcp_ticks - 2 * timeout_ticks;
    pcb.last_keepalive_tmr = tcp_ticks - 2 * timeout_ticks;
    pcb.keep_cnt_sent = 1;

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 4);
    pcb.unacked = &storage.seg;
    pcb.last_unacked = &storage.seg;
    pcb.snd_nxt += 4;
    pcb.ticks_since_data_sent = 0;
    pcb.rtime = 0;
    pcb.rto_deadline_us = INT64_MAX;

    u32_t abort_tick = 0;
    for (u32_t tick = 1; tick <= 2 * timeout_ticks && abort_tick == 0; ++tick) {
        slowtmr_tick(pcb);
        if (g_error_calls > 0) {
            abort_tick = tick;
        }
    }

    EXPECT_EQ(timeout_ticks + 1, abort_tick) << "user timeout must run from the send";
    EXPECT_EQ(0, g_probe_calls) << "no keepalive probe while data is on unacked";
    EXPECT_EQ(ERR_TIMEOUT, g_last_error);
    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
}

/* An idle connection with a user timeout shorter than keep_idle + keep_intvl. The
 * first probe goes out one tick after keep_idle. The abort waits a full keep_intvl
 * after that probe, past the user timeout. */
TEST(tcp_slowtmr, keepalive_user_timeout_waits_keep_intvl_after_probe)
{
    timer_resolution_guard timer_guard(100);
    slowtmr_test_guard test_guard;
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.ip_output = record_ctrl_output;
    pcb.so_options |= SOF_KEEPALIVE;
    pcb.keep_idle = 2000;
    pcb.keep_intvl = 5000;
    pcb.keep_cnt = 9;
    pcb.user_timeout_ms = 3000;
    pcb.keepalive_rx_tmr = tcp_ticks;
    pcb.last_keepalive_tmr = tcp_ticks;

    const u32_t idle_ticks = tcp_ms_to_ticks(pcb.keep_idle);
    const u32_t intvl_ticks = tcp_ms_to_ticks(pcb.keep_intvl);
    const u32_t timeout_ticks = tcp_ms_to_ticks(pcb.user_timeout_ms);
    ASSERT_GT(timeout_ticks, idle_ticks + 1);
    ASSERT_LT(timeout_ticks, idle_ticks + 1 + intvl_ticks);

    u32_t probe_tick = 0;
    u32_t abort_tick = 0;
    for (u32_t tick = 1; tick <= 2 * (idle_ticks + intvl_ticks) && abort_tick == 0; ++tick) {
        slowtmr_tick(pcb);
        if (probe_tick == 0 && g_probe_calls > 0) {
            probe_tick = tick;
        }
        if (g_error_calls > 0) {
            abort_tick = tick;
        }
    }

    EXPECT_EQ(idle_ticks + 1, probe_tick) << "first probe one tick after keep_idle";
    EXPECT_EQ(probe_tick + intvl_ticks, abort_tick) << "abort one keep_intvl after the probe";
    EXPECT_EQ(1, g_probe_calls);
    EXPECT_EQ(1, g_rst_calls);
    EXPECT_EQ(ERR_TIMEOUT, g_last_error);
    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
}

namespace {

static struct tcp_seg *no_seg_alloc(void *p_conn)
{
    (void)p_conn;
    return nullptr;
}

static u16_t no_route_mtu(struct tcp_pcb *pcb)
{
    (void)pcb;
    return 0;
}

/* tcp_output() prefetches a spare segment, and the SYN-ACK input path reads the route
 * MTU. The tests need no spare segment and no route. */
struct output_hooks_guard {
    output_hooks_guard()
        : saved_seg_alloc(external_tcp_seg_alloc)
        , saved_route_mtu(external_ip_route_mtu)
    {
        register_tcp_seg_alloc(no_seg_alloc);
        register_ip_route_mtu(no_route_mtu);
    }

    ~output_hooks_guard()
    {
        register_tcp_seg_alloc(saved_seg_alloc);
        register_ip_route_mtu(saved_route_mtu);
    }

    tcp_seg_alloc_fn saved_seg_alloc;
    ip_route_mtu_fn saved_route_mtu;
};

} // namespace

/* tcp_rexmit_rto() moved the sent segment back to unsent, and a zero window keeps it
 * there. unacked is empty and the RTO timer runs. The last receive is older than
 * user_timeout and a keepalive probe is out. Keepalive must not probe or abort. The
 * user timeout aborts the connection one tick after it expires, measured from the
 * send. */
TEST(tcp_slowtmr, keepalive_skips_parked_rto_retransmission)
{
    timer_resolution_guard timer_guard(100);
    slowtmr_test_guard test_guard;
    output_hooks_guard hooks_guard;
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.ip_output = record_ctrl_output;
    pcb.snd_wnd = 0;
    pcb.so_options |= SOF_KEEPALIVE;
    pcb.keep_idle = 1000;
    pcb.keep_intvl = 1000;
    pcb.keep_cnt = 3;
    pcb.user_timeout_ms = 5000;
    const u32_t timeout_ticks = tcp_ms_to_ticks(pcb.user_timeout_ms);
    pcb.keepalive_rx_tmr = tcp_ticks - 2 * timeout_ticks;
    pcb.last_keepalive_tmr = tcp_ticks - 2 * timeout_ticks;
    pcb.keep_cnt_sent = 1;

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 4);
    pcb.unsent = &storage.seg;
    pcb.last_unsent = &storage.seg;
    pcb.snd_nxt += 4;
    pcb.nrtx = 1;
    pcb.ticks_since_data_sent = 0;
    pcb.rtime = 0;
    pcb.rto_deadline_us = 0;

    u32_t abort_tick = 0;
    for (u32_t tick = 1; tick <= 2 * timeout_ticks && abort_tick == 0; ++tick) {
        slowtmr_tick(pcb);
        if (g_error_calls > 0) {
            abort_tick = tick;
        } else {
            ASSERT_EQ(nullptr, pcb.unacked) << "tick " << tick;
            ASSERT_EQ(&storage.seg, pcb.unsent) << "tick " << tick;
            ASSERT_TRUE(tcp_rexmit_timer_running(&pcb)) << "tick " << tick;
        }
    }

    EXPECT_EQ(timeout_ticks + 1, abort_tick) << "user timeout must run from the send";
    EXPECT_EQ(0, g_probe_calls) << "no keepalive probe for a parked retransmission";
    EXPECT_EQ(1, g_rst_calls);
    EXPECT_EQ(ERR_TIMEOUT, g_last_error);
    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
}

/* Without TCP_USER_TIMEOUT, data on unacked does not stop keepalive. Probe k goes out
 * once the idle time exceeds keep_idle + k * keep_intvl. The abort follows when the
 * idle time exceeds keep_idle + keep_cnt * keep_intvl. The RTO deadline is far
 * ahead, so no retransmission occurs in this test. */
TEST(tcp_slowtmr, keepalive_aborts_unacked_data_without_user_timeout)
{
    timer_resolution_guard timer_guard(100);
    slowtmr_test_guard test_guard;
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.ip_output = record_ctrl_output;
    pcb.so_options |= SOF_KEEPALIVE;
    pcb.keep_idle = 2000;
    pcb.keep_intvl = TCP_KEEPINTVL_DEFAULT;
    pcb.keep_cnt = TCP_KEEPCNT_DEFAULT;
    pcb.keepalive_rx_tmr = tcp_ticks;
    pcb.last_keepalive_tmr = tcp_ticks;

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 4);
    pcb.unacked = &storage.seg;
    pcb.last_unacked = &storage.seg;
    pcb.snd_nxt += 4;
    pcb.ticks_since_data_sent = 0;
    pcb.rtime = 0;
    pcb.rto_deadline_us = INT64_MAX;

    const u32_t keep_idle = pcb.keep_idle;
    const u32_t keep_intvl = pcb.keep_intvl;
    const u32_t keep_cnt = pcb.keep_cnt;
    const u32_t expected_abort_tick = tcp_ms_to_ticks(keep_idle + keep_cnt * keep_intvl) + 1;
    u32_t abort_tick = 0;
    u32_t probes = 0;
    for (u32_t tick = 1; tick <= 2 * expected_abort_tick && abort_tick == 0; ++tick) {
        slowtmr_tick(pcb);
        if (g_error_calls > 0) {
            abort_tick = tick;
        } else if ((u32_t)g_probe_calls != probes) {
            ASSERT_EQ(probes + 1, (u32_t)g_probe_calls) << "more than one probe at tick " << tick;
            EXPECT_EQ(tcp_ms_to_ticks(keep_idle + probes * keep_intvl) + 1, tick)
                << "probe " << probes;
            ++probes;
        }
    }

    EXPECT_EQ(keep_cnt, probes);
    EXPECT_EQ(expected_abort_tick, abort_tick);
    EXPECT_EQ(1, g_rst_calls);
    EXPECT_EQ(ERR_TIMEOUT, g_last_error);
    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
}

/* tcp_user_timeout_occured() does not run in CLOSE_WAIT. With data on unacked,
 * keepalive still probes a dead peer and aborts the connection at the last receive
 * plus user_timeout. keep_intvl is one tick, so the probe interval does not delay the
 * abort. The RTO deadline is far ahead, so no retransmission occurs in this test. */
TEST(tcp_slowtmr, keepalive_aborts_close_wait_with_unacked_data)
{
    timer_resolution_guard timer_guard(100);
    slowtmr_test_guard test_guard;
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.private_state = CLOSE_WAIT;
    pcb.ip_output = record_ctrl_output;
    pcb.so_options |= SOF_KEEPALIVE;
    pcb.keep_idle = 1000;
    pcb.keep_intvl = slow_tmr_interval;
    pcb.keep_cnt = 100;
    pcb.user_timeout_ms = 5000;
    pcb.keepalive_rx_tmr = tcp_ticks;
    pcb.last_keepalive_tmr = tcp_ticks;

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 4);
    pcb.unacked = &storage.seg;
    pcb.last_unacked = &storage.seg;
    pcb.snd_nxt += 4;
    pcb.ticks_since_data_sent = 0;
    pcb.rtime = 0;
    pcb.rto_deadline_us = INT64_MAX;

    const u32_t timeout_ticks = tcp_ms_to_ticks(pcb.user_timeout_ms);
    u32_t abort_tick = 0;
    for (u32_t tick = 1; tick <= 2 * timeout_ticks && abort_tick == 0; ++tick) {
        slowtmr_tick(pcb);
        if (g_error_calls > 0) {
            abort_tick = tick;
        }
    }

    EXPECT_EQ(timeout_ticks, abort_tick) << "abort at the last receive plus user_timeout";
    EXPECT_GT(g_probe_calls, 0);
    EXPECT_EQ(1, g_rst_calls);
    EXPECT_EQ(ERR_TIMEOUT, g_last_error);
    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
}

namespace {

/* One IPv4 header (20 B, no options) and one TCP header (no options). */
struct test_rx_packet {
    pbuf p {};
    unsigned char bytes[20 + TCP_HLEN] {};
};

/* Feed one segment without payload to pcb through L3_level_tcp_input(), with a
 * refreshed RX-batch timestamp. ref=2 keeps the test-owned pbuf alive after the input
 * path frees it. */
static void inject_segment(tcp_pcb &pcb, u32_t seqno, u32_t ackno, u8_t flags, u16_t wnd = 65535)
{
    test_rx_packet pkt;
    unsigned char *b = pkt.bytes;
    b[0] = 0x45; /* IPv4, IHL 5 */
    b[3] = sizeof(pkt.bytes); /* IPv4 total length */
    tcp_hdr *th = reinterpret_cast<tcp_hdr *>(&b[20]);
    th->seqno = htonl(seqno);
    th->ackno = htonl(ackno);
    TCPH_HDRLEN_FLAGS_SET(th, TCP_HLEN / 4, flags);
    th->wnd = htons(wnd);

    pkt.p.payload = pkt.bytes;
    pkt.p.len = sizeof(pkt.bytes);
    pkt.p.tot_len = sizeof(pkt.bytes);
    pkt.p.type = PBUF_RAM;
    pkt.p.ref = 2;
    xlio_now_us_batch batch;
    batch.refresh();
    L3_level_tcp_input(&pkt.p, &pcb);
}

static err_t accept_ok(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    (void)arg;
    (void)newpcb;
    (void)err;
    return ERR_OK;
}

/* Keepalive with TCP_USER_TIMEOUT. The idle time starts now. */
static void set_keepalive_with_user_timeout(tcp_pcb &pcb)
{
    pcb.ip_output = record_ctrl_output;
    pcb.so_options |= SOF_KEEPALIVE;
    pcb.keep_idle = 2000;
    pcb.keep_intvl = 5000;
    pcb.keep_cnt = 9;
    pcb.user_timeout_ms = 8000;
    pcb.tmr = tcp_ticks;
    pcb.last_keepalive_tmr = tcp_ticks;
    pcb.keepalive_rx_tmr = tcp_ticks;
}

/* A keepalive pcb that accepts segments from L3_level_tcp_input(). */
static void init_keepalive_input_pcb(tcp_pcb &pcb, enum tcp_state state)
{
    init_pcb_for_output(pcb);
    pcb.private_state = state;
    pcb.snd_lbb = pcb.snd_nxt;
    pcb.snd_wl2 = pcb.snd_nxt;
    pcb.rcv_nxt = 5000;
    pcb.snd_wl1 = pcb.rcv_nxt - 1;
    pcb.rcv_wnd_max = pcb.rcv_wnd;
    pcb.rcv_ann_right_edge = pcb.rcv_nxt + pcb.rcv_wnd;
    set_keepalive_with_user_timeout(pcb);
}

/* Queue one segment on unsent and send it with tcp_output(). tcp_output() starts
 * the RTO timer, as for a SYN from tcp_connect(), a SYN-ACK from tcp_listen_input()
 * or data from tcp_write(). */
static void send_segment(tcp_pcb &pcb, test_segment_storage &storage, u32_t len, u8_t flags)
{
    init_unsent_segment(storage, pcb.snd_nxt, len);
    storage.seg.tcp_flags = flags;
    TCPH_SET_FLAG(storage.seg.tcphdr, flags);
    pcb.unsent = &storage.seg;
    pcb.last_unsent = &storage.seg;
    pcb.snd_lbb = pcb.snd_nxt + TCP_SEGLEN(&storage.seg);
    ASSERT_EQ(ERR_OK, tcp_output(&pcb));
    ASSERT_EQ(&storage.seg, pcb.unacked);
    ASSERT_EQ(nullptr, pcb.unsent);
    ASSERT_TRUE(tcp_rexmit_timer_running(&pcb));
}

/* Nothing waits for an ACK and the RTO timer is stopped (rtime == -1). Keepalive
 * sends its first probe one tick after keep_idle. keep_cnt_sent counts keepalive
 * probes only, not persist probes. */
static void expect_keepalive_probe_after_keep_idle(tcp_pcb &pcb)
{
    ASSERT_EQ(ESTABLISHED, get_tcp_state(&pcb));
    EXPECT_EQ(nullptr, pcb.unacked);
    EXPECT_EQ(nullptr, pcb.unsent);
    EXPECT_EQ(-1, (int)pcb.rtime);
    const u32_t idle_ticks = tcp_ms_to_ticks(pcb.keep_idle);
    for (u32_t tick = 1; tick <= idle_ticks; ++tick) {
        slowtmr_tick(pcb);
    }
    EXPECT_EQ(0, (int)pcb.keep_cnt_sent) << "no keepalive probe before keep_idle";
    slowtmr_tick(pcb);
    EXPECT_EQ(1, (int)pcb.keep_cnt_sent) << "keepalive probe one tick after keep_idle";
    EXPECT_EQ(0, g_error_calls);
}

} // namespace

/* The SYN-ACK acknowledges the SYN, the only segment on unacked. The handshake stops
 * the RTO timer, so keepalive runs on the idle connection. */
TEST(tcp_slowtmr, keepalive_probes_after_active_handshake)
{
    timer_resolution_guard timer_guard(100);
    slowtmr_test_guard test_guard;
    output_hooks_guard hooks_guard;
    tcp_pcb pcb;
    init_keepalive_input_pcb(pcb, SYN_SENT);

    test_segment_storage syn;
    ASSERT_NO_FATAL_FAILURE(send_segment(pcb, syn, 0, TCP_SYN));
    inject_segment(pcb, pcb.rcv_nxt - 1, pcb.snd_nxt, TCP_SYN | TCP_ACK);

    expect_keepalive_probe_after_keep_idle(pcb);
}

/* sockinfo_tcp::accept_clone() creates the child pcb with tcp_pcb_init(), and
 * tcp_listen_input() sends the SYN-ACK. The final ACK of the handshake stops the RTO
 * timer, so keepalive runs on the idle connection. */
TEST(tcp_slowtmr, keepalive_probes_after_passive_handshake)
{
    timer_resolution_guard timer_guard(100);
    slowtmr_test_guard test_guard;
    output_hooks_guard hooks_guard;
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    tcp_pcb_init(&pcb, TCP_PRIO_NORMAL, nullptr);
    EXPECT_FALSE(tcp_rexmit_timer_running(&pcb));

    set_tcp_state(&pcb, SYN_RCVD);
    pcb.rcv_nxt = 5000;
    pcb.rcv_ann_right_edge = pcb.rcv_nxt;
    pcb.snd_wl1 = pcb.rcv_nxt - 1;
    pcb.accept = accept_ok;
    pcb.errf = capture_error;
    pcb.snd_wnd = 65535;
    pcb.snd_wnd_max = pcb.snd_wnd;
    pcb.ssthresh = pcb.snd_wnd;
    set_keepalive_with_user_timeout(pcb);

    test_segment_storage syn_ack;
    ASSERT_NO_FATAL_FAILURE(send_segment(pcb, syn_ack, 0, TCP_SYN | TCP_ACK));
    inject_segment(pcb, pcb.rcv_nxt, pcb.snd_nxt, TCP_ACK);

    expect_keepalive_probe_after_keep_idle(pcb);
}

/* An ACK for all data on unacked stops the RTO timer, so keepalive runs on the idle
 * connection. */
TEST(tcp_slowtmr, keepalive_probes_after_all_data_acked)
{
    timer_resolution_guard timer_guard(100);
    slowtmr_test_guard test_guard;
    output_hooks_guard hooks_guard;
    tcp_pcb pcb;
    init_keepalive_input_pcb(pcb, ESTABLISHED);

    test_segment_storage data;
    ASSERT_NO_FATAL_FAILURE(send_segment(pcb, data, 4, 0));
    inject_segment(pcb, pcb.rcv_nxt, pcb.snd_nxt, TCP_ACK);
    EXPECT_EQ(0, pcb.persist_backoff);

    expect_keepalive_probe_after_keep_idle(pcb);
}

/* An ACK for all data with a zero window arms the persist timer and stops the RTO
 * timer, so keepalive runs next to the persist probes. */
TEST(tcp_slowtmr, keepalive_probes_after_zero_window_ack_arms_persist)
{
    timer_resolution_guard timer_guard(100);
    slowtmr_test_guard test_guard;
    output_hooks_guard hooks_guard;
    tcp_pcb pcb;
    init_keepalive_input_pcb(pcb, ESTABLISHED);

    test_segment_storage data;
    ASSERT_NO_FATAL_FAILURE(send_segment(pcb, data, 4, 0));
    inject_segment(pcb, pcb.rcv_nxt, pcb.snd_nxt, TCP_ACK, 0);
    EXPECT_EQ(1, pcb.persist_backoff);

    expect_keepalive_probe_after_keep_idle(pcb);
}

namespace {

/* sockinfo_tcp::handle_fin() shuts down the receive side on a FIN. */
static err_t shutdown_rx_on_fin(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    (void)arg;
    (void)err;
    if (p == NULL) {
        tcp_shutdown(tpcb, 1, 0);
    }
    return ERR_OK;
}

} // namespace

/* A received FIN sets TF_RXCLOSED and pcb->tmr stops. Keepalive must still
 * measure idle time from the last received segment. The peer answers every
 * second probe only. Each reply must restart keep_idle, and no abort occurs. */
TEST(tcp_slowtmr, keepalive_in_close_wait_restarts_idle_time_on_reply)
{
    timer_resolution_guard timer_guard(100);
    slowtmr_test_guard test_guard;
    output_hooks_guard hooks_guard;
    tcp_pcb pcb;
    init_keepalive_input_pcb(pcb, ESTABLISHED);
    pcb.recv = shutdown_rx_on_fin;

    inject_segment(pcb, pcb.rcv_nxt, pcb.snd_nxt, TCP_FIN | TCP_ACK);
    ASSERT_EQ(CLOSE_WAIT, get_tcp_state(&pcb));
    ASSERT_NE(0, pcb.flags & TF_RXCLOSED);
    g_probe_calls = 0;

    const u32_t idle_ticks = tcp_ms_to_ticks(pcb.keep_idle);
    const u32_t intvl_ticks = tcp_ms_to_ticks(pcb.keep_intvl);
    const u32_t total_ticks = tcp_ms_to_ticks(40000);
    u32_t last_event_tick = 0; /* The FIN, then each probe. */
    bool last_probe_answered = true; /* The FIN counts as a received segment. */
    int probes = 0;
    for (u32_t tick = 1; tick <= total_ticks; ++tick) {
        slowtmr_tick(pcb);
        ASSERT_EQ(0, g_error_calls) << "aborted at tick " << tick << " after " << probes
                                    << " probes with err " << (int)g_last_error;
        if (g_probe_calls == probes) {
            continue;
        }
        ASSERT_EQ(probes + 1, g_probe_calls) << "more than one probe at tick " << tick;
        ++probes;
        const u32_t gap = tick - last_event_tick;
        const u32_t expected_gap = last_probe_answered ? idle_ticks : intvl_ticks;
        EXPECT_GE(gap, expected_gap) << "probe " << probes << " at tick " << tick;
        EXPECT_LE(gap, expected_gap + 1) << "probe " << probes << " at tick " << tick;
        last_event_tick = tick;
        last_probe_answered = (probes % 2) == 0;
        if (last_probe_answered) {
            inject_segment(pcb, pcb.rcv_nxt, pcb.snd_nxt, TCP_ACK);
        }
    }

    EXPECT_EQ(CLOSE_WAIT, get_tcp_state(&pcb));
    EXPECT_EQ(0, g_rst_calls);
    EXPECT_GE(probes, (int)(2 * (total_ticks / (idle_ticks + 1 + intvl_ticks))));
}

namespace {

/* ESTABLISHED pcb with one data segment in flight and an elapsed RTO deadline,
 * at the TCP_MAXRTX retransmission count. */
static void init_pcb_at_max_data_retries(tcp_pcb &pcb, test_segment_storage &storage)
{
    init_pcb_for_output(pcb);
    pcb.ip_output = succeed_always;
    init_unsent_segment(storage, pcb.snd_nxt, 4);
    pcb.unacked = &storage.seg;
    pcb.last_unacked = &storage.seg;
    pcb.snd_nxt += 4;
    pcb.ticks_since_data_sent = 0;
    pcb.rtime = 0;
    pcb.nrtx = TCP_MAXRTX;
    pcb.rto_us = (s32_t)slow_tmr_interval * 1000;
    pcb.rto_deadline_us = 1;
}

} // namespace

/* With TCP_USER_TIMEOUT armed in ESTABLISHED, the TCP_MAXRTX cap must not abort
 * the connection. Retransmissions continue and the user timeout owns the abort. */
TEST(tcp_slowtmr, rto_user_timeout_overrides_max_data_retries)
{
    timer_resolution_guard timer_guard(100);
    slowtmr_test_guard test_guard;
    output_hooks_guard hooks_guard;
    tcp_pcb pcb;
    test_segment_storage storage;
    init_pcb_at_max_data_retries(pcb, storage);
    pcb.user_timeout_ms = 3000;

    const u32_t timeout_ticks = tcp_ms_to_ticks(pcb.user_timeout_ms);
    u32_t abort_tick = 0;
    for (u32_t tick = 1; tick <= 2 * timeout_ticks && abort_tick == 0; ++tick) {
        slowtmr_tick(pcb);
        if (g_error_calls > 0) {
            abort_tick = tick;
        }
    }

    EXPECT_EQ(timeout_ticks + 1, abort_tick) << "abort must come from the user timeout";
    EXPECT_EQ(ERR_TIMEOUT, g_last_error);
    EXPECT_GE(g_ip_output_calls, 2) << "retransmissions must continue past TCP_MAXRTX";
    EXPECT_GT(pcb.nrtx, TCP_MAXRTX);
    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
}

/* Without a user timeout the TCP_MAXRTX cap keeps the abort. */
TEST(tcp_slowtmr, rto_max_data_retries_abort_without_user_timeout)
{
    timer_resolution_guard timer_guard(100);
    slowtmr_test_guard test_guard;
    output_hooks_guard hooks_guard;
    tcp_pcb pcb;
    test_segment_storage storage;
    init_pcb_at_max_data_retries(pcb, storage);

    slowtmr_tick(pcb);

    EXPECT_EQ(1, g_error_calls);
    EXPECT_EQ(ERR_ABRT, g_last_error);
    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
}

/* A stopped send clock (ticks_since_data_sent == -1) keeps the TCP_MAXRTX abort
 * even with a user timeout armed in ESTABLISHED. The user timeout needs the
 * clock, so without it the retransmission count must stay the bound. */
TEST(tcp_slowtmr, rto_max_data_retries_abort_with_user_timeout_and_stopped_clock)
{
    timer_resolution_guard timer_guard(100);
    slowtmr_test_guard test_guard;
    output_hooks_guard hooks_guard;
    tcp_pcb pcb;
    test_segment_storage storage;
    init_pcb_at_max_data_retries(pcb, storage);
    pcb.user_timeout_ms = 3000;
    pcb.ticks_since_data_sent = -1;
    pcb.rto_deadline_us = INT64_MAX;

    slowtmr_tick(pcb);

    EXPECT_EQ(1, g_error_calls);
    EXPECT_EQ(ERR_ABRT, g_last_error);
    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
}

/* tcp_user_timeout_occured() cannot fire outside ESTABLISHED and SYN_SENT, so
 * with a user timeout armed in FIN_WAIT_1 the TCP_MAXRTX cap keeps the abort.
 * Otherwise the retransmissions would have no bound. */
TEST(tcp_slowtmr, rto_max_data_retries_abort_in_fin_wait_1_with_user_timeout)
{
    timer_resolution_guard timer_guard(100);
    slowtmr_test_guard test_guard;
    output_hooks_guard hooks_guard;
    tcp_pcb pcb;
    test_segment_storage storage;
    init_pcb_at_max_data_retries(pcb, storage);
    pcb.private_state = FIN_WAIT_1;
    pcb.user_timeout_ms = 3000;

    slowtmr_tick(pcb);

    EXPECT_EQ(1, g_error_calls);
    EXPECT_EQ(ERR_ABRT, g_last_error);
    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
}

#ifdef XLIO_TIME_DEBUG_COUNTERS
/* Clock-read counters for debug/test builds. */

TEST(tcp_time_counters, idle_wouldblock_reads_clock_for_sample_and_retry_deadline)
{
    xlio_time_debug_counters_reset();

    tcp_pcb pcb;
    init_pcb_for_output(pcb);

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 4);
    pcb.unsent = &storage.seg;
    pcb.last_unsent = &storage.seg;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    ASSERT_EQ(ERR_OK, tcp_output(&pcb));
    ASSERT_TRUE(pcb.is_last_seg_dropped);
    ASSERT_NE(0, pcb.rto_deadline_us);

    const xlio_time_debug_counters_t c = xlio_time_debug_counters_get();
    EXPECT_EQ(1U, c.tx_rtt_start_read);
    EXPECT_EQ(1U, c.tx_arm_idle_read)
        << "the cold local-failure path needs a fresh post-attempt deadline timestamp";
}

/* FIN-only send uses only the deadline-arm clock read. */
TEST(tcp_time_counters, fin_from_idle_reads_clock_once_for_arm)
{
    xlio_time_debug_counters_reset();

    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.ip_output = succeed_always;

    test_segment_storage storage;
    make_fin_only_segment(storage, pcb);

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    g_ip_output_calls = 0;
    ASSERT_EQ(ERR_OK, tcp_output(&pcb));
    ASSERT_NE(0, pcb.rto_deadline_us);

    const xlio_time_debug_counters_t c = xlio_time_debug_counters_get();
    EXPECT_EQ(1U, c.tx_arm_idle_read) << "arm-from-idle must read the clock exactly once";
    EXPECT_EQ(0U, c.tx_rtt_start_read) << "FIN-only must not start an RTT sample";
    EXPECT_EQ(0U, c.refresh_rx_batch);
}

/* Data send reuses its RTT-sample timestamp for deadline arming. */
TEST(tcp_time_counters, data_from_idle_reads_clock_once_for_rtt_sample)
{
    xlio_time_debug_counters_reset();

    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.ip_output = succeed_always;

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 4);
    pcb.unsent = &storage.seg;
    pcb.last_unsent = &storage.seg;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    g_ip_output_calls = 0;
    ASSERT_EQ(ERR_OK, tcp_output(&pcb));
    ASSERT_NE(0, pcb.rttest_us);
    ASSERT_NE(0, pcb.rto_deadline_us);

    const xlio_time_debug_counters_t c = xlio_time_debug_counters_get();
    EXPECT_EQ(1U, c.tx_rtt_start_read) << "data send must start exactly one RTT sample read";
    EXPECT_EQ(0U, c.tx_arm_idle_read) << "arm must reuse the sample-start read, not re-read";
}

/* The batch guard partitions refreshed RX batches from empty polls. */
TEST(tcp_time_counters, rx_batch_guard_partitions_refresh_and_empty_poll)
{
    xlio_time_debug_counters_reset();
    g_xlio_tls_now_us = 0;
    {
        xlio_now_us_batch batch;
        EXPECT_FALSE(batch.armed());
    }
    {
        const xlio_time_debug_counters_t c = xlio_time_debug_counters_get();
        EXPECT_EQ(0U, c.refresh_rx_batch);
        EXPECT_EQ(1U, c.empty_polls);
    }

    xlio_time_debug_counters_reset();
    g_xlio_tls_now_us = 0;
    {
        xlio_now_us_batch batch;
        const int64_t now = batch.refresh();
        EXPECT_TRUE(batch.armed());
        EXPECT_NE(0, now);
        EXPECT_EQ(now, xlio_now_us());
    }
    EXPECT_EQ(0, xlio_now_us()) << "TLS slot must be cleared on batch scope exit";
    {
        const xlio_time_debug_counters_t c = xlio_time_debug_counters_get();
        EXPECT_EQ(1U, c.refresh_rx_batch) << "exactly one refresh per non-empty batch";
        EXPECT_EQ(0U, c.empty_polls);
    }

    xlio_time_debug_counters_reset();
    const uint64_t empty_iterations = 1000000;
    for (uint64_t i = 0; i < empty_iterations; ++i) {
        xlio_now_us_batch batch;
        (void)batch;
    }
    {
        const xlio_time_debug_counters_t c = xlio_time_debug_counters_get();
        EXPECT_EQ(0U, c.refresh_rx_batch) << "empty polls must never read the clock";
        EXPECT_EQ(empty_iterations, c.empty_polls);
    }
}
#endif /* XLIO_TIME_DEBUG_COUNTERS */
