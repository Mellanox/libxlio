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
