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

static err_t fail_with_wouldblock(struct pbuf *p, struct tcp_seg *seg, void *pcb, u16_t flags)
{
    (void)p;
    (void)seg;
    (void)pcb;
    (void)flags;
    ++g_ip_output_calls;
    return ERR_WOULDBLOCK;
}

/* Returns ERR_OK on the first call and ERR_WOULDBLOCK thereafter. Used by
 * the Karn integration test below: the first segment in a flight succeeds
 * (and starts an RTT sample), then the second segment's send fails. The
 * second call is NOT eligible to start a new sample (rttest_us != 0), so
 * sample_started_here is false and the failed-send clear must be a no-op.
 */
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

/* Always succeeds. Models an external tcp_output() re-drive (a later send() or
 * an incoming ACK) after a transient ring-full / TX-buffer-pool WOULDBLOCK has
 * cleared.
 */
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
    std::memset(&pcb, 0, sizeof(pcb));
    tcp_rto_pcb_seed(&pcb);
    pcb.private_state = ESTABLISHED;
    /* Real PCBs get a congestion-control algo at init (tcp.c defaults to
     * &none_cc_algo). The RTO-retransmit path in tcp_slowtmr() calls
     * cc_cong_signal(), which dereferences pcb->cc_algo, so a memset-0 PCB
     * would crash the moment a test drives an actual retransmit. */
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

TEST(tcp_output, wouldblock_first_send_keeps_segment_unsent)
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
    EXPECT_EQ(&storage.seg, pcb.unsent);
    EXPECT_EQ(&storage.seg, pcb.last_unsent);
    EXPECT_EQ(nullptr, pcb.unacked);
    EXPECT_EQ(nullptr, pcb.last_unacked);
    EXPECT_EQ(1000U, pcb.snd_nxt);
    EXPECT_EQ(0, pcb.rttest_us);
    EXPECT_EQ(0, pcb.rto_deadline_us);
    /* a failed send must not bump rtime / ticks_since_data_sent
     * away from -1 (the "no flight" sentinel). The marker fields are now only
     * advanced inside tcp_rto_timer_start_if_needed on the success path.
     */
    EXPECT_EQ(-1, pcb.rtime);
    EXPECT_EQ(-1, pcb.ticks_since_data_sent);
}

/* Karn integration test: drives tcp_output_segment() through tcp_output()
 * with a mocked ip_output that succeeds for the first segment and fails
 * (ERR_WOULDBLOCK) for the second. The first segment's call starts an RTT
 * sample (sample_started_here=true at that call's frame); the second
 * segment's call is not eligible to start a new sample (rttest_us != 0,
 * so sample_started_here=false at that frame). Karn requires the second
 * call's failed-send branch to NOT erase the first call's in-flight
 * sample.
 */
TEST(tcp_output, karn_failed_second_send_preserves_first_call_sample)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.ip_output = succeed_then_wouldblock;

    /* Two segments back-to-back. seg1 at snd_nxt (eligible to start
     * sample), seg2 immediately after.
     */
    test_segment_storage seg1, seg2;
    init_unsent_segment(seg1, pcb.snd_nxt, 4);
    init_unsent_segment(seg2, pcb.snd_nxt + 4, 4);
    seg1.seg.next = &seg2.seg;

    pcb.unsent = &seg1.seg;
    pcb.last_unsent = &seg2.seg;
    pcb.snd_lbb = pcb.snd_nxt + 8; /* both segs in lbb range */

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    g_ip_output_calls = 0;
    err_t rc = tcp_output(&pcb);

    /* tcp_output translates ERR_WOULDBLOCK -> ERR_OK at its return
     * boundary (preserved upstream contract). */
    EXPECT_EQ(ERR_OK, rc);
    EXPECT_EQ(2, g_ip_output_calls);

    /* seg1 succeeded: moved off unsent and onto unacked; snd_nxt
     * advanced past it. */
    EXPECT_EQ(&seg2.seg, pcb.unsent);
    EXPECT_EQ(&seg1.seg, pcb.unacked);
    EXPECT_EQ(1004U, pcb.snd_nxt);

    /* seg1's call started an RTT sample. The Karn invariant under test:
     * seg2's failed-send branch (sample_started_here=false at that call)
     * must NOT erase rttest_us.
     */
    EXPECT_NE(0, pcb.rttest_us) << "Karn invariant broken: seg2's failed-send erased seg1's sample";
    EXPECT_EQ(1000U, pcb.rtseq);

    /* seg2 was never linked to unacked (failed before the post-send
     * accounting). last_unacked points at seg1 only.
     */
    EXPECT_EQ(&seg1.seg, pcb.last_unacked);

    /* rto_deadline_us must be armed (seg1 succeeded and reached the
     * tcp_rto_timer_start_if_needed branch). */
    EXPECT_NE(0, pcb.rto_deadline_us);
}

/* Recovery test for the "failed first send on an idle PCB" case.
 *
 * Scenario: an otherwise-idle socket (empty unacked) sends the first segment of
 * a flight and the send fails with ERR_WOULDBLOCK (TX-buffer-pool exhaustion on
 * a non-blocking socket; see dst_entry_tcp::fast_send get_buffer()==NULL). The
 * byte was already accepted into lwIP's send buffer, so the application sees
 * success and does not retry. The failed-send path leaves the segment on unsent
 * with NOTHING armed (rto_deadline_us == 0, rtime == -1, empty unacked).
 *
 * Because nothing is in flight, the RTO deadline gate can never fire for it, so
 * recovery cannot come from the RTO path. It must come from tcp_slowtmr()'s
 * stuck-unsent re-drive (unacked == NULL && unsent != NULL), which deliberately
 * does NOT require rtime >= 0 so it also covers this -1 "no flight" case. This
 * test is the regression guard for that broadened condition.
 */
TEST(tcp_output, wouldblock_first_send_idle_pcb_recovered_by_slowtmr)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);

    test_segment_storage storage;
    init_unsent_segment(storage, pcb.snd_nxt, 4);
    pcb.unsent = &storage.seg;
    pcb.last_unsent = &storage.seg;

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    /* Phase 1: idle PCB, first send fails -> parked, nothing armed. */
    g_ip_output_calls = 0;
    err_t rc = tcp_output(&pcb);

    EXPECT_EQ(ERR_OK, rc);
    EXPECT_EQ(1, g_ip_output_calls);
    EXPECT_EQ(&storage.seg, pcb.unsent);
    EXPECT_EQ(nullptr, pcb.unacked);
    EXPECT_EQ(0, pcb.rto_deadline_us);
    EXPECT_EQ(-1, pcb.rtime);

    /* The RTO deadline gate cannot fire for the parked segment (no armed
     * deadline, empty unacked), so the slow timer's RTO path is NOT the recovery
     * mechanism - the stuck-unsent re-drive is.
     */
    const int64_t far_future_us = (int64_t)TCP_RTO_MAX_US * 4;
    EXPECT_FALSE(tcp_rto_deadline_elapsed(&pcb, far_future_us));

    /* Phase 2: the transient send failure clears; one slow-timer pass must
     * re-drive tcp_output() and flush the parked segment even though rtime is
     * still the -1 "no flight" sentinel.
     */
    pcb.ip_output = succeed_always;
    g_ip_output_calls = 0;
    tcp_slowtmr(&pcb, far_future_us);

    EXPECT_EQ(1, g_ip_output_calls) << "slow timer did not re-drive tcp_output() for parked unsent";
    EXPECT_EQ(&storage.seg, pcb.unacked) << "slow timer did not flush the parked segment";
    EXPECT_EQ(nullptr, pcb.unsent);
    EXPECT_EQ(1004U, pcb.snd_nxt);
    EXPECT_NE(0, pcb.rto_deadline_us) << "successful flush must arm the RTO deadline";
}

/* An RTO moves the whole unacked queue back to unsent before calling
 * tcp_output(). If the retransmission cannot reach the wire, no flight remains
 * to own the deadline that tcp_slowtmr() prepared for that attempt. The later
 * successful re-drive must therefore arm from its actual transmit time instead
 * of consuming the backed-off RTO while parked on unsent. */
TEST(tcp_output, rto_wouldblock_rearms_only_after_retransmit_reaches_wire)
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
    EXPECT_EQ(nullptr, pcb.unacked);
    EXPECT_EQ(&storage.seg, pcb.unsent);
    EXPECT_EQ(first_rto << 1, pcb.rto_us);
    EXPECT_EQ(1, pcb.nrtx);
    EXPECT_EQ(0, pcb.rto_deadline_us)
        << "a failed retransmission must not retain a deadline with no flight";
    EXPECT_EQ(0, pcb.rtime) << "failed retransmission must retain the retry marker";
    EXPECT_EQ(1, pcb.ticks_since_data_sent)
        << "failed retransmission must not reset TCP_USER_TIMEOUT age";

    pcb.ip_output = succeed_always;
    g_ip_output_calls = 0;
    const int64_t before_send_us = clock_gettime_monotonic_us();
    tcp_slowtmr(&pcb, first_deadline + 2);
    const int64_t after_send_us = clock_gettime_monotonic_us();

    ASSERT_EQ(1, g_ip_output_calls);
    EXPECT_EQ(&storage.seg, pcb.unacked);
    EXPECT_EQ(nullptr, pcb.unsent);
    EXPECT_GE(pcb.rto_deadline_us, before_send_us + pcb.rto_us);
    EXPECT_LE(pcb.rto_deadline_us, after_send_us + pcb.rto_us);
}

namespace {

/* Turn an idle-PCB unsent segment into a FIN-only control segment: zero
 * payload, FIN in both the cached seg->tcp_flags (TCP_SEGLEN uses it to charge
 * the +1 sequence number and queue the segment on unacked) and the on-wire
 * tcphdr flags. Models tcp_close() enqueuing a lone FIN on an otherwise-idle
 * connection. */
static void make_fin_only_segment(test_segment_storage &storage, tcp_pcb &pcb)
{
    init_unsent_segment(storage, pcb.snd_nxt, 0);
    storage.seg.tcp_flags = TCP_FIN;
    TCPH_SET_FLAG(storage.seg.tcphdr, TCP_FIN);
    pcb.flags |= TF_FIN; /* FIN enqueued for this PCB (bypasses the Nagle hold) */
    pcb.unsent = &storage.seg;
    pcb.last_unsent = &storage.seg;
}

} // namespace

/* Pin-down for the FIN-from-idle deadline arming the PR's cold-path read
 * enables. A FIN-only segment sent from an idle ESTABLISHED PCB (empty
 * unacked/unsent, no RTT sample in flight) is NOT sample-eligible
 * (tcp_rtt_sample_should_start excludes FIN-only), so rttest_us stays 0 and the
 * deadline is armed through the "cold path - first segment after idle" clock
 * read. A later slow-timer pass past that deadline must then retransmit the FIN
 * with backoff. This is a pin-down, not a RED-GREEN bugfix: it must pass on the
 * current PR code. If it fails, the arming or retransmit is broken - stop and
 * report rather than adjusting the test. */
TEST(tcp_output, fin_only_from_idle_arms_deadline_and_retransmits)
{
    tcp_pcb pcb;
    init_pcb_for_output(pcb);
    pcb.ip_output = succeed_always;

    test_segment_storage storage;
    make_fin_only_segment(storage, pcb);

    tcp_seg spare_seg {};
    pcb.seg_alloc = &spare_seg;

    /* Phase 1: send the FIN from idle. */
    g_ip_output_calls = 0;
    err_t rc = tcp_output(&pcb);

    EXPECT_EQ(ERR_OK, rc);
    EXPECT_EQ(1, g_ip_output_calls);
    /* The FIN charges one sequence number (TCP_SEGLEN == 1), so it is queued on
     * unacked and snd_nxt advances past it. */
    EXPECT_EQ(&storage.seg, pcb.unacked);
    EXPECT_EQ(nullptr, pcb.unsent);
    EXPECT_EQ(1001U, pcb.snd_nxt);
    /* FIN-only is not RTT-sample-eligible: no sample started. */
    EXPECT_EQ(0, pcb.rttest_us);
    /* Deadline armed via the cold-path (arm-from-idle) read. */
    EXPECT_NE(0, pcb.rto_deadline_us);
    EXPECT_EQ(0, pcb.nrtx);
    const int64_t deadline0 = pcb.rto_deadline_us;

    /* Phase 2: a slow-timer pass past the deadline retransmits the FIN with
     * RFC 6298 5.5 backoff. */
    g_ip_output_calls = 0;
    tcp_slowtmr(&pcb, deadline0 + 1);

    EXPECT_EQ(1, pcb.nrtx) << "FIN-from-idle RTO deadline did not fire a retransmit";
    EXPECT_EQ(1, g_ip_output_calls) << "retransmit did not re-send the FIN";
    EXPECT_EQ(&storage.seg, pcb.unacked) << "FIN not re-queued on unacked after retransmit";
    EXPECT_EQ(nullptr, pcb.unsent);
    EXPECT_NE(0, pcb.rto_deadline_us);
    EXPECT_GT(pcb.rto_deadline_us, deadline0) << "deadline not re-armed with backoff";
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
/* --- Design invariant I2: clock-read counters (debug/test builds only) ---
 *
 * These assert the two TX-side clock-read sites the unit-test binary can reach
 * (tcp_out.c is linked into it; the RX/timer/fallback sites live in files it
 * does not compile - those are exercised in gtest/lab) plus the RX-batch guard
 * partition that underpins the whole invariant. Compiled out in release with
 * the counters themselves. */

/* A FIN-only send from idle reads the monotonic clock exactly once - for the
 * cold-path deadline arm - and starts no RTT sample, so tx_rtt_start_read stays
 * 0. No defensive fallback fires on this hot path. */
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
    EXPECT_EQ(0U, c.fallback_reads);
    EXPECT_EQ(0U, c.refresh_rx_batch);
}

/* A data segment sent from idle reads the clock exactly once - for the RTT
 * sample start - and the deadline arm reuses that read, so tx_arm_idle_read
 * stays 0. */
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
    ASSERT_NE(0, pcb.rttest_us);       /* RTT sample started */
    ASSERT_NE(0, pcb.rto_deadline_us); /* deadline armed reusing the sample read */

    const xlio_time_debug_counters_t c = xlio_time_debug_counters_get();
    EXPECT_EQ(1U, c.tx_rtt_start_read) << "data send must start exactly one RTT sample read";
    EXPECT_EQ(0U, c.tx_arm_idle_read) << "arm must reuse the sample-start read, not re-read";
    EXPECT_EQ(0U, c.fallback_reads);
}

/* The xlio_now_us_batch guard is the single choke point for the RX-batch clock
 * read. A batch that refreshes counts exactly one refresh and clears the TLS
 * slot on scope exit; a batch that never refreshes counts one empty poll and
 * reads the clock zero times. This is the mechanism the CQ managers rely on for
 * "<= 1 read per non-empty batch, 0 on empty polls". */
TEST(tcp_time_counters, rx_batch_guard_partitions_refresh_and_empty_poll)
{
    /* Empty poll: construct + destruct without refreshing. */
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

    /* Non-empty batch: exactly one refresh; TLS armed within scope, cleared on
     * exit. */
    xlio_time_debug_counters_reset();
    g_xlio_tls_now_us = 0;
    {
        xlio_now_us_batch batch;
        const int64_t now = batch.refresh();
        EXPECT_TRUE(batch.armed());
        EXPECT_NE(0, now);
        EXPECT_EQ(now, xlio_now_us()); /* readable within the batch */
    }
    EXPECT_EQ(0, xlio_now_us()) << "TLS slot must be cleared on batch scope exit";
    {
        const xlio_time_debug_counters_t c = xlio_time_debug_counters_get();
        EXPECT_EQ(1U, c.refresh_rx_batch) << "exactly one refresh per non-empty batch";
        EXPECT_EQ(0U, c.empty_polls);
    }

    /* Empty busy-poll (design-doc verification): a long run of empty polls never
     * reads the clock; empty_polls grows, the refresh counter stays 0. */
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
