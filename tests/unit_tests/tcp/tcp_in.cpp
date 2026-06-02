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

/* RX-path (tcp_in.c) integration tests: drive L3_level_tcp_input() with
 * hand-crafted IPv4+TCP frames against a synthetic ESTABLISHED PCB.
 *
 * The suite covers the ACK-side RTO semantics:
 *   - an advancing ACK resets the retry episode without collapsing the
 *     current backed-off RTO unless the ACK also yields a valid RTT sample.
 */

namespace {

struct test_segment_storage {
    tcp_seg seg {};
    pbuf p {};
    unsigned char bytes[TCP_HLEN + 16] {};
};

static int g_ip_output_calls;

static err_t count_and_succeed(struct pbuf *p, struct tcp_seg *seg, void *pcb, u16_t flags)
{
    (void)p;
    (void)seg;
    (void)pcb;
    (void)flags;
    ++g_ip_output_calls;
    return ERR_OK;
}

/* The full-ACK path frees consumed segments through the registered external
 * hooks (production registers the sockinfo allocators). The test segments are
 * caller-owned stack storage, so the hooks are no-ops. */
static void noop_seg_free(void *p_conn, struct tcp_seg *seg)
{
    (void)p_conn;
    (void)seg;
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

static u16_t noop_route_mtu(struct tcp_pcb *pcb)
{
    (void)pcb;
    return 0;
}

static struct pbuf *fail_tx_pbuf_alloc(void *p_conn, pbuf_type type, pbuf_desc *desc,
                                       struct pbuf *p_buff)
{
    (void)p_conn;
    (void)type;
    (void)desc;
    (void)p_buff;
    return nullptr;
}

/* tcp_output() prefetches pcb->seg_alloc through external_tcp_seg_alloc when
 * it is NULL (production registers the sockinfo segment allocator). Serve
 * those prefetches from a small static pool so the RX-driven tcp_output() at
 * the end of L3_level_tcp_input() does not call an unregistered hook. */
static tcp_seg g_spare_segs[8];
static unsigned g_spare_seg_next;

static struct tcp_seg *test_seg_alloc(void *p_conn)
{
    (void)p_conn;
    if (g_spare_seg_next >= sizeof(g_spare_segs) / sizeof(g_spare_segs[0])) {
        return nullptr;
    }
    g_spare_segs[g_spare_seg_next] = {};
    return &g_spare_segs[g_spare_seg_next++];
}

static void register_noop_free_hooks()
{
    register_tcp_seg_free(noop_seg_free);
    register_tcp_tx_pbuf_free(noop_tx_pbuf_free);
    register_tcp_tx_pbuf_alloc(fail_tx_pbuf_alloc);
    register_tcp_seg_alloc(test_seg_alloc);
    register_tcp_state_observer(noop_state_observer);
    register_ip_route_mtu(noop_route_mtu);
    g_spare_seg_next = 0;
}

static void init_established_pcb(tcp_pcb &pcb)
{
    std::memset(&pcb, 0, sizeof(pcb));
    tcp_rto_pcb_seed(&pcb);
    pcb.private_state = ESTABLISHED;
    pcb.cc_algo = &none_cc_algo;
    pcb.rtime = -1;
    pcb.ticks_since_data_sent = -1;
    pcb.mss = 1460;
    pcb.cwnd = 1460;
    pcb.ssthresh = TCP_INITIAL_SSTHRESH;
    pcb.snd_wnd = 65535;
    pcb.snd_wnd_max = 65535;
    pcb.rcv_wnd = 65535;
    pcb.rcv_ann_wnd = 65535;
    pcb.rcv_wnd_max = 65535;
    pcb.rcv_nxt = 5000;
    pcb.rcv_ann_right_edge = 5000 + 65535;
    pcb.lastack = 1000;
    pcb.snd_nxt = 1000;
    pcb.snd_lbb = 1000;
    pcb.snd_wl1 = 5000 - 1;
    pcb.snd_wl2 = 1000;
    pcb.ip_output = count_and_succeed;
}

static void init_segment(test_segment_storage &storage, uint32_t seqno, uint32_t len)
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
    TCPH_HDRLEN_FLAGS_SET(storage.seg.tcphdr, TCP_HLEN / 4, TCP_ACK);
}

static void attach_unacked_segment(tcp_pcb &pcb, test_segment_storage &storage, uint32_t seqno,
                                   uint32_t len)
{
    init_segment(storage, seqno, len);
    pcb.unacked = &storage.seg;
    pcb.last_unacked = &storage.seg;
    pcb.snd_nxt = seqno + len;
    pcb.snd_lbb = seqno + len;
}

static void attach_two_unacked_segments(tcp_pcb &pcb, test_segment_storage &first,
                                        test_segment_storage &second, uint32_t seqno,
                                        uint32_t len)
{
    init_segment(first, seqno, len);
    init_segment(second, seqno + len, len);
    first.seg.next = &second.seg;
    pcb.unacked = &first.seg;
    pcb.last_unacked = &second.seg;
    pcb.snd_nxt = seqno + 2 * len;
    pcb.snd_lbb = seqno + 2 * len;
}

/* One IPv4 (20 B, no options) + TCP (20 B, no options) frame. */
struct test_rx_packet {
    pbuf p {};
    unsigned char bytes[20 + TCP_HLEN] {};
};

/* Inject a pure ACK (no payload) into the PCB through the real RX entry
 * point. The pbuf is caller-owned: ref = 2 so L3_level_tcp_input()'s final
 * pbuf_free() only drops the reference. */
static void inject_ack(tcp_pcb &pcb, test_rx_packet &pkt, uint32_t ackno, uint32_t seqno,
                       uint16_t wnd = 65535, uint8_t flags = TCP_ACK)
{
    pkt.p = {};
    std::memset(pkt.bytes, 0, sizeof(pkt.bytes));
    unsigned char *b = pkt.bytes;

    /* IPv4 header: version 4, IHL 5, total length = 40. */
    b[0] = 0x45;
    b[2] = 0;
    b[3] = 40;

    struct tcp_hdr *th = reinterpret_cast<tcp_hdr *>(&b[20]);
    th->src = htons(50001);
    th->dest = htons(50002);
    th->seqno = htonl(seqno);
    th->ackno = htonl(ackno);
    TCPH_HDRLEN_FLAGS_SET(th, TCP_HLEN / 4, flags);
    th->wnd = htons(wnd);

    pkt.p.payload = pkt.bytes;
    pkt.p.len = sizeof(pkt.bytes);
    pkt.p.tot_len = sizeof(pkt.bytes);
    pkt.p.type = PBUF_RAM;
    pkt.p.ref = 2;

    L3_level_tcp_input(&pkt.p, &pcb);
}

} // namespace

/* A clean handshake may seed the operational RTO, but it must not smuggle the
 * configured floor into estimator variance. This matters when the configured
 * floor exceeds the 1 s initial RTO: the first data sample must still replace
 * sv_us instead of mistaking a clean handshake for the SYN-loss fallback. */
TEST(tcp_in, clean_handshake_seed_does_not_pollute_estimator_variance)
{
    register_noop_free_hooks();
    const s32_t original_floor_us = tcp_rto_get_floor_us();
    tcp_rto_set_floor_us(2000000);

    tcp_pcb pcb;
    init_established_pcb(pcb);
    pcb.private_state = SYN_SENT;

    test_segment_storage syn;
    attach_unacked_segment(pcb, syn, 1000, 0);
    syn.seg.tcp_flags = TCP_SYN;
    TCPH_SET_FLAG(syn.seg.tcphdr, TCP_SYN);
    pcb.snd_nxt = 1001;
    pcb.snd_lbb = 1001;
    pcb.rttest_us = 1000000;
    pcb.rtseq = 1000;

    g_xlio_tls_now_us = 1000100;
    test_rx_packet pkt;
    inject_ack(pcb, pkt, /*ackno*/ 1001, /*seqno*/ 5000, /*wnd*/ 65535,
               TCP_SYN | TCP_ACK);
    g_xlio_tls_now_us = 0;

    EXPECT_EQ(ESTABLISHED, pcb.private_state);
    EXPECT_EQ(2000000, pcb.rto_us) << "clean handshake RTO must honor the configured floor";
    EXPECT_EQ(0, pcb.sa_us) << "the data-path SRTT must remain uninitialized";
    EXPECT_EQ(TCP_RTO_INITIAL_US, pcb.sv_us)
        << "clean handshake must not masquerade as conservative SYN-loss variance";

    tcp_rto_set_floor_us(original_floor_us);
}

/* One RX batch can remain active while processing an earlier ACK causes a new
 * transmit. Its cached batch timestamp then predates the new RTT sample. A
 * later ACK from that batch must not turn the causally inverted timestamps
 * into a one-microsecond handshake measurement. */
TEST(tcp_in, clean_handshake_discards_causally_stale_batch_timestamp)
{
    register_noop_free_hooks();
    const s32_t original_floor_us = tcp_rto_get_floor_us();
    tcp_rto_set_floor_us(TCP_RTO_FLOOR_DEFAULT_US);

    tcp_pcb pcb;
    init_established_pcb(pcb);
    pcb.private_state = SYN_SENT;

    test_segment_storage syn;
    attach_unacked_segment(pcb, syn, 1000, 0);
    syn.seg.tcp_flags = TCP_SYN;
    TCPH_SET_FLAG(syn.seg.tcphdr, TCP_SYN);
    pcb.snd_nxt = 1001;
    pcb.snd_lbb = 1001;

    const int64_t process_now_us = clock_gettime_monotonic_us();
    pcb.rttest_us = process_now_us - 500000;
    pcb.rtseq = 1000;
    g_xlio_tls_now_us = process_now_us - 1000000;

    test_rx_packet pkt;
    inject_ack(pcb, pkt, /*ackno*/ 1001, /*seqno*/ 5000, /*wnd*/ 65535,
               TCP_SYN | TCP_ACK);
    g_xlio_tls_now_us = 0;

    EXPECT_EQ(ESTABLISHED, pcb.private_state);
    EXPECT_EQ(tcp_rto_clamp_us(TCP_RTO_INITIAL_US), pcb.rto_us)
        << "an inverted batch timestamp must not seed the handshake RTO";
    EXPECT_EQ(0, pcb.rttest_us) << "the unusable handshake sample must be closed";

    tcp_rto_set_floor_us(original_floor_us);
}

/* Forward progress ends the current retry episode even when Karn leaves no
 * valid RTT sample. The backed-off RTO must remain intact, but nrtx must reset;
 * otherwise the next slow-timer pass can abort an already recovered PCB merely
 * because the preceding episode reached TCP_MAXRTX. */
TEST(tcp_in, advancing_ack_resets_retry_count_without_collapsing_rto)
{
    register_noop_free_hooks();

    tcp_pcb pcb;
    init_established_pcb(pcb);

    test_segment_storage storage;
    attach_unacked_segment(pcb, storage, 1000, 4);

    /* Simulate an RTO episode at the retry limit with a backed-off timeout and
     * no usable sample. */
    pcb.nrtx = TCP_MAXRTX;
    pcb.rto_us = 400000;
    pcb.rttest_us = 0;
    tcp_rto_timer_start_if_needed(&pcb, 1000000);

    /* Advancing ACK for the whole flight, no sample in flight. */
    g_xlio_tls_now_us = 2000000;
    test_rx_packet pkt;
    inject_ack(pcb, pkt, /*ackno*/ 1004, /*seqno*/ pcb.rcv_nxt);
    g_xlio_tls_now_us = 0;

    EXPECT_EQ(1004U, pcb.lastack) << "ACK was not processed at all";
    EXPECT_EQ(nullptr, pcb.unacked);
    EXPECT_EQ(0, pcb.nrtx) << "forward progress must start a fresh retry episode";
    EXPECT_EQ(400000, pcb.rto_us) << "backed-off RTO must survive a sample-less ACK";
}

/* A valid RTT sample additionally replaces the backed-off operational RTO
 * with a fresh estimator result. */
TEST(tcp_in, valid_rtt_sample_recomputes_backed_off_rto)
{
    register_noop_free_hooks();

    tcp_pcb pcb;
    init_established_pcb(pcb);

    test_segment_storage storage;
    attach_unacked_segment(pcb, storage, 1000, 4);

    pcb.nrtx = 1;
    pcb.rto_us = 400000;
    /* Fresh (post-episode) segment carries a live RTT sample. */
    pcb.rttest_us = 1999500;
    pcb.rtseq = 1000;
    tcp_rto_timer_start_if_needed(&pcb, 1999500);

    g_xlio_tls_now_us = 2000000; /* sample = 500 us */
    test_rx_packet pkt;
    inject_ack(pcb, pkt, /*ackno*/ 1004, /*seqno*/ pcb.rcv_nxt);
    g_xlio_tls_now_us = 0;

    EXPECT_EQ(1004U, pcb.lastack);
    EXPECT_EQ(0, pcb.nrtx) << "the advancing ACK must reset the retry episode";
    EXPECT_EQ(500 << 3, pcb.sa_us) << "estimator must be seeded from the 500 us sample";
    EXPECT_EQ(0, pcb.rttest_us) << "sample must be closed";
    /* Additive floor: rto = 500 + max(1000, configured floor). */
    EXPECT_EQ(TCP_RTO_FLOOR_DEFAULT_US + 500, pcb.rto_us);
}

/* A cached RX-batch timestamp can predate a sample started while an earlier
 * packet in that batch was processed. Even when the later ACK covers the
 * sampled sequence, the inverted timestamps are not an RTT measurement. */
TEST(tcp_in, advancing_full_ack_discards_causally_stale_batch_timestamp)
{
    register_noop_free_hooks();

    tcp_pcb pcb;
    init_established_pcb(pcb);

    test_segment_storage storage;
    attach_unacked_segment(pcb, storage, 1000, 4);

    pcb.sa_us = 8000;
    pcb.sv_us = 2000;
    pcb.rto_us = 700000;
    const int64_t process_now_us = clock_gettime_monotonic_us();
    pcb.rttest_us = process_now_us - 500000;
    pcb.rtseq = 1000;
    tcp_rto_timer_start_if_needed(&pcb, pcb.rttest_us);

    g_xlio_tls_now_us = process_now_us - 1000000;
    test_rx_packet pkt;
    inject_ack(pcb, pkt, /*ackno*/ 1004, /*seqno*/ pcb.rcv_nxt);
    g_xlio_tls_now_us = 0;

    EXPECT_EQ(nullptr, pcb.unacked);
    EXPECT_EQ(0, pcb.rttest_us) << "the unusable sample must be closed";
    EXPECT_EQ(8000, pcb.sa_us) << "an inverted timestamp must not update SRTT";
    EXPECT_EQ(2000, pcb.sv_us) << "an inverted timestamp must not update RTTVAR";
    EXPECT_EQ(700000, pcb.rto_us) << "an inverted timestamp must not update RTO";
}

/* A partial ACK with the same timestamp inversion still restarts the RTO per
 * RFC 6298 section 5.3. The once-per-batch clock policy keeps using the batch
 * timestamp for that restart, but it must not use the inverted pair as an RTT
 * sample. */
TEST(tcp_in, advancing_partial_ack_discards_causally_stale_rtt_sample)
{
    register_noop_free_hooks();

    tcp_pcb pcb;
    init_established_pcb(pcb);

    test_segment_storage first;
    test_segment_storage second;
    attach_two_unacked_segments(pcb, first, second, 1000, 4);

    pcb.sa_us = 8000;
    pcb.sv_us = 2000;
    pcb.rto_us = 700000;
    const int64_t process_now_us = clock_gettime_monotonic_us();
    pcb.rttest_us = process_now_us - 500000;
    pcb.rtseq = 1000;
    tcp_rto_timer_start_if_needed(&pcb, pcb.rttest_us);

    g_xlio_tls_now_us = process_now_us - 1000000;
    test_rx_packet pkt;
    inject_ack(pcb, pkt, /*ackno*/ 1004, /*seqno*/ pcb.rcv_nxt);
    g_xlio_tls_now_us = 0;

    ASSERT_EQ(&second.seg, pcb.unacked);
    EXPECT_EQ(0, pcb.rttest_us) << "the unusable sample must be closed";
    EXPECT_EQ(8000, pcb.sa_us) << "an inverted timestamp must not update SRTT";
    EXPECT_EQ(2000, pcb.sv_us) << "an inverted timestamp must not update RTTVAR";
    EXPECT_EQ(700000, pcb.rto_us) << "an inverted timestamp must not update RTO";
    EXPECT_EQ(process_now_us - 1000000 + pcb.rto_us, pcb.rto_deadline_us)
        << "partial ACK must retain the once-per-batch rearm policy";
}

/* Purge is terminal for queued data. Its timer and sample markers must be
 * terminal too, so diagnostics and any later lifecycle observer cannot see
 * timing ownership for queues that no longer exist. */
TEST(tcp_in, pcb_purge_clears_dead_timing_ownership)
{
    register_noop_free_hooks();

    tcp_pcb pcb;
    init_established_pcb(pcb);

    test_segment_storage storage;
    attach_unacked_segment(pcb, storage, 1000, 4);
    pcb.rttest_us = 1000000;
    pcb.rtseq = 1000;
    tcp_rto_timer_start_if_needed(&pcb, 1000000);

    tcp_pcb_purge(&pcb);

    EXPECT_EQ(nullptr, pcb.unacked);
    EXPECT_EQ(nullptr, pcb.last_unacked);
    EXPECT_EQ(-1, pcb.rtime);
    EXPECT_EQ(-1, pcb.ticks_since_data_sent);
    EXPECT_EQ(0, pcb.rto_deadline_us);
    EXPECT_EQ(0, pcb.rttest_us);
    EXPECT_EQ(0U, pcb.rtseq);
}

/* --- ACK re-arm and legacy expiry consequence --- */

/* A duplicate ACK does not change the retransmission deadline. An advancing
 * full ACK consumes the flight and stops the timer. */
TEST(tcp_in, duplicate_ack_keeps_deadline_advancing_ack_stops_timer)
{
    register_noop_free_hooks();

    tcp_pcb pcb;
    init_established_pcb(pcb);

    test_segment_storage storage;
    attach_unacked_segment(pcb, storage, 1000, 4);
    tcp_rto_timer_start_if_needed(&pcb, 1000000);
    const int64_t deadline = pcb.rto_deadline_us;

    /* Duplicate ACK: ackno == lastack, no payload, same window. */
    g_xlio_tls_now_us = 3000000;
    test_rx_packet dpkt;
    inject_ack(pcb, dpkt, /*ackno*/ 1000, /*seqno*/ pcb.rcv_nxt);
    g_xlio_tls_now_us = 0;

    EXPECT_EQ(deadline, pcb.rto_deadline_us) << "duplicate ACK must not re-arm the timer";
    EXPECT_EQ(&storage.seg, pcb.unacked) << "duplicate ACK must not consume the segment";

    /* An advancing ACK consumes the whole flight and stops the timer. */
    g_xlio_tls_now_us = 4000000;
    test_rx_packet apkt;
    inject_ack(pcb, apkt, /*ackno*/ 1004, /*seqno*/ pcb.rcv_nxt);
    g_xlio_tls_now_us = 0;

    EXPECT_EQ(0, pcb.rto_deadline_us);
    EXPECT_EQ(nullptr, pcb.unacked);
}

/* The first established-data expiry retains XLIO's existing consequence:
 * congestion response, whole-queue retransmission, Karn suppression, and
 * exponential backoff. */
TEST(tcp_in, slowtmr_first_data_expiry_keeps_legacy_consequence)
{
    register_noop_free_hooks();
    set_tmr_resolution(10);

    tcp_pcb pcb;
    init_established_pcb(pcb);
    pcb.cc_algo = &lwip_cc_algo;
    pcb.cwnd = 10000;
    pcb.ssthresh = 40000;

    test_segment_storage first;
    test_segment_storage second;
    attach_two_unacked_segments(pcb, first, second, 1000, 4);

    const int64_t t_arm = 1000000;
    tcp_rto_timer_start_if_needed(&pcb, t_arm);
    const s32_t rto_at_fire = pcb.rto_us;

    const int64_t t_fire = pcb.rto_deadline_us + 5;
    g_ip_output_calls = 0;
    tcp_slowtmr(&pcb, t_fire);

    EXPECT_EQ(2, g_ip_output_calls) << "the entire rewound queue must be retransmitted";
    EXPECT_EQ(1, pcb.nrtx);
    EXPECT_EQ((u32_t)pcb.mss, pcb.cwnd) << "RTO must collapse cwnd to 1 MSS";
    EXPECT_EQ(5000U, pcb.ssthresh) << "RTO halves the effective window (10000 / 2)";
    EXPECT_EQ(0, pcb.rttest_us) << "Karn: a retransmission must not carry an RTT sample";
    EXPECT_EQ(rto_at_fire << 1, pcb.rto_us) << "first RTO applies the legacy backoff";
    EXPECT_EQ(t_fire + (int64_t)pcb.rto_us, pcb.rto_deadline_us);
    EXPECT_EQ(&first.seg, pcb.unacked);
    EXPECT_EQ(&second.seg, pcb.last_unacked);
    EXPECT_EQ(&second.seg, first.seg.next);
}

/* An advancing partial ACK re-arms from the ACK's RX-batch timestamp after the
 * acknowledged segment is removed. If no later ACK arrives, the new deadline
 * expires through the existing congestion-loss path. */
TEST(tcp_in, partial_ack_rearms_then_expiry_keeps_legacy_consequence)
{
    register_noop_free_hooks();
    set_tmr_resolution(10);

    tcp_pcb pcb;
    init_established_pcb(pcb);
    pcb.cc_algo = &lwip_cc_algo;
    pcb.cwnd = 10000;
    pcb.ssthresh = 40000;

    test_segment_storage first;
    test_segment_storage second;
    attach_two_unacked_segments(pcb, first, second, 1000, 4);
    pcb.nrtx = 5;
    pcb.rto_us = 400000;
    tcp_rto_timer_start_if_needed(&pcb, 1000000);

    const int64_t t_ack = 1200000;
    g_xlio_tls_now_us = t_ack;
    test_rx_packet pkt;
    inject_ack(pcb, pkt, /*ackno*/ 1004, /*seqno*/ pcb.rcv_nxt);
    g_xlio_tls_now_us = 0;

    ASSERT_EQ(1004U, pcb.lastack);
    ASSERT_EQ(&second.seg, pcb.unacked) << "partial ACK must leave the second segment in flight";
    ASSERT_EQ(&second.seg, pcb.last_unacked);
    ASSERT_EQ(0, pcb.nrtx) << "partial forward progress must reset the retry episode";
    ASSERT_EQ(400000, pcb.rto_us) << "a sample-less ACK must retain the current backoff";
    ASSERT_EQ(t_ack + pcb.rto_us, pcb.rto_deadline_us)
        << "partial ACK must re-arm from its RX-batch timestamp";

    const s32_t rto_at_fire = pcb.rto_us;
    const int64_t t_fire = pcb.rto_deadline_us + 5;
    g_ip_output_calls = 0;
    tcp_slowtmr(&pcb, t_fire);

    EXPECT_EQ(1, g_ip_output_calls) << "remaining flight must be retransmitted";
    EXPECT_EQ(1, pcb.nrtx);
    EXPECT_EQ(rto_at_fire << 1, pcb.rto_us)
        << "the next timeout must double the retained operational RTO";
    EXPECT_EQ((u32_t)pcb.mss, pcb.cwnd) << "expiry retains the congestion response";
    EXPECT_EQ(&second.seg, pcb.unacked) << "the oldest remaining segment must stay in flight";
}

/* A SYN RTO retains the existing retransmission consequence. */
TEST(tcp_in, slowtmr_syn_expiry_keeps_legacy_path)
{
    register_noop_free_hooks();
    set_tmr_resolution(10);

    tcp_pcb pcb;
    init_established_pcb(pcb);
    pcb.private_state = SYN_SENT;
    pcb.cc_algo = &lwip_cc_algo;

    test_segment_storage storage;
    attach_unacked_segment(pcb, storage, 1000, 0);
    storage.seg.tcp_flags = TCP_SYN;
    TCPH_SET_FLAG(storage.seg.tcphdr, TCP_SYN);
    pcb.snd_nxt = 1001; /* SYN charges one sequence number */

    const int64_t t_arm = 1000000;
    tcp_rto_timer_start_if_needed(&pcb, t_arm);

    g_ip_output_calls = 0;
    tcp_slowtmr(&pcb, pcb.rto_deadline_us + 5);

    EXPECT_EQ(1, pcb.nrtx) << "SYN expiry must retransmit (legacy path)";
    EXPECT_EQ(1, g_ip_output_calls);
    EXPECT_NE(0, pcb.flags & TF_SYN_RTO_REXMITTED);
}
