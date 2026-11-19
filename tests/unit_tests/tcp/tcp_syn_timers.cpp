/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/* tcp_slowtmr() SYN-phase timers: the per-socket SYN(-ACK) retransmit budget
 * (TCP_SYNCNT / net.ipv4.tcp_synack_retries) and its interaction with the RTO
 * deadline and TCP_USER_TIMEOUT. */

#include <gtest/gtest.h>
#include <cstring>

#include "core/lwip/tcp.h"
#include "core/lwip/tcp_impl.h"
#include "core/lwip/tcp_rto.h"

namespace {

static int g_syn_ip_output_calls;
static int g_syn_error_calls;
static err_t g_syn_last_error;

static void syn_capture_error(void *arg, err_t err)
{
    (void)arg;
    ++g_syn_error_calls;
    g_syn_last_error = err;
}

static err_t syn_record_output(struct pbuf *p, struct tcp_seg *seg, void *pcb, u16_t flags)
{
    (void)p;
    (void)seg;
    (void)pcb;
    (void)flags;
    ++g_syn_ip_output_calls;
    return ERR_OK;
}

static void syn_noop_seg_free(void *p_conn, struct tcp_seg *seg)
{
    (void)p_conn;
    (void)seg;
}

static void syn_noop_tx_pbuf_free(void *p_conn, struct pbuf *p)
{
    (void)p_conn;
    (void)p;
}

static void syn_noop_state_observer(void *p_conn, enum tcp_state state)
{
    (void)p_conn;
    (void)state;
}

static struct tcp_seg *syn_no_seg_alloc(void *p_conn)
{
    (void)p_conn;
    return nullptr;
}

struct syn_seg_storage {
    tcp_seg seg {};
    pbuf p {};
    unsigned char bytes[TCP_HLEN + 16] {};
};

/* Each test gets its own tcp_ticks clock, timer resolution, and hooks. */
struct syn_test_guard {
    syn_test_guard()
        : saved_ticks(tcp_ticks)
        , saved_slow_interval(slow_tmr_interval)
        , saved_seg_alloc(external_tcp_seg_alloc)
    {
        set_tmr_resolution(100);
        register_tcp_seg_alloc(syn_no_seg_alloc);
        register_tcp_seg_free(syn_noop_seg_free);
        register_tcp_tx_pbuf_free(syn_noop_tx_pbuf_free);
        register_tcp_state_observer(syn_noop_state_observer);
        g_syn_ip_output_calls = 0;
        g_syn_error_calls = 0;
        g_syn_last_error = ERR_OK;
    }

    ~syn_test_guard()
    {
        tcp_ticks = saved_ticks;
        slow_tmr_interval = saved_slow_interval;
        register_tcp_seg_alloc(saved_seg_alloc);
    }

    u32_t saved_ticks;
    u32_t saved_slow_interval;
    tcp_seg_alloc_fn saved_seg_alloc;
};

/* A pcb in a SYN phase with one segment in flight. The RTO deadline and the
 * retransmit count are set by each test. */
static void init_syn_pcb(tcp_pcb &pcb, syn_seg_storage &storage, enum tcp_state state)
{
    std::memset(&pcb, 0, sizeof(pcb));
    tcp_rto_pcb_seed(&pcb);
    pcb.private_state = state;
    pcb.cc_algo = &none_cc_algo;
    pcb.mss = 1460;
    pcb.cwnd = 1460;
    pcb.snd_wnd = 1460;
    pcb.snd_wnd_max = 1460;
    pcb.lastack = 1000;
    pcb.snd_nxt = 1001;
    pcb.snd_lbb = 1001;
    pcb.rcv_wnd = 65535;
    pcb.rcv_ann_wnd = 65535;
    pcb.ip_output = syn_record_output;
    pcb.errf = syn_capture_error;
    pcb.tmr = tcp_ticks;

    storage.seg = {};
    storage.p = {};
    std::memset(storage.bytes, 0, sizeof(storage.bytes));
    storage.p.payload = storage.bytes;
    storage.p.len = TCP_HLEN;
    storage.p.tot_len = TCP_HLEN;
    storage.p.type = PBUF_RAM;
    storage.p.ref = 1;
    storage.seg.p = &storage.p;
    storage.seg.len = 0;
    storage.seg.seqno = 1000;
    storage.seg.tcphdr = reinterpret_cast<tcp_hdr *>(storage.bytes);
    storage.seg.tcphdr->seqno = htonl(1000);
    TCPH_HDRLEN_FLAGS_SET(storage.seg.tcphdr, TCP_HLEN / 4, TCP_SYN);
    pcb.unacked = &storage.seg;
    pcb.last_unacked = &storage.seg;

    pcb.rtime = 0;
    pcb.ticks_since_data_sent = 0;
}

/* One slow-timer pass: tcp_ticks advances once per pass, as in xlio_lwip. */
static void syn_slowtmr_tick(tcp_pcb &pcb)
{
    ++tcp_ticks;
    tcp_slowtmr(&pcb, (int64_t)tcp_ticks * slow_tmr_interval * 1000);
}

} // namespace

/* A TCP_SYNCNT below the default lowers the abort point: with the per-socket
 * budget reached and the RTO deadline over, the pass aborts with ERR_TIMEOUT. */
TEST(tcp_syn_timers, syn_sent_aborts_at_per_socket_budget)
{
    syn_test_guard guard;
    tcp_pcb pcb;
    syn_seg_storage storage;
    init_syn_pcb(pcb, storage, SYN_SENT);
    pcb.syn_max_rtx = 3;
    pcb.nrtx = 3;
    pcb.rto_deadline_us = 1;

    syn_slowtmr_tick(pcb);

    EXPECT_EQ(1, g_syn_error_calls);
    EXPECT_EQ(ERR_TIMEOUT, g_syn_last_error);
    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
}

/* At the budget the abort waits for the last RTO window: no abort while the
 * deadline runs, and an abort with no extra retransmit when it elapses. The
 * total connect-failure time then covers the full backoff series, as in Linux. */
TEST(tcp_syn_timers, syn_abort_waits_for_the_last_rto_window)
{
    syn_test_guard guard;
    tcp_pcb pcb;
    syn_seg_storage storage;
    init_syn_pcb(pcb, storage, SYN_SENT);
    pcb.syn_max_rtx = 3;
    pcb.nrtx = 3;
    pcb.rto_deadline_us = (int64_t)(tcp_ticks + 5) * slow_tmr_interval * 1000;

    for (int pass = 1; pass <= 4; ++pass) {
        syn_slowtmr_tick(pcb);
        EXPECT_EQ(0, g_syn_error_calls) << "aborted before the last window, pass " << pass;
    }
    syn_slowtmr_tick(pcb);

    EXPECT_EQ(1, g_syn_error_calls);
    EXPECT_EQ(ERR_TIMEOUT, g_syn_last_error);
    EXPECT_EQ(0, g_syn_ip_output_calls) << "no retransmit past the budget";
    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
}

/* A budget above TCP_MAXRTX (12) keeps retransmitting past 12: the data retry
 * limit does not apply to the SYN states. */
TEST(tcp_syn_timers, syn_budget_above_data_retry_limit_retransmits)
{
    syn_test_guard guard;
    tcp_pcb pcb;
    syn_seg_storage storage;
    init_syn_pcb(pcb, storage, SYN_SENT);
    pcb.syn_max_rtx = 13;
    pcb.nrtx = 12;
    pcb.rto_deadline_us = 1;

    syn_slowtmr_tick(pcb);

    EXPECT_EQ(0, g_syn_error_calls) << "the data retry limit stole the SYN abort";
    EXPECT_EQ(SYN_SENT, get_tcp_state(&pcb));
    EXPECT_EQ(13, pcb.nrtx);
}

/* A budget at or above TCP_MAXRTX (12) stays with the SYN abort: the data
 * retry limit must not steal the wait with an early ERR_ABRT. */
TEST(tcp_syn_timers, syn_budget_above_data_retry_limit_keeps_the_wait)
{
    syn_test_guard guard;
    tcp_pcb pcb;
    syn_seg_storage storage;
    init_syn_pcb(pcb, storage, SYN_SENT);
    pcb.syn_max_rtx = 12;
    pcb.nrtx = 12;
    pcb.rto_deadline_us = (int64_t)(tcp_ticks + 5) * slow_tmr_interval * 1000;

    for (int pass = 1; pass <= 4; ++pass) {
        syn_slowtmr_tick(pcb);
        EXPECT_EQ(0, g_syn_error_calls) << "an abort stole the last window, pass " << pass;
    }
    syn_slowtmr_tick(pcb);

    EXPECT_EQ(1, g_syn_error_calls);
    EXPECT_EQ(ERR_TIMEOUT, g_syn_last_error) << "the abort must come from the SYN budget";
    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
}

/* A cleared RTO deadline at the budget aborts at once: the budget stays a hard
 * bound when a retransmission is parked by a local send failure. */
TEST(tcp_syn_timers, syn_budget_with_cleared_deadline_aborts_at_once)
{
    syn_test_guard guard;
    tcp_pcb pcb;
    syn_seg_storage storage;
    init_syn_pcb(pcb, storage, SYN_SENT);
    pcb.syn_max_rtx = 3;
    pcb.nrtx = 3;
    pcb.rto_deadline_us = 0;

    syn_slowtmr_tick(pcb);

    EXPECT_EQ(1, g_syn_error_calls);
    EXPECT_EQ(ERR_TIMEOUT, g_syn_last_error);
    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
}

/* SYN_RCVD follows the same budget: at the SYN-ACK retransmit budget with the
 * last RTO window over, the pass aborts. */
TEST(tcp_syn_timers, syn_rcvd_aborts_at_synack_budget)
{
    syn_test_guard guard;
    tcp_pcb pcb;
    syn_seg_storage storage;
    init_syn_pcb(pcb, storage, SYN_RCVD);
    pcb.syn_max_rtx = 2;
    pcb.nrtx = 2;
    pcb.rto_deadline_us = 1;

    syn_slowtmr_tick(pcb);

    EXPECT_EQ(1, g_syn_error_calls);
    EXPECT_EQ(ERR_TIMEOUT, g_syn_last_error);
    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
}

/* A SYN_RCVD pcb inside its SYN-ACK budget survives past 20 s of handshake
 * silence: the budget is the bound, there is no fixed watchdog. */
TEST(tcp_syn_timers, syn_rcvd_inside_budget_survives_twenty_seconds)
{
    syn_test_guard guard;
    tcp_pcb pcb;
    syn_seg_storage storage;
    init_syn_pcb(pcb, storage, SYN_RCVD);
    pcb.syn_max_rtx = 10;
    pcb.nrtx = 4;
    pcb.rto_deadline_us = INT64_MAX;
    /* The last received segment is 25 s in the past. */
    pcb.tmr = tcp_ticks - tcp_ms_to_ticks(25000);

    syn_slowtmr_tick(pcb);

    EXPECT_EQ(0, g_syn_error_calls) << "a fixed SYN_RCVD watchdog fired";
    EXPECT_EQ(SYN_RCVD, get_tcp_state(&pcb));
}

/* A SYN-ACK budget of 0 (net.ipv4.tcp_synack_retries=0) disables SYN-ACK
 * retransmissions: the pcb aborts at the first elapsed deadline, as in the
 * kernel. In SYN_RCVD the field is the budget itself, not "unset". */
TEST(tcp_syn_timers, syn_rcvd_zero_budget_aborts_without_retransmit)
{
    syn_test_guard guard;
    tcp_pcb pcb;
    syn_seg_storage storage;
    init_syn_pcb(pcb, storage, SYN_RCVD);
    pcb.syn_max_rtx = 0;
    pcb.nrtx = 0;
    pcb.rto_deadline_us = 1;

    syn_slowtmr_tick(pcb);

    EXPECT_EQ(1, g_syn_error_calls);
    EXPECT_EQ(ERR_TIMEOUT, g_syn_last_error);
    EXPECT_EQ(0, g_syn_ip_output_calls) << "a zero budget must not retransmit";
    EXPECT_EQ(CLOSED, get_tcp_state(&pcb));
}

/* The user timeout does not govern SYN_RCVD: the listener timeout never
 * preempts the SYN-ACK budget, as in Linux. */
TEST(tcp_syn_timers, syn_rcvd_ignores_user_timeout)
{
    syn_test_guard guard;
    tcp_pcb pcb;
    syn_seg_storage storage;
    init_syn_pcb(pcb, storage, SYN_RCVD);
    pcb.syn_max_rtx = 10;
    pcb.nrtx = 4;
    pcb.rto_deadline_us = INT64_MAX;
    pcb.user_timeout_ms = 1000;
    pcb.ticks_since_data_sent = tcp_ms_to_ticks(5000);

    syn_slowtmr_tick(pcb);

    EXPECT_EQ(0, g_syn_error_calls) << "the user timeout fired in SYN_RCVD";
    EXPECT_EQ(SYN_RCVD, get_tcp_state(&pcb));
}

/* Below the budget the connection stays up and the elapsed deadline
 * retransmits the SYN instead of aborting. */
TEST(tcp_syn_timers, syn_sent_retransmits_below_budget)
{
    syn_test_guard guard;
    tcp_pcb pcb;
    syn_seg_storage storage;
    init_syn_pcb(pcb, storage, SYN_SENT);
    pcb.syn_max_rtx = 3;
    pcb.nrtx = 2;
    pcb.rto_deadline_us = 1;

    syn_slowtmr_tick(pcb);

    EXPECT_EQ(0, g_syn_error_calls);
    EXPECT_EQ(SYN_SENT, get_tcp_state(&pcb));
    EXPECT_EQ(3, pcb.nrtx);
    EXPECT_GE(g_syn_ip_output_calls, 1) << "the SYN must be retransmitted";
}
