/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef __LWIP_TCP_RTO_H__
#define __LWIP_TCP_RTO_H__

#include <stdint.h>
#include <stdbool.h>

#include "core/lwip/opt.h"
#include "core/lwip/tcp.h" /* struct tcp_pcb full definition for tcp_rexmit_timer_running() inline */
#include "core/proto/xlio_time.h"

#ifdef __cplusplus
extern "C" {
#endif

/* RTT/RTO constants in microseconds. */
#define TCP_RTO_INITIAL_US       ((int64_t)TCP_INITIAL_RTO_MS * 1000)
#define TCP_RTO_FALLBACK_US      ((int64_t)TCP_FALLBACK_RTO_MS * 1000)
#define TCP_RTO_FLOOR_MIN_US     ((int64_t)1000)
#define TCP_RTO_FLOOR_DEFAULT_US ((int64_t)600000)
#define TCP_RTO_MAX_US           ((int64_t)120000000)
#define TCP_OOSEQ_RTO_MIN_TICKS  TCP_MIN_RTO_TICKS

/* Warn on sustained timer-lock contention without logging isolated misses. */
#define XLIO_TCP_TIMER_SKIP_WARN_THRESHOLD 2

/* Slow-timer cadence in fast-timer ticks. */
#define TCP_SLOW_INTERVAL_FACTOR 2U

/* sa_us stores 8 * SRTT and must fit in int32_t. */
#if defined(__cplusplus)
static_assert(TCP_RTO_MAX_US <= 0x7FFFFFFF / 8,
              "TCP_RTO_MAX_US too large; sa_us would overflow int32_t");
static_assert(TCP_RTO_FLOOR_MIN_US > 0, "TCP_RTO_FLOOR_MIN_US must be positive");
static_assert(TCP_RTO_FLOOR_DEFAULT_US > 0, "TCP_RTO_FLOOR_DEFAULT_US must be positive");
static_assert(TCP_RTO_MAX_US > 0, "TCP_RTO_MAX_US must be positive");
static_assert(TCP_RTO_FLOOR_MIN_US <= TCP_RTO_FLOOR_DEFAULT_US,
              "TCP_RTO_FLOOR_MIN_US must not exceed TCP_RTO_FLOOR_DEFAULT_US");
static_assert(TCP_RTO_FLOOR_DEFAULT_US <= TCP_RTO_MAX_US,
              "TCP_RTO_FLOOR_DEFAULT_US must not exceed TCP_RTO_MAX_US");
static_assert(TCP_RTO_INITIAL_US >= TCP_RTO_FLOOR_DEFAULT_US,
              "TCP_RTO_INITIAL_US must not undershoot TCP_RTO_FLOOR_DEFAULT_US");
static_assert(TCP_RTO_INITIAL_US <= TCP_RTO_MAX_US,
              "TCP_RTO_INITIAL_US must not exceed TCP_RTO_MAX_US");
static_assert(TCP_RTO_FALLBACK_US >= TCP_RTO_FLOOR_DEFAULT_US,
              "TCP_RTO_FALLBACK_US must not undershoot TCP_RTO_FLOOR_DEFAULT_US");
static_assert(TCP_RTO_FALLBACK_US <= TCP_RTO_MAX_US,
              "TCP_RTO_FALLBACK_US must not exceed TCP_RTO_MAX_US");
#else
_Static_assert(TCP_RTO_MAX_US <= 0x7FFFFFFF / 8,
               "TCP_RTO_MAX_US too large; sa_us would overflow int32_t");
_Static_assert(TCP_RTO_FLOOR_MIN_US > 0, "TCP_RTO_FLOOR_MIN_US must be positive");
_Static_assert(TCP_RTO_FLOOR_DEFAULT_US > 0, "TCP_RTO_FLOOR_DEFAULT_US must be positive");
_Static_assert(TCP_RTO_MAX_US > 0, "TCP_RTO_MAX_US must be positive");
_Static_assert(TCP_RTO_FLOOR_MIN_US <= TCP_RTO_FLOOR_DEFAULT_US,
               "TCP_RTO_FLOOR_MIN_US must not exceed TCP_RTO_FLOOR_DEFAULT_US");
_Static_assert(TCP_RTO_FLOOR_DEFAULT_US <= TCP_RTO_MAX_US,
               "TCP_RTO_FLOOR_DEFAULT_US must not exceed TCP_RTO_MAX_US");
_Static_assert(TCP_RTO_INITIAL_US >= TCP_RTO_FLOOR_DEFAULT_US,
               "TCP_RTO_INITIAL_US must not undershoot TCP_RTO_FLOOR_DEFAULT_US");
_Static_assert(TCP_RTO_INITIAL_US <= TCP_RTO_MAX_US,
               "TCP_RTO_INITIAL_US must not exceed TCP_RTO_MAX_US");
_Static_assert(TCP_RTO_FALLBACK_US >= TCP_RTO_FLOOR_DEFAULT_US,
               "TCP_RTO_FALLBACK_US must not undershoot TCP_RTO_FLOOR_DEFAULT_US");
_Static_assert(TCP_RTO_FALLBACK_US <= TCP_RTO_MAX_US,
               "TCP_RTO_FALLBACK_US must not exceed TCP_RTO_MAX_US");
#endif

/* Pure RTT/RTO math helpers; no clock reads. */

/* Clamp estimator state to int32_t while reserving 0 as the no-sample sentinel. */
s32_t tcp_estimator_clamp_i32(int64_t value);

/* Set/get the process-wide additive RTO floor. Configuration is immutable
 * before the lwIP subsystem starts, so the floor needs no per-PCB storage.
 * The setter defensively clamps to [TCP_RTO_FLOOR_MIN_US, TCP_RTO_MAX_US].
 */
void tcp_rto_set_floor_us(int64_t floor_us);
s32_t tcp_rto_get_floor_us(void);

/* Clamp an RTO candidate to [configured floor, TCP_RTO_MAX_US] and return
 * the result as int32_t.
 */
s32_t tcp_rto_clamp_us(int64_t value);

/* Clamp a raw RTT sample to [1 usec, TCP_RTO_MAX_US]. */
int64_t tcp_rtt_sample_clamp_us(int64_t raw_sample_us);

/* RTO = (sa>>3) + max(sv, floor), clamped to the configured floor and maximum. */
s32_t tcp_rto_from_estimator_us(s32_t sa_us, s32_t sv_us);

/* Seed rto_us from a single handshake (SYN->SYN-ACK) RTT sample, RFC 6298 2.2:
 * RTO = 3 * R (clamped). Does NOT touch the VJ estimator (sa_us/sv_us), so the
 * first data sample still seeds it; only the initial RTO is influenced. */
s32_t tcp_rto_seed_from_handshake_us(int64_t raw_rtt_us);

/* Update VJ estimator with a fresh raw RTT sample (microseconds). On the
 * first sample (sa_us == 0), seeds sa_us = R << 3, sv_us = R << 1. On later
 * samples, runs the classic VJ form. Always updates pcb->rto_us via the
 * clamp helper.
 */
void tcp_rtt_estimator_update_us(struct tcp_pcb *pcb, int64_t raw_sample_us);

/* RTT sampling accepts new payload or SYN, never retransmits or FIN-only traffic. */
bool tcp_rtt_sample_should_start(const struct tcp_pcb *pcb, u32_t seg_seqno, u32_t seg_len,
                                 bool seg_is_syn);

bool tcp_rto_deadline_elapsed(const struct tcp_pcb *pcb, int64_t timer_now_us);

/* Clamped RFC 6298 5.7 fallback after SYN RTO retransmission. */
s32_t tcp_syn_fallback_rto_us(void);

/* Timer-state helpers maintain deadline ownership by pcb->unacked. */

/* Predicate for the coarse retransmission-age marker. Absolute expiry uses
 * rto_deadline_us.
 */
static inline bool tcp_rexmit_timer_running(const struct tcp_pcb *pcb)
{
    return pcb->rtime >= 0;
}

/* Clear only the absolute RTO deadline. Keep rtime and
 * ticks_since_data_sent running when an RTO retransmission is parked on
 * unsent, so retry and TCP_USER_TIMEOUT age remain observable while no
 * segment is in flight. */
void tcp_rto_deadline_clear(struct tcp_pcb *pcb);

/* Stop all retransmission timer markers. */
void tcp_rto_timer_stop(struct tcp_pcb *pcb);

/* Re-arm from now_us with the current RTO and reset age markers. */
void tcp_rto_timer_rearm(struct tcp_pcb *pcb, int64_t now_us);

/* Apply an ACK RTT sample before arming the resulting RTO. */
void tcp_rtt_estimator_update_and_rearm_us(struct tcp_pcb *pcb, int64_t ack_now_us,
                                           int64_t rearm_now_us);

/* Arm once per flight; the first in-flight segment and deadline become observable together. */
void tcp_rto_timer_start_if_needed(struct tcp_pcb *pcb, int64_t now_us);

/* OOSEQ retention timeout in microseconds with a three-tick minimum:
 * ooseq_rto = max(pcb->rto_us, TCP_OOSEQ_RTO_MIN_TICKS *
 * slow_interval_us) * TCP_OOSEQ_TIMEOUT.
 */
uint64_t tcp_ooseq_timeout_us(const struct tcp_pcb *pcb, uint64_t slow_interval_us);

/* Initialize estimator and deadline state. sa_us == 0 marks no RTT sample;
 * rto_us starts at the clamped RFC 6298 initial RTO. */
void tcp_rto_pcb_seed(struct tcp_pcb *pcb);

#ifdef __cplusplus
}
#endif

#endif /* __LWIP_TCP_RTO_H__ */
