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

/* --- RTT/RTO constants (microsecond domain) ---
 */
#define TCP_RTO_INITIAL_US             ((int64_t)TCP_INITIAL_RTO_MS * 1000)
#define TCP_RTO_FALLBACK_US            ((int64_t)TCP_FALLBACK_RTO_MS * 1000)
#define TCP_RTO_FLOOR_MIN_US           ((int64_t)1000)
#define TCP_RTO_FLOOR_DEFAULT_US       ((int64_t)600000)
#define TCP_RTO_MAX_US                 ((int64_t)120000000)
#define TCP_RTO_LEGACY_OOSEQ_MIN_TICKS TCP_MIN_RTO_TICKS

/* WARN-level log threshold for consecutive TCP timer trylock misses.
 * One miss postpones this socket's fast and slow timer work until its next
 * visit, one XLIO_TCP_TIMER_RESOLUTION_MSEC cadence later. Warn on the second
 * consecutive miss so sustained lock contention is visible without logging
 * every ordinary single-pass miss.
 */
#define XLIO_TCP_TIMER_SKIP_WARN_THRESHOLD 2

/* Slow-timer interval multiplier relative to the fast-timer cadence. lwIP
 * runs the slow timer every TCP_SLOW_INTERVAL_FACTOR fast-timer ticks. See
 * tcp_slowtmr() scheduling in tcp.c.
 */
#define TCP_SLOW_INTERVAL_FACTOR 2U

/* Compile-time sanity: estimator clamps fit in 32-bit signed and the
 * RTO floor / ceiling are both positive and ordered. The positivity
 * checks back the (uint32_t) cast in sockinfo_tcp::get_tcp_info() that
 * publishes tcpi_rto / tcpi_rtt / tcpi_rttvar: as long as the clamp
 * helpers are the only writers, the published values are non-negative.
 *
 * sa_us holds 8 * SRTT; the largest legal SRTT is TCP_RTO_MAX_US, so the
 * largest sa_us is 8 * TCP_RTO_MAX_US. That must fit in int32_t.
 */
/* Pin the compile-time defaults to the legal range. Runtime configuration is
 * independently bounded by tcp_rto_set_floor_us().
 */
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

/* --- Pure math helpers (no clock reads inside) ---
 *
 * These take values by argument and do not touch xlio_time TLS. Reachable
 * from unit tests without linking the full TCP stack.
 */

/* Clamp a wide intermediate value into the int32_t estimator field range.
 * Lower bound is 1, NOT 0: sa_us == 0 is the "no prior sample" sentinel
 * used by the first-sample branch. A clamp that could drive a post-sample
 * sa_us to 0 would re-fire the first-sample branch and overwrite a healthy
 * estimator with the next single sample.
 */
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

/* Validate a raw RTT sample. Samples <= 0 are defensively clamped to 1 usec,
 * although the RX ACK path rejects stale or noncausal timestamps before it
 * updates the estimator. Samples > TCP_RTO_MAX_US clamp down.
 */
int64_t tcp_rtt_sample_clamp_us(int64_t raw_sample_us);

/* RTO from the estimator with the additive floor: (sa>>3) + max(sv, floor),
 * clamped (see tcp_rto_from_estimator_us() for the shape rationale). */
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

/* True when the outgoing segment is eligible to start a fresh RTT sample:
 * no sample in flight (rttest_us == 0), not a retransmit (Karn: seqno not below
 * snd_nxt), and the segment either carries payload (seg_len > 0) or is the SYN
 * (seg_is_syn) whose SYN->SYN-ACK RTT seeds only the initial RTO and is closed
 * at establishment. FIN-only / control-only segments are excluded. */
bool tcp_rtt_sample_should_start(const struct tcp_pcb *pcb, u32_t seg_seqno, u32_t seg_len,
                                 bool seg_is_syn);

/* Predicate: should tcp_slowtmr() retransmit on this PCB at this timer
 * pass time? True iff outstanding unacked data exists, the deadline is
 * armed, and the timer pass time has reached it.
 */
bool tcp_rto_deadline_elapsed(const struct tcp_pcb *pcb, int64_t timer_now_us);

/* SYN/SYN-ACK fallback RTO value, applied after SYN RTO retransmission
 * when the upstream fallback condition holds, then clamped by the configured
 * floor and maximum.
 */
s32_t tcp_syn_fallback_rto_us(void);

/* --- Timer-state helpers ---
 *
 * Encode the invariant: any active rto_deadline_us implies non-NULL
 * pcb->unacked. These helpers centralize send, ACK, purge, and blocked-send
 * transitions. Expiry and PCB seeding also write deadline state as part of
 * their broader atomic state transitions.
 */

/* Marker predicate for the legacy rtime "timer running" semantic. rtime
 * is no longer compared to pcb->rto for RTO expiration (rto_deadline_us
 * owns that); it is still consumed by fast-retransmit dup-ACK counting
 * and by TCP_USER_TIMEOUT logic as a "did we recently send" marker.
 */
static inline bool tcp_rexmit_timer_running(const struct tcp_pcb *pcb)
{
    return pcb->rtime >= 0;
}

bool tcp_rto_timer_active(const struct tcp_pcb *pcb);

/* Clear only the absolute RTO deadline. Keep rtime and
 * ticks_since_data_sent running when an RTO retransmission is parked on
 * unsent, so retry and TCP_USER_TIMEOUT age remain observable while no
 * segment is in flight. */
void tcp_rto_deadline_clear(struct tcp_pcb *pcb);

/* Stop the retransmission timer: rtime = -1, ticks_since_data_sent = -1,
 * rto_deadline_us = 0. Called when all unacked data has been ACKed.
 */
void tcp_rto_timer_stop(struct tcp_pcb *pcb);

/* Re-arm the retransmission timer: rtime = 0, ticks_since_data_sent = 0,
 * rto_deadline_us = now_us + rto_us. Called after a partial ACK leaves
 * unacked data outstanding.
 */
void tcp_rto_timer_rearm(struct tcp_pcb *pcb, int64_t now_us);

/* Update the RTT estimator from an ACK timestamp and re-arm the deadline
 * against the freshly computed RTO. Used for partial ACKs that leave unacked
 * data outstanding.
 */
void tcp_rtt_estimator_update_and_rearm_us(struct tcp_pcb *pcb, int64_t ack_now_us,
                                           int64_t rearm_now_us);

/* Arm rto_deadline_us only if it is currently 0 (RFC 6298 5.1: "if the timer
 * is not running, start it"). Idempotent: a subsequent call within the same
 * flight does not restart the deadline. Caller MUST have just successfully
 * linked data to pcb->unacked.
 */
void tcp_rto_timer_start_if_needed(struct tcp_pcb *pcb, int64_t now_us);

/* OOSEQ retention timeout in microseconds. Preserves the legacy 3-tick
 * floor: ooseq_rto = max(pcb->rto_us, TCP_RTO_LEGACY_OOSEQ_MIN_TICKS *
 * slow_interval_us) * TCP_OOSEQ_TIMEOUT.
 */
uint64_t tcp_ooseq_timeout_us(const struct tcp_pcb *pcb, uint64_t slow_interval_us);

/* Seed/reset the RTT/RTO estimator and deadline state on a PCB. Initial RTO
 * comes from RFC 6298 (1 s), clamped by the configured floor. sa_us == 0 is
 * the "no prior sample" sentinel,
 * so sv_us is seeded to the initial RTO (matches the legacy lwIP seed
 * shape) and rto_us is set explicitly to skip the estimator until the
 * first valid sample arrives. Single source of truth used by tcp_pcb_init,
 * tcp_pcb_recycle, and the unit-test PCB reset helper.
 */
void tcp_rto_pcb_seed(struct tcp_pcb *pcb);

#ifdef __cplusplus
}
#endif

#endif /* __LWIP_TCP_RTO_H__ */
