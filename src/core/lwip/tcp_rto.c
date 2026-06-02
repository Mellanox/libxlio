/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "core/lwip/tcp_rto.h"
#include "core/lwip/tcp.h"
#include "core/lwip/tcp_impl.h"

static s32_t g_tcp_rto_floor_us = (s32_t)TCP_RTO_FLOOR_DEFAULT_US;

/* --- Pure math helpers --- */

void tcp_rto_set_floor_us(int64_t floor_us)
{
    if (floor_us < TCP_RTO_FLOOR_MIN_US) {
        floor_us = TCP_RTO_FLOOR_MIN_US;
    } else if (floor_us > TCP_RTO_MAX_US) {
        floor_us = TCP_RTO_MAX_US;
    }
    g_tcp_rto_floor_us = (s32_t)floor_us;
}

s32_t tcp_rto_get_floor_us(void)
{
    return g_tcp_rto_floor_us;
}

static inline s32_t tcp_rto_clamp_with_floor_us(int64_t value, s32_t floor_us)
{
    if (value < floor_us) {
        return floor_us;
    }
    if (value > TCP_RTO_MAX_US) {
        return (s32_t)TCP_RTO_MAX_US;
    }
    return (s32_t)value;
}

s32_t tcp_estimator_clamp_i32(int64_t value)
{
    if (value < 1) {
        return 1;
    }
    if (value > 0x7FFFFFFF) {
        return 0x7FFFFFFF;
    }
    return (s32_t)value;
}

s32_t tcp_rto_clamp_us(int64_t value)
{
    return tcp_rto_clamp_with_floor_us(value, tcp_rto_get_floor_us());
}

int64_t tcp_rtt_sample_clamp_us(int64_t raw_sample_us)
{
    if (raw_sample_us <= 0) {
        return 1;
    }
    if (raw_sample_us > TCP_RTO_MAX_US) {
        return TCP_RTO_MAX_US;
    }
    return raw_sample_us;
}

s32_t tcp_rto_from_estimator_us(s32_t sa_us, s32_t sv_us)
{
    /* Additive floor: RTO = SRTT + max(4*RTTVAR, floor) (sa_us = 8*SRTT,
     * sv_us ~ 4*RTTVAR). The floor rides on the variance term instead of
     * substituting for the whole RTO, so under load a delayed ACK no longer
     * trips the timer; at idle (SRTT ~ 0) it is still approximately the floor. */
    const s32_t floor_us = tcp_rto_get_floor_us();
    int64_t var_term = (int64_t)sv_us;
    if (var_term < floor_us) {
        var_term = floor_us;
    }
    int64_t rto = ((int64_t)sa_us >> 3) + var_term;
    return tcp_rto_clamp_with_floor_us(rto, floor_us);
}

s32_t tcp_rto_seed_from_handshake_us(int64_t raw_rtt_us)
{
    /* RFC 6298 2.2 first-measurement RTO from a single sample R:
     * SRTT = R, RTTVAR = R/2, RTO = SRTT + 4*RTTVAR = 3R. Computed without
     * touching the VJ estimator (sa_us/sv_us stay 0) so the first data
     * sample still seeds the estimator; this only seeds rto_us. */
    int64_t r = tcp_rtt_sample_clamp_us(raw_rtt_us);
    return tcp_rto_clamp_us(r + 2 * r);
}

void tcp_rtt_estimator_update_us(struct tcp_pcb *pcb, int64_t raw_sample_us)
{
    int64_t m_us = tcp_rtt_sample_clamp_us(raw_sample_us);

    if (pcb->sa_us == 0) {
        const s32_t previous_sv_us = pcb->sv_us;

        /* First valid RTT sample: initialize the VJ estimator directly
         * (SRTT = R, RTTVAR = R/2; stored as sa_us = R << 3,
         * sv_us = R << 1) instead of mixing the sample into the
         * no-sample variance seed.
         *
         * The "previous_sv_us > TCP_RTO_INITIAL_US" branch preserves the
         * SYN fallback. tcp_handle_syn_established() raises sv_us to
         * TCP_RTO_FALLBACK_US (3s) when the SYN was retransmitted under
         * RFC 6298 5.7; without this branch the first post-handshake
         * datacenter-RTT (a few hundred us) would shrink sv_us back to
         * ~m<<1 and defeat the "stay conservative after a lossy
         * handshake" semantics. The threshold is "> TCP_RTO_INITIAL_US"
         * (1s), not the specific TCP_RTO_FALLBACK_US value, so future
         * paths that elevate sv_us conservatively above the initial
         * seed inherit the same protection.
         */
        pcb->sa_us = tcp_estimator_clamp_i32(m_us << 3);
        if (previous_sv_us > TCP_RTO_INITIAL_US) {
            pcb->sv_us = previous_sv_us;
        } else {
            pcb->sv_us = tcp_estimator_clamp_i32(m_us << 1);
        }
        pcb->rto_us = tcp_rto_from_estimator_us(pcb->sa_us, pcb->sv_us);
        return;
    }

    /* Later samples: classic VJ; RTO via tcp_rto_from_estimator_us(). */
    int64_t err_us = m_us - ((int64_t)pcb->sa_us >> 3);
    int64_t sa_us = (int64_t)pcb->sa_us + err_us;
    int64_t abs_err_us = err_us < 0 ? -err_us : err_us;
    int64_t sv_us = (int64_t)pcb->sv_us + (abs_err_us - ((int64_t)pcb->sv_us >> 2));

    pcb->sa_us = tcp_estimator_clamp_i32(sa_us);
    pcb->sv_us = tcp_estimator_clamp_i32(sv_us);
    pcb->rto_us = tcp_rto_from_estimator_us(pcb->sa_us, pcb->sv_us);
}

bool tcp_rtt_sample_should_start(const struct tcp_pcb *pcb, u32_t seg_seqno, u32_t seg_len,
                                 bool seg_is_syn)
{
    /* Karn: no sample in flight and not a retransmit. A segment must also carry
     * payload (seg_len > 0) to seed a data RTT sample; the one exception is the
     * SYN (zero length), whose SYN->SYN-ACK RTT seeds only the initial RTO and
     * is closed at establishment. This excludes FIN-only / control-only
     * segments from starting a sample. */
    return pcb->rttest_us == 0 && !TCP_SEQ_LT(seg_seqno, pcb->snd_nxt) &&
        (seg_len > 0 || seg_is_syn);
}

bool tcp_rto_deadline_elapsed(const struct tcp_pcb *pcb, int64_t timer_now_us)
{
    return pcb->unacked != NULL && pcb->rto_deadline_us != 0 &&
        timer_now_us >= pcb->rto_deadline_us;
}

s32_t tcp_syn_fallback_rto_us(void)
{
    return tcp_rto_clamp_us(TCP_RTO_FALLBACK_US);
}

/* --- Timer-state helpers --- */

bool tcp_rto_timer_active(const struct tcp_pcb *pcb)
{
    return pcb->unacked != NULL && pcb->rto_deadline_us != 0;
}

void tcp_rto_deadline_clear(struct tcp_pcb *pcb)
{
    pcb->rto_deadline_us = 0;
}

void tcp_rto_timer_stop(struct tcp_pcb *pcb)
{
    pcb->rtime = -1;
    pcb->ticks_since_data_sent = -1;
    pcb->rto_deadline_us = 0;
}

void tcp_rto_timer_rearm(struct tcp_pcb *pcb, int64_t now_us)
{
    pcb->rtime = 0;
    pcb->ticks_since_data_sent = 0;
    pcb->rto_deadline_us = now_us + (int64_t)pcb->rto_us;
}

void tcp_rtt_estimator_update_and_rearm_us(struct tcp_pcb *pcb, int64_t ack_now_us,
                                           int64_t rearm_now_us)
{
    tcp_rtt_estimator_update_us(pcb, ack_now_us - pcb->rttest_us);
    pcb->rttest_us = 0;
    tcp_rto_timer_rearm(pcb, rearm_now_us);
}

void tcp_rto_timer_start_if_needed(struct tcp_pcb *pcb, int64_t now_us)
{
    if (pcb->rto_deadline_us == 0) {
        pcb->rto_deadline_us = now_us + (int64_t)pcb->rto_us;
        if (pcb->rtime == -1) {
            pcb->rtime = 0;
        }
        if (pcb->ticks_since_data_sent == -1) {
            pcb->ticks_since_data_sent = 0;
        }
    }
}

uint64_t tcp_ooseq_timeout_us(const struct tcp_pcb *pcb, uint64_t slow_interval_us)
{
    uint64_t legacy_floor_us = (uint64_t)TCP_RTO_LEGACY_OOSEQ_MIN_TICKS * slow_interval_us;
    uint64_t rto_us_pos = pcb->rto_us > 0 ? (uint64_t)pcb->rto_us : 0;
    uint64_t ooseq_rto_us = rto_us_pos > legacy_floor_us ? rto_us_pos : legacy_floor_us;

    return ooseq_rto_us * (uint64_t)TCP_OOSEQ_TIMEOUT;
}

void tcp_rto_pcb_seed(struct tcp_pcb *pcb)
{
    pcb->rttest_us = 0;
    /* rtseq is dead state when rttest_us == 0 (the eligibility check in
     * tcp_receive short-circuits on rttest_us first). Cleared here anyway
     * so debug dumps of a recycled PCB do not show the previous
     * lifetime's sequence number.
     */
    pcb->rtseq = 0;
    pcb->sa_us = 0;
    pcb->sv_us = (s32_t)TCP_RTO_INITIAL_US;
    pcb->rto_us = tcp_rto_clamp_us(TCP_RTO_INITIAL_US);
    pcb->rto_deadline_us = 0;
}
