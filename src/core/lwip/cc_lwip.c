/*-
 * Copyright (c) 2007-2008
 * 	Swinburne University of Technology, Melbourne, Australia.
 * Copyright (c) 2009-2010 Lawrence Stewart <lstewart@freebsd.org>
 * Copyright (c) 2010 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed at the Centre for Advanced Internet
 * Architectures, Swinburne University of Technology, by Lawrence Stewart and
 * James Healy, made possible in part by a grant from the Cisco University
 * Research Program Fund at Community Foundation Silicon Valley.
 *
 * Portions of this software were developed at the Centre for Advanced
 * Internet Architectures, Swinburne University of Technology, Melbourne,
 * Australia by David Hayes under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * This software was first released in 2007 by James Healy and Lawrence Stewart
 * whilst working on the NewTCP research project at Swinburne University of
 * Technology's Centre for Advanced Internet Architectures, Melbourne,
 * Australia, which was made possible in part by a grant from the Cisco
 * University Research Program Fund at Community Foundation Silicon Valley.
 * More details are available at:
 *   http://caia.swin.edu.au/urp/newtcp/
 */

/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "core/lwip/cc.h"
#include "core/lwip/tcp.h"

#if TCP_CC_ALGO_MOD

static void lwip_ack_received(struct tcp_pcb *pcb, uint16_t type);
static void lwip_cong_signal(struct tcp_pcb *pcb, uint32_t type);
static void lwip_conn_init(struct tcp_pcb *pcb);
static void lwip_post_recovery(struct tcp_pcb *pcb);

struct cc_algo lwip_cc_algo = {.name = "lwip",
                               .ack_received = lwip_ack_received,
                               .cong_signal = lwip_cong_signal,
                               .conn_init = lwip_conn_init,
                               .post_recovery = lwip_post_recovery};

static void lwip_ack_received(struct tcp_pcb *pcb, uint16_t type)
{

    /* Inflate the congestion window, but not if it means that
           the value overflows. */

    if (type == CC_DUPACK) {
        if ((u32_t)(pcb->cwnd + pcb->mss) > pcb->cwnd) {
            pcb->cwnd += pcb->mss;
        }
    } else if (type == CC_ACK) {
        /* Congestion window validation (RFC 2861 Section 3, the rule behind
         * Linux's tcp_is_cwnd_limited()): increase cwnd only if the window was
         * full when the ACK arrived. On a loss-free, receive-window-limited
         * flow the in-flight data stays below cwnd (the established-state
         * ssthresh is effectively infinite, so such a flow lives in slow
         * start), so ungated growth inflates cwnd on every ACK without bound -
         * in slow start and congestion avoidance alike - and saturates,
         * destabilizing the steady state. RFC 7661 (obsoletes 2861) allows
         * growth more broadly (validated phase); this gate is conservative
         * with respect to it. Utilization is measured as of before this ACK
         * (see tcp_inflight_pre_ack). */
        u32_t inflight_pre_ack = tcp_inflight_pre_ack(pcb->snd_nxt, pcb->lastack, pcb->acked);

        if (tcp_cwnd_may_grow(inflight_pre_ack, pcb->cwnd)) {
            if (pcb->cwnd < pcb->ssthresh) {
                u32_t increase = tcp_calc_slow_start_increment(pcb->acked, pcb->mss);
                if ((u32_t)(pcb->cwnd + increase) > pcb->cwnd) {
                    pcb->cwnd += increase;
                }
                LWIP_DEBUGF(TCP_CWND_DEBUG,
                            ("tcp_receive: slow start cwnd %" U32_F "\n", pcb->cwnd));
            } else {
                /* Congestion avoidance. mss^2/cwnd truncates to 0 once cwnd >
                 * mss^2; the floor at 1 (from 7c7981dc) keeps CA progressing and
                 * must be kept - removing it reintroduces the original stall. It
                 * is safe now that growth is gated on utilization above: the floor
                 * can only fire when the flow is genuinely cwnd-limited. */
                u32_t increment = ((u32_t)pcb->mss * (u32_t)pcb->mss) / pcb->cwnd;

                if (increment == 0) {
                    increment = 1;
                }

                u32_t new_cwnd = pcb->cwnd + increment;
                if (new_cwnd > pcb->cwnd) {
                    pcb->cwnd = new_cwnd;
                }
                LWIP_DEBUGF(TCP_CWND_DEBUG,
                            ("tcp_receive: congestion avoidance cwnd %" U32_F "\n", pcb->cwnd));
            }
        }
    }
}

static void lwip_cong_signal(struct tcp_pcb *pcb, uint32_t type)
{
    /* Set ssthresh to half of the minimum of the current
     * cwnd and the advertised window */
    if (pcb->cwnd > pcb->snd_wnd) {
        pcb->ssthresh = pcb->snd_wnd / 2;
    } else {
        pcb->ssthresh = pcb->cwnd / 2;
    }

    /* The minimum value for ssthresh should be 2 MSS */
    if ((u32_t)pcb->ssthresh < (u32_t)2 * pcb->mss) {
        LWIP_DEBUGF(TCP_FR_DEBUG,
                    ("tcp_receive: The minimum value for ssthresh %" U16_F
                     " should be min 2 mss %" U16_F "...\n",
                     pcb->ssthresh, 2 * pcb->mss));
        pcb->ssthresh = 2 * pcb->mss;
    }

    if (type == CC_NDUPACK) {
        pcb->cwnd = pcb->ssthresh + 3 * pcb->mss;
    } else if (type == CC_RTO) {
        pcb->cwnd = pcb->mss;
    }
}

static void lwip_post_recovery(struct tcp_pcb *pcb)
{
    pcb->cwnd = pcb->ssthresh;
}

static void lwip_conn_init(struct tcp_pcb *pcb)
{
    pcb->cwnd = tcp_calc_initial_cwnd(pcb->mss);
    pcb->ssthresh = tcp_calc_initial_ssthresh();
}

#endif // TCP_CC_ALGO_MOD
