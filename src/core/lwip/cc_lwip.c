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
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
        if (pcb->cwnd < pcb->ssthresh) {
            /* Slow start: Increment cwnd by the number of bytes acknowledged.
             * RFC 5681: "During slow start, a TCP increments cwnd by at most SMSS
             * bytes for each ACK received that cumulatively acknowledges new data."
             * This means cwnd grows by N*MSS when N segments are ACKed, giving
             * exponential growth (e.g., cwnd doubles per RTT if all segments are ACKed).
             *
             * Fixed from incorrect linear growth (cwnd += mss) to proper exponential
             * growth (cwnd += acked). This matches modern TCP implementations including
             * Linux CUBIC and is critical for TSO where one ACK can acknowledge many
             * segments (e.g., 64KB = 44 segments at 1460 MSS).
             */
            if ((u32_t)(pcb->cwnd + pcb->acked) > pcb->cwnd) {
                pcb->cwnd += pcb->acked;
            }
            LWIP_DEBUGF(TCP_CWND_DEBUG, ("tcp_receive: slow start cwnd %" U32_F "\n", pcb->cwnd));
        } else {
            u32_t new_cwnd = (pcb->cwnd + ((u32_t)pcb->mss * (u32_t)pcb->mss) / pcb->cwnd);
            if (new_cwnd > pcb->cwnd) {
                pcb->cwnd = new_cwnd;
            }
            LWIP_DEBUGF(TCP_CWND_DEBUG,
                        ("tcp_receive: congestion avoidance cwnd %" U32_F "\n", pcb->cwnd));
        }
    }
}

static void lwip_cong_signal(struct tcp_pcb *pcb, uint32_t type)
{
    /* Use centralized TSO-aware congestion recovery logic */
    bool is_rto = (type == CC_RTO);
    tcp_reset_cwnd_on_congestion(pcb, is_rto);
}

static void lwip_post_recovery(struct tcp_pcb *pcb)
{
    pcb->cwnd = pcb->ssthresh;
}

static void lwip_conn_init(struct tcp_pcb *pcb)
{
    /* Only set cwnd if it's still uninitialized (placeholder value of 1).
     * Otherwise, preserve the value set by tcp_set_initial_cwnd_ssthresh().
     */
    if (pcb->cwnd == 1) {
        tcp_set_initial_cwnd_ssthresh(pcb);
    }
}

#endif // TCP_CC_ALGO_MOD
