/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#ifndef __LWIP_TCP_IMPL_H__
#define __LWIP_TCP_IMPL_H__

#include "core/lwip/opt.h"

#include "core/lwip/tcp.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Functions for interfacing with TCP: */
#if defined(__GNUC__) && (((__GNUC__ == 4) && (__GNUC_MINOR__ >= 4)) || (__GNUC__ > 4))
#pragma GCC visibility push(hidden)
#endif

void tcp_tmr(struct tcp_pcb *pcb); /* Must be called every (slow_tmr_interval / 2) ms. */
/* It is also possible to call these two functions at the right
   intervals (instead of calling tcp_tmr()). */
void tcp_slowtmr(struct tcp_pcb *pcb);
void tcp_fasttmr(struct tcp_pcb *pcb);

void L3_level_tcp_input(struct pbuf *p, struct tcp_pcb *pcb);

/* Used within the TCP code only: */
struct tcp_pcb *tcp_alloc(u8_t prio);
struct pbuf *tcp_tx_pbuf_alloc(struct tcp_pcb *pcb, u32_t length, pbuf_type type, pbuf_desc *desc,
                               struct pbuf *p_buff);
void tcp_tx_preallocted_buffers_free(struct tcp_pcb *pcb);
void tcp_tx_pbuf_free(struct tcp_pcb *pcb, struct pbuf *pbuf);
void tcp_abandon(struct tcp_pcb *pcb, int reset);
err_t tcp_send_empty_ack(struct tcp_pcb *pcb);
void tcp_split_segment(struct tcp_pcb *pcb, struct tcp_seg *seg, u32_t wnd);
void tcp_rexmit(struct tcp_pcb *pcb);
void tcp_rexmit_rto(struct tcp_pcb *pcb);
void tcp_rexmit_fast(struct tcp_pcb *pcb);
u32_t tcp_update_rcv_ann_wnd(struct tcp_pcb *pcb);
void set_tmr_resolution(u32_t v);

#if defined(__GNUC__) && (((__GNUC__ == 4) && (__GNUC_MINOR__ >= 4)) || (__GNUC__ > 4))
#pragma GCC visibility pop
#endif

#define tcp_nodelay_treshold(tpcb)                                                                 \
    (((tpcb)->unsent != NULL) && ((tpcb)->unsent->len >= lwip_tcp_nodelay_treshold))

/**
 * This is the Nagle algorithm: try to combine user data to send as few TCP
 * segments as possible. Only send if
 * - no previously transmitted data on the connection remains unacknowledged or
 * - the TF_NODELAY flag is set (nagle algorithm turned off for this pcb)
 *   and unset length is above treshold or
 * - the only unsent segment is at least pcb->mss bytes long (or there is more
 *   than one unsent segment - with lwIP, this can happen although unsent->len < mss)
 * - or if we are in fast-retransmit (TF_INFR)
 */
#define tcp_do_output_nagle(tpcb)                                                                  \
    ((((tpcb)->unacked == NULL) || (((tpcb)->flags & TF_NODELAY) && tcp_nodelay_treshold(tpcb)) || \
      ((tpcb)->flags & TF_INFR) ||                                                                 \
      (((tpcb)->unsent != NULL) &&                                                                 \
       (((tpcb)->unsent->next != NULL) || ((tpcb)->unsent->len >= (tpcb)->mss))))                  \
         ? 1                                                                                       \
         : 0)
#define tcp_output_nagle(tpcb) (tcp_do_output_nagle(tpcb) ? tcp_output(tpcb) : ERR_OK)

#define TCP_SEQ_LT(a, b)  ((s32_t)((u32_t)(a) - (u32_t)(b)) < 0)
#define TCP_SEQ_LEQ(a, b) ((s32_t)((u32_t)(a) - (u32_t)(b)) <= 0)
#define TCP_SEQ_GT(a, b)  ((s32_t)((u32_t)(a) - (u32_t)(b)) > 0)
#define TCP_SEQ_GEQ(a, b) ((s32_t)((u32_t)(a) - (u32_t)(b)) >= 0)
/* is b<=a<=c? */
#define TCP_SEQ_BETWEEN(a, b, c) (TCP_SEQ_GEQ(a, b) && TCP_SEQ_LEQ(a, c))
#define TCP_FIN                  0x01U
#define TCP_SYN                  0x02U
#define TCP_RST                  0x04U
#define TCP_PSH                  0x08U
#define TCP_ACK                  0x10U
#define TCP_URG                  0x20U
#define TCP_ECE                  0x40U
#define TCP_CWR                  0x80U

#define TCP_FLAGS 0x3fU

/* Length of the TCP header, excluding options. */
#ifndef TCP_HLEN
#define TCP_HLEN 20
#endif

#define TCP_FIN_WAIT_TIMEOUT 20000 /* milliseconds */
#define TCP_SYN_RCVD_TIMEOUT 20000 /* milliseconds */

#define TCP_OOSEQ_TIMEOUT 6U /* x RTO */

#ifndef TCP_MSL
#define TCP_MSL 60000UL /* The maximum segment lifetime in milliseconds */
#endif

/* Keepalive values, compliant with RFC 1122. Don't change this unless you know what you're doing */
#ifndef TCP_KEEPIDLE_DEFAULT
#define TCP_KEEPIDLE_DEFAULT 7200000UL /* Default KEEPALIVE timer in milliseconds */
#endif

#ifndef TCP_KEEPINTVL_DEFAULT
#define TCP_KEEPINTVL_DEFAULT 75000UL /* Default Time between KEEPALIVE probes in milliseconds */
#endif

#ifndef TCP_KEEPCNT_DEFAULT
#define TCP_KEEPCNT_DEFAULT 9U /* Default Counter for KEEPALIVE probes */
#endif

#define TCP_MAXIDLE TCP_KEEPCNT_DEFAULT *TCP_KEEPINTVL_DEFAULT /* Maximum KEEPALIVE probe time */

/* Fields are (of course) in network byte order.
 * Some fields are converted to host byte order in tcp_input().
 */
PACK_STRUCT_BEGIN
struct tcp_hdr {
    PACK_STRUCT_FIELD(u16_t src);
    PACK_STRUCT_FIELD(u16_t dest);
    PACK_STRUCT_FIELD(u32_t seqno);
    PACK_STRUCT_FIELD(u32_t ackno);
    PACK_STRUCT_FIELD(u16_t _hdrlen_rsvd_flags);
    PACK_STRUCT_FIELD(u16_t wnd);
    PACK_STRUCT_FIELD(u16_t chksum);
    PACK_STRUCT_FIELD(u16_t urgp);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END

#define TCPH_OFFSET(phdr) (ntohs((phdr)->_hdrlen_rsvd_flags) >> 8)
#define TCPH_HDRLEN(phdr) (ntohs((phdr)->_hdrlen_rsvd_flags) >> 12)
#define TCPH_FLAGS(phdr)  (ntohs((phdr)->_hdrlen_rsvd_flags) & TCP_FLAGS)

#define TCPH_OFFSET_SET(phdr, offset)                                                              \
    (phdr)->_hdrlen_rsvd_flags = htons(((offset) << 8) | TCPH_FLAGS(phdr))
#define TCPH_HDRLEN_SET(phdr, len)                                                                 \
    (phdr)->_hdrlen_rsvd_flags = htons(((len) << 12) | TCPH_FLAGS(phdr))
#define TCPH_FLAGS_SET(phdr, flags)                                                                \
    (phdr)->_hdrlen_rsvd_flags =                                                                   \
        (((phdr)->_hdrlen_rsvd_flags & PP_HTONS((u16_t)(~(u16_t)(TCP_FLAGS)))) | htons(flags))
#define TCPH_HDRLEN_FLAGS_SET(phdr, len, flags)                                                    \
    (phdr)->_hdrlen_rsvd_flags = htons(((len) << 12) | (flags))

#define TCPH_SET_FLAG(phdr, flags)                                                                 \
    (phdr)->_hdrlen_rsvd_flags = ((phdr)->_hdrlen_rsvd_flags | htons(flags))
#define TCPH_UNSET_FLAG(phdr, flags)                                                               \
    (phdr)->_hdrlen_rsvd_flags = (phdr)->_hdrlen_rsvd_flags & (~htons((flags) & (TCP_FLAGS)))

#define TCP_TCPLEN(seg)                                                                            \
    ((seg)->len + (((TCPH_FLAGS((seg)->tcphdr) & (TCP_FIN | TCP_SYN)) != 0) ? 1U : 0U))

/** Version of TCP_TCPLEN which uses cached TCP flags. It avoids extra dereference, however,
 *  it can be used only with outgoing segments.
 */
#define TCP_SEGLEN(seg) ((seg)->len + ((((seg)->tcp_flags & (TCP_FIN | TCP_SYN)) != 0) ? 1U : 0U))

/** Flags used on input processing, not on pcb->flags
 */
#define TF_RESET   (u8_t)0x08U /* Connection was reset. */
#define TF_CLOSED  (u8_t)0x10U /* Connection was successfully closed. */
#define TF_GOT_FIN (u8_t)0x20U /* Connection was closed by the remote end. */

#define TCP_EVENT_ACCEPT(pcb, err, ret)                                                            \
    do {                                                                                           \
        if ((pcb)->accept != NULL)                                                                 \
            (ret) = (pcb)->accept((pcb)->callback_arg, (pcb), (err));                              \
        else                                                                                       \
            (ret) = ERR_ARG;                                                                       \
    } while (0)

#define TCP_EVENT_SYN_RECEIVED(pcb, p_npcb, ret)                                                   \
    do {                                                                                           \
        if ((pcb)->syn_handled_cb != NULL)                                                         \
            (ret) = (pcb)->syn_handled_cb((pcb)->callback_arg, (p_npcb));                          \
        else                                                                                       \
            (ret) = ERR_ARG;                                                                       \
    } while (0)

#define TCP_EVENT_CLONE_PCB(pcb, p_npcb, ret)                                                      \
    do {                                                                                           \
        if ((pcb)->clone_conn != NULL)                                                             \
            (ret) = (pcb)->clone_conn((pcb)->callback_arg, (p_npcb));                              \
        else                                                                                       \
            (ret) = ERR_ARG;                                                                       \
    } while (0)

#define TCP_EVENT_ACCEPTED_PCB(pcb, newpcb)                                                        \
    do {                                                                                           \
        if ((pcb)->accepted_pcb != NULL)                                                           \
            (pcb)->accepted_pcb((newpcb));                                                         \
    } while (0)

#define TCP_EVENT_ACKED(pcb, acked, ret)                                                           \
    do {                                                                                           \
        if ((pcb)->acked_cb != NULL)                                                               \
            (ret) = (pcb)->acked_cb((pcb)->callback_arg, (pcb), (acked));                          \
        else                                                                                       \
            (ret) = ERR_OK;                                                                        \
    } while (0)

#define TCP_EVENT_RECV(pcb, p, err, ret)                                                           \
    do {                                                                                           \
        if ((pcb)->recv != NULL) {                                                                 \
            (ret) = (pcb)->recv((pcb)->callback_arg, (pcb), (p), (err));                           \
        } else {                                                                                   \
            (ret) = tcp_recv_null(NULL, (pcb), (p), (err));                                        \
        }                                                                                          \
    } while (0)

#define TCP_EVENT_CLOSED(pcb, ret)                                                                 \
    do {                                                                                           \
        if (((pcb)->recv != NULL)) {                                                               \
            (ret) = (pcb)->recv((pcb)->callback_arg, (pcb), NULL, ERR_OK);                         \
        } else {                                                                                   \
            (ret) = ERR_OK;                                                                        \
        }                                                                                          \
    } while (0)

#define TCP_EVENT_CONNECTED(pcb, err, ret)                                                         \
    do {                                                                                           \
        if ((pcb)->connected != NULL)                                                              \
            (ret) = (pcb)->connected((pcb)->callback_arg, (pcb), (err));                           \
        else                                                                                       \
            (ret) = ERR_OK;                                                                        \
    } while (0)

#define TCP_EVENT_ERR(errf, arg, err)                                                              \
    do {                                                                                           \
        if ((errf) != NULL)                                                                        \
            (errf)((arg), (err));                                                                  \
    } while (0)

/* This structure represents a TCP segment on the unsent, unacked and ooseq queues */
struct tcp_seg {
    struct tcp_seg *next; /* used when putting segments on a queue */
    struct tcp_hdr *tcphdr; /* the TCP header */
    struct pbuf *p; /* buffer containing data + TCP header */

    u32_t seqno;
    u32_t len; /* the TCP length of this segment should allow >64K size */

    u8_t flags;
#define TF_SEG_OPTS_MSS      (u8_t)0x01U /* Include MSS option. */
#define TF_SEG_OPTS_TS       (u8_t)0x02U /* Include timestamp option. */
#define TF_SEG_OPTS_WNDSCALE (u8_t)0x08U /* Include window scaling option */
#define TF_SEG_OPTS_TSO      (u8_t) TCP_WRITE_TSO /* Use TSO send mode */
#define TF_SEG_OPTS_NOMERGE  (u8_t)0x40U /* Don't merge with other segments */
#define TF_SEG_OPTS_ZEROCOPY (u8_t) TCP_WRITE_ZEROCOPY /* Use zerocopy send mode */

    u8_t tcp_flags; /* Cached TCP flags for outgoing segments */

    /* L2+L3+TCP header for zerocopy segments, it must have enough room for options
       This should have enough space for L2 (ETH+vLAN), L3 (IPv4/6), L4 (TCP)
       L2 = 20: (6 for alignment, so IPv4 packet is 4 bytes aligned)
       L3 = 20: for IPv4, 40 for IPv6 (Currently NO IP options are supported)
       L4 = 40: TCP + options.
       XLIO requires header pointer to be aligned to 4 bytes boundary.
    */
    u32_t l2_l3_tcphdr_zc[25] __attribute__((aligned(4)));
};

#if LWIP_TCP_TIMESTAMPS
#define LWIP_TCP_OPT_LEN_TS 12U
#endif

/* This macro calculates total length of tcp additional options
 * basing on option flags
 */
#define LWIP_TCP_OPT_LENGTH(flags)                                                                 \
    (flags & TF_SEG_OPTS_MSS ? 4 : 0) + (flags & TF_SEG_OPTS_WNDSCALE ? 1 + 3 : 0) +               \
        (flags & TF_SEG_OPTS_TS ? 12 : 0)

/* This macro calculates total length of tcp header including
 * additional options
 */
#define LWIP_TCP_HDRLEN(_tcphdr) (TCPH_HDRLEN(((struct tcp_hdr *)(_tcphdr))) * 4)

/** This returns a TCP header option for MSS in an u32_t */
#define TCP_BUILD_MSS_OPTION(x, mss)                                                               \
    (x) = PP_HTONL(((u32_t)2 << 24) | ((u32_t)4 << 16) | (((u32_t)mss / 256) << 8) | (mss & 255))

/** This returns a TCP header option for WINDOW SCALING in an u32_t - NOTE: the 1 at MSB serves as
 * NOOP */
#define TCP_BUILD_WNDSCALE_OPTION(x, scale)                                                        \
    (x) = PP_HTONL((((u32_t)1 << 24) | ((u32_t)3 << 16) | ((u32_t)3 << 8)) | ((u32_t)scale))

/* Global variables: */
extern struct tcp_pcb *tcp_input_pcb;
extern int32_t enable_wnd_scale;
extern u32_t rcv_wnd_scale;
extern u8_t enable_push_flag;
extern u8_t enable_ts_option;
extern u32_t tcp_ticks;
extern ip_route_mtu_fn external_ip_route_mtu;

#if defined(__GNUC__) && (((__GNUC__ == 4) && (__GNUC_MINOR__ >= 4)) || (__GNUC__ > 4))
#pragma GCC visibility push(hidden)
#endif
/* Internal functions: */
struct tcp_pcb *tcp_pcb_copy(struct tcp_pcb *pcb);
void tcp_pcb_purge(struct tcp_pcb *pcb);
void tcp_pcb_remove(struct tcp_pcb *pcb);

void tcp_segs_free(struct tcp_pcb *pcb, struct tcp_seg *seg);
void tcp_seg_free(struct tcp_pcb *pcb, struct tcp_seg *seg);
void tcp_tx_segs_free(struct tcp_pcb *pcb, struct tcp_seg *seg);
void tcp_tx_seg_free(struct tcp_pcb *pcb, struct tcp_seg *seg);
struct tcp_seg *tcp_seg_copy(struct tcp_pcb *pcb, struct tcp_seg *seg);

#define tcp_ack(pcb)                                                                               \
    do {                                                                                           \
        if ((pcb)->flags & TF_ACK_DELAY) {                                                         \
            (pcb)->flags &= ~TF_ACK_DELAY;                                                         \
            (pcb)->flags |= TF_ACK_NOW;                                                            \
        } else {                                                                                   \
            (pcb)->flags |= TF_ACK_DELAY;                                                          \
        }                                                                                          \
    } while (0)

#define tcp_ack_now(pcb)                                                                           \
    do {                                                                                           \
        (pcb)->flags |= TF_ACK_NOW;                                                                \
    } while (0)

err_t tcp_send_fin(struct tcp_pcb *pcb);
err_t tcp_enqueue_flags(struct tcp_pcb *pcb, u8_t flags);

void tcp_rst(u32_t seqno, u32_t ackno, u16_t local_port, u16_t remote_port, struct tcp_pcb *pcb);

u32_t tcp_next_iss(void);

void tcp_keepalive(struct tcp_pcb *pcb);
void tcp_zero_window_probe(struct tcp_pcb *pcb);

u16_t tcp_initial_mss(struct tcp_pcb *pcb);
u16_t tcp_send_mss(struct tcp_pcb *pcb);

err_t tcp_recv_null(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err);

#if TCP_DEBUG || TCP_INPUT_DEBUG || TCP_OUTPUT_DEBUG
void tcp_debug_print(struct tcp_hdr *tcphdr);
void tcp_debug_print_flags(u8_t flags);
void tcp_debug_print_state(enum tcp_state s);
void tcp_debug_print_pcbs(void);
#else
#define tcp_debug_print(tcphdr)
#define tcp_debug_print_flags(flags)
#define tcp_debug_print_state(s)
#define tcp_debug_print_pcbs()
#endif /* TCP_DEBUG */

/** External function (implemented in timers.c), called when TCP detects
 * that a timer is needed (i.e. active- or time-wait-pcb found). */
void tcp_timer_needed(void);

#if defined(__GNUC__) && (((__GNUC__ == 4) && (__GNUC_MINOR__ >= 4)) || (__GNUC__ > 4))
#pragma GCC visibility pop
#endif

#ifdef __cplusplus
}
#endif

#endif /* __LWIP_TCP_H__ */
