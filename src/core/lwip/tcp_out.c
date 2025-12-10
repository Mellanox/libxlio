/**
 * @file
 * Transmission Control Protocol, outgoing traffic
 *
 * The output functions of TCP.
 *
 */

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

#include "core/lwip/opt.h"

#include "core/lwip/tcp_impl.h"

#include <string.h>
#include <errno.h>
#include <assert.h>

#if LWIP_DEBUG_ENABLE
static char *_dump_seg(struct tcp_seg *seg)
{
    static __thread char _tcp_dump_buf[100];
    struct tcp_seg *cur_seg = NULL;
    struct pbuf *cur_pbuf = NULL;
    int seg_num = 0;
    int pbuf_num = 0;
    int seg_len = 0;
    int pbuf_len = 0;

    cur_seg = seg;
    while (cur_seg) {
        seg_len += cur_seg->len;
        seg_num++;
        cur_pbuf = cur_seg->p;
        while (cur_pbuf) {
            pbuf_len += cur_pbuf->len;
            pbuf_num++;
            cur_pbuf = cur_pbuf->next;
        }
        cur_seg = cur_seg->next;
    }

    snprintf(_tcp_dump_buf, sizeof(_tcp_dump_buf),
             "[seg] num: %-2d len: %-6d [pbuf] num: %-2d len: %-6d", seg_num, seg_len, pbuf_num,
             pbuf_len);
    return _tcp_dump_buf;
}
#endif /* LWIP_DEBUG_ENABLE */

sys_now_fn sys_now;
void register_sys_now(sys_now_fn fn)
{
    sys_now = fn;
}

ip_route_mtu_fn external_ip_route_mtu;

void register_ip_route_mtu(ip_route_mtu_fn fn)
{
    external_ip_route_mtu = fn;
}

/* Forward declarations.*/
static err_t tcp_output_segment(struct tcp_seg *seg, struct tcp_pcb *pcb);

/** Allocate a pbuf and create a tcphdr at p->payload, used for output
 * functions other than the default tcp_output -> tcp_output_segment
 * (e.g. tcp_send_empty_ack, etc.)
 *
 * @param pcb tcp pcb for which to send a packet (used to initialize tcp_hdr)
 * @param optlen length of header-options
 * @param datalen length of tcp data to reserve in pbuf
 * @param seqno_be seqno in network byte order (big-endian)
 * @return pbuf with p->payload being the tcp_hdr
 */
static struct pbuf *tcp_output_alloc_header(struct tcp_pcb *pcb, u16_t optlen, u16_t datalen,
                                            u32_t seqno_be /* already in network byte order */)
{
    struct tcp_hdr *tcphdr;
    struct pbuf *p = tcp_tx_pbuf_alloc(pcb, optlen + datalen, PBUF_RAM, NULL, NULL);
    if (p != NULL) {
        pbuf_header(p, TCP_HLEN);
        LWIP_ASSERT("check that first pbuf can hold struct tcp_hdr", (p->len >= TCP_HLEN + optlen));
        tcphdr = (struct tcp_hdr *)p->payload;
        tcphdr->src = htons(pcb->local_port);
        tcphdr->dest = htons(pcb->remote_port);
        tcphdr->seqno = seqno_be;
        tcphdr->ackno = htonl(pcb->rcv_nxt);
        TCPH_HDRLEN_FLAGS_SET(tcphdr, (5 + optlen / 4), TCP_ACK);
        tcphdr->wnd = htons(TCPWND_MIN16(RCV_WND_SCALE(pcb, pcb->rcv_ann_wnd)));
        tcphdr->chksum = 0;
        tcphdr->urgp = 0;

        /* If we're sending a packet, update the announced right window edge */
        pcb->rcv_ann_right_edge = pcb->rcv_nxt + pcb->rcv_ann_wnd;
    }
    return p;
}

/**
 * Called by tcp_close() to send a segment including FIN flag but not data.
 *
 * @param pcb the tcp_pcb over which to send a segment
 * @return ERR_OK if sent, another err_t otherwise
 */
err_t tcp_send_fin(struct tcp_pcb *pcb)
{
    /* first, try to add the fin to the last unsent segment */
    if (pcb->unsent != NULL) {
        if ((TCPH_FLAGS(pcb->last_unsent->tcphdr) & (TCP_SYN | TCP_FIN | TCP_RST)) == 0) {
            /* no SYN/FIN/RST flag in the header, we can add the FIN flag */
            TCPH_SET_FLAG(pcb->last_unsent->tcphdr, TCP_FIN);
            pcb->last_unsent->tcp_flags |= TCP_FIN;
            pcb->flags |= TF_FIN;
            return ERR_OK;
        }
    }
    /* no data, no length, flags, copy=1, no optdata */
    return tcp_enqueue_flags(pcb, TCP_FIN);
}

/**
 * Create a TCP segment with prefilled header.
 *
 * Called by tcp_write and tcp_enqueue_flags.
 *
 * @param pcb Protocol control block for the TCP connection.
 * @param p pbuf that is used to hold the TCP header.
          The caller is responsible to free the buffer when necessary,
          in case of failure.
 * @param flags TCP flags for header.
 * @param seqno TCP sequence number of this packet
 * @param optflags options to include in TCP header
 * @return a new tcp_seg pointing to p, or NULL.
 * The TCP header is filled in except ackno and wnd.
 * p is freed on failure.
 */
static struct tcp_seg *tcp_create_segment(struct tcp_pcb *pcb, struct pbuf *p, u8_t flags,
                                          u32_t seqno, u8_t optflags)
{
    struct tcp_seg *seg;
    u8_t optlen = LWIP_TCP_OPT_LENGTH(optflags);

    if (!pcb->seg_alloc) {
        // seg_alloc is not valid, we should allocate a new segment.
        if ((seg = external_tcp_seg_alloc(pcb)) == NULL) {
            LWIP_DEBUGF(TCP_OUTPUT_DEBUG | 2, ("tcp_create_segment: no memory.\n"));
            return NULL;
        }

        seg->next = NULL;
    } else {
        // seg_alloc is valid, we dont need to allocate a new segment element.
        seg = pcb->seg_alloc;
        pcb->seg_alloc = NULL;
    }

    if (p == NULL) {
        // Request a new segment in order to update seg_alloc for the next packet.
        seg->p = NULL;
        return seg;
    }

    seg->flags = optflags;
    seg->tcp_flags = flags;
    seg->p = p;
    seg->len = p->tot_len - optlen;
    seg->seqno = seqno;

    if (seg->flags & TF_SEG_OPTS_ZEROCOPY) {
        /* XXX Don't hardcode size/offset */
        seg->tcphdr = (struct tcp_hdr *)(&seg->l2_l3_tcphdr_zc[15]);
        seg->len = p->tot_len;
        goto set_tcphdr;
    }

    /* build TCP header */
    if (pbuf_header(p, TCP_HLEN)) {
        LWIP_DEBUGF(TCP_OUTPUT_DEBUG | 2,
                    ("tcp_create_segment: no room for TCP header in pbuf.\n"));
        /* Note: this call frees the input pbuf, that might cause problems. */
        tcp_tx_seg_free(pcb, seg);
        return NULL;
    }
    seg->tcphdr = (struct tcp_hdr *)seg->p->payload;

set_tcphdr:
    seg->tcphdr->src = htons(pcb->local_port);
    seg->tcphdr->dest = htons(pcb->remote_port);
    seg->tcphdr->seqno = htonl(seqno);
    /* ackno is set in tcp_output */
    TCPH_HDRLEN_FLAGS_SET(seg->tcphdr, (5 + optlen / 4), flags);
    /* wnd and chksum are set in tcp_output */
    seg->tcphdr->urgp = 0;
    return seg;
}

/**
 * Allocate a pbuf.
 * p_buff points to the original pbuf in case of a split operation.
 */
static struct pbuf *tcp_pbuf_prealloc(u32_t length, struct tcp_pcb *pcb, pbuf_type type,
                                      pbuf_desc *desc, struct pbuf *p_buff)
{
    struct pbuf *p = tcp_tx_pbuf_alloc(pcb, length, type, desc, p_buff);

    if (p) {
        LWIP_ASSERT("need unchained pbuf", p->next == NULL);
        p->len = p->tot_len = length;
    }
    return p;
}

/** Checks if tcp_write is allowed or not ().
 *
 * @param pcb the tcp pcb to check for
 * @return ERR_OK if tcp_write is allowed to proceed, another err_t otherwise
 */
static err_t tcp_write_is_state_valid(struct tcp_pcb *pcb)
{
    /* connection is in invalid state for data transmission? */
    if ((get_tcp_state(pcb) != ESTABLISHED) && (get_tcp_state(pcb) != CLOSE_WAIT) &&
        (get_tcp_state(pcb) != SYN_SENT) && (get_tcp_state(pcb) != SYN_RCVD)) {
        LWIP_DEBUGF(TCP_OUTPUT_DEBUG | LWIP_DBG_STATE | LWIP_DBG_LEVEL_SEVERE,
                    ("tcp_write() called in invalid state\n"));
        return ERR_CONN;
    }
    return ERR_OK;
}

static inline u32_t tcp_xmit_size_goal(struct tcp_pcb *pcb, int use_max)
{
    u32_t size = pcb->mss;

#if LWIP_TCP_TIMESTAMPS
    if ((pcb->flags & TF_TIMESTAMP)) {
        /* ensure that segments can hold at least one data byte... */
        size = LWIP_MAX(size, LWIP_TCP_OPT_LEN_TS + 1);
    }
#endif /* LWIP_TCP_TIMESTAMPS */

    if (use_max && tcp_tso(pcb) && pcb->tso.max_buf_sz) {
        /* use maximum buffer size in case TSO */
        size = LWIP_MAX(size, pcb->tso.max_buf_sz);
    }

    /* don't allocate segments bigger than half the maximum window we ever received */
    size = LWIP_MIN(size, (pcb->snd_wnd_max >> 1));

    return size;
}

/**
 * Write data for sending (but does not send it immediately).
 *
 * It waits in the expectation of more data being sent soon (as
 * it can send them more efficiently by combining them together).
 * To prompt the system to send data now, call tcp_output() after
 * calling tcp_write().
 *
 * The function will copy the data from arg to a new pbuf.
 *
 * @param pcb Protocol control block for the TCP connection to enqueue data for.
 * @param arg Pointer to the data to be enqueued for sending.
 * @param len Data length in bytes
 * @param apiflags combination of following flags:
 * - TCP_WRITE_FILE (0x40) data should be taken from file
 * @param desc Additional metadata that allows later to check the data mkey/lkey.
 * @return ERR_OK if enqueued, another err_t on error
 */
err_t tcp_write(struct tcp_pcb *pcb, const void *arg, u32_t len, u16_t apiflags, pbuf_desc *desc)
{
    struct tcp_seg *seg = NULL;
    struct tcp_seg *prev_seg = NULL;
    struct tcp_seg *queue = NULL;
    u32_t pos = 0;
    u8_t optlen = 0;
    u8_t optflags = 0;
    err_t err;
    const bool is_file = (apiflags & TCP_WRITE_FILE) == TCP_WRITE_FILE;
    u32_t oversize_used = 0;
    u32_t mss_local = 0;
    const int piov_max_size = 512;
    const int piov_max_len = 65536;
    struct iovec piov[piov_max_size];
    int piov_cur_index = 0;
    int piov_cur_len = 0;
    off_t offset = 0;
    off_t offset_next = 0;

    if (len < pcb->mss) {
        const u32_t byte_queued = pcb->snd_nxt - pcb->lastack;
        pcb->snd_sml_add = (pcb->unacked ? pcb->unacked->len : 0) + byte_queued;
    }

    LWIP_DEBUGF(TCP_OUTPUT_DEBUG,
                ("tcp_write(pcb=%p, data=%p, len=%" U16_F ", apiflags=%" U16_F ")\n", (void *)pcb,
                 arg, len, (u16_t)apiflags));

    err = tcp_write_is_state_valid(pcb);
    if (err != ERR_OK) {
        return err;
    }

#if LWIP_TCP_TIMESTAMPS
    if (pcb->flags & TF_TIMESTAMP) {
        optflags |= TF_SEG_OPTS_TS;
    }
#endif /* LWIP_TCP_TIMESTAMPS */
    optlen = LWIP_TCP_OPT_LENGTH(optflags);

    mss_local = tcp_xmit_size_goal(pcb, 1);
    if (is_file) {
        offset = offset_next = *(__off64_t *)arg;
    }

    /*
     * TCP segmentation is done in two phases with increasing complexity:
     *
     * 1. Copy data directly into an oversized pbuf.
     * 2. Create new segments.
     *
     * We may run out of memory at any point. In that case we must return ERR_MEM
     * and not change anything in pcb. Therefore, all changes are recorded in local
     * variables and committed at the end of the function. Some pcb fields are
     * maintained in local copies.
     *
     * 'seg' points to the last segment tampered with.
     *
     * mss_local never exceeds the physical buffer size. Therefore, we always
     * can create an mss_local sized segment with a single pbuf. There is no
     * point in supporting the case when we add an extra pbuf to the last_unsent.
     */

    if (pcb->last_unsent != NULL) {
        /*
         * Phase 1: Copy data directly into an oversized pbuf.
         *
         * The number of bytes copied is recorded in the oversize_used variable.
         * The actual copying is done at the bottom of the function.
         */
        const u16_t unsent_optlen = LWIP_TCP_OPT_LENGTH(pcb->last_unsent->flags);
        if (!is_file && (pcb->last_unsent->p->type == PBUF_RAM) &&
            (mss_local > pcb->last_unsent->len + unsent_optlen) &&
            (TCP_SEQ_GEQ(pcb->last_unsent->seqno, pcb->snd_nxt)) &&
            (pcb->last_unsent->seqno + pcb->last_unsent->len == pcb->snd_lbb)) {
            oversize_used = mss_local - (pcb->last_unsent->len + unsent_optlen);
            oversize_used = LWIP_MIN(oversize_used, len);
            pos += oversize_used;
        }
        seg = pcb->last_unsent;
    }

    /*
     * Phase 2: Create new segments.
     */
    while (pos < len) {
        struct pbuf *p;
        u32_t left = len - pos;
        u32_t seglen = LWIP_MIN(left, mss_local - optlen);

        p = tcp_pbuf_prealloc(seglen + optlen, pcb, PBUF_RAM, desc, NULL);
        if (!p) {
            LWIP_DEBUGF(TCP_OUTPUT_DEBUG | 2, ("tcp_write: could not allocate pbuf\n"));
            goto memerr;
        }
        if (is_file) {
            piov[piov_cur_index].iov_base = (void *)((char *)p->payload + optlen);
            piov[piov_cur_index].iov_len = seglen;

            piov_cur_index++;
            piov_cur_len += seglen;
            offset_next += seglen;
            if ((left <= seglen) || (piov_cur_index >= piov_max_size) ||
                (piov_cur_len >= piov_max_len)) {
                int ret = 0;
                int fd = desc->fd;
                ret = preadv(fd, piov, piov_cur_index, offset);
                /* Set as failure any unexpected return values because tcp_write() function
                 * does not support partial write
                 */
                if (ret != piov_cur_len) {
                    goto memerr;
                }
                piov_cur_index = 0;
                piov_cur_len = 0;
                offset = offset_next;
            }
        } else {
            assert(p->type == PBUF_RAM);
            memcpy((char *)p->payload + optlen, (u8_t *)arg + pos, seglen);
        }

        seg = tcp_create_segment(pcb, p, 0, pcb->snd_lbb + pos, optflags);
        if (!seg) {
            tcp_tx_pbuf_free(pcb, p);
            goto memerr;
        }
        if (queue == NULL) {
            queue = seg;
        } else {
            prev_seg->next = seg;
        }
        prev_seg = seg;

        pos += seglen;
    }

    /*
     * All 2 segmentation phases were successful. We can commit the transaction.
     */

    /*
     * Phase 1: Fill the last_unsent tail if it's incomplete.
     */
    if (oversize_used > 0) {
        struct pbuf *p;
        /* Bump tot_len of whole chain, len of tail */
        for (p = pcb->last_unsent->p; p; p = p->next) {
            p->tot_len += oversize_used;
            if (p->next == NULL) {
                memcpy((char *)p->payload + p->len, arg, oversize_used);
                p->len += oversize_used;
            }
        }
        pcb->last_unsent->len += oversize_used;
    }

    /*
     * Phase 2: Append queue to pcb->unsent. Queue may be NULL, but that is harmless.
     */
    if (pcb->last_unsent == NULL) {
        pcb->unsent = queue;
    } else {
        pcb->last_unsent->next = queue;
    }
    pcb->last_unsent = seg;

    /* Finally update the pcb state. */
    pcb->snd_lbb += len;

    /* Set the PSH flag in the last segment that we enqueued. */
    if (enable_push_flag && seg != NULL && seg->tcphdr != NULL) {
        TCPH_SET_FLAG(seg->tcphdr, TCP_PSH);
    }

    LWIP_DEBUGF(TCP_TSO_DEBUG | LWIP_DBG_TRACE,
                ("tcp_write:  mss: %-5d unsent %s\n", mss_local, _dump_seg(pcb->unsent)));

    return ERR_OK;
memerr:
    pcb->flags |= TF_NAGLEMEMERR;

    if (queue != NULL) {
        tcp_tx_segs_free(pcb, queue);
    }
    return ERR_MEM;
}

/**
 * Write data for sending (but does not send it immediately).
 *
 * The function will zero-copy the data into the payload, i.e. the data pointer, instead of the
 * data, will be set.
 *
 * @param pcb Protocol control block for the TCP connection to enqueue data for.
 * @param iov Vector of the data buffers to be enqueued for sending.
 * @param iovcnt Number of the iov elements.
 * @param desc Additional metadata that allows later to check the data mkey/lkey.
 * @return ERR_OK if enqueued, another err_t on error
 */
err_t tcp_write_express(struct tcp_pcb *pcb, const struct iovec *iov, u32_t iovcnt, pbuf_desc *desc)
{
    struct pbuf *p = NULL;
    struct tcp_seg *seg = NULL;
    struct tcp_seg *queue = NULL;
    struct tcp_seg *last;
    void *opaque = NULL;
    const u32_t seglen_max = tcp_tso(pcb) ? pcb->tso.max_payload_sz : pcb->mss;
    u32_t pos;
    u32_t seglen;
    u32_t last_seglen;
    u32_t total_len = 0;
    u8_t optflags = TF_SEG_OPTS_ZEROCOPY;

    /*
     * We may run out of memory at any point. In that case we must return ERR_MEM and not change
     * anything in pcb. Therefore, all changes are recorded in local variables and committed at
     * the end of the function. Some pcb fields are maintained in local copies.
     */

    last = pcb->last_unsent;
    const bool can_merge =
        last && (last->flags & TF_SEG_OPTS_ZEROCOPY) && TCP_SEQ_GEQ(last->seqno, pcb->snd_nxt);
    if (!can_merge) {
        /* We cannot append data to a segment of different type or a retransmitted segment. */
        last = NULL;
    }
    last_seglen = last ? last->len : 0;

    if (desc->attr == PBUF_DESC_EXPRESS) {
        /*
         * Keep opaque value only in the right most pbuf for each send operation.
         *
         * Express path needs to call the completion callback only after the send operation
         * is completed and all the related buffers are not used by XLIO.
         * Current implementation keeps the opaque in the last pbuf and calls the callback
         * when the opaque is set.
         * This implementation can call the callback while a buffer is still in SQ in a specific
         * case of spurious retransmission. However, without HW offloads and user memory
         * deregistration, the buffer in the SQ won't lead to a functional issue.
         * This is a place for improvements.
         */
        opaque = desc->opaque;
        desc->opaque = NULL;
    }

    for (unsigned i = 0; i < iovcnt; ++i) {
        u8_t *data = (u8_t *)iov[i].iov_base;
        const u32_t len = iov[i].iov_len;
        pos = 0;

        /* Chain a new pbuf to the last segment if there is enough space. */
        if (last) {
            seg = last;
            const u32_t space = seglen_max - seg->len;

            if (space > 0 && pbuf_clen(seg->p) < pcb->tso.max_send_sge) {
                seglen = space < len ? space : len;

                p = tcp_pbuf_prealloc(seglen, pcb, PBUF_ZEROCOPY, desc, NULL);
                if (!p) {
                    goto memerr;
                }
                p->payload = data;
                pbuf_cat(seg->p, p);
                seg->len += p->tot_len;
                pos += seglen;
            }
        }

        while (pos < len) {
            u32_t left = len - pos;
            seglen = left > seglen_max ? seglen_max : left;

            p = tcp_pbuf_prealloc(seglen, pcb, PBUF_ZEROCOPY, desc, NULL);
            if (!p) {
                goto memerr;
            }
            p->payload = data + pos;

            seg = tcp_create_segment(pcb, p, 0, pcb->snd_lbb + total_len + pos, optflags);
            if (!seg) {
                tcp_tx_pbuf_free(pcb, p);
                goto memerr;
            }

            if (!queue) {
                queue = seg;
            }
            if (last) {
                last->next = seg;
            }
            last = seg;

            pos += seglen;
        }

        total_len += len;
    }

    /* Set the PSH flag in the last segment that we enqueued. */
    if (enable_push_flag && seg != NULL && seg->tcphdr != NULL) {
        TCPH_SET_FLAG(seg->tcphdr, TCP_PSH);
    }

    if (!pcb->last_unsent) {
        pcb->unsent = queue;
    } else {
        /* The next field is either NULL or equals to queue, so we can overwrite. */
        pcb->last_unsent->next = queue;
    }
    if (last) {
        pcb->last_unsent = last;
    }

    if (desc->attr == PBUF_DESC_EXPRESS) {
        /* See description above. */
        if (p) {
            /* 'p' is the last allocated pbuf. */
            p->desc.opaque = opaque;
        }
        desc->opaque = opaque;
    }

    /* Update the pcb state. */
    pcb->snd_lbb += total_len;

    /* TODO Move Minshall's logic to tcp_output(). */
    if (total_len < pcb->mss) {
        const u32_t byte_queued = pcb->snd_nxt - pcb->lastack;
        pcb->snd_sml_add = (pcb->unacked ? pcb->unacked->len : 0) + byte_queued;
    }

    return ERR_OK;

memerr:
    /* Error path - restore unsent queue. */
    pcb->flags |= TF_NAGLEMEMERR;
    if (queue != NULL) {
        tcp_tx_segs_free(pcb, queue);
    }
    if (pcb->last_unsent && last_seglen > 0) {
        pcb->last_unsent->next = NULL;
        p = pcb->last_unsent->p;
        while (last_seglen > 0) {
            last_seglen -= p->len;
            p = p->next;
        }
        if (p) {
            pcb->last_unsent->len -= p->tot_len;
            struct pbuf *ptmp = pcb->last_unsent->p;
            while (ptmp) {
                ptmp->tot_len -= p->tot_len;
                if (ptmp->next == p) {
                    ptmp->next = NULL;
                }
                ptmp = ptmp->next;
            }
            assert(pcb->last_unsent->len == last_seglen);
            assert(pcb->last_unsent->p->tot_len == last_seglen);
        }
    }
    if (desc->attr == PBUF_DESC_EXPRESS) {
        /* Restore opaque value on error path. */
        desc->opaque = opaque;
    }
    return ERR_MEM;
}

/**
 * Enqueue TCP options for transmission.
 *
 * Called by tcp_connect(), tcp_listen_input(), and tcp_send_ctrl().
 *
 * @param pcb Protocol control block for the TCP connection.
 * @param flags TCP header flags to set in the outgoing segment.
 * @param optdata pointer to TCP options, or NULL.
 * @param optlen length of TCP options in bytes.
 */
err_t tcp_enqueue_flags(struct tcp_pcb *pcb, u8_t flags)
{
    struct pbuf *p;
    struct tcp_seg *seg;
    u8_t optflags = 0;
    u8_t optlen = 0;

    LWIP_ASSERT(
        "tcp_enqueue_flags: need either TCP_SYN or TCP_FIN in flags (programmer violates API)",
        (flags & (TCP_SYN | TCP_FIN)) != 0);

    if (flags & TCP_SYN) {
        optflags = TF_SEG_OPTS_MSS;
        if (enable_wnd_scale && ((get_tcp_state(pcb) != SYN_RCVD) || (pcb->flags & TF_WND_SCALE))) {
            /* In a <SYN,ACK> (sent in state SYN_RCVD), the window scale option may only
                be sent if we received a window scale option from the remote host. */
            optflags |= TF_SEG_OPTS_WNDSCALE;
        }
#if LWIP_TCP_TIMESTAMPS
        if (pcb->enable_ts_opt && !(flags & TCP_ACK)) {
            // enable initial timestamp announcement only for the connecting side. accepting side
            // reply accordingly.
            optflags |= TF_SEG_OPTS_TS;
        }
#endif
    }
#if LWIP_TCP_TIMESTAMPS
    if ((pcb->flags & TF_TIMESTAMP)) {
        optflags |= TF_SEG_OPTS_TS;
    }
#endif /* LWIP_TCP_TIMESTAMPS */
    optlen = LWIP_TCP_OPT_LENGTH(optflags);

    /* Allocate pbuf with room for TCP header + options */
    if ((p = tcp_tx_pbuf_alloc(pcb, optlen, PBUF_RAM, NULL, NULL)) == NULL) {
        pcb->flags |= TF_NAGLEMEMERR;
        return ERR_MEM;
    }

    /* Allocate memory for tcp_seg, and fill in fields. */
    if ((seg = tcp_create_segment(pcb, p, flags, pcb->snd_lbb, optflags)) == NULL) {
        pcb->flags |= TF_NAGLEMEMERR;
        tcp_tx_pbuf_free(pcb, p);
        return ERR_MEM;
    }

    LWIP_DEBUGF(
        TCP_OUTPUT_DEBUG | LWIP_DBG_TRACE,
        ("tcp_enqueue_flags: queueing %" U32_F ":%" U32_F " (0x%" X16_F ")\n",
         ntohl(seg->tcphdr->seqno), ntohl(seg->tcphdr->seqno) + TCP_SEGLEN(seg), (u16_t)flags));

    /* Now append seg to pcb->unsent queue */
    if (pcb->unsent == NULL) {
        pcb->unsent = seg;
    } else {
        pcb->last_unsent->next = seg;
    }
    pcb->last_unsent = seg;

    /* SYN and FIN bump the sequence number */
    if (flags & (TCP_SYN | TCP_FIN)) {
        pcb->snd_lbb++;
    }
    if (flags & TCP_FIN) {
        pcb->flags |= TF_FIN;
    }

    return ERR_OK;
}

#if LWIP_TCP_TIMESTAMPS
/* Build a timestamp option (12 bytes long) at the specified options pointer)
 *
 * @param pcb tcp_pcb
 * @param opts option pointer where to store the timestamp option
 */
static void tcp_build_timestamp_option(struct tcp_pcb *pcb, u32_t *opts)
{
    /* Pad with two NOP options to make everything nicely aligned */
    opts[0] = PP_HTONL(0x0101080A);
    opts[1] = htonl(sys_now());
    opts[2] = htonl(pcb->ts_recent);
}
#endif

/** Send an ACK without data.
 *
 * @param pcb Protocol control block for the TCP connection to send the ACK
 */
err_t tcp_send_empty_ack(struct tcp_pcb *pcb)
{
    struct pbuf *p;
    struct tcp_hdr *tcphdr;
    u8_t optlen = 0;
    u32_t *opts;

#if LWIP_TCP_TIMESTAMPS
    if (pcb->flags & TF_TIMESTAMP) {
        optlen = LWIP_TCP_OPT_LENGTH(TF_SEG_OPTS_TS);
    }
#endif

    p = tcp_output_alloc_header(pcb, optlen, 0, htonl(pcb->snd_nxt));
    if (p == NULL) {
        LWIP_DEBUGF(TCP_OUTPUT_DEBUG, ("tcp_output: (ACK) could not allocate pbuf\n"));
        return ERR_BUF;
    }
    tcphdr = (struct tcp_hdr *)p->payload;
    LWIP_DEBUGF(TCP_OUTPUT_DEBUG, ("tcp_output: sending ACK for %" U32_F "\n", pcb->rcv_nxt));
    /* remove ACK flags from the PCB, as we send an empty ACK now */
    pcb->flags &= ~(TF_ACK_DELAY | TF_ACK_NOW);

    opts = (u32_t *)(void *)(tcphdr + 1);

    /* NB. MSS option is only sent on SYNs, so ignore it here */
#if LWIP_TCP_TIMESTAMPS
    pcb->ts_lastacksent = pcb->rcv_nxt;

    if (pcb->flags & TF_TIMESTAMP) {
        tcp_build_timestamp_option(pcb, opts);
        opts += 3;
    }
#endif
    pcb->ip_output(p, NULL, pcb, 0);
    tcp_tx_pbuf_free(pcb, p);

    (void)opts; /* Fix warning -Wunused-but-set-variable */

    return ERR_OK;
}

/* Used by split functions to move FIN/RST flags to the rightmost segment. */
static void tcp_seg_move_flags(struct tcp_seg *from, struct tcp_seg *to, u8_t flags)
{
    u16_t from_flags = TCPH_FLAGS(from->tcphdr) & flags;

    if ((from != to) && (to != NULL) && from_flags) {
        TCPH_SET_FLAG(to->tcphdr, from_flags);
        to->tcp_flags = from_flags;
        TCPH_UNSET_FLAG(from->tcphdr, flags);
        from->tcp_flags &= ~flags;
    }
}

/**
 * Called by tcp_output() to actually join few following TCP segments
 * in one to send a TCP segment over IP using Large Segment Offload method.
 *
 * @param pcb the tcp_pcb for the TCP connection used to send the segment
 * @param seg the tcp_seg to send
 * @param wnd current wnd
 * @return pbuf with p->payload being the tcp_hdr
 */
static void tcp_tso_segment(struct tcp_pcb *pcb, struct tcp_seg *seg, u32_t wnd)
{
    struct tcp_seg *cur_seg = seg;
    u32_t max_payload_sz = LWIP_MIN(pcb->tso.max_payload_sz, (wnd - (seg->seqno - pcb->lastack)));
    u32_t tot_len = 0;
    u8_t flags = seg->flags;
    u8_t tot_p = 0;

    /* Ignore retransmitted segments and special segments
     */
    if (TCP_SEQ_LT(seg->seqno, pcb->snd_nxt) ||
        (seg->flags & (TF_SEG_OPTS_TSO | TF_SEG_OPTS_NOMERGE)) ||
        ((TCPH_FLAGS(seg->tcphdr) & (~(TCP_ACK | TCP_PSH))) != 0)) {
        goto err;
    }

    while (cur_seg && cur_seg->next && (cur_seg->flags == flags) &&
           ((TCPH_FLAGS(cur_seg->tcphdr) & (~(TCP_ACK | TCP_PSH))) == 0)) {

        tot_len += cur_seg->len;
        if (tot_len > max_payload_sz) {
            goto err;
        }

        tot_p += pbuf_clen(cur_seg->p);
        if (tot_p > pcb->tso.max_send_sge) {
            goto err;
        }

        /* Don't merge different types of segments */
        if ((seg->flags & TF_SEG_OPTS_ZEROCOPY) != (cur_seg->flags & TF_SEG_OPTS_ZEROCOPY)) {
            goto err;
        }

        if (seg != cur_seg) {
            /* Update the original segment with current segment details */
            seg->next = cur_seg->next;
            seg->len += cur_seg->len;

            /* Update the first pbuf of current segment, unless this is a zerocopy segment */
            if (!(cur_seg->flags & TF_SEG_OPTS_ZEROCOPY)) {
                cur_seg->p->payload = (u8_t *)cur_seg->tcphdr + LWIP_TCP_HDRLEN(cur_seg->tcphdr);
            }
            cur_seg->p->len = cur_seg->len - (cur_seg->p->tot_len - cur_seg->p->len);
            cur_seg->p->tot_len = cur_seg->len;

            /* Concatenate two pbufs (each may be a pbuf chain) and
             * update tot_len values for all pbuf in the chain
             */
            pbuf_cat(seg->p, cur_seg->p);

            /* Free joined segment w/o releasing pbuf
             * tcp_seg_free() and tcp_segs_free() release pbuf chain.
             * Note, this code doesn't join the last unsent segment and thus
             * pcb->last_unsent is left unchanged. Otherwise, we would have
             * to update the last_unsent pointer to keep it valid.
             */
            external_tcp_seg_free(pcb, cur_seg);
        }
        cur_seg = seg->next;
    }

err:

    /* All segments that greater than MSS must be processed as TSO segments
     * For example it can be actual for segments with large (more than MSS) buffer size
     */
    if (seg->len + LWIP_TCP_OPT_LENGTH(seg->flags) > pcb->mss) {
        seg->flags |= TF_SEG_OPTS_TSO;
    }

#if TCP_TSO_DEBUG
    LWIP_DEBUGF(TCP_TSO_DEBUG | LWIP_DBG_TRACE,
                ("tcp_join:   max: %-5d unsent %s\n", max_payload_sz, _dump_seg(pcb->unsent)));
#endif /* TCP_TSO_DEBUG */

    return;
}

/**
 * Called by tcp_output() to split a retransmitted multi-pbuf segment. This is
 * done to handle spurious retransmissions concurrently with incoming TCP ACK.
 * If we don't split multi-pbuf segments, an internal pbuf may be freed while
 * its payload is used by the retransmission WQE.
 *
 * @param pcb the tcp_pcb for the TCP connection
 * @param seg the tcp_seg to split
 */
void tcp_split_rexmit(struct tcp_pcb *pcb, struct tcp_seg *seg)
{
    struct tcp_seg *cur_seg = NULL;
    struct tcp_seg *new_seg = NULL;
    struct pbuf *cur_p = NULL;
    int tcp_hlen_delta;
    u8_t optflags = 0;
    u8_t optlen = 0;
    u32_t seqno = 0;

#if LWIP_TCP_TIMESTAMPS
    if ((pcb->flags & TF_TIMESTAMP)) {
        optflags |= TF_SEG_OPTS_TS;
    }
#endif /* LWIP_TCP_TIMESTAMPS */

    optlen = LWIP_TCP_OPT_LENGTH(optflags);

    if (seg->flags & TF_SEG_OPTS_ZEROCOPY) {
        optlen = 0;
        optflags |= TF_SEG_OPTS_ZEROCOPY;
        tcp_hlen_delta = 0;
    } else {
        tcp_hlen_delta = TCP_HLEN;
    }

    seg->flags |= TF_SEG_OPTS_NOMERGE;
    cur_seg = seg;
    cur_p = seg->p->next;

    while (cur_p) {
        cur_p->len += optlen;
        cur_p->tot_len += optlen;
        cur_p->payload = (u8_t *)cur_p->payload - optlen;

        seqno = cur_seg->seqno + cur_seg->p->len - tcp_hlen_delta - optlen;
        new_seg = tcp_create_segment(pcb, cur_p, 0, seqno, optflags);
        if (!new_seg) {
            /* Avoid corrupting original segment's buffer in case of failure */
            cur_p->len -= optlen;
            cur_p->tot_len -= optlen;
            cur_p->payload = (u8_t *)cur_p->payload + optlen;
            return;
        }

        /* New segment update */
        new_seg->next = cur_seg->next;
        new_seg->flags = cur_seg->flags;

        /* Original segment update */
        cur_seg->next = new_seg;
        cur_seg->len = cur_seg->p->len - tcp_hlen_delta - optlen;
        cur_seg->p->tot_len = cur_seg->p->len;
        cur_seg->p->next = NULL;

        if (pcb->last_unsent == cur_seg) {
            /* We have split the last unsent segment, update last_unsent */
            pcb->last_unsent = new_seg;
        }

        tcp_seg_move_flags(cur_seg, new_seg, TCP_FIN | TCP_RST);
        cur_seg = new_seg;
        cur_p = cur_seg->p->next;
    }
}

void tcp_split_segment(struct tcp_pcb *pcb, struct tcp_seg *seg, u32_t wnd)
{
    struct pbuf *p = NULL;
    struct tcp_seg *newseg = NULL;
    int tcp_hlen_delta;
    u32_t lentosend = 0;
    u8_t optlen = 0;
    u8_t optflags = 0;
    pbuf_type type = PBUF_RAM;
    int is_zerocopy = 0;

    if (((seg->seqno - pcb->lastack) >= wnd) || (seg->p->ref > 1)) {
        return;
    }

    is_zerocopy = seg->flags & TF_SEG_OPTS_ZEROCOPY ? 1 : 0;
    lentosend = (wnd - (seg->seqno - pcb->lastack));

#if LWIP_TCP_TIMESTAMPS
    if ((pcb->flags & TF_TIMESTAMP)) {
        optflags |= TF_SEG_OPTS_TS;
    }
#endif /* LWIP_TCP_TIMESTAMPS */
    optlen = LWIP_TCP_OPT_LENGTH(optflags);

    if (is_zerocopy) {
        optflags |= TF_SEG_OPTS_ZEROCOPY;
        type = PBUF_ZEROCOPY;
        optlen = 0;
        tcp_hlen_delta = 0;
    } else {
        tcp_hlen_delta = TCP_HLEN;
    }

    if (seg->p->len > ((tcp_hlen_delta + optlen) + lentosend)) {
        /* First buffer is too big, split it */
        u32_t lentoqueue = seg->p->len - (tcp_hlen_delta + optlen) - lentosend;

        p = tcp_pbuf_prealloc(lentoqueue + optlen, pcb, type, &seg->p->desc, seg->p);
        if (!p) {
            LWIP_DEBUGF(TCP_OUTPUT_DEBUG | 2, ("tcp_split_segment: could not allocate pbuf\n"));
            return;
        }

        if (seg->p->desc.attr == PBUF_DESC_EXPRESS) {
            /* Keep opaque value only in the right most pbuf for each send operation. */
            seg->p->desc.opaque = NULL;
        }

        /* Copy the data from the original buffer */
        if (is_zerocopy) {
            p->payload = (char *)seg->p->payload + lentosend;
        } else {
            memcpy((char *)p->payload + optlen,
                   (u8_t *)seg->tcphdr + LWIP_TCP_HDRLEN(seg->tcphdr) + lentosend, lentoqueue);
        }

        /* Update new buffer */
        p->tot_len = seg->p->tot_len - lentosend - tcp_hlen_delta;
        p->next = seg->p->next;

        /* Allocate memory for tcp_seg and fill in fields. */
        newseg = tcp_create_segment(pcb, p, 0, seg->seqno + lentosend, optflags);
        if (!newseg) {
            LWIP_DEBUGF(TCP_OUTPUT_DEBUG | 2, ("tcp_split_segment: could not allocate segment\n"));
            /* Avoid corrupting original segment's buffer in case of failure */
            p->next = NULL;
            tcp_tx_pbuf_free(pcb, p);
            return;
        }

        /* Update original buffer */
        seg->p->next = NULL;
        seg->p->len = seg->p->len - lentoqueue;
        seg->p->tot_len = seg->p->len;

        /* New segment update */
        newseg->next = seg->next;
        newseg->flags = seg->flags;

        /* Original segment update */
        seg->next = newseg;
        seg->len = seg->p->len - (tcp_hlen_delta + optlen);

        /* Set the PSH flag in the last segment that we enqueued. */
        if (enable_push_flag) {
            TCPH_SET_FLAG(newseg->tcphdr, TCP_PSH);
        }

        if (pcb->last_unsent == seg) {
            /* We have split the last unsent segment, update last_unsent */
            pcb->last_unsent = newseg;
        }
    } else if (seg->p->next) {
        /* Segment with more than one pbuf and seg->p->len <= lentosend
           split segment pbuf chain. At least one pbuf will be sent. */
        struct pbuf *pnewhead = seg->p->next;
        struct pbuf *pnewtail = seg->p;
        struct pbuf *ptmp = seg->p;
        u32_t headchainlen = seg->p->len;

        while ((headchainlen + pnewhead->len - (tcp_hlen_delta + optlen)) <= lentosend) {
            if (pnewtail->ref > 1) {
                return;
            }

            headchainlen += pnewhead->len;
            pnewtail = pnewhead;
            pnewhead = pnewhead->next;
            if (NULL == pnewhead) {
                LWIP_ASSERT("tcp_split_segment: We should not be here", 0);
                return;
            }
        }

        /* Allocate memory for tcp_seg, and fill in fields. */
        newseg = tcp_create_segment(
            pcb, pnewhead, 0, seg->seqno + headchainlen - (tcp_hlen_delta + optlen), optflags);
        if (!newseg) {
            LWIP_DEBUGF(TCP_OUTPUT_DEBUG | 2, ("tcp_split_segment: could not allocate segment\n"));
            return;
        }

        /* Update new tail */
        pnewtail->next = NULL;

        /* New segment update */
        newseg->next = seg->next;
        newseg->flags = seg->flags;

        /* Original segment update */
        seg->next = newseg;
        seg->len = headchainlen - (tcp_hlen_delta + optlen);

        /* Update original buffers */
        while (ptmp) {
            ptmp->tot_len = headchainlen;
            headchainlen -= ptmp->len;
            ptmp = ptmp->next;
        }

        /* Update last unsent segment */
        if (pcb->last_unsent == seg) {
            pcb->last_unsent = newseg;
        }
    } else {
        LWIP_ASSERT("tcp_split_segment: We should not be here [else]", 0);
    }

    tcp_seg_move_flags(seg, newseg, TCP_FIN | TCP_RST);

#if TCP_TSO_DEBUG
    LWIP_DEBUGF(TCP_TSO_DEBUG | LWIP_DBG_TRACE,
                ("tcp_split:  max: %-5d unsent %s\n", lentosend, _dump_seg(pcb->unsent)));
#endif /* TCP_TSO_DEBUG */

    return;
}

/**
 * Check whether the input data_len fits the window
 *
 * @param pcb Protocol control block for the TCP connection to send data
 * @parma data_len length to be checked
 * @return 1 if input size fits the window, else 0.
 */
s32_t tcp_is_wnd_available(struct tcp_pcb *pcb, u32_t data_len)
{
    s32_t tot_unacked_len = 0;
    s32_t tot_unsent_len = 0;
    s32_t wnd = (s32_t)(LWIP_MIN(pcb->snd_wnd, pcb->cwnd));
    s32_t tot_opts_hdrs_len = 0;

#if LWIP_TCP_TIMESTAMPS
    if (pcb->flags & TF_TIMESTAMP) {
        /* The default TCP Maximum Segment Size is 536 (LWIP_TCP_MSS) - RFC-879 */
        u16_t mss = pcb->mss ? pcb->mss : LWIP_TCP_MSS;
        u16_t mss_local = LWIP_MIN(pcb->mss, pcb->snd_wnd_max / 2);
        mss_local = mss_local ? mss_local : mss;
        tot_opts_hdrs_len =
            ((LWIP_TCP_OPT_LENGTH(TF_SEG_OPTS_TS)) * (1 + ((data_len - 1) / (mss_local))));
    }
#endif

    if (pcb->unacked) {
        tot_unacked_len = pcb->last_unacked->seqno - pcb->unacked->seqno + pcb->last_unacked->len;
    }

    if (pcb->unsent) {
        tot_unsent_len = pcb->last_unsent->seqno - pcb->unsent->seqno + pcb->last_unsent->len;
    }

    return ((wnd - tot_unacked_len) >= (tot_unsent_len + (tot_opts_hdrs_len + (s32_t)data_len)));
}

/**
 * Find out what we can send and send it
 *
 * @param pcb Protocol control block for the TCP connection to send data
 * @return ERR_OK if data has been sent or nothing to send
 *         another err_t on error
 */
err_t tcp_output(struct tcp_pcb *pcb)
{
    struct tcp_seg *seg, *useg;
    u32_t wnd, snd_nxt;
    err_t rc = ERR_OK;
#if TCP_CWND_DEBUG
    s16_t i = 0;
#endif /* TCP_CWND_DEBUG */

    /* First, check if we are invoked by the TCP input processing
       code. If so, we do not output anything. Instead, we rely on the
       input processing code to call us when input processing is done
       with. */
    if (pcb->is_in_input) {
        return ERR_OK;
    }

    wnd = LWIP_MIN(pcb->snd_wnd, pcb->cwnd);

    LWIP_DEBUGF(TCP_CWND_DEBUG,
                ("tcp_output: snd_wnd %" U32_F ", cwnd %" U32_F ", wnd %" U32_F "\n", pcb->snd_wnd,
                 pcb->cwnd, wnd));

    if (pcb->is_last_seg_dropped && pcb->unacked && !pcb->unacked->next) {
        /* Forcibly retransmit segment from the unacked queue if it was dropped
         * on the previous iteration.
         * Disable the retransmission timer after the unacked queue is emptied.
         */
        pcb->is_last_seg_dropped = false;
        pcb->unacked->next = pcb->unsent;
        pcb->unsent = pcb->unacked;
        pcb->unacked = NULL;
        if (NULL == pcb->last_unsent) {
            pcb->last_unsent = pcb->last_unacked;
        }
        pcb->last_unacked = NULL;
        pcb->rtime = -1;
        pcb->ticks_since_data_sent = -1;
    }
    seg = pcb->unsent;

#if TCP_OUTPUT_DEBUG
    if (seg == NULL) {
        LWIP_DEBUGF(TCP_OUTPUT_DEBUG, ("tcp_output: nothing to send (%p)\n", (void *)pcb->unsent));
    }
#endif /* TCP_OUTPUT_DEBUG */
#if TCP_CWND_DEBUG
    if (seg == NULL) {
        LWIP_DEBUGF(TCP_CWND_DEBUG,
                    ("tcp_output: snd_wnd %" U32_F ", cwnd %" U32_F ", wnd %" U32_F
                     ", seg == NULL, ack %" U32_F "\n",
                     pcb->snd_wnd, pcb->cwnd, wnd, pcb->lastack));
    } else {
        LWIP_DEBUGF(
            TCP_CWND_DEBUG,
            ("tcp_output: snd_wnd %" U32_F ", cwnd %" U32_F ", wnd %" U32_F ", effwnd %" U32_F
             ", seq %" U32_F ", ack %" U32_F "\n",
             pcb->snd_wnd, pcb->cwnd, wnd, ntohl(seg->tcphdr->seqno) - pcb->lastack + seg->len,
             ntohl(seg->tcphdr->seqno), pcb->lastack));
    }
#endif /* TCP_CWND_DEBUG */
#if TCP_TSO_DEBUG
    if (seg) {
        LWIP_DEBUGF(TCP_TSO_DEBUG | LWIP_DBG_TRACE,
                    ("tcp_output: wnd: %-5d unsent %s\n", wnd, _dump_seg(pcb->unsent)));
    }
#endif /* TCP_TSO_DEBUG */

    while (seg && rc == ERR_OK) {
        /* TSO segment can be in unsent queue only in case of retransmission.
         * Clear TSO flag, tcp_split_segment() and tcp_tso_segment() will handle
         * all scenarios further.
         */
        seg->flags &= ~TF_SEG_OPTS_TSO;

        if (TCP_SEQ_LT(seg->seqno, pcb->snd_nxt) && seg->p && seg->p->len != seg->p->tot_len) {
            tcp_split_rexmit(pcb, seg);
        }

        /* Split the segment in case of a small window */
        if ((NULL == pcb->unacked) && (wnd) && ((seg->len + seg->seqno - pcb->lastack) > wnd)) {
            tcp_split_segment(pcb, seg, wnd);
        }

        /* data available and window allows it to be sent? */
        if (((seg->seqno - pcb->lastack + seg->len) <= wnd)) {
            LWIP_ASSERT("RST not expected here!", (TCPH_FLAGS(seg->tcphdr) & TCP_RST) == 0);

            /* Stop sending if the nagle algorithm would prevent it
             * Don't stop:
             * - if tcp_write had a memory error before (prevent delayed ACK timeout) or
             * - if this is not a dummy segment
             * - if FIN was already enqueued for this PCB (SYN is always alone in a segment -
             *   either seg->next != NULL or pcb->unacked == NULL;
             *   RST is no sent using tcp_write/tcp_output.
             */
            if ((tcp_do_output_nagle(pcb) == 0) &&
                ((pcb->flags & (TF_NAGLEMEMERR | TF_FIN)) == 0)) {
                if (pcb->snd_sml_snt > (pcb->unacked ? pcb->unacked->len : 0)) {
                    pcb->flags &= ~(TF_ACK_NOW); // TODO bug #3574064: check if maybe we do want to
                                                 // send empty ack
                    break;
                } else {
                    if ((u32_t)((seg->next ? seg->next->len : 0) + seg->len) <= pcb->snd_sml_add) {
                        pcb->snd_sml_snt = pcb->snd_sml_add;
                    }
                }
            }

            /* Use TSO send operation in case TSO is enabled
             * and current segment is not retransmitted
             */
            if (tcp_tso(pcb)) {
                tcp_tso_segment(pcb, seg, wnd);
            }

#if TCP_CWND_DEBUG
            LWIP_DEBUGF(
                TCP_CWND_DEBUG,
                ("tcp_output: snd_wnd %" U32_F ", cwnd %" U16_F ", wnd %" U32_F ", effwnd %" U32_F
                 ", seq %" U32_F ", ack %" U32_F ", i %" S16_F "\n",
                 pcb->snd_wnd, pcb->cwnd, wnd, ntohl(seg->tcphdr->seqno) + seg->len - pcb->lastack,
                 ntohl(seg->tcphdr->seqno), pcb->lastack, i));
            ++i;
#endif /* TCP_CWND_DEBUG */

            if (get_tcp_state(pcb) != SYN_SENT) {
                TCPH_SET_FLAG(seg->tcphdr, TCP_ACK);
                pcb->flags &= ~(TF_ACK_DELAY | TF_ACK_NOW);
            }

            rc = tcp_output_segment(seg, pcb);
            if (rc != ERR_OK && pcb->unacked) {
                /* Transmission failed, skip moving the segment to unacked, so we
                 * retry with the next tcp_output(). We must have at least one unacked
                 * segment in this case or RTO would be broken otherwise. */
                break;
            }
            if (rc == ERR_WOULDBLOCK) {
                /* Mark that the segment is dropped, so we can retransmit it during
                 * the next iteration. */
                pcb->is_last_seg_dropped = true;
            }

            pcb->unsent = seg->next;
            snd_nxt = seg->seqno + TCP_SEGLEN(seg);
            if (TCP_SEQ_LT(pcb->snd_nxt, snd_nxt)) {
                pcb->snd_nxt = snd_nxt;
            }
            /* put segment on unacknowledged list if length > 0 */
            if (TCP_SEGLEN(seg) > 0) {
                seg->next = NULL;
                /* unacked list is empty? */
                if (pcb->unacked == NULL) {
                    pcb->unacked = seg;
                    pcb->last_unacked = seg;
                    /* unacked list is not empty? */
                } else {
                    /* In the case of fast retransmit, the packet should not go to the tail
                     * of the unacked queue, but rather somewhere before it. We need to check
                     * for this case. -STJ Jul 27, 2004 */
                    useg = pcb->last_unacked;
                    if (TCP_SEQ_LT(seg->seqno, useg->seqno)) {
                        /* add segment to before tail of unacked list, keeping the list sorted
                         */
                        struct tcp_seg **cur_seg = &(pcb->unacked);
                        while (*cur_seg && TCP_SEQ_LT((*cur_seg)->seqno, seg->seqno)) {
                            cur_seg = &((*cur_seg)->next);
                        }
                        LWIP_ASSERT("Value of last_unacked is invalid",
                                    *cur_seg != pcb->last_unacked->next);
                        seg->next = (*cur_seg);
                        (*cur_seg) = seg;
                    } else {
                        /* add segment to tail of unacked list */
                        useg->next = seg;
                        pcb->last_unacked = seg;
                    }
                }
                /* do not queue empty segments on the unacked list */
            } else {
                tcp_tx_seg_free(pcb, seg);
            }
            seg = pcb->unsent;
        } else {
            break;
        }
    }

    if (pcb->unsent == NULL) {
        /* We have sent all pending segments, reset last_unsent */
        pcb->last_unsent = NULL;
    }

    /* Send empty ACK if TF_ACK_NOW was set and no data was sent. */
    if (pcb->flags & TF_ACK_NOW) {
        tcp_send_empty_ack(pcb);
    }

    pcb->flags &= ~TF_NAGLEMEMERR;

    // Fetch buffers for the next packet.
    if (!pcb->seg_alloc) {
        // Fetch tcp segment for the next packet.
        pcb->seg_alloc = tcp_create_segment(pcb, NULL, 0, 0, 0);
    }

    return rc == ERR_WOULDBLOCK ? ERR_OK : rc;
}

/**
 * Called by tcp_output() to actually send a TCP segment over IP.
 *
 * @param seg the tcp_seg to send
 * @param pcb the tcp_pcb for the TCP connection used to send the segment
 */
static err_t tcp_output_segment(struct tcp_seg *seg, struct tcp_pcb *pcb)
{
    /* zc_buf is only used to pass pointer to TCP header to ip_output(). */
    struct pbuf zc_pbuf;
    struct pbuf *p;
    u32_t *opts;

    /* The TCP header has already been constructed, but the ackno and
     wnd fields remain. */
    seg->tcphdr->ackno = htonl(pcb->rcv_nxt);

    if (seg->flags & TF_SEG_OPTS_WNDSCALE) {
        /* The Window field in a SYN segment itself (the only type where we send
           the window scale option) is never scaled. */
        seg->tcphdr->wnd = htons(TCPWND_MIN16(pcb->rcv_ann_wnd));
    } else {
        /* advertise our receive window size in this TCP segment */
        seg->tcphdr->wnd = htons(TCPWND_MIN16(RCV_WND_SCALE(pcb, pcb->rcv_ann_wnd)));
    }

    pcb->rcv_ann_right_edge = pcb->rcv_nxt + pcb->rcv_ann_wnd;

    /* Add any requested options.  NB MSS option is only set on SYN
       packets, so ignore it here */
    LWIP_ASSERT("seg->tcphdr not aligned", ((uintptr_t)(seg->tcphdr + 1) % 4) == 0);
    opts = (u32_t *)(void *)(seg->tcphdr + 1);
    if (seg->flags & TF_SEG_OPTS_MSS) {
        /* coverity[result_independent_of_operands] */
        TCP_BUILD_MSS_OPTION(*opts, pcb->advtsd_mss);
        opts++; // Move to the next line (meaning next 32 bit) as this option is 4 bytes long
    }

    /* If RCV_SCALE is set then prepare segment for window scaling option */
    if (seg->flags & TF_SEG_OPTS_WNDSCALE) {
        TCP_BUILD_WNDSCALE_OPTION(*opts, rcv_wnd_scale);
        opts++; // Move to the next line (meaning next 32 bit) as this option is 3 bytes long +
                // we added 1 byte NOOP padding => total 4 bytes
    }

#if LWIP_TCP_TIMESTAMPS
    pcb->ts_lastacksent = pcb->rcv_nxt;

    if (seg->flags & TF_SEG_OPTS_TS) {
        tcp_build_timestamp_option(pcb, opts);
        /* opts += 3; */ /* Note: suppress warning 'opts' is never read */ // Move to the next line
                                                                           // (meaning next 32 bit)
                                                                           // as this option is 10
                                                                           // bytes long, 12 with
                                                                           // padding (so jump 3
                                                                           // lines)
    }
#endif

    /* If we don't have a local IP address, we get one by
       calling ip_route(). */
    if (ip_addr_isany(&(pcb->local_ip), pcb->is_ipv6)) {
        LWIP_ASSERT("tcp_output_segment: need to find route to host", 0);
    }

    /* Set retransmission timer running if it is not currently enabled */
    if (pcb->rtime == -1) {
        pcb->rtime = 0;
    }

    if (pcb->ticks_since_data_sent == -1) {
        pcb->ticks_since_data_sent = 0;
    }

    if (pcb->rttest == 0) {
        pcb->rttest = tcp_ticks;
        pcb->rtseq = seg->seqno;

        LWIP_DEBUGF(TCP_RTO_DEBUG, ("tcp_output_segment: rtseq %" U32_F "\n", pcb->rtseq));
    }

    LWIP_DEBUGF(TCP_OUTPUT_DEBUG,
                ("tcp_output_segment: %" U32_F ":%" U32_F "\n", htonl(seg->tcphdr->seqno),
                 htonl(seg->tcphdr->seqno) + seg->len));

    seg->tcphdr->chksum = 0;

    /* for zercopy, add a pbuf for tcp/l3/l2 headers, prepend it to the list of pbufs */
    if (seg->flags & TF_SEG_OPTS_ZEROCOPY) {
        p = &zc_pbuf;
        /* Assign a unique type to distinguish pbuf on stack */
        p->type = PBUF_STACK;
        p->payload = seg->tcphdr;
        p->next = seg->p;
        p->len = p->tot_len = LWIP_TCP_HDRLEN(seg->tcphdr);
    } else {
        u32_t len = (u32_t)((u8_t *)seg->tcphdr - (u8_t *)seg->p->payload);

        seg->p->len -= len;
        seg->p->tot_len -= len;

        seg->p->payload = seg->tcphdr;
        p = seg->p;
    }

    u16_t flags = 0;
    flags |= seg->flags & TF_SEG_OPTS_TSO;
    flags |= (TCP_SEQ_LT(seg->seqno, pcb->snd_nxt) ? TCP_WRITE_REXMIT : 0);
    flags |= seg->flags & TF_SEG_OPTS_ZEROCOPY;

    return pcb->ip_output(p, seg, pcb, flags);
}

/**
 * Send a TCP RESET packet (empty segment with RST flag set) either to
 * abort a connection or to show that there is no matching local connection
 * for a received segment.
 *
 * Called by tcp_abort() (to abort a local connection), tcp_input() (if no
 * matching local pcb was found), tcp_listen_input() (if incoming segment
 * has ACK flag set) and tcp_process() (received segment in the wrong state)
 *
 * Since a RST segment is in most cases not sent for an active connection,
 * tcp_rst() has a number of arguments that are taken from a tcp_pcb for
 * most other segment output functions.
 *
 * The pcb is given only when its valid and from an output context.
 * It is used with the ip_output function.
 *
 * @param seqno the sequence number to use for the outgoing segment
 * @param ackno the acknowledge number to use for the outgoing segment
 * @param local_ip the local IP address to send the segment from
 * @param remote_ip the remote IP address to send the segment to
 * @param local_port the local TCP port to send the segment from
 * @param remote_port the remote TCP port to send the segment to
 */
void tcp_rst(u32_t seqno, u32_t ackno, u16_t local_port, u16_t remote_port, struct tcp_pcb *pcb)
{
    struct pbuf *p;
    struct tcp_hdr *tcphdr;

    if (!pcb) {
        return;
    }

    p = tcp_tx_pbuf_alloc(pcb, 0, PBUF_RAM, NULL, NULL);
    if (p == NULL) {
        LWIP_DEBUGF(TCP_DEBUG, ("tcp_rst: could not allocate memory for pbuf\n"));
        return;
    }
    pbuf_header(p, TCP_HLEN);
    LWIP_ASSERT("check that first pbuf can hold struct tcp_hdr",
                (p->len >= sizeof(struct tcp_hdr)));

    tcphdr = (struct tcp_hdr *)p->payload;
    tcphdr->src = htons(local_port);
    tcphdr->dest = htons(remote_port);
    tcphdr->seqno = htonl(seqno);
    tcphdr->ackno = htonl(ackno);
    TCPH_HDRLEN_FLAGS_SET(tcphdr, TCP_HLEN / 4, TCP_RST | TCP_ACK);
    tcphdr->wnd = PP_HTONS((TCP_WND & 0xFFFF));
    tcphdr->chksum = 0;
    tcphdr->urgp = 0;

    pcb->ip_output(p, NULL, pcb, 0);
    tcp_tx_pbuf_free(pcb, p);

    // Don't send delayed ACKs after RST
    pcb->flags &= ~TF_ACK_DELAY;

    LWIP_DEBUGF(TCP_RST_DEBUG, ("tcp_rst: seqno %" U32_F " ackno %" U32_F ".\n", seqno, ackno));
}

/**
 * Requeue all unacked segments for retransmission
 *
 * Called by tcp_slowtmr() for slow retransmission.
 *
 * @param pcb the tcp_pcb for which to re-enqueue all unacked segments
 */
void tcp_rexmit_rto(struct tcp_pcb *pcb)
{
    if (pcb->unacked == NULL) {
        return;
    }

    if (pcb->unsent != NULL && TCP_SEQ_GT(pcb->unacked->seqno, pcb->unsent->seqno)) {
        // Move fast-retransmitted segments to unacked - RTO after fast retransmission
        struct tcp_seg *rexmit_start = pcb->unsent;
        struct tcp_seg *rexmit_end = pcb->unsent;
        while (rexmit_end->next != NULL &&
               TCP_SEQ_GT(pcb->unacked->seqno, rexmit_end->next->seqno)) {
            rexmit_end = rexmit_end->next;
        }

        pcb->unsent = rexmit_end->next;
        if (pcb->unsent == NULL) {
            pcb->last_unsent = NULL;
        }

        rexmit_end->next = pcb->unacked;
        pcb->unacked = rexmit_start;
    }

    /* Move all unacked segments to the head of the unsent queue */
    if (pcb->unsent) {
        pcb->last_unacked->next = pcb->unsent;
    } else {
        /* If there are no unsent segments, update last_unsent to the last unacked */
        pcb->last_unsent = pcb->last_unacked;
    }
    /* unsent queue is the concatenated queue (of unacked, unsent) */
    pcb->unsent = pcb->unacked;
    /* unacked queue is now empty */
    pcb->unacked = NULL;
    pcb->last_unacked = NULL;

    /* increment number of retransmissions */
    ++pcb->nrtx;

    /* Don't take any RTT measurements after retransmitting. */
    pcb->rttest = 0;

    /* Do the actual retransmission */
    tcp_output(pcb);
}

/**
 * Requeue the first unacked segment for retransmission
 *
 * Called by tcp_receive() for fast retramsmit.
 *
 * @param pcb the tcp_pcb for which to retransmit the first unacked segment
 */
void tcp_rexmit(struct tcp_pcb *pcb)
{
    struct tcp_seg *seg;
    struct tcp_seg **cur_seg;

    if (pcb->unacked == NULL) {
        return;
    }

    /* Move the first unacked segment to the unsent queue */
    /* Keep the unsent queue sorted. */
    seg = pcb->unacked;

    pcb->unacked = pcb->unacked->next;
    if (NULL == pcb->unacked) {
        pcb->last_unacked = NULL;
    }

    cur_seg = &(pcb->unsent);
    while (*cur_seg && TCP_SEQ_LT((*cur_seg)->seqno, seg->seqno)) {
        cur_seg = &((*cur_seg)->next);
    }
    seg->next = *cur_seg;
    *cur_seg = seg;
    if (seg->next == NULL) {
        /* The retransmitted segment is the last in the unsent queue, update last_unsent */
        pcb->last_unsent = seg;
    }

    ++pcb->nrtx;

    /* Don't take any rtt measurements after retransmitting. */
    pcb->rttest = 0;
}

/**
 * Handle retransmission after three dupacks received
 *
 * @param pcb the tcp_pcb for which to retransmit the first unacked segment
 */
void tcp_rexmit_fast(struct tcp_pcb *pcb)
{
    if (pcb->unacked != NULL && !(pcb->flags & TF_INFR)) {
        /* This is fast retransmit. Retransmit the first unacked segment. */
        LWIP_DEBUGF(TCP_FR_DEBUG,
                    ("tcp_receive: dupacks %" U16_F " (%" U32_F "), fast retransmit %" U32_F "\n",
                     (u16_t)pcb->dupacks, pcb->lastack, pcb->unacked->seqno));
        tcp_rexmit(pcb);
#if TCP_CC_ALGO_MOD
        cc_cong_signal(pcb, CC_NDUPACK);
#else
        /* Set ssthresh to half of the minimum of the current
         * cwnd and the advertised window */
        if (pcb->cwnd > pcb->snd_wnd) {
            pcb->ssthresh = pcb->snd_wnd / 2;
        } else {
            pcb->ssthresh = pcb->cwnd / 2;
        }

        /* The minimum value for ssthresh should be 2 MSS */
        if (pcb->ssthresh < (2U * pcb->mss)) {
            LWIP_DEBUGF(TCP_FR_DEBUG,
                        ("tcp_receive: The minimum value for ssthresh %" U16_F
                         " should be min 2 mss %" U16_F "...\n",
                         pcb->ssthresh, 2 * pcb->mss));
            pcb->ssthresh = 2 * pcb->mss;
        }

        pcb->cwnd = pcb->ssthresh + 3 * pcb->mss;
#endif
        pcb->flags |= TF_INFR;
    }
}

/**
 * Send keepalive packets to keep a connection active although
 * no data is sent over it.
 *
 * Called by tcp_slowtmr()
 *
 * @param pcb the tcp_pcb for which to send a keepalive packet
 */
void tcp_keepalive(struct tcp_pcb *pcb)
{
    struct pbuf *p;
    struct tcp_hdr *tcphdr;
    u8_t optlen = 0;
    u32_t *opts;

    LWIP_DEBUGF_IP_ADDR(TCP_DEBUG, "tcp_keepalive: sending KEEPALIVE probe to ", pcb->remote_ip,
                        pcb->is_ipv6);

    LWIP_DEBUGF(TCP_DEBUG,
                ("tcp_keepalive: tcp_ticks %" U32_F "   pcb->tmr %" U32_F
                 " pcb->keep_cnt_sent %" U16_F "\n",
                 tcp_ticks, pcb->tmr, pcb->keep_cnt_sent));

#if LWIP_TCP_TIMESTAMPS
    if (pcb->flags & TF_TIMESTAMP) {
        optlen = LWIP_TCP_OPT_LENGTH(TF_SEG_OPTS_TS);
    }
#endif

    p = tcp_output_alloc_header(pcb, optlen, 0, htonl(pcb->snd_nxt - 1));
    if (p == NULL) {
        LWIP_DEBUGF(TCP_DEBUG, ("tcp_keepalive: could not allocate memory for pbuf\n"));
        return;
    }
    tcphdr = (struct tcp_hdr *)p->payload;
    opts = (u32_t *)(void *)(tcphdr + 1);

#if LWIP_TCP_TIMESTAMPS
    pcb->ts_lastacksent = pcb->rcv_nxt;
    if (pcb->flags & TF_TIMESTAMP) {
        tcp_build_timestamp_option(pcb, opts);
        opts += 3;
    }
#endif

    /* Send output to IP */
    pcb->ip_output(p, NULL, pcb, 0);
    tcp_tx_pbuf_free(pcb, p);

    if (pcb->ticks_since_data_sent == -1) {
        pcb->ticks_since_data_sent = 0;
    }

    LWIP_DEBUGF(
        TCP_DEBUG,
        ("tcp_keepalive: seqno %" U32_F " ackno %" U32_F ".\n", pcb->snd_nxt - 1, pcb->rcv_nxt));
    (void)tcphdr; /* Fix warning -Wunused-but-set-variable*/
    (void)opts; /* Fix warning -Wunused-but-set-variable */
}

/**
 * Send persist timer zero-window probes to keep a connection active
 * when a window update is lost.
 *
 * Called by tcp_slowtmr()
 *
 * @param pcb the tcp_pcb for which to send a zero-window probe packet
 */
void tcp_zero_window_probe(struct tcp_pcb *pcb)
{
    struct pbuf *p;
    struct tcp_hdr *tcphdr;
    struct tcp_seg *seg;
    u16_t len;
    u8_t is_fin;
    u8_t optlen = 0;
    u32_t snd_nxt;
    u32_t *opts;

    LWIP_DEBUGF_IP_ADDR(TCP_DEBUG, "tcp_zero_window_probe: sending ZERO WINDOW probe to ",
                        pcb->remote_ip, pcb->is_ipv6);

    LWIP_DEBUGF(TCP_DEBUG,
                ("tcp_zero_window_probe: tcp_ticks %" U32_F "   pcb->tmr %" U32_F
                 " pcb->keep_cnt_sent %" U16_F "\n",
                 tcp_ticks, pcb->tmr, pcb->keep_cnt_sent));

    /* Only consider unsent, persist timer should be off when there data is in-flight */
    seg = pcb->unsent;
    if (seg == NULL) {
        /* Not expected, persist timer should be off when the send buffer is empty */
        return;
    }

    is_fin = ((TCPH_FLAGS(seg->tcphdr) & TCP_FIN) != 0) && (seg->len == 0);
    /* we want to send one seqno: either FIN or data (no options) */
    len = is_fin ? 0 : 1;

#if LWIP_TCP_TIMESTAMPS
    if (pcb->flags & TF_TIMESTAMP) {
        optlen = LWIP_TCP_OPT_LENGTH(TF_SEG_OPTS_TS);
    }
#endif

    /**
     * While sending probe of 1 byte we must split the first unsent segment.
     * This change is commented out because tcp_zero_window_probe() was replaced
     * with tcp_keepalive().
     * if (len > 0 && seg->len != 1) {
     *   tcp_split_segment(pcb, seg, seg->seqno - pcb->lastack + 1);
     *   seg = pcb->unsent;
     * }
     */

    p = tcp_output_alloc_header(pcb, optlen, len, seg->tcphdr->seqno);
    if (p == NULL) {
        LWIP_DEBUGF(TCP_DEBUG, ("tcp_zero_window_probe: no memory for pbuf\n"));
        return;
    }
    tcphdr = (struct tcp_hdr *)p->payload;
    opts = (u32_t *)(void *)(tcphdr + 1);

#if LWIP_TCP_TIMESTAMPS
    pcb->ts_lastacksent = pcb->rcv_nxt;
    if (pcb->flags & TF_TIMESTAMP) {
        tcp_build_timestamp_option(pcb, opts);
        opts += 3;
    }
#endif

    if (is_fin) {
        /* FIN segment, no data */
        TCPH_FLAGS_SET(tcphdr, TCP_ACK | TCP_FIN);
    } else {
        /* Data segment, copy in one byte from the head of the unacked queue */
        *((char *)p->payload + TCP_HLEN + optlen) =
            *(char *)((u8_t *)seg->tcphdr + LWIP_TCP_HDRLEN(seg->tcphdr));
    }

    /* The byte may be acknowledged without the window being opened. */
    snd_nxt = ntohl(seg->tcphdr->seqno) + 1;
    if (TCP_SEQ_LT(pcb->snd_nxt, snd_nxt)) {
        pcb->snd_nxt = snd_nxt;
    }

    /* Send output to IP */
    pcb->ip_output(p, NULL, pcb, 0);
    tcp_tx_pbuf_free(pcb, p);

    LWIP_DEBUGF(TCP_DEBUG,
                ("tcp_zero_window_probe: seqno %" U32_F " ackno %" U32_F ".\n", pcb->snd_nxt - 1,
                 pcb->rcv_nxt));
    (void)opts; /* Fix warning -Wunused-but-set-variable */
}
