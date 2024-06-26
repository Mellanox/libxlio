/**
 * @file
 * Packet buffer management
 *
 * Packets are built from the pbuf data structure. It supports dynamic
 * memory allocation for packet contents or can reference externally
 * managed packet contents both in RAM and ROM. Quick allocation for
 * incoming packets is provided through pools with fixed sized pbufs.
 *
 * A packet may span over multiple pbufs, chained as a singly linked
 * list. This is called a "pbuf chain".
 *
 * Multiple packets may be queued, also using this singly linked list.
 * This is called a "packet queue".
 *
 * So, a packet queue consists of one or more pbuf chains, each of
 * which consist of one or more pbufs. CURRENTLY, PACKET QUEUES ARE
 * NOT SUPPORTED!!! Use helper structs to queue multiple packets.
 *
 * The differences between a pbuf chain and a packet queue are very
 * precise but subtle.
 *
 * The last pbuf of a packet has a ->tot_len field that equals the
 * ->len field. It can be found by traversing the list. If the last
 * pbuf of a packet has a ->next field other than NULL, more packets
 * are on the queue.
 *
 * Therefore, looping through a pbuf of a single packet, has an
 * loop end condition (tot_len == p->len), NOT (next == NULL).
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

#include "core/lwip/pbuf.h"

#if TCP_QUEUE_OOSEQ
#include "core/lwip/tcp_impl.h"
#endif

/**
 * Shrink a pbuf chain to a desired length.
 *
 * @param p pbuf to shrink.
 * @param new_len desired new length of pbuf chain
 *
 * Depending on the desired length, the first few pbufs in a chain might
 * be skipped and left unchanged. The new last pbuf in the chain will be
 * resized, and any remaining pbufs will be freed.
 *
 * @note If the pbuf is ROM/REF, only the ->tot_len and ->len fields are adjusted.
 * @note May not be called on a packet queue.
 *
 * @note Despite its name, pbuf_realloc cannot grow the size of a pbuf (chain).
 */
void pbuf_realloc(struct pbuf *p, u32_t new_len)
{
    struct pbuf *q;
    u32_t rem_len; /* remaining length */
    s32_t grow;

    LWIP_ASSERT("pbuf_realloc: p != NULL", p != NULL);
    LWIP_ASSERT("pbuf_realloc: sane p->type", p->type == PBUF_RAM);

    /* desired length larger than current length? */
    if (new_len >= p->tot_len) {
        /* enlarging not yet supported */
        return;
    }

    /* the pbuf chain grows by (new_len - p->tot_len) bytes
     * (which may be negative in case of shrinking) */
    grow = new_len - p->tot_len;

    /* first, step over any pbufs that should remain in the chain */
    rem_len = new_len;
    q = p;
    /* should this pbuf be kept? */
    while (rem_len > q->len) {
        /* decrease remaining length by pbuf length */
        rem_len -= q->len;
        /* decrease total length indicator */
        q->tot_len += grow;
        /* proceed to next pbuf in chain */
        q = q->next;
        LWIP_ASSERT("pbuf_realloc: q != NULL", q != NULL);
    }
    /* we have now reached the new last pbuf (in q) */
    /* rem_len == desired length for pbuf q */

    /* shrink allocated memory for PBUF_RAM */
    /* (other types merely adjust their length fields */
    if ((q->type == PBUF_RAM) && (rem_len != q->len)) {
        LWIP_ASSERT("pbuf_realloc: we don't need to be here ", 0);
    }
    /* adjust length fields for new last pbuf */
    q->len = rem_len;
    q->tot_len = q->len;

    /* any remaining pbufs in chain? */
    if (q->next != NULL) {
        /* free remaining pbufs in chain */
        pbuf_free(q->next);
    }
    /* q is last packet in chain */
    q->next = NULL;
}

/**
 * Adjusts the payload pointer to hide or reveal headers in the payload.
 *
 * Adjusts the ->payload pointer so that space for a header
 * (dis)appears in the pbuf payload.
 * Only PBUF_RAM buffers are allowed.
 *
 * The ->payload, ->tot_len and ->len fields are adjusted.
 *
 * @param p pbuf to change the header size.
 * @param header_size_increment Number of bytes to increment header size which
 * increases the size of the pbuf. New space is on the front.
 * (Using a negative value decreases the header size.)
 * If hdr_size_inc is 0, this function does nothing and returns success.
 *
 * @return non-zero on failure, zero on success.
 */
u8_t pbuf_header(struct pbuf *p, s32_t header_size_increment)
{
    LWIP_ASSERT("p != NULL", p != NULL);

    if (p->type != PBUF_RAM) {
        return 1;
    }

    if (header_size_increment >= 0) {
        u32_t header_increment = (u32_t)header_size_increment;
        /* set new payload pointer */
        p->payload = (u8_t *)p->payload - header_increment;
        /* modify pbuf length fields */
        p->len += header_increment;
        p->tot_len += header_increment;
    } else {
        u32_t header_decrement = (u32_t)(-header_size_increment);
        /* Check that we aren't going to move off the end of the pbuf */
        if (header_decrement > p->len) {
            return 1;
        }

        /* set new payload pointer */
        p->payload = (u8_t *)p->payload + header_decrement;
        /* modify pbuf length fields */
        p->len -= header_decrement;
        p->tot_len -= header_decrement;
    }

    LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE,
                ("pbuf_header: new %p (%" S32_F ")\n", (void *)p->payload, header_size_increment));

    return 0;
}

/**
 * Dereference a pbuf chain or queue and deallocate any no-longer-used
 * pbufs at the head of this chain or queue.
 *
 * Decrements the pbuf reference count. If it reaches zero, the pbuf is
 * deallocated.
 *
 * For a pbuf chain, this is repeated for each pbuf in the chain,
 * up to the first pbuf which has a non-zero reference count after
 * decrementing. So, when all reference counts are one, the whole
 * chain is free'd.
 *
 * @param p The pbuf (chain) to be dereferenced.
 *
 * @return the number of pbufs that were de-allocated
 * from the head of the chain.
 *
 * @note MUST NOT be called on a packet queue (Not verified to work yet).
 * @note the reference counter of a pbuf equals the number of pointers
 * that refer to the pbuf (or into the pbuf).
 *
 * @internal examples:
 *
 * Assuming existing chains a->b->c with the following reference
 * counts, calling pbuf_free(a) results in:
 *
 * 1->2->3 becomes ...1->3
 * 3->3->3 becomes 2->3->3
 * 1->1->2 becomes ......1
 * 2->1->1 becomes 1->1->1
 * 1->1->1 becomes .......
 *
 */
u8_t pbuf_free(struct pbuf *p)
{
    struct pbuf *q;
    u8_t count;

    if (p == NULL) {
        LWIP_ASSERT("p != NULL", p != NULL);
        /* if assertions are disabled, proceed with debug output */
        LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("pbuf_free(p == NULL) was called.\n"));
        return 0;
    }
    LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_free(%p)\n", (void *)p));

    LWIP_ASSERT("pbuf_free: sane type", p->type == PBUF_RAM || p->type == PBUF_ZEROCOPY);

    count = 0;
    /* de-allocate all consecutive pbufs from the head of the chain that
     * obtain a zero reference count after decrementing */
    while (p != NULL) {
        /* all pbufs in a chain are referenced at least once */
        LWIP_ASSERT("pbuf_free: p->ref > 0", p->ref > 0);
        if ((--p->ref) == 0) {
            q = p->next;
            external_tcp_rx_pbuf_free(p);
            count++;
            p = q;
        } else {
            /* stop walking through the chain */
            p = NULL;
        }
    }
    return count;
}

/**
 * Count number of pbufs in a chain
 *
 * @param p first pbuf of chain
 * @return the number of pbufs in a chain
 */

u8_t pbuf_clen(struct pbuf *p)
{
    u8_t len;

    len = 0;
    while (p != NULL) {
        ++len;
        p = p->next;
    }
    return len;
}

/**
 * Increment the reference count of the pbuf.
 *
 * @param p pbuf to increase reference counter of
 *
 */
void pbuf_ref(struct pbuf *p)
{
    /* pbuf given? */
    if (p != NULL) {
        ++(p->ref);
    }
}

/**
 * Concatenate two pbufs (each may be a pbuf chain) and take over
 * the caller's reference of the tail pbuf.
 *
 * @note The caller MAY NOT reference the tail pbuf afterwards.
 * Use pbuf_chain() for that purpose in the original lwip project.
 *
 * @see pbuf_chain()
 */

void pbuf_cat(struct pbuf *h, struct pbuf *t)
{
    struct pbuf *p;

    LWIP_ASSERT("(h != NULL) && (t != NULL) (programmer violates API)",
                ((h != NULL) && (t != NULL)));

    /* proceed to last pbuf of chain */
    for (p = h; p->next != NULL; p = p->next) {
        /* add total length of second chain to all totals of first chain */
        p->tot_len += t->tot_len;
    }
    /* { p is last pbuf of first h chain, p->next == NULL } */
    LWIP_ASSERT("p->tot_len == p->len (of last pbuf in chain)", p->tot_len == p->len);
    LWIP_ASSERT("p->next == NULL", p->next == NULL);
    /* add total length of second chain to last pbuf total of first chain */
    p->tot_len += t->tot_len;
    /* chain last pbuf of head (p) with first of tail (t) */
    p->next = t;
    /* p->next now references t, but the caller will drop its reference to t,
     * so netto there is no change to the reference count of t.
     */
}
