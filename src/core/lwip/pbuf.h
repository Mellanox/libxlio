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

#ifndef __LWIP_PBUF_H__
#define __LWIP_PBUF_H__

#include "core/lwip/opt.h"
#include "core/lwip/err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PBUF_NONE, /* impossible type to catch zeroed pbuf objects */
    PBUF_RAM, /* pbuf data is stored in RAM */
    PBUF_STACK, /* pbuf is allocated on stack and mustn't be freed */
    PBUF_ZEROCOPY /* pbuf points to user's memory which mustn't be modified */
} pbuf_type;

/** indicates this packet's data should be immediately passed to the application */
#define PBUF_FLAG_PUSH 0x01U

/** Private data depending on type */
enum {
    PBUF_DESC_NONE = 0,
    PBUF_DESC_MDESC,
    PBUF_DESC_FD,
    PBUF_DESC_MKEY,
    PBUF_DESC_STRIDE,
    PBUF_DESC_TLS_RX,
    PBUF_DESC_NVME_TX,
    PBUF_DESC_EXPRESS,
};

typedef struct {
    int attr;
    u32_t mkey;
    union {
        int fd;
        void *mdesc;
        void *opaque;
    };
} pbuf_desc;

struct pbuf {
    /** next pbuf in singly linked pbuf chain */
    struct pbuf *next;

    /** pointer to the actual data in the buffer */
    void *payload;

    /** length of this buffer */
    u32_t len;

    u8_t gro;

    /**
     * total length of this buffer and all next buffers in chain
     * belonging to the same packet.
     *
     * For non-queue packet chains this is the invariant:
     * p->tot_len == p->len + (p->next? p->next->tot_len: 0)
     */
    u32_t tot_len; // windows scale needs large pbuf

    /** pbuf_type as u8_t instead of enum to save space */
    u8_t /*pbuf_type*/ type;

    /** misc flags */
    u8_t flags;

    /**
     * the reference count always equals the number of pointers
     * that refer to this pbuf. This can be pointers from an application,
     * the stack itself, or pbuf->next pointers from a chain.
     */
    u16_t ref;

    /** Customer specific description */
    pbuf_desc desc;
};

/** Prototype for a function to free a custom pbuf */
typedef void (*pbuf_free_custom_fn)(struct pbuf *p);

/** A custom pbuf: like a pbuf, but following a function pointer to free it. */
struct pbuf_custom {
    /** The actual pbuf */
    struct pbuf pbuf;
};

void pbuf_realloc(struct pbuf *p, u32_t size);
u8_t pbuf_header(struct pbuf *p, s32_t header_size);
void pbuf_ref(struct pbuf *p);
u8_t pbuf_free(struct pbuf *p);
u8_t pbuf_clen(struct pbuf *p);
void pbuf_cat(struct pbuf *head, struct pbuf *tail);

#ifdef __cplusplus
}
#endif

#endif /* __LWIP_PBUF_H__ */
