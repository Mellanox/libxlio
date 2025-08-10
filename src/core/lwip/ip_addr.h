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
#ifndef __LWIP_IP_ADDR_H__
#define __LWIP_IP_ADDR_H__

#include <stdbool.h>
#include "core/lwip/opt.h"
#include "core/lwip/def.h"
#include "utils/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define XLIO_IPV4_VERSION 4U
#define XLIO_IPV6_VERSION 6U

/* RFC879 Section 1. Introduction */
#define IPV4_MIN_MTU 576U

#ifndef IPV6_MIN_MTU
#define IPV6_MIN_MTU 1280U
#endif
/* RFC6691 Section 2. The Short Statement */
#define IP_HLEN 20U
/* RFC2460 Section 8.3 Maximum Upper-Layer Payload Size */
#define IPV6_HLEN 40U

/** This is the aligned version of ip6_addr_t,
    used as local variable, on the stack, etc. */
typedef union ip6_addr {
    u64_t addr[2];
} ip6_addr_t;

/* This is the aligned version of ip_addr_t,
   used as local variable, on the stack, etc. */
typedef union ip4_addr {
    u32_t addr;
} ip4_addr_t;

/** ip_addr_t uses a struct for convenience only, so that the same defines can
 * operate both on ip_addr_t as well as on ip_addr_p_t. */
typedef union ip_addr_lwip {
    ip6_addr_t ip6;
    ip4_addr_t ip4;
} ip_addr_t;

/** Copy IP address - faster than ip_addr_set: no NULL check */
static inline void ip_addr_from_raw(ip_addr_t *dest, const void *src, bool is_ipv6)
{
    if (is_ipv6) {
        u64_t *src_addr = (u64_t *)src;
        dest->ip6.addr[0] = src_addr[0];
        dest->ip6.addr[1] = src_addr[1];
    } else {
        u32_t *src_addr = (u32_t *)src;
        dest->ip4.addr = *src_addr;
    }
}

static inline void ip_addr_copy(ip_addr_t *dest, const ip_addr_t *src, bool is_ipv6)
{
    if (is_ipv6) {
        dest->ip6.addr[0] = src->ip6.addr[0];
        dest->ip6.addr[1] = src->ip6.addr[1];
    } else {
        dest->ip4.addr = src->ip4.addr;
    }
}

static inline bool ip_addr_isany(const void *addr, bool is_ipv6)
{
    const u64_t *addr_64_view = (const u64_t *)addr;
    const u32_t *addr_32_view = (const u32_t *)addr;

    return is_ipv6 ? unlikely(addr_64_view[0] == 0ULL) && likely(addr_64_view[1] == 0ULL)
                   : unlikely(addr_32_view[0] == 0UL);
}

#ifdef __cplusplus
}
#endif

#endif /* __LWIP_IP_ADDR_H__ */
