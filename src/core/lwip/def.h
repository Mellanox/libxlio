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
#ifndef __LWIP_DEF_H__
#define __LWIP_DEF_H__

#include "core/lwip/opt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LWIP_MAX(x, y) (((x) > (y)) ? (x) : (y))
#define LWIP_MIN(x, y) (((x) < (y)) ? (x) : (y))

#ifndef NULL
#define NULL ((void *)0)
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
/* These macros should be calculated by the preprocessor and are used
   with compile-time constants only (so that there is no little-endian
   overhead at runtime). */
#define PP_HTONS(x) ((((x)&0xff) << 8) | (((x)&0xff00) >> 8))
#define PP_NTOHS(x) PP_HTONS(x)
#define PP_HTONL(x)                                                                                \
    ((((x)&0xff) << 24) | (((x)&0xff00) << 8) | (((x)&0xff0000UL) >> 8) |                          \
     (((x)&0xff000000UL) >> 24))
#define PP_NTOHL(x) PP_HTONL(x)
#else /* __BYTE_ORDER__ */
#define PP_HTONS(x) (x)
#define PP_NTOHS(x) (x)
#define PP_HTONL(x) (x)
#define PP_NTOHL(x) (x)
#endif /* __BYTE_ORDER__ */

static inline u32_t read32_be(const void *addr)
{
    const u8_t *p = (const u8_t *)addr;
    u32_t ret = 0;

    ret |= (u32_t)p[3];
    ret |= (u32_t)p[2] << 8U;
    ret |= (u32_t)p[1] << 16U;
    ret |= (u32_t)p[0] << 24U;

    return ret;
}

#ifdef __cplusplus
}
#endif

#endif /* __LWIP_DEF_H__ */
