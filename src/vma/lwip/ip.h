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
#ifndef __LWIP_IP_H__
#define __LWIP_IP_H__

#include "vma/lwip/opt.h"
#include "vma/lwip/ip_addr.h"

#ifdef __cplusplus
extern "C" {
#endif

/* This is the common part of all PCB types. It needs to be at the
   beginning of a PCB type definition. It is located here so that
   changes to this common part are made in one location instead of
   having to change all PCB structs. */
#define IP_PCB \
  /* ip addresses in network byte order */ \
  ip_addr_t local_ip; \
  ip_addr_t remote_ip; \
  bool is_ipv6; \
   /* Socket options */  \
  u8_t so_options;      \
   /* Type Of Service */ \
  u8_t tos;              \
  /* Time To Live */     \
  u8_t ttl

/*
 * Option flags per-socket. These are the same like SO_XXX.
 */
/*#define SOF_DEBUG       (u8_t)0x01U     Unimplemented: turn on debugging info recording */
#define SOF_ACCEPTCONN    (u8_t)0x02U  /* socket has had listen() */
#define SOF_REUSEADDR     (u8_t)0x04U  /* allow local address reuse */
#define SOF_KEEPALIVE     (u8_t)0x08U  /* keep connections alive */
/*#define SOF_DONTROUTE   (u8_t)0x10U     Unimplemented: just use interface addresses */
#define SOF_BROADCAST     (u8_t)0x20U  /* permit to send and to receive broadcast messages (see IP_SOF_BROADCAST option) */
/*#define SOF_USELOOPBACK (u8_t)0x40U     Unimplemented: bypass hardware when possible */
#define SOF_LINGER        (u8_t)0x80U  /* linger on close if data present */
/*#define SOF_OOBINLINE   (u16_t)0x0100U     Unimplemented: leave received OOB data in line */
/*#define SOF_REUSEPORT   (u16_t)0x0200U     Unimplemented: allow local address & port reuse */

/* These flags are inherited (e.g. from a listen-pcb to a connection-pcb): */
#define SOF_INHERITED   (SOF_REUSEADDR|SOF_KEEPALIVE|SOF_LINGER/*|SOF_DEBUG|SOF_DONTROUTE|SOF_OOBINLINE*/)

#define IPV6_VERSION 6U

#define IP_HLEN 20U
#define IPV6_HLEN 40U

#ifdef __cplusplus
}
#endif

#endif /* __LWIP_IP_H__ */
