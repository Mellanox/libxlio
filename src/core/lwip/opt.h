/**
 * @file
 *
 * lwIP Options Configuration
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
#ifndef __LWIP_OPT_H__
#define __LWIP_OPT_H__

#include <stdint.h>
#include <arpa/inet.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/*
   ---------------------------------
   ---------- TCP options ----------
   ---------------------------------
*/

/**
 * TCP_QUICKACK_THRESHOLD: TCP quickack threshold (bytes)
 * Quickack will be sent for payload <= TCP_QUICKACK_THRESHOLD.
 * if TCP_QUICKACK_THRESHOLD = 0, quickack threshold is disabled.
 * The threshold is effective only when TCP_QUICKACK is enabled.
 */
#define TCP_QUICKACK_THRESHOLD 0

/**
 * TCP_WND: The size of a TCP window.  This must be at least
 * (2 * TCP_MSS) for things to work well
 */
#define TCP_WND 0xFFFF

/**
 * TCP_MSS: TCP Maximum segment size. (default is 536, a conservative default,
 * you might want to increase this.)
 * For the receive side, this MSS is advertised to the remote side
 * when opening a connection. For the transmit size, this MSS sets
 * an upper limit on the MSS advertised by the remote host.
 */
/*
 * If you don't want to use lwip_tcp_mss for setting the mss during runtime, define TCP_MSS to the
 * DEFAULT_TCP_MSS
 */
#define CONST_TCP_MSS 1460
#define LWIP_TCP_MSS  (lwip_tcp_mss)

/* Misc */

// Enable LWIP DEBUG here
//#define PBUF_DEBUG       LWIP_DBG_ON
//#define TCP_DEBUG        LWIP_DBG_ON
//#define TCP_INPUT_DEBUG  LWIP_DBG_ON
//#define TCP_FR_DEBUG     LWIP_DBG_ON
//#define TCP_RTO_DEBUG    LWIP_DBG_ON
//#define TCP_CWND_DEBUG   LWIP_DBG_ON
//#define TCP_WND_DEBUG    LWIP_DBG_ON
//#define TCP_OUTPUT_DEBUG LWIP_DBG_ON
//#define TCP_RST_DEBUG    LWIP_DBG_ON
//#define TCP_QLEN_DEBUG   LWIP_DBG_ON
//#define TCP_TSO_DEBUG    LWIP_DBG_ON

/*
   ---------------------------------
   ---------- TCP options ----------
   ---------------------------------
*/

/**
 * TCP_TTL: Default Time-To-Live value.
 */
#ifndef TCP_TTL
#define TCP_TTL 255
#endif

/*
 * use custom congestion control algorithms
 */
#ifndef TCP_CC_ALGO_MOD
#define TCP_CC_ALGO_MOD 1
#endif

/**
 * window scaling parameter
 */
#define TCP_WND_SCALED(pcb) (TCP_WND << (pcb)->rcv_scale)

/**
 * TCP_MAXRTX: Maximum number of retransmissions of data segments.
 */
#ifndef TCP_MAXRTX
#define TCP_MAXRTX 12
#endif

/**
 * TCP_SYNMAXRTX: Maximum number of retransmissions of SYN segments.
 */
#ifndef TCP_SYNMAXRTX
#define TCP_SYNMAXRTX 6
#endif

/**
 * TCP_QUEUE_OOSEQ==1: TCP will queue segments that arrive out of order.
 * Define to 0 if your device is low on memory.
 */
#ifndef TCP_QUEUE_OOSEQ
#define TCP_QUEUE_OOSEQ 1
#endif

/**
 * TCP_CALCULATE_EFF_SEND_MSS: "The maximum size of a segment that TCP really
 * sends, the 'effective send MSS,' MUST be the smaller of the send MSS (which
 * reflects the available reassembly buffer size at the remote host) and the
 * largest size permitted by the IP layer" (RFC 1122)
 * Setting this to 1 enables code that checks TCP_MSS against the MTU of the
 * netif used for a connection and limits the MSS if it would be too big otherwise.
 */
#ifndef TCP_CALCULATE_EFF_SEND_MSS
#define TCP_CALCULATE_EFF_SEND_MSS 1
#endif

/**
 * LWIP_TCP_TIMESTAMPS==1: support the TCP timestamp option.
 */
#ifndef LWIP_TCP_TIMESTAMPS
#define LWIP_TCP_TIMESTAMPS 1
#endif

/**
 * TCP_WND_UPDATE_THRESHOLD: difference in window to trigger an
 * explicit window update
 */
#ifndef TCP_WND_UPDATE_THRESHOLD
#define TCP_WND_UPDATE_THRESHOLD (pcb->rcv_wnd_max / 4)
#endif

/*
   ------------------------------------
   ---------- Socket options ----------
   ------------------------------------
*/
/**
 * LWIP_TCP_KEEPALIVE==1: Enable TCP_KEEPIDLE, TCP_KEEPINTVL and TCP_KEEPCNT
 * options processing. Note that TCP_KEEPIDLE and TCP_KEEPINTVL have to be set
 * in seconds. (does not require sockets.c, and will affect tcp.c)
 */
#ifndef LWIP_TCP_KEEPALIVE
#define LWIP_TCP_KEEPALIVE 0
#endif

/* Platform endianness */
#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || !defined(__ORDER_BIG_ENDIAN__)
#warning "__BYTE_ORDER__ or __ORDER_..._ENDIAN__ is not defined"
#endif /* __BYTE_ORDER__ */

/* Define generic types used in lwIP */
typedef uint8_t u8_t;
typedef int8_t s8_t;
typedef uint16_t u16_t;
typedef int16_t s16_t;
typedef uint32_t u32_t;
typedef int32_t s32_t;
typedef uint64_t u64_t;
typedef int64_t s64_t;

/* Define (sn)printf formatters for these lwIP types */
#define X8_F  "02x"
#define U16_F "hu"
#define S16_F "hd"
#define X16_F "hx"
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"

/* Compiler hints for packing structures */
#define PACK_STRUCT_FIELD(x) x
#define PACK_STRUCT_STRUCT   __attribute__((packed))
#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_END

/* prototypes for printf() and abort() */
#include <stdio.h>
#include <stdlib.h>

#define LWIP_PLATFORM_ASSERT(x)                                                                    \
    do {                                                                                           \
        printf("Assertion \"%s\" failed at line %d in %s\n", x, __LINE__, __FILE__);               \
        fflush(NULL);                                                                              \
    } while (0)

#ifndef LWIP_UNUSED_ARG
#define LWIP_UNUSED_ARG(x) (void)x
#endif /* LWIP_UNUSED_ARG */

/*
   ---------------------------------------
   ---------- Debugging options ----------
   ---------------------------------------
*/

/** lower two bits indicate debug level
 * - 0 all
 * - 1 warning
 * - 2 serious
 * - 3 severe
 */
#define LWIP_DBG_LEVEL_ALL     0x00
#define LWIP_DBG_LEVEL_OFF     LWIP_DBG_LEVEL_ALL /* compatibility define only */
#define LWIP_DBG_LEVEL_WARNING 0x01 /* bad checksums, dropped packets, ... */
#define LWIP_DBG_LEVEL_SERIOUS 0x02 /* memory allocation failures, ... */
#define LWIP_DBG_LEVEL_SEVERE  0x03
#define LWIP_DBG_MASK_LEVEL    0x03

/** flag for LWIP_DEBUGF to enable that debug message */
#define LWIP_DBG_ON 0x80U
/** flag for LWIP_DEBUGF to disable that debug message */
#define LWIP_DBG_OFF 0x00U

/** flag for LWIP_DEBUGF indicating a tracing message (to follow program flow) */
#define LWIP_DBG_TRACE 0x40U
/** flag for LWIP_DEBUGF indicating a state debug message (to follow module states) */
#define LWIP_DBG_STATE 0x20U
/** flag for LWIP_DEBUGF indicating newly added code, not thoroughly tested yet */
#define LWIP_DBG_FRESH 0x10U
/** flag for LWIP_DEBUGF to halt after printing this debug message */
#define LWIP_DBG_HALT 0x08U

#define LWIP_ASSERT(message, assertion)

/** if "expression" isn't true, then print "message" and execute "handler" expression */
#ifndef LWIP_ERROR
#define LWIP_ERROR(message, expression, handler)                                                   \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            LWIP_PLATFORM_ASSERT(message);                                                         \
            handler;                                                                               \
        }                                                                                          \
    } while (0)
#endif /* LWIP_ERROR */

/**
 * LWIP_DBG_MIN_LEVEL: After masking, the value of the debug is
 * compared against this value. If it is smaller, then debugging
 * messages are written.
 */
#ifndef LWIP_DBG_MIN_LEVEL
#define LWIP_DBG_MIN_LEVEL LWIP_DBG_LEVEL_ALL
#endif

/**
 * LWIP_DBG_TYPES_ON: A mask that can be used to globally enable/disable
 * debug messages of certain types.
 */
#ifndef LWIP_DBG_TYPES_ON
#define LWIP_DBG_TYPES_ON LWIP_DBG_ON
#endif

/**
 * PBUF_DEBUG: Enable debugging in pbuf.c.
 */
#ifndef PBUF_DEBUG
#define PBUF_DEBUG LWIP_DBG_OFF
#endif

/**
 * TCP_DEBUG: Enable debugging for TCP.
 */
#ifndef TCP_DEBUG
#define TCP_DEBUG LWIP_DBG_OFF
#endif

/**
 * TCP_INPUT_DEBUG: Enable debugging in tcp_in.c for incoming debug.
 */
#ifndef TCP_INPUT_DEBUG
#define TCP_INPUT_DEBUG LWIP_DBG_OFF
#endif

/**
 * TCP_FR_DEBUG: Enable debugging in tcp_in.c for fast retransmit.
 */
#ifndef TCP_FR_DEBUG
#define TCP_FR_DEBUG LWIP_DBG_OFF
#endif

/**
 * TCP_RTO_DEBUG: Enable debugging in TCP for retransmit
 * timeout.
 */
#ifndef TCP_RTO_DEBUG
#define TCP_RTO_DEBUG LWIP_DBG_OFF
#endif

/**
 * TCP_CWND_DEBUG: Enable debugging for TCP congestion window.
 */
#ifndef TCP_CWND_DEBUG
#define TCP_CWND_DEBUG LWIP_DBG_OFF
#endif

/**
 * TCP_WND_DEBUG: Enable debugging in tcp_in.c for window updating.
 */
#ifndef TCP_WND_DEBUG
#define TCP_WND_DEBUG LWIP_DBG_OFF
#endif

/**
 * TCP_OUTPUT_DEBUG: Enable debugging in tcp_out.c output functions.
 */
#ifndef TCP_OUTPUT_DEBUG
#define TCP_OUTPUT_DEBUG LWIP_DBG_OFF
#endif

/**
 * TCP_RST_DEBUG: Enable debugging for TCP with the RST message.
 */
#ifndef TCP_RST_DEBUG
#define TCP_RST_DEBUG LWIP_DBG_OFF
#endif

/**
 * TCP_QLEN_DEBUG: Enable debugging for TCP queue lengths.
 */
#ifndef TCP_QLEN_DEBUG
#define TCP_QLEN_DEBUG LWIP_DBG_OFF
#endif

/**
 * TCP_TSO_DEBUG: Enable debugging for TSO.
 */
#ifndef TCP_TSO_DEBUG
#define TCP_TSO_DEBUG LWIP_DBG_OFF
#endif

#define LWIP_DEBUG_ENABLE                                                                          \
    PBUF_DEBUG | TCP_DEBUG | TCP_INPUT_DEBUG | TCP_FR_DEBUG | TCP_RTO_DEBUG | TCP_CWND_DEBUG |     \
        TCP_WND_DEBUG | TCP_OUTPUT_DEBUG | TCP_RST_DEBUG | TCP_QLEN_DEBUG | TCP_TSO_DEBUG

#if LWIP_DEBUG_ENABLE

/* Plaform specific diagnostic output */
#define LWIP_PLATFORM_DIAG(x)                                                                      \
    do {                                                                                           \
        printf x;                                                                                  \
        fflush(0);                                                                                 \
    } while (0)

/** print debug message only if debug message type is enabled...
 *  AND is of correct type AND is at least LWIP_DBG_LEVEL
 */
#define LWIP_DEBUGF(debug, message)                                                                \
    do {                                                                                           \
        if (((debug)&LWIP_DBG_ON) && ((debug)&LWIP_DBG_TYPES_ON) &&                                \
            ((s16_t)((debug)&LWIP_DBG_MASK_LEVEL) >= LWIP_DBG_MIN_LEVEL)) {                        \
            LWIP_PLATFORM_DIAG(message);                                                           \
            if ((debug)&LWIP_DBG_HALT) {                                                           \
                while (1)                                                                          \
                    ;                                                                              \
            }                                                                                      \
        }                                                                                          \
    } while (0)
#define LWIP_DEBUGF_IP_ADDR(debug, message, ip_addr, is_ipv6)                                      \
    do {                                                                                           \
        char _buf[INET6_ADDRSTRLEN] = "\0";                                                        \
        inet_ntop((is_ipv6) ? AF_INET6 : AF_INET, ip_addr, _buf, sizeof(_buf));                    \
        LWIP_DEBUGF(debug, ("%s : %s\n", message, _buf));                                          \
    } while (0)

#else /* LWIP_DEBUG_ENABLE */
#define LWIP_PLATFORM_DIAG(x)
#define LWIP_DEBUGF(debug, message)
#define LWIP_DEBUGF_IP_ADDR(debug, message, ip_addr, is_ipv6)
#endif /* LWIP_DEBUG_ENABLE */

#endif /* __LWIP_OPT_H__ */
