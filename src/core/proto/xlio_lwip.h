/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef _XLIO_LWIP_H
#define _XLIO_LWIP_H

#include "core/event/timer_handler.h"
#include "core/proto/mem_buf_desc.h"
#include "core/lwip/tcp.h"

typedef enum xlio_wr_tx_packet_attr {
    /* 8 bits are reserved for TCP flags (see lwip/tcp.h)
     * this option should be synchronized with lwip/tcp value
     */
    /* retransmit operation. */
    XLIO_TX_PACKET_REXMIT = TCP_WRITE_REXMIT, /* 0x08 */
    /* large segment offload operation. */
    XLIO_TX_PACKET_TSO = TCP_WRITE_TSO, /* 0x20 */
    /* sendfile operation. */
    XLIO_TX_FILE = TCP_WRITE_FILE, /* 0x40 */
    /* zcopy write operation (MSG_ZEROCOPY). */
    XLIO_TX_PACKET_ZEROCOPY = TCP_WRITE_ZEROCOPY, /* 0x80 */

    /* MLX5_ETH_WQE_L3_CSUM offload to HW L3 (IP) header checksum
     * Important:
     *  - hardcoded value used directly to program send to wire
     *  - it is the same as XLIO_TX_FILE but there is no conflict as far as
     *    XLIO_TX_FILE is passed into dst_entry::fast_send() operation
     *    and it is not needed later doing send to wire
     */
    XLIO_TX_PACKET_L3_CSUM = (1 << 6),
    /* MLX5_ETH_WQE_L4_CSUM offload to HW L4 (TCP/UDP) header checksum
     * Important:
     *  - hardcoded value used directly to program send to wire
     *  - it is the same as TCP_WRITE_ZEROCOPY but there is no conflict as far as
     *    TCP_WRITE_ZEROCOPY is passed into dst_entry::fast_send() operation
     *    and it is not needed later doing send to wire
     */
    XLIO_TX_PACKET_L4_CSUM = (1 << 7),
    /* blocking send operation */
    XLIO_TX_PACKET_BLOCK = (1 << 8),
    /* Force SW checksum */
    XLIO_TX_SW_L4_CSUM = (1 << 9),
    /* Skip TX polling */
    XLIO_TX_SKIP_POLL = (1 << 10),
} xlio_wr_tx_packet_attr;

static inline bool is_set(xlio_wr_tx_packet_attr state_, xlio_wr_tx_packet_attr tx_mode_)
{
    return (uint32_t)state_ & (uint32_t)tx_mode_;
}

static inline const char *lwip_cc_algo_str(uint32_t algo)
{
    switch (algo) {
    case CC_MOD_CUBIC:
        return "cubic";
    case CC_MOD_NONE:
        return "disable";
    case CC_MOD_LWIP:
    default:
        return "lwip";
    }
}

class xlio_lwip : public timer_handler {
public:
    xlio_lwip();
    virtual ~xlio_lwip();

    virtual void handle_timer_expired(void *user_data);

    static u32_t sys_now(void);

private:
    bool m_run_timers;

    void free_lwip_resources(void);

    static u8_t read_tcp_timestamp_option(void);
};

extern xlio_lwip *g_p_lwip;

uint32_t get_lwip_tcp_mss(uint32_t mtu, uint32_t lwip_mss);

#endif
