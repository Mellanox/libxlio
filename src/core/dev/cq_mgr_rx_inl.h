/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef CQ_MGR_INL_H
#define CQ_MGR_INL_H

#include "cq_mgr_rx.h"
#include "ring_simple.h"
#include "util/utils.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>

/**/
/** inlining functions can only help if they are implemented before their usage **/
/**/

inline void cq_mgr_rx::process_recv_buffer(mem_buf_desc_t *p_mem_buf_desc, void *pv_fd_ready_array)
{
    // Assume locked!!!

    // Pass the Rx buffer ib_comm_mgr for further IP processing
    if (!m_p_ring->rx_process_buffer(p_mem_buf_desc, pv_fd_ready_array)) {
        // If buffer is dropped by callback - return to RX pool
        reclaim_recv_buffer_helper(p_mem_buf_desc);
    }
}

inline uint32_t cq_mgr_rx::process_recv_queue(void *pv_fd_ready_array)
{
    // Assume locked!!!
    // If we have packets in the queue, dequeue one and process it
    // until reaching cq_poll_batch_max or empty queue
    uint32_t processed = 0;

    while (!m_rx_queue.empty()) {
        mem_buf_desc_t *buff = m_rx_queue.get_and_pop_front();
        process_recv_buffer(buff, pv_fd_ready_array);
        if (++processed >= m_n_sysvar_cq_poll_batch_max) {
            break;
        }
    }
    m_p_cq_stat->n_rx_sw_queue_len = m_rx_queue.size();
    return processed;
}

// This method is used as part of RX-Drain-and-Process flow, to decide if the packet
// should be processed immediately (TCP) or pushed to a queue (UDP).
inline bool is_eth_tcp_frame(mem_buf_desc_t *buff)
{
    struct ethhdr *p_eth_h = (struct ethhdr *)(buff->p_buffer);
    uint16_t h_proto = p_eth_h->h_proto;

    size_t transport_header_len = ETH_HDR_LEN;
    struct vlanhdr *p_vlan_hdr = nullptr;
    if (h_proto == htons(ETH_P_8021Q)) {
        p_vlan_hdr = (struct vlanhdr *)((uint8_t *)p_eth_h + transport_header_len);
        transport_header_len = ETH_VLAN_HDR_LEN;
        h_proto = p_vlan_hdr->h_vlan_encapsulated_proto;
    }
    if (h_proto == htons(ETH_P_IP)) {
        struct iphdr *p_ip_h = (struct iphdr *)(buff->p_buffer + transport_header_len);
        return (p_ip_h->protocol == IPPROTO_TCP);
    }
    if (likely(h_proto == htons(ETH_P_IPV6))) {
        struct ip6_hdr *p_ip_h = (struct ip6_hdr *)(buff->p_buffer + transport_header_len);

        // For IPv6 we must consider the case that there might be extention headers.
        // There is no way to determine the L4 protocol without parsing the ext headers.
        // Parsing the headers at this stage is a huge overhead.
        // So for all next_headers that are not TCP or UDP, we consider it as TCP,
        // Because for TCP with ext headers we still must return true. Otherwise,
        // there will be a long stall on the connection.

        // By using | we avoid branching.
        return ((p_ip_h->ip6_nxt == IPPROTO_TCP) | (p_ip_h->ip6_nxt != IPPROTO_UDP));
    }

    return false;
}

#endif // CQ_MGR_INL_H
