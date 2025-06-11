/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef RFS_UC_TCP_GRO_H
#define RFS_UC_TCP_GRO_H

#include "dev/rfs_uc.h"
#include <netinet/tcp.h>

#define IP_H_LEN_NO_OPTIONS    5
#define IP6_H_LEN_BYTES_NO_EXT 40

// ip_tot_len:
//     For IPv4, includes the header len and payload.
//     For IPv6, includes only the payload.
struct gro_mem_buf_desc {
    mem_buf_desc_t *p_first;
    mem_buf_desc_t *p_last;
    tcphdr *p_tcp_h;
    uint32_t buf_count;
    uint32_t next_seq;
    uint32_t ack;
    uint32_t ts_present;
    uint32_t tsval;
    uint32_t tsecr;
    uint16_t ip_tot_len;
    uint16_t wnd;
} typedef gro_mem_buf_desc_t;

class gro_mgr;

/**
 * @class rfs_uc_tcp_gro
 *
 * Object to manages the sink list of a UC TCP GRO flow
 * This object is used for maintaining the sink list and dispatching packets
 *
 */
class rfs_uc_tcp_gro : public rfs_uc {
public:
    rfs_uc_tcp_gro(flow_tuple *flow_spec_5t, ring_simple *p_ring,
                   rfs_rule_filter *rule_filter = nullptr, uint32_t flow_tag_id = 0);

    virtual bool rx_dispatch_packet(mem_buf_desc_t *p_rx_wc_buf_desc, void *pv_fd_ready_array);

    void flush(void *pv_fd_ready_array);

private:
    inline void flush_gro_desc(void *pv_fd_ready_array);
    inline bool add_packet(mem_buf_desc_t *mem_buf_desc, void *payload_ptr, tcphdr *p_tcp_h);
    inline void init_gro_desc(mem_buf_desc_t *mem_buf_desc, uint16_t ip_tot_len_pkt,
                              tcphdr *p_tcp_h);
    inline bool tcp_check(mem_buf_desc_t *mem_buf_desc, tcphdr *p_tcp_h);
    inline bool timestamp_check(tcphdr *p_tcp_h);

    gro_mgr *m_p_gro_mgr;
    ring_simple *m_p_ring_simple;
    bool m_b_active;
    bool m_b_reserved;
    struct gro_mem_buf_desc m_gro_desc;
    uint32_t m_n_buf_max;
    uint32_t m_n_byte_max;
    struct tcp_pcb *m_pcb;
};

#endif /* RFS_UC_TCP_GRO_H */
