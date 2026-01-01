/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef DST_ENTRY_UDP_H
#define DST_ENTRY_UDP_H

#include "core/proto/dst_entry.h"

class dst_entry_udp : public dst_entry {
public:
    dst_entry_udp(const sock_addr &dst, uint16_t src_port, socket_data &sock_data,
                  resource_allocation_key &ring_alloc_logic);
    virtual ~dst_entry_udp();

    ssize_t fast_send(const iovec *p_iov, const ssize_t sz_iov, xlio_send_attr attr);
    ssize_t slow_send(const iovec *p_iov, const ssize_t sz_iov, xlio_send_attr attr,
                      struct xlio_rate_limit_t &rate_limit, int flags = 0, sockinfo *sock = nullptr,
                      tx_call_t call_type = TX_UNDEF);
    static bool fast_send_fragmented_ipv6(mem_buf_desc_t *p_mem_buf_desc, const iovec *p_iov,
                                          const ssize_t sz_iov, xlio_wr_tx_packet_attr attr,
                                          size_t sz_udp_payload, int n_num_frags,
                                          xlio_ibv_send_wr *p_send_wqe, ring_user_id_t user_id,
                                          ibv_sge *p_sge, header *p_header,
                                          uint16_t max_ip_payload_size, ring *p_ring,
                                          uint32_t pakcet_id);

protected:
    virtual transport_t get_transport(const sock_addr &to);
    virtual uint8_t get_protocol_type() const { return IPPROTO_UDP; };
    virtual uint32_t get_inline_sge_num() { return 2; };
    virtual ibv_sge *get_sge_lst_4_inline_send() { return m_sge; };
    virtual ibv_sge *get_sge_lst_4_not_inline_send() { return &m_sge[1]; };
    virtual void configure_headers();
    virtual void init_sge();
    ssize_t pass_buff_to_neigh(const iovec *p_iov, size_t sz_iov);

private:
    inline uint16_t gen_packet_id_ip4() { return htons(static_cast<uint16_t>(m_frag_tx_pkt_id++)); }

    inline uint32_t gen_packet_id_ip6() { return htonl(m_frag_tx_pkt_id++); }

    inline ssize_t fast_send_not_fragmented(const iovec *p_iov, const ssize_t sz_iov,
                                            xlio_wr_tx_packet_attr attr, size_t sz_udp_payload,
                                            ssize_t sz_data_payload);
    inline bool fast_send_fragmented_ipv4(mem_buf_desc_t *p_mem_buf_desc, const iovec *p_iov,
                                          const ssize_t sz_iov, xlio_wr_tx_packet_attr attr,
                                          size_t sz_udp_payload, int n_num_frags);
    inline bool fast_send_fragmented_ipv6(mem_buf_desc_t *p_mem_buf_desc, const iovec *p_iov,
                                          const ssize_t sz_iov, xlio_wr_tx_packet_attr attr,
                                          size_t sz_udp_payload, int n_num_frags);
    ssize_t fast_send_fragmented(const iovec *p_iov, const ssize_t sz_iov,
                                 xlio_wr_tx_packet_attr attr, size_t sz_udp_payload,
                                 ssize_t sz_data_payload);

    uint32_t m_frag_tx_pkt_id = 0U;
    const uint32_t m_n_sysvar_tx_bufs_batch_udp;
    const bool m_b_sysvar_tx_nonblocked_eagains;
    const uint32_t m_n_sysvar_tx_prefetch_bytes;
};

#endif /* DST_ENTRY_UDP_H */
