/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "utils/bullseye.h"
#include "core/util/utils.h"
#include "dst_entry_udp.h"
#include "sock/sockinfo.h"

#define MODULE_NAME "dst_udp"

#define dst_udp_logpanic   __log_panic
#define dst_udp_logerr     __log_err
#define dst_udp_logwarn    __log_warn
#define dst_udp_loginfo    __log_info
#define dst_udp_logdbg     __log_info_dbg
#define dst_udp_logfunc    __log_info_func
#define dst_udp_logfuncall __log_info_funcall

dst_entry_udp::dst_entry_udp(const sock_addr &dst, uint16_t src_port, socket_data &sock_data,
                             resource_allocation_key &ring_alloc_logic)
    : dst_entry(dst, src_port, sock_data, ring_alloc_logic)
    , m_n_sysvar_tx_bufs_batch_udp(safe_mce_sys().tx_bufs_batch_udp)
    , m_b_sysvar_tx_nonblocked_eagains(safe_mce_sys().tx_nonblocked_eagains)
    , m_n_sysvar_tx_prefetch_bytes(safe_mce_sys().tx_prefetch_bytes)
{
    dst_udp_logdbg("%s", to_str().c_str());
}

dst_entry_udp::~dst_entry_udp()
{
    dst_udp_logdbg("%s", to_str().c_str());
}

transport_t dst_entry_udp::get_transport(const sock_addr &to)
{
    return __xlio_match_udp_sender(TRANS_XLIO, safe_mce_sys().app_id, to.get_p_sa(), sizeof to);
}

// The following function supposed to be called under m_lock
void dst_entry_udp::configure_headers()
{
    m_header->init();
    m_header->configure_udp_header(m_dst_port, m_src_port);
    dst_entry::configure_headers();
}

// Static function to server both neigh (slow) path and dst_entry (fast) path
bool dst_entry_udp::fast_send_fragmented_ipv6(mem_buf_desc_t *p_mem_buf_desc, const iovec *p_iov,
                                              const ssize_t sz_iov, xlio_wr_tx_packet_attr attr,
                                              size_t sz_udp_payload, int n_num_frags,
                                              xlio_ibv_send_wr *p_send_wqe, ring_user_id_t user_id,
                                              ibv_sge *p_sge, header *p_header,
                                              uint16_t max_ip_payload_size, ring *p_ring,
                                              uint32_t packet_id)
{
    tx_ipv6_hdr_template_t *p_pkt;
    ip6_hdr *p_ip_hdr;
    udphdr *p_udp_hdr = nullptr;
    ip6_frag *p_frag_h;
    mem_buf_desc_t *tmp;

    bool first_frag = true;
    uint32_t n_ip_frag_offset = 0;
    size_t sz_user_data_offset = 0;

    // fragmentation extension header - copy it to every fragment
    // the only field that will change here is ip6f_offlg
    ip6_frag frag_h;
    frag_h.ip6f_ident = packet_id;
    frag_h.ip6f_nxt = IPPROTO_UDP;
    frag_h.ip6f_offlg = IP6F_MORE_FRAG;
    frag_h.ip6f_reserved = 0;

    while (n_num_frags--) {
        // Calc this ip datagram fragment size (include any headers)
        size_t sz_ip_frag = std::min((size_t)(max_ip_payload_size),
                                     (sz_udp_payload - n_ip_frag_offset + FRAG_EXT_HLEN));
        size_t sz_user_data_to_copy = sz_ip_frag - FRAG_EXT_HLEN;
        size_t hdr_len = p_header->m_transport_header_len +
            p_header->m_ip_header_len + // Add count of L2 (ipoib or mac) header length
            FRAG_EXT_HLEN; // Add count of fragmentation header length

        p_pkt = reinterpret_cast<tx_ipv6_hdr_template_t *>(p_mem_buf_desc->p_buffer);
        p_header->copy_l2_ip_hdr(p_pkt);

        if (first_frag) {
            get_ipv6_hdrs_frag_ext_udp_ptr(p_pkt, p_ip_hdr, p_frag_h, p_udp_hdr);
            memcpy(p_udp_hdr, p_header->get_udp_hdr(), sizeof(udphdr));

            // Add count of udp header length
            hdr_len += UDP_HLEN;

            // Copy less from user data
            sz_user_data_to_copy -= UDP_HLEN;

            // Only for first fragment add the udp header
            p_udp_hdr->len = htons((uint16_t)sz_udp_payload);

            // temporary sum of the entire payload
            // final checksum is calculated by attr XLIO_TX_PACKET_L4_CSUM
            p_udp_hdr->check = calc_sum_of_payload(p_iov, sz_iov);
            attr = (xlio_wr_tx_packet_attr)(attr | XLIO_TX_PACKET_L4_CSUM | XLIO_TX_SW_L4_CSUM);
        } else {
            get_ipv6_hdrs_frag_ext_ptr(p_pkt, p_ip_hdr, p_frag_h);
            attr = (xlio_wr_tx_packet_attr)(attr & ~(XLIO_TX_PACKET_L4_CSUM | XLIO_TX_SW_L4_CSUM));
        }

        memcpy(p_frag_h, &frag_h, sizeof(ip6_frag));
        if (n_num_frags == 0) {
            p_frag_h->ip6f_offlg &= ~IP6F_MORE_FRAG;
        }
        // offset should be << 3, but need to devide by 8, so no need to change n_ip_frag_offset
        p_frag_h->ip6f_offlg |= IP6F_OFF_MASK & htons(n_ip_frag_offset);

        p_ip_hdr->ip6_nxt = IPPROTO_FRAGMENT;
        p_ip_hdr->ip6_plen = htons(sz_ip_frag);

        // Calc payload start point (after the udp header if present else just after ip header)
        uint8_t *p_payload =
            p_mem_buf_desc->p_buffer + p_header->m_transport_header_tx_offset + hdr_len;

        // Copy user data to our tx buffers
        int ret =
            memcpy_fromiovec(p_payload, p_iov, sz_iov, sz_user_data_offset, sz_user_data_to_copy);
        BULLSEYE_EXCLUDE_BLOCK_START
        if (ret != (int)sz_user_data_to_copy) {
            vlog_printf(VLOG_ERROR, "memcpy_fromiovec error (sz_user_data_to_copy=%zu, ret=%d)\n",
                        sz_user_data_to_copy, ret);
            p_ring->mem_buf_tx_release(p_mem_buf_desc, true);
            return false;
        }
        BULLSEYE_EXCLUDE_BLOCK_END

        p_mem_buf_desc->tx.p_ip_h = p_ip_hdr;
        p_mem_buf_desc->tx.p_udp_h = p_udp_hdr;

        p_sge[0].addr =
            (uintptr_t)(p_mem_buf_desc->p_buffer + (uint8_t)p_header->m_transport_header_tx_offset);
        p_sge[0].length = sz_user_data_to_copy + hdr_len;
        p_sge[0].lkey = p_ring->get_tx_lkey(user_id);
        p_send_wqe->wr_id = (uintptr_t)p_mem_buf_desc;

        vlog_printf(VLOG_DEBUG, "packet_sz=%d, payload_sz=%zu, ip_offset=%u id=%u\n",
                    p_sge[0].length - p_header->m_transport_header_len, sz_user_data_to_copy,
                    n_ip_frag_offset, ntohl(packet_id));

        tmp = p_mem_buf_desc->p_next_desc;
        p_mem_buf_desc->p_next_desc = nullptr;

        // We don't check the return valuse of post send when we reach the HW we consider that we
        // completed our job
        p_ring->send_ring_buffer(user_id, p_send_wqe, attr);

        p_mem_buf_desc = tmp;

        // Update ip frag offset position
        n_ip_frag_offset += sz_ip_frag - FRAG_EXT_HLEN;

        // Update user data start offset copy location
        sz_user_data_offset += sz_user_data_to_copy;

        first_frag = false;
    } // while(n_num_frags)

    return true;
}

inline ssize_t dst_entry_udp::fast_send_not_fragmented(const iovec *p_iov, const ssize_t sz_iov,
                                                       xlio_wr_tx_packet_attr attr,
                                                       size_t sz_udp_payload,
                                                       ssize_t sz_data_payload)
{
    mem_buf_desc_t *p_mem_buf_desc;
    xlio_ibv_send_wr *p_send_wqe;
    bool b_blocked = is_set(attr, XLIO_TX_PACKET_BLOCK);

    // Get a bunch of tx buf descriptor and data buffers
    if (unlikely(!m_p_tx_mem_buf_desc_list)) {
        m_p_tx_mem_buf_desc_list =
            m_p_ring->mem_buf_tx_get(m_id, b_blocked, PBUF_RAM, m_n_sysvar_tx_bufs_batch_udp);

        if (unlikely(!m_p_tx_mem_buf_desc_list)) {
            if (b_blocked) {
                dst_udp_logdbg("Error when blocking for next tx buffer (errno=%d %m)", errno);
            } else {
                dst_udp_logfunc(
                    "Packet dropped. NonBlocked call but not enough tx buffers. Returning OK");
                if (!m_b_sysvar_tx_nonblocked_eagains) {
                    return sz_data_payload;
                }
            }
            errno = EAGAIN;
            return -1;
        }
    }
    // Disconnect the first buffer from the list
    p_mem_buf_desc = m_p_tx_mem_buf_desc_list;
    m_p_tx_mem_buf_desc_list = m_p_tx_mem_buf_desc_list->p_next_desc;
    p_mem_buf_desc->p_next_desc = nullptr;

    set_tx_buff_list_pending(false);

    // Check if inline is possible
    // Skip inlining in case of L4 SW checksum because headers and data are not contiguous in memory
    if (sz_iov == 1 && ((sz_data_payload + m_header->m_total_hdr_len) < m_max_inline) &&
        !is_set(attr, XLIO_TX_SW_L4_CSUM)) {
        p_send_wqe = &m_inline_send_wqe;

        m_header->get_udp_hdr()->len = htons((uint16_t)sz_udp_payload);
        m_header->set_ip_len(m_header->m_ip_header_len + sz_udp_payload);

        p_mem_buf_desc->tx.p_ip_h = m_header->get_ip_hdr();
        p_mem_buf_desc->tx.p_udp_h = m_header->get_udp_hdr();

        // m_sge[0].addr  already points to the header
        // so we just need to update the payload addr + len
        m_sge[1].length = p_iov[0].iov_len;
        m_sge[1].addr = (uintptr_t)p_iov[0].iov_base;
        m_sge[1].lkey = m_p_ring->get_tx_lkey(m_id);
    } else {
        p_send_wqe = &m_not_inline_send_wqe;

        void *p_pkt = p_mem_buf_desc->p_buffer;
        void *p_ip_hdr;
        void *p_udp_hdr;

        size_t hdr_len = m_header->m_transport_header_len + m_header->m_ip_header_len +
            UDP_HLEN; // Add count of L2 (ipoib or mac) header length and udp header

        if (m_n_sysvar_tx_prefetch_bytes) {
            prefetch_range(p_mem_buf_desc->p_buffer + m_header->m_transport_header_tx_offset,
                           std::min(sz_udp_payload, (size_t)m_n_sysvar_tx_prefetch_bytes));
        }

        m_header->copy_l2_ip_udp_hdr(p_pkt);

        uint16_t payload_length_ipv4 = m_header->m_ip_header_len + sz_udp_payload;
        if (get_sa_family() == AF_INET6) {
            fill_hdrs<tx_ipv6_hdr_template_t>(p_pkt, p_ip_hdr, p_udp_hdr);
            set_ipv6_len(p_ip_hdr, htons(payload_length_ipv4 - IPV6_HLEN));
        } else {
            fill_hdrs<tx_ipv4_hdr_template_t>(p_pkt, p_ip_hdr, p_udp_hdr);
            set_ipv4_len(p_ip_hdr, htons(payload_length_ipv4));
            reinterpret_cast<iphdr *>(p_ip_hdr)->frag_off = htons(0);
            reinterpret_cast<iphdr *>(p_ip_hdr)->id = 0;
        }

        reinterpret_cast<udphdr *>(p_udp_hdr)->len = htons((uint16_t)sz_udp_payload);
        p_mem_buf_desc->tx.p_ip_h = p_ip_hdr;
        p_mem_buf_desc->tx.p_udp_h = reinterpret_cast<udphdr *>(p_udp_hdr);

        // Update the payload addr + len
        m_sge[1].length = sz_data_payload + hdr_len;
        m_sge[1].addr =
            (uintptr_t)(p_mem_buf_desc->p_buffer + (uint8_t)m_header->m_transport_header_tx_offset);
        m_sge[1].lkey = m_p_ring->get_tx_lkey(m_id);

        // Calc payload start point (after the udp header if present else just after ip header)
        uint8_t *p_payload =
            p_mem_buf_desc->p_buffer + m_header->m_transport_header_tx_offset + hdr_len;

        // Copy user data to our tx buffers
        int ret = memcpy_fromiovec(p_payload, p_iov, sz_iov, 0, sz_data_payload);
        BULLSEYE_EXCLUDE_BLOCK_START
        if (ret != (int)sz_data_payload) {
            dst_udp_logerr("memcpy_fromiovec error (sz_user_data_to_copy=%lu, ret=%d)",
                           sz_data_payload, ret);
            m_p_ring->mem_buf_tx_release(p_mem_buf_desc, true);
            errno = EINVAL;
            return -1;
        }
        BULLSEYE_EXCLUDE_BLOCK_END
    }

    p_send_wqe->wr_id = reinterpret_cast<uintptr_t>(p_mem_buf_desc);
    m_p_ring->send_ring_buffer(m_id, p_send_wqe, attr);

    // request tx buffers for the next packets
    if (unlikely(!m_p_tx_mem_buf_desc_list)) {
        m_p_tx_mem_buf_desc_list =
            m_p_ring->mem_buf_tx_get(m_id, b_blocked, PBUF_RAM, m_n_sysvar_tx_bufs_batch_udp);
    }

    // If all went well :) then return the user data count transmitted
    return sz_data_payload;
}

inline bool dst_entry_udp::fast_send_fragmented_ipv4(mem_buf_desc_t *p_mem_buf_desc,
                                                     const iovec *p_iov, const ssize_t sz_iov,
                                                     xlio_wr_tx_packet_attr attr,
                                                     size_t sz_udp_payload, int n_num_frags)
{
    void *p_pkt;
    void *p_ip_hdr;
    void *p_udp_hdr;
    mem_buf_desc_t *tmp;
    xlio_ibv_send_wr *p_send_wqe = &m_fragmented_send_wqe;
    uint16_t packet_id = gen_packet_id_ip4();

    // Int for counting offset inside the ip datagram payload
    uint32_t n_ip_frag_offset = 0;
    size_t sz_user_data_offset = 0;

    while (n_num_frags--) {
        // Calc this ip datagram fragment size (include any udp header)
        size_t sz_ip_frag =
            std::min((size_t)m_max_ip_payload_size, (sz_udp_payload - n_ip_frag_offset));
        size_t sz_user_data_to_copy = sz_ip_frag;
        size_t hdr_len = m_header->m_transport_header_len +
            m_header->m_ip_header_len; // Add count of L2 (ipoib or mac) header length

        if (m_n_sysvar_tx_prefetch_bytes) {
            prefetch_range(p_mem_buf_desc->p_buffer + m_header->m_transport_header_tx_offset,
                           std::min(sz_ip_frag, (size_t)m_n_sysvar_tx_prefetch_bytes));
        }

        p_pkt = p_mem_buf_desc->p_buffer;

        fill_hdrs<tx_ipv4_hdr_template_t>(p_pkt, p_ip_hdr, p_udp_hdr);

        uint16_t frag_off = 0;
        if (n_num_frags) {
            frag_off |= IP_MF;
        }

        if (n_ip_frag_offset == 0) {
            m_header->copy_l2_ip_udp_hdr(p_pkt);
            // Add count of udp header length
            hdr_len += UDP_HLEN;

            // Copy less from user data
            sz_user_data_to_copy -= UDP_HLEN;

            // Only for first fragment add the udp header
            reinterpret_cast<udphdr *>(p_udp_hdr)->len = htons((uint16_t)sz_udp_payload);
        } else {
            m_header->copy_l2_ip_hdr(p_pkt);
            frag_off |= IP_OFFMASK & (n_ip_frag_offset / 8);
        }

        iphdr *p_ip_hdr_cast = reinterpret_cast<iphdr *>(p_ip_hdr);
        p_ip_hdr_cast->frag_off = htons(frag_off);
        // Update ip header specific values
        p_ip_hdr_cast->id = packet_id;
        p_ip_hdr_cast->tot_len = htons(m_header->m_ip_header_len + sz_ip_frag);

        // Calc payload start point (after the udp header if present else just after ip header)
        uint8_t *p_payload =
            p_mem_buf_desc->p_buffer + m_header->m_transport_header_tx_offset + hdr_len;

        // Copy user data to our tx buffers
        int ret =
            memcpy_fromiovec(p_payload, p_iov, sz_iov, sz_user_data_offset, sz_user_data_to_copy);
        BULLSEYE_EXCLUDE_BLOCK_START
        if (ret != (int)sz_user_data_to_copy) {
            dst_udp_logerr("memcpy_fromiovec error (sz_user_data_to_copy=%lu, ret=%d)",
                           sz_user_data_to_copy, ret);
            m_p_ring->mem_buf_tx_release(p_mem_buf_desc, true);
            return false;
        }
        BULLSEYE_EXCLUDE_BLOCK_END

        p_mem_buf_desc->tx.p_ip_h = p_ip_hdr;
        p_mem_buf_desc->tx.p_udp_h = reinterpret_cast<udphdr *>(p_udp_hdr);

        m_sge[1].addr =
            (uintptr_t)(p_mem_buf_desc->p_buffer + (uint8_t)m_header->m_transport_header_tx_offset);
        m_sge[1].length = sz_user_data_to_copy + hdr_len;
        m_sge[1].lkey = m_p_ring->get_tx_lkey(m_id);
        p_send_wqe->wr_id = (uintptr_t)p_mem_buf_desc;

        dst_udp_logfunc("packet_sz=%d, payload_sz=%d, ip_offset=%d id=%d",
                        m_sge[1].length - m_header->m_transport_header_len, sz_user_data_to_copy,
                        n_ip_frag_offset, ntohs(packet_id));

        tmp = p_mem_buf_desc->p_next_desc;
        p_mem_buf_desc->p_next_desc = nullptr;

        // We don't check the return valuse of post send when we reach the HW we consider that we
        // completed our job
        m_p_ring->send_ring_buffer(m_id, p_send_wqe, attr);

        p_mem_buf_desc = tmp;

        // Update ip frag offset position
        n_ip_frag_offset += sz_ip_frag;

        // Update user data start offset copy location
        sz_user_data_offset += sz_user_data_to_copy;

    } // while(n_num_frags)

    return true;
}

ssize_t dst_entry_udp::fast_send_fragmented(const iovec *p_iov, const ssize_t sz_iov,
                                            xlio_wr_tx_packet_attr attr, size_t sz_udp_payload,
                                            ssize_t sz_data_payload)
{
    bool b_blocked = is_set(attr, XLIO_TX_PACKET_BLOCK);
    bool is_ipv6 = (get_sa_family() == AF_INET6);
    uint16_t max_payload_size_per_packet = m_max_ip_payload_size - (is_ipv6 ? FRAG_EXT_HLEN : 0);

    // Find number of ip fragments (-> packets, buffers, buffer descs...)
    int n_num_frags =
        (sz_udp_payload + max_payload_size_per_packet - 1) / max_payload_size_per_packet;
    dst_udp_logfunc(
        "udp info: IPv%s, payload_sz=%d, frags=%d, scr_port=%d, dst_port=%d, blocked=%s, ",
        (is_ipv6) ? "6" : "4", sz_data_payload, n_num_frags, ntohs(m_header->get_udp_hdr()->source),
        ntohs(m_dst_port), b_blocked ? "true" : "false");

    // Get all needed tx buf descriptor and data buffers
    mem_buf_desc_t *p_mem_buf_desc =
        m_p_ring->mem_buf_tx_get(m_id, b_blocked, PBUF_RAM, n_num_frags);

    if (unlikely(!p_mem_buf_desc)) {
        if (b_blocked) {
            dst_udp_logdbg("Error when blocking for next tx buffer (errno=%d %m)", errno);
        } else {
            dst_udp_logfunc(
                "Packet dropped. NonBlocked call but not enough tx buffers. Returning OK");
            if (!m_b_sysvar_tx_nonblocked_eagains) {
                return sz_data_payload;
            }
        }
        errno = EAGAIN;
        return -1;
    }

    bool ret;
    if (is_ipv6) {
        ret = dst_entry_udp::fast_send_fragmented_ipv6(
            p_mem_buf_desc, p_iov, sz_iov, attr, sz_udp_payload, n_num_frags,
            &m_fragmented_send_wqe, m_id, &m_sge[1], m_header, m_max_ip_payload_size, m_p_ring,
            gen_packet_id_ip6());
    } else {
        ret = fast_send_fragmented_ipv4(p_mem_buf_desc, p_iov, sz_iov, attr, sz_udp_payload,
                                        n_num_frags);
    }

    if (!ret) {
        errno = EINVAL;
        return -1;
    }
    return sz_data_payload;
}

ssize_t dst_entry_udp::fast_send(const iovec *p_iov, const ssize_t sz_iov, xlio_send_attr attr)
{
    /* Suppress flags that should not be used anymore
     * to avoid conflicts with XLIO_TX_PACKET_L3_CSUM and XLIO_TX_PACKET_L4_CSUM
     */
    attr.flags = (xlio_wr_tx_packet_attr)(attr.flags & ~(XLIO_TX_PACKET_ZEROCOPY | XLIO_TX_FILE));

    // Calc udp payload size
    size_t sz_udp_payload = attr.length + sizeof(struct udphdr);
    if (sz_udp_payload <= (size_t)m_max_udp_payload_size) {
        attr.flags =
            (xlio_wr_tx_packet_attr)(attr.flags | XLIO_TX_PACKET_L3_CSUM | XLIO_TX_PACKET_L4_CSUM);
        return fast_send_not_fragmented(p_iov, sz_iov, attr.flags, sz_udp_payload, attr.length);
    } else {
        attr.flags = (xlio_wr_tx_packet_attr)(attr.flags | XLIO_TX_PACKET_L3_CSUM);
        return fast_send_fragmented(p_iov, sz_iov, attr.flags, sz_udp_payload, attr.length);
    }
}

ssize_t dst_entry_udp::slow_send(const iovec *p_iov, const ssize_t sz_iov, xlio_send_attr attr,
                                 struct xlio_rate_limit_t &rate_limit, int flags /*= 0*/,
                                 sockinfo *sock /*= 0*/, tx_call_t call_type /*= 0*/)
{
    ssize_t ret_val = 0;

    dst_udp_logdbg("In slow send");

    prepare_to_send(rate_limit, false);

    if (m_b_force_os || !m_b_is_offloaded) {
        class sock_addr to_saddr(get_sa_family(), &m_dst_ip, m_dst_port);

        dst_udp_logdbg("Calling to tx_os");
        ret_val = sock->tx_os(call_type, p_iov, sz_iov, flags, (const struct sockaddr *)&to_saddr,
                              to_saddr.get_socklen());
    } else {
        if (!is_valid()) { // That means that the neigh is not resolved yet
            ret_val = pass_buff_to_neigh(p_iov, sz_iov);
        } else {
            ret_val = fast_send(p_iov, sz_iov, attr);
        }
    }

    return ret_val;
}

void dst_entry_udp::init_sge()
{
    m_sge[0].length = m_header->m_total_hdr_len;
    m_sge[0].addr = m_header->m_actual_hdr_addr;
    m_sge[0].lkey = m_p_ring->get_tx_lkey(m_id);
}

ssize_t dst_entry_udp::pass_buff_to_neigh(const iovec *p_iov, size_t sz_iov)
{
    m_header_neigh->init();
    m_header_neigh->configure_udp_header(m_dst_port, m_src_port);

    uint32_t packet_id = (get_sa_family() == AF_INET6) ? gen_packet_id_ip6() : gen_packet_id_ip4();

    return pass_pkt_to_neigh(p_iov, sz_iov, packet_id);
}
