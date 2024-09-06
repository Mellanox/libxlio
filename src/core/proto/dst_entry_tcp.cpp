/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "dst_entry_tcp.h"
#include "mapping.h"
#include "mem_desc.h"
#include <netinet/tcp.h>

#define MODULE_NAME "dst_tcp"

#define dst_tcp_logpanic   __log_panic
#define dst_tcp_logerr     __log_err
#define dst_tcp_logwarn    __log_warn
#define dst_tcp_loginfo    __log_info
#define dst_tcp_logdbg     __log_info_dbg
#define dst_tcp_logfunc    __log_info_fine
#define dst_tcp_logfine    __log_info_fine
#define dst_tcp_logfuncall __log_info_finer

dst_entry_tcp::dst_entry_tcp(const sock_addr &dst, uint16_t src_port, socket_data &sock_data,
                             resource_allocation_key &ring_alloc_logic)
    : dst_entry(dst, src_port, sock_data, ring_alloc_logic)
    , m_n_sysvar_tx_bufs_batch_tcp(safe_mce_sys().tx_bufs_batch_tcp)
    , m_n_sysvar_user_huge_page_size(safe_mce_sys().user_huge_page_size)
{
    m_user_huge_page_mask = ~((uint64_t)m_n_sysvar_user_huge_page_size - 1);
}

dst_entry_tcp::~dst_entry_tcp()
{
}

transport_t dst_entry_tcp::get_transport(const sock_addr &to)
{
    NOT_IN_USE(to);
    return TRANS_XLIO;
}

uint32_t dst_entry_tcp::send_doca(struct pbuf *p, uint16_t flags)
{
    bool is_zerocopy = !!(flags & XLIO_TX_PACKET_ZEROCOPY);
    bool is_tso = !!(flags & XLIO_TX_PACKET_TSO);
    void *p_ip_hdr = nullptr;
    void *p_tcp_hdr = nullptr;

    struct pbuf *payload_pbuf = is_zerocopy ? p->next : p;
    if (unlikely(payload_pbuf->ref > 1)) {
        dst_tcp_logwarn(
            "There is no such list in DOCA implementation. Need to test if this scenario works");
    }
    payload_pbuf->ref++;

    uint32_t total_packet_len =
        payload_pbuf->tot_len + m_header->m_total_hdr_len + (is_zerocopy ? p->len : 0);
    void *p_pkt = (void *)((uint8_t *)p->payload - m_header->m_aligned_l2_l3_len);
    m_header->copy_l2_ip_hdr(p_pkt);
    uint16_t payload_length_ipv4 = total_packet_len - m_header->m_transport_header_len;
    if (get_sa_family() == AF_INET6) {
        fill_hdrs<tx_ipv6_hdr_template_t>(p_pkt, p_ip_hdr, p_tcp_hdr);
        set_ipv6_len(p_ip_hdr, htons(payload_length_ipv4 - IPV6_HLEN));
    } else {
        fill_hdrs<tx_ipv4_hdr_template_t>(p_pkt, p_ip_hdr, p_tcp_hdr);
        set_ipv4_len(p_ip_hdr, htons(payload_length_ipv4));
    }

    // ZC or TSO are possible only with DOCA LSO send
    if (is_zerocopy || is_tso) {
        size_t tcp_hdr_len = (static_cast<tcphdr *>(p_tcp_hdr))->doff << 2;
        struct iovec h = {(void *)((uint8_t *)p->payload - m_header->m_total_hdr_len),
                          m_header->m_total_hdr_len + tcp_hdr_len};
        return m_p_ring->send_doca_lso(h, payload_pbuf, is_zerocopy);
    }

    // Regular send - single packet with a single pbuf
    void *ptr = (void *)((uint8_t *)payload_pbuf->payload - m_header->m_total_hdr_len);
    mem_buf_desc_t *user_data = reinterpret_cast<mem_buf_desc_t *>(p);
    return m_p_ring->send_doca_single(ptr, total_packet_len, user_data);
}

ssize_t dst_entry_tcp::fast_send(const iovec *p_iov, const ssize_t sz_iov, xlio_send_attr attr)
{
    int ret = 0;
    void *p_pkt;
    void *p_ip_hdr;
    void *p_tcp_hdr;
    tcp_iovec *p_tcp_iov = nullptr;
    xlio_ibv_send_wr *p_send_wqe;
    size_t hdr_alignment_diff = 0;

    bool is_zerocopy = is_set(attr.flags, XLIO_TX_PACKET_ZEROCOPY);

    /* The header is aligned for fast copy but we need to maintain this diff
     * in order to get the real header pointer easily
     */
    hdr_alignment_diff = m_header->m_aligned_l2_l3_len - m_header->m_total_hdr_len;

    p_tcp_iov = (tcp_iovec *)p_iov;

    /* Suppress flags that should not be used anymore
     * to avoid conflicts with XLIO_TX_PACKET_L3_CSUM and XLIO_TX_PACKET_L4_CSUM
     */
    attr.flags = (xlio_wr_tx_packet_attr)(attr.flags & ~(XLIO_TX_PACKET_ZEROCOPY | XLIO_TX_FILE));

    /* ZC uses multiple IOVs, only the mlx5 TSO path supports that */
    /* for small (< mss) ZC sends, must turn off CX5.SXP.disable_lso_on_only_packets
     * BF  --> mcra /dev/mst/mt41682_pciconf0 0x31500.3:1 0
     * CX5 --> mcra /dev/mst/mt4121_pciconf0 0x31500.3:1 0
     * When set, single packet LSO WQEs are not treated as LSO. This prevents wrong handling of
     * packets with padding by SW */
    if (is_zerocopy) {
        attr.flags = (xlio_wr_tx_packet_attr)(attr.flags | XLIO_TX_PACKET_TSO);
    }

    attr.flags =
        (xlio_wr_tx_packet_attr)(attr.flags | XLIO_TX_PACKET_L3_CSUM | XLIO_TX_PACKET_L4_CSUM);

    /* Supported scenarios:
     * 1. Standard:
     *    Use lwip memory buffer (zero copy) in case iov consists of single buffer with single TCP
     * packet.
     * 2. Large send offload:
     *    Use lwip sequence of memory buffers (zero copy) in case attribute is set as TSO and no
     * retransmission. Size of iov can be one or more.
     * 3. Simple:
     *    Use intermediate buffers for data send
     */
    if (likely(m_p_ring->is_active_member(p_tcp_iov->p_desc->p_desc_owner, m_id) &&
               (is_set(attr.flags, (xlio_wr_tx_packet_attr)(XLIO_TX_PACKET_TSO)) ||
                (sz_iov == 1 &&
                 !is_set(attr.flags, (xlio_wr_tx_packet_attr)(XLIO_TX_PACKET_REXMIT)))))) {
        size_t total_packet_len = 0;
        size_t tcp_hdr_len;
        xlio_ibv_send_wr send_wqe;
        wqe_send_handler send_wqe_h;
        void *masked_addr;

        /* iov_base is a pointer to TCP header and data
         * so p_pkt should point to L2
         */
        if (is_zerocopy) {
            p_pkt = (void *)((uint8_t *)p_tcp_iov[0].tcphdr - m_header->m_aligned_l2_l3_len);
        } else {
            p_pkt =
                (void *)((uint8_t *)p_tcp_iov[0].iovec.iov_base - m_header->m_aligned_l2_l3_len);
        }

        /* attr.length is payload size and L4 header size
         * m_total_hdr_len is a size of L2/L3 header
         */
        total_packet_len = attr.length + m_header->m_total_hdr_len;

        /* copy just L2/L3 headers to p_pkt */
        m_header->copy_l2_ip_hdr(p_pkt);

        uint16_t payload_length_ipv4 = total_packet_len - m_header->m_transport_header_len;
        if (get_sa_family() == AF_INET6) {
            fill_hdrs<tx_ipv6_hdr_template_t>(p_pkt, p_ip_hdr, p_tcp_hdr);
            set_ipv6_len(p_ip_hdr, htons(payload_length_ipv4 - IPV6_HLEN));
        } else {
            fill_hdrs<tx_ipv4_hdr_template_t>(p_pkt, p_ip_hdr, p_tcp_hdr);
            set_ipv4_len(p_ip_hdr, htons(payload_length_ipv4));
        }

        tcp_hdr_len = (static_cast<tcphdr *>(p_tcp_hdr))->doff * 4;

        if (!is_zerocopy && (total_packet_len < m_max_inline) && (1 == sz_iov)) {
            p_send_wqe = &m_inline_send_wqe;
            p_tcp_iov[0].iovec.iov_base = (uint8_t *)p_pkt + hdr_alignment_diff;
            p_tcp_iov[0].iovec.iov_len = total_packet_len;
        } else if (is_set(attr.flags, (xlio_wr_tx_packet_attr)(XLIO_TX_PACKET_TSO))) {
            /* update send work request. do not expect noninlined scenario */
            send_wqe_h.init_not_inline_wqe(send_wqe, m_sge, sz_iov);
            if (attr.mss < (attr.length - tcp_hdr_len)) {
                send_wqe_h.enable_tso(send_wqe, (void *)((uint8_t *)p_pkt + hdr_alignment_diff),
                                      m_header->m_total_hdr_len + tcp_hdr_len,
                                      attr.mss - (tcp_hdr_len - TCP_HLEN));
            } else {
                send_wqe_h.enable_tso(send_wqe, (void *)((uint8_t *)p_pkt + hdr_alignment_diff),
                                      m_header->m_total_hdr_len + tcp_hdr_len, 0);
            }
            p_send_wqe = &send_wqe;
            if (!is_zerocopy) {
                p_tcp_iov[0].iovec.iov_base = (uint8_t *)p_tcp_hdr + tcp_hdr_len;
                p_tcp_iov[0].iovec.iov_len -= tcp_hdr_len;
            }
        } else {
            p_send_wqe = &m_not_inline_send_wqe;
            p_tcp_iov[0].iovec.iov_base = (uint8_t *)p_pkt + hdr_alignment_diff;
            p_tcp_iov[0].iovec.iov_len = total_packet_len;
        }

        if (unlikely(p_tcp_iov[0].p_desc->lwip_pbuf.ref > 1)) {
            /*
             * First buffer in the vector is used for reference counting.
             * The reference is released after completion depending on
             * batching mode.
             * There is situation, when a buffer resides in the list for
             * batching completion and the same buffer is queued for
             * retransmission. In this case, sending the buffer leads to
             * the list corruption because the buffer is re-inserted.
             *
             * As workaround, allocate new fake buffer which will be
             * assigned to wr_id and used for reference counting. This
             * buffer is allocated with ref == 1, so we must not increase
             * it. When completion happens, ref becomes 0 and the fake
             * buffer is released.
             *
             * We don't change data, only pointer to buffer descriptor.
             */
            pbuf_type type = (pbuf_type)p_tcp_iov[0].p_desc->lwip_pbuf.type;
            mem_buf_desc_t *p_mem_buf_desc =
                get_buffer(type, &(p_tcp_iov[0].p_desc->lwip_pbuf.desc),
                           is_set(attr.flags, XLIO_TX_PACKET_BLOCK));
            if (!p_mem_buf_desc) {
                return -1;
            }
            p_tcp_iov[0].p_desc = p_mem_buf_desc;
        } else {
            p_tcp_iov[0].p_desc->lwip_pbuf.ref++;
        }

        /* save pointers to ip and tcp headers for software checksum calculation */
        p_tcp_iov[0].p_desc->tx.p_ip_h = p_ip_hdr;
        p_tcp_iov[0].p_desc->tx.p_tcp_h = static_cast<tcphdr *>(p_tcp_hdr);

        /* set wr_id as a pointer to memory descriptor */
        p_send_wqe->wr_id = (uintptr_t)p_tcp_iov[0].p_desc;

        /* Update scatter gather element list
         * ref counter is incremented (above) for the first memory descriptor only because it is
         * needed for processing send wr completion (tx batching mode)
         */
        ib_ctx_handler *ib_ctx = m_p_ring->get_ctx(m_id);
        for (int i = 0; i < sz_iov; ++i) {
            m_sge[i].addr = (uintptr_t)p_tcp_iov[i].iovec.iov_base;
            m_sge[i].length = p_tcp_iov[i].iovec.iov_len;
            if (is_zerocopy) {
                auto *p_desc = p_tcp_iov[i].p_desc;
                auto &pbuf_descriptor = p_desc->lwip_pbuf.desc;
                if (PBUF_DESC_EXPRESS == pbuf_descriptor.attr) {
                    m_sge[i].lkey = pbuf_descriptor.mkey;
                } else if (PBUF_DESC_MKEY == pbuf_descriptor.attr) {
                    /* PBUF_DESC_MKEY - value is provided by user */
                    m_sge[i].lkey = pbuf_descriptor.mkey;
                } else if (PBUF_DESC_MDESC == pbuf_descriptor.attr ||
                           PBUF_DESC_NVME_TX == pbuf_descriptor.attr) {
                    mem_desc *mdesc = (mem_desc *)pbuf_descriptor.mdesc;
                    m_sge[i].lkey =
                        mdesc->get_lkey(p_desc, ib_ctx, (void *)m_sge[i].addr, m_sge[i].length);
                    if (m_sge[i].lkey == LKEY_TX_DEFAULT) {
                        m_sge[i].lkey = m_p_ring->get_tx_lkey(m_id);
                    }
                } else {
                    /* Do not check desc.attr for specific type because
                     * PBUF_DESC_FD - is not possible for XLIO_TX_PACKET_ZEROCOPY
                     * PBUF_DESC_NONE - map should be initialized to NULL in
                     * dst_entry_tcp::get_buffer() object
                     */
                    masked_addr = (void *)((uint64_t)m_sge[i].addr & m_user_huge_page_mask);
                    m_sge[i].lkey =
                        m_p_ring->get_tx_user_lkey(masked_addr, m_n_sysvar_user_huge_page_size);
                }
            } else {
                m_sge[i].lkey = (i == 0 ? m_p_ring->get_tx_lkey(m_id) : m_sge[0].lkey);
            }
        }

        ret = send_lwip_buffer(m_id, p_send_wqe, attr.flags, attr.tis);
    } else { // We don'nt support inline in this case, since we believe that this a very rare case
        mem_buf_desc_t *p_mem_buf_desc;
        size_t total_packet_len = 0;

        p_mem_buf_desc = get_buffer(PBUF_RAM, nullptr, is_set(attr.flags, XLIO_TX_PACKET_BLOCK));
        if (!p_mem_buf_desc) {
            ret = -1;
            goto out;
        }

        m_header->copy_l2_ip_hdr(static_cast<void *>(p_mem_buf_desc->p_buffer));

        // Actually this is not the real packet len we will subtract the alignment diff at the end
        // of the copy
        total_packet_len = m_header->m_aligned_l2_l3_len;

        for (int i = 0; i < sz_iov; ++i) {
            memcpy(p_mem_buf_desc->p_buffer + total_packet_len, p_tcp_iov[i].iovec.iov_base,
                   p_tcp_iov[i].iovec.iov_len);
            total_packet_len += p_tcp_iov[i].iovec.iov_len;
        }

        m_sge[0].addr = (uintptr_t)(p_mem_buf_desc->p_buffer + hdr_alignment_diff);
        m_sge[0].length = total_packet_len - hdr_alignment_diff;
        m_sge[0].lkey = m_p_ring->get_tx_lkey(m_id);

        p_pkt = static_cast<void *>(p_mem_buf_desc->p_buffer);

        uint16_t payload_length_ipv4 = m_sge[0].length - m_header->m_transport_header_len;
        if (get_sa_family() == AF_INET6) {
            fill_hdrs<tx_ipv6_hdr_template_t>(p_pkt, p_ip_hdr, p_tcp_hdr);
            set_ipv6_len(p_ip_hdr, htons(payload_length_ipv4 - IPV6_HLEN));
        } else {
            fill_hdrs<tx_ipv4_hdr_template_t>(p_pkt, p_ip_hdr, p_tcp_hdr);
            set_ipv4_len(p_ip_hdr, htons(payload_length_ipv4));
        }

        p_mem_buf_desc->tx.p_ip_h = p_ip_hdr;
        p_mem_buf_desc->tx.p_tcp_h = static_cast<tcphdr *>(p_tcp_hdr);

        p_send_wqe = &m_not_inline_send_wqe;
        p_send_wqe->wr_id = (uintptr_t)p_mem_buf_desc;

        send_ring_buffer(m_id, p_send_wqe, attr.flags);
    }

    if (unlikely(!m_p_tx_mem_buf_desc_list)) {
        m_p_tx_mem_buf_desc_list = m_p_ring->mem_buf_tx_get(
            m_id, is_set(attr.flags, XLIO_TX_PACKET_BLOCK), PBUF_RAM, m_n_sysvar_tx_bufs_batch_tcp);
    }

out:
    if (unlikely(is_set(attr.flags, XLIO_TX_PACKET_REXMIT))) {
        m_p_ring->inc_tx_retransmissions_stats(m_id);
    }

    return ret;
}

uint32_t dst_entry_tcp::doca_slow_path(struct pbuf *p, uint16_t flags,
                                       struct xlio_rate_limit_t &rate_limit)
{
    uint32_t ret = 0;

    m_slow_path_lock.lock();
    prepare_to_send(rate_limit, true);
    if (m_b_is_offloaded) {
        if (is_valid()) {
            ret = send_doca(p, flags);
        } else {
            bool is_tso_or_zerocopy = !!(flags & (XLIO_TX_PACKET_ZEROCOPY | XLIO_TX_PACKET_TSO));
            if (is_tso_or_zerocopy) {
                dst_tcp_logwarn("TSO/ZC send when dst_entry is not valid");
            }

            iovec iov = {p, p->len};
            ret = pass_buff_to_neigh(&iov, 1);
        }
    }
    m_slow_path_lock.unlock();
    return ret;
}

ssize_t dst_entry_tcp::slow_send(const iovec *p_iov, const ssize_t sz_iov, xlio_send_attr attr,
                                 struct xlio_rate_limit_t &rate_limit, int flags /*= 0*/,
                                 sockinfo *sock /*= 0*/, tx_call_t call_type /*= 0*/)
{
    ssize_t ret_val = -1;

    NOT_IN_USE(sock);
    NOT_IN_USE(call_type);
    NOT_IN_USE(flags);

    m_slow_path_lock.lock();

    prepare_to_send(rate_limit, true);

    if (m_b_is_offloaded) {
        if (!is_valid()) { // That means that the neigh is not resolved yet
            // there is a copy inside so we should not update any ref-counts
            ret_val = pass_buff_to_neigh(p_iov, sz_iov);
        } else {
            ret_val = fast_send(p_iov, sz_iov, attr);
        }
    } else {
        dst_tcp_logdbg("Dst_entry is not offloaded, bug?");
    }
    m_slow_path_lock.unlock();
    return ret_val;
}

ssize_t dst_entry_tcp::slow_send_neigh(const iovec *p_iov, size_t sz_iov,
                                       struct xlio_rate_limit_t &rate_limit)
{
    ssize_t ret_val = -1;

    m_slow_path_lock.lock();

    prepare_to_send(rate_limit, true);

    if (m_b_is_offloaded) {
        ret_val = pass_buff_to_neigh(p_iov, sz_iov);
    } else {
        dst_tcp_logdbg("Dst_entry is not offloaded, bug?");
    }

    m_slow_path_lock.unlock();
    return ret_val;
}

// The following function supposed to be called under m_lock
void dst_entry_tcp::configure_headers()
{
    m_header->init();
    dst_entry::configure_headers();
}

ssize_t dst_entry_tcp::pass_buff_to_neigh(const iovec *p_iov, size_t sz_iov, uint32_t packet_id)
{
    NOT_IN_USE(packet_id);
    m_header_neigh->init();
    m_header_neigh->configure_tcp_ports(m_dst_port, m_src_port);
    return (dst_entry::pass_buff_to_neigh(p_iov, sz_iov));
}

mem_buf_desc_t *dst_entry_tcp::get_buffer(pbuf_type type, pbuf_desc *desc,
                                          bool b_blocked /*=false*/)
{
    mem_buf_desc_t **p_desc_list;

    set_tx_buff_list_pending(false);

    p_desc_list = type == PBUF_ZEROCOPY ? &m_p_zc_mem_buf_desc_list : &m_p_tx_mem_buf_desc_list;

    // Get a bunch of tx buf descriptor and data buffers
    if (unlikely(!*p_desc_list)) {
        *p_desc_list =
            m_p_ring->mem_buf_tx_get(m_id, b_blocked, type, m_n_sysvar_tx_bufs_batch_tcp);
    }

    mem_buf_desc_t *p_mem_buf_desc = *p_desc_list;
    if (unlikely(!p_mem_buf_desc)) {
        dst_tcp_logfunc("silent packet drop, no buffers!");
    } else {
        *p_desc_list = (*p_desc_list)->p_next_desc;
        p_mem_buf_desc->p_next_desc = nullptr;
        // for TX, set lwip payload to the data segment.
        // lwip will send it with payload pointing to the tcp header.
        if (p_mem_buf_desc->p_buffer) {
            p_mem_buf_desc->lwip_pbuf.payload = (u8_t *)p_mem_buf_desc->p_buffer +
                m_header->m_aligned_l2_l3_len + sizeof(struct tcphdr);
        } else {
            p_mem_buf_desc->lwip_pbuf.payload = nullptr;
        }

        /* Initialize pbuf description */
        memset(&p_mem_buf_desc->lwip_pbuf.desc, 0, sizeof(p_mem_buf_desc->lwip_pbuf.desc));
        p_mem_buf_desc->lwip_pbuf.desc.attr = PBUF_DESC_NONE;
        if (desc) {
            memcpy(&p_mem_buf_desc->lwip_pbuf.desc, desc, sizeof(p_mem_buf_desc->lwip_pbuf.desc));
            if (p_mem_buf_desc->lwip_pbuf.desc.attr == PBUF_DESC_MDESC ||
                p_mem_buf_desc->lwip_pbuf.desc.attr == PBUF_DESC_NVME_TX) {
                mem_desc *mdesc = (mem_desc *)p_mem_buf_desc->lwip_pbuf.desc.mdesc;
                mdesc->get();
            }
        }
    }

    return p_mem_buf_desc;
}

// called from lwip under sockinfo_tcp lock
// handle un-chained pbuf
// only single p_desc
void dst_entry_tcp::put_buffer(mem_buf_desc_t *p_desc)
{
    // todo accumulate buffers?

    if (unlikely(!p_desc)) {
        return;
    }

    if (likely(m_p_ring->is_member(p_desc->p_desc_owner))) {
        m_p_ring->mem_buf_desc_return_single_to_owner_tx(p_desc);
    } else {

        // potential race, ref is protected here by tcp lock, and in ring by ring_tx lock
        if (likely(p_desc->lwip_pbuf.ref)) {
            p_desc->lwip_pbuf.ref--;
        } else {
            dst_tcp_logerr("ref count of %p is already zero, double free??", p_desc);
        }

        if (p_desc->lwip_pbuf.ref == 0) {
            p_desc->p_next_desc = nullptr;
            buffer_pool::free_tx_lwip_pbuf_custom(&p_desc->lwip_pbuf);
        }
    }
}

void dst_entry_tcp::put_zc_buffer(mem_buf_desc_t *p_desc)
{
    if (likely(p_desc->lwip_pbuf.ref <= 1)) {
        p_desc->lwip_pbuf.ref = 1;
        p_desc->p_next_desc = m_p_zc_mem_buf_desc_list;
        m_p_zc_mem_buf_desc_list = p_desc;
    } else {
        p_desc->lwip_pbuf.ref--;
    }
}
