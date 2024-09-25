/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-3-Clause
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

#ifndef DST_ENTRY_TCP_H
#define DST_ENTRY_TCP_H

#include "core/proto/dst_entry.h"

/* Structure for TCP scatter/gather I/O.  */
typedef struct tcp_iovec {
    struct iovec iovec;
    mem_buf_desc_t *p_desc;
    void *tcphdr;
} tcp_iovec;

class dst_entry_tcp : public dst_entry {
public:
    dst_entry_tcp(const sock_addr &dst, uint16_t src_port, socket_data &data,
                  resource_allocation_key &ring_alloc_logic);
    virtual ~dst_entry_tcp();

    ssize_t fast_send(const iovec *p_iov, const ssize_t sz_iov, xlio_send_attr attr);
    ssize_t slow_send(const iovec *p_iov, const ssize_t sz_iov, xlio_send_attr attr,
                      struct xlio_rate_limit_t &rate_limit, int flags = 0, sockinfo *sock = nullptr,
                      tx_call_t call_type = TX_UNDEF);
    ssize_t slow_send_neigh(const iovec *p_iov, size_t sz_iov,
                            struct xlio_rate_limit_t &rate_limit);

    mem_buf_desc_t *get_buffer(pbuf_type type, pbuf_desc *desc, bool b_blocked = false);
    void put_buffer(mem_buf_desc_t *p_desc);
    void put_zc_buffer(mem_buf_desc_t *p_desc);

protected:
    transport_t get_transport(const sock_addr &to);
    virtual uint8_t get_protocol_type() const { return IPPROTO_TCP; };
    virtual uint32_t get_inline_sge_num() { return 1; };
    virtual ibv_sge *get_sge_lst_4_inline_send() { return m_sge; };
    virtual ibv_sge *get_sge_lst_4_not_inline_send() { return m_sge; };

    virtual void configure_headers();
    ssize_t pass_buff_to_neigh(const iovec *p_iov, size_t sz_iov);

private:
    const uint32_t m_n_sysvar_tx_bufs_batch_tcp;
    const uint32_t m_n_sysvar_user_huge_page_size;
    uint64_t m_user_huge_page_mask;

    inline int send_lwip_buffer(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe,
                                xlio_wr_tx_packet_attr attr, xlio_tis *tis)
    {
        if (unlikely(is_set(attr, XLIO_TX_PACKET_DUMMY))) {
            if (m_p_ring->get_hw_dummy_send_support(id, p_send_wqe)) {
                xlio_ibv_wr_opcode last_opcode =
                    m_p_send_wqe_handler->set_opcode(*p_send_wqe, XLIO_IBV_WR_NOP);
                m_p_ring->send_lwip_buffer(id, p_send_wqe, attr, tis);
                m_p_send_wqe_handler->set_opcode(*p_send_wqe, last_opcode);
            }
            /* no need to free the buffer if dummy send is not supported, as for lwip buffers we
             * have 2 ref counts, */
            /* one for caller, and one for completion. for completion, we ref count in    */
            /* send_lwip_buffer(). Since we are not going in, the caller will free the    */
            /* buffer. */
            return 0;
        }

        return m_p_ring->send_lwip_buffer(id, p_send_wqe, attr, tis);
    }
};

#endif /* DST_ENTRY_TCP_H */
