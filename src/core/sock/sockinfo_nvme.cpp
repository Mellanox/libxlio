/*
 * Copyright (c) 2001-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include <algorithm>
#include <functional>
#include "sockinfo_tcp.h"
#include "sockinfo_ulp.h"
#include "sockinfo_nvme.h"
#include "proto/nvme_parse_input_args.h"

#define MODULE_NAME "si_nvme"

#define si_nvme_logdbg  __log_info_dbg
#define si_nvme_loginfo __log_info_info
#define si_nvme_logerr  __log_info_err

int sockinfo_tcp_ops_nvme::setsockopt(int level, int optname, const void *optval, socklen_t optlen)
{
    if (level != NVDA_NVME) {
        return m_p_sock->tcp_setsockopt(level, optname, optval, optlen);
    }

    if (unlikely(optname != NVME_TX && optname != NVME_RX)) {
        errno = ENOPROTOOPT;
        return -1;
    }

    if (optname == NVME_RX && !((ring::NVME_CRC_RX | ring::NVME_ZEROCOPY) & m_nvme_feature_mask)) {
        errno = ENOTSUP;
        return -1;
    }

    if (optname == NVME_TX) {
        if (!(ring::NVME_CRC_TX & m_nvme_feature_mask)) {
            errno = ENOTSUP;
            return -1;
        }
        if (optlen != sizeof(uint32_t)) {
            errno = EINVAL;
            return -1;
        }
        uint32_t config = *reinterpret_cast<const uint32_t *>(optval);
        int ret = setsockopt_tx(config);
        m_is_tx_offload = (ret == 0);
        m_is_ddgs_on = m_is_tx_offload && (XLIO_NVME_DDGST_MASK == (config & XLIO_NVME_DDGST_MASK));
        return ret;
    }

    return 0;
}

ssize_t sockinfo_tcp_ops_nvme::tx(xlio_tx_call_attr_t &tx_arg)
{
    if (!m_is_tx_offload) {
        return m_p_sock->tcp_tx(tx_arg);
    }

    if (tx_arg.opcode != TX_SENDMSG || tx_arg.priv.attr != PBUF_DESC_NVME_TX) {
        si_nvme_logdbg("Invalid opcode or priv attribute");
        errno = EINVAL;
        return -1;
    }
    auto aux_data = reinterpret_cast<xlio_pd_key *>(tx_arg.priv.map);
    auto msg = tx_arg.msg.hdr;

    if (msg->msg_iov == nullptr || aux_data == nullptr || msg->msg_iovlen == 0U ||
        aux_data[0].message_length == 0U) {
        si_nvme_logerr("Invalid msg_iov, msg_iovlen, or auxiliary data");
        errno = EINVAL;
        return -1;
    }

    size_t num_iovecs {0U};
    size_t total_tx_length {0U};
    unsigned sndbuf_len = m_p_sock->sndbuf_available();

    /* The new request points at a new PDU */
    while (num_iovecs < msg->msg_iovlen && sndbuf_len > total_tx_length) {
        size_t data_len = aux_data[num_iovecs].message_length;
        /* Check if there is enough place in sndbuf for the current PDU */
        if (sndbuf_len < total_tx_length + data_len) {
            break;
        }
        total_tx_length += data_len;

        /* Iterate the PDU iovecs */
        while (num_iovecs < msg->msg_iovlen && data_len >= msg->msg_iov[num_iovecs].iov_len) {
            data_len -= msg->msg_iov[num_iovecs].iov_len;
            num_iovecs++;
        }

        if (data_len != 0) {
            si_nvme_logerr("Invalid iovec - incomplete PDU?");
            errno = EINVAL;
            return -1;
        }
    }
    if (num_iovecs == 0U || total_tx_length == 0U) {
        si_nvme_logerr("Found %zu iovecs with length %zu to fit in sndbuff %u", num_iovecs,
                       total_tx_length, sndbuf_len);
        m_p_sock->set_reguired_send_block(aux_data[num_iovecs].message_length);
        errno = ENOBUFS;
        return -1;
    }
    m_p_sock->set_reguired_send_block(1U);

    /* Update tx_arg before sending to TCP */
    auto *desc = nvme_pdu_mdesc::create(num_iovecs, msg->msg_iov, aux_data,
                                        m_p_sock->get_next_tcp_seqno(), total_tx_length);
    if (desc == nullptr) {
        si_nvme_logerr("Unable to allocate nvme_mdesc");
        errno = ENOMEM;
        return -1;
    }
    /* Ambiguous reuse of the enum */
    tx_arg.priv.attr = PBUF_DESC_NVME_TX;
    tx_arg.priv.mdesc = reinterpret_cast<void *>(desc);
    tx_arg.msg.iov = desc->m_iov;
    tx_arg.msg.sz_iov = static_cast<ssize_t>(desc->m_num_segments);

    ssize_t ret = m_p_sock->tcp_tx(tx_arg);
    if (ret < static_cast<ssize_t>(total_tx_length)) {
        si_nvme_logerr("Sent %zd instead of %zu", ret, total_tx_length);
    }

    desc->put();
    return ret;
}

static inline bool request_credits_for_resync(ring *p_ring, size_t datalen, size_t mss)
{
    unsigned dump_nr = (datalen + mss - 1) / mss;
    unsigned credits = SQ_CREDITS_SET_PSV + dump_nr * SQ_CREDITS_DUMP + !dump_nr * SQ_CREDITS_NOP;
    return p_ring->credits_get(credits);
}

int sockinfo_tcp_ops_nvme::postrouting(pbuf *p, tcp_seg *seg, xlio_send_attr &attr)
{
    if (!m_is_ddgs_on || p == nullptr || seg == nullptr || seg->len == 0U) {
        return ERR_OK;
    }
    assert(m_p_tis != nullptr);

    attr.tis = m_p_tis.get();
    if (likely(seg->seqno == m_expected_seqno)) {
        m_expected_seqno += seg->len;
        return ERR_OK;
    }
    assert(p->next != nullptr);
    assert(p->next->desc.attr == PBUF_DESC_NVME_TX);

    ring *p_ring = m_p_sock->get_tx_ring();
    if (p_ring == nullptr) {
        si_nvme_logerr("No ring");
        return ERR_RTE;
    }

    auto nvme_mdesc = dynamic_cast<nvme_pdu_mdesc *>(static_cast<mem_desc *>(p->next->desc.mdesc));
    if (unlikely(nvme_mdesc == nullptr)) {
        si_nvme_logerr("NVME momory descriptor not found");
        return ERR_RTE;
    }

    assert(seg->seqno >= nvme_mdesc->m_seqno);
    assert(seg->seqno < nvme_mdesc->m_seqno + nvme_mdesc->m_length);

    const size_t mss = m_p_sock->get_mss();
    size_t datalen_to_dump_post = nvme_mdesc->reset(seg->seqno);

    if (!request_credits_for_resync(p_ring, datalen_to_dump_post, mss)) {
        si_nvme_logdbg("Not enough room in SQ for resync");
        return ERR_WOULDBLOCK;
    }
    p_ring->nvme_set_progress_context(m_p_tis.get(), nvme_mdesc->m_seqno);

    /* The requested segment is in the beginning of the PDU */
    if (unlikely(datalen_to_dump_post == 0U)) {
        p_ring->post_nop_fence();
        m_expected_seqno = seg->seqno + seg->len;
        return ERR_OK;
    }

    bool is_first = true;
    /* Advance the TIS context from the PDU start seqnum to seg->seqno */
    do {
        auto chunk = nvme_mdesc->next_chunk(std::min(mss, datalen_to_dump_post));
        if (!chunk.is_valid()) {
            /* datalen_to_dump_post should be 0 before we exhaust the PDU */
            si_nvme_logerr("Unable to dump post segment of size %zu",
                           std::min(mss, datalen_to_dump_post));
            return ERR_RTE;
        }
        p_ring->post_dump_wqe(m_p_tis.get(), chunk.iov.iov_base, chunk.iov.iov_len, chunk.mkey,
                              is_first);
        datalen_to_dump_post -= chunk.iov.iov_len;
        is_first = false;
    } while (datalen_to_dump_post > 0U);

    m_expected_seqno = seg->seqno + seg->len;
    return ERR_OK;
}

bool sockinfo_tcp_ops_nvme::handle_send_ret(ssize_t ret, tcp_seg *seg)
{
    if (ret < 0 && seg) {
        m_expected_seqno -= seg->len;
        return false;
    }

    return true;
}

err_t sockinfo_tcp_ops_nvme::recv(pbuf *p)
{
    return p != nullptr ? ERR_OK : ERR_ARG;
}

int sockinfo_tcp_ops_nvme::setsockopt_tx(const uint32_t &config)
{
    ring *p_ring = m_p_sock->get_tx_ring();
    if (p_ring == nullptr) {
        errno = ENOTSUP;
        return -1;
    }
    m_p_tis = p_ring->create_tis(DPCP_TIS_FLAGS | DPCP_TIS_NVME_FLAG);
    if (m_p_tis == nullptr) {
        errno = ENOTSUP;
        return -1;
    }

    if (!p_ring->credits_get(SQ_CREDITS_UMR + SQ_CREDITS_SET_PSV)) {
        si_nvme_logdbg("No available space in SQ to create the TX context");
        errno = ENOPROTOOPT;
        return -1;
    }
    m_expected_seqno = m_p_sock->get_next_tcp_seqno();
    p_ring->nvme_set_static_context(m_p_tis.get(), config);
    p_ring->nvme_set_progress_context(m_p_tis.get(), m_expected_seqno);
    return 0;
}

size_t nvme_pdu_mdesc::reset(uint32_t seqno)
{
    if (seqno > m_seqno + m_length) {
        return m_length;
    }

    size_t curr_pdu_seqno = m_seqno;
    size_t curr_index = 0U;

    /* Outer loop, iterate PDUs */
    while (curr_pdu_seqno + m_aux_data[curr_index].message_length <= seqno) {
        assert(m_aux_data[curr_index].message_length != 0U);

        auto pdu_length = m_aux_data[curr_index].message_length;
        curr_pdu_seqno += pdu_length;

        /* Inner loop, iterate iovecs */
        while (curr_index < m_num_segments && pdu_length >= m_iov[curr_index].iov_len) {
            curr_index++;
            pdu_length -= m_iov[curr_index].iov_len;
        }

        if (pdu_length != 0U) {
            si_nvme_logerr("Unable to iterate PDUs - corrupted mdesc");
            return m_length;
        }
    }

    m_view.index = curr_index;
    m_view.offset = 0U;
    return seqno - curr_pdu_seqno;
}

nvme_pdu_mdesc::chunk nvme_pdu_mdesc::next_chunk(size_t length)
{
    if (m_view.index >= m_num_segments || length == 0U) {
        return chunk();
    }

    auto iov_base = reinterpret_cast<void *>(
        reinterpret_cast<uintptr_t>(m_iov[m_view.index].iov_base) + m_view.offset);
    size_t iov_len = std::min(m_iov[m_view.index].iov_len - m_view.offset, length);
    uint32_t mkey = m_aux_data[m_view.index].mkey;
    if (m_view.offset + iov_len == std::min(m_iov[m_view.index].iov_len, length)) {
        m_view.offset = 0U;
        m_view.index++;
    } else {
        m_view.offset += iov_len;
    }
    return chunk(iov_base, iov_len, mkey);
}
