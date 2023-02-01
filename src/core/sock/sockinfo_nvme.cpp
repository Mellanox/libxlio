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
        uint32_t config =
            (optlen < sizeof(uint32_t)) ? 0U : *reinterpret_cast<const uint32_t *>(optval);
        int ret = setsockopt_tx(config);
        m_is_tx_offload = (ret == 0);
        m_is_ddgs_on = m_is_tx_offload && (XLIO_NVME_DDGST_MASK == (config & XLIO_NVME_DDGST_MASK));
        return ret;
    }

    return 0;
}

using tx_func = std::function<ssize_t(xlio_tx_call_attr_t &)>;
using segment_size_func = std::function<size_t()>;

static inline ssize_t send_pdu_segment(iovec *iov, size_t sz_iov, mem_desc *desc, tx_func tx)
{
    pbuf_desc pdesc;
    pdesc.attr = PBUF_DESC_NVME_TX;
    pdesc.mdesc = desc;
    xlio_tx_call_attr_t nvme_tx_arg {TX_SENDMSG,
                                     xlio_tx_call_attr_t::_msg {
                                         .iov = &iov[0],
                                         .sz_iov = static_cast<ssize_t>(sz_iov),
                                         .flags = MSG_ZEROCOPY,
                                         .addr = nullptr,
                                         .len = 0U,
                                         .hdr = nullptr,
                                     },
                                     TX_FLAG_NO_PARTIAL_WRITE, std::move(pdesc)};
    return tx(nvme_tx_arg);
}

static inline ssize_t send_pdu(nvme_pdu_mdesc *desc, segment_size_func segment_available,
                               tx_func tx)
{
    ssize_t bytes_sent = 0;
    do {
        iovec iov[64U];
        auto segment = desc->m_pdu->get_segment(segment_available(), &iov[0], 64U);
        if (!segment.is_valid()) {
            break;
        }
        ssize_t ret = send_pdu_segment(&iov[0], segment.iov_num, desc, tx);
        if (ret >= 0) {
            desc->m_pdu->consume(ret);
            bytes_sent += ret;
        } else {
            bytes_sent = ret;
            break;
        }
    } while (true);
    return bytes_sent;
}

ssize_t sockinfo_tcp_ops_nvme::tx(xlio_tx_call_attr_t &tx_arg)
{
    if (!m_is_tx_offload) {
        return m_p_sock->tcp_tx(tx_arg);
    }

    if (tx_arg.opcode != TX_SENDMSG || tx_arg.priv.attr != PBUF_DESC_NVME_TX) {
        errno = EINVAL;
        return -1;
    }

    auto aux_data = reinterpret_cast<xlio_pd_key *>(tx_arg.priv.map);
    auto msg = tx_arg.msg.hdr;
    auto nvme = nvmeotcp_tx(msg->msg_iov, aux_data, msg->msg_iovlen);

    if (m_pdu_mdesc == nullptr) {
        if (!is_new_nvme_pdu(aux_data, msg->msg_iovlen)) {
            errno = EINVAL;
            return -1;
        }
        auto pdu = nvme.get_next_pdu(m_p_sock->get_next_tcp_seqno());
        if (pdu == nullptr) {
            errno = EINVAL;
            return -1;
        }
        m_pdu_mdesc = new nvme_pdu_mdesc(std::move(pdu));
    }

    if (m_pdu_mdesc == nullptr) {
        errno = ENOMEM;
        return -1;
    }

    segment_size_func sndbuf_available = [sock = m_p_sock]() { return sock->sndbuf_available(); };
    tx_func tx = [sock = m_p_sock](xlio_tx_call_attr_t &attr) { return sock->tcp_tx(attr); };

    ssize_t bytes_sent = 0;
    ssize_t ret = 0;
    while ((ret = send_pdu(m_pdu_mdesc, sndbuf_available, tx)) ==
           static_cast<ssize_t>(m_pdu_mdesc->m_pdu->length())) {
        m_pdu_mdesc->put();
        m_pdu_mdesc = nullptr;
        auto pdu = nvme.get_next_pdu(m_p_sock->get_next_tcp_seqno());
        if (pdu == nullptr) {
            break;
        }
        m_pdu_mdesc = new nvme_pdu_mdesc(std::move(pdu));
        if (m_pdu_mdesc == nullptr) {
            break;
        }
        bytes_sent += ret;
    }

    return ret >= 0 ? (bytes_sent + ret) : ret;
}

int sockinfo_tcp_ops_nvme::postrouting(pbuf *p, tcp_seg *seg, xlio_send_attr &attr)
{
    if (!m_is_ddgs_on || p == nullptr || seg == nullptr || seg->len == 0U) {
        return 0;
    }
    assert(p->desc.attr == PBUF_DESC_NVME_TX);
    assert(m_p_tis != nullptr);

    attr.tis = m_p_tis.get();
    if (likely(seg->seqno == m_expected_seqno)) {
        return ERR_OK;
    }

    ring *p_ring = m_p_sock->get_tx_ring();
    if (p_ring == nullptr) {
        return ERR_OK;
    }

    auto nvme_pdu_rec =
        dynamic_cast<nvme_pdu_mdesc *>(static_cast<mem_desc *>(p->next->desc.mdesc));
    if (unlikely(nvme_pdu_rec == nullptr)) {
        return ERR_RTE;
    }

    auto &pdu = nvme_pdu_rec->m_pdu;
    assert(pdu->is_valid());
    p_ring->nvme_set_progress_conext(m_p_tis.get(), pdu->m_seqnum);

    /* The requested segment is in the beginning of the PDU */
    if (unlikely(seg->seqno == pdu->m_seqnum)) {
        p_ring->post_nop_fence();
        return ERR_OK;
    }
    assert(seg->seqno >= pdu->m_seqnum);

    size_t datalen_to_dump_post = seg->seqno - pdu->m_seqnum;
    const size_t mss = m_p_sock->get_mss();

    pdu->reset();
    /* Send the first segment */
    iovec iov = pdu->current_iov();
    if (iov.iov_base == nullptr) {
        return ERR_RTE;
    }
    iov.iov_len = std::min({iov.iov_len, mss, datalen_to_dump_post});
    p_ring->post_dump_wqe(m_p_tis.get(), iov.iov_base, iov.iov_len, pdu->current_mkey(), true);
    pdu->consume(iov.iov_len);
    datalen_to_dump_post -= iov.iov_len;

    /* Send the rest of the segments */
    while (datalen_to_dump_post > 0U) {
        iov.iov_len = std::min({iov.iov_len, mss, datalen_to_dump_post});
        p_ring->post_dump_wqe(m_p_tis.get(), iov.iov_base, iov.iov_len, pdu->current_mkey(), true);
        pdu->consume(iov.iov_len);
        datalen_to_dump_post -= iov.iov_len;
    }

    m_expected_seqno = seg->seqno;

    return ERR_OK;
}

bool sockinfo_tcp_ops_nvme::handle_send_ret(ssize_t ret, tcp_seg *seg)
{
    if (ret < 0 && seg) {
        /* m_expected_seqno -= seg->len; */
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

    m_expected_seqno = m_p_sock->get_next_tcp_seqno();
    p_ring->nvme_set_static_conext(m_p_tis.get(), config);
    p_ring->nvme_set_progress_conext(m_p_tis.get(), m_expected_seqno);
    return 0;
}
