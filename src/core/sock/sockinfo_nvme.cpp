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

#include "sockinfo_tcp.h"
#include "sockinfo_ulp.h"
#include "sockinfo_nvme.h"

#define MODULE_NAME "si_nvme"

#define si_nvme_logdbg  __log_info_dbg
#define si_nvme_loginfo __log_info_info
#define si_nvme_logerr  __log_info_err

int sockinfo_tcp_ops_nvme::setsockopt(int level, int optname, const void *optval, socklen_t optlen)
{
    if (level != SOL_NVME) {
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
        return setsockopt_tx();
    }

    return 0;
}

ssize_t sockinfo_tcp_ops_nvme::tx(xlio_tx_call_attr_t &tx_arg)
{
    return m_p_sock->tcp_tx(tx_arg);
}

int sockinfo_tcp_ops_nvme::postrouting(struct pbuf *p, struct tcp_seg *seg, xlio_send_attr &attr)
{
    NOT_IN_USE(p);
    NOT_IN_USE(seg);
    NOT_IN_USE(attr);
    return 0;
}

bool sockinfo_tcp_ops_nvme::handle_send_ret(ssize_t ret, struct tcp_seg *seg)
{
    NOT_IN_USE(ret);
    NOT_IN_USE(seg);
    return true;
}

err_t sockinfo_tcp_ops_nvme::recv(struct pbuf *p)
{
    NOT_IN_USE(p);
    return ERR_OK;
};

int sockinfo_tcp_ops_nvme::setsockopt_tx()
{
    ring *p_ring = m_p_sock->get_tx_ring();
    m_p_tis = p_ring != nullptr ? p_ring->create_nvme_context() : nullptr;
    if (m_p_tis == nullptr) {
        errno = ENOTSUP;
        return -1;
    }
    return 0;
}
