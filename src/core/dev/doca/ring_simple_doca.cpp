/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "util/vtypes.h"
#ifndef DEFINED_DPCP_PATH_RX_AND_TX
#include <mutex>
#include "dev/ring_simple.h"

#undef MODULE_NAME
#define MODULE_NAME "ring_simple_doca"
DOCA_LOG_REGISTER(ring_simple_doca);
#undef MODULE_HDR
#define MODULE_HDR MODULE_NAME "%d:%s() "

#ifndef DEFINED_DPCP_PATH_TX
// This probably can be removed completely for DOCA.
// It is unused in epoll and for DOCA we remove the full SQ poll attempt.
int ring_simple::get_tx_channel_fd() const
{
    return m_hqtx->get_notification_handle();
}

bool ring_simple::request_notification_tx()
{
    std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
    return m_hqtx->request_notification();
}

void ring_simple::poll_and_process_element_tx()
{
    std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
    m_hqtx->poll_and_process_doca_tx();
}

uint32_t ring_simple::send_doca_single(void *ptr, uint32_t len, mem_buf_desc_t *buff)
{
    std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
    uint32_t ret = m_hqtx->send_doca_single(ptr, len, buff);
    m_p_ring_stat->n_tx_dropped_wqes += (ret == 0);
    m_hqtx->poll_and_process_doca_tx();
    return ret;
}

uint32_t ring_simple::send_doca_lso(struct iovec &h, struct pbuf *p, uint16_t mss, bool is_zerocopy)
{
    std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
    uint32_t ret = m_hqtx->send_doca_lso(h, p, mss, is_zerocopy);
    m_p_ring_stat->n_tx_dropped_wqes += (ret == 0);
    m_hqtx->poll_and_process_doca_tx();
    return ret;
}
#endif // !DEFINED_DPCP_PATH_TX

#ifndef DEFINED_DPCP_PATH_RX
int ring_simple::get_rx_channel_fd(size_t ch_idx) const
{
    NOT_IN_USE(ch_idx);
    return m_hqrx->get_notification_handle();
}

bool ring_simple::request_notification_rx()
{
    std::lock_guard<decltype(m_lock_ring_rx)> lock(m_lock_ring_rx);
    return m_hqrx->request_notification();
}

void ring_simple::clear_rx_notification()
{
    std::lock_guard<decltype(m_lock_ring_rx)> lock(m_lock_ring_rx);
    m_hqrx->clear_notification();
}

bool ring_simple::poll_and_process_element_rx(void *pv_fd_ready_array)
{
    std::lock_guard<decltype(m_lock_ring_rx)> lock(m_lock_ring_rx);
    NOT_IN_USE(pv_fd_ready_array);
    return m_hqrx->poll_and_process_rx();
}

bool ring_simple::reclaim_recv_buffers(descq_t *rx_reuse)
{
    if (likely(!m_lock_ring_rx.trylock())) {
        m_hqrx->reclaim_rx_buffer_chain_queue(rx_reuse);
        m_lock_ring_rx.unlock();
        return true;
    }

    errno = EAGAIN;
    return false;
}

bool ring_simple::reclaim_recv_buffers(mem_buf_desc_t *rx_reuse_lst)
{
    if (likely(!m_lock_ring_rx.trylock())) {
        m_hqrx->reclaim_rx_buffer_chain(rx_reuse_lst);
        m_lock_ring_rx.unlock();
        return true;
    }

    errno = EAGAIN;
    return false;
}

bool ring_simple::reclaim_recv_buffers_no_lock(mem_buf_desc_t *rx_reuse_lst)
{
    m_hqrx->reclaim_rx_buffer_chain(rx_reuse_lst);
    return true;
}

int ring_simple::drain_and_proccess()
{
    return 0;
}

#endif // !DEFINED_DPCP_PATH_RX
#endif // !DEFINED_DPCP_PATH_RX_AND_TX
