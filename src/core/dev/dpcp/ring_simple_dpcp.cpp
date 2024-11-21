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

#include "config.h"
#ifdef DEFINED_DPCP_PATH_RX
#include <mutex>
#include "dev/ring_simple.h"

#undef MODULE_NAME
#define MODULE_NAME "ring_simple_dpcp"
DOCA_LOG_REGISTER(ring_simple_dpcp);
#undef MODULE_HDR
#define MODULE_HDR MODULE_NAME "%d:%s() "

#define RING_LOCK_AND_RUN(__lock__, __func_and_params__)                                           \
    __lock__.lock();                                                                               \
    __func_and_params__;                                                                           \
    __lock__.unlock();

#define RING_TRY_LOCK_RUN_AND_UPDATE_RET(__lock__, __func_and_params__)                            \
    if (!__lock__.trylock()) {                                                                     \
        ret = __func_and_params__;                                                                 \
        __lock__.unlock();                                                                         \
    } else {                                                                                       \
        errno = EAGAIN;                                                                            \
    }

int ring_simple::get_rx_channel_fd(size_t ch_idx) const
{
    NOT_IN_USE(ch_idx);
    return m_p_rx_comp_event_channel->fd;
}

void ring_simple::clear_rx_notification()
{
    std::lock_guard<decltype(m_lock_ring_rx)> lock(m_lock_ring_rx);
    m_p_cq_mgr_rx->wait_for_notification();
}

bool ring_simple::poll_and_process_element_rx(void *pv_fd_ready_array)
{
    std::lock_guard<decltype(m_lock_ring_rx)> lock(m_lock_ring_rx);
    return m_p_cq_mgr_rx->poll_and_process_element_rx(pv_fd_ready_array);
}

bool ring_simple::reclaim_recv_buffers(descq_t *rx_reuse)
{
    bool ret = false;
    RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx, m_p_cq_mgr_rx->reclaim_recv_buffers(rx_reuse));
    return ret;
}

bool ring_simple::reclaim_recv_buffers(mem_buf_desc_t *rx_reuse_lst)
{
    bool ret = false;
    RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx,
                                     m_p_cq_mgr_rx->reclaim_recv_buffers(rx_reuse_lst));
    return ret;
}

bool ring_simple::reclaim_recv_buffers_no_lock(mem_buf_desc_t *rx_reuse_lst)
{
    return m_p_cq_mgr_rx->reclaim_recv_buffers_no_lock(rx_reuse_lst);
}

void ring_simple::mem_buf_desc_return_to_owner_rx(mem_buf_desc_t *p_mem_buf_desc,
                                                  void *pv_fd_ready_array /*NULL*/)
{
    ring_logfuncall(LOG_FUNCTION_CALL);
    RING_LOCK_AND_RUN(
        m_lock_ring_rx,
        m_p_cq_mgr_rx->mem_buf_desc_return_to_owner(p_mem_buf_desc, pv_fd_ready_array));
}

int ring_simple::drain_and_proccess()
{
    int ret = 0;
    RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx, m_p_cq_mgr_rx->drain_and_proccess());
    return ret;
}

#endif // DEFINED_DPCP_PATH_RX
