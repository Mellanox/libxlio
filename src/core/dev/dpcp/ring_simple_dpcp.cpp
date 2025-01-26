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

#include <mutex>
#include "dev/ring_simple.h"
#include "sock/sock-redirect.h"

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

#ifdef DEFINED_DPCP_PATH_TX
// inlining functions can only help if they are implemented before their usage **/
inline void ring_simple::send_status_handler(int ret, xlio_ibv_send_wr *p_send_wqe)
{
    BULLSEYE_EXCLUDE_BLOCK_START
    if (unlikely(ret)) {
        // Error during post_send, reclaim the tx buffer
        if (p_send_wqe) {
            mem_buf_desc_t *p_mem_buf_desc = (mem_buf_desc_t *)(p_send_wqe->wr_id);
            mem_buf_tx_release(p_mem_buf_desc);
        }
    } else {
        // Update TX statistics
        sg_array sga(p_send_wqe->sg_list, p_send_wqe->num_sge);
        m_hqtx->m_hwq_tx_stats.n_tx_byte_count += sga.length();
        ++m_hqtx->m_hwq_tx_stats.n_tx_pkt_count;
    }
    BULLSEYE_EXCLUDE_BLOCK_END
}

void ring_simple::poll_and_process_element_tx()
{
    std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
    m_p_cq_mgr_tx->poll_and_process_element_tx();
}

/* note that this function is inline, so keep it above the functions using it */
inline int ring_simple::send_buffer(xlio_ibv_send_wr *p_send_wqe, xlio_wr_tx_packet_attr attr,
                                    xlio_tis *tis)
{
    int ret = 0;
    unsigned credits = m_hqtx->credits_calculate(p_send_wqe);

    if (likely(m_hqtx->credits_get(credits)) ||
        is_available_qp_wr(is_set(attr, XLIO_TX_PACKET_BLOCK), credits)) {
        m_hqtx->send_wqe(p_send_wqe, attr, tis, credits);
    } else {
        ring_logdbg("Silent packet drop, SQ is full!");
        ret = -1;
        reinterpret_cast<mem_buf_desc_t *>(p_send_wqe->wr_id)->p_next_desc = nullptr;
        ++m_p_ring_stat->n_tx_dropped_wqes;
    }
    return ret;
}

bool ring_simple::get_hw_dummy_send_support(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe)
{
    NOT_IN_USE(id);
    NOT_IN_USE(p_send_wqe);

    return m_hqtx->get_hw_dummy_send_support();
}

void ring_simple::send_ring_buffer(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe,
                                   xlio_wr_tx_packet_attr attr)
{
    NOT_IN_USE(id);

    if (attr & XLIO_TX_SW_L4_CSUM) {
        compute_tx_checksum((mem_buf_desc_t *)(p_send_wqe->wr_id), attr & XLIO_TX_PACKET_L3_CSUM,
                            attr & XLIO_TX_PACKET_L4_CSUM);
        attr = (xlio_wr_tx_packet_attr)(attr & ~(XLIO_TX_PACKET_L4_CSUM));
    }

    std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
    int ret = send_buffer(p_send_wqe, attr, nullptr);
    send_status_handler(ret, p_send_wqe);
}

int ring_simple::send_lwip_buffer(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe,
                                  xlio_wr_tx_packet_attr attr, xlio_tis *tis)
{
    NOT_IN_USE(id);
    std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
    int ret = send_buffer(p_send_wqe, attr, tis);
    send_status_handler(ret, p_send_wqe);
    return ret;
}

/*
 * called under m_lock_ring_tx lock
 */
bool ring_simple::is_available_qp_wr(bool b_block, unsigned credits)
{
    bool granted;
    int ret;

    do {
        // Try to poll once in the hope that we get space in SQ
        m_p_cq_mgr_tx->poll_and_process_element_tx();
        granted = m_hqtx->credits_get(credits);
        if (granted) {
            break;
        }

        if (b_block) {
            // Arm & Block on cq_mgr_tx notification channel until we get space in SQ

            // Only a single thread should block on next Tx cqe event, hence the dedicated lock!
            /* coverity[double_unlock] TODO: RM#1049980 */
            m_lock_ring_tx.unlock();
            m_lock_ring_tx_buf_wait.lock();
            /* coverity[double_lock] TODO: RM#1049980 */
            m_lock_ring_tx.lock();

            // TODO Resolve race window between previous polling and request_notification
            ret = m_p_cq_mgr_tx->request_notification();
            if (ret < 0) {
                // this is most likely due to cq_poll_sn out of sync, need to poll_cq again
                ring_logdbg("failed arming cq_mgr_tx (hqtx=%p, cq_mgr_tx=%p) (errno=%d %m)", m_hqtx,
                            m_p_cq_mgr_tx, errno);
            } else if (ret == 0) {
                // prepare to block
                // CQ is armed, block on the CQ's Tx event channel (fd)
                struct pollfd poll_fd = {/*.fd=*/0, /*.events=*/POLLIN, /*.revents=*/0};
                poll_fd.fd = m_p_tx_comp_event_channel->fd;

                // Now it is time to release the ring lock (for restart events to be handled
                // while this thread block on CQ channel)
                /* coverity[double_unlock] TODO: RM#1049980 */
                m_lock_ring_tx.unlock();

                ret = SYSCALL(poll, &poll_fd, 1, -1);
                if (ret <= 0) {
                    ring_logdbg("failed blocking on cq_mgr_tx (errno=%d %m)", errno);
                    m_lock_ring_tx_buf_wait.unlock();
                    /* coverity[double_lock] TODO: RM#1049980 */
                    m_lock_ring_tx.lock();
                    /* coverity[missing_unlock] */
                    return false;
                }
                /* coverity[double_lock] TODO: RM#1049980 */
                m_lock_ring_tx.lock();

                // Find the correct cq_mgr_tx from the CQ event,
                // It might not be the active_cq object since we have a single TX CQ comp
                // channel for all cq_mgr_tx's
                cq_mgr_tx *p_cq_mgr_tx =
                    cq_mgr_tx::get_cq_mgr_from_cq_event(m_p_tx_comp_event_channel);
                if (p_cq_mgr_tx) {

                    // Allow additional CQ arming now
                    p_cq_mgr_tx->reset_notification_armed();

                    // Perform a non blocking event read, clear the fd channel
                    p_cq_mgr_tx->poll_and_process_element_tx();
                }
            }

            /* coverity[double_unlock] TODO: RM#1049980 */
            m_lock_ring_tx.unlock();
            m_lock_ring_tx_buf_wait.unlock();
            /* coverity[double_lock] TODO: RM#1049980 */
            m_lock_ring_tx.lock();
        }
    } while (b_block);

    /* coverity[missing_unlock] */
    return granted;
}

uint32_t ring_simple::get_tx_user_lkey(void *addr, size_t length)
{
    uint32_t lkey;

    /*
     * Current implementation supports a ring registration cache where addr is the key.
     *
     * The mode is used for send zerocopy.
     *
     * TODO The mode doesnn't support memory deregistration.
     */
    auto iter = m_user_lkey_map.find(addr);
    if (iter != m_user_lkey_map.end()) {
        lkey = iter->second;
    } else {
        lkey =
            m_p_ib_ctx->get_ctx_ibv_dev().user_mem_reg(addr, length, XLIO_IBV_ACCESS_LOCAL_WRITE);
        if (lkey == LKEY_ERROR) {
            ring_logerr("Can't register user memory addr %p len %lx", addr, length);
        } else {
            m_user_lkey_map[addr] = lkey;
        }
    }
    return lkey;
}

uint32_t ring_simple::get_max_inline_data()
{
    return m_hqtx->get_max_inline_data();
}

uint32_t ring_simple::get_max_send_sge()
{
    return m_hqtx->get_max_send_sge();
}
#endif // DEFINED_DPCP_PATH_TX

#ifdef DEFINED_DPCP_PATH_RX
int ring_simple::get_rx_channel_fd(size_t ch_idx) const
{
    NOT_IN_USE(ch_idx);
    return m_p_rx_comp_event_channel->fd;
}

bool ring_simple::request_notification_rx()
{
    std::lock_guard<decltype(m_lock_ring_rx)> lock(m_lock_ring_rx);
    return m_p_cq_mgr_rx->request_notification();
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
