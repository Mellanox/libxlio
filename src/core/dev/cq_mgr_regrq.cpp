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

#include "cq_mgr_regrq.h"

#if defined(DEFINED_DIRECT_VERBS)

#include <util/valgrind.h>
#include "cq_mgr.inl"
#include "cq_mgr_mlx5.inl"
#include "qp_mgr.h"
#include "qp_mgr_eth_mlx5.h"
#include "ring_simple.h"

#include <netinet/ip6.h>

#define MODULE_NAME "cqm_mlx5"

#define cq_logfunc    __log_info_func
#define cq_logdbg     __log_info_dbg
#define cq_logwarn    __log_info_warn
#define cq_logerr     __log_info_err
#define cq_logpanic   __log_info_panic
#define cq_logfuncall __log_info_funcall

cq_mgr_mlx5::cq_mgr_mlx5(ring_simple *p_ring, ib_ctx_handler *p_ib_ctx_handler, uint32_t cq_size,
                         struct ibv_comp_channel *p_comp_event_channel, bool is_rx,
                         bool call_configure)
    : cq_mgr(p_ring, p_ib_ctx_handler, cq_size, p_comp_event_channel, is_rx, call_configure)
    , m_qp(NULL)
    , m_rx_hot_buffer(NULL)
{
    cq_logfunc("");

    memset(&m_mlx5_cq, 0, sizeof(m_mlx5_cq));
}

uint32_t cq_mgr_mlx5::clean_cq()
{
    uint32_t ret_total = 0;
    uint64_t cq_poll_sn = 0;
    mem_buf_desc_t *buff;

    if (m_b_is_rx) {
        /* Sanity check for cq: initialization of tx and rx cq has difference:
         * tx - is done in qp_mgr::configure()
         * rx - is done in qp_mgr::up()
         * as a result rx cq can be created but not initialized
         */
        if (NULL == m_qp) {
            return 0;
        }

        buff_status_e status = BS_OK;
        while ((buff = poll(status))) {
            if (cqe_process_rx(buff, status)) {
                m_rx_queue.push_back(buff);
            }
            ++ret_total;
        }
        update_global_sn(cq_poll_sn, ret_total);
    } else { // Tx
        int ret = 0;
        /* coverity[stack_use_local_overflow] */
        xlio_ibv_wc wce[MCE_MAX_CQ_POLL_BATCH];
        while ((ret = cq_mgr::poll(wce, MCE_MAX_CQ_POLL_BATCH, &cq_poll_sn)) > 0) {
            for (int i = 0; i < ret; i++) {
                buff = cqe_log_and_get_buf_tx(&wce[i]);
                if (buff) {
                    m_p_ring->mem_buf_desc_return_single_to_owner_tx(buff);
                }
            }
            ret_total += ret;
        }
    }

    return ret_total;
}

cq_mgr_mlx5::~cq_mgr_mlx5()
{
    cq_logfunc("");
    cq_logdbg("destroying CQ as %s", (m_b_is_rx ? "Rx" : "Tx"));
}

mem_buf_desc_t *cq_mgr_mlx5::poll(enum buff_status_e &status)
{
    mem_buf_desc_t *buff = NULL;

#ifdef RDTSC_MEASURE_RX_XLIO_TCP_IDLE_POLL
    RDTSC_TAKE_END(RDTSC_FLOW_RX_XLIO_TCP_IDLE_POLL);
#endif // RDTSC_MEASURE_RX_TCP_IDLE_POLLL

#if defined(RDTSC_MEASURE_RX_VERBS_READY_POLL) || defined(RDTSC_MEASURE_RX_VERBS_IDLE_POLL)
    RDTSC_TAKE_START_RX_VERBS_POLL(RDTSC_FLOW_RX_VERBS_READY_POLL, RDTSC_FLOW_RX_VERBS_IDLE_POLL);
#endif // RDTSC_MEASURE_RX_VERBS_READY_POLL || RDTSC_MEASURE_RX_VERBS_IDLE_POLL

    if (unlikely(NULL == m_rx_hot_buffer)) {
        if (likely(m_qp->m_mlx5_qp.rq.tail != (m_qp->m_mlx5_qp.rq.head))) {
            uint32_t index = m_qp->m_mlx5_qp.rq.tail & (m_qp_rec.qp->m_rx_num_wr - 1);
            m_rx_hot_buffer = (mem_buf_desc_t *)m_qp->m_rq_wqe_idx_to_wrid[index];
            m_qp->m_rq_wqe_idx_to_wrid[index] = 0;
            prefetch((void *)m_rx_hot_buffer);
            prefetch((uint8_t *)m_mlx5_cq.cq_buf +
                     ((m_mlx5_cq.cq_ci & (m_mlx5_cq.cqe_count - 1)) << m_mlx5_cq.cqe_size_log));
        } else {
#ifdef RDTSC_MEASURE_RX_VERBS_IDLE_POLL
            RDTSC_TAKE_END(RDTSC_FLOW_RX_VERBS_IDLE_POLL);
#endif

#if defined(RDTSC_MEASURE_RX_XLIO_TCP_IDLE_POLL) || defined(RDTSC_MEASURE_RX_CQE_RECEIVEFROM)
            RDTSC_TAKE_START_XLIO_IDLE_POLL_CQE_TO_RECVFROM(RDTSC_FLOW_RX_XLIO_TCP_IDLE_POLL,
                                                            RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM);
#endif // RDTSC_MEASURE_RX_XLIO_TCP_IDLE_POLL || RDTSC_MEASURE_RX_CQE_RECEIVEFROM
            /* If rq_tail and rq_head are pointing to the same wqe,
             * the wq is empty and there is no cqe to be received */
            return NULL;
        }
    }
    xlio_mlx5_cqe *cqe = check_cqe();
    if (likely(cqe)) {
        /* Update the consumer index */
        ++m_mlx5_cq.cq_ci;
        rmb();
        cqe_to_mem_buff_desc(cqe, m_rx_hot_buffer, status);

        ++m_qp->m_mlx5_qp.rq.tail;
        *m_mlx5_cq.dbrec = htonl(m_mlx5_cq.cq_ci & 0xffffff);

        buff = m_rx_hot_buffer;
        m_rx_hot_buffer = NULL;

#ifdef RDTSC_MEASURE_RX_VERBS_READY_POLL
        RDTSC_TAKE_END(RDTSC_FLOW_RX_VERBS_READY_POLL);
#endif // RDTSC_MEASURE_RX_VERBS_READY_POLL

#ifdef RDTSC_MEASURE_RX_READY_POLL_TO_LWIP
        RDTSC_TAKE_START(RDTSC_FLOW_RX_READY_POLL_TO_LWIP);
#endif
    } else {
#ifdef RDTSC_MEASURE_RX_VERBS_IDLE_POLL
        RDTSC_TAKE_END(RDTSC_FLOW_RX_VERBS_IDLE_POLL);
#endif

#if defined(RDTSC_MEASURE_RX_XLIO_TCP_IDLE_POLL) || defined(RDTSC_MEASURE_RX_CQE_RECEIVEFROM)
        RDTSC_TAKE_START_XLIO_IDLE_POLL_CQE_TO_RECVFROM(RDTSC_FLOW_RX_XLIO_TCP_IDLE_POLL,
                                                        RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM);
#endif // RDTSC_MEASURE_RX_XLIO_TCP_IDLE_POLL || RDTSC_MEASURE_RX_CQE_RECEIVEFROM

        prefetch((void *)m_rx_hot_buffer);
    }

    prefetch((uint8_t *)m_mlx5_cq.cq_buf +
             ((m_mlx5_cq.cq_ci & (m_mlx5_cq.cqe_count - 1)) << m_mlx5_cq.cqe_size_log));

    return buff;
}

void cq_mgr_mlx5::cqe_to_mem_buff_desc(struct xlio_mlx5_cqe *cqe, mem_buf_desc_t *p_rx_wc_buf_desc,
                                       enum buff_status_e &status)
{
    struct mlx5_err_cqe *ecqe;
    ecqe = (struct mlx5_err_cqe *)cqe;

    switch (MLX5_CQE_OPCODE(cqe->op_own)) {
    case MLX5_CQE_RESP_WR_IMM:
        cq_logerr("IBV_WC_RECV_RDMA_WITH_IMM is not supported");
        status = BS_CQE_RESP_WR_IMM_NOT_SUPPORTED;
        break;
    case MLX5_CQE_RESP_SEND:
    case MLX5_CQE_RESP_SEND_IMM:
    case MLX5_CQE_RESP_SEND_INV: {
        status = BS_OK;
        p_rx_wc_buf_desc->sz_data = ntohl(cqe->byte_cnt);
#ifdef DEFINED_UTLS
        p_rx_wc_buf_desc->rx.tls_decrypted = (cqe->pkt_info >> 3) & 0x3;
#endif /* DEFINED_UTLS */
        p_rx_wc_buf_desc->rx.timestamps.hw_raw = ntohll(cqe->timestamp);
        p_rx_wc_buf_desc->rx.flow_tag_id = xlio_get_flow_tag(cqe);
        p_rx_wc_buf_desc->rx.is_sw_csum_need =
            !(m_b_is_rx_hw_csum_on && (cqe->hds_ip_ext & MLX5_CQE_L4_OK) &&
              (cqe->hds_ip_ext & MLX5_CQE_L3_OK));
        if (cqe->lro_num_seg > 1) {
            lro_update_hdr(cqe, p_rx_wc_buf_desc);
            m_p_cq_stat->n_rx_lro_packets++;
            m_p_cq_stat->n_rx_lro_bytes += p_rx_wc_buf_desc->sz_data;
        }
        return;
    }
    case MLX5_CQE_INVALID: /* No cqe!*/
    {
        cq_logerr("We should no receive a buffer without a cqe\n");
        status = BS_CQE_INVALID;
        break;
    }
    case MLX5_CQE_REQ:
    case MLX5_CQE_REQ_ERR:
    case MLX5_CQE_RESP_ERR:
    default: {
        if (MLX5_CQE_SYNDROME_WR_FLUSH_ERR == ecqe->syndrome) {
            status = BS_IBV_WC_WR_FLUSH_ERR;
        } else {
            status = BS_GENERAL_ERR;
        }
        /*
          IB compliant completion with error syndrome:
          0x1: Local_Length_Error
          0x2: Local_QP_Operation_Error
          0x4: Local_Protection_Error
          0x5: Work_Request_Flushed_Error
          0x6: Memory_Window_Bind_Error
          0x10: Bad_Response_Error
          0x11: Local_Access_Error
          0x12: Remote_Invalid_Request_Error
          0x13: Remote_Access_Error
          0x14: Remote_Operation_Error
          0x15: Transport_Retry_Counter_Exceeded
          0x16: RNR_Retry_Counter_Exceeded
          0x22: Aborted_Error
          other: Reserved
         */
        break;
    }
    }

    // increase cqe error counter should be done once, here (regular flow)
    switch (MLX5_CQE_OPCODE(cqe->op_own)) {
    case MLX5_CQE_INVALID:
    case MLX5_CQE_REQ_ERR:
    case MLX5_CQE_RESP_ERR:
        m_p_cq_stat->n_rx_cqe_error++;
        break;
    }
}

int cq_mgr_mlx5::drain_and_proccess_helper(mem_buf_desc_t *buff, buff_status_e status,
                                           uintptr_t *p_recycle_buffers_last_wr_id)
{
    ++m_n_wce_counter;
    if (cqe_process_rx(buff, status)) {
        if (p_recycle_buffers_last_wr_id) {
            m_p_cq_stat->n_rx_pkt_drop++;
            reclaim_recv_buffer_helper(buff);
        } else {
            bool procces_now =
                (m_transport_type == XLIO_TRANSPORT_ETH ? is_eth_tcp_frame(buff) : false);

            if (procces_now) { // We process immediately all non udp/ip traffic..
                buff->rx.is_xlio_thr = true;
                if ((++m_qp_rec.debt < (int)m_n_sysvar_rx_num_wr_to_post_recv) ||
                    !compensate_qp_poll_success(buff)) {
                    process_recv_buffer(buff, nullptr);
                }
            } else { // udp/ip traffic we just put in the cq's rx queue
                m_rx_queue.push_back(buff);
                mem_buf_desc_t *buff_cur = m_rx_queue.get_and_pop_front();
                if ((++m_qp_rec.debt < (int)m_n_sysvar_rx_num_wr_to_post_recv) ||
                    !compensate_qp_poll_success(buff_cur)) {
                    m_rx_queue.push_front(buff_cur);
                }
            }
        }
    }

    if (p_recycle_buffers_last_wr_id) {
        *p_recycle_buffers_last_wr_id = (uintptr_t)buff;
    }

    return 1;
}

int cq_mgr_mlx5::drain_and_proccess(uintptr_t *p_recycle_buffers_last_wr_id /*=NULL*/)
{
    cq_logfuncall("cq was %s drained. %d processed wce since last check. %d wce in m_rx_queue",
                  (m_b_was_drained ? "" : "not "), m_n_wce_counter, m_rx_queue.size());

    /* CQ polling loop until max wce limit is reached for this interval or CQ is drained */
    uint32_t ret_total = 0;
    uint64_t cq_poll_sn = 0;

    /* drain_and_proccess() is mainly called in following cases as
     * Internal thread:
     *   Frequency of real polling can be controlled by
     *   PROGRESS_ENGINE_INTERVAL and PROGRESS_ENGINE_WCE_MAX.
     * socketxtreme:
     *   User does socketxtreme_poll()
     * Cleanup:
     *   QP down logic to release rx buffers should force polling to do this.
     *   Not null argument indicates one.
     */

    while (((m_n_sysvar_progress_engine_wce_max > m_n_wce_counter) && (!m_b_was_drained)) ||
           (p_recycle_buffers_last_wr_id)) {
        buff_status_e status = BS_OK;
        mem_buf_desc_t *buff = poll(status);
        if (NULL == buff) {
            update_global_sn(cq_poll_sn, ret_total);
            m_b_was_drained = true;
            m_p_ring->m_gro_mgr.flush_all(NULL);
            return ret_total;
        }

        ++m_n_wce_counter;

        if (cqe_process_rx(buff, status)) {
            if (p_recycle_buffers_last_wr_id) {
                m_p_cq_stat->n_rx_pkt_drop++;
                reclaim_recv_buffer_helper(buff);
            } else {
                bool procces_now = false;
                if (m_transport_type == XLIO_TRANSPORT_ETH) {
                    procces_now = is_eth_tcp_frame(buff);
                }
                /* We process immediately all non udp/ip traffic.. */
                if (procces_now) {
                    buff->rx.is_xlio_thr = true;
                    if ((++m_qp_rec.debt < (int)m_n_sysvar_rx_num_wr_to_post_recv) ||
                        !compensate_qp_poll_success(buff)) {
                        process_recv_buffer(buff, NULL);
                    }
                } else { /* udp/ip traffic we just put in the cq's rx queue */
                    m_rx_queue.push_back(buff);
                    mem_buf_desc_t *buff_cur = m_rx_queue.front();
                    m_rx_queue.pop_front();
                    if ((++m_qp_rec.debt < (int)m_n_sysvar_rx_num_wr_to_post_recv) ||
                        !compensate_qp_poll_success(buff_cur)) {
                        m_rx_queue.push_front(buff_cur);
                    }
                }
            }
        }

        if (p_recycle_buffers_last_wr_id) {
            *p_recycle_buffers_last_wr_id = (uintptr_t)buff;
        }

        ++ret_total;
    }

    update_global_sn(cq_poll_sn, ret_total);

    m_p_ring->m_gro_mgr.flush_all(NULL);

    m_n_wce_counter = 0;
    m_b_was_drained = false;

    // Update cq statistics
    m_p_cq_stat->n_rx_sw_queue_len = m_rx_queue.size();
    m_p_cq_stat->n_rx_drained_at_once_max =
        std::max(ret_total, m_p_cq_stat->n_rx_drained_at_once_max);

    return ret_total;
}

mem_buf_desc_t *cq_mgr_mlx5::cqe_process_rx(mem_buf_desc_t *p_mem_buf_desc,
                                            enum buff_status_e status)
{
    /* Assume locked!!! */
    cq_logfuncall("");

    /* we use context to verify that on reclaim rx buffer path we return the buffer to the right CQ
     */
    p_mem_buf_desc->rx.is_xlio_thr = false;
    p_mem_buf_desc->rx.context = NULL;

    if (unlikely(status != BS_OK)) {
        m_p_next_rx_desc_poll = NULL;
        reclaim_recv_buffer_helper(p_mem_buf_desc);
        return NULL;
    }

    if (m_n_sysvar_rx_prefetch_bytes_before_poll) {
        m_p_next_rx_desc_poll = p_mem_buf_desc->p_prev_desc;
        p_mem_buf_desc->p_prev_desc = NULL;
    }

    VALGRIND_MAKE_MEM_DEFINED(p_mem_buf_desc->p_buffer, p_mem_buf_desc->sz_data);

    prefetch_range((uint8_t *)p_mem_buf_desc->p_buffer + m_sz_transport_header,
                   std::min(p_mem_buf_desc->sz_data - m_sz_transport_header,
                            (size_t)m_n_sysvar_rx_prefetch_bytes));

    return p_mem_buf_desc;
}

mem_buf_desc_t *cq_mgr_mlx5::poll_and_process_socketxtreme()
{
    buff_status_e status = BS_OK;
    mem_buf_desc_t *buff_wqe = poll(status);

    if (buff_wqe) {
        if (cqe_process_rx(buff_wqe, status)) {
            if ((++m_qp_rec.debt < (int)m_n_sysvar_rx_num_wr_to_post_recv) ||
                !compensate_qp_poll_success(buff_wqe)) {
                return buff_wqe;
            }
        } else if (++m_qp_rec.debt >= (int)m_n_sysvar_rx_num_wr_to_post_recv) {
            compensate_qp_poll_failed();
        }
    } else {
        compensate_qp_poll_failed();
    }

    return nullptr;
}

int cq_mgr_mlx5::poll_and_process_element_rx(uint64_t *p_cq_poll_sn, void *pv_fd_ready_array)
{
    /* Assume locked!!! */
    cq_logfuncall("");

    uint32_t ret_rx_processed = process_recv_queue(pv_fd_ready_array);
    if (unlikely(ret_rx_processed >= m_n_sysvar_cq_poll_batch_max)) {
        m_p_ring->m_gro_mgr.flush_all(pv_fd_ready_array);
        return ret_rx_processed;
    }

    if (m_p_next_rx_desc_poll) {
        prefetch_range((uint8_t *)m_p_next_rx_desc_poll->p_buffer,
                       m_n_sysvar_rx_prefetch_bytes_before_poll);
    }

    buff_status_e status = BS_OK;
    uint32_t ret = 0;
    while (ret < m_n_sysvar_cq_poll_batch_max) {
        mem_buf_desc_t *buff = poll(status);
        if (buff) {
            ++ret;
            if (cqe_process_rx(buff, status)) {
                if ((++m_qp_rec.debt < (int)m_n_sysvar_rx_num_wr_to_post_recv) ||
                    !compensate_qp_poll_success(buff)) {
                    process_recv_buffer(buff, pv_fd_ready_array);
                }
            } else {
                m_p_cq_stat->n_rx_pkt_drop++;
                if (++m_qp_rec.debt >= (int)m_n_sysvar_rx_num_wr_to_post_recv) {
                    compensate_qp_poll_failed();
                }
            }
        } else {
            m_b_was_drained = true;
            break;
        }
    }

    update_global_sn(*p_cq_poll_sn, ret);

    if (likely(ret > 0)) {
        ret_rx_processed += ret;
        m_n_wce_counter += ret;
        m_p_ring->m_gro_mgr.flush_all(pv_fd_ready_array);
    } else {
        compensate_qp_poll_failed();
    }

    return ret_rx_processed;
}

void cq_mgr_mlx5::log_cqe_error(struct xlio_mlx5_cqe *cqe)
{
    struct mlx5_err_cqe *ecqe = (struct mlx5_err_cqe *)cqe;

    /* TODO We can also ask qp_mgr to log WQE fields from SQ. But at first, we need to remove
     * prefetch and memset of the next WQE there. Credit system will guarantee that we don't
     * reuse the WQE at this point.
     */

    if (MLX5_CQE_SYNDROME_WR_FLUSH_ERR != ecqe->syndrome) {
        cq_logwarn("cqe: syndrome=0x%x vendor=0x%x hw=0x%x (type=0x%x) wqe_opcode_qpn=0x%x "
                   "wqe_counter=0x%x",
                   ecqe->syndrome, ecqe->vendor_err_synd, *((uint8_t *)&ecqe->rsvd1 + 16),
                   *((uint8_t *)&ecqe->rsvd1 + 17), ntohl(ecqe->s_wqe_opcode_qpn),
                   ntohs(ecqe->wqe_counter));
    }
}

void cq_mgr_mlx5::handle_sq_wqe_prop(unsigned index)
{
    sq_wqe_prop *p = &m_qp->m_sq_wqe_idx_to_prop[index];
    sq_wqe_prop *prev;
    unsigned credits = 0;

    /*
     * TX completions can be signalled for a set of WQEs as an optimization.
     * Therefore, for every TX completion we may need to handle multiple
     * WQEs. Since every WQE can have various size and the WQE index is
     * wrapped around, we build a linked list to simplify things. Each
     * element of the linked list represents properties of a previously
     * posted WQE.
     *
     * We keep index of the last completed WQE and stop processing the list
     * when we reach the index. This condition is checked in
     * is_sq_wqe_prop_valid().
     */

    do {
        if (p->buf) {
            m_p_ring->mem_buf_desc_return_single_locked(p->buf);
        }
        if (p->ti) {
            xlio_ti *ti = p->ti;
            if (ti->m_callback) {
                ti->m_callback(ti->m_callback_arg);
            }

            ti->put();
            if (unlikely(ti->m_released && ti->m_ref == 0)) {
                m_qp->ti_released(ti);
            }
        }
        credits += p->credits;

        prev = p;
        p = p->next;
    } while (p != NULL && m_qp->is_sq_wqe_prop_valid(p, prev));

    m_p_ring->return_tx_pool_to_global_pool();
    m_qp->credits_return(credits);
    m_qp->m_sq_wqe_prop_last_signalled = index;
}

int cq_mgr_mlx5::poll_and_process_element_tx(uint64_t *p_cq_poll_sn)
{
    cq_logfuncall("");

    static auto is_error_opcode = [&](uint8_t opcode) {
        return opcode == MLX5_CQE_REQ_ERR || opcode == MLX5_CQE_RESP_ERR;
    };

    int ret = 0;
    uint32_t num_polled_cqes = 0;
    xlio_mlx5_cqe *cqe = get_cqe_tx(num_polled_cqes);

    if (likely(cqe)) {
        unsigned index = ntohs(cqe->wqe_counter) & (m_qp->m_tx_num_wr - 1);

        // All error opcodes have the most significant bit set.
        if (unlikely(cqe->op_own & 0x80) && is_error_opcode(cqe->op_own >> 4)) {
            m_p_cq_stat->n_rx_cqe_error++;
            log_cqe_error(cqe);
        }

        handle_sq_wqe_prop(index);
        ret = 1;
    }
    update_global_sn(*p_cq_poll_sn, num_polled_cqes);

    return ret;
}

void cq_mgr_mlx5::set_qp_rq(qp_mgr *qp)
{
    m_qp = static_cast<qp_mgr_eth_mlx5 *>(qp);

    m_qp->m_rq_wqe_counter = 0; // In case of bonded qp, wqe_counter must be reset to zero
    m_rx_hot_buffer = NULL;

    if (0 != xlio_ib_mlx5_get_cq(m_p_ibv_cq, &m_mlx5_cq)) {
        cq_logpanic("xlio_ib_mlx5_get_cq failed (errno=%d %m)", errno);
    }
    VALGRIND_MAKE_MEM_DEFINED(&m_mlx5_cq, sizeof(m_mlx5_cq));
    cq_logfunc("qp_mgr=%p m_mlx5_cq.dbrec=%p m_mlx5_cq.cq_buf=%p", m_qp, m_mlx5_cq.dbrec,
               m_mlx5_cq.cq_buf);
}

void cq_mgr_mlx5::add_qp_rx(qp_mgr *qp)
{
    cq_logfunc("");
    set_qp_rq(qp);
    cq_mgr::add_qp_rx(qp);
}

void cq_mgr_mlx5::add_qp_tx(qp_mgr *qp)
{
    // Assume locked!
    cq_mgr::add_qp_tx(qp);
    m_qp = static_cast<qp_mgr_eth_mlx5 *>(qp);

    if (0 != xlio_ib_mlx5_get_cq(m_p_ibv_cq, &m_mlx5_cq)) {
        cq_logpanic("xlio_ib_mlx5_get_cq failed (errno=%d %m)", errno);
    }

    cq_logfunc("qp_mgr=%p m_mlx5_cq.dbrec=%p m_mlx5_cq.cq_buf=%p", m_qp, m_mlx5_cq.dbrec,
               m_mlx5_cq.cq_buf);
}

void cq_mgr_mlx5::lro_update_hdr(struct xlio_mlx5_cqe *cqe, mem_buf_desc_t *p_rx_wc_buf_desc)
{
    struct ethhdr *p_eth_h = (struct ethhdr *)(p_rx_wc_buf_desc->p_buffer);
    struct tcphdr *p_tcp_h;
    size_t transport_header_len = ETH_HDR_LEN;

    if (p_eth_h->h_proto == htons(ETH_P_8021Q)) {
        transport_header_len = ETH_VLAN_HDR_LEN;
    }

    if (0x02 == ((cqe->l4_hdr_type_etc >> 2) & 0x3)) {
        // CQE indicates IPv4 in the l3_hdr_type field
        struct iphdr *p_ip_h = (struct iphdr *)(p_rx_wc_buf_desc->p_buffer + transport_header_len);

        assert(p_ip_h->version == IPV4_VERSION);
        assert(p_ip_h->protocol == IPPROTO_TCP);

        p_ip_h->ttl = cqe->lro_min_ttl;
        p_ip_h->tot_len = htons(ntohl(cqe->byte_cnt) - transport_header_len);
        p_ip_h->check = 0; // Ignore.

        p_tcp_h = (struct tcphdr *)((uint8_t *)p_ip_h + (int)(p_ip_h->ihl) * 4);
    } else {
        // Assume LRO can happen for either IPv4 or IPv6 L3 protocol. Skip checking l3_hdr_type.
        struct ip6_hdr *p_ip6_h =
            (struct ip6_hdr *)(p_rx_wc_buf_desc->p_buffer + transport_header_len);

        assert(0x01 == ((cqe->l4_hdr_type_etc >> 2) & 0x3)); // IPv6 L3 header.
        assert(ip_header_version(p_ip6_h) == IPV6);
        assert(p_ip6_h->ip6_nxt == IPPROTO_TCP);
        assert(ntohl(cqe->byte_cnt) >= transport_header_len + IPV6_HLEN);

        p_ip6_h->ip6_hlim = cqe->lro_min_ttl;
        // Payload length doesn't include main header.
        p_ip6_h->ip6_plen = htons(ntohl(cqe->byte_cnt) - transport_header_len - IPV6_HLEN);

        // LRO doesn't create a session for packets with extension headers, so IPv6 header is 40b.
        p_tcp_h = (struct tcphdr *)((uint8_t *)p_ip6_h + IPV6_HLEN);
    }

    p_tcp_h->psh = !!(cqe->lro_tcppsh_abort_dupack & MLX5_CQE_LRO_TCP_PUSH_MASK);

    /* TCP packet <ACK> flag is set, and packet carries no data or
     * TCP packet <ACK> flag is set, and packet carries data
     */
    if ((0x03 == ((cqe->l4_hdr_type_etc >> 4) & 0x7)) ||
        (0x04 == ((cqe->l4_hdr_type_etc >> 4) & 0x7))) {
        p_tcp_h->ack = 1;
        p_tcp_h->ack_seq = cqe->lro_ack_seq_num;
        p_tcp_h->window = cqe->lro_tcp_win;
        p_tcp_h->check = 0; // Ignore.
    }
}

#endif /* DEFINED_DIRECT_VERBS */
