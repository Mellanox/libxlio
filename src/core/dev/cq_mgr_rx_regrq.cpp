/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "cq_mgr_rx_regrq.h"

#if defined(DEFINED_DIRECT_VERBS)

#include <util/valgrind.h>
#include "cq_mgr_rx_inl.h"
#include "hw_queue_rx.h"
#include "ring_simple.h"

#include <netinet/ip6.h>

#define MODULE_NAME "cq_mgr_rx_regrq"

#define cq_logfunc    __log_info_func
#define cq_logdbg     __log_info_dbg
#define cq_logwarn    __log_info_warn
#define cq_logerr     __log_info_err
#define cq_logpanic   __log_info_panic
#define cq_logfuncall __log_info_funcall

cq_mgr_rx_regrq::cq_mgr_rx_regrq(ring_simple *p_ring, ib_ctx_handler *p_ib_ctx_handler,
                                 uint32_t cq_size, struct ibv_comp_channel *p_comp_event_channel)
    : cq_mgr_rx(p_ring, p_ib_ctx_handler, cq_size, p_comp_event_channel)
{
    cq_logfunc("");
}

uint32_t cq_mgr_rx_regrq::clean_cq()
{
    uint32_t ret_total = 0;
    uint64_t cq_poll_sn = 0;
    mem_buf_desc_t *buff;

    if (!m_hqrx_ptr) { // Sanity check
        return 0;
    }

    buff_status_e status = BS_OK;
    while ((buff = poll(status))) {
        if (cqe_process_rx(buff, status)) {
            m_rx_queue.push_back(buff);
        }
        ++ret_total;
    }
    update_global_sn_rx(cq_poll_sn, ret_total);

    return ret_total;
}

cq_mgr_rx_regrq::~cq_mgr_rx_regrq()
{
    cq_logdbg("Destroying CQ REGRQ");
}

mem_buf_desc_t *cq_mgr_rx_regrq::poll(enum buff_status_e &status)
{
    mem_buf_desc_t *buff = nullptr;

    if (unlikely(!m_rx_hot_buffer)) {
        if (likely(m_hqrx_ptr->m_rq_data.tail != (m_hqrx_ptr->m_rq_data.head))) {
            uint32_t index = m_hqrx_ptr->m_rq_data.tail & (m_hqrx_ptr->m_rx_num_wr - 1);
            m_rx_hot_buffer = (mem_buf_desc_t *)m_hqrx_ptr->m_rq_wqe_idx_to_wrid[index];
            m_hqrx_ptr->m_rq_wqe_idx_to_wrid[index] = 0;
            prefetch((void *)m_rx_hot_buffer);
            prefetch((uint8_t *)m_mlx5_cq.cq_buf +
                     ((m_mlx5_cq.cq_ci & (m_mlx5_cq.cqe_count - 1)) << m_mlx5_cq.cqe_size_log));
        } else {
            /* If rq_tail and rq_head are pointing to the same wqe,
             * the wq is empty and there is no cqe to be received */
            return nullptr;
        }
    }
    xlio_mlx5_cqe *cqe = check_cqe();
    if (likely(cqe)) {
        ++m_mlx5_cq.cq_ci;
        rmb();
        cqe_to_mem_buff_desc(cqe, m_rx_hot_buffer, status);

        ++m_hqrx_ptr->m_rq_data.tail;

        buff = m_rx_hot_buffer;
        m_rx_hot_buffer = nullptr;
    } else {
        prefetch((void *)m_rx_hot_buffer);
    }

    prefetch((uint8_t *)m_mlx5_cq.cq_buf +
             ((m_mlx5_cq.cq_ci & (m_mlx5_cq.cqe_count - 1)) << m_mlx5_cq.cqe_size_log));

    return buff;
}

void cq_mgr_rx_regrq::cqe_to_mem_buff_desc(struct xlio_mlx5_cqe *cqe,
                                           mem_buf_desc_t *p_rx_wc_buf_desc,
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
        p_rx_wc_buf_desc->rx.flow_tag_id = ntohl(cqe->sop_rxdrop_qpn_flowtag) & 0x00FFFFFF;
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

int cq_mgr_rx_regrq::drain_and_proccess(uintptr_t *p_recycle_buffers_last_wr_id /*=NULL*/)
{
    cq_logfuncall("cq contains %d wce in m_rx_queue", m_rx_queue.size());

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

    while ((m_n_sysvar_progress_engine_wce_max > ret_total) || p_recycle_buffers_last_wr_id) {
        buff_status_e status = BS_OK;
        mem_buf_desc_t *buff = poll(status);
        if (!buff) {
            update_global_sn_rx(cq_poll_sn, ret_total);
            m_p_ring->m_gro_mgr.flush_all(nullptr);
            return ret_total;
        }

        if (cqe_process_rx(buff, status)) {
            if (p_recycle_buffers_last_wr_id) {
                m_p_cq_stat->n_rx_pkt_drop++;
                reclaim_recv_buffer_helper(buff);
            } else {
                bool procces_now = is_eth_tcp_frame(buff);

                /* We process immediately all non udp/ip traffic.. */
                if (procces_now) {
                    buff->rx.is_xlio_thr = true;
                    if ((++m_debt < (int)m_n_sysvar_rx_num_wr_to_post_recv) ||
                        !compensate_qp_poll_success(buff)) {
                        process_recv_buffer(buff, NULL);
                    }
                } else { /* udp/ip traffic we just put in the cq's rx queue */
                    m_rx_queue.push_back(buff);
                    mem_buf_desc_t *buff_cur = m_rx_queue.front();
                    m_rx_queue.pop_front();
                    if ((++m_debt < (int)m_n_sysvar_rx_num_wr_to_post_recv) ||
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

    update_global_sn_rx(cq_poll_sn, ret_total);

    m_p_ring->m_gro_mgr.flush_all(nullptr);

    // Update cq statistics
    m_p_cq_stat->n_rx_sw_queue_len = m_rx_queue.size();
    m_p_cq_stat->n_rx_drained_at_once_max =
        std::max(ret_total, m_p_cq_stat->n_rx_drained_at_once_max);

    return ret_total;
}

mem_buf_desc_t *cq_mgr_rx_regrq::poll_and_process_socketxtreme()
{
    buff_status_e status = BS_OK;
    mem_buf_desc_t *buff_wqe = poll(status);

    if (buff_wqe) {
        if (cqe_process_rx(buff_wqe, status)) {
            if ((++m_debt < (int)m_n_sysvar_rx_num_wr_to_post_recv) ||
                !compensate_qp_poll_success(buff_wqe)) {
                return buff_wqe;
            }
        } else if (++m_debt >= (int)m_n_sysvar_rx_num_wr_to_post_recv) {
            compensate_qp_poll_failed();
        }
    } else {
        compensate_qp_poll_failed();
    }

    return nullptr;
}

bool cq_mgr_rx_regrq::poll_and_process_element_rx(uint64_t *p_cq_poll_sn, void *pv_fd_ready_array)
{
    cq_logfuncall("");

    if (unlikely(m_n_sysvar_cq_poll_batch_max <= process_recv_queue(pv_fd_ready_array))) {
        m_p_ring->m_gro_mgr.flush_all(pv_fd_ready_array);
        return false; // CQ was not drained.
    }

    if (m_p_next_rx_desc_poll) {
        prefetch_range((uint8_t *)m_p_next_rx_desc_poll->p_buffer,
                       m_n_sysvar_rx_prefetch_bytes_before_poll);
    }

    buff_status_e status = BS_OK;
    uint32_t rx_polled = 0;
    while (rx_polled < m_n_sysvar_cq_poll_batch_max) {
        mem_buf_desc_t *buff = poll(status);
        if (buff) {
            ++rx_polled;
            if (cqe_process_rx(buff, status)) {
                if ((++m_debt < (int)m_n_sysvar_rx_num_wr_to_post_recv) ||
                    !compensate_qp_poll_success(buff)) {
                    process_recv_buffer(buff, pv_fd_ready_array);
                }
            } else {
                m_p_cq_stat->n_rx_pkt_drop++;
                if (++m_debt >= (int)m_n_sysvar_rx_num_wr_to_post_recv) {
                    compensate_qp_poll_failed();
                }
            }
        } else {
            break;
        }
    }

    update_global_sn_rx(*p_cq_poll_sn, rx_polled);

    if (likely(rx_polled > 0)) {
        m_p_ring->m_gro_mgr.flush_all(pv_fd_ready_array);
    } else {
        compensate_qp_poll_failed();
    }

    return (rx_polled < m_n_sysvar_cq_poll_batch_max);
}

#endif /* DEFINED_DIRECT_VERBS */
