/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "cq_mgr_rx_strq.h"

#if defined(DEFINED_DIRECT_VERBS)

#include <util/valgrind.h>
#include "cq_mgr_rx_inl.h"
#include "hw_queue_rx.h"
#include "ring_simple.h"
#include <cinttypes>

#define MODULE_NAME "cq_mgr_rx_strq"

#define cq_logfunc    __log_info_func
#define cq_logdbg     __log_info_dbg
#define cq_logerr     __log_info_err
#define cq_logpanic   __log_info_panic
#define cq_logfuncall __log_info_funcall
#define cq_logdbg_no_funcname(log_fmt, log_args...)                                                \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_DEBUG)                                                         \
            vlog_printf(VLOG_DEBUG, MODULE_NAME "[%p]:%d: " log_fmt "\n", __INFO__, __LINE__,      \
                        ##log_args);                                                               \
    } while (0)

cq_mgr_rx_strq::cq_mgr_rx_strq(ring_simple *p_ring, ib_ctx_handler *p_ib_ctx_handler,
                               uint32_t cq_size, uint32_t stride_size_bytes, uint32_t strides_num,
                               struct ibv_comp_channel *p_comp_event_channel)
    : cq_mgr_rx(p_ring, p_ib_ctx_handler, cq_size, p_comp_event_channel)
    , _owner_ring(p_ring)
    , _stride_size_bytes(stride_size_bytes)
    , _strides_num(strides_num)
    , _wqe_buff_size_bytes(strides_num * stride_size_bytes)
{
    cq_logfunc("");
    m_n_sysvar_rx_prefetch_bytes_before_poll =
        std::min(m_n_sysvar_rx_prefetch_bytes_before_poll, stride_size_bytes);

    return_stride(next_stride()); // Fill _stride_cache
}

/**
 * @brief Destructor for cq_mgr_rx_strq class
 *
 * Cleans up all resources associated with the CQ STRQ
 *
 * @note The coverity[UNCAUGHT_EXCEPT] was added as it's a False Positive
 */
// coverity[UNCAUGHT_EXCEPT]
cq_mgr_rx_strq::~cq_mgr_rx_strq()
{
    cq_logfunc("");
    cq_logdbg("destroying CQ STRQ");

    if (m_rx_queue.size()) {
        cq_logdbg("Clearing %zu stride objects)", m_rx_queue.size());

        while (!m_rx_queue.empty()) {
            mem_buf_desc_t *buff = m_rx_queue.get_and_pop_front();
            if (likely(buff)) {
                reclaim_recv_buffer_helper(buff);
            }
        }

        m_p_cq_stat->n_rx_sw_queue_len = m_rx_queue.size();
    }

    if (_hot_buffer_stride) {
        return_stride(_hot_buffer_stride);
    }

    g_buffer_pool_rx_stride->put_buffers_thread_safe(&_stride_cache, _stride_cache.size());
}

mem_buf_desc_t *cq_mgr_rx_strq::next_stride()
{
    if (unlikely(_stride_cache.size() <= 0U)) {
        if (!g_buffer_pool_rx_stride->get_buffers_thread_safe(
                _stride_cache, _owner_ring, safe_mce_sys().strq_strides_compensation_level, 0U)) {
            // This pool should be an infinite pool
            __log_info_panic(
                "Unable to retrieve strides from global pool, Free: %zu, Requested: %u",
                g_buffer_pool_rx_stride->get_free_count(),
                safe_mce_sys().strq_strides_compensation_level);
        }
    }

    return _stride_cache.get_and_pop_back();
}

void cq_mgr_rx_strq::return_stride(mem_buf_desc_t *desc)
{
    _stride_cache.push_back(desc);

    if (unlikely(_stride_cache.size() >= safe_mce_sys().strq_strides_compensation_level * 2U)) {
        g_buffer_pool_rx_stride->put_buffers_thread_safe(
            &_stride_cache, _stride_cache.size() - safe_mce_sys().strq_strides_compensation_level);
    }
}

uint32_t cq_mgr_rx_strq::clean_cq()
{
    uint32_t ret_total = 0;
    uint64_t cq_poll_sn = 0;

    if (!m_hqrx_ptr) { // Sanity check
        return 0;
    }

    mem_buf_desc_t *stride_buf = nullptr;
    buff_status_e status = BS_OK;
    while (poll(status, stride_buf) || stride_buf) {
        if (stride_buf && cqe_process_rx(stride_buf, status)) {
            m_rx_queue.push_back(stride_buf);
        }

        ++ret_total;
        stride_buf = nullptr;
    }

    update_global_sn_rx(cq_poll_sn, ret_total);

    return ret_total;
}

bool cq_mgr_rx_strq::set_current_hot_buffer()
{
    if (likely(m_hqrx_ptr->m_rq_data.tail != (m_hqrx_ptr->m_rq_data.head))) {
        uint32_t index = m_hqrx_ptr->m_rq_data.tail & (m_hqrx_ptr->m_rx_num_wr - 1);
        m_rx_hot_buffer = (mem_buf_desc_t *)m_hqrx_ptr->m_rq_wqe_idx_to_wrid[index];
        m_rx_hot_buffer->set_ref_count(_strides_num);
        m_hqrx_ptr->m_rq_wqe_idx_to_wrid[index] = 0;
        return true;
    }

    // If rq_tail and rq_head are pointing to the same wqe,
    // the wq is empty and there is no cqe to be received */
    return false;
}

mem_buf_desc_t *cq_mgr_rx_strq::poll(enum buff_status_e &status, mem_buf_desc_t *&buff_stride)
{
    mem_buf_desc_t *buff = nullptr;

    if (unlikely(!m_rx_hot_buffer)) {
        if (!set_current_hot_buffer()) {
            return nullptr;
        }
    }

    if (likely(!_hot_buffer_stride)) {
        _hot_buffer_stride = next_stride();
        prefetch((void *)_hot_buffer_stride);
        prefetch((uint8_t *)m_mlx5_cq.cq_buf +
                 ((m_mlx5_cq.cq_ci & (m_mlx5_cq.cqe_count - 1)) << m_mlx5_cq.cqe_size_log));
    }

    xlio_mlx5_cqe *cqe = check_cqe();
    if (likely(cqe)) {
        ++m_mlx5_cq.cq_ci;
        rmb();

        bool is_filler = false;
        bool is_wqe_complete = strq_cqe_to_mem_buff_desc(cqe, status, is_filler);

        if (is_wqe_complete) {
            ++m_hqrx_ptr->m_rq_data.tail;
            buff = m_rx_hot_buffer;
            m_rx_hot_buffer = nullptr;
            if (likely(status == BS_OK)) {
                ++m_p_cq_stat->n_rx_consumed_rwqe_count;
            }
        }

        if (likely(!is_filler)) {
            ++m_p_cq_stat->n_rx_packet_count;
            m_p_cq_stat->n_rx_stride_count += _hot_buffer_stride->rx.strides_num;
            m_p_cq_stat->n_rx_max_stirde_per_packet = std::max(
                m_p_cq_stat->n_rx_max_stirde_per_packet, _hot_buffer_stride->rx.strides_num);
            buff_stride = _hot_buffer_stride;
            _hot_buffer_stride = nullptr;
        } else if (status != BS_CQE_INVALID) {
            reclaim_recv_buffer_helper(_hot_buffer_stride);
            _hot_buffer_stride = nullptr;
        }
    } else {
        prefetch((void *)_hot_buffer_stride);
    }

    prefetch((uint8_t *)m_mlx5_cq.cq_buf +
             ((m_mlx5_cq.cq_ci & (m_mlx5_cq.cqe_count - 1)) << m_mlx5_cq.cqe_size_log));

    return buff;
}

inline bool cq_mgr_rx_strq::strq_cqe_to_mem_buff_desc(struct xlio_mlx5_cqe *cqe,
                                                      enum buff_status_e &status, bool &is_filler)
{
    struct mlx5_err_cqe *ecqe;
    ecqe = (struct mlx5_err_cqe *)cqe;
    uint32_t host_byte_cnt = ntohl(cqe->byte_cnt);

    switch (MLX5_CQE_OPCODE(cqe->op_own)) {
    case MLX5_CQE_RESP_WR_IMM:
        cq_logerr("IBV_WC_RECV_RDMA_WITH_IMM is not supported");
        status = BS_CQE_RESP_WR_IMM_NOT_SUPPORTED;
        break;
    case MLX5_CQE_RESP_SEND:
    case MLX5_CQE_RESP_SEND_IMM:
    case MLX5_CQE_RESP_SEND_INV: {
        status = BS_OK;
        _hot_buffer_stride->rx.strides_num = ((host_byte_cnt >> 16) & 0x00003FFF);
        _hot_buffer_stride->lwip_pbuf.desc.attr = PBUF_DESC_STRIDE;
        _hot_buffer_stride->lwip_pbuf.desc.mdesc = m_rx_hot_buffer;

        is_filler = (host_byte_cnt >> 31 != 0U ? true : false);
        _hot_buffer_stride->sz_data =
            host_byte_cnt & 0x0000FFFFU; // In case of a Filler/Error this size is invalid.
        _hot_buffer_stride->p_buffer = m_rx_hot_buffer->p_buffer +
            _current_wqe_consumed_bytes; //(_stride_size_bytes * ntohs(cqe->wqe_counter))
        _hot_buffer_stride->sz_buffer = _hot_buffer_stride->rx.strides_num * _stride_size_bytes;
        _current_wqe_consumed_bytes += _hot_buffer_stride->sz_buffer;

        _hot_buffer_stride->rx.timestamps.hw_raw = ntohll(cqe->timestamp);
        uint32_t sop_rxdrop_qpn_flowtag_h_byte = ntohl(cqe->sop_rxdrop_qpn_flowtag);
        _hot_buffer_stride->rx.flow_tag_id = sop_rxdrop_qpn_flowtag_h_byte & 0x00FFFFFF;
        m_p_cq_stat->n_rx_hw_pkt_drops += sop_rxdrop_qpn_flowtag_h_byte >> 24;
        _hot_buffer_stride->rx.is_sw_csum_need =
            !(m_b_is_rx_hw_csum_on && (cqe->hds_ip_ext & MLX5_CQE_L4_OK) &&
              (cqe->hds_ip_ext & MLX5_CQE_L3_OK));
#ifdef DEFINED_UTLS
        _hot_buffer_stride->rx.tls_decrypted = (cqe->pkt_info >> 3) & 0x3;
#endif /* DEFINED_UTLS */
        if (cqe->lro_num_seg > 1) {
            lro_update_hdr(cqe, _hot_buffer_stride);
            m_p_cq_stat->n_rx_lro_packets++;
            m_p_cq_stat->n_rx_lro_bytes += _hot_buffer_stride->sz_data;
        }
        break;
    }
    case MLX5_CQE_INVALID: /* No cqe!*/
    {
        cq_logerr("We should no receive a buffer without a cqe\n");
        status = BS_CQE_INVALID;
        return false;
    }
    case MLX5_CQE_REQ:
    case MLX5_CQE_REQ_ERR:
    case MLX5_CQE_RESP_ERR:
    default: {
        _hot_buffer_stride->rx.strides_num = ((host_byte_cnt >> 16) & 0x00003FFF);
        _hot_buffer_stride->lwip_pbuf.desc.attr = PBUF_DESC_STRIDE;
        _hot_buffer_stride->lwip_pbuf.desc.mdesc = m_rx_hot_buffer;
        is_filler = true;
        _current_wqe_consumed_bytes = _wqe_buff_size_bytes;
        _hot_buffer_stride->sz_data = 0U;
        _hot_buffer_stride->p_buffer = nullptr;
        _hot_buffer_stride->sz_buffer = 0U;

        if (_hot_buffer_stride->rx.strides_num == 0U) {
            _hot_buffer_stride->rx.strides_num = _strides_num;
        }

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

    cq_logfunc("STRQ CQE. Status: %d, WQE-ID: %hu, Is-Filler: %" PRIu32 ", Orig-HBC: %" PRIu32
               ", Data-Size: %" PRIu32 ", Strides: %hu, Consumed-Bytes: %" PRIu32
               ", RX-HB: %p, RX-HB-SZ: %zu\n",
               static_cast<int>(status), cqe->wqe_id, (host_byte_cnt >> 31), cqe->byte_cnt,
               (host_byte_cnt & 0x0000FFFFU), _hot_buffer_stride->rx.strides_num,
               _current_wqe_consumed_bytes, m_rx_hot_buffer, m_rx_hot_buffer->sz_buffer);
    // vlog_print_buffer(VLOG_FINE, "STRQ CQE. Data: ", "\n",
    //	reinterpret_cast<const char*>(_hot_buffer_stride->p_buffer), min(112,
    // static_cast<int>(_hot_buffer_stride->sz_data)));

    if (_current_wqe_consumed_bytes >= _wqe_buff_size_bytes) {
        _current_wqe_consumed_bytes = 0;
        return true;
    }

    return false;
}

int cq_mgr_rx_strq::drain_and_proccess_helper(mem_buf_desc_t *buff, mem_buf_desc_t *buff_wqe,
                                              buff_status_e status,
                                              uintptr_t *p_recycle_buffers_last_wr_id)
{
    int ret_total = 0;
    if (buff_wqe && (++m_debt >= (int)m_n_sysvar_rx_num_wr_to_post_recv) &&
        !p_recycle_buffers_last_wr_id) {
        compensate_qp_poll_failed(); // Reuse this method as success.
    }

    // Handle a stride. It can be that we have got a Filler CQE, in this case buff is null.
    if (buff) {
        ++ret_total;
        if (process_strq_cq_element_rx(buff, status)) {
            if (p_recycle_buffers_last_wr_id) {
                m_p_cq_stat->n_rx_sw_pkt_drops++;
                reclaim_recv_buffer_helper(buff);
            } else {
                bool procces_now = is_eth_tcp_frame(buff);

                // We process immediately all non udp/ip traffic..
                if (procces_now) {
                    process_recv_buffer(buff, nullptr);
                } else { // udp/ip traffic we just put in the cq's rx queue
                    m_rx_queue.push_back(buff);
                }
            }
        }
    }

    if (p_recycle_buffers_last_wr_id && buff_wqe) {
        *p_recycle_buffers_last_wr_id = (uintptr_t)buff_wqe;
    }

    return ret_total;
}

int cq_mgr_rx_strq::drain_and_proccess(uintptr_t *p_recycle_buffers_last_wr_id)
{
    cq_logfuncall("cq contains %d wce in m_rx_queue", m_rx_queue.size());

    // CQ polling loop until max wce limit is reached for this interval or CQ is drained
    uint32_t ret_total = 0;
    uint64_t cq_poll_sn = 0;

    // drain_and_proccess() is mainly called in following cases as
    // Internal thread:
    //   Frequency of real polling can be controlled by
    //   PROGRESS_ENGINE_INTERVAL and PROGRESS_ENGINE_WCE_MAX.
    // Cleanup:
    //   QP down logic to release rx buffers should force polling to do this.
    //   Not null argument indicates one.

    while ((m_n_sysvar_progress_engine_wce_max > ret_total) || p_recycle_buffers_last_wr_id) {
        buff_status_e status = BS_OK;
        mem_buf_desc_t *buff = nullptr;
        mem_buf_desc_t *buff_wqe = poll(status, buff);
        if (!buff && !buff_wqe) {
            update_global_sn_rx(cq_poll_sn, ret_total);
            m_p_ring->m_gro_mgr.flush_all(nullptr);
            return ret_total;
        }

        ret_total +=
            drain_and_proccess_helper(buff, buff_wqe, status, p_recycle_buffers_last_wr_id);
    }

    update_global_sn_rx(cq_poll_sn, ret_total);

    m_p_ring->m_gro_mgr.flush_all(nullptr);

    // Update cq statistics
    m_p_cq_stat->n_rx_sw_queue_len = m_rx_queue.size();
    m_p_cq_stat->n_rx_drained_at_once_max =
        std::max(ret_total, m_p_cq_stat->n_rx_drained_at_once_max);

    return ret_total;
}

mem_buf_desc_t *cq_mgr_rx_strq::process_strq_cq_element_rx(mem_buf_desc_t *p_mem_buf_desc,
                                                           enum buff_status_e status)
{
    /* Assume locked!!! */
    cq_logfuncall("");

    if (unlikely(status != BS_OK)) {
        reclaim_recv_buffer_helper(p_mem_buf_desc);
        return nullptr;
    }

    VALGRIND_MAKE_MEM_DEFINED(p_mem_buf_desc->p_buffer, p_mem_buf_desc->sz_data);

    prefetch_range((uint8_t *)p_mem_buf_desc->p_buffer + m_sz_transport_header,
                   std::min(p_mem_buf_desc->sz_data - m_sz_transport_header,
                            (size_t)m_n_sysvar_rx_prefetch_bytes));

    return p_mem_buf_desc;
}

int cq_mgr_rx_strq::poll_and_process_element_rx(uint64_t *p_cq_poll_sn, void *pv_fd_ready_array)
{
    cq_logfuncall("");

    if (unlikely(m_n_sysvar_cq_poll_batch_max <= process_recv_queue(pv_fd_ready_array))) {
        m_p_ring->m_gro_mgr.flush_all(pv_fd_ready_array);
        return false; // CQ was not drained.
    }

    if (m_n_sysvar_rx_prefetch_bytes_before_poll && m_rx_hot_buffer) {
        prefetch_range((uint8_t *)m_rx_hot_buffer->p_buffer + _current_wqe_consumed_bytes,
                       m_n_sysvar_rx_prefetch_bytes_before_poll);
    }

    buff_status_e status = BS_OK;
    uint32_t rx_polled = 0;
    while (rx_polled < m_n_sysvar_cq_poll_batch_max) {
        mem_buf_desc_t *buff = nullptr;
        mem_buf_desc_t *buff_wqe = poll(status, buff);

        if (buff_wqe && (++m_debt >= (int)m_n_sysvar_rx_num_wr_to_post_recv)) {
            compensate_qp_poll_failed(); // Reuse this method as success.
        }

        if (buff) {
            ++rx_polled;
            if (cqe_process_rx(buff, status)) {
                process_recv_buffer(buff, pv_fd_ready_array);
            }
        } else if (!buff_wqe) {
            break;
        }
    }

    update_global_sn_rx(*p_cq_poll_sn, rx_polled);

    if (likely(rx_polled > 0)) {
        m_p_ring->m_gro_mgr.flush_all(pv_fd_ready_array);
        return static_cast<int>(m_n_sysvar_cq_poll_batch_max - rx_polled);
    }

    compensate_qp_poll_failed();
    return -1;
}

void cq_mgr_rx_strq::add_hqrx(hw_queue_rx *hqrx)
{
    cq_logfunc("");
    _hot_buffer_stride = nullptr;
    _current_wqe_consumed_bytes = 0U;
    cq_mgr_rx::add_hqrx(hqrx);
}

void cq_mgr_rx_strq::statistics_print()
{
    cq_mgr_rx::statistics_print();
    cq_logdbg_no_funcname("RWQE consumed: %12" PRIu64, m_p_cq_stat->n_rx_consumed_rwqe_count);
    cq_logdbg_no_funcname("Packets count: %12" PRIu64, m_p_cq_stat->n_rx_packet_count);
    cq_logdbg_no_funcname("Max Strides per Packet: %12" PRIu16,
                          m_p_cq_stat->n_rx_max_stirde_per_packet);
    cq_logdbg_no_funcname("Strides count: %12" PRIu64, m_p_cq_stat->n_rx_stride_count);
    cq_logdbg_no_funcname("LRO packet count: %12" PRIu64, m_p_cq_stat->n_rx_lro_packets);
    cq_logdbg_no_funcname("LRO bytes: %12" PRIu64, m_p_cq_stat->n_rx_lro_bytes);
}

void cq_mgr_rx_strq::reclaim_recv_buffer_helper(mem_buf_desc_t *buff)
{
    if (buff->dec_ref_count() <= 1 && (buff->lwip_pbuf.ref-- <= 1)) {
        if (likely(buff->p_desc_owner == m_p_ring)) {
            mem_buf_desc_t *temp = nullptr;
            while (buff) {
                if (unlikely(buff->lwip_pbuf.desc.attr != PBUF_DESC_STRIDE)) {
                    __log_info_err("CQ STRQ reclaim_recv_buffer_helper with incompatible "
                                   "mem_buf_desc_t object");
                    // We cannot continue iterating over a broken buffer object.
                    break;
                }

                mem_buf_desc_t *rwqe =
                    reinterpret_cast<mem_buf_desc_t *>(buff->lwip_pbuf.desc.mdesc);
                if (buff->rx.strides_num == rwqe->add_ref_count(-buff->rx.strides_num)) {
                    // Is last stride.
                    cq_mgr_rx::reclaim_recv_buffer_helper(rwqe);
                }

                VLIST_DEBUG_CQ_MGR_PRINT_ERROR_IS_MEMBER;
                temp = buff;
                assert(temp->lwip_pbuf.type != PBUF_ZEROCOPY);
                buff = temp->p_next_desc;
                temp->clear_transport_data();
                temp->p_next_desc = nullptr;
                temp->p_prev_desc = nullptr;
                temp->reset_ref_count();
                free_lwip_pbuf(&temp->lwip_pbuf);
                return_stride(temp);
            }

            m_p_cq_stat->n_buffer_pool_len = m_rx_pool.size();
        } else {
            cq_logfunc("Stride returned to wrong CQ");
            g_buffer_pool_rx_ptr->put_buffers_thread_safe(buff);
        }
    }
}

#endif /* DEFINED_DIRECT_VERBS */
