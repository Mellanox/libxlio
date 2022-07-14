/*
 * Copyright (c) 2001-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include "qp_mgr_eth_mlx5_dpcp.h"

#if defined(DEFINED_DPCP)

#include <cinttypes>
#include "ring_simple.h"
#include "rfs_rule_dpcp.h"
#include "cq_mgr_mlx5_strq.h"

#define MODULE_NAME "qp_mgr_eth_mlx5_dpcp"

qp_mgr_eth_mlx5_dpcp::qp_mgr_eth_mlx5_dpcp(struct qp_mgr_desc *desc, uint32_t tx_num_wr,
                                           uint16_t vlan)
    : qp_mgr_eth_mlx5(desc, tx_num_wr, vlan, false)
{
    if (configure(desc)) {
        throw_vma_exception("Failed creating qp_mgr_eth_mlx5_dpcp");
    }

    if (!configure_rq_dpcp()) {
        throw_vma_exception("Failed to create qp_mgr_eth_mlx5_dpcp");
    }
}

bool qp_mgr_eth_mlx5_dpcp::configure_rq_dpcp()
{
    qp_logdbg("Creating RQ of transport type '%s' on ibv device '%s' [%p] on port %d",
              priv_vma_transport_type_str(m_p_ring->get_transport_type()),
              m_p_ib_ctx_handler->get_ibname(), m_p_ib_ctx_handler->get_ibv_device(), m_port_num);

    m_qp_cap.max_recv_wr = m_rx_num_wr;

    qp_logdbg("Requested RQ parameters: wre: rx = %d sge: rx = %d", m_qp_cap.max_recv_wr,
              m_qp_cap.max_recv_sge);

    vma_ib_mlx5_cq_t mlx5_cq;
    memset(&mlx5_cq, 0, sizeof(mlx5_cq));
    vma_ib_mlx5_get_cq(m_p_cq_mgr_rx->get_ibv_cq_hndl(), &mlx5_cq);

    qp_logdbg("Configuring dpcp RQ, cq-rx: %p, cqn-rx: %u", m_p_cq_mgr_rx,
              static_cast<unsigned int>(mlx5_cq.cq_num));

    if (safe_mce_sys().enable_striding_rq) {
        m_qp_cap.max_recv_sge = 2U; // Striding-RQ needs a reserved segment.
        _strq_wqe_reserved_seg = 1U;

        delete[] m_ibv_rx_sg_array;
        m_ibv_rx_sg_array = new ibv_sge[m_n_sysvar_rx_num_wr_to_post_recv * m_qp_cap.max_recv_sge];
        for (uint32_t wr_idx = 0; wr_idx < m_n_sysvar_rx_num_wr_to_post_recv; wr_idx++) {
            m_ibv_rx_wr_array[wr_idx].sg_list = &m_ibv_rx_sg_array[wr_idx * m_qp_cap.max_recv_sge];
            m_ibv_rx_wr_array[wr_idx].num_sge = m_qp_cap.max_recv_sge;
            memset(m_ibv_rx_wr_array[wr_idx].sg_list, 0, sizeof(ibv_sge));
            m_ibv_rx_wr_array[wr_idx].sg_list[0].length =
                1U; // To bypass a check inside vma_ib_mlx5_post_recv.
        }
    }

    // Create the QP
    if (!prepare_rq(mlx5_cq.cq_num)) {
        return false;
    }

    return true;
}

bool qp_mgr_eth_mlx5_dpcp::prepare_rq(uint32_t cqn)
{
    qp_logdbg("");

    dpcp::adapter *dpcp_adapter = m_p_ib_ctx_handler->get_dpcp_adapter();
    if (!dpcp_adapter) {
        qp_logerr("Failed to get dpcp::adapter for prepare_rq");
        return false;
    }

    // user_index Unused.
    dpcp::rq_attr rqattrs;
    memset(&rqattrs, 0, sizeof(rqattrs));
    rqattrs.cqn = cqn;
    rqattrs.wqe_num = m_qp_cap.max_recv_wr;
    rqattrs.wqe_sz = m_qp_cap.max_recv_sge;

    std::unique_ptr<dpcp::basic_rq> new_rq;
    dpcp::status rc = dpcp::DPCP_OK;

    if (safe_mce_sys().enable_striding_rq) {
        rqattrs.buf_stride_sz = safe_mce_sys().strq_stride_size_bytes;
        rqattrs.buf_stride_num = safe_mce_sys().strq_stride_num_per_rwqe;

        // Striding-RQ WQE format is as of Shared-RQ (PRM, page 381, wq_type).
        // In this case the WQE minimum size is 2 * 16, and the first segment is reserved.
        rqattrs.wqe_sz = m_qp_cap.max_recv_sge * 16U;

        dpcp::striding_rq *new_rq_ptr = nullptr;
        rc = dpcp_adapter->create_striding_rq(rqattrs, new_rq_ptr);
        new_rq.reset(new_rq_ptr);
    } else {
        dpcp::regular_rq *new_rq_ptr = nullptr;
        rc = dpcp_adapter->create_regular_rq(rqattrs, new_rq_ptr);
        new_rq.reset(new_rq_ptr);
    }

    if (dpcp::DPCP_OK != rc) {
        qp_logerr("Failed to create dpcp rq, rc: %d, cqn: %" PRIu32, static_cast<int>(rc), cqn);
        return false;
    }

    memset(&m_mlx5_qp, 0, sizeof(m_mlx5_qp));
    if (!store_rq_mlx5_params(*new_rq)) {
        qp_logerr(
            "Failed to retrieve initial DPCP RQ parameters, rc: %d, basic_rq: %p, cqn: %" PRIu32,
            static_cast<int>(rc), new_rq.get(), cqn);
        return false;
    }

    _rq = std::move(new_rq);

    // At this stage there is no TIR associated with the RQ, So it mimics QP INIT state.
    // At RDY state without a TIR, Work Requests can be submitted to the RQ.
    modify_rq_to_ready_state();

    qp_logdbg("Succeeded to create dpcp rq, rqn: %" PRIu32 ", cqn: %" PRIu32, m_mlx5_qp.rqn, cqn);

    return true;
}

bool qp_mgr_eth_mlx5_dpcp::store_rq_mlx5_params(dpcp::basic_rq &new_rq)
{
    uint32_t *dbrec_tmp = nullptr;
    dpcp::status rc = new_rq.get_dbrec(dbrec_tmp);
    if (dpcp::DPCP_OK != rc) {
        qp_logerr("Failed to retrieve dbrec of dpcp rq, rc: %d, basic_rq: %p", static_cast<int>(rc),
                  &new_rq);
        return false;
    }
    m_mlx5_qp.rq.dbrec = dbrec_tmp;

    rc = new_rq.get_wq_buf(m_mlx5_qp.rq.buf);
    if (dpcp::DPCP_OK != rc) {
        qp_logerr("Failed to retrieve wq-buf of dpcp rq, rc: %d, basic_rq: %p",
                  static_cast<int>(rc), &new_rq);
        return false;
    }

    rc = new_rq.get_id(m_mlx5_qp.rqn);
    if (dpcp::DPCP_OK != rc) {
        qp_logerr("Failed to retrieve rqn of dpcp rq, rc: %d, basic_rq: %p", static_cast<int>(rc),
                  &new_rq);
        return false;
    }

    new_rq.get_wqe_num(m_mlx5_qp.rq.wqe_cnt);
    new_rq.get_wq_stride_sz(m_mlx5_qp.rq.stride);
    if (safe_mce_sys().enable_striding_rq) {
        m_mlx5_qp.rq.stride /= 16U;
    }

    m_mlx5_qp.rq.wqe_shift = ilog_2(m_mlx5_qp.rq.stride);
    m_mlx5_qp.rq.head = 0;
    m_mlx5_qp.rq.tail = 0;
    m_mlx5_qp.cap.max_recv_wr = m_qp_cap.max_recv_wr;
    m_mlx5_qp.cap.max_recv_sge = m_qp_cap.max_recv_sge;
    m_mlx5_qp.tirn = 0U;

    return true;
}

void qp_mgr_eth_mlx5_dpcp::init_tir_rq()
{
    if (_rq && !store_rq_mlx5_params(*_rq)) {
        qp_logpanic("Failed to retrieve DPCP RQ parameters (errno=%d %m)", errno);
    }

    _tir.reset(create_tir());
    if (!_tir) {
        qp_logpanic("TIR creation for qp_mgr_eth_mlx5_dpcp failed (errno=%d %m)", errno);
    }
}

void qp_mgr_eth_mlx5_dpcp::up()
{
    qp_mgr_eth_mlx5::init_qp();
    init_tir_rq();
    qp_mgr::up();
    init_device_memory();
}

void qp_mgr_eth_mlx5_dpcp::down()
{
    _tir.reset(nullptr);

    qp_mgr_eth_mlx5::down();
}

rfs_rule *qp_mgr_eth_mlx5_dpcp::create_rfs_rule(vma_ibv_flow_attr &attrs, xlio_tir *tir_ext)
{
    // TODO Remove copypaste.
#ifdef DEFINED_UTLS
    if (tir_ext && m_p_ib_ctx_handler && m_p_ib_ctx_handler->get_dpcp_adapter()) {
        std::unique_ptr<rfs_rule_dpcp> new_rule(new rfs_rule_dpcp());
        if (new_rule->create(attrs, *xlio_tir_to_dpcp_tir(tir_ext),
                             *m_p_ib_ctx_handler->get_dpcp_adapter())) {
            return new_rule.release();
        }
    } else
#endif /* DEFINED_UTLS */
        if (_tir && m_p_ib_ctx_handler && m_p_ib_ctx_handler->get_dpcp_adapter()) {
        std::unique_ptr<rfs_rule_dpcp> new_rule(new rfs_rule_dpcp());
        if (new_rule->create(attrs, *_tir, *m_p_ib_ctx_handler->get_dpcp_adapter())) {
            return new_rule.release();
        }
    }

    NOT_IN_USE(tir_ext);
    return nullptr;
}

void qp_mgr_eth_mlx5_dpcp::modify_qp_to_ready_state()
{
    qp_mgr_eth_mlx5::modify_qp_to_ready_state();
    modify_rq_to_ready_state();
}

void qp_mgr_eth_mlx5_dpcp::modify_qp_to_error_state()
{
    m_p_cq_mgr_rx->clean_cq();

    qp_mgr_eth_mlx5::modify_qp_to_error_state();

    dpcp::status rc = _rq->modify_state(dpcp::RQ_ERR);

    /* During plugout theres is possibility that kernel
     * remove device resources before working process complete
     * removing process. As a result ibv api function can
     * return EIO=5 errno code.
     */
    if (dpcp::DPCP_OK != rc && errno != EIO) {
        qp_logerr("Failed to modify rq state to ERR, rc: %d, rqn: %" PRIu32, static_cast<int>(rc),
                  m_mlx5_qp.rqn);
    }
}

void qp_mgr_eth_mlx5_dpcp::modify_rq_to_ready_state()
{
    dpcp::status rc = _rq->modify_state(dpcp::RQ_RDY);
    if (dpcp::DPCP_OK != rc) {
        qp_logerr("Failed to modify rq state to RDY, rc: %d, rqn: %" PRIu32, static_cast<int>(rc),
                  m_mlx5_qp.rqn);
    }
}

cq_mgr *qp_mgr_eth_mlx5_dpcp::init_rx_cq_mgr(struct ibv_comp_channel *p_rx_comp_event_channel)
{
    if (unlikely(!safe_mce_sys().enable_striding_rq)) {
        return qp_mgr_eth_mlx5::init_rx_cq_mgr(p_rx_comp_event_channel);
    }

    return (!init_rx_cq_mgr_prepare()
                ? nullptr
                : new cq_mgr_mlx5_strq(m_p_ring, m_p_ib_ctx_handler,
                                       safe_mce_sys().strq_stride_num_per_rwqe * m_rx_num_wr,
                                       safe_mce_sys().strq_stride_size_bytes,
                                       safe_mce_sys().strq_stride_num_per_rwqe,
                                       p_rx_comp_event_channel, true));
}

void qp_mgr_eth_mlx5_dpcp::post_recv_buffer(mem_buf_desc_t *p_mem_buf_desc)
{
    uint32_t index = (m_curr_rx_wr * m_qp_cap.max_recv_sge) + _strq_wqe_reserved_seg;
    m_ibv_rx_sg_array[index].addr = (uintptr_t)p_mem_buf_desc->p_buffer;
    m_ibv_rx_sg_array[index].length = p_mem_buf_desc->sz_buffer;
    m_ibv_rx_sg_array[index].lkey = p_mem_buf_desc->lkey;

    post_recv_buffer_rq(p_mem_buf_desc);
}

dpcp::tir *qp_mgr_eth_mlx5_dpcp::create_tir(bool is_tls /*=false*/)
{
    dpcp::tir *tir_obj = nullptr;
    dpcp::status status = dpcp::DPCP_OK;
    dpcp::tir::attr tir_attr;

    memset(&tir_attr, 0, sizeof(tir_attr));
    tir_attr.flags = dpcp::TIR_ATTR_INLINE_RQN | dpcp::TIR_ATTR_TRANSPORT_DOMAIN;
    tir_attr.inline_rqn = m_mlx5_qp.rqn;
    tir_attr.transport_domain = m_p_ib_ctx_handler->get_dpcp_adapter()->get_td();

    if (m_p_ring->m_lro.cap && m_p_ring->m_lro.max_payload_sz) {
        tir_attr.flags |= dpcp::TIR_ATTR_LRO;
        tir_attr.lro.timeout_period_usecs = VMA_MLX5_PARAMS_LRO_TIMEOUT;
        tir_attr.lro.enable_mask = 3; // Bitmask for IPv4 and IPv6 support
        tir_attr.lro.max_msg_sz = m_p_ring->m_lro.max_payload_sz >> 8;
    }

    if (is_tls) {
        tir_attr.flags |= dpcp::TIR_ATTR_TLS;
        tir_attr.tls_en = 1;
    }

    status = m_p_ib_ctx_handler->get_dpcp_adapter()->create_tir(tir_attr, tir_obj);

    if (dpcp::DPCP_OK != status) {
        qp_logerr("Failed creating dpcp tir with flags=0x%x status=%d", tir_attr.flags, status);
        return nullptr;
    }

    qp_logdbg("TIR: %p created", tir_obj);

    return tir_obj;
}

#endif // defined(DEFINED_DPCP)
