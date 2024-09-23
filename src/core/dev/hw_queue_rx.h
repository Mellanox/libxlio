/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-3-Clause
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

#ifndef HW_QUEUE_RX_H
#define HW_QUEUE_RX_H

#include <vector>
#include "dev/xlio_ti.h"
#include "dev/ib_ctx_handler.h"
#include "dev/rfs_rule.h"
#include "dev/cq_mgr_rx.h"
#include "proto/mem_buf_desc.h"
#include "util/sg_array.h"

class ring_simple;

// @class hw_queue_rx
// Object to manages the SQ operations. This object is used for Rx.
// Once created it requests from the system a CQ to work with.
class hw_queue_rx : public xlio_ti_owner {
    friend class cq_mgr_rx;
    friend class cq_mgr_rx_regrq;
    friend class cq_mgr_rx_strq;

public:
    hw_queue_rx(ring_simple *ring, ib_ctx_handler *ib_ctx, ibv_comp_channel *rx_comp_event_channel,
                uint16_t vlan);
    virtual ~hw_queue_rx();

    virtual void ti_released(xlio_ti *ti) override;

    void up();
    void down();

    // Post for receive single mem_buf_desc
    void post_recv_buffer(mem_buf_desc_t *p_mem_buf_desc);

    // Post for receive a list of mem_buf_desc
    void post_recv_buffers(descq_t *p_buffers, size_t count);

    cq_mgr_rx *get_rx_cq_mgr() const { return m_p_cq_mgr_rx; }
    uint32_t get_rx_max_wr_num() const { return m_rx_num_wr; }
    uint16_t get_vlan() const { return m_vlan; };
    void modify_queue_to_ready_state();
    void modify_queue_to_error_state();
    void release_rx_buffers();

    rfs_rule *create_rfs_rule(dpcp::match_params &match_value, dpcp::match_params &match_mask,
                              uint16_t priority, uint32_t flow_tag, xlio_tir *tir_ext);

#ifdef DEFINED_UTLS
    xlio_tir *tls_create_tir(bool cached);
    void tls_release_tir(xlio_tir *tir);
#endif /* DEFINED_UTLS */

private:
    cq_mgr_rx *init_rx_cq_mgr(struct ibv_comp_channel *p_rx_comp_event_channel);

    bool init_rx_cq_mgr_prepare();
    void post_recv_buffer_rq(mem_buf_desc_t *p_mem_buf_desc);
    void put_tls_tir_in_cache(xlio_tir *tir);
    bool prepare_rq(uint32_t cqn);
    bool configure_rq(ibv_comp_channel *rx_comp_event_channel);
    bool store_rq_mlx5_params(dpcp::basic_rq &new_rq);
    int xlio_raw_post_recv(struct ibv_recv_wr **bad_wr);
    bool is_rq_empty() const { return (m_rq_data.head == m_rq_data.tail); }

    dpcp::tir *create_tir(bool is_tls = false);
    dpcp::tir *xlio_tir_to_dpcp_tir(xlio_tir *tir) { return tir->m_p_tir.get(); }

    struct {
        volatile uint32_t *dbrec;
        void *buf;
        uint32_t wqe_cnt;
        uint32_t stride;
        uint32_t wqe_shift;
        uint32_t rqn;
        unsigned head;
        unsigned tail;
    } m_rq_data;

    std::vector<xlio_tir *> m_tls_tir_cache;
    std::unique_ptr<dpcp::tir> m_tir = {nullptr};
    std::unique_ptr<dpcp::basic_rq> m_rq = {nullptr};
    ring_simple *m_p_ring;
    cq_mgr_rx *m_p_cq_mgr_rx = nullptr;
    ib_ctx_handler *m_p_ib_ctx_handler;
    ibv_sge *m_ibv_rx_sg_array;
    ibv_recv_wr *m_ibv_rx_wr_array;
    uintptr_t m_last_posted_rx_wr_id = 0U; // Remember so in case we flush RQ we know to wait until
                                           // this WR_ID is received
    mem_buf_desc_t *m_p_prev_rx_desc_pushed = nullptr;
    uint64_t *m_rq_wqe_idx_to_wrid = nullptr;
    uint64_t m_rq_wqe_counter = 0U;
    uint32_t m_curr_rx_wr = 0U;
    uint32_t m_strq_wqe_reserved_seg = 0U;
    uint32_t m_n_sysvar_rx_num_wr_to_post_recv;
    uint32_t m_rx_num_wr;
    uint32_t m_rx_sge = 1U;
    const uint32_t m_n_sysvar_rx_prefetch_bytes_before_poll;
    uint16_t m_vlan;
};

#endif // HW_QUEUE_RX_H
