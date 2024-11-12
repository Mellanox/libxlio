/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include <doca_eth_rxq.h>
#include <doca_pe.h>
#include <doca_buf_inventory.h>
#include <doca_mmap.h>
#include <doca_ctx.h>
#include <doca_eth_rxq_cpu_data_path.h>
#include "dev/xlio_ti.h"
#include "dev/ib_ctx_handler.h"
#include "dev/rfs_rule.h"
#include "dev/cq_mgr_rx.h"
#include "proto/mem_buf_desc.h"
#include "util/sg_array.h"

class ring_simple;
struct doca_flow_match;

// @class hw_queue_rx
// Object to manages the SQ operations. This object is used for Rx.
// Once created it requests from the system a CQ to work with.
class hw_queue_rx : public xlio_ti_owner {
    friend class cq_mgr_rx;
    friend class cq_mgr_rx_regrq;
    friend class cq_mgr_rx_strq;
    friend class ring_simple;

public:
    hw_queue_rx(ring_simple *ring, ib_ctx_handler *ib_ctx, ibv_comp_channel *rx_comp_event_channel,
                uint16_t vlan);
    virtual ~hw_queue_rx();

    virtual void ti_released(xlio_ti *ti) override;

    void up();
    void down();

    bool poll_and_process_rx();
    void reclaim_rx_buffer_chain(mem_buf_desc_t *buff_chain);
    void reclaim_rx_buffer_chain_queue(descq_t *buff_list);
    bool request_notification();
    void clear_notification();
    doca_notification_handle_t get_notification_handle() const { return m_notification_handle; }

    // Post for receive single mem_buf_desc
    void post_recv_buffer(mem_buf_desc_t *p_mem_buf_desc);

    // Post for receive a list of mem_buf_desc
    void post_recv_buffers(descq_t *p_buffers, size_t count);

    cq_mgr_rx *get_rx_cq_mgr() const { return m_p_cq_mgr_rx; }
    uint32_t get_rx_max_wr_num() const { return m_rx_num_wr; }
    uint16_t get_vlan() const { return m_vlan; };

    void update_gro_stats(uint64_t gro_frags, uint64_t gro_bytes)
    {
        m_hwq_rx_stats.n_rx_gro_packets++;
        m_hwq_rx_stats.n_rx_gro_frags += gro_frags;
        m_hwq_rx_stats.n_rx_gro_bytes += gro_bytes;
    }

    void modify_queue_to_ready_state();
    void modify_queue_to_error_state();
    void release_rx_buffers();
    void modify_moderation(uint16_t period_usec, uint16_t comp_count);

    rfs_rule *create_rfs_rule(doca_flow_match &match_val, doca_flow_match &match_msk,
                              dpcp::match_params &match_value, dpcp::match_params &match_mask,
                              uint16_t priority, uint32_t flow_tag, xlio_tir *tir_ext);

#ifdef DEFINED_UTLS
    xlio_tir *tls_create_tir(bool cached);
    void tls_release_tir(xlio_tir *tir);
#endif /* DEFINED_UTLS */

private:
    static void destory_doca_rxq(doca_eth_rxq *rxq);
    static void destory_doca_inventory(doca_buf_inventory *inv);
    static void destory_doca_pe(doca_pe *pe);

    static void rx_task_completion_cb(doca_eth_rxq_task_recv *task_recv, doca_data task_user_data,
                                      doca_data ctx_user_data);

    static void rx_task_error_cb(doca_eth_rxq_task_recv *task_recv, doca_data task_user_data,
                                 doca_data ctx_user_data);

    bool prepare_doca_rxq();
    void submit_rxq_tasks();
    bool submit_rxq_task(uint32_t task_flag);
    bool fill_buffers_from_global_pool();
    void return_doca_buf(doca_buf *buf);
    void start_doca_rxq();
    void stop_doca_rxq();
    void return_doca_task(doca_eth_rxq_task_recv *task_recv);
    void reclaim_rx_buffer_chain_loop(mem_buf_desc_t *buff);
    void post_reclaim_fill();
    void return_extra_buffers();
    void process_recv_buffer(mem_buf_desc_t *p_mem_buf_desc);

    cq_mgr_rx *init_rx_cq_mgr(struct ibv_comp_channel *p_rx_comp_event_channel);

    void post_recv_buffer_rq(mem_buf_desc_t *p_mem_buf_desc);
    void put_tls_tir_in_cache(xlio_tir *tir);
    bool prepare_rq(uint32_t cqn);
    bool configure_rq(ibv_comp_channel *rx_comp_event_channel);
    bool store_rq_mlx5_params(dpcp::basic_rq &new_rq);
    int xlio_raw_post_recv(struct ibv_recv_wr **bad_wr);
    bool is_rq_empty() const { return (m_rq_data.head == m_rq_data.tail); }

    void update_rx_buffer_pool_len_stats()
    {
        m_hwq_rx_stats.n_rx_buffer_pool_len = static_cast<uint32_t>(m_rx_pool.size());
    }

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
    std::unique_ptr<dpcp::tir> m_tir {nullptr};
    std::unique_ptr<dpcp::basic_rq> m_rq {nullptr};

    std::unique_ptr<doca_eth_rxq, decltype(&destory_doca_rxq)> m_doca_rxq {nullptr,
                                                                           destory_doca_rxq};
    std::unique_ptr<doca_buf_inventory, decltype(&destory_doca_inventory)> m_doca_inventory {
        nullptr, destory_doca_inventory};
    std::unique_ptr<doca_pe, decltype(&destory_doca_pe)> m_doca_pe {nullptr, destory_doca_pe};

    doca_mmap *m_doca_mmap = nullptr;
    doca_ctx *m_doca_ctx_rxq = nullptr;
    descq_t m_rx_pool;
    mem_buf_desc_t *m_polled_buf = nullptr;
    uint32_t m_rxq_task_debt = 0U;
    uint32_t m_rx_debt_submit_treshold = 0U;
    hw_queue_rx_stats_t m_hwq_rx_stats;
    uint32_t m_rxq_burst_size = 0U;
    uint32_t m_rx_buff_pool_treshold_max = 0U;
    uint32_t m_rx_buff_pool_treshold_min = 0U;
    doca_notification_handle_t m_notification_handle;
    ring_simple *m_p_ring;
    bool m_notification_armed = false;

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
    uint16_t m_doca_rx_queue_id = 0U;
};

#endif // HW_QUEUE_RX_H
