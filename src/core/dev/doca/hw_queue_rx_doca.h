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

#ifndef HW_QUEUE_RX_DOCA_H
#define HW_QUEUE_RX_DOCA_H

#include "config.h"
#ifndef DEFINED_DPCP_PATH_RX
#include "dev/dpcp/xlio_ti.h"
#include "dev/ib_ctx_handler.h"
#include "dev/rfs_rule.h"
#include "proto/mem_buf_desc.h"
#include <doca_eth_rxq.h>
#include <doca_pe.h>
#include <doca_buf_inventory.h>
#include <doca_mmap.h>
#include <doca_ctx.h>
#include <doca_eth_rxq_cpu_data_path.h>

struct doca_flow_match;
class ring_simple;

// @class hw_queue_rx
// This objects represents DOCA HW RX queue
class hw_queue_rx {
    friend class ring_simple;

public:
    virtual ~hw_queue_rx();

    void up();
    void down();
    uint16_t get_vlan() const { return m_vlan; }
    void modify_moderation(uint16_t period_usec, uint16_t comp_count);

    void update_gro_stats(uint64_t gro_frags, uint64_t gro_bytes)
    {
        m_hwq_rx_stats.n_rx_gro_packets++;
        m_hwq_rx_stats.n_rx_gro_frags += gro_frags;
        m_hwq_rx_stats.n_rx_gro_bytes += gro_bytes;
    }

    hw_queue_rx(ring_simple *ring, ib_ctx_handler *ib_ctx, uint16_t vlan);
    bool poll_and_process_rx();
    void reclaim_rx_buffer_chain(mem_buf_desc_t *buff_chain);
    void reclaim_rx_buffer_chain_queue(descq_t *buff_list);
    bool request_notification();
    void clear_notification();
    doca_notification_handle_t get_notification_handle() const { return m_notification_handle; }

    rfs_rule *create_rfs_rule(doca_flow_match &match_val, doca_flow_match &match_msk,
                              uint16_t priority, uint32_t flow_tag);

private:
    static void destroy_doca_rxq(doca_eth_rxq *rxq);
    static void destroy_doca_inventory(doca_buf_inventory *inv);
    static void destroy_doca_pe(doca_pe *pe);

    static void rx_task_completion_cb(doca_eth_rxq_task_recv *task_recv, doca_data task_user_data,
                                      doca_data ctx_user_data);

    static void rx_task_error_cb(doca_eth_rxq_task_recv *task_recv, doca_data task_user_data,
                                 doca_data ctx_user_data);

    void update_rx_buffer_pool_len_stats()
    {
        m_hwq_rx_stats.n_rx_buffer_pool_len = static_cast<uint32_t>(m_rx_pool.size());
    }

    void return_extra_buffers();
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
    void process_recv_buffer(mem_buf_desc_t *p_mem_buf_desc);

    std::unique_ptr<doca_eth_rxq, decltype(&destroy_doca_rxq)> m_doca_rxq {nullptr,
                                                                           destroy_doca_rxq};
    std::unique_ptr<doca_buf_inventory, decltype(&destroy_doca_inventory)> m_doca_inventory {
        nullptr, destroy_doca_inventory};
    std::unique_ptr<doca_pe, decltype(&destroy_doca_pe)> m_doca_pe {nullptr, destroy_doca_pe};

    doca_mmap *m_doca_mmap = nullptr;
    doca_ctx *m_doca_ctx_rxq = nullptr;
    mem_buf_desc_t *m_polled_buf = nullptr;
    uint32_t m_rxq_task_debt = 0U;
    uint32_t m_rx_debt_submit_treshold = 0U;
    uint32_t m_rxq_burst_size = 0U;
    doca_notification_handle_t m_notification_handle;
    uint16_t m_doca_rx_queue_id = 0U;
    uint16_t m_vlan;
    descq_t m_rx_pool;
    hw_queue_rx_stats_t m_hwq_rx_stats;
    uint32_t m_rx_buff_pool_treshold_max = 0U;
    uint32_t m_rx_buff_pool_treshold_min = 0U;
    ring_simple *m_p_ring;
    ib_ctx_handler *m_p_ib_ctx_handler;
    bool m_notification_armed = false;
};

#endif // !DEFINED_DPCP_PATH_RX
#endif // HW_QUEUE_RX_DOCA_H
