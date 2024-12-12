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

#ifndef HW_QUEUE_TX_DOCA_H
#define HW_QUEUE_TX_DOCA_H

#include "config.h"
#ifndef DEFINED_DPCP_PATH_TX
#include <list>
#include "dev/xlio_ti.h"
#include "proto/mem_buf_desc.h"
#include "proto/xlio_lwip.h"
#include "util/cached_obj_pool.h"
#include "dev/dm_mgr.h"
#include <doca_eth_txq.h>
#include <doca_pe.h>
#include <doca_buf_inventory.h>
#include <doca_mmap.h>
#include <doca_ctx.h>
#include <doca_eth_txq_cpu_data_path.h>

// DOCA LSO user data
struct doca_lso_metadata {
    struct doca_gather_list headers;
    union {
        mem_buf_desc_t *buff;
        doca_lso_metadata *next;
    };
};

typedef cached_obj_pool<doca_lso_metadata> lso_metadata_pool;
extern lso_metadata_pool *g_lso_metadata_pool;
struct slave_data_t;
struct xlio_tls_info;
class ring_simple;

// @class hw_queue_tx
// Object to manages the SQ operations. This object is used for Tx.
// Once created it requests from the system a CQ to work with.
class hw_queue_tx : public xlio_ti_owner {
    friend class ring_simple;

public:
    hw_queue_tx(ring_simple *ring, const slave_data_t *slave);
    virtual ~hw_queue_tx();

    void up();
    void down();
    int modify_qp_ratelimit(struct xlio_rate_limit_t &, uint32_t) { return -1; }
    void dm_release_data(mem_buf_desc_t *) {}
    uint32_t is_ratelimit_change(struct xlio_rate_limit_t &) { return 0;}
    void ti_released(xlio_ti *) override {} // Dummy
    doca_notification_handle_t get_notification_handle() const { return m_notification_handle; }
    uint32_t send_doca_single(void *ptr, uint32_t len, mem_buf_desc_t *user_data);
    uint32_t send_doca_lso(struct iovec &h, struct pbuf *p, uint16_t mss, bool is_zerocopy);
    void poll_and_process_doca_tx();
    bool request_notification();
    void clear_notification();
    void put_lso_metadata(doca_lso_metadata *lso_metadata);

private:
    static void destory_doca_txq(doca_eth_txq *txq);
    static void destory_doca_inventory(doca_buf_inventory *inv);
    static void destory_doca_pe(doca_pe *pe);
    static void tx_task_completion_cb(doca_eth_txq_task_send *task_send, doca_data task_user_data,
                                      doca_data ctx_user_data);
    static void tx_task_error_cb(doca_eth_txq_task_send *task_send, doca_data task_user_data,
                                 doca_data ctx_user_data);
    static void tx_task_lso_completion_cb(doca_eth_txq_task_lso_send *task_send,
                                          doca_data task_user_data, doca_data ctx_user_data);
    static void tx_task_lso_error_cb(doca_eth_txq_task_lso_send *task_send,
                                     doca_data task_user_data, doca_data ctx_user_data);
    void return_doca_task(doca_eth_txq_task_send *task_send);
    void return_doca_lso_task(doca_eth_txq_task_lso_send *lso_task);
    void return_doca_buf(doca_buf *buf);
    bool prepare_doca_txq();
    bool expand_doca_inventory();
    bool expand_doca_task_pool(bool is_lso);
    void start_doca_txq();
    void stop_doca_txq();
    bool check_doca_caps(doca_devinfo *devinfo, uint32_t &max_burst_size, uint32_t &max_send_sge);
    doca_lso_metadata *get_lso_metadata();

    std::unique_ptr<doca_eth_txq, decltype(&destory_doca_txq)> m_doca_txq {nullptr,
                                                                           destory_doca_txq};
    std::unique_ptr<doca_buf_inventory, decltype(&destory_doca_inventory)> m_doca_inventory {
        nullptr, destory_doca_inventory};
    std::unique_ptr<doca_pe, decltype(&destory_doca_pe)> m_doca_pe {nullptr, destory_doca_pe};
    doca_mmap *m_doca_mmap = nullptr;
    doca_ctx *m_doca_ctx_txq = nullptr;
    doca_notification_handle_t m_notification_handle;
    uint32_t m_task_list_count = 0;
    uint8_t m_doca_max_sge = 0U;
    bool m_notification_armed = false;
    doca_lso_metadata *m_p_doca_lso_metadata_list = nullptr;
    hw_queue_tx_stats_t m_hwq_tx_stats;
    ring_simple *m_p_ring;
    ib_ctx_handler *m_p_ib_ctx_handler;
};

#endif // !DEFINED_DPCP_PATH_TX
#endif // HW_QUEUE_TX_DOCA_H