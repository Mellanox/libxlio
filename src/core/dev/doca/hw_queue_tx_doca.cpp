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

#include <time.h>
#include "dev/doca/hw_queue_tx_doca.h"
#include "dev/ring_simple.h"
#include <cinttypes>
#include <sock/sock-app.h>
#include <doca_buf.h>

#undef MODULE_NAME
#define MODULE_NAME "hw_queue_tx_doca"
DOCA_LOG_REGISTER(hw_queue_tx);

#define hwqtx_logpanic   __log_info_panic
#define hwqtx_logerr     __log_info_err
#define hwqtx_logwarn    __log_info_warn
#define hwqtx_loginfo    __log_info_info
#define hwqtx_logdbg     __log_info_dbg
#define hwqtx_logfunc    __log_info_func
#define hwqtx_logfuncall __log_info_funcall

#define DOCA_EXPAND_BATCH_SIZE     (1024)
#define DOCA_MAX_LSO_HEADER        (64)
#define DOCA_CHECKSUM_HW_L3_ENABLE (1)
#define DOCA_CHECKSUM_HW_L4_ENABLE (1)
#define DOCA_MAX_SGE_WITHOUT_TSO   (1)

lso_metadata_pool *g_lso_metadata_pool = nullptr;

hw_queue_tx::hw_queue_tx(ring_simple *ring, const slave_data_t *slave)
    : m_doca_mmap(g_buffer_pool_tx->get_doca_mmap())
    , m_p_ring(ring)
    , m_p_ib_ctx_handler(slave->p_ib_ctx)
{
    hwqtx_logfunc(LOG_FUNCTION_CALL);

    memset(&m_hwq_tx_stats, 0, sizeof(m_hwq_tx_stats));

    if (!prepare_doca_txq()) {
        throw_xlio_exception("Failed to create DOCA TXQ");
    }
}

hw_queue_tx::~hw_queue_tx()
{
    hwqtx_logfunc(LOG_FUNCTION_CALL);

    m_doca_txq.reset(nullptr); // Must be destroyed before TX PE.

    if (m_p_doca_lso_metadata_list) {
        g_lso_metadata_pool->put_objs(m_p_doca_lso_metadata_list);
    }

    hwqtx_logdbg("Destructor hw_queue_tx end");
}

bool hw_queue_tx::check_doca_caps(doca_devinfo *devinfo, uint32_t &max_burst_size,
                                  uint32_t &max_send_sge)
{
    doca_error_t err = doca_eth_txq_cap_is_type_supported(devinfo, DOCA_ETH_TXQ_TYPE_REGULAR,
                                                          DOCA_ETH_TXQ_DATA_PATH_TYPE_CPU);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_eth_txq_cap_is_type_supported");
        return false;
    }

    err = doca_eth_txq_cap_get_max_send_buf_list_len(devinfo, &max_send_sge);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_eth_txq_cap_get_max_send_buf_list_len");
        return false;
    }

    err = doca_eth_txq_cap_get_max_burst_size(devinfo, max_send_sge, DOCA_MAX_LSO_HEADER,
                                              &max_burst_size);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_eth_txq_cap_get_max_burst_size");
        return false;
    }

    uint32_t txq_burst_size_conf = (align32pow2(safe_mce_sys().tx_num_wr));
    if (txq_burst_size_conf > max_burst_size) {
        // TODO: Currently we will always have this warning... tx_num_wr set to 32K.
        hwqtx_loginfo("Decreasing BurstSize %u to capability %u.", txq_burst_size_conf,
                      max_burst_size);
        txq_burst_size_conf = max_burst_size;
    }
    max_burst_size = txq_burst_size_conf;

    err = doca_eth_txq_cap_is_l3_chksum_offload_supported(devinfo);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_eth_txq_cap_is_l3_chksum_offload_supported");
        return false;
    }

    err = doca_eth_txq_cap_is_l4_chksum_offload_supported(devinfo);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_eth_txq_cap_is_l4_chksum_offload_supported");
        return false;
    }

    return true;
}

bool hw_queue_tx::prepare_doca_txq()
{
    doca_error_t err;
    doca_dev *dev = m_p_ib_ctx_handler->get_ctx_doca_dev().get_doca_device();
    doca_devinfo *devinfo = doca_dev_as_devinfo(dev);
    uint32_t max_burst_size = 0U;
    uint32_t max_send_sge = 0U;

    if (!check_doca_caps(devinfo, max_burst_size, max_send_sge)) {
        hwqtx_logerr("TXQ caps failed, Dev:%s", m_p_ib_ctx_handler->get_ibname().c_str());
        return false;
    }

    doca_eth_txq *txq = nullptr;
    err = doca_eth_txq_create(dev, max_burst_size, &txq);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_eth_txq_create");
        return false;
    }
    m_doca_txq.reset(txq);
    m_doca_ctx_txq = doca_eth_txq_as_doca_ctx(m_doca_txq.get());

    err = doca_eth_txq_set_max_send_buf_list_len(txq, max_send_sge);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_eth_txq_set_max_send_buf_list_len");
        return false;
    }

    /*  Issues with mss configuration per txq:
        1. LSO will not work if remote side decided to reduce MSS.
        2. We reduce mss to allow LSO for both IPv4 and IPv6. It means IPv4 packets will be smaller
       by 20 bytes, so the performance will be slightly worse than what we can get with bigger
       packets.
    */
    // err = doca_eth_txq_set_mss(m_doca_txq.get(), m_p_ring->get_mtu() - IPV6_HLEN - TCP_HLEN);
    err = doca_eth_txq_set_mss(m_doca_txq.get(), m_p_ring->get_mtu() - 20 - TCP_HLEN);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_eth_txq_set_mss");
        return false;
    }

    err = doca_eth_txq_set_max_lso_header_size(m_doca_txq.get(), DOCA_MAX_LSO_HEADER);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_eth_txq_set_max_lso_header_size");
        return false;
    }

    err = doca_ctx_set_user_data(m_doca_ctx_txq, {.ptr = this});
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_ctx_set_user_data ctx/hw_queue_tx: %p,%p",
                       m_doca_ctx_txq, this);
        return false;
    }

    err = doca_eth_txq_set_type(m_doca_txq.get(), DOCA_ETH_TXQ_TYPE_REGULAR);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_eth_txq_get_type_supported");
        return false;
    }

    err = doca_eth_txq_task_send_set_conf(m_doca_txq.get(), tx_task_completion_cb, tx_task_error_cb,
                                          max_burst_size);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_eth_txq_task_send_set_conf txq: %p max-tasks: %u",
                       txq, max_burst_size);
        return false;
    }

    err = doca_eth_txq_task_lso_send_set_conf(m_doca_txq.get(), tx_task_lso_completion_cb,
                                              tx_task_lso_error_cb, max_burst_size);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err,
                       "doca_eth_txq_task_lso_send_set_conf txq: %p max-tasks: %u",
                       m_doca_txq.get(), max_burst_size);
        return false;
    }

    m_task_list_count = max_burst_size;

    err = doca_eth_txq_set_l3_chksum_offload(txq, DOCA_CHECKSUM_HW_L3_ENABLE);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_eth_txq_set_l3_chksum_offload txq: %p",
                       m_doca_txq.get());
        return false;
    }

    err = doca_eth_txq_set_l4_chksum_offload(txq, DOCA_CHECKSUM_HW_L4_ENABLE);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_eth_txq_set_l4_chksum_offload txq: %p",
                       m_doca_txq.get());
        return false;
    }

    doca_pe *pe;
    err = doca_pe_create(&pe);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_pe_create");
        return false;
    }
    m_doca_pe.reset(pe);

    err = doca_pe_connect_ctx(pe, m_doca_ctx_txq);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_pe_connect_ctx pe/ctx/txq: %p,%p,%p", pe,
                       m_doca_ctx_txq, m_doca_txq.get());
        return false;
    }

    err = doca_pe_set_event_mode(pe, DOCA_PE_EVENT_MODE_PROGRESS_ALL);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_pe_set_event_mode pe: %p", pe);
        return false;
    }

    err = doca_pe_get_notification_handle(pe, &m_notification_handle);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_pe_get_notification_handle");
        return false;
    }

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    if (safe_mce_sys().app.distribute_cq_interrupts) {
        uint32_t num_comp_vectors = 0;
        err = doca_ctx_cap_get_num_completion_vectors(devinfo, &num_comp_vectors);
        if (DOCA_IS_ERROR(err)) {
            PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_ctx_cap_get_num_completion_vectors devinfo: %p",
                           devinfo);
            return false;
        }

        // fetching once - as this operation requires locking
        const int worker_id = g_p_app->get_worker_id();
        if (likely(worker_id >= 0)) {
            const uint32_t comp_vector = worker_id % num_comp_vectors;
            hwqtx_logdbg("Setting PE completion affinity: %" PRIu32 ", pid: %d", comp_vector,
                         getpid());
            err = doca_ctx_set_completion_vector(m_doca_ctx_txq, comp_vector);
            if (DOCA_IS_ERROR(err)) {
                PRINT_DOCA_ERR(hwqtx_logerr, err,
                               "doca_ctx_set_completion_vector ctx/comp_vector: %p,%" PRIu32,
                               m_doca_ctx_txq, comp_vector);
            }
        }
    }
#endif

    doca_buf_inventory *inventory = nullptr;
    err = doca_buf_inventory_create(max_burst_size, &inventory);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_buf_inventory_create");
        return false;
    }
    m_doca_inventory.reset(inventory);

    err = doca_buf_inventory_start(inventory);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_buf_inventory_start");
        return false;
    }

    hwqtx_loginfo("Creating DOCA TXQ MaxBurstSize: %u, Dev:%s", max_burst_size,
                  m_p_ib_ctx_handler->get_ibname().c_str());
    return true;
}

void hw_queue_tx::start_doca_txq()
{
    doca_error_t err = doca_ctx_start(m_doca_ctx_txq);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_ctx_start(TXQ). TXQ:%p", m_doca_txq.get());
        return;
    }

    hwqtx_loginfo("DOCA TXQ started, ctx: %p", m_doca_ctx_txq);
}

void hw_queue_tx::stop_doca_txq()
{
    hwqtx_logdbg("Stopping DOCA TXQ: %p", m_doca_txq.get());

    doca_error_t err = doca_ctx_stop(m_doca_ctx_txq);
    if (DOCA_ERROR_IN_PROGRESS == err) {
        doca_ctx_states ctx_state = DOCA_CTX_STATE_STOPPING; // Just to enter the while loop.
        while (DOCA_CTX_STATE_IDLE != ctx_state) {
            if (!doca_pe_progress(m_doca_pe.get())) {
                err = doca_ctx_get_state(m_doca_ctx_txq, &ctx_state);
                if (err != DOCA_SUCCESS) {
                    PRINT_DOCA_ERR(hwqtx_logerr, err,
                                   "Error flushing DOCA TXQ (doca_ctx_get_state). TXQ:%p",
                                   m_doca_txq.get());
                    break;
                }
            }
        }
    } else if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_ctx_stop(TXQ). TXQ:%p", m_doca_txq.get());
    }
}

void hw_queue_tx::up()
{
    start_doca_txq();
}

void hw_queue_tx::down()
{
    stop_doca_txq();
}

void hw_queue_tx::destroy_doca_txq(doca_eth_txq *txq)
{
    doca_error_t err = doca_eth_txq_destroy(txq);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(__log_err, err, "doca_eth_txq_destroy txq: %p", txq);
    }
}

void hw_queue_tx::destroy_doca_inventory(doca_buf_inventory *inv)
{
    doca_error_t err = doca_buf_inventory_destroy(inv);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(__log_err, err, "doca_buf_inventory_destroy Inv: %p", inv);
    }
}

void hw_queue_tx::destroy_doca_pe(doca_pe *pe)
{
    doca_error_t err = doca_pe_destroy(pe);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(__log_err, err, "doca_pe_destroy PE: %p", pe);
    }
}

void hw_queue_tx::tx_task_completion_cb(doca_eth_txq_task_send *task_send, doca_data task_user_data,
                                        doca_data ctx_user_data)
{
    mem_buf_desc_t *mem_buf = reinterpret_cast<mem_buf_desc_t *>(task_user_data.ptr);
    hw_queue_tx *hw_tx = reinterpret_cast<hw_queue_tx *>(ctx_user_data.ptr);

    hw_tx->return_doca_task(task_send);
    hw_tx->m_p_ring->put_tx_buffer_helper(mem_buf);
}

void hw_queue_tx::tx_task_lso_completion_cb(doca_eth_txq_task_lso_send *lso_task,
                                            doca_data task_user_data, doca_data ctx_user_data)
{
    doca_lso_metadata *lso_metadata = reinterpret_cast<doca_lso_metadata *>(task_user_data.ptr);
    hw_queue_tx *hw_tx = reinterpret_cast<hw_queue_tx *>(ctx_user_data.ptr);

    hw_tx->return_doca_lso_task(lso_task);
    hw_tx->m_p_ring->put_tx_buffer_helper(lso_metadata->buff);
    hw_tx->put_lso_metadata(lso_metadata);
}

void hw_queue_tx::tx_task_error_cb(doca_eth_txq_task_send *task_send, doca_data task_user_data,
                                   doca_data ctx_user_data)
{
    mem_buf_desc_t *mem_buf = reinterpret_cast<mem_buf_desc_t *>(task_user_data.ptr);
    hw_queue_tx *hw_tx = reinterpret_cast<hw_queue_tx *>(ctx_user_data.ptr);
    doca_ctx_states ctx_state = DOCA_CTX_STATE_STOPPING;
    doca_error_t rc_state = doca_ctx_get_state(hw_tx->m_doca_ctx_txq, &ctx_state);
    ctx_state = ((ctx_state != DOCA_CTX_STATE_IDLE) ? ctx_state : DOCA_CTX_STATE_STOPPING);
    if (rc_state != DOCA_SUCCESS || ctx_state != DOCA_CTX_STATE_STOPPING) {
        PRINT_DOCA_ERR(__log_err,
                       doca_task_get_status(doca_eth_txq_task_send_as_doca_task(task_send)),
                       "TX Task Error");
        // TODO DOCA: Add statistics for errors
    }

    hw_tx->return_doca_task(task_send);
    hw_tx->m_p_ring->put_tx_buffer_helper(mem_buf);
}

void hw_queue_tx::tx_task_lso_error_cb(doca_eth_txq_task_lso_send *lso_task,
                                       doca_data task_user_data, doca_data ctx_user_data)
{
    doca_lso_metadata *lso_metadata = reinterpret_cast<doca_lso_metadata *>(task_user_data.ptr);
    hw_queue_tx *hw_tx = reinterpret_cast<hw_queue_tx *>(ctx_user_data.ptr);
    doca_ctx_states ctx_state = DOCA_CTX_STATE_STOPPING;
    doca_error_t rc_state = doca_ctx_get_state(hw_tx->m_doca_ctx_txq, &ctx_state);
    ctx_state = ((ctx_state != DOCA_CTX_STATE_IDLE) ? ctx_state : DOCA_CTX_STATE_STOPPING);
    if (rc_state != DOCA_SUCCESS || ctx_state != DOCA_CTX_STATE_STOPPING) {
        PRINT_DOCA_ERR(__log_err,
                       doca_task_get_status(doca_eth_txq_task_lso_send_as_doca_task(lso_task)),
                       "TX Task Error");
        // TODO DOCA: Add statistics for errors
    }

    __log_func("tx_task_lso_error_cb, lso_task: %p, rc_state: %d, ctx_state: %d", lso_task,
               rc_state, ctx_state);

    hw_tx->return_doca_lso_task(lso_task);
    hw_tx->m_p_ring->put_tx_buffer_helper(lso_metadata->buff);
    hw_tx->put_lso_metadata(lso_metadata);
}

void hw_queue_tx::return_doca_task(doca_eth_txq_task_send *task_send)
{
    doca_buf *buf = nullptr;
    doca_error_t err = doca_eth_txq_task_send_get_pkt(task_send, &buf);
    if (unlikely(DOCA_IS_ERROR(err))) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_eth_txq_task_send_get_pkt");
    } else {
        return_doca_buf(buf);
    }

    doca_task_free(doca_eth_txq_task_send_as_doca_task(task_send));
}

void hw_queue_tx::return_doca_lso_task(doca_eth_txq_task_lso_send *lso_task)
{
    doca_buf *buf = nullptr;
    doca_error_t err = doca_eth_txq_task_lso_send_get_pkt_payload(lso_task, &buf);
    if (unlikely(DOCA_IS_ERROR(err))) {
        PRINT_DOCA_ERR(hwqtx_logerr, err, "doca_eth_txq_task_lso_send_get_pkt_payload");
    } else {
        return_doca_buf(buf);
    }

    doca_task_free(doca_eth_txq_task_lso_send_as_doca_task(lso_task));
}

void hw_queue_tx::return_doca_buf(doca_buf *buf)
{
    doca_error_t rc_state = doca_buf_dec_refcount(buf, nullptr);
    if (unlikely(rc_state != DOCA_SUCCESS)) {
        PRINT_DOCA_ERR(hwqtx_logerr, rc_state, "doca_buf_dec_refcount");
    }
}

bool hw_queue_tx::expand_doca_inventory()
{
    doca_error_t rc = doca_buf_inventory_expand(m_doca_inventory.get(), DOCA_EXPAND_BATCH_SIZE);
    if (DOCA_IS_ERROR(rc)) {
        PRINT_DOCA_ERR(hwqtx_logerr, rc, "doca_buf_inventory_expand");
        return false;
    }
    return true;
}

bool hw_queue_tx::expand_doca_task_pool(bool is_lso)
{
    if (m_task_list_count >= safe_mce_sys().tx_queue_max_elements) {
        hwqtx_logfunc("Silent packet drop, can't expand task pool");
        return false;
    }

    doca_error_t rc;
    doca_eth_txq *txq = m_doca_txq.get();
    if (is_lso) {
        rc = doca_eth_txq_task_lso_send_num_expand(txq, DOCA_EXPAND_BATCH_SIZE);
    } else {
        rc = doca_eth_txq_task_send_num_expand(txq, DOCA_EXPAND_BATCH_SIZE);
    }

    if (DOCA_IS_ERROR(rc)) {
        PRINT_DOCA_ERR(hwqtx_logerr, rc, "DOCA expand task pool (LSO=%d) failed", is_lso);
        return false;
    }

    m_task_list_count += DOCA_EXPAND_BATCH_SIZE;
    return true;
}

doca_lso_metadata *hw_queue_tx::get_lso_metadata()
{
    if (unlikely(!m_p_doca_lso_metadata_list)) {
        m_p_doca_lso_metadata_list = g_lso_metadata_pool->get_objs(safe_mce_sys().lso_pool_batch);
        if (unlikely(!m_p_doca_lso_metadata_list)) {
            return nullptr;
        }
    }
    doca_lso_metadata *ret = m_p_doca_lso_metadata_list;
    m_p_doca_lso_metadata_list = m_p_doca_lso_metadata_list->next;
    return ret;
}

void hw_queue_tx::put_lso_metadata(doca_lso_metadata *lso_metadata)
{
    lso_metadata->next = m_p_doca_lso_metadata_list;
    m_p_doca_lso_metadata_list = lso_metadata;
}

bool hw_queue_tx::request_notification()
{
    if (likely(!m_notification_armed)) {
        doca_error_t rc = doca_pe_request_notification(m_doca_pe.get());
        if (unlikely(DOCA_IS_ERROR(rc))) {
            PRINT_DOCA_ERR(hwqtx_logerr, rc, "doca_pe_request_notification");
            return false;
        }

        ++m_hwq_tx_stats.n_tx_interrupt_requests;
    }

    m_notification_armed = true;
    return true;
}

void hw_queue_tx::clear_notification()
{
    if (m_notification_armed) {
        m_notification_armed = false;
        doca_error_t rc = doca_pe_clear_notification(m_doca_pe.get(), m_notification_handle);
        if (unlikely(DOCA_IS_ERROR(rc))) {
            PRINT_DOCA_ERR(hwqtx_logerr, rc, "doca_pe_clear_notification");
        } else {
            ++m_hwq_tx_stats.n_tx_interrupt_received;
        }
    } else {
        hwqtx_logwarn("Clear notification attempt on unarmed PE. hw_queue_tx: %p", this);
    }
}

/*
    1. doca_buf_inventory_buf_get_by_data
    2. doca task allocation
    3. doca_task_submit
    In case step 1 and 2 fail - we try to expand inventory/task pool and retry.
*/
uint32_t hw_queue_tx::send_doca_single(void *ptr, uint32_t len, mem_buf_desc_t *user_data)
{
    doca_eth_txq_task_send *task = nullptr;
    doca_buf *tx_doca_buf = nullptr;

get_buf:
    doca_error_t rc = doca_buf_inventory_buf_get_by_data(m_doca_inventory.get(), m_doca_mmap, ptr,
                                                         len, &tx_doca_buf);
    if (DOCA_IS_ERROR(rc)) {
        if ((DOCA_ERROR_NO_MEMORY == rc) && expand_doca_inventory()) {
            goto get_buf;
        }
        PRINT_DOCA_ERR(hwqtx_loginfo, rc, "doca_buf_inventory_buf_get_by_data");
        return 0;
    }

get_task:
    rc = doca_eth_txq_task_send_allocate_init(m_doca_txq.get(), tx_doca_buf, {.ptr = user_data},
                                              &task);
    if (DOCA_IS_ERROR(rc)) {
        if ((DOCA_ERROR_NO_MEMORY == rc) && expand_doca_task_pool(false)) {
            goto get_task;
        }
        return_doca_buf(tx_doca_buf);
        PRINT_DOCA_ERR(hwqtx_loginfo, rc, "doca_eth_txq_task_send_allocate_init");
        return 0;
    }

    rc = doca_task_submit(doca_eth_txq_task_send_as_doca_task(task));
    if (DOCA_IS_ERROR(rc)) {
        return_doca_task(task);
        PRINT_DOCA_ERR(hwqtx_logerr, rc, "doca_eth_txq_task_send_as_doca_task");
        return 0;
    }

    ++m_hwq_tx_stats.n_tx_pkt_count;
    m_hwq_tx_stats.n_tx_byte_count += len;
    return len;
}

uint32_t hw_queue_tx::send_doca_lso(struct iovec &h, struct pbuf *p, uint16_t mss, bool is_zerocopy)
{
    struct doca_eth_txq_task_lso_send *task = nullptr;
    doca_buf *tx_doca_buf = nullptr;

    doca_lso_metadata *lso_metadata = get_lso_metadata();
    if (!lso_metadata) {
        hwqtx_logwarn("Couldn't get LSO metadata object.");
        return 0;
    }

    struct doca_mmap *mmap = (PBUF_DESC_MDESC == p->desc.attr)
        ? reinterpret_cast<mapping_t *>(p->desc.mdesc)->get_doca_mmap()
        : m_doca_mmap;

    /*  In case of non-zc - p->payload points to TCP header. In LSO we should split between headers
     * and payload, therefore we move payload pointer after TCP header and reduce length of first
     * doca pbuf.
     */
    void *first_pkt = (uint8_t *)p->payload + (is_zerocopy ? 0 : TCP_HLEN);
    uint32_t first_pkt_len = p->len - (is_zerocopy ? 0 : TCP_HLEN);

get_first_buf:
    doca_error_t rc = doca_buf_inventory_buf_get_by_data(m_doca_inventory.get(), mmap, first_pkt,
                                                         first_pkt_len, &tx_doca_buf);
    if (DOCA_IS_ERROR(rc)) {
        if ((DOCA_ERROR_NO_MEMORY == rc) && expand_doca_inventory()) {
            goto get_first_buf;
        }
        PRINT_DOCA_ERR(hwqtx_logerr, rc, "doca_buf_inventory_buf_get_by_data");
        return 0;
    }

    uint32_t len_sent = h.iov_len + first_pkt_len + (p->next ? p->next->tot_len : 0);

    lso_metadata->headers.addr = h.iov_base;
    lso_metadata->headers.len = h.iov_len;
    lso_metadata->headers.next = nullptr;
    lso_metadata->buff = reinterpret_cast<mem_buf_desc_t *>(p);
    p = p->next;

    hwqtx_logfunc("LSO first part, len=%" PRIu32 ". LSO-Headers len=%" PRIu64, first_pkt_len,
                  lso_metadata->headers.len);

    doca_buf *prev_doca_buf = tx_doca_buf;
    doca_buf *next_doca_buf = nullptr;
    while (p) {
        mmap = (PBUF_DESC_MDESC == p->desc.attr)
            ? reinterpret_cast<mapping_t *>(p->desc.mdesc)->get_doca_mmap()
            : m_doca_mmap;
        rc = doca_buf_inventory_buf_get_by_data(m_doca_inventory.get(), mmap, p->payload, p->len,
                                                &next_doca_buf);
        if (DOCA_IS_ERROR(rc)) {
            if ((DOCA_ERROR_NO_MEMORY == rc) && expand_doca_inventory()) {
                continue;
            }
            PRINT_DOCA_ERR(hwqtx_logerr, rc, "doca_buf_inventory_buf_get_by_data");
            return_doca_buf(tx_doca_buf);
            return 0;
        }

        hwqtx_logfunc("LSO part, len=%" PRIu32, p->len);

        doca_buf_chain_list_tail(tx_doca_buf, prev_doca_buf, next_doca_buf);
        prev_doca_buf = next_doca_buf;
        p = p->next;
    }

get_lso_task:
    rc = doca_eth_txq_task_lso_send_allocate_init(
        m_doca_txq.get(), tx_doca_buf, &lso_metadata->headers, {.ptr = lso_metadata}, &task);
    if (DOCA_IS_ERROR(rc)) {
        if ((DOCA_ERROR_NO_MEMORY == rc) && expand_doca_task_pool(true)) {
            goto get_lso_task;
        }
        PRINT_DOCA_ERR(hwqtx_logerr, rc, "doca_eth_txq_task_lso_send_allocate_init");
        return_doca_buf(tx_doca_buf);
        return 0;
    }

    hwqtx_logfunc("LSO Task, len_sent=%" PRIu32 ", mss=%" PRIu16, len_sent, mss);

    doca_eth_txq_task_lso_send_set_mss(task, mss);

    rc = doca_task_submit(doca_eth_txq_task_lso_send_as_doca_task(task));
    if (DOCA_IS_ERROR(rc)) {
        return_doca_lso_task(task);
        PRINT_DOCA_ERR(hwqtx_logerr, rc, "doca_task_submit");
        return 0;
    }

    ++m_hwq_tx_stats.n_tx_pkt_count;
    m_hwq_tx_stats.n_tx_byte_count += len_sent;
    ++m_hwq_tx_stats.n_tx_tso_pkt_count;
    m_hwq_tx_stats.n_tx_tso_byte_count += len_sent;
    return len_sent;
}

void hw_queue_tx::poll_and_process_doca_tx()
{
    while (doca_pe_progress(m_doca_pe.get())) {
        ;
    }

    m_p_ring->return_to_global_pool();
}
