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

#include "config.h"
#ifndef DEFINED_DPCP_PATH_RX
#include <algorithm>
#include <thread>
#include <cinttypes>
#include <sys/mman.h>
#include <sock/sock-app.h>
#include "dev/doca/hw_queue_rx_doca.h"
#include "dev/buffer_pool.h"
#include "dev/ring_simple.h"
#include "dev/rfs_rule.h"
#include <doca_buf.h>

#undef MODULE_NAME
#define MODULE_NAME "hw_queue_rx"
DOCA_LOG_REGISTER(hw_queue_rx);

#define hwqrx_logpanic   __log_info_panic
#define hwqrx_logerr     __log_info_err
#define hwqrx_logwarn    __log_info_warn
#define hwqrx_loginfo    __log_info_info
#define hwqrx_logdbg     __log_info_dbg
#define hwqrx_logfunc    __log_info_func
#define hwqrx_logfuncall __log_info_funcall

hw_queue_rx::hw_queue_rx(ring_simple *ring, ib_ctx_handler *ib_ctx, uint16_t vlan)
    : m_doca_mmap(g_buffer_pool_rx_rwqe->get_doca_mmap())
    , m_vlan(vlan)
    , m_p_ring(ring)
    , m_p_ib_ctx_handler(ib_ctx)
{
    hwqrx_logfunc(LOG_FUNCTION_CALL);

    memset(&m_hwq_rx_stats, 0, sizeof(m_hwq_rx_stats));

    if (!prepare_doca_rxq()) {
        throw_xlio_exception("Failed to create DOCA RXQ");
    }
}

hw_queue_rx::~hw_queue_rx()
{
    hwqrx_logfunc(LOG_FUNCTION_CALL);

    m_doca_rxq.reset(nullptr); // Must be destroyed before RX PE.

    g_buffer_pool_rx_rwqe->put_buffers_thread_safe(&m_rx_pool, m_rx_pool.size());

    hwqrx_logdbg("Rx buffer poll: %ld free global buffers available",
                 g_buffer_pool_rx_rwqe->get_free_count());
}

bool hw_queue_rx::prepare_doca_rxq()
{
    doca_dev *dev = m_p_ib_ctx_handler->get_ctx_doca_dev().get_doca_device();
    doca_devinfo *devinfo = doca_dev_as_devinfo(dev);

    doca_error_t type_supported = doca_eth_rxq_cap_is_type_supported(
        devinfo, DOCA_ETH_RXQ_TYPE_REGULAR, DOCA_ETH_RXQ_DATA_PATH_TYPE_CPU);

    uint32_t max_burst_size = 0U;
    uint32_t max_packet_size = 0U;
    doca_error_t err1 = doca_eth_rxq_cap_get_max_burst_size(devinfo, &max_burst_size);
    doca_error_t err2 = doca_eth_rxq_cap_get_max_packet_size(devinfo, &max_packet_size);

    if (DOCA_IS_ERROR(type_supported) || DOCA_IS_ERROR(err1) || DOCA_IS_ERROR(err2)) {
        PRINT_DOCA_ERR(hwqrx_logerr, type_supported, "doca_eth_rxq_cap_is_type_supported");
        PRINT_DOCA_ERR(hwqrx_logerr, err1, "doca_eth_rxq_cap_get_max_burst_size");
        PRINT_DOCA_ERR(hwqrx_logerr, err2, "doca_eth_rxq_cap_get_max_packet_size");
        return false;
    }

    hwqrx_loginfo("RXQ caps MaxBurstSize %u, MaxPacketSize %u, Dev:%s", max_burst_size,
                  max_packet_size, m_p_ib_ctx_handler->get_ibname().c_str());

    m_rxq_burst_size = (align32pow2(safe_mce_sys().rx_num_wr));
    if (m_rxq_burst_size > max_burst_size) {
        hwqrx_logwarn("Decreasing BurstSize %u to capability %u.", m_rxq_burst_size,
                      max_burst_size);
        m_rxq_burst_size = max_burst_size;
    }

    hwqrx_loginfo("Creating DOCA RXQ MaxBurstSize: %u, MaxPacketSize: %u, Dev:%s", m_rxq_burst_size,
                  max_packet_size, m_p_ib_ctx_handler->get_ibname().c_str());

    doca_eth_rxq *rxq = nullptr;
    // For DOCA_ETH_RXQ_TYPE_REGULAR the max_packet_size has no effect but cannot be 0.
    doca_error_t err = doca_eth_rxq_create(dev, m_rxq_burst_size, max_packet_size, &rxq);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqrx_logerr, err, "doca_eth_rxq_create");
        return false;
    }

    m_doca_rxq.reset(rxq);
    m_doca_ctx_rxq = doca_eth_rxq_as_doca_ctx(rxq);
    m_rxq_task_debt = m_rxq_burst_size;
    m_rx_buff_pool_treshold_max = m_rxq_burst_size * 2U;
    m_rx_buff_pool_treshold_min = m_rxq_burst_size;
    m_rx_debt_submit_treshold = m_rxq_burst_size / 2U;

    err = doca_ctx_set_user_data(m_doca_ctx_rxq, {.ptr = this});
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqrx_logerr, err, "doca_ctx_set_user_data ctx/hw_queue_rx: %p,%p",
                       m_doca_ctx_rxq, this);
        return false;
    }

    err = doca_eth_rxq_set_type(m_doca_rxq.get(), DOCA_ETH_RXQ_TYPE_REGULAR);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqrx_logerr, err, "doca_eth_rxq_get_type_supported");
        return false;
    }

    err = doca_eth_rxq_task_recv_set_conf(m_doca_rxq.get(), rx_task_completion_cb, rx_task_error_cb,
                                          m_rxq_burst_size);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqrx_logerr, err, "doca_eth_rxq_task_recv_set_conf rxq: %p max-tasks: %u",
                       m_doca_rxq.get(), m_rxq_burst_size);
        return false;
    }

    err = doca_eth_rxq_set_flow_tag(m_doca_rxq.get(), 1U);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqrx_logerr, err, "doca_eth_rxq_set_flow_tag");
        return false;
    }

    doca_pe *pe;
    err = doca_pe_create(&pe);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqrx_logerr, err, "doca_pe_create");
        return false;
    }

    m_doca_pe.reset(pe);

    err = doca_pe_connect_ctx(pe, m_doca_ctx_rxq);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqrx_logerr, err, "doca_pe_connect_ctx pe/ctx/rxq: %p,%p,%p", pe,
                       m_doca_ctx_rxq, m_doca_rxq.get());
        return false;
    }

    err = doca_pe_set_event_mode(pe, DOCA_PE_EVENT_MODE_PROGRESS_ALL);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqrx_logerr, err, "doca_pe_set_event_mode pe: %p", pe);
        return false;
    }

    err = doca_pe_get_notification_handle(pe, &m_notification_handle);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqrx_logerr, err, "doca_pe_get_notification_handle");
        return false;
    }

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    if (safe_mce_sys().app.distribute_cq_interrupts) {
        uint32_t num_comp_vectors = 0;
        err = doca_ctx_cap_get_num_completion_vectors(devinfo, &num_comp_vectors);
        if (DOCA_IS_ERROR(err)) {
            PRINT_DOCA_ERR(hwqrx_logerr, err, "doca_ctx_cap_get_num_completion_vectors devinfo: %p",
                           devinfo);
            return false;
        }

        // fetching once - as this operation requires locking
        const int worker_id = g_p_app->get_worker_id();
        if (likely(worker_id >= 0)) {
            const uint32_t comp_vector = worker_id % num_comp_vectors;
            hwqrx_logdbg("Setting PE completion affinity: %" PRIu32 ", pid: %d", comp_vector,
                         getpid());
            err = doca_ctx_set_completion_vector(m_doca_ctx_rxq, comp_vector);
            if (DOCA_IS_ERROR(err)) {
                PRINT_DOCA_ERR(hwqrx_logerr, err,
                               "doca_ctx_set_completion_vector ctx/comp_vector: %p,%" PRIu32,
                               m_doca_ctx_rxq, comp_vector);
            }
        }
    }
#endif

    doca_buf_inventory *inventory = nullptr;
    err = doca_buf_inventory_create(m_rxq_burst_size, &inventory);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqrx_logerr, err, "doca_buf_inventory_create");
        return false;
    }

    m_doca_inventory.reset(inventory);

    err = doca_buf_inventory_start(inventory);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqrx_logerr, err, "doca_buf_inventory_start");
        return false;
    }

    hwqrx_logdbg("Created DOCA RXQ and PE %p/%p", m_doca_rxq.get(), m_doca_pe.get());
    return true;
}

void hw_queue_rx::submit_rxq_tasks()
{
    fill_buffers_from_global_pool();

    size_t batch_size = std::min(static_cast<size_t>(m_rxq_task_debt), m_rx_pool.size());
    if (batch_size > 0) {
        while (--batch_size > 0) {
            if (unlikely(!submit_rxq_task(DOCA_TASK_SUBMIT_FLAG_NONE))) {
                break;
            }
        }

        submit_rxq_task(DOCA_TASK_SUBMIT_FLAG_FLUSH);
        update_rx_buffer_pool_len_stats();
    }
}

bool hw_queue_rx::submit_rxq_task(uint32_t task_flag)
{
    doca_eth_rxq_task_recv *rx_doca_task = nullptr;
    doca_buf *rx_doca_buf = nullptr;
    mem_buf_desc_t *buff = m_rx_pool.front();
    doca_error_t rc = doca_buf_inventory_buf_get_by_addr(
        m_doca_inventory.get(), m_doca_mmap, buff->p_buffer, buff->sz_buffer, &rx_doca_buf);
    if (DOCA_IS_ERROR(rc)) {
        PRINT_DOCA_ERR(hwqrx_logerr, rc, "doca_buf_inventory_buf_get_by_data");
        return false;
    }

    rc = doca_eth_rxq_task_recv_allocate_init(m_doca_rxq.get(), rx_doca_buf, {.ptr = buff},
                                              &rx_doca_task);
    if (DOCA_IS_ERROR(rc)) {
        return_doca_buf(rx_doca_buf);
        PRINT_DOCA_ERR(hwqrx_logerr, rc, "doca_eth_rxq_task_recv_allocate_init");
        return false;
    }

    --m_rxq_task_debt; // Must be set before return_doca_task()
    rc = doca_task_submit_ex(doca_eth_rxq_task_recv_as_doca_task(rx_doca_task), task_flag);
    if (DOCA_IS_ERROR(rc)) {
        return_doca_task(rx_doca_task);
        PRINT_DOCA_ERR(hwqrx_logerr, rc, "doca_eth_rxq_task_recv_as_doca_task");
        return false;
    }

    buff->clear_transport_data();
    m_rx_pool.pop_front();
    return true;
}

bool hw_queue_rx::fill_buffers_from_global_pool()
{
    size_t more_bufs =
        (m_rxq_task_debt > m_rx_pool.size() ? m_rxq_task_debt - m_rx_pool.size() : 0U);

    if (more_bufs) {
        hwqrx_logfunc("Allocating additional %ld buffers for internal use", more_bufs);

        // Assume locked!
        // Add an additional free buffer descs to RX cq mgr
        if (!g_buffer_pool_rx_rwqe->get_buffers_thread_safe(m_rx_pool, m_p_ring, more_bufs, 0)) {
            return false;
        }
    }

    update_rx_buffer_pool_len_stats();
    return true;
}

void hw_queue_rx::return_doca_buf(doca_buf *buf)
{
    doca_error_t rc_state = doca_buf_dec_refcount(buf, nullptr);
    if (unlikely(rc_state != DOCA_SUCCESS)) {
        PRINT_DOCA_ERR(hwqrx_logerr, rc_state, "doca_buf_dec_refcount");
    }
}

/*void hw_queue_rx::callback_rxq_state_changed(
    const union doca_data user_data, struct doca_ctx *ctx,
    enum doca_ctx_states prev_state,  enum doca_ctx_states next_state)
{
    hw_queue_rx *hw_rxq = reinterpret_cast<hw_queue_rx *>(user_data.ptr);
    if (DOCA_CTX_STATE_IDLE == next_state) {
        hw_rxq-
    }
}*/

void hw_queue_rx::start_doca_rxq()
{
    hwqrx_logdbg("Starting DOCA RXQ: %p pid: %d", m_doca_rxq.get(), getpid());

    if (!m_p_ib_ctx_handler->get_ctx_doca_dev().get_doca_flow_port()) {
        hwqrx_logerr("modify_queue_to_ready_state unable to get DOCA flow port, RXQ: %p", this);
    }

    doca_error_t err = doca_ctx_start(m_doca_ctx_rxq);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqrx_logerr, err, "doca_ctx_start(RXQ). RXQ:%p", m_doca_rxq.get());
    }

    hwqrx_loginfo("DOCA RXQ started, ctx: %p", m_doca_ctx_rxq);

    err = doca_eth_rxq_get_flow_queue_id(m_doca_rxq.get(), &m_doca_rx_queue_id);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqrx_logerr, err, "doca_eth_rxq_get_flow_queue_id. RXQ:%p",
                       m_doca_rxq.get());
    }

    submit_rxq_tasks();
}

void hw_queue_rx::stop_doca_rxq()
{
    hwqrx_logdbg("Stopping DOCA RXQ: %p", m_doca_rxq.get());

    doca_error_t err = doca_ctx_stop(m_doca_ctx_rxq);
    if (DOCA_ERROR_IN_PROGRESS == err) {
        doca_ctx_states ctx_state = DOCA_CTX_STATE_STOPPING; // Just to enter the while loop.
        while (DOCA_CTX_STATE_IDLE != ctx_state) {
            if (!doca_pe_progress(m_doca_pe.get())) {
                err = doca_ctx_get_state(m_doca_ctx_rxq, &ctx_state);
                if (err != DOCA_SUCCESS) {
                    PRINT_DOCA_ERR(hwqrx_logerr, err,
                                   "Error flushing DOCA RXQ (doca_ctx_get_state). RXQ:%p",
                                   m_doca_rxq.get());
                    break;
                }
            }
        }
    } else if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(hwqrx_logerr, err, "doca_ctx_stop(RXQ). RXQ:%p", m_doca_rxq.get());
    }
}

void hw_queue_rx::destroy_doca_rxq(doca_eth_rxq *rxq)
{
    doca_error_t err = doca_eth_rxq_destroy(rxq);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(__log_err, err, "doca_eth_rxq_destroy rxq: %p", rxq);
    }
}

void hw_queue_rx::destroy_doca_inventory(doca_buf_inventory *inv)
{
    doca_error_t err = doca_buf_inventory_destroy(inv);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(__log_err, err, "doca_buf_inventory_destroy Inv: %p", inv);
    }
}

void hw_queue_rx::destroy_doca_pe(doca_pe *pe)
{
    doca_error_t err = doca_pe_destroy(pe);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(__log_err, err, "doca_pe_destroy PE: %p", pe);
    }
}

void hw_queue_rx::return_doca_task(doca_eth_rxq_task_recv *task_recv)
{
    doca_buf *buf = nullptr;
    doca_error_t err = doca_eth_rxq_task_recv_get_pkt(task_recv, &buf);
    if (unlikely(DOCA_IS_ERROR(err))) {
        PRINT_DOCA_ERR(hwqrx_logerr, err, "doca_eth_rxq_task_recv_get_pkt");
    } else {
        return_doca_buf(buf);
    }

    doca_task_free(doca_eth_rxq_task_recv_as_doca_task(task_recv));
    ++m_rxq_task_debt;
}

void hw_queue_rx::reclaim_rx_buffer_chain_loop(mem_buf_desc_t *buff)
{
    // TODO DOCA: Remove usage of lwip_pbuf.ref for RX
    if (buff->dec_ref_count() <= 1 && (buff->lwip_pbuf.ref-- <= 1)) {
        mem_buf_desc_t *temp = nullptr;
        while (buff) {
            buff->p_desc_owner = m_p_ring; // In case socket switched rings.
            temp = buff;
            assert(temp->lwip_pbuf.type != PBUF_ZEROCOPY);
            buff = temp->p_next_desc;
            temp->p_next_desc = nullptr;
            temp->p_prev_desc = nullptr;
            temp->reset_ref_count();
            free_lwip_pbuf(&temp->lwip_pbuf);
            m_rx_pool.push_front(temp);
        }
        update_rx_buffer_pool_len_stats();
    } else if (buff->lwip_pbuf.ref != (unsigned int)buff->get_ref_count()) {
        hwqrx_logwarn("Uneven lwip.ref and buf.ref %u,%d", buff->lwip_pbuf.ref,
                      buff->get_ref_count());
    }
}

void hw_queue_rx::reclaim_rx_buffer_chain(mem_buf_desc_t *buff_chain)
{
    reclaim_rx_buffer_chain_loop(buff_chain);
    post_reclaim_fill();
}

void hw_queue_rx::reclaim_rx_buffer_chain_queue(descq_t *buff_list)
{
    while (!buff_list->empty()) {
        reclaim_rx_buffer_chain_loop(buff_list->get_and_pop_front());
    }

    post_reclaim_fill();
}

void hw_queue_rx::post_reclaim_fill()
{
    if (unlikely(m_rxq_task_debt > m_rx_debt_submit_treshold)) {
        submit_rxq_tasks();
    }

    return_extra_buffers();
}

void hw_queue_rx::return_extra_buffers()
{
    // Use integers for percents calculations to avoid floating point operations.
    if (unlikely(m_rx_pool.size() > m_rx_buff_pool_treshold_max)) {
        size_t return_buffs_num = m_rx_pool.size() - m_rx_buff_pool_treshold_min;

        hwqrx_logfunc("Returning %zu buffers to global RX pool", return_buffs_num);
        g_buffer_pool_rx_rwqe->put_buffers_thread_safe(&m_rx_pool, return_buffs_num);
        update_rx_buffer_pool_len_stats();
    }
}

void hw_queue_rx::rx_task_completion_cb(doca_eth_rxq_task_recv *task_recv, doca_data task_user_data,
                                        doca_data ctx_user_data)
{
    mem_buf_desc_t *mem_buf = reinterpret_cast<mem_buf_desc_t *>(task_user_data.ptr);
    hw_queue_rx *hw_rx = reinterpret_cast<hw_queue_rx *>(ctx_user_data.ptr);
    doca_buf *buf = nullptr;
    doca_error_t rc = doca_eth_rxq_task_recv_get_pkt(task_recv, &buf);
    if (unlikely(DOCA_IS_ERROR(rc))) {
        PRINT_DOCA_ERR(__log_err, rc, "doca_eth_rxq_task_recv_get_pkt");
        rx_task_error_cb(task_recv, task_user_data, ctx_user_data);
        return;
    }

    uint8_t l3ok = 0U;
    uint8_t l4ok = 0U;
    uint32_t flow_tag = FLOW_TAG_MASK;
    rc = doca_buf_get_data_len(buf, &mem_buf->sz_data);
    doca_error_t rc3 = doca_eth_rxq_task_recv_get_l3_ok(task_recv, &l3ok);
    doca_error_t rc4 = doca_eth_rxq_task_recv_get_l4_ok(task_recv, &l4ok);
    doca_error_t rctag = doca_eth_rxq_task_recv_get_flow_tag(task_recv, &flow_tag);
    if (unlikely(DOCA_IS_ERROR(rc) || DOCA_IS_ERROR(rc3) || DOCA_IS_ERROR(rc4) ||
                 DOCA_IS_ERROR(rctag))) {
        __log_err("rx_task_completion_cb, task_recv: %p, buf: %p, rc/rc3/rc4/rctag: %d/%d/%d/%d",
                  task_recv, buf, static_cast<int>(rc), static_cast<int>(rc3),
                  static_cast<int>(rc4), static_cast<int>(rctag));
        rx_task_error_cb(task_recv, task_user_data, ctx_user_data);
        return;
    }

    mem_buf->rx.is_sw_csum_need = (l3ok == 0U || l4ok == 0);
    mem_buf->rx.flow_tag_id = flow_tag;

    hw_rx->return_doca_task(task_recv);
    hw_rx->m_polled_buf = mem_buf;

    __log_func("rx_task_completion_cb pid: %d. flowtag: %" PRIu32, static_cast<int>(getpid()),
               flow_tag);
}

void hw_queue_rx::rx_task_error_cb(doca_eth_rxq_task_recv *task_recv, doca_data task_user_data,
                                   doca_data ctx_user_data)
{
    mem_buf_desc_t *mem_buf = reinterpret_cast<mem_buf_desc_t *>(task_user_data.ptr);
    hw_queue_rx *hw_rx = reinterpret_cast<hw_queue_rx *>(ctx_user_data.ptr);
    doca_ctx_states ctx_state = DOCA_CTX_STATE_STOPPING;
    doca_error_t rc_state = doca_ctx_get_state(hw_rx->m_doca_ctx_rxq, &ctx_state);
    ctx_state = ((ctx_state != DOCA_CTX_STATE_IDLE) ? ctx_state : DOCA_CTX_STATE_STOPPING);
    if (rc_state != DOCA_SUCCESS || ctx_state != DOCA_CTX_STATE_STOPPING) {
        PRINT_DOCA_ERR(__log_err,
                       doca_task_get_status(doca_eth_rxq_task_recv_as_doca_task(task_recv)),
                       "RX Task Error");
        // TODO DOCA: Add statistics for errors
    }

    __log_func("rx_task_error_cb, task_recv: %p, rc_state: %d, ctx_state: %d", task_recv, rc_state,
               ctx_state);

    hw_rx->return_doca_task(task_recv);
    hw_rx->reclaim_rx_buffer_chain_loop(mem_buf);
    hw_rx->m_polled_buf = nullptr;
    ++hw_rx->m_hwq_rx_stats.n_rx_task_error;
}

bool hw_queue_rx::poll_and_process_rx()
{
    hwqrx_logfunc(LOG_FUNCTION_CALL);

    // DOCA forbides calling doca_pe_progress on armed PE.
    if (unlikely(m_notification_armed)) {
        // hwqrx_logwarn("Poll attempt on armed PE. hw_queue_rx: %p", this);
        // Armed PE context is suspended inside DOCA until event arrives. No way to poll.
        return true;
    }

    uint32_t rx_polled = 0U;
    while (rx_polled < safe_mce_sys().cq_poll_batch_max && doca_pe_progress(m_doca_pe.get())) {
        if (likely(m_polled_buf)) { // The doca_pe_progress returns 1 for error-progress as well.
            process_recv_buffer(m_polled_buf);
            ++rx_polled;
        }
    }

    m_p_ring->m_gro_mgr.flush_all(nullptr);

    submit_rxq_tasks();

    return (rx_polled < safe_mce_sys().cq_poll_batch_max);
}

void hw_queue_rx::process_recv_buffer(mem_buf_desc_t *p_mem_buf_desc)
{
    m_hwq_rx_stats.n_rx_byte_count += p_mem_buf_desc->sz_data;
    ++m_hwq_rx_stats.n_rx_pkt_count;

    if (!m_p_ring->rx_process_buffer(p_mem_buf_desc, nullptr)) {
        // If buffer is dropped by callback - return to RX pool
        reclaim_rx_buffer_chain_loop(p_mem_buf_desc);
    }
}

bool hw_queue_rx::request_notification()
{
    if (likely(!m_notification_armed)) {
        doca_error_t rc = doca_pe_request_notification(m_doca_pe.get());
        if (unlikely(DOCA_IS_ERROR(rc))) {
            PRINT_DOCA_ERR(hwqrx_logerr, rc, "doca_pe_request_notification");
            return false;
        }

        ++m_hwq_rx_stats.n_rx_interrupt_requests;
    }

    hwqrx_logfunc("Requested notification hw_queue_rx: %p", this);
    m_notification_armed = true;
    return true;
}

void hw_queue_rx::clear_notification()
{
    if (m_notification_armed) {
        m_notification_armed = false;
        doca_error_t rc = doca_pe_clear_notification(m_doca_pe.get(), m_notification_handle);
        if (unlikely(DOCA_IS_ERROR(rc))) {
            PRINT_DOCA_ERR(hwqrx_logerr, rc, "doca_pe_clear_notification");
        } else {
            ++m_hwq_rx_stats.n_rx_interrupt_received;
        }
    } else {
        hwqrx_logwarn("Clear notification attempt on unarmed PE. hw_queue_rx: %p", this);
    }
}

void hw_queue_rx::modify_moderation(uint16_t period_usec, uint16_t comp_count)
{
    doca_error_t rc =
        doca_eth_rxq_set_notification_moderation(m_doca_rxq.get(), period_usec, comp_count);
    if (unlikely(DOCA_IS_ERROR(rc))) {
        PRINT_DOCA_ERR(hwqrx_logerr, rc, "doca_eth_rxq_set_notification_moderation");
    } else {
        m_hwq_rx_stats.n_rx_cq_moderation_period = period_usec;
        m_hwq_rx_stats.n_rx_cq_moderation_count = comp_count;
    }
}

rfs_rule *hw_queue_rx::create_rfs_rule(doca_flow_match &match_val, doca_flow_match &match_msk,
                                       uint16_t priority, uint32_t flow_tag)

{
    std::unique_ptr<rfs_rule> new_rule(new rfs_rule());
    // TODO: Add Support for TLS-RX.
    if (m_doca_rx_queue_id && m_p_ib_ctx_handler &&
        new_rule->create(match_val, match_msk, m_doca_rx_queue_id, priority, flow_tag,
                         *m_p_ib_ctx_handler)) {
        return new_rule.release();
    }

    return nullptr;
}

void hw_queue_rx::up()
{
    start_doca_rxq();
}

void hw_queue_rx::down()
{
    stop_doca_rxq();
}

#endif // !DEFINED_DPCP_PATH_RX
