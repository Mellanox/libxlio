/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "config.h"
#include "poll_group.h"

#include "dev/net_device_table_mgr.h"
#include "dev/net_device_val.h"
#include "dev/ring.h"
#include "event/event_handler_manager_local.h"
#include "sock/sockinfo_tcp.h"

#define MODULE_NAME "group:"

#define grp_logpanic __log_panic
#define grp_logerr   __log_err
#define grp_logwarn  __log_warn
#define grp_loginfo  __log_info
#define grp_logdbg   __log_dbg

/*
 * Collection of the groups to destroy leftovers in the library destructor.
 * Groups are likely pre-initialized in a small number (up to the number of CPU cores)
 * and destroyed at exit. Therefore, a simple collection data structure is enough.
 */
static std::vector<poll_group *> s_poll_groups;
static lock_spin s_poll_groups_lock;
static thread_local lock_dummy t_lock_dummy_group;

static lock_base *get_new_group_lock()
{
    return (
        safe_mce_sys().xlio_threads > 0
            ? static_cast<lock_base *>(multilock::create_new_lock(MULTILOCK_RECURSIVE, "poll_group"))
            : static_cast<lock_base *>(&t_lock_dummy_group));
}

poll_group::poll_group(const struct xlio_poll_group_attr *attr)
    : m_socket_event_cb(attr->socket_event_cb)
    , m_socket_comp_cb(attr->socket_comp_cb)
    , m_socket_rx_cb(attr->socket_rx_cb)
    , m_socket_accept_cb(attr->socket_accept_cb)
    , m_group_flags(attr->flags)
    , m_group_lock(get_new_group_lock())
{
    /*
     * In the best case, we expect a single ring per group. Reserve two elements for a scenario
     * with two network interfaces and when the both interfaces are used by the sockets.
     * More complex scenarios will be covered with re-allocation.
     */
    m_rings.reserve(2);

    m_event_handler = std::make_unique<event_handler_manager_local>();
    m_tcp_timers = std::make_unique<tcp_timers_collection>(1U);
    m_tcp_timers->set_group(this);

    s_poll_groups_lock.lock();
    s_poll_groups.push_back(this);
    s_poll_groups_lock.unlock();

    grp_logdbg("Polling group %p created", this);
}

poll_group::poll_group(const struct xlio_poll_group_attr *attr, size_t xlio_thread_idx)
    : poll_group(attr)
{
    m_xlio_thread_idx = xlio_thread_idx;
}

poll_group::~poll_group()
{
    s_poll_groups_lock.lock();
    auto iter = std::find(s_poll_groups.begin(), s_poll_groups.end(), this);
    if (iter != std::end(s_poll_groups)) {
        s_poll_groups.erase(iter);
    }
    s_poll_groups_lock.unlock();

    while (!m_sockets_list.empty()) {
        sockinfo_tcp *si = dynamic_cast<sockinfo_tcp *>(m_sockets_list.front());
        if (likely(si)) {
            close_socket(si, true);
        }
    }

    // Release references to the rings that we take in add_ring()
    for (auto &item : m_rings_ref) {
        item.second->release_ring(item.first.get());
    }
    m_rings_ref.clear();

    grp_logdbg("Polling group %p destroyed", this);
}

/*static*/
void poll_group::destroy_all_groups()
{
    s_poll_groups_lock.lock();
    std::vector<poll_group *> groups(std::move(s_poll_groups));
    s_poll_groups_lock.unlock();
    for (poll_group *grp : groups) {
        delete grp;
    }
}

int poll_group::update(const struct xlio_poll_group_attr *attr)
{
    if (m_group_flags != attr->flags) {
        // Runtime flags change is not supported for now.
        errno = EINVAL;
        return -1;
    }

    m_socket_event_cb = attr->socket_event_cb;
    m_socket_comp_cb = attr->socket_comp_cb;
    m_socket_rx_cb = attr->socket_rx_cb;

    return 0;
}

int poll_group::poll_rings()
{
    m_event_handler->do_tasks_check();

    int all_drained = -1;
    for (ring *rng : m_rings) {
        uint64_t sn = 0;
        all_drained = std::max(all_drained, rng->poll_and_process_element_tx(&sn));
        sn = 0;
        all_drained = std::max(all_drained, rng->poll_and_process_element_rx(&sn));
    }

    return all_drained;
}

int poll_group::poll()
{
    m_event_handler->take_curr_time();
    return poll_rings();
}

int poll_group::process()
{
    m_event_handler->take_curr_time();

    int all_drained = poll();

    if (clear_rx_buffers()) {
        all_drained = 0;
    }

    m_job_q_lock.lock();
    m_all_jobs_temp.swap(m_job_q);
    m_job_q_lock.unlock();

    bool wastx = false;
    while (!m_all_jobs_temp.empty()) {
        job_desc jd = m_all_jobs_temp.front();
        m_all_jobs_temp.pop();
        if (jd.job_type == JOB_TYPE_TX) {
            const struct iovec iov = {.iov_base = reinterpret_cast<void *>(jd.buf->p_buffer), .iov_len = jd.buf->sz_data};
            jd.sock->tcp_tx_express(&iov, 1, LKEY_TX_DEFAULT, 0, reinterpret_cast<void *>(jd.buf));
            wastx = true;
        } else if (jd.job_type == JOB_TYPE_CLOSE_SOCK) {
            m_rem_socket_jobs.push((job_desc){JOB_TYPE_CLOSE_SOCK,jd.sock,nullptr});
        }
    }

    if (handle_ack_ready_sockets()) {
        all_drained = 0;
        wastx = true;
    }

    if (wastx) {
        flush();
    }

    while (!m_rem_socket_jobs.empty()) {
        job_desc jd = m_rem_socket_jobs.front();
        m_rem_socket_jobs.pop();
        close_socket(jd.sock, true);
    }

    return all_drained;
}

bool poll_group::handle_ack_ready_sockets()
{
    if (!m_ack_ready_list.empty()) {
        auto temp_stack = m_ack_ready_list.pop_all();
        while (!temp_stack.empty()) {
            sockinfo_tcp *sock = temp_stack.get_and_pop();
            sock->make_dirty();
        }

        return true;
    }

    return false;
}

void poll_group::add_dirty_socket(sockinfo_tcp *si)
{
    if (m_group_flags & XLIO_GROUP_FLAG_DIRTY) {
        m_dirty_sockets.push_back(si);
    }
}

void poll_group::flush()
{
    std::lock_guard<decltype(m_group_lock)> lock(m_group_lock);
    flush_no_lock();
}

void poll_group::flush_no_lock()
{
    for (auto si : m_dirty_sockets) {
        si->flush();
    }
    m_dirty_sockets.clear();
    // TODO Ring doorbell and request TX completion.
}

void poll_group::add_ring(ring *rng, ring_alloc_logic_attr *attr)
{
    if (std::find(m_rings.begin(), m_rings.end(), rng) == std::end(m_rings)) {
        grp_logdbg("New ring %p in group %p", rng, this);
        m_rings.push_back(rng);

        /*
         * Take reference to the ring. This avoids a race between socket destruction and buffer
         * return to the group. Socket destruction can lead to the ring destruction. But user
         * may return a buffer outside of the socket lifecycle.
         * This also avoids extra ring destruction in a scenario when application closes all
         * the sockets multiple times in runtime.
         */
        net_device_val *nd = g_p_net_device_table_mgr->get_net_device_val(rng->get_if_index());
        if (nd) {
            ring *reserved = nd->reserve_ring(attr);
            if (reserved != rng) {
                grp_logerr("Cannot reserve ring %p (reserved=%p)", rng, reserved);
                if (reserved) {
                    nd->release_ring(attr);
                }
            } else {
                m_rings_ref.push_back(
                    std::make_pair(std::make_unique<ring_alloc_logic_attr>(*attr), nd));
            }
        }
    }
}

void poll_group::add_socket(sockinfo_tcp *si)
{
    std::lock_guard<decltype(m_group_lock)> lock(m_group_lock);

    m_sockets_list.push_back(si);
    // For the flow_tag fast path support.
    g_p_fd_collection->set_socket(si->get_fd(), si);
}

void poll_group::remove_socket(sockinfo_tcp *si)
{
    std::lock_guard<decltype(m_group_lock)> lock(m_group_lock);

    g_p_fd_collection->clear_socket(si->get_fd());
    m_sockets_list.erase(si);

    auto iter = std::find(m_dirty_sockets.begin(), m_dirty_sockets.end(), si);
    if (iter != std::end(m_dirty_sockets)) {
        m_dirty_sockets.erase(iter);
    }
}

void poll_group::close_socket_threaded(sockinfo_tcp *si)
{
    job_insert(JOB_TYPE_CLOSE_SOCK, si, nullptr);
}

void poll_group::close_socket(sockinfo_tcp *si, bool force /*=false*/)
{
    {
        std::lock_guard<decltype(m_group_lock)> lock(m_group_lock);

        remove_socket(si);
    }

    bool closed = si->prepare_to_close(force);
    if (closed) {
        /*
         * Current implementation forces TCP reset, so the socket is expected to be closable.
         * Do a polling iteration to increase the chance that all the relevant WQEs are completed
         * and XLIO emitted all the TX completion before the XLIO_SOCKET_EVENT_TERMINATED event.
         *
         * TODO Implement more reliable mechanism of deferred socket destruction if there are
         * not completed TX operations.
         */
        poll();

        si->clean_socket_obj();
    } else {

    }
}

mem_buf_desc_t *poll_group::get_tx_buffer()
{
    mem_buf_desc_t *buf = nullptr;
    ring *rng = m_rings.front();

    if (rng) {
        buf = rng->mem_buf_tx_get(0, false, PBUF_RAM, 1);
    }
    return buf;
}

void poll_group::return_tx_buffer(mem_buf_desc_t *buf)
{
    ring *rng = m_rings.front();
    if (rng) {
        buf->p_next_desc = nullptr;
        rng->mem_buf_tx_release(buf, false, false);
    }
}

void poll_group::return_rx_buffers(mem_buf_desc_t *first, mem_buf_desc_t*last)
{
    m_returned_buffers.put_objs(first, last);
}

bool poll_group::clear_rx_buffers()
{
    mem_buf_desc_t *first = m_returned_buffers.get_all_objs();
    if (first) {
        // We assume only one RX ring per group.
        first->p_desc_owner->reclaim_recv_buffers_chain(first);
        return true;
    }

    return false;
}
