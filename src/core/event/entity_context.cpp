/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "entity_context.h"
#include "vlogger/vlogger.h"
#include "dev/ring.h"
#include "sock/fd_collection.h"
#include "sock/sockinfo_tcp.h"
#include "sock/sock-redirect.h"

using namespace std::chrono;

#define MODULE_NAME "entity_context"

#define ctx_logpanic __log_panic
#define ctx_logerr   __log_err
#define ctx_logwarn  __log_warn
#define ctx_loginfo  __log_info_info
#define ctx_logdbg   __log_info_dbg

entity_context::entity_context(size_t index)
    : poll_group(xlio_poll_group_attr {XLIO_GROUP_FLAG_SAFE | XLIO_GROUP_FLAG_DIRTY, nullptr,
                                       entity_context_comp_cb, nullptr, nullptr})
    , m_index(index)
    , m_prev_proc_time(steady_clock::now())
    , m_last_poll_hit(false)
    , m_intr_setup_ok(false)
{
    memset(&m_stats, 0, sizeof(m_stats));
    xlio_stats_instance_create_ent_ctx_block(&m_stats);

    get_event_handler()->do_tasks(); // Update last_taken_time

    if (safe_mce_sys().is_interrupt_mode()) {
        m_wakeup_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (m_wakeup_fd < 0) {
            ctx_logerr("Failed to create wakeup eventfd (errno=%d %m)", errno);
        }

        m_epoll_fd = SYSCALL(epoll_create1, EPOLL_CLOEXEC);
        if (m_epoll_fd < 0) {
            ctx_logerr("Failed to create interrupt epoll fd (errno=%d %m)", errno);
        }

        if (m_epoll_fd >= 0 && m_wakeup_fd >= 0) {
            struct epoll_event ev = {};
            ev.events = EPOLLIN;
            ev.data.fd = m_wakeup_fd;
            if (SYSCALL(epoll_ctl, m_epoll_fd, EPOLL_CTL_ADD, m_wakeup_fd, &ev) < 0) {
                ctx_logerr("Failed to add wakeup fd to epoll (errno=%d %m)", errno);
            } else {
                m_intr_setup_ok = true;
            }
        }
    }

    ctx_logdbg("Entity Context created (%p)", this);
}

entity_context::~entity_context()
{
    xlio_stats_instance_remove_ent_ctx_block(&m_stats);

    if (m_epoll_fd >= 0) {
        SYSCALL(close, m_epoll_fd);
    }
    if (m_wakeup_fd >= 0) {
        SYSCALL(close, m_wakeup_fd);
    }

    ctx_logdbg("Entity Context destroyed (%p)", this);
}

bool entity_context::process()
{
    auto ts = steady_clock::now();
    (!m_last_poll_hit ? m_stats.idle_time : m_stats.hit_poll_time) +=
        duration_cast<nanoseconds>(get_event_handler()->last_taken_time() - m_prev_proc_time)
            .count();
    (!m_last_job_size ? m_stats.idle_time : m_stats.job_proc_time) +=
        duration_cast<nanoseconds>(ts - get_event_handler()->last_taken_time()).count();
    m_prev_proc_time = ts;

    m_last_poll_hit = poll();

    auto &jobs = m_job_queue.get_all();
    for (auto &job : jobs) {
        switch (job.job_id) {
        case JOB_TYPE_SOCK_ADD_AND_CONNECT:
            connect_socket_job(job);
            break;
        case JOB_TYPE_SOCK_ADD_AND_LISTEN:
            listen_socket_job(job);
            break;
        case JOB_TYPE_SOCK_TX:
            tx_data_job(job);
            break;
        case JOB_TYPE_SOCK_RX_DATA_RECVD:
            rx_data_recvd_job(job);
            break;
        case JOB_TYPE_SOCK_CLOSE:
            close_socket_job(job);
            break;
        default:
            // Unknown job type
            break;
        }
    }

    m_stats.job_queue_size_acc += static_cast<uint32_t>(jobs.size());
    m_stats.job_queue_hits += (jobs.size() ? 1 : 0);
    m_stats.job_queue_size_max =
        std::max(m_stats.job_queue_size_max, static_cast<uint32_t>(jobs.size()));
    m_last_job_size = jobs.size();
    jobs.clear();

    flush();

    return m_last_poll_hit || m_last_job_size;
}

void entity_context::add_job(const job_desc &job)
{
    if (m_job_queue.insert_job(job)) {
        wakeup();
    }
}

void entity_context::connect_socket_job(const job_desc &job)
{
    sockinfo *sock = job.sock;
    if (sock->get_protocol() == PROTO_TCP) {
        sock->set_entity_context(this);
        add_socket(reinterpret_cast<sockinfo_tcp *>(sock));
        reinterpret_cast<sockinfo_tcp *>(sock)->connect_entity_context();
        if (sock->isPassthrough()) {
            int fd = sock->get_fd();
            /* copy before handle_close may destroy sock */
            sock_addr peer = sock->get_peername();
            handle_close(fd, false, true);
            SYSCALL(connect, fd, peer.get_p_sa(), peer.get_socklen());
            return;
        }
        ++m_stats.socket_num_added;
        ctx_logdbg("New TCP socket added (sock: %p)", sock);
    } else {
        ctx_logdbg("Unsupported socket protocol %hd for Threads mode", sock->get_protocol());
    }
}

void entity_context::tx_data_job(const job_desc &job)
{
    if (unlikely(!job.buf || !job.sock)) {
        ctx_logwarn("Invalid TX job");
        return;
    }
    job.sock->tx_thread_commit(job.buf, job.offset, job.tot_size, job.flags);
}

void entity_context::add_incoming_socket(sockinfo *sock)
{
    if (sock->get_protocol() == PROTO_TCP) {
        ++m_stats.socket_num_added;
        add_socket(reinterpret_cast<sockinfo_tcp *>(sock));
    }
}

void entity_context::rx_data_recvd_job(const job_desc &job)
{
    if (job.buf) {
        /* coverity[check_return] */
        job.buf->p_desc_owner->reclaim_recv_buffers(job.buf);
    }

    if (job.sock) {
        job.sock->rx_data_recvd(job.tot_size);
    }
}

void entity_context::listen_socket_job(const job_desc &job)
{
    sockinfo *sock = job.sock;
    if (sock->get_protocol() == PROTO_TCP) {
        sock->set_entity_context(this);
        add_socket_helper(reinterpret_cast<sockinfo_tcp *>(sock));
        reinterpret_cast<sockinfo_tcp *>(sock)->listen_entity_context();
        ++m_stats.listen_rsschild_num;
        ctx_logdbg("New TCP Listen rss_child socket added (sock: %p)", sock);
    } else {
        ctx_logdbg("Unsupported socket protocol %hd for Threads mode", sock->get_protocol());
    }
}

void entity_context::close_socket_job(const job_desc &job)
{
    sockinfo *si = job.sock;
    assert(si);

    ctx_logdbg("Processing close job for socket (sock: %p, fd: %d)", si, si->get_fd());

    if (si->get_protocol() == PROTO_TCP) {
        sockinfo_tcp *tcp_si = reinterpret_cast<sockinfo_tcp *>(si);

        if (tcp_si->get_listen_context()) {
            assert(tcp_si->get_listen_context()->is_rss_child_listen_socket());
            // If this is a listen RSS child, notify parent.
            // Note: We must notify parent BEFORE calling close_socket_helper():
            // - If we close the socket first, we lose the reference to the parent
            // - It's safe to close socket after parent notification because:
            //   1. Entity context runs on a single thread
            //   2. No other thread can poll for new incoming connections while we're here
            //   3. Therefore, we won't call parent epoll notify after this point
            // - This avoids backing up parent reference and keeps code clean
            sockinfo_tcp *parent = tcp_si->get_listen_context()->get_parent_listen_socket();
            parent->get_listen_context()->increment_finish_counter();
            --m_stats.listen_rsschild_num;
        } else if (!tcp_si->isPassthrough()) {
            ++m_stats.socket_num_removed;
        }
        // Use poll_group::close_socket_helper which handles :
        // - remove_socket(si)
        // - prepare_to_close() and clean_socket_obj() or add to pending close list
        close_socket_helper(tcp_si);
    }
}

void entity_context::arm_cq_notifications()
{
    for (ring *rng : get_rings()) {
        bool success = rng->request_notification(CQT_RX);
        if (unlikely(!success)) {
            ctx_logerr("Failed to arm CQ notification for ring %p", rng);
	    // We should never reach this place because with current code, 
	    // rng->request_notification() never fails. This code serves to alert
	    // if this ever changes. If it happens, the error message will fire,
	    // and we need to deal with it by returning bool and changing 
	    // wait_for_interrupt() to handle the failure.
        }
    }
}

void entity_context::drain_wakeup_fd()
{
    if (unlikely(m_wakeup_fd < 0)) {
        return;
    }

    uint64_t val;
    int ret = SYSCALL(read, m_wakeup_fd, &val, sizeof(val));
    if (unlikely(ret < 0 && errno != EAGAIN)) {
        ctx_logerr("Failed to read from wakeup fd (errno=%d %m)", errno);
    }
}

entity_context::wakeup_reason entity_context::wait_for_interrupt(int timeout_ms)
{
    wakeup_reason reason = WAKEUP_NONE;

    if (unlikely(!m_intr_setup_ok)) {
        return WAKEUP_NONE;
    }

    // Transition to sleeping first. An app thread that inserted a job between
    // the last poll and this point either made the job visible to the check
    // inside try_sleep(), or takes the queue lock after it and writes to
    // wakeup_fd. Doing this before arming keeps the job path free of the CQ
    // arming cost, and a solicited interrupt is requested only when the worker
    // really intends to sleep.
    if (!m_job_queue.try_sleep()) {
        return WAKEUP_JOB_POSTED;
    }

    arm_cq_notifications();

    // Race avoidance: re-poll CQ after arming. The notification stays armed and
    // is acknowledged on the next wakeup - there is no disarm primitive.
    if (poll()) {
        m_job_queue.wake();
        return WAKEUP_CQ_EVENT;
    }

    static constexpr int MAX_EVENTS = 8;
    struct epoll_event events[MAX_EVENTS];
    int nfds;

    do {
        nfds = SYSCALL(epoll_wait, m_epoll_fd, events, MAX_EVENTS, timeout_ms);
    } while (nfds == -1 && errno == EINTR && !g_b_exit);

    m_job_queue.wake();

    if (unlikely(nfds == -1)) {
        if (errno != EINTR || !g_b_exit) {
            ctx_logerr("Failed to wait for epoll events (errno=%d %m)", errno);
        }
        return WAKEUP_NONE;
    }

    if (nfds == 0) {
        return WAKEUP_TIMEOUT;
    }

    for (int i = 0; i < nfds; ++i) {
        if (events[i].data.fd == m_wakeup_fd) {
            drain_wakeup_fd();
            if (reason == WAKEUP_NONE) {
                reason = WAKEUP_JOB_POSTED;
            }
        } else {
            cq_channel_info *p_cq_ch_info = g_p_fd_collection
                ? g_p_fd_collection->get_cq_channel_fd(events[i].data.fd)
                : nullptr;
            if (p_cq_ch_info) {
                ring *p_ring = p_cq_ch_info->get_ring();
                p_ring->ack_cq_events();
            }
            // CQ event has higher priority than job posted.
            reason = WAKEUP_CQ_EVENT;
        }
    }

    return reason;
}

void entity_context::wakeup()
{
    if (unlikely(!m_intr_setup_ok)) {
        return;
    }

    const uint64_t val = 1;
    if (SYSCALL(write, m_wakeup_fd, &val, sizeof(val)) < 0 && errno != EAGAIN) {
        ctx_logerr("Failed to write to wakeup fd (errno=%d %m)", errno);
    }
}

/*static*/
void entity_context::entity_context_comp_cb(xlio_socket_t sock, uintptr_t userdata_sq,
                                            uintptr_t userdata_op)
{
    mem_buf_desc_t *buf = reinterpret_cast<mem_buf_desc_t *>(userdata_op);

    NOT_IN_USE(sock);
    NOT_IN_USE(userdata_sq);

    if (buf->lwip_pbuf.ref > 1) {
        // Optimization to reduce the number of ring locks.
        --buf->lwip_pbuf.ref;
    } else {
        buf->p_desc_owner->mem_buf_tx_release(buf, true);
    }
}

void entity_context::notify_ring_added(ring *rng)
{
    if (!m_intr_setup_ok) {
        // This covers busy polling mode and run-time failures during entity context construction.
        return;
    }

    size_t num_fds = 0;
    int *fds = rng->get_rx_channel_fds(num_fds);
    for (size_t i = 0; i < num_fds; ++i) {
        struct epoll_event ev = {};
        ev.events = EPOLLIN;
        ev.data.fd = fds[i];
        if (SYSCALL(epoll_ctl, m_epoll_fd, EPOLL_CTL_ADD, fds[i], &ev) < 0 && errno != EEXIST) {
            ctx_logerr("Failed to add CQ channel fd %d to epoll (errno=%d %m)", fds[i], errno);
        }
    }
}
