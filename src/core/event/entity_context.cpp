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

#include "entity_context.h"
#include "vlogger/vlogger.h"
#include "sock/sockinfo_tcp.h"

using namespace std::chrono;

#define MODULE_NAME "worker_thread"

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
{
    xlio_stats_instance_create_ent_ctx_block(&m_stats);

    get_event_handler()->do_tasks(); // Update last_taken_time

    ctx_logdbg("Entity Context created");
}

entity_context::~entity_context()
{
    xlio_stats_instance_remove_ent_ctx_block(&m_stats);

    ctx_logdbg("Entity Context destroyed");
}

void entity_context::process()
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
}

void entity_context::add_job(const job_desc &job)
{
    m_job_queue.insert_job(job);
}

void entity_context::connect_socket_job(const job_desc &job)
{
    sockinfo *sock = job.sock;
    if (sock->get_protocol() == PROTO_TCP) {
        sock->set_entity_context(this);
        add_socket(reinterpret_cast<sockinfo_tcp *>(sock));
        reinterpret_cast<sockinfo_tcp *>(sock)->connect_entity_context();
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
        } else {
            ++m_stats.socket_num_removed;
        }
        // Use poll_group::close_socket_helper which handles :
        // - remove_socket(si)
        // - prepare_to_close() and clean_socket_obj() or add to pending close list
        close_socket_helper(tcp_si);
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
