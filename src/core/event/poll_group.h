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

#ifndef XLIO_GROUP_H
#define XLIO_GROUP_H

#include <memory>
#include <queue>
#include <vector>

#include "sock/fd_collection.h"
#include "xlio.h"
#include "sock/sockinfo_tcp.h"
#include "util/xlio_lockless_stack.h"
#include "event/event_handler_manager_local.h"

/* Forward declarations */
struct xlio_poll_group_attr;
class event_handler_manager_local;
class ring;
class ring_alloc_logic_attr;
class tcp_timers_collection;

#define JOB_TYPE_TX         0
#define JOB_TYPE_CLOSE_SOCK 1

struct job_desc {
    int job_type;
    sockinfo_tcp *sock;
    mem_buf_desc_t *buf;
};

class poll_group {
public:
    poll_group(const struct xlio_poll_group_attr *attr);
    ~poll_group();
    static void destroy_all_groups();

    int update(const struct xlio_poll_group_attr *attr);

    int poll();
    int process();

    void add_dirty_socket(sockinfo_tcp *si);
    void flush();
    void flush_no_lock();

    void add_ring(ring *rng, ring_alloc_logic_attr *attr);

    void add_socket(sockinfo_tcp *si);
    void remove_socket(sockinfo_tcp *si);
    void close_socket(sockinfo_tcp *si, bool force = false);
    void close_socket_threaded(sockinfo_tcp *si);

    unsigned get_flags() const { return m_group_flags; }
    event_handler_manager_local *get_event_handler() const { return m_event_handler.get(); }
    tcp_timers_collection *get_tcp_timers() const { return m_tcp_timers.get(); }

    mem_buf_desc_t *get_tx_buffer();
    void return_tx_buffer(mem_buf_desc_t *buf);
    void return_rx_buffers(mem_buf_desc_t *first, mem_buf_desc_t*last);
    void add_epoll_ctx(epfd_info *epfd, sockinfo_tcp &sock);
    void remove_epoll_ctx(epfd_info *epfd);

    bool add_ack_ready_socket(sockinfo_tcp &sock) { return m_ack_ready_list.push(&sock); }

    const std::chrono::high_resolution_clock::time_point& get_curr_time() const { return m_event_handler.get()->curr_time_sample(); }

    void job_insert(int job_type, sockinfo_tcp *si, mem_buf_desc_t *buf)
    {
        std::lock_guard<decltype(m_job_q_lock)> lock(m_job_q_lock);
        m_job_q.push((job_desc) {job_type,si, buf});
    }

public:
    xlio_socket_event_cb_t m_socket_event_cb;
    xlio_socket_comp_cb_t m_socket_comp_cb;
    xlio_socket_rx_cb_t m_socket_rx_cb;
    xlio_socket_accept_cb_t m_socket_accept_cb;

private:
    int poll_rings();
    bool clear_rx_buffers();
    bool handle_ack_ready_sockets();

    cached_obj_pool_simple<mem_buf_desc_t> m_returned_buffers;

    std::vector<ring *> m_rings;
    std::unique_ptr<event_handler_manager_local> m_event_handler;
    std::unique_ptr<tcp_timers_collection> m_tcp_timers;

    unsigned m_group_flags;
    std::vector<sockinfo_tcp *> m_dirty_sockets;

    multilock m_group_lock;
    sock_fd_api_list_t m_sockets_list;
    std::vector<std::pair<std::unique_ptr<ring_alloc_logic_attr>, net_device_val *>> m_rings_ref;

    std::unordered_map<epfd_info *, std::pair<uint32_t, ep_ready_fd_list_t*>> m_epoll_ctx;
    xlio_lockless_stack<sockinfo_tcp, sockinfo_tcp::ack_thread_ready_list> m_ack_ready_list;

    lock_spin m_job_q_lock;
    std::queue<job_desc> m_job_q;
    std::queue<job_desc> m_rem_socket_jobs;
    std::queue<job_desc> m_all_jobs_temp;
};

#endif /* XLIO_GROUP_H */
