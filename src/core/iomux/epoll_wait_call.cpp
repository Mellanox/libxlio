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

#include "epoll_wait_call.h"

#include <vlogger/vlogger.h>

#include <util/vtypes.h>
#include <sock/sock-redirect.h>
#include <sock/sockinfo.h>
#include <sock/fd_collection.h>

#include "epfd_info.h"

#define MODULE_NAME "epoll_wait_call"
DOCA_LOG_REGISTER(epoll_wait_call);

epoll_wait_call::epoll_wait_call(epoll_event *extra_events_buffer,
                                 offloaded_mode_t *off_modes_buffer, int epfd, epoll_event *events,
                                 int maxevents, int timeout, const sigset_t *sigmask /* = NULL */)
    : io_mux_call(nullptr, off_modes_buffer, 0, sigmask)
    , // TODO: rethink on these arguments
    m_epfd(epfd)
    , m_events(events)
    , m_maxevents(maxevents)
    , m_timeout(timeout)
    , m_p_ready_events(extra_events_buffer)
{
    // get epfd_info
    m_epfd_info = fd_collection_get_epfd(epfd);
    if (!m_epfd_info || maxevents <= 0) {
        __log_dbg("error, epfd %d not found or maxevents <= 0 (=%d)", epfd, maxevents);
        errno = maxevents <= 0 ? EINVAL : EBADF;
        xlio_throw_object(io_mux_call::io_error);
    }

    // create stats
    m_p_stats = &m_epfd_info->stats()->stats;
}

void epoll_wait_call::init_offloaded_fds()
{
    // copy offloaded_fds pointer and count
    m_epfd_info->get_offloaded_fds_arr_and_size(&m_p_num_all_offloaded_fds, &m_p_all_offloaded_fds);
    m_num_all_offloaded_fds =
        *m_p_num_all_offloaded_fds; // TODO: fix orig ugly code, and then remove this

    __log_func("building: epfd=%d, m_epfd_info->get_fd_offloaded_size()=%zu, "
               "m_epfd_info->get_fd_non_offloaded_size()=%zu, *m_p_num_all_offloaded_fds=%d",
               m_epfd, m_epfd_info->get_fd_offloaded_size(),
               m_epfd_info->get_fd_non_offloaded_size(), *m_p_num_all_offloaded_fds);
}

int epoll_wait_call::get_current_events()
{
    if (m_epfd_info->m_ready_fds.empty()) {
        return m_n_all_ready_fds;
    }

    xlio_list_t<sockinfo, sockinfo::socket_fd_list_node_offset> socket_fd_list;

    lock();

    int i = m_n_all_ready_fds;
    int ready_rfds = 0;
    int ready_wfds = 0;
    sockinfo *si = m_epfd_info->m_ready_fds.front();
    while (si && i < m_maxevents) {
        sockinfo *si_next = m_epfd_info->m_ready_fds.next(si);
        bool got_event = false;

        m_events[i].events = 0;

        // epoll_wait will always wait for EPOLLERR and EPOLLHUP.
        uint32_t mutual_events =
            si->get_epoll_event_flags() & (si->m_fd_rec.events | EPOLLERR | EPOLLHUP);

        // EPOLLHUP & EPOLLOUT are mutually exclusive. See poll man pages. Epoll adapts the poll
        // behavior.
        if ((mutual_events & EPOLLHUP) && (mutual_events & EPOLLOUT)) {
            mutual_events &= ~EPOLLOUT;
        }

        if (mutual_events & EPOLLIN) {
            if (handle_epoll_event(si->is_readable(true), EPOLLIN, si, i)) {
                ready_rfds++;
                got_event = true;
            }
            mutual_events &= ~EPOLLIN;
        }

        if (mutual_events & EPOLLOUT) {
            if (handle_epoll_event(si->is_writeable(), EPOLLOUT, si, i)) {
                ready_wfds++;
                got_event = true;
            }
            mutual_events &= ~EPOLLOUT;
        }

        // Handle zcopy notification mechanism
        if (mutual_events & EPOLLERR) {
            int unused;
            if (handle_epoll_event(si->is_errorable(&unused), EPOLLERR, si, i)) {
                got_event = true;
            }
            mutual_events &= ~EPOLLERR;
        }

        if (mutual_events) {
            if (handle_epoll_event(true, mutual_events, si, i)) {
                got_event = true;
            }
        }

        if (got_event) {
            socket_fd_list.push_back(si);
            ++i;
        }
        si = si_next;
    }

    m_n_ready_rfds += ready_rfds;
    m_n_ready_wfds += ready_wfds;
    m_p_stats->n_iomux_rx_ready += ready_rfds;

    unlock();

    /*
     * For checking ring migration rx we need a socket context.
     * In epoll we separate the rings from the sockets, so only here we access the sockets.
     * Therefore, it is most convenient to check it here.
     * We need to move the ring migration to the epfd, going over the registered sockets,
     * when polling the rings was not fruitful.
     * This  will be more similar to the behavior of select/poll.
     * See RM task 212058
     */
    while (!socket_fd_list.empty()) {
        si = socket_fd_list.get_and_pop_front();
        si->consider_rings_migration_rx();
    }

    return (i);
}

epoll_wait_call::~epoll_wait_call()
{
}

void epoll_wait_call::prepare_to_block()
{
    // Empty
}

bool epoll_wait_call::_wait(int timeout)
{
    int i, ready_fds, fd;
    bool cq_ready = false;
    epoll_fd_rec *fd_rec;

    __log_func("calling os epoll: %d", m_epfd);

    if (timeout) {
        lock();
        if (m_epfd_info->m_ready_fds.empty()) {
            m_epfd_info->going_to_sleep();
        } else {
            timeout = 0;
        }
        unlock();
    }

    if (m_sigmask) {
        ready_fds = SYSCALL(epoll_pwait, m_epfd, m_p_ready_events, m_maxevents, timeout, m_sigmask);
    } else {
        ready_fds = SYSCALL(epoll_wait, m_epfd, m_p_ready_events, m_maxevents, timeout);
    }

    if (timeout) {
        lock();
        m_epfd_info->return_from_sleep();
        unlock();
    }

    if (ready_fds < 0) {
        xlio_throw_object(io_mux_call::io_error);
    }

    // convert the returned events to user events and mark offloaded fds
    m_n_all_ready_fds = 0;
    for (i = 0; i < ready_fds; ++i) {
        fd = m_p_ready_events[i].data.fd;

        // wakeup event
        if (m_epfd_info->is_wakeup_fd(fd)) {
            lock();
            m_epfd_info->remove_wakeup_fd();
            unlock();
            continue;
        }

        // If it's CQ
        if (m_epfd_info->is_cq_fd(m_p_ready_events[i].data.u64)) {
            cq_ready = true;
            continue;
        }

        if (m_p_ready_events[i].events & EPOLLIN) {
            sockinfo *temp_sock_fd_api = fd_collection_get_sockfd(fd);
            if (temp_sock_fd_api) {
                // Instructing the socket to sample the OS immediately to prevent hitting EAGAIN on
                // recvfrom(), after iomux returned a shadow fd as ready (only for non-blocking
                // sockets)
                temp_sock_fd_api->set_immediate_os_sample();
            }
        }

        // Copy event bits and data
        m_events[m_n_all_ready_fds].events = m_p_ready_events[i].events;
        fd_rec = m_epfd_info->get_fd_rec(fd);
        if (fd_rec) {
            m_events[m_n_all_ready_fds].data = fd_rec->epdata;
            ++m_n_all_ready_fds;
        } else {
            __log_dbg("error - could not found fd %d in m_fd_info of epfd %d", fd, m_epfd);
        }
    }

    return cq_ready;
}

bool epoll_wait_call::wait_os(bool zero_timeout)
{
    return _wait(zero_timeout ? 0 : m_timeout);
}

bool epoll_wait_call::wait(const timeval &elapsed)
{
    int timeout;

    if (m_timeout < 0) {
        timeout = m_timeout;
    } else {
        timeout = m_timeout - tv_to_msec(&elapsed);
        if (timeout < 0) {
            // Already reached timeout
            return false;
        }
    }

    return _wait(timeout);
}

bool epoll_wait_call::is_timeout(const timeval &elapsed)
{
    return m_timeout >= 0 && m_timeout <= tv_to_msec(&elapsed);
}

void epoll_wait_call::set_offloaded_rfd_ready(int fd_index)
{
    // Empty - event inserted via event callback
    NOT_IN_USE(fd_index);
}

void epoll_wait_call::set_offloaded_wfd_ready(int fd_index)
{
    // Empty
    NOT_IN_USE(fd_index);
}

void epoll_wait_call::set_rfd_ready(int fd)
{
    // Empty
    NOT_IN_USE(fd);
}

void epoll_wait_call::set_wfd_ready(int fd)
{
    // Empty
    NOT_IN_USE(fd);
}

void epoll_wait_call::set_efd_ready(int fd, int errors)
{
    // Empty
    NOT_IN_USE(fd);
    NOT_IN_USE(errors);
}

void epoll_wait_call::lock()
{
    m_epfd_info->lock();
}

void epoll_wait_call::unlock()
{
    m_epfd_info->unlock();
}

bool epoll_wait_call::check_all_offloaded_sockets()
{
    // check cq for acks
    bool all_drained = ring_poll_and_process_element();
    m_n_all_ready_fds = get_current_events();

    __log_func("m_n_all_ready_fds=%d, m_n_ready_rfds=%d, m_n_ready_wfds=%d, all_drained=%d",
               m_n_all_ready_fds, m_n_ready_rfds, m_n_ready_wfds, !!all_drained);
    return all_drained;
}

bool epoll_wait_call::handle_epoll_event(bool is_ready, uint32_t events, sockinfo *socket_object,
                                         int index)
{
    if (is_ready) {
        epoll_fd_rec &fd_rec = socket_object->m_fd_rec;
        m_events[index].data = fd_rec.epdata;
        m_events[index].events |= events;

        if (fd_rec.events & EPOLLONESHOT) {
            // Clear events for this fd
            fd_rec.events &= ~events;
        }
        if (fd_rec.events & EPOLLET) {
            m_epfd_info->remove_epoll_event(socket_object, events);
        }
        return true;
    } else {
        // not readable, need to erase from our ready list (LT support)
        m_epfd_info->remove_epoll_event(socket_object, events);
        return false;
    }
}

bool epoll_wait_call::ring_poll_and_process_element()
{
    return m_epfd_info->ring_poll_and_process_element(nullptr);
}

bool epoll_wait_call::ring_request_notification()
{
    return m_epfd_info->ring_request_notification();
}

void epoll_wait_call::ring_clear_rx_notification()
{
    m_epfd_info->ring_clear_rx_notification();
}

void epoll_wait_call::clear_false_cq_events()
{
    m_epfd_info->clear_cq_events();
}
