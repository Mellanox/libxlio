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

#include "xlio_thread.h"
#include "core/sock/sockinfo_tcp.h"

#define MODULE_NAME "xlio_thread"

#define xt_logpanic   __log_panic
#define xt_logerr     __log_err
#define xt_logwarn    __log_warn
#define xt_loginfo    __log_info
#define xt_logdbg     __log_dbg

xlio_thread::xlio_thread()
{

}

xlio_thread::~xlio_thread()
{

}

void xlio_thread::socket_event_cb(xlio_socket_t sock, uintptr_t userdata_sq, int event, int value)
{
    sockinfo_tcp *tcp_sock = reinterpret_cast<sockinfo_tcp *>(sock);
    __log_info("sock-fd: %d, event: %d, value: %d", tcp_sock->get_fd(), event, value);

    NOT_IN_USE(userdata_sq);
}

void xlio_thread::socket_comp_cb(xlio_socket_t sock, uintptr_t userdata_sq, uintptr_t userdata_op)
{
    sockinfo_tcp *tcp_sock = reinterpret_cast<sockinfo_tcp *>(sock);
    __log_info("sock-fd: %d", tcp_sock->get_fd());

    NOT_IN_USE(userdata_sq);
    NOT_IN_USE(userdata_op);
}

void xlio_thread::socket_rx_cb(xlio_socket_t sock, uintptr_t userdata_sq, void *data, size_t len,
                               struct xlio_buf *buf)
{
    sockinfo_tcp *tcp_sock = reinterpret_cast<sockinfo_tcp *>(sock);
    __log_info("sock-fd: %d, len: %sz", tcp_sock->get_fd(), len);

    NOT_IN_USE(userdata_sq);
    NOT_IN_USE(data);
    NOT_IN_USE(buf);
}

void xlio_thread::socket_accept_cb(xlio_socket_t sock, xlio_socket_t parent,
                                   uintptr_t parent_userdata_sq)
{
    sockinfo_tcp *tcp_sock = reinterpret_cast<sockinfo_tcp *>(sock);
    sockinfo_tcp *tcp_sock_parent = reinterpret_cast<sockinfo_tcp *>(parent);
    __log_info("sock-fd: %d, parent: %d", tcp_sock->get_fd(), tcp_sock_parent->get_fd());

    NOT_IN_USE(parent_userdata_sq);
}

int xlio_thread::add_listen_socket(sockinfo_tcp *si)
{
    si->set_xlio_socket_thread(m_poll_group);
    m_poll_group->add_socket(si);

    // TODO handle positive return code from prepareListen() and convert it to errno
    int rc = (si->prepareListen() ?: si->listen(-1));

    xt_loginfo("Socket added tid: %d, fd: %d, rc: %d", (int)gettid(), si->get_fd(), rc);
    return rc;
}

void xlio_thread::xlio_thread_loop()
{
    while (m_running.load(std::memory_order_relaxed)) {
        m_poll_group->poll();
        m_poll_group->flush();
    }
}

void xlio_thread::xlio_thread_main(xlio_thread& t)
{
    xt_loginfo("Started");

    xlio_poll_group_attr pollg_attr {
        XLIO_GROUP_FLAG_SAFE | XLIO_GROUP_FLAG_DIRTY,
        socket_event_cb,
        socket_comp_cb,
        socket_rx_cb,
        socket_accept_cb
    };

    t.m_poll_group = new poll_group(&pollg_attr);

    t.xlio_thread_loop();

    delete t.m_poll_group;

    xt_loginfo("Terminated");
}

void xlio_thread::start_thread()
{
    xt_loginfo("Starting XLIO thread");
    m_running.store(true);
    m_thread = std::move(std::thread(xlio_thread_main, std::ref(*this)));
}

void xlio_thread::stop_thread()
{
    xt_loginfo("Stopping XLIO thread");
    m_running.store(false);
    m_thread.join();
}