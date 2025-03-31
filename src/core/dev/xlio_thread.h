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

#ifndef XLIO_THREAD_H
#define XLIO_THREAD_H

#include <thread>
#include <atomic>
#include "core/util/wakeup_pipe.h"
#include "core/event/poll_group.h"
#include "core/util/xlio_idle_cpu.h"

class xlio_thread : public wakeup_pipe
{
public:

    xlio_thread();
    ~xlio_thread();

    void start_thread(size_t thread_idx);
    void stop_thread();
    int add_listen_socket(sockinfo_tcp *si);
    int add_accepted_socket(sockinfo_tcp *si);
    int add_connect_socket(sockinfo_tcp *si, const struct sockaddr *to, socklen_t tolen);

private:

    static void socket_event_cb(xlio_socket_t, uintptr_t userdata_sq, int event, int value);
    static void socket_comp_cb(xlio_socket_t, uintptr_t userdata_sq, uintptr_t userdata_op);
    static void socket_rx_cb(xlio_socket_t, uintptr_t userdata_sq, void *data, size_t len,
                             struct xlio_buf *buf);
    static void socket_accept_cb(xlio_socket_t sock, xlio_socket_t parent,
                                 uintptr_t parent_userdata_sq);
    static void xlio_thread_main(xlio_thread& t, size_t thread_idx);

    void xlio_thread_loop();
    void xlio_thread_measure_idle(bool last_process_idle);

    poll_group *m_poll_group;

    // Must be atomic for the start and stop to synchronize.
    std::atomic_bool m_running{false};

    xlio_idle_cpu m_idle_cpu;

    std::thread m_thread;
};

#endif // XLIO_THREAD_H
