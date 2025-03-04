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

#include "xlio_thread_manager.h"
#include "core/sock/sockinfo_tcp.h"

xlio_thread_manager *g_p_xlio_thread_manager = nullptr;

xlio_thread_manager::xlio_thread_manager(size_t threads)
    : m_threads_num(threads)
{
    if (m_threads_num > 0 && m_threads_num < UINT32_MAX) {
        m_xlio_threads = std::move(std::make_unique<xlio_thread[]>(m_threads_num));
    }

    std::for_each(m_xlio_threads.get(), m_xlio_threads.get() + m_threads_num,
        [](xlio_thread& t) { t.start_thread(); });
}

xlio_thread_manager::~xlio_thread_manager()
{
    std::for_each(m_xlio_threads.get(), m_xlio_threads.get() + m_threads_num,
        [](xlio_thread& t) { t.stop_thread(); });
}

int xlio_thread_manager::add_listen_socket(sockinfo_tcp *sock)
{
    std::lock_guard<decltype(m_mgr_lock)> lock(m_mgr_lock);
    int rc = m_xlio_threads.get()[m_next_add_group++].add_listen_socket(sock);
    m_next_add_group %= m_threads_num;
    return rc;
}

int xlio_thread_manager::add_accepted_socket(sockinfo_tcp *sock)
{
    std::lock_guard<decltype(m_mgr_lock)> lock(m_mgr_lock);
    int rc = m_xlio_threads.get()[m_next_add_group++].add_accepted_socket(sock);
    m_next_add_group %= m_threads_num;
    return rc;
}
