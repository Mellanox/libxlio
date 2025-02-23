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

void xlio_thread::xlio_thread_loop(xlio_thread& t)
{
    xt_loginfo("Started");

    while (t.m_running.load(std::memory_order_relaxed)) {

    }

    xt_loginfo("Terminated");
}

void xlio_thread::start_thread()
{
    xt_loginfo("Starting XLIO thread");
    m_running.store(true);
    m_thread = std::move(std::thread(xlio_thread_loop, std::ref(*this)));
}

void xlio_thread::stop_thread()
{
    xt_loginfo("Stopping XLIO thread");
    m_running.store(false);
    m_thread.join();
}