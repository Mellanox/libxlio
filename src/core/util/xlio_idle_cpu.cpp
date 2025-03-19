
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

#include "xlio_idle_cpu.h"
#include "vlogger/vlogger.h"
#include "core/util/sys_vars.h"

#define MODULE_NAME "xlio_idle_cpu"

#define xidle_loginfo    __log_info

thread_local xlio_idle_cpu tl_idle_cpu("AppThread");

xlio_idle_cpu::xlio_idle_cpu(const char *name)
    : m_prev_idle_time(m_prev_idle_time.min())
    , m_name(name)
{
}

void xlio_idle_cpu::measure_idle(const high_resolution_clock::time_point& curr_time, bool last_process_idle)
{
    // Is currently in busy time and last proces was idle. Start measure idle.
    if ((m_prev_idle_time == m_prev_idle_time.min()) && last_process_idle) {
        m_prev_idle_time = curr_time;
    } else if ((m_prev_idle_time != m_prev_idle_time.min()) && !last_process_idle) {
        // Is currently in idle time and last proces was not idle.
        // Count accumulated idel time and move to busy.
        m_idle_time += curr_time - m_prev_idle_time;
        m_prev_idle_time = m_prev_idle_time.min();
    }

    if (likely(safe_mce_sys().xlio_thread_idle_count_sec <
               duration_cast<seconds>(curr_time - m_prev_count_time).count())) {
        if (m_prev_idle_time != m_prev_idle_time.min()) {
            m_idle_time += curr_time - m_prev_idle_time;
            m_prev_idle_time = curr_time;
        }
        auto total_time_ms = duration_cast<milliseconds>(curr_time - m_prev_count_time).count();
        auto idle_time_ms = duration_cast<milliseconds>(m_idle_time).count();
        m_prev_count_time = high_resolution_clock::now();
        m_idle_time = m_idle_time.zero();
        xidle_loginfo("%s (%d) Idle time: %.0f%", m_name, static_cast<int>(gettid()),
            (idle_time_ms * 100) / static_cast<double>(total_time_ms));
    }
}