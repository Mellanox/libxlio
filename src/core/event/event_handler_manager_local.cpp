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

#include "event_handler_manager_local.h"
#include "util/sys_vars.h"
#include "xlio.h"

using namespace std::chrono;

thread_local event_handler_manager_local g_event_handler_manager_local;

event_handler_manager_local::event_handler_manager_local()
    : event_handler_manager(false)
{
}

void event_handler_manager_local::post_new_reg_action(reg_action_t &reg_action)
{
    // For thread local event handler registration can be immediate.
    handle_registration_action(reg_action);
}

void event_handler_manager_local::take_curr_time()
{
    m_curr_sample = high_resolution_clock::now();
}

void event_handler_manager_local::do_tasks()
{
    take_curr_time();
    do_tasks_check();
}

void event_handler_manager_local::do_tasks_check()
{
    if (likely(safe_mce_sys().tcp_timer_resolution_msec >
               duration_cast<milliseconds>(m_curr_sample - m_last_run_time).count())) {
        return;
    }

    m_last_run_time = m_curr_sample;

    do_tasks_for_thread_local();
}

void event_handler_manager_local::do_tasks_for_thread_local()
{
    m_timer.process_registered_timers_uncond();

    while (!m_close_postponed_sockets.empty()) {
        XLIO_CALL(close, m_close_postponed_sockets.get_and_pop_front()->get_fd());
    }
}

void event_handler_manager_local::add_close_postponed_socket(sockinfo *sock)
{
    m_close_postponed_sockets.push_front(sock);
}
