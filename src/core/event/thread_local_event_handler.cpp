/*
 * Copyright (c) 2001-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "thread_local_event_handler.h"
#include "util/sys_vars.h"

thread_local thread_local_event_handler g_thread_local_event_handler;

thread_local_event_handler::thread_local_event_handler()
    : event_handler_manager(false)
{
}

void thread_local_event_handler::do_tasks()
{
    auto curr_time = chrono::steady_clock::now();
    if (likely(
            safe_mce_sys().tcp_timer_resolution_msec >
            chrono::duration_cast<std::chrono::milliseconds>(curr_time - _last_run_time).count())) {
        return;
    }

    _last_run_time = curr_time;

    do_tasks_for_thread_local();
}

void thread_local_event_handler::do_tasks_for_thread_local()
{
    // Handle registration events.
    reg_action_q_t *temp = m_p_reg_action_q_to_push_to;
    m_p_reg_action_q_to_push_to = m_p_reg_action_q_to_pop_from;
    m_p_reg_action_q_to_pop_from = temp;

    reg_action_t reg_action;
    while (!m_p_reg_action_q_to_pop_from->empty()) {
        reg_action = m_p_reg_action_q_to_pop_from->front();
        m_p_reg_action_q_to_pop_from->pop_front();
        handle_registration_action(reg_action);
    }

    m_timer.process_registered_timers_uncond();
}
