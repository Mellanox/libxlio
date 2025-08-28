/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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

void event_handler_manager_local::do_tasks()
{
    m_last_taken_time = steady_clock::now();
    if (likely(safe_mce_sys().tcp_timer_resolution_msec >
               duration_cast<milliseconds>(m_last_taken_time - m_last_run_time).count())) {
        return;
    }

    m_last_run_time = m_last_taken_time;

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
