/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "sockinfo_tcp_listen_context.h"
#include "util/sys_vars.h"

sockinfo_tcp_listen_context::sockinfo_tcp_listen_context()
{
    m_listen_rss_children.reserve(safe_mce_sys().worker_threads);
}

void sockinfo_tcp_listen_context::increment_finish_counter()
{
    {
        // C++ standard requires: shared variables used in condition_variable predicates must be
        // modified while holding the same mutex used by wait(), even if atomic
        std::lock_guard<std::mutex> lock(m_ready_mutex);
        m_sockinfo_tcp_listen_finish_counter.fetch_add(1);
    }
    // Wake up parent to check if all children are ready
    m_ready_condition.notify_one();
}

void sockinfo_tcp_listen_context::increment_error_counter()
{
    {
        // C++ standard requires: shared variables used in condition_variable predicates must be
        // modified while holding the same mutex used by wait(), even if atomic
        std::lock_guard<std::mutex> lock(m_ready_mutex);
        m_sockinfo_tcp_listen_error_counter.fetch_add(1);
    }
    // Wake up parent immediately on any error
    m_ready_condition.notify_one();
}

bool sockinfo_tcp_listen_context::wait_for_rss_children_ready()
{
    // std::condition_variable works only with std::unique_lock<std::mutex>
    std::unique_lock<std::mutex> lock(m_ready_mutex);
    // Wait until either:
    // 1. ALL children are ready (finish_counter == rss_children_size), OR
    // 2. At least 1 error occurred (error_counter > 0)
    // Each child wakes up parent, parent checks condition, goes back to wait if not met
    m_ready_condition.wait(lock, [this] {
        return get_finish_counter() == get_listen_rss_children_size() || get_error_counter() > 0;
    });
    return true; // Condition was met
}
