/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "api_guard.h"

#include <atomic>
#include <chrono>
#include <pthread.h>
#include <unistd.h>

#include "vlogger/vlogger.h"
#include "sock/fd_collection.h"

#define MODULE_NAME "api_guard"

namespace {

constexpr std::chrono::milliseconds DRAIN_TIMEOUT {1000};
// A thread counted before the barrier closed can go to sleep after a wakeup round.
constexpr std::chrono::milliseconds DRAIN_WAKEUP_INTERVAL {50};
constexpr useconds_t DRAIN_POLL_USEC = 1000;

std::atomic<int> s_inflight {0};
std::atomic<bool> s_closed {false};
thread_local int t_depth = 0;

void reset_inflight_in_child()
{
    // Only the forking thread exists in the child.
    s_inflight.store(t_depth > 0 ? 1 : 0, std::memory_order_relaxed);
}

} // namespace

bool api_guard::s_enabled = false;

void api_guard::init(bool enabled)
{
    static bool atfork_registered = false;

    s_enabled = enabled;
    if (enabled && !atfork_registered) {
        atfork_registered = (pthread_atfork(nullptr, nullptr, reset_inflight_in_child) == 0);
    }
}

void api_guard::enter()
{
    if (t_depth > 0) {
        ++t_depth;
        m_counted = true;
        return;
    }

    // Count first, then check the barrier: either drain() sees this call or this call sees the
    // barrier. That needs seq_cst here and in drain().
    s_inflight.fetch_add(1, std::memory_order_seq_cst);
    if (unlikely(s_closed.load(std::memory_order_seq_cst))) {
        s_inflight.fetch_sub(1, std::memory_order_release);
        m_teardown = true;
        return;
    }
    // After the counter, so that a signal handler interrupting this function counts itself.
    ++t_depth;
    m_counted = true;
}

void api_guard::leave()
{
    if (--t_depth == 0) {
        s_inflight.fetch_sub(1, std::memory_order_release);
    }
}

bool api_guard::drain()
{
    if (!s_enabled) {
        return true;
    }
    if (s_closed.exchange(true, std::memory_order_seq_cst)) {
        __log_warn("Teardown is already in progress, skipping resource cleanup");
        return false;
    }

    // exit() may be called from inside an intercepted call, e.g. by a signal handler.
    const int own = (t_depth > 0) ? 1 : 0;
    const auto start = std::chrono::steady_clock::now();
    auto next_wakeup = start;
    int inflight;

    while ((inflight = s_inflight.load(std::memory_order_seq_cst) - own) > 0) {
        const auto now = std::chrono::steady_clock::now();
        if (now - start >= DRAIN_TIMEOUT) {
            __log_warn("%d thread(s) still inside intercepted calls after %lld ms, skipping "
                       "resource cleanup",
                       inflight, static_cast<long long>(DRAIN_TIMEOUT.count()));
            return false;
        }
        if (now >= next_wakeup) {
            if (g_p_fd_collection) {
                g_p_fd_collection->wakeup_all_waiters();
            }
            next_wakeup = now + DRAIN_WAKEUP_INTERVAL;
        }
        usleep(DRAIN_POLL_USEC);
    }
    return true;
}
