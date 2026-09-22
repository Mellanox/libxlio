/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef WORKER_THREAD_LOOP_H
#define WORKER_THREAD_LOOP_H

#include <chrono>

namespace worker_thread_detail {

/*
 * This is a template so production and tests execute the same scheduling logic
 * without adding virtual methods or test hooks to entity_context. The production
 * specialization is resolved at compile time, so the worker hot path has no
 * interface-dispatch overhead. Tests substitute deterministic context and clock
 * types and therefore need neither a real thread nor hardware nor elapsed wall
 * time.
 *
 * Production invocation parameters:
 * - context: entity_context
 * - WakeupReason: entity_context::wakeup_reason
 * - wakeup_reason: reason returned by the previous interrupt wait
 * - cq_wakeup_reason: entity_context::WAKEUP_CQ_EVENT
 * - poll_budget: XLIO_SELECT_POLL converted to microseconds
 * - interrupt_timeout_ms: configured TCP timer resolution
 * - now: callable returning std::chrono::steady_clock::now()
 * - running: callable reading worker_thread::m_running
 *
 * Test invocation parameters:
 * - context: scripted fake_context recording process and wait calls
 * - WakeupReason: test_wakeup_reason
 * - wakeup_reason/cq_wakeup_reason: scripted test enum values
 * - poll_budget/interrupt_timeout_ms: test-controlled values
 * - now: callable returning fake_clock::now()
 * - running: test-controlled predicate
 */
template <typename Context, typename WakeupReason, typename Clock, typename Running>
WakeupReason run_interrupt_cycle(Context &context, WakeupReason wakeup_reason,
                                 WakeupReason cq_wakeup_reason,
                                 std::chrono::microseconds poll_budget, int interrupt_timeout_ms,
                                 Clock now, Running running)
{
    if (wakeup_reason != cq_wakeup_reason) {
        // Process jobs and timer work once after a non-CQ wakeup.
        if (!context.process()) {
            if (!running()) {
                return wakeup_reason;
            }
            return context.wait_for_interrupt(interrupt_timeout_ms);
        }
    }

    auto poll_deadline = now() + poll_budget;
    while (running()) {
        bool cq_activity = context.process();
        auto current = now();

        if (cq_activity) {
            poll_deadline = current + poll_budget;
        } else if (current >= poll_deadline) {
            break;
        }
    }

    if (!running()) {
        return wakeup_reason;
    }
    return context.wait_for_interrupt(interrupt_timeout_ms);
}

} // namespace worker_thread_detail

#endif // WORKER_THREAD_LOOP_H
