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
 * Account for a completed process call and the idle gap preceding it.
 * All timestamps use the same monotonic clock; counters accumulate nanoseconds.
 *
 * Parameters:
 * - stats: counters providing idle_time, hit_poll_time and job_proc_time fields.
 * - previous_end: end of the preceding accounted call, or context creation time.
 * - start: current call's start timestamp; in continuous polling this is the
 *   preceding call's end timestamp, so loop overhead belongs to the poll phase.
 * - poll_end: event-handler timestamp taken after the current CQ poll.
 * - end: caller's timestamp taken after the current process call returns.
 * - poll_hit: whether the current CQ poll found hardware activity.
 * - jobs_processed: whether the current call processed any queued jobs.
 */
template <typename Stats, typename TimePoint>
void account_process_time(Stats &stats, TimePoint previous_end, TimePoint start, TimePoint poll_end,
                          TimePoint end, bool poll_hit, bool jobs_processed)
{
    using std::chrono::duration_cast;
    using std::chrono::nanoseconds;

    stats.idle_time += duration_cast<nanoseconds>(start - previous_end).count();
    (poll_hit ? stats.hit_poll_time : stats.idle_time) +=
        duration_cast<nanoseconds>(poll_end - start).count();
    (jobs_processed ? stats.job_proc_time : stats.idle_time) +=
        duration_cast<nanoseconds>(end - poll_end).count();
}

/*
 * This is a template so production and tests execute the same scheduling logic
 * without adding virtual methods or test hooks to entity_context. The production
 * specialization is resolved at compile time, so the worker hot path has no
 * interface-dispatch overhead. Tests substitute deterministic context and clock
 * types and therefore need neither a real thread nor hardware nor elapsed wall
 * time.
 *
 * A CQ channel event is only a notification hint. If the verification poll
 * finds no activity, production calls wait_for_interrupt() again; that method
 * always arms CQ notifications and performs one final poll before epoll_wait().
 * This preserves the no-lost-event sleep transition.
 *
 * Production invocation parameters:
 * - context: entity_context; each process call is accounted before waiting
 * - WakeupReason: entity_context::wakeup_reason
 * - wakeup_reason: reason returned by the previous interrupt wait
 * - cq_activity_reason: entity_context::WAKEUP_CQ_ACTIVITY
 * - poll_budget: XLIO_SELECT_POLL converted to microseconds
 * - interrupt_timeout_ms: configured TCP timer resolution
 * - now: callable returning std::chrono::steady_clock::now(); the post-process
 *   timestamp is shared by time accounting and the polling deadline
 * - running: callable reading worker_thread::m_running
 *
 * Test invocation parameters:
 * - context: scripted fake_context recording process and wait calls
 * - WakeupReason: test_wakeup_reason
 * - wakeup_reason/cq_activity_reason: scripted test enum values
 * - poll_budget/interrupt_timeout_ms: test-controlled values
 * - now: callable returning fake_clock::now()
 * - running: test-controlled predicate
 */
template <typename Context, typename WakeupReason, typename Clock, typename Running>
WakeupReason run_interrupt_cycle(Context &context, WakeupReason wakeup_reason,
                                 WakeupReason cq_activity_reason,
                                 std::chrono::microseconds poll_budget, int interrupt_timeout_ms,
                                 Clock now, Running running)
{
    bool cq_activity = (wakeup_reason == cq_activity_reason);
    // Unverified wakeups get one process call before waiting unless it finds activity.
    auto poll_deadline = now() + (cq_activity ? poll_budget : std::chrono::microseconds::zero());
    while (running()) {
        cq_activity = context.process();
        auto current = now();
        context.account_process_time(current);

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
