/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <gtest/gtest.h>

#include <chrono>
#include <deque>

#include "core/event/worker_thread_loop.h"

enum test_wakeup_reason {
    TEST_WAKEUP_NONE = 0,
    TEST_WAKEUP_CQ_EVENT,
    TEST_WAKEUP_CQ_ACTIVITY,
    TEST_WAKEUP_JOB_POSTED,
    TEST_WAKEUP_TIMEOUT,
};

class fake_clock {
public:
    using time_point = std::chrono::steady_clock::time_point;

    time_point now() const { return m_now; }
    void advance(std::chrono::microseconds duration) { m_now += duration; }

private:
    time_point m_now {};
};

class fake_context {
public:
    fake_context(fake_clock &clock, std::chrono::microseconds process_duration)
        : m_clock(clock)
        , m_process_duration(process_duration)
    {
    }

    bool process()
    {
        ++process_calls;
        m_clock.advance(m_process_duration);
        if (process_results.empty()) {
            return false;
        }

        bool result = process_results.front();
        process_results.pop_front();
        return result;
    }

    test_wakeup_reason wait_for_interrupt(int timeout_ms)
    {
        ++wait_calls;
        last_timeout_ms = timeout_ms;
        if (wait_results.empty()) {
            return TEST_WAKEUP_NONE;
        }

        test_wakeup_reason result = wait_results.front();
        wait_results.pop_front();
        return result;
    }

    std::deque<bool> process_results;
    std::deque<test_wakeup_reason> wait_results;
    int process_calls = 0;
    int wait_calls = 0;
    int last_timeout_ms = 0;

private:
    fake_clock &m_clock;
    std::chrono::microseconds m_process_duration;
};

TEST(worker_thread_test, unverified_wakeup_processes_once_before_waiting)
{
    const test_wakeup_reason unverified_reasons[] = {
        TEST_WAKEUP_NONE,
        TEST_WAKEUP_CQ_EVENT,
        TEST_WAKEUP_JOB_POSTED,
        TEST_WAKEUP_TIMEOUT,
    };

    for (test_wakeup_reason reason : unverified_reasons) {
        fake_clock clock;
        fake_context context(clock, std::chrono::microseconds(1));
        context.wait_results.push_back(TEST_WAKEUP_TIMEOUT);

        test_wakeup_reason next_reason = worker_thread_detail::run_interrupt_cycle(
            context, reason, TEST_WAKEUP_CQ_ACTIVITY, std::chrono::microseconds(10), 77,
            [&clock] { return clock.now(); }, [] { return true; });

        EXPECT_EQ(TEST_WAKEUP_TIMEOUT, next_reason);
        EXPECT_EQ(1, context.process_calls);
        EXPECT_EQ(1, context.wait_calls);
        EXPECT_EQ(77, context.last_timeout_ms);
    }
}

TEST(worker_thread_test, verified_cq_activity_polls_until_budget_expires)
{
    fake_clock clock;
    fake_context context(clock, std::chrono::microseconds(4));
    context.wait_results.push_back(TEST_WAKEUP_JOB_POSTED);

    test_wakeup_reason next_reason = worker_thread_detail::run_interrupt_cycle(
        context, TEST_WAKEUP_CQ_ACTIVITY, TEST_WAKEUP_CQ_ACTIVITY, std::chrono::microseconds(10),
        77, [&clock] { return clock.now(); }, [] { return true; });

    EXPECT_EQ(TEST_WAKEUP_JOB_POSTED, next_reason);
    EXPECT_EQ(3, context.process_calls);
    EXPECT_EQ(1, context.wait_calls);
}

TEST(worker_thread_test, cq_activity_extends_polling_deadline)
{
    fake_clock clock;
    fake_context context(clock, std::chrono::microseconds(6));
    context.process_results = {true, false, false};
    context.wait_results.push_back(TEST_WAKEUP_TIMEOUT);

    worker_thread_detail::run_interrupt_cycle(
        context, TEST_WAKEUP_CQ_ACTIVITY, TEST_WAKEUP_CQ_ACTIVITY, std::chrono::microseconds(10),
        77, [&clock] { return clock.now(); }, [] { return true; });

    // The hit at 6us moves the deadline from 10us to 16us. Extending the old
    // deadline to 20us would require a fourth process call.
    EXPECT_EQ(3, context.process_calls);
    EXPECT_EQ(1, context.wait_calls);
}

TEST(worker_thread_test, cq_activity_at_expired_deadline_still_extends_polling)
{
    fake_clock clock;
    fake_context context(clock, std::chrono::microseconds(6));
    context.process_results = {false, true, false, false};
    context.wait_results.push_back(TEST_WAKEUP_TIMEOUT);

    worker_thread_detail::run_interrupt_cycle(
        context, TEST_WAKEUP_CQ_ACTIVITY, TEST_WAKEUP_CQ_ACTIVITY, std::chrono::microseconds(10),
        77, [&clock] { return clock.now(); }, [] { return true; });

    // The hit at 12us must move the deadline even though the old 10us deadline
    // has passed.
    EXPECT_EQ(4, context.process_calls);
    EXPECT_EQ(1, context.wait_calls);
}

TEST(worker_thread_test, repeated_cq_activity_repeatedly_extends_polling_deadline)
{
    fake_clock clock;
    fake_context context(clock, std::chrono::microseconds(4));
    context.process_results = {true, true, true, false, false, false};
    context.wait_results.push_back(TEST_WAKEUP_TIMEOUT);

    worker_thread_detail::run_interrupt_cycle(
        context, TEST_WAKEUP_CQ_ACTIVITY, TEST_WAKEUP_CQ_ACTIVITY, std::chrono::microseconds(10),
        77, [&clock] { return clock.now(); }, [] { return true; });

    EXPECT_EQ(6, context.process_calls);
    EXPECT_EQ(1, context.wait_calls);
}

TEST(worker_thread_test, cq_found_after_internal_wakeup_starts_bounded_polling)
{
    fake_clock clock;
    fake_context context(clock, std::chrono::microseconds(4));
    context.process_results.push_back(true);
    context.wait_results.push_back(TEST_WAKEUP_TIMEOUT);

    worker_thread_detail::run_interrupt_cycle(
        context, TEST_WAKEUP_JOB_POSTED, TEST_WAKEUP_CQ_ACTIVITY, std::chrono::microseconds(10), 77,
        [&clock] { return clock.now(); }, [] { return true; });

    EXPECT_EQ(4, context.process_calls);
    EXPECT_EQ(1, context.wait_calls);
}

TEST(worker_thread_test, cq_event_starts_bounded_polling_only_after_poll_finds_activity)
{
    fake_clock clock;
    fake_context context(clock, std::chrono::microseconds(4));
    context.process_results.push_back(true);
    context.wait_results.push_back(TEST_WAKEUP_TIMEOUT);

    worker_thread_detail::run_interrupt_cycle(
        context, TEST_WAKEUP_CQ_EVENT, TEST_WAKEUP_CQ_ACTIVITY, std::chrono::microseconds(10), 77,
        [&clock] { return clock.now(); }, [] { return true; });

    EXPECT_EQ(4, context.process_calls);
    EXPECT_EQ(1, context.wait_calls);
}

TEST(worker_thread_test, stop_after_cq_event_verification_does_not_wait)
{
    fake_clock clock;
    fake_context context(clock, std::chrono::microseconds(1));
    context.process_results.push_back(true);

    test_wakeup_reason next_reason = worker_thread_detail::run_interrupt_cycle(
        context, TEST_WAKEUP_CQ_EVENT, TEST_WAKEUP_CQ_ACTIVITY, std::chrono::microseconds(10), 77,
        [&clock] { return clock.now(); }, [&context] { return context.process_calls == 0; });

    EXPECT_EQ(TEST_WAKEUP_CQ_EVENT, next_reason);
    EXPECT_EQ(1, context.process_calls);
    EXPECT_EQ(0, context.wait_calls);
}

TEST(worker_thread_test, zero_budget_verified_activity_polls_once)
{
    fake_clock clock;
    fake_context context(clock, std::chrono::microseconds(0));
    context.wait_results.push_back(TEST_WAKEUP_TIMEOUT);

    test_wakeup_reason next_reason = worker_thread_detail::run_interrupt_cycle(
        context, TEST_WAKEUP_CQ_ACTIVITY, TEST_WAKEUP_CQ_ACTIVITY, std::chrono::microseconds(0), 77,
        [&clock] { return clock.now(); }, [&context] { return context.process_calls < 2; });

    EXPECT_EQ(TEST_WAKEUP_TIMEOUT, next_reason);
    EXPECT_EQ(1, context.process_calls);
    EXPECT_EQ(1, context.wait_calls);
}

TEST(worker_thread_test, zero_budget_continues_on_activity_until_first_miss)
{
    fake_clock clock;
    fake_context context(clock, std::chrono::microseconds(0));
    context.process_results = {true, true, true, false};
    context.wait_results.push_back(TEST_WAKEUP_TIMEOUT);

    test_wakeup_reason next_reason = worker_thread_detail::run_interrupt_cycle(
        context, TEST_WAKEUP_CQ_EVENT, TEST_WAKEUP_CQ_ACTIVITY, std::chrono::microseconds(0), 77,
        [&clock] { return clock.now(); }, [&context] { return context.process_calls < 6; });

    EXPECT_EQ(TEST_WAKEUP_TIMEOUT, next_reason);
    EXPECT_EQ(4, context.process_calls);
    EXPECT_EQ(1, context.wait_calls);
}

TEST(worker_thread_test, stop_during_bounded_polling_does_not_wait)
{
    fake_clock clock;
    fake_context context(clock, std::chrono::microseconds(1));

    test_wakeup_reason next_reason = worker_thread_detail::run_interrupt_cycle(
        context, TEST_WAKEUP_CQ_ACTIVITY, TEST_WAKEUP_CQ_ACTIVITY, std::chrono::microseconds(100),
        77, [&clock] { return clock.now(); }, [&context] { return context.process_calls < 3; });

    EXPECT_EQ(TEST_WAKEUP_CQ_ACTIVITY, next_reason);
    EXPECT_EQ(3, context.process_calls);
    EXPECT_EQ(0, context.wait_calls);
}

TEST(worker_thread_test, stop_after_processing_does_not_wait)
{
    fake_clock clock;
    fake_context context(clock, std::chrono::microseconds(1));

    test_wakeup_reason next_reason = worker_thread_detail::run_interrupt_cycle(
        context, TEST_WAKEUP_JOB_POSTED, TEST_WAKEUP_CQ_ACTIVITY, std::chrono::microseconds(10), 77,
        [&clock] { return clock.now(); }, [&context] { return context.process_calls == 0; });

    EXPECT_EQ(TEST_WAKEUP_JOB_POSTED, next_reason);
    EXPECT_EQ(1, context.process_calls);
    EXPECT_EQ(0, context.wait_calls);
}
