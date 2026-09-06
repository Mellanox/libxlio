/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/*
 * blocking_wait::wait_until() with a mutex and a sticky self-pipe waiter.
 * No socket, ring, NIC, or XLIO preload.
 */

#include "common/def.h"

#include "util/blocking_wait.h"
#include "util/blocking_wait_sock.h"

#include <sys/epoll.h>
#include <unistd.h>
#include <cerrno>

#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>

using ms = std::chrono::milliseconds;

static long elapsed_ms(std::chrono::steady_clock::time_point start)
{
    return std::chrono::duration_cast<ms>(std::chrono::steady_clock::now() - start).count();
}

class test_waiter {
public:
    test_waiter()
    {
        m_epfd = ::epoll_create1(EPOLL_CLOEXEC);
        if (::pipe(m_pipe) != 0) {
            m_pipe[0] = m_pipe[1] = -1;
        } else {
            // Sticky token, like wakeup_pipe's "^" byte. Never drained.
            const ssize_t n = ::write(m_pipe[1], "^", 1);
            (void)n;
        }
    }

    ~test_waiter()
    {
        if (m_epfd >= 0) {
            ::close(m_epfd);
        }
        if (m_pipe[0] >= 0) {
            ::close(m_pipe[0]);
        }
        if (m_pipe[1] >= 0) {
            ::close(m_pipe[1]);
        }
    }

    test_waiter(const test_waiter &) = delete;
    test_waiter &operator=(const test_waiter &) = delete;

    void arm() { m_armed = true; }

    int block(int timeout_ms)
    {
        struct epoll_event evs[4];
        m_woken_by_watched_fd = false;
        const int count = ::epoll_wait(m_epfd, evs, 4, timeout_ms);

        for (int index = 0; index < count; ++index) {
            if (evs[index].data.fd == m_watched_fd) {
                m_woken_by_watched_fd = true;
            }
        }
        return count;
    }

    void disarm()
    {
        m_armed = false;
        // ENOENT if the pipe was never armed - same as remove_wakeup_fd().
        ::epoll_ctl(m_epfd, EPOLL_CTL_DEL, m_pipe[0], nullptr);
    }

    void notify()
    {
        if (!m_armed) {
            return;
        }
        struct epoll_event ev = {};
        ev.events = EPOLLIN;
        ev.data.fd = m_pipe[0];
        // EEXIST if already armed - same as do_wakeup().
        ::epoll_ctl(m_epfd, EPOLL_CTL_ADD, m_pipe[0], &ev);
    }

    bool watch_fd(int fd)
    {
        struct epoll_event ev = {};

        ev.events = EPOLLIN;
        ev.data.fd = fd;
        m_watched_fd = fd;
        return ::epoll_ctl(m_epfd, EPOLL_CTL_ADD, fd, &ev) == 0;
    }

    bool was_woken_by_watched_fd() const { return m_woken_by_watched_fd; }

private:
    int m_epfd = -1;
    int m_pipe[2] = {-1, -1};
    int m_watched_fd = -1;
    bool m_armed = false;
    bool m_woken_by_watched_fd = false;
};

// Production waiter: one wakeup_pipe + one m_rx_epfd + m_is_sleeping. Pipe byte stays unread.
class sticky_wake_pipe {
public:
    sticky_wake_pipe()
    {
        m_epfd = ::epoll_create1(EPOLL_CLOEXEC);
        if (::pipe(m_pipe) != 0) {
            m_pipe[0] = m_pipe[1] = -1;
        } else {
            const ssize_t n = ::write(m_pipe[1], "^", 1);
            (void)n;
        }
    }

    ~sticky_wake_pipe()
    {
        if (m_epfd >= 0) {
            ::close(m_epfd);
        }
        if (m_pipe[0] >= 0) {
            ::close(m_pipe[0]);
        }
        if (m_pipe[1] >= 0) {
            ::close(m_pipe[1]);
        }
    }

    sticky_wake_pipe(const sticky_wake_pipe &) = delete;
    sticky_wake_pipe &operator=(const sticky_wake_pipe &) = delete;

    void going_to_sleep() { ++m_is_sleeping; }
    void return_from_sleep() { --m_is_sleeping; }

    void do_wakeup()
    {
        if (!m_is_sleeping) {
            return;
        }
        struct epoll_event ev = {};
        ev.events = EPOLLIN;
        ev.data.fd = m_pipe[0];
        ::epoll_ctl(m_epfd, EPOLL_CTL_ADD, m_pipe[0], &ev);
    }

    void remove_wakeup_fd()
    {
        // Force-DEL even if siblings still sleep. Skip-DEL while count!=0 livelocks.
        ::epoll_ctl(m_epfd, EPOLL_CTL_DEL, m_pipe[0], nullptr);
    }

    int epfd() const { return m_epfd; }
    int pipe_rd() const { return m_pipe[0]; }

private:
    int m_epfd = -1;
    int m_pipe[2] = {-1, -1};
    int m_is_sleeping = 0;
};

class sticky_wake_waiter {
public:
    sticky_wake_waiter(sticky_wake_pipe &pipe, std::atomic<int> &block_calls,
                       std::atomic<int> &in_block)
        : m_pipe(pipe)
        , m_block_calls(block_calls)
        , m_in_block(in_block)
    {
    }

    void arm() { m_pipe.going_to_sleep(); }

    int block(int timeout_ms)
    {
        m_in_block.fetch_add(1, std::memory_order_release);
        m_block_calls.fetch_add(1, std::memory_order_relaxed);
        struct epoll_event evs[4];
        m_woken_by_wakeup_fd = false;
        const int n = ::epoll_wait(m_pipe.epfd(), evs, 4, timeout_ms);
        for (int i = 0; i < n; ++i) {
            if (evs[i].data.fd == m_pipe.pipe_rd()) {
                m_woken_by_wakeup_fd = true;
            }
        }
        m_in_block.fetch_sub(1, std::memory_order_release);
        return n;
    }

    void disarm()
    {
        m_pipe.return_from_sleep();
        if (m_woken_by_wakeup_fd) {
            m_pipe.remove_wakeup_fd();
            m_woken_by_wakeup_fd = false;
        }
    }

    void notify() { m_pipe.do_wakeup(); }

private:
    sticky_wake_pipe &m_pipe;
    std::atomic<int> &m_block_calls;
    std::atomic<int> &m_in_block;
    bool m_woken_by_wakeup_fd = false;
};

TEST(blocking_wait, ready_without_sleep_when_condition_true)
{
    test_waiter w;
    std::mutex lock;
    bool ready = true;

    lock.lock();
    blocking_wait::result r = blocking_wait::wait_until(lock, w, [&] { return ready; }, 1000);
    lock.unlock();

    EXPECT_EQ(blocking_wait::result::READY, r);
}

TEST(blocking_wait, timeout_when_condition_stays_false)
{
    test_waiter w;
    std::mutex lock;
    bool ready = false;

    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    lock.lock();
    blocking_wait::result r = blocking_wait::wait_until(lock, w, [&] { return ready; }, 100);
    lock.unlock();
    long took = elapsed_ms(start);

    EXPECT_EQ(blocking_wait::result::TIMEOUT, r);
    EXPECT_GE(took, 90); // did actually wait
    EXPECT_LT(took, 2000); // but not forever
}

TEST(blocking_wait, worker_wakes_sleeping_app)
{
    test_waiter w;
    std::mutex lock;
    bool ready = false;

    std::thread worker([&] {
        std::this_thread::sleep_for(ms(100));
        std::lock_guard<std::mutex> g(lock);
        ready = true;
        w.notify();
    });

    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    lock.lock();
    blocking_wait::result r = blocking_wait::wait_until(lock, w, [&] { return ready; }, 5000);
    lock.unlock();
    long took = elapsed_ms(start);

    worker.join();

    EXPECT_EQ(blocking_wait::result::READY, r);
    // Lost wakeup would land near the 5s timeout, not ~100ms after notify.
    EXPECT_LT(took, 2000);
}

// Shadow-listener readiness must be pred, not a spurious wake.
TEST(blocking_wait, watched_external_fd_returns_control)
{
    test_waiter w;
    std::mutex lock;
    int external_pipe[2] = {-1, -1};

    ASSERT_EQ(0, ::pipe(external_pipe));
    ASSERT_TRUE(w.watch_fd(external_pipe[0]));

    std::thread producer([&] {
        std::this_thread::sleep_for(ms(100));
        const ssize_t written = ::write(external_pipe[1], "x", 1);
        (void)written;
    });

    lock.lock();
    const blocking_wait::result r = blocking_wait::wait_until(
        lock, w, [&] { return w.was_woken_by_watched_fd(); }, 2000);
    lock.unlock();

    producer.join();
    EXPECT_EQ(blocking_wait::result::READY, r);
    EXPECT_TRUE(w.was_woken_by_watched_fd());
    ::close(external_pipe[0]);
    ::close(external_pipe[1]);
}

TEST(blocking_wait, no_lost_wakeup_when_signaled_in_check_sleep_window)
{
    const int iterations = 200;
    const int timeout_ms = 2000;

    for (int i = 0; i < iterations; ++i) {
        test_waiter w;
        std::mutex lock;
        bool ready = false;
        std::atomic<bool> worker_started(false);

        // App holds the lock first; worker cannot make-ready+notify until wait_until()
        // arms and unlocks - the lost-wakeup window.
        lock.lock();

        std::thread worker([&] {
            worker_started.store(true, std::memory_order_release);
            std::lock_guard<std::mutex> g(lock);
            ready = true;
            w.notify();
        });

        while (!worker_started.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        // Let the worker reach lock() before we enter wait_until().
        std::this_thread::sleep_for(ms(1));

        std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
        blocking_wait::result r = blocking_wait::wait_until(
            lock, w, [&] { return ready; }, timeout_ms);
        lock.unlock();
        long took = elapsed_ms(start);

        worker.join();

        ASSERT_EQ(blocking_wait::result::READY, r) << "lost wakeup at iteration " << i;
        ASSERT_LT(took, 1000) << "woken by timeout, not by notify, at iteration " << i;
    }
}

TEST(blocking_wait, infinite_wait_returns_ready_on_late_notify)
{
    test_waiter w;
    std::mutex lock;
    bool ready = false;
    const int notify_after_ms = 250;

    std::thread worker([&] {
        std::this_thread::sleep_for(ms(notify_after_ms));
        std::lock_guard<std::mutex> g(lock);
        ready = true;
        w.notify();
    });

    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    lock.lock();
    blocking_wait::result r = blocking_wait::wait_until(
        lock, w, [&] { return ready; }, -1);
    lock.unlock();
    long took = elapsed_ms(start);

    worker.join();

    EXPECT_EQ(blocking_wait::result::READY, r);
    EXPECT_GE(took, notify_after_ms - 20);
    EXPECT_LT(took, 5000);
}

TEST(blocking_wait, timeout_honors_user_deadline)
{
    test_waiter w;
    std::mutex lock;
    bool ready = false;
    const int user_timeout_ms = 250;

    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    lock.lock();
    blocking_wait::result r = blocking_wait::wait_until(
        lock, w, [&] { return ready; }, user_timeout_ms);
    lock.unlock();
    long took = elapsed_ms(start);

    EXPECT_EQ(blocking_wait::result::TIMEOUT, r);
    EXPECT_GE(took, user_timeout_ms - 10);
    EXPECT_LT(took, 5000);
}

// N>=2 waiters, notify matches no pred. Skip-DEL while count!=0 turns block() into a hot loop.
TEST(blocking_wait, two_waiters_unmatched_notify_parks_not_spins)
{
    sticky_wake_pipe pipe;
    std::mutex lock;
    std::atomic<int> block_calls(0);
    std::atomic<int> in_block(0);
    sticky_wake_waiter w1(pipe, block_calls, in_block);
    sticky_wake_waiter w2(pipe, block_calls, in_block);
    const int timeout_ms = 200;

    auto run = [&](sticky_wake_waiter &w) {
        lock.lock();
        (void)blocking_wait::wait_until(
            lock, w, [] { return false; }, timeout_ms);
        lock.unlock();
    };

    std::thread t1([&] { run(w1); });
    std::thread t2([&] { run(w2); });

    while (in_block.load(std::memory_order_acquire) < 2) {
        std::this_thread::yield();
    }
    {
        std::lock_guard<std::mutex> g(lock);
        pipe.do_wakeup();
    }

    t1.join();
    t2.join();

    // Park: one wait per waiter. Spin: thousands of immediate epoll_wait returns.
    EXPECT_LT(block_calls.load(std::memory_order_relaxed), 20);
}

// Pins blocking_wait_sock_waiter::block()'s event scan directly (real epoll_wait cannot force
// the batch ordering). A wakeup fd ahead of the watched fd must still flag the watched fd; a
// break after the wakeup fd would leave was_woken_by_watched_fd() false and drop accept wakeups.
TEST(blocking_wait_sock, classify_flags_both_when_wakeup_precedes_watched)
{
    const int wakeup_fd = 7;
    const int watched_fd = 9;
    struct epoll_event evs[2] = {};
    evs[0].data.fd = wakeup_fd;
    evs[1].data.fd = watched_fd;

    bool woken_wakeup = false;
    bool woken_watched = false;
    classify_wake_events(
        evs, 2, [&](int fd) { return fd == wakeup_fd; }, watched_fd, woken_wakeup, woken_watched);

    EXPECT_TRUE(woken_wakeup);
    EXPECT_TRUE(woken_watched);
}

TEST(blocking_wait_sock, classify_flags_both_when_watched_precedes_wakeup)
{
    const int wakeup_fd = 7;
    const int watched_fd = 9;
    struct epoll_event evs[2] = {};
    evs[0].data.fd = watched_fd;
    evs[1].data.fd = wakeup_fd;

    bool woken_wakeup = false;
    bool woken_watched = false;
    classify_wake_events(
        evs, 2, [&](int fd) { return fd == wakeup_fd; }, watched_fd, woken_wakeup, woken_watched);

    EXPECT_TRUE(woken_wakeup);
    EXPECT_TRUE(woken_watched);
}

TEST(blocking_wait_sock, classify_isolates_wakeup_and_watched)
{
    const int wakeup_fd = 7;
    const int watched_fd = 9;
    bool woken_wakeup = false;
    bool woken_watched = false;

    struct epoll_event watched_only[1] = {};
    watched_only[0].data.fd = watched_fd;
    classify_wake_events(watched_only, 1, [&](int fd) { return fd == wakeup_fd; }, watched_fd,
                         woken_wakeup, woken_watched);
    EXPECT_FALSE(woken_wakeup);
    EXPECT_TRUE(woken_watched);

    struct epoll_event wakeup_only[1] = {};
    wakeup_only[0].data.fd = wakeup_fd;
    classify_wake_events(wakeup_only, 1, [&](int fd) { return fd == wakeup_fd; }, watched_fd,
                         woken_wakeup, woken_watched);
    EXPECT_TRUE(woken_wakeup);
    EXPECT_FALSE(woken_watched);
}
