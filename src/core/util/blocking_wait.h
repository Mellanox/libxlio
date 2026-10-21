/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef BLOCKING_WAIT_H
#define BLOCKING_WAIT_H

#include <cerrno>
#include <chrono>

/**
 * App-thread park / worker-thread wake for worker-threads mode.
 * wait_until() is the one check-then-sleep loop: pred, arm, unlock, block,
 * relock, disarm, re-check.
 *
 * Lost-wakeup: pred() and waiter.arm() run in the same locked critical section
 * (no unlock between them). The worker takes that same lock, makes the
 * condition true, then posts the sticky token (wakeup_pipe::do_wakeup()).
 * block() runs unlocked so the worker can proceed. A wake between unlock and
 * block() still unblocks. Spurious wakes re-check pred().
 *
 * wait_until() is arm / block / disarm only; it never calls notify().
 * waiter.notify() is do_wakeup() when the caller has a Waiter (tests).
 * Production wakes have the socket pipe, not the stack Waiter.
 *
 * Parking matches R2C: one block() for the caller deadline (SO_RCVTIMEO /
 * SO_SNDTIMEO leftover), or -1 when timeout_ms < 0. Slice expiry is not a
 * timeout. timeout_ms < 0 never returns TIMEOUT. Silent g_b_exit with no
 * notify hangs like R2C until teardown wakeup or EINTR.
 *
 * Contract: caller holds lock on entry; wait_until() returns still holding it.
 * pred runs under lock. Worker do_wakeup() uses the same lock, after the
 * condition is true. Waiter is duck-typed (arm/block/disarm/notify).
 */
class blocking_wait {
public:
    enum class result {
        READY, // predicate satisfied
        TIMEOUT, // deadline elapsed with predicate still false
        INTERRUPTED, // block() interrupted by a signal (EINTR) and predicate still false
        ERROR, // unexpected error in block() (errno set)
    };

    template <typename Lock, typename Waiter, typename Pred>
    static result wait_until(Lock &lock, Waiter &waiter, Pred pred, int timeout_ms)
    {
        using clock = std::chrono::steady_clock;
        const bool infinite = (timeout_ms < 0);
        const clock::time_point deadline =
            infinite ? clock::time_point() : clock::now() + std::chrono::milliseconds(timeout_ms);

        for (;;) {
            if (pred()) {
                return result::READY;
            }

            int wait_ms = -1;
            if (!infinite) {
                const clock::time_point now = clock::now();
                if (now >= deadline) {
                    return result::TIMEOUT;
                }
                int remaining_ms = static_cast<int>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
                // now < deadline; sub-ms remainder truncates to 0. block(0) busy-spins.
                if (remaining_ms == 0) {
                    remaining_ms = 1;
                }
                wait_ms = remaining_ms;
            }

            waiter.arm();
            lock.unlock();
            const int r = waiter.block(wait_ms);
            lock.lock();
            waiter.disarm();

            // READY beats timeout / EINTR.
            if (pred()) {
                return result::READY;
            }
            if (r < 0) {
                return (errno == EINTR) ? result::INTERRUPTED : result::ERROR;
            }
        }
    }
};

#endif /* BLOCKING_WAIT_H */
