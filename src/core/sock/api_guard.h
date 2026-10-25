/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef API_GUARD_H
#define API_GUARD_H

#include "utils/types.h"

/**
 * Exit barrier for intercepted calls (core.syscall.exit_barrier).
 *
 * Applications may call exit() while other threads are still inside intercepted calls. The
 * library destructor then frees sockets and epoll objects that those threads are using. When the
 * barrier is enabled, every intercepted function holds an api_guard for its whole duration, and
 * the guards count the threads that are inside XLIO. At teardown, drain() closes the barrier,
 * wakes threads sleeping inside XLIO, and waits for the count to drop to zero before anything is
 * freed. A guard constructed after the barrier is closed is not counted and reports teardown();
 * its caller must not touch XLIO state and falls back to the OS instead.
 *
 * Only the outermost guard on a thread counts and checks the barrier. Intercepted calls made from
 * inside a counted call (e.g. libibverbs calling ioctl()) keep their XLIO behavior.
 *
 * When the barrier is disabled, a guard costs one test of a global flag.
 */
class api_guard {
public:
    api_guard()
    {
        if (unlikely(s_enabled)) {
            enter();
        }
    }

    ~api_guard()
    {
        if (unlikely(m_counted)) {
            leave();
        }
    }

    api_guard(const api_guard &) = delete;
    api_guard &operator=(const api_guard &) = delete;

    // The barrier is closed: the caller must not touch XLIO state.
    bool teardown() const { return m_teardown; }

    // Stop counting this call. Only for a final OS call that touches no XLIO state and may block.
    void release()
    {
        if (m_counted) {
            leave();
            m_counted = false;
        }
    }

    // Called once from xlio_init(), before the application can create threads that use XLIO.
    static void init(bool enabled);

    // Closes the barrier and waits for counted calls to return. Returns false if XLIO resources
    // must not be freed: the calls did not finish in time, or the barrier was already closed.
    static bool drain();

private:
    void enter();
    void leave();

    static bool s_enabled;

    bool m_counted = false;
    bool m_teardown = false;
};

#endif /* API_GUARD_H */
