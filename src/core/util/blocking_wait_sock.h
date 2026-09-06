/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef BLOCKING_WAIT_SOCK_H
#define BLOCKING_WAIT_SOCK_H

class wakeup_pipe;

/**
 * Production waiter for blocking_wait::wait_until().
 * Adapts the socket's wakeup_pipe + m_rx_epfd. Owns no wakeup resources.
 * arm/disarm/notify under the socket lock; block() without it.
 */
class blocking_wait_sock_waiter {
public:
    blocking_wait_sock_waiter(wakeup_pipe &wp, int rx_epfd)
        : m_wakeup_pipe(wp)
        , m_rx_epfd(rx_epfd)
    {
    }

    blocking_wait_sock_waiter(const blocking_wait_sock_waiter &) = delete;
    blocking_wait_sock_waiter &operator=(const blocking_wait_sock_waiter &) = delete;

    void arm();
    int block(int timeout_ms);
    void disarm();
    void notify();

private:
    wakeup_pipe &m_wakeup_pipe;
    int m_rx_epfd;
    // App thread only. If the pipe woke us, force-DEL even if siblings still sleep.
    bool m_woken_by_wakeup_fd = false;
};

#endif /* BLOCKING_WAIT_SOCK_H */
