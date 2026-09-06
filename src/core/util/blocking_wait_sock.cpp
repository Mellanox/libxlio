/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "util/blocking_wait_sock.h"

#include <sys/epoll.h>

#include "util/wakeup_pipe.h"
#include "sock/sockinfo.h" // SI_RX_EPFD_EVENT_MAX
#include "sock/sock-redirect.h" // SYSCALL()

void blocking_wait_sock_waiter::arm()
{
    m_wakeup_pipe.going_to_sleep();
}

// SYSCALL: m_rx_epfd is XLIO-internal; do not take the interposed epoll_wait().
int blocking_wait_sock_waiter::block(int timeout_ms)
{
    struct epoll_event events[SI_RX_EPFD_EVENT_MAX];
    m_woken_by_wakeup_fd = false;

    const int n = SYSCALL(epoll_wait, m_rx_epfd, events, SI_RX_EPFD_EVENT_MAX, timeout_ms);

    for (int i = 0; i < n; ++i) {
        if (m_wakeup_pipe.is_wakeup_fd(events[i].data.fd)) {
            m_woken_by_wakeup_fd = true;
            break;
        }
    }
    return n;
}

// return_from_sleep() first so the counter is right for the next do_wakeup().
// Force-DEL even if siblings still sleep: skip-DEL livelocks N>=2 unmatched preds.
void blocking_wait_sock_waiter::disarm()
{
    m_wakeup_pipe.return_from_sleep();
    if (m_woken_by_wakeup_fd) {
        m_wakeup_pipe.force_remove_wakeup_fd();
        m_woken_by_wakeup_fd = false;
    }
}

void blocking_wait_sock_waiter::notify()
{
    m_wakeup_pipe.do_wakeup();
}
