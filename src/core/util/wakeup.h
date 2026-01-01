/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef WAKEUP_H
#define WAKEUP_H

/**
 * wakeup class that adds a wakeup functionality to socket (tcp and udp) and epoll.
 */
#include <sys/epoll.h>
#include "utils/lock_wrapper.h"

class wakeup {
public:
    wakeup(void);
    virtual ~wakeup() {};
    virtual bool is_wakeup_fd(int fd) = 0;
    virtual void remove_wakeup_fd() = 0;
    void going_to_sleep();
    void return_from_sleep() { --m_is_sleeping; };
    void wakeup_clear() { m_is_sleeping = 0; }
    void wakeup_set_epoll_fd(int epfd);

protected:
    int m_is_sleeping;
    int m_wakeup_epfd;
    struct epoll_event m_ev;
};

#endif /* WAKEUP_H */
