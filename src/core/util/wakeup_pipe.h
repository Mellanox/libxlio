/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef WAKEUP_PIPE_H
#define WAKEUP_PIPE_H

/**
 * wakeup class that adds a wakeup functionality to socket (tcp and udp) and epoll using a pipe.
 */
#include "wakeup.h"
#include "utils/atomic.h"

class wakeup_pipe : public wakeup {
public:
    wakeup_pipe(void);
    ~wakeup_pipe();
    // do_wakeup() and remove_wakeup_fd() keep m_wakeup_pending in sync with the
    // epfd registration. The owner must serialize them under the same lock.
    void do_wakeup();
    virtual inline bool is_wakeup_fd(int fd) { return fd == g_wakeup_pipes[0]; };
    virtual void remove_wakeup_fd();
    void force_remove_wakeup_fd(); // DEL; ignores m_is_sleeping

private:
    static int g_wakeup_pipes[2];
    static atomic_t ref_count;
    bool m_wakeup_pending;
};

#endif /* WAKEUP_PIPE_H */
