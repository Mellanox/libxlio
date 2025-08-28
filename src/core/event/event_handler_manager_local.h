/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef THREAD_LOCAL_EVENT_HANDLER_H
#define THREAD_LOCAL_EVENT_HANDLER_H

#include <chrono>

#include "event_handler_manager.h"
#include "sock/sockinfo.h"

class event_handler_manager_local : public event_handler_manager {
public:
    typedef std::chrono::steady_clock::time_point time_point;

    event_handler_manager_local();

    void add_close_postponed_socket(sockinfo *sock);
    void do_tasks();
    const time_point &last_taken_time() { return m_last_taken_time; }

protected:
    virtual void post_new_reg_action(reg_action_t &reg_action) override;

private:
    void do_tasks_for_thread_local();

    time_point m_last_run_time;
    time_point m_last_taken_time;
    // When delegate mode is enabled, incoming sockets with failed handshake are not closed
    // immediately because in this mode socket object will be immediately destroyed in the middle of
    // socket processing. This leads to access after destroy in related flows. Instead, we keep the
    // socket in this list and the close() will be invoked as part of timers handling. We reuse the
    // socket_fd_list_node_offset var to build the list, since this var is used for epoll and so
    // guaranteed to be unused for half open sockets as application does not receive the fd for such
    // sockets.
    xlio_list_t<sockinfo, sockinfo::socket_fd_list_node_offset> m_close_postponed_sockets;
};

extern thread_local event_handler_manager_local g_event_handler_manager_local;

#endif
