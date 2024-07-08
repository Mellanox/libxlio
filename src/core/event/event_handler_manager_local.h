/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef THREAD_LOCAL_EVENT_HANDLER_H
#define THREAD_LOCAL_EVENT_HANDLER_H

#include <chrono>

#include "event_handler_manager.h"
#include "sock/sockinfo.h"

class event_handler_manager_local : public event_handler_manager {
public:
    event_handler_manager_local();

    void add_close_postponed_socket(sockinfo *sock);
    void do_tasks();

protected:
    virtual void post_new_reg_action(reg_action_t &reg_action) override;

private:
    void do_tasks_for_thread_local();

    std::chrono::steady_clock::time_point m_last_run_time;

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
