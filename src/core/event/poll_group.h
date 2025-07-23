/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef XLIO_GROUP_H
#define XLIO_GROUP_H

#include <memory>
#include <vector>

#include "sock/fd_collection.h"
#include "xlio.h"

/* Forward declarations */
struct xlio_poll_group_attr;
class event_handler_manager_local;
class ring;
class ring_alloc_logic_attr;
class sockinfo_tcp;
class tcp_timers_collection;

enum poll_group_socket_op {
    POLL_GROUP_SOCKET_INVALID = 0,
    POLL_GROUP_SOCKET_CLOSE,
    POLL_GROUP_SOCKET_DESTROY,
};

class poll_group {
public:
    poll_group(const struct xlio_poll_group_attr &attr);
    ~poll_group();
    static void destroy_all_groups();

    int update(const struct xlio_poll_group_attr *attr);

    void poll();

    void add_dirty_socket(sockinfo_tcp *si);
    void flush();

    void add_ring(ring *rng, ring_alloc_logic_attr *attr);

    void add_socket(sockinfo_tcp *si);
    void remove_socket(sockinfo_tcp *si);
    void reuse_sockfd(int fd, sockinfo_tcp *si);
    void close_socket(sockinfo_tcp *si, bool force = false);
    void mark_socket_to_close(sockinfo_tcp *si);
    void mark_socket_to_destroy(sockinfo_tcp *si);
    unsigned get_flags() const { return m_group_flags; }
    event_handler_manager_local *get_event_handler() const { return m_event_handler.get(); }
    tcp_timers_collection *get_tcp_timers() const { return m_tcp_timers.get(); }

private:
    void slow_path_run();

public:
    xlio_socket_event_cb_t m_socket_event_cb;
    xlio_socket_comp_cb_t m_socket_comp_cb;
    xlio_socket_rx_cb_t m_socket_rx_cb;
    xlio_socket_accept_cb_t m_socket_accept_cb;

private:
    bool m_is_slow_path = false;
    unsigned m_group_flags;

    std::vector<ring *> m_rings;
    std::unique_ptr<event_handler_manager_local> m_event_handler;
    std::unique_ptr<tcp_timers_collection> m_tcp_timers;

    std::vector<sockinfo_tcp *> m_dirty_sockets;
    std::vector<std::pair<enum poll_group_socket_op, sockinfo_tcp *>> m_slow_path_sockets;
    std::list<sockinfo_tcp *> m_pending_to_remove_lst;
    sockinfo_list_t m_sockets_list;
    std::vector<std::pair<std::unique_ptr<ring_alloc_logic_attr>, net_device_val *>> m_rings_ref;
};

#endif /* XLIO_GROUP_H */
