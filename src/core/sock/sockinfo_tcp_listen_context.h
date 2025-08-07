/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef SOCKINFO_TCP_LISTEN_CONTEXT_H
#define SOCKINFO_TCP_LISTEN_CONTEXT_H

#include <vector>
#include <atomic>
#include <cstddef>
#include <mutex>
#include <condition_variable>

class sockinfo_tcp;

class sockinfo_tcp_listen_context {
public:
    sockinfo_tcp_listen_context();
    ~sockinfo_tcp_listen_context() = default;

    size_t get_listen_rss_children_size() const { return m_listen_rss_children.size(); }
    sockinfo_tcp *get_listen_rss_child(size_t index) { return m_listen_rss_children[index]; }
    void add_listen_rss_child(sockinfo_tcp *rss_child)
    {
        m_listen_rss_children.push_back(rss_child);
    }
    bool listen_rss_children_empty() const { return m_listen_rss_children.empty(); }

    int get_steering_index() const { return m_socketinfo_tcp_listen_steering_index; }
    void set_steering_index(int index) { m_socketinfo_tcp_listen_steering_index = index; }

    bool is_rss_child_listen_socket() const { return m_parent_listen_socket != nullptr; }

    sockinfo_tcp *get_parent_listen_socket() const { return m_parent_listen_socket; }
    void set_parent_listen_socket(sockinfo_tcp *parent) { m_parent_listen_socket = parent; }

    size_t get_round_robin_index() const { return m_round_robin_index; }
    size_t increment_round_robin_index() { return m_round_robin_index++; }

    void increment_finish_counter();
    void increment_error_counter();
    uint16_t get_finish_counter() const { return m_sockinfo_tcp_listen_finish_counter.load(); }
    uint16_t get_error_counter() const { return m_sockinfo_tcp_listen_error_counter.load(); }

    bool wait_for_rss_children_ready();

private:
    sockinfo_tcp *m_parent_listen_socket = nullptr;
    size_t m_round_robin_index = 0;
    std::vector<sockinfo_tcp *> m_listen_rss_children;
    std::atomic_uint16_t m_sockinfo_tcp_listen_finish_counter {0};
    std::atomic_uint16_t m_sockinfo_tcp_listen_error_counter {0};
    int m_socketinfo_tcp_listen_steering_index = -1;
    std::mutex m_ready_mutex;
    std::condition_variable m_ready_condition;
};

#endif /* SOCKINFO_TCP_LISTEN_CONTEXT_H */
