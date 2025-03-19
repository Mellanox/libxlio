
/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "sock_stats.h"

sock_stats *sock_stats::s_instance = nullptr;

void sock_stats::init_instance(size_t max_stats)
{
    if (!s_instance) {
        s_instance = new sock_stats();
        if (max_stats) {
            s_instance->init_sock_stats(max_stats);
        }
    }
}

void sock_stats::destroy_instance()
{
    if (s_instance) {
        delete s_instance;
        s_instance = nullptr;
    }
}

// Calling init_instance() before instance() is a hard requirement.
sock_stats &sock_stats::instance()
{
    return *s_instance;
}

socket_stats_t *sock_stats::get_stats_obj()
{
    std::lock_guard<decltype(_stats_lock)> lock(_stats_lock);

    if (!_socket_stats_list) {
        return nullptr;
    }

    socket_stats_t *stat = _socket_stats_list;
    _socket_stats_list = _socket_stats_list->_next_stat;
    return stat;
}

void sock_stats::return_stats_obj(socket_stats_t *stats)
{
    std::lock_guard<decltype(_stats_lock)> lock(_stats_lock);
    stats->_next_stat = _socket_stats_list;
    _socket_stats_list = stats;
}

void sock_stats::init_sock_stats(size_t max_stats)
{
    std::lock_guard<decltype(_stats_lock)> lock(_stats_lock);

    _socket_stats_vec.resize(max_stats);
    for (size_t idx = 1; idx < _socket_stats_vec.size(); ++idx) {
        _socket_stats_vec[idx - 1U]._next_stat = &_socket_stats_vec[idx];
    }

    _socket_stats_vec[_socket_stats_vec.size() - 1U]._next_stat = nullptr;
    _socket_stats_list = &_socket_stats_vec[0];
}
