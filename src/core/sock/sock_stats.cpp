
/*
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
