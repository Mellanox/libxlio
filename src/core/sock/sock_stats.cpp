
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

std::unique_ptr<sock_stats> sock_stats::s_sock_stats;
thread_local socket_stats_t sock_stats::tl_dummy_stats;

sock_stats* sock_stats::get_sock_stats()
{
    if (unlikely(!s_sock_stats)) {
        s_sock_stats.reset(new sock_stats());
    }

    return s_sock_stats.get();
}

socket_stats_t* sock_stats::get_stats_obj()
{
    if (!_socket_stats_first)
        return nullptr;

    std::lock_guard<decltype(_stats_lock)> lock(_stats_lock);
    auto *stat = _socket_stats_first;
    _socket_stats_first = _socket_stats_first->_next_stat;
    return stat;
}

void sock_stats::return_stats_obj(socket_stats_t* stats)
{
    std::lock_guard<decltype(_stats_lock)> lock(_stats_lock);
    stats->_next_stat = _socket_stats_first;
    _socket_stats_first = stats;
}

void sock_stats::init_sock_stats(size_t max_stats)
{
    if (max_stats == 0U) {
        return;
    }

    std::lock_guard<decltype(_stats_lock)> lock(_stats_lock);

    _socket_stats_vec.resize(max_stats);
    for (size_t idx = 1; idx < _socket_stats_vec.size(); ++idx) {
        _socket_stats_vec[idx - 1U]._next_stat = &_socket_stats_vec[idx];
    }

    _socket_stats_vec[_socket_stats_vec.size() - 1U]._next_stat = nullptr;
    _socket_stats_first = &_socket_stats_vec[0];
}