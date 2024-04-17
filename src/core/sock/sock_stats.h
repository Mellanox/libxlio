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

#ifndef SOCK_STATS_H
#define SOCK_STATS_H

#include <vector>
#include <bitset>
#include <mutex>
#include <memory>
#include "util/ip_address.h"
#include "util/xlio_stats.h"

class sock_stats {
public:
    static void init_instance(size_t max_stats);
    static void destroy_instance();
    static sock_stats &instance();

    socket_stats_t *get_stats_obj();
    void return_stats_obj(socket_stats_t *stats);

    static thread_local socket_stats_t t_dummy_stats;

private:
    sock_stats() {}
    void init_sock_stats(size_t max_stats);

    static sock_stats *s_instance;
    std::mutex _stats_lock;
    socket_stats_t *_socket_stats_list = nullptr;
    std::vector<socket_stats_t> _socket_stats_vec;
};

#endif
