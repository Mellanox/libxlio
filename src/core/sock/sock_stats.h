/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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

private:
    sock_stats() {}
    void init_sock_stats(size_t max_stats);

    static sock_stats *s_instance;
    std::mutex _stats_lock;
    socket_stats_t *_socket_stats_list = nullptr;
    std::vector<socket_stats_t> _socket_stats_vec;
};

#endif
