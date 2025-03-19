/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "proto/flow_tuple.h"
#include "utils/lock_wrapper.h"
#include <unordered_map>
#include <unordered_set>

using namespace std;

#ifndef IP_BIND_ADDRESS_NO_PORT
#define IP_BIND_ADDRESS_NO_PORT 24
#endif

class bind_no_port {
public:
    int bind_and_set_port_map(const sock_addr &src, const sock_addr &dst, int fd);
    void release_port(const sock_addr &src, const sock_addr &dst);

private:
    in_port_t choose_src_port(flow_tuple &tuple);
    int set_src_port_in_db(int fd, in_port_t port, flow_tuple &tuple);
    lock_spin_recursive m_lock;
    unordered_map<in_port_t, unordered_set<flow_tuple>> m_port_tuple_map;
};

extern bind_no_port *g_bind_no_port;
