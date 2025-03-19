/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2023-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "bind_no_port.h"
#include "sock/sock-redirect.h"
#include <mutex>

in_port_t bind_no_port::choose_src_port(flow_tuple &tuple)
{
    for (const auto &item : m_port_tuple_map) {
        auto tuple_iter = item.second.find(tuple);
        if (tuple_iter == item.second.end()) {
            return item.first;
        }
    }
    return INPORT_ANY;
}

int bind_no_port::set_src_port_in_db(int fd, in_port_t port, flow_tuple &tuple)
{
    int ret = 0;

    if (INPORT_ANY == port) {
        sock_addr addr;
        socklen_t addr_len = sizeof(addr);
        if ((ret = SYSCALL(getsockname, fd, addr.get_p_sa(), &addr_len))) {
            return ret;
        }
        port = addr.get_in_port();
    }

    m_port_tuple_map[port].insert(tuple);
    return ret;
}

void bind_no_port::release_port(const sock_addr &src, const sock_addr &dst)
{
    in_port_t port_to_release = src.get_in_port();
    flow_tuple tuple(dst.get_ip_addr(), dst.get_in_port(), src.get_ip_addr(), 0, PROTO_TCP,
                     src.get_sa_family());

    lock_guard<decltype(m_lock)> lock(m_lock);
    if (m_port_tuple_map[port_to_release].find(tuple) != m_port_tuple_map[port_to_release].end()) {
        m_port_tuple_map[port_to_release].erase(tuple);
        if (m_port_tuple_map[port_to_release].size() == 0) {
            m_port_tuple_map.erase(port_to_release);
        }
    }
}

/*  Logic of IP_BIND_ADDRESS_NO_PORT
In case we need a new port from OS, we call bind with port 0,
Otherwise - we call bind with specific port from our DB. */
int bind_no_port::bind_and_set_port_map(const sock_addr &src, const sock_addr &dst, int fd)
{
    int ret = 0;
    sock_addr addr(src);
    socklen_t addr_len = sizeof(addr);
    flow_tuple tuple(dst.get_ip_addr(), dst.get_in_port(), src.get_ip_addr(), 0, PROTO_TCP,
                     src.get_sa_family());

    lock_guard<decltype(m_lock)> lock(m_lock);
    in_port_t chosen_port = choose_src_port(tuple);
    addr.set_in_port(chosen_port);

    if ((ret = SYSCALL(bind, fd, addr.get_p_sa(), addr_len))) {
        return ret;
    }

    return set_src_port_in_db(fd, chosen_port, tuple);
}
