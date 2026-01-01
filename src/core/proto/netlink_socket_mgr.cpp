/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2022-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "core/util/utils.h"
#include "vlogger/vlogger.h"
#include "utils/bullseye.h"
#include "netlink_socket_mgr.h"

#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <unistd.h> // getpid()

#include <netlink/route/route.h>
#include <netlink/route/rule.h>

bool netlink_socket_mgr::is_valid_addr(struct nl_addr *addr)
{
    if (addr == nullptr) {
        return false;
    }

    const sa_family_t family = nl_addr_get_family(addr);
    const int addr_len = nl_addr_get_len(addr);
    if (addr_len == 0) {
        return false;
    }

    if (family == AF_INET && addr_len != sizeof(in_addr_t)) {
        return false;
    }

    if (family == AF_INET6 && addr_len != sizeof(in6_addr)) {
        return false;
    }

    return true;
}

#ifndef MODULE_NAME
#define MODULE_NAME "netlink_socket_mgr:"
#endif

// Update data in a table
void netlink_socket_mgr::update_tbl(nl_data_t data_type)
{
    nl_sock *sock = nullptr;

    BULLSEYE_EXCLUDE_BLOCK_START

    sock = nl_socket_alloc();
    if (sock == nullptr) {
        __log_err("NL socket Creation: ");
        throw_xlio_exception("Failed nl_socket_alloc");
    }

    if (nl_connect(sock, NETLINK_ROUTE) < 0) {
        __log_err("NL socket Connection: ");
        nl_socket_free(sock);
        throw_xlio_exception("Failed nl_connect");
    }

    struct nl_cache *cache_state = nullptr;
    int err = 0;

    // cache allocation fetches the latest existing rules/routes
    if (data_type == RULE_DATA_TYPE) {
        err = rtnl_rule_alloc_cache(sock, AF_UNSPEC, &cache_state);
    } else if (data_type == ROUTE_DATA_TYPE) {
        err = rtnl_route_alloc_cache(sock, AF_UNSPEC, 0, &cache_state);
    }

    if (err < 0) {
        if (cache_state) {
            nl_cache_free(cache_state);
        }
        nl_socket_free(sock);
        throw_xlio_exception("Failed to allocate route cache");
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    parse_tbl(cache_state);

    nl_cache_free(cache_state);
    nl_socket_free(sock);
}

// Parse received data in a table
void netlink_socket_mgr::parse_tbl(struct nl_cache *cache_state)
{
    // a lambda can't be casted to a c-fptr with ref captures - so we provide context ourselves
    nl_cache_foreach(
        cache_state,
        [](struct nl_object *nl_obj, void *context) {
            netlink_socket_mgr *this_ptr = reinterpret_cast<netlink_socket_mgr *>(context);
            this_ptr->parse_entry(nl_obj);
        },
        this);
}

#undef MODULE_NAME
