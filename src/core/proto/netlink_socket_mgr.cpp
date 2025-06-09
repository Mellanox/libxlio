/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2022-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "core/util/utils.h"
#include "vlogger/vlogger.h"
#include "utils/bullseye.h"
#include "netlink_socket_mgr.h"

#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <unistd.h> // getpid()

#include <netlink/route/route.h>
#include <netlink/route/rule.h>

#ifndef MODULE_NAME
#define MODULE_NAME "netlink_socket_mgr:"
#endif

// Update data in a table
void netlink_socket_mgr::update_tbl(nl_data_t data_type)
{
    nl_sock *sockfd = nullptr;

    BULLSEYE_EXCLUDE_BLOCK_START

    sockfd = nl_socket_alloc();
    if (sockfd == nullptr) {
        __log_err("NL socket Creation: ");
        throw_xlio_exception("Failed nl_socket_alloc");
    }

    if (nl_connect(sockfd, NETLINK_ROUTE) < 0) {
        __log_err("NL socket Connection: ");
        nl_socket_free(sockfd);
        throw_xlio_exception("Failed nl_connect");
    }

    struct nl_cache *cache_state = {0};
    int err = 0;

    // cache allocation fetches the latest existing rules/routes
    if (data_type == RULE_DATA_TYPE) {
        err = rtnl_rule_alloc_cache(sockfd, AF_INET, &cache_state);
    } else if (data_type == ROUTE_DATA_TYPE) {
        err = rtnl_route_alloc_cache(sockfd, AF_INET, 0, &cache_state);
    }

    if (err < 0) {
        nl_socket_free(sockfd);
        throw_xlio_exception("Failed to allocate route cache");
    }

    parse_tbl(cache_state);

    nl_cache_free(cache_state);
    nl_socket_free(sockfd);
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
