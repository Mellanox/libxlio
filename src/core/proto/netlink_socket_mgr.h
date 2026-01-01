/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef NETLINK_SOCKET_MGR_H
#define NETLINK_SOCKET_MGR_H
#include <netlink/netlink.h>

// This enum specify the type of data to be retrieve using netlink socket.
enum nl_data_t { RULE_DATA_TYPE, ROUTE_DATA_TYPE };

// This class manages retrieving data (Rule, Route) from kernel using netlink socket.
class netlink_socket_mgr {
protected:
    static bool is_valid_addr(struct nl_addr *addr);
    virtual void parse_entry(struct nl_object *nl_obj) = 0;
    virtual void update_tbl(nl_data_t data_type);

private:
    void parse_tbl(struct nl_cache *cache_state);
};

#endif /* NETLINK_SOCKET_MGR_H */
