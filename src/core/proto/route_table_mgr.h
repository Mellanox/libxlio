/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-3-Clause
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

#ifndef ROUTE_TABLE_MGR_H
#define ROUTE_TABLE_MGR_H

#include "core/infra/cache_subject_observer.h"
#include "netlink_socket_mgr.h"
#include "route_rule_table_key.h"
#include "route_entry.h"
#include "route_val.h"

#include <unordered_map>
#include <vector>

// Forward declarations
class event;

typedef std::unordered_map<ip_address, route_entry *> in_addr_route_entry_map_t;
typedef std::vector<route_val> route_table_t;

struct route_result {
    uint32_t mtu;
    int if_index;
};

typedef struct {
    uint32_t n_lookup_hit;
    uint32_t n_lookup_miss;
    uint32_t n_updates_newroute;
    uint32_t n_updates_delroute;
    uint32_t n_updates_unhandled;
} route_table_stats_t;

class route_table_mgr : public netlink_socket_mgr,
                        public cache_table_mgr<route_rule_table_key, route_val *>,
                        public observer {
public:
    route_table_mgr();
    virtual ~route_table_mgr();

    bool route_resolve(IN route_rule_table_key key, OUT route_result &res);

    virtual void notify_cb(event *ev) override;

    void dump_tbl();

protected:
    virtual void parse_entry(struct nlmsghdr *nl_header) override;

    route_entry *create_new_entry(route_rule_table_key key, const observer *obs) override;

private:
    // save current main rt table
    void update_tbl(nl_data_t data_type) override;
    void parse_attr(struct rtattr *rt_attribute, route_val &val);
    void print_tbl();

    void update_entry(INOUT route_entry *p_ent, bool b_register_to_net_dev = false);

    void new_route_event(const route_val &netlink_route_val);
    void del_route_event(const route_val &netlink_route_val);

    // IPv4 routing infromation
    route_table_t m_table_in4;
    // IPv6 routing information
    route_table_t m_table_in6;
    // Statistics
    route_table_stats_t m_stats;
};

extern route_table_mgr *g_p_route_table_mgr;

#endif /* ROUTE_TABLE_MGR_H */
