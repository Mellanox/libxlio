/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <cinttypes>
#include <algorithm>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#include <netlink/route/route.h>
#include <netlink/netlink.h>

#include "utils/bullseye.h"
#include "utils/lock_wrapper.h"
#include "vlogger/vlogger.h"
#include "core/util/vtypes.h"
#include "core/util/utils.h"
#include "core/sock/sockinfo.h"
#include "core/sock/sock-redirect.h"
#include "core/dev/net_device_table_mgr.h"
#include "core/util/ip_address.h"
#include "route_table_mgr.h"
#include "rule_table_mgr.h"

// debugging macros
#define MODULE_NAME        "rtm:"
#define rt_mgr_if_logpanic __log_panic
#define rt_mgr_logerr      __log_err
#define rt_mgr_logwarn     __log_warn
#define rt_mgr_loginfo     __log_info
#define rt_mgr_logdbg      __log_dbg
#define rt_mgr_logfunc     __log_func
#define rt_mgr_logfuncall  __log_funcall

#define DEFAULT_ROUTE_TABLE_SIZE 256
#define MAX_ROUTE_TABLE_SIZE     32768

static inline route_val *find_route_val(route_table_t &table, const ip_address &dst,
                                        uint32_t table_id);
route_table_mgr *g_p_route_table_mgr = nullptr;

route_table_mgr::route_table_mgr()
    : netlink_socket_mgr()
    , cache_table_mgr<route_rule_table_key, route_val *>("route_table_mgr")
{
    rt_mgr_logdbg("");

    memset(&m_stats, 0, sizeof(m_stats));

    m_table_in4.reserve(DEFAULT_ROUTE_TABLE_SIZE);
    m_table_in6.reserve(DEFAULT_ROUTE_TABLE_SIZE);

    // Read Route table from kernel and save it in local variable.
    update_tbl(ROUTE_DATA_TYPE);

    // Print table
    print_tbl();

    // register to netlink event
    g_p_netlink_handler->register_event(nlgrpROUTE, this);
    rt_mgr_logdbg("Registered to g_p_netlink_handler");

    rt_mgr_logdbg("Done");
}

route_table_mgr::~route_table_mgr()
{
    rt_mgr_logdbg("");

    auto cache_itr = m_cache_tbl.begin();
    for (; cache_itr != m_cache_tbl.end(); cache_itr = m_cache_tbl.begin()) {
        delete (cache_itr->second);
        m_cache_tbl.erase(cache_itr);
    }
    rt_mgr_logdbg("Done");
}

void route_table_mgr::dump_tbl()
{
    std::lock_guard<decltype(m_lock)> lock(m_lock);

    auto print_tbl = [&](route_table_t &table, bool print_deleted) {
        size_t active_nr = 0;

        for (auto iter = table.begin(); iter != table.end(); ++iter) {
            if (print_deleted || !iter->is_deleted()) {
                rt_mgr_loginfo("  %s", iter->to_str().c_str());
            }
            active_nr += !iter->is_deleted();
        }
        rt_mgr_loginfo("Total: %zu active and %zu deleted entries.", active_nr,
                       table.size() - active_nr);
        if (table.size() == MAX_ROUTE_TABLE_SIZE) {
            rt_mgr_loginfo("Table is full!");
        }
    };

    rt_mgr_loginfo("Routing table IPv4:");
    print_tbl(m_table_in4, false);
    rt_mgr_loginfo("");
    rt_mgr_loginfo("Routing table IPv6:");
    print_tbl(m_table_in6, false);

    rt_mgr_loginfo("");
    rt_mgr_loginfo("Routing table lookup stats: %u / %u [hit/miss]", m_stats.n_lookup_hit,
                   m_stats.n_lookup_miss);
    rt_mgr_loginfo("Routing table update stats: %u / %u / %u [new/del/unhandled]",
                   m_stats.n_updates_newroute, m_stats.n_updates_delroute,
                   m_stats.n_updates_unhandled);
}

void route_table_mgr::update_tbl(nl_data_t data_type)
{
    std::lock_guard<decltype(m_lock)> lock(m_lock);

    netlink_socket_mgr::update_tbl(data_type);
}

void route_table_mgr::parse_entry(struct nl_object *nl_obj)
{
    route_val val;

    // Cast the generic nl_object to a specific route or rule object
    struct rtnl_route *route = reinterpret_cast<struct rtnl_route *>(nl_obj);

    val.set_family(rtnl_route_get_family(route));
    val.set_protocol(rtnl_route_get_protocol(route));
    val.set_scope(rtnl_route_get_scope(route));
    val.set_type(rtnl_route_get_type(route));

    int table_id = rtnl_route_get_table(route);
    if (table_id > 0) {
        val.set_table_id(table_id);
    }

    // Set destination mask and prefix length
    struct nl_addr *dst = rtnl_route_get_dst(route);
    if (dst) {
        val.set_dst_pref_len(nl_addr_get_prefixlen(dst));
    }

    parse_attr(route, val);

    val.set_state(true);

    route_table_t &table = val.get_family() == AF_INET ? m_table_in4 : m_table_in6;
    table.push_back(val);
}

void route_table_mgr::parse_attr(struct rtnl_route *route, route_val &val)
{
    struct nl_addr *addr;

    // Destination Address
    addr = rtnl_route_get_dst(route);
    if (addr && is_valid_addr(addr)) {
        val.set_dst_addr(ip_address(nl_addr_get_binary_addr(addr), nl_addr_get_family(addr)));
    }

    // Source Address
    addr = rtnl_route_get_pref_src(route);
    if (addr && is_valid_addr(addr)) {
        val.set_src_addr(ip_address(nl_addr_get_binary_addr(addr), nl_addr_get_family(addr)));
    }

    // Metrics (e.g., MTU)
    uint32_t mtu = 0;
    int get_metric_result = rtnl_route_get_metric(route, RTAX_MTU, &mtu);
    if (get_metric_result == 0) {
        if (mtu > 0) {
            val.set_mtu(mtu);
        }
    }

    // Nexthop handling: Extract interface and gateway from nexthops
    // Try foreach_nexthop first for multipath/weight-based selection,
    // then fall back to nexthop_n(0) for routes that don't iterate
    struct nexthop_iterator_context {
        struct rtnl_nexthop *best_next_hop;
        uint8_t best_next_hop_weight;
        sa_family_t family;

    } best_next_hop_context = {.best_next_hop = nullptr,
                               .best_next_hop_weight = 0,
                               .family = static_cast<sa_family_t>(val.get_family())};

    rtnl_route_foreach_nexthop(
        route,
        [](struct rtnl_nexthop *next_hop, void *context) {
            nexthop_iterator_context *ctx = (nexthop_iterator_context *)context;
            const uint8_t current_nh_weight = rtnl_route_nh_get_weight(next_hop);

            // Check gateway - skip link-local gateways as they're not usable for routing
            struct nl_addr *gw = rtnl_route_nh_get_gateway(next_hop);
            if (gw && is_valid_addr(gw)) {
                ip_address gw_ip(nl_addr_get_binary_addr(gw), nl_addr_get_family(gw));
                // Skip link-local gateways (matching old RTA_MULTIPATH behavior)
                if (gw_ip.is_linklocal(ctx->family)) {
                    return;
                }
            }

            // Normalize weight: Linux defaults to 1 when unspecified (weight 0 is non-standard)
            // For multipath routes, select the nexthop with highest weight (most traffic share)
            const uint8_t normalized_weight = (current_nh_weight == 0) ? 1 : current_nh_weight;
            if (normalized_weight > ctx->best_next_hop_weight) {
                ctx->best_next_hop_weight = normalized_weight;
                ctx->best_next_hop = next_hop;
            }
        },
        &best_next_hop_context);

    // If foreach didn't find anything, try direct nexthop access (for routes without iteration)
    struct rtnl_nexthop *nh = best_next_hop_context.best_next_hop;
    if (!nh) {
        nh = rtnl_route_nexthop_n(route, 0);
    }

    if (nh) {
        // Gateway Address
        const auto nh_gateway = rtnl_route_nh_get_gateway(nh);
        if (nh_gateway && is_valid_addr(nh_gateway)) {
            val.set_gw(
                ip_address(nl_addr_get_binary_addr(nh_gateway), nl_addr_get_family(nh_gateway)));
        }

        // Output Interface Index and Name
        const int if_index = rtnl_route_nh_get_ifindex(nh);
        if (if_index > 0) {
            val.set_if_index(if_index);
            char nh_if_name[IFNAMSIZ] = {0};
            if_indextoname(if_index, nh_if_name);
            val.set_if_name(nh_if_name);
        }
    }
}

void route_table_mgr::print_tbl()
{
    if (g_vlogger_level >= VLOG_DEBUG) {
        for (const auto &table_entry : m_table_in6) {
            table_entry.print_val();
        }
        for (const auto &table_entry : m_table_in4) {
            table_entry.print_val();
        }
    }
}

static inline route_val *find_route_val(route_table_t &table, const ip_address &dst,
                                        uint32_t table_id)
{
    int longest_prefix = -1;
    route_val *found {nullptr};

    for (auto &val : table) {
        bool is_valid_entry_with_longer_prefix = !val.is_deleted() &&
            val.get_table_id() == table_id &&
            val.get_dst_addr().is_equal_with_prefix(dst, val.get_dst_pref_len(),
                                                    val.get_family()) &&
            val.get_dst_pref_len() > longest_prefix;

        if (is_valid_entry_with_longer_prefix) {
            longest_prefix = val.get_dst_pref_len();
            found = &val;
        }
    }

    return found;
}

bool route_table_mgr::route_resolve(IN route_rule_table_key key, OUT route_result &res)
{
    rt_mgr_logdbg("key: %s", key.to_str().c_str());

    const ip_address &dst_addr = key.get_dst_ip();
    const sa_family_t family = key.get_family();

    route_table_t &rt = family == AF_INET ? m_table_in4 : m_table_in6;
    route_val *p_val = nullptr;

    auto table_id_list = g_p_rule_table_mgr->rule_resolve(key);

    std::lock_guard<decltype(m_lock)> lock(m_lock);

    for (const auto &table_id : table_id_list) {
        p_val = ::find_route_val(rt, dst_addr, table_id);
        if (p_val) {
            res.mtu = p_val->get_mtu();
            res.if_index = p_val->get_if_index();

            rt_mgr_logdbg("dst ip '%s' resolved to if_index: %d, src-addr: %s, gw-addr: %s, "
                          "route-mtu: %" PRIu32,
                          dst_addr.to_str(family).c_str(), p_val->get_if_index(),
                          p_val->get_src_addr().to_str(family).c_str(),
                          p_val->get_gw_addr().to_str(family).c_str(), p_val->get_mtu());
            ++m_stats.n_lookup_hit;
            return true;
        }
    }

    ++m_stats.n_lookup_miss;
    /* prevent usage on false return */
    return false;
}

void route_table_mgr::update_entry(INOUT route_entry *p_ent, bool b_register_to_net_dev /*= false*/)
{

    std::lock_guard<decltype(m_lock)> lock(m_lock);
    if (p_ent && !p_ent->is_valid()) { // if entry is found in the collection and is not valid
        rt_mgr_logdbg("entry [%p]", p_ent);
        route_table_t &rt = p_ent->get_key().get_family() == AF_INET ? m_table_in4 : m_table_in6;
        rt_mgr_logdbg("route_entry is not valid-> update value");
        rule_entry *p_rr_entry = p_ent->get_rule_entry();
        std::deque<rule_val *> *p_rr_val;
        if (p_rr_entry && p_rr_entry->get_val(p_rr_val)) {
            route_val *p_val = nullptr;
            const ip_address &peer_ip = p_ent->get_key().get_dst_ip();
            for (const auto &p_rule_val : *p_rr_val) {
                uint32_t table_id = p_rule_val->get_table_id();

                if ((p_val = ::find_route_val(rt, peer_ip, table_id))) {
                    p_ent->set_val(p_val);
                    if (b_register_to_net_dev) {
                        // Check if broadcast IPv4 which is NOT supported
                        if ((p_ent->get_key().get_family() == AF_INET) &&
                            (peer_ip == ip_address::broadcast4_addr())) {
                            rt_mgr_logdbg("Disabling Offload for broadcast route_entry '%s'",
                                          p_ent->to_str().c_str());
                            // Need to route traffic to/from OS
                            // Prevent registering of net_device to route entry
                        } else {
                            // register to net device for bonding events
                            p_ent->register_to_net_device();
                        }
                    }
                    // All good, validate the new route entry
                    p_ent->set_entry_valid();
                    break;
                } else {
                    rt_mgr_logdbg("could not find route val for route_entry '%s in table %u'",
                                  p_ent->to_str().c_str(), table_id);
                }
            }
        } else {
            rt_mgr_logdbg("rule entry is not valid");
        }
    }
}

route_entry *route_table_mgr::create_new_entry(route_rule_table_key key, const observer *obs)
{
    // no need for lock - lock is activated in cache_collection_mgr::register_observer

    rt_mgr_logdbg("");
    NOT_IN_USE(obs);
    route_entry *p_ent = new route_entry(key);
    update_entry(p_ent, true);
    rt_mgr_logdbg("new entry %p created successfully", p_ent);
    return p_ent;
}

void route_table_mgr::new_route_event(const route_val &netlink_route_val)
{
    route_val val;

    val.set_dst_addr(netlink_route_val.get_dst_addr());
    val.set_dst_pref_len(netlink_route_val.get_dst_pref_len());
    val.set_src_addr(netlink_route_val.get_src_addr());
    val.set_gw(netlink_route_val.get_gw_addr());
    val.set_family(netlink_route_val.get_family());
    val.set_protocol(netlink_route_val.get_protocol());
    val.set_scope(netlink_route_val.get_scope());
    val.set_type(netlink_route_val.get_type());
    val.set_table_id(netlink_route_val.get_table_id());
    val.set_if_index(netlink_route_val.get_if_index());
    val.set_if_name(const_cast<char *>(netlink_route_val.get_if_name()));
    val.set_mtu((netlink_route_val.get_mtu()));
    val.set_state(true);
    val.print_val();

    std::lock_guard<decltype(m_lock)> lock(m_lock);
    route_table_t &table = val.get_family() == AF_INET ? m_table_in4 : m_table_in6;
    // Search for deleted duplicate routes
    auto iter = table.begin();
    for (; iter != table.end(); ++iter) {
        if (*iter == val && iter->is_deleted()) {
            *iter = val; // Overwrites m_b_deleted
            break;
        }
    }
    // Push new value if there is no deleted duplicate route
    if (iter == table.end() && table.size() < MAX_ROUTE_TABLE_SIZE) {
        table.push_back(val);
    }
}

void route_table_mgr::del_route_event(const route_val &netlink_route_val)
{
    route_table_t &table = netlink_route_val.get_family() == AF_INET ? m_table_in4 : m_table_in6;
    std::lock_guard<decltype(m_lock)> lock(m_lock);

    // We cannot erase elements in the array, because this would invalide pointers
    for (auto iter = table.begin(); iter != table.end(); ++iter) {
        if (*iter == netlink_route_val) {
            (*iter).set_deleted(true);
            break;
        }
    }
}

void route_table_mgr::notify_cb(event *ev)
{
    rt_mgr_logdbg("received route event from netlink");

    route_nl_event *route_netlink_ev = dynamic_cast<route_nl_event *>(ev);
    if (!route_netlink_ev) {
        rt_mgr_logwarn("Received non route event!!!");
        return;
    }

    netlink_route_info *p_netlink_route_info = route_netlink_ev->get_route_info();
    if (!p_netlink_route_info) {
        rt_mgr_logdbg("Received invalid route event!!!");
        return;
    }

    switch (route_netlink_ev->nl_type) {
    case RTM_NEWROUTE:
        new_route_event(p_netlink_route_info->get_route_val());
        ++m_stats.n_updates_newroute;
        break;
    case RTM_DELROUTE:
        del_route_event(p_netlink_route_info->get_route_val());
        ++m_stats.n_updates_delroute;
        break;
    default:
        ++m_stats.n_updates_unhandled;
        rt_mgr_logdbg("Route event (%u) is not handled", route_netlink_ev->nl_type);
        break;
    }
}
