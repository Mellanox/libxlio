/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include <algorithm>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <linux/fib_rules.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#include "utils/bullseye.h"
#include "utils/lock_wrapper.h"
#include "vlogger/vlogger.h"
#include "core/util/vtypes.h"
#include "core/util/utils.h"
#include "core/util/if.h"
#include "core/util/ip_address.h"
#include "rule_table_mgr.h"

// debugging macros
#define MODULE_NAME "rrm:"

#define rr_mgr_if_logpanic __log_panic
#define rr_mgr_logerr      __log_err
#define rr_mgr_logwarn     __log_warn
#define rr_mgr_loginfo     __log_info
#define rr_mgr_logdbg      __log_dbg
#define rr_mgr_logfunc     __log_func
#define rr_mgr_logfuncall  __log_funcall

#define DEFAULT_RULE_TABLE_SIZE 64

rule_table_mgr *g_p_rule_table_mgr = nullptr;
static inline bool is_matching_rule(const route_rule_table_key &key, const rule_val &val);

rule_table_mgr::rule_table_mgr()
    : netlink_socket_mgr()
    , cache_table_mgr<route_rule_table_key, std::deque<rule_val *> *>("rule_table_mgr")
{

    rr_mgr_logdbg("");

    m_table_in4.reserve(DEFAULT_RULE_TABLE_SIZE);
    m_table_in6.reserve(DEFAULT_RULE_TABLE_SIZE);

    // Read Rule table from kernel and save it in local variable.
    update_tbl(RULE_DATA_TYPE);

    // Print table
    print_tbl();

    rr_mgr_logdbg("Done");
}

// This function uses Netlink to get routing rules saved in kernel then saved it locally.
void rule_table_mgr::update_tbl(nl_data_t data_type)
{
    std::lock_guard<decltype(m_lock)> lock(m_lock);

    netlink_socket_mgr::update_tbl(data_type);

    return;
}

// Parse received rule entry into custom object (rule_val).
// Parameters:
//		nl_header	: object that contain rule entry.
//		p_val		: custom object that contain parsed rule data.
// return true if its not related to local or default table, false otherwise.
void rule_table_mgr::parse_entry(struct nlmsghdr *nl_header)
{
    int len;
    struct rtmsg *rt_msg;
    struct rtattr *rt_attribute;
    rule_val val;

    // get rule entry header
    rt_msg = (struct rtmsg *)NLMSG_DATA(nl_header);

    val.set_family(rt_msg->rtm_family);
    val.set_protocol(rt_msg->rtm_protocol);
    val.set_scope(rt_msg->rtm_scope);
    val.set_type(rt_msg->rtm_type);
    val.set_tos(rt_msg->rtm_tos);
    val.set_table_id(rt_msg->rtm_table);

    len = RTM_PAYLOAD(nl_header);
    rt_attribute = (struct rtattr *)RTM_RTA(rt_msg);

    for (; RTA_OK(rt_attribute, len); rt_attribute = RTA_NEXT(rt_attribute, len)) {
        parse_attr(rt_attribute, val);
    }
    val.set_state(true);

    rule_table_t &table = val.get_family() == AF_INET ? m_table_in4 : m_table_in6;
    table.push_back(val);
}

// Parse received rule attribute for given rule.
// Parameters:
//		rt_attribute	: object that contain rule attribute.
//		p_val			: custom object that contain parsed rule data.
void rule_table_mgr::parse_attr(struct rtattr *rt_attribute, rule_val &val)
{
    switch (rt_attribute->rta_type) {
    case FRA_PRIORITY:
        val.set_priority(*(uint32_t *)RTA_DATA(rt_attribute));
        break;
    case FRA_DST:
        val.set_dst_addr(ip_address((void *)RTA_DATA(rt_attribute), val.get_family()));
        break;
    case FRA_SRC:
        val.set_src_addr(ip_address((void *)RTA_DATA(rt_attribute), val.get_family()));
        break;
    case FRA_IFNAME:
        val.set_iif_name((char *)RTA_DATA(rt_attribute));
        break;
    case FRA_TABLE:
        val.set_table_id(*(uint32_t *)RTA_DATA(rt_attribute));
        break;
#if DEFINED_FRA_OIFNAME
    case FRA_OIFNAME:
        val.set_oif_name((char *)RTA_DATA(rt_attribute));
        break;
#endif
    default:
        rr_mgr_logdbg("got undetected rta_type %d %x", rt_attribute->rta_type,
                      *(uint32_t *)RTA_DATA(rt_attribute));
        break;
    }
}

void rule_table_mgr::print_tbl()
{
    if (g_vlogger_level >= VLOG_DEBUG) {
        for (const auto &rule : m_table_in6) {
            rule.print_val();
        }
        for (const auto &rule : m_table_in4) {
            rule.print_val();
        }
    }
}

// Create rule entry object for given destination key and fill it with matching rule value from rule
// table. Parameters:
//		key		: key object that contain information about destination.
//		obs		: object that contain observer for specific rule entry.
//	Returns created rule entry object.
rule_entry *rule_table_mgr::create_new_entry(route_rule_table_key key, const observer *obs)
{
    rr_mgr_logdbg("");
    NOT_IN_USE(obs);
    rule_entry *p_ent = new rule_entry(key);
    update_entry(p_ent);
    rr_mgr_logdbg("new entry %p created successfully", p_ent);
    return p_ent;
}

// Update invalid rule entry with matching rule value from rule table.
// Parameters:
//		p_ent		: rule entry that will be updated if it is invalid.
void rule_table_mgr::update_entry(rule_entry *p_ent)
{
    rr_mgr_logdbg("entry [%p]", p_ent);
    std::lock_guard<decltype(m_lock)> lock(m_lock);

    if (p_ent && !p_ent->is_valid()) { // if entry is found in the collection and is not valid

        rr_mgr_logdbg("rule_entry is not valid-> update value");
        std::deque<rule_val *> *p_rrv;
        p_ent->get_val(p_rrv);
        /* p_rrv->clear(); TODO for future rule live updates */
        if (!find_rule_val(p_ent->get_key(), p_rrv)) {
            rr_mgr_logdbg("ERROR: could not find rule val for rule_entry '%s'",
                          p_ent->to_str().c_str());
        }
    }
}

// Find rule form rule table that match given destination info.
// Parameters:
//		key		: key object that contain information about destination.
//		p_val	: list of rule_val object that will contain information about all rule that match
// destination info
// Returns true if at least one rule match destination info, false otherwise.
bool rule_table_mgr::find_rule_val(const route_rule_table_key &key, std::deque<rule_val *> *p_val)
{
    rr_mgr_logfunc("destination info %s:", key.to_str().c_str());

    rule_table_t &table = key.get_family() == AF_INET ? m_table_in4 : m_table_in6;
    bool found = false;

    for (auto &val : table) {
        if (::is_matching_rule(key, val)) {
            found = true;
            p_val->push_back(&val);
            rr_mgr_logdbg("found rule val: %s", val.to_str().c_str());
        }
    }

    return found;
}

static inline bool is_matching_rule(const route_rule_table_key &key, const rule_val &val)
{
    const ip_address &m_dst_ip = key.get_dst_ip();
    const ip_address &m_src_ip = key.get_src_ip();
    uint8_t m_tos = key.get_tos();

    const ip_address &rule_dst_ip = val.get_dst_addr();
    const ip_address &rule_src_ip = val.get_src_addr();
    uint8_t rule_tos = val.get_tos();
    const char *rule_iif_name = val.get_iif_name();
    const char *rule_oif_name = val.get_oif_name();

    // Only destination IP, source IP and TOS are checked with rule, since IIF and OIF is not filled
    // in dst_entry object.
    return val.is_valid() &&
        // Check match in address family
        (val.get_family() == key.get_family()) &&
        // Check match in destination IP
        ((rule_dst_ip.is_anyaddr()) || (rule_dst_ip == m_dst_ip)) &&
        // Check match in source IP
        ((rule_src_ip.is_anyaddr()) || (rule_src_ip == m_src_ip)) &&
        // Check match in TOS value
        ((rule_tos == 0) || (rule_tos == m_tos)) &&
        // Check that rule doesn't contain IIF since we can't check match with
        (strcmp(rule_iif_name, "") == 0) &&
        // Check that rule doesn't contain OIF since we can't check match with
        (strcmp(rule_oif_name, "") == 0);
}

// Find table ID for given destination info.
// Parameters:
//		key			: key object that contain information about destination.
// Returns a collection of rule table IDs sorted by priority
std::vector<uint32_t> rule_table_mgr::rule_resolve(route_rule_table_key key)
{
    rr_mgr_logdbg("dst info: '%s'", key.to_str().c_str());

    std::vector<uint32_t> res;
    std::deque<rule_val *> values;

    {
        std::lock_guard<decltype(m_lock)> lock(m_lock);
        if (!find_rule_val(key, &values)) {
            return res;
        }
    }
    std::sort(values.begin(), values.end(), [](const rule_val *rhs, const rule_val *lhs) {
        return rhs->get_priority() < lhs->get_priority();
    });
    res.reserve(values.size());
    std::transform(values.begin(), values.end(), std::back_inserter(res),
                   [](rule_val *rule) { return rule->get_table_id(); });

    return res;
}
