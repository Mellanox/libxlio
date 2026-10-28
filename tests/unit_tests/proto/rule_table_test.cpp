/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "core/util/ip_address.h"
#include "core/proto/rule_table_mgr.h"

#include <gtest/gtest.h>

#include <netlink/addr.h>
#include <netlink/route/rule.h>

#include <algorithm>
#include <arpa/inet.h>
#include <vector>

/*
 * rule_table_mgr is linked into this hardware-free unit-test target. Its
 * constructor dumps the live rule table over netlink (a read-only request),
 * so a manager instance may also hold the host's own rules. The tests stay
 * independent of host state: they feed synthetic libnl rule objects through
 * parse_entry(), including their own fallback rules, and assert only on
 * table ids in the 10157-10166 range that no host configuration uses.
 *
 * The cache-table garbage collector is never started here; stub the
 * event-handler timer registration it would otherwise need.
 */

#include "core/event/event_handler_manager.h"

event_handler_manager *g_p_event_handler_manager = nullptr;

void *event_handler_manager::register_timer_event(int, timer_handler *, timer_req_type_t, void *)
{
    return nullptr;
}

void event_handler_manager::unregister_timer_event(timer_handler *, void *)
{
}

class rule_table_mgr_under_test : public rule_table_mgr {
public:
    void parse(struct rtnl_rule *rule) { parse_entry(reinterpret_cast<struct nl_object *>(rule)); }
};

namespace {

struct rtnl_rule *make_rule(int family, uint32_t table, uint32_t prio)
{
    struct rtnl_rule *rule = rtnl_rule_alloc();
    rtnl_rule_set_family(rule, family);
    rtnl_rule_set_table(rule, table);
    rtnl_rule_set_prio(rule, prio);
    rtnl_rule_set_action(rule, FR_ACT_TO_TBL);
    return rule;
}

void rule_set_src(struct rtnl_rule *rule, int family, const char *cidr)
{
    struct nl_addr *addr = nullptr;
    ASSERT_EQ(0, nl_addr_parse(cidr, family, &addr));
    ASSERT_EQ(0, rtnl_rule_set_src(rule, addr));
    nl_addr_put(addr);
}

void rule_set_dst(struct rtnl_rule *rule, int family, const char *cidr)
{
    struct nl_addr *addr = nullptr;
    ASSERT_EQ(0, nl_addr_parse(cidr, family, &addr));
    ASSERT_EQ(0, rtnl_rule_set_dst(rule, addr));
    nl_addr_put(addr);
}

ip_address make_ip(int family, const char *str)
{
    if (family == AF_INET) {
        in_addr a;
        EXPECT_EQ(1, inet_pton(AF_INET, str, &a));
        return ip_address(a);
    }
    in6_addr a6;
    EXPECT_EQ(1, inet_pton(AF_INET6, str, &a6));
    return ip_address(a6);
}

route_rule_table_key make_key(int family, const char *dst, const char *src)
{
    ip_address dst_ip = dst ? make_ip(family, dst) : ip_address(in6addr_any);
    ip_address src_ip = src ? make_ip(family, src) : ip_address(in6addr_any);
    return route_rule_table_key(dst_ip, src_ip, family, 0);
}

bool contains(const std::vector<uint32_t> &tables, uint32_t id)
{
    return std::find(tables.begin(), tables.end(), id) != tables.end();
}

} // namespace

TEST(rule_table_mgr, fwmark_rule_does_not_match_unmarked_lookup)
{
    rule_table_mgr_under_test mgr;

    // Kernel dump shape for 'ip rule add fwmark 1': mark with a full mask.
    struct rtnl_rule *rule = make_rule(AF_INET, 10157, 100);
    rtnl_rule_set_mark(rule, 1);
    rtnl_rule_set_mask(rule, 0xFFFFFFFFU);
    mgr.parse(rule);
    rtnl_rule_put(rule);

    // An unconditional fallback with a higher priority number: the walk must
    // skip the marked rule and still reach this one.
    struct rtnl_rule *fallback = make_rule(AF_INET, 10164, 300);
    mgr.parse(fallback);
    rtnl_rule_put(fallback);

    std::vector<uint32_t> tables = mgr.rule_resolve(make_key(AF_INET, "8.8.8.8", nullptr));
    EXPECT_FALSE(contains(tables, 10157));
    EXPECT_TRUE(contains(tables, 10164));
}

TEST(rule_table_mgr, zero_mask_mark_rule_matches_unmarked_lookup)
{
    rule_table_mgr_under_test mgr;

    // 'ip rule add fwmark 5/0': a zero mask matches every flow, like the kernel.
    struct rtnl_rule *rule = make_rule(AF_INET, 10163, 106);
    rtnl_rule_set_mark(rule, 5);
    rtnl_rule_set_mask(rule, 0);
    mgr.parse(rule);
    rtnl_rule_put(rule);

    std::vector<uint32_t> tables = mgr.rule_resolve(make_key(AF_INET, "8.8.8.8", nullptr));
    EXPECT_TRUE(contains(tables, 10163));
}

TEST(rule_table_mgr, unmarked_rule_matches_every_lookup)
{
    rule_table_mgr_under_test mgr;

    struct rtnl_rule *rule = make_rule(AF_INET, 10158, 101);
    mgr.parse(rule);
    rtnl_rule_put(rule);

    std::vector<uint32_t> tables = mgr.rule_resolve(make_key(AF_INET, "8.8.8.8", nullptr));
    EXPECT_TRUE(contains(tables, 10158));
}

TEST(rule_table_mgr, src_prefix_rule_matches_whole_subnet)
{
    rule_table_mgr_under_test mgr;

    struct rtnl_rule *rule = make_rule(AF_INET, 10159, 102);
    rule_set_src(rule, AF_INET, "10.77.0.0/16");
    mgr.parse(rule);
    rtnl_rule_put(rule);

    // Any source inside the /16 matches, not only the network address.
    std::vector<uint32_t> tables = mgr.rule_resolve(make_key(AF_INET, "8.8.8.8", "10.77.1.2"));
    EXPECT_TRUE(contains(tables, 10159));

    // A source outside the /16 does not match.
    tables = mgr.rule_resolve(make_key(AF_INET, "8.8.8.8", "10.78.1.2"));
    EXPECT_FALSE(contains(tables, 10159));

    // A lookup with an unspecified source does not match a from-rule.
    tables = mgr.rule_resolve(make_key(AF_INET, "8.8.8.8", nullptr));
    EXPECT_FALSE(contains(tables, 10159));
}

TEST(rule_table_mgr, dst_prefix_rule_matches_whole_subnet)
{
    rule_table_mgr_under_test mgr;

    struct rtnl_rule *rule = make_rule(AF_INET, 10160, 103);
    rule_set_dst(rule, AF_INET, "198.51.0.0/16");
    mgr.parse(rule);
    rtnl_rule_put(rule);

    std::vector<uint32_t> tables = mgr.rule_resolve(make_key(AF_INET, "198.51.100.7", nullptr));
    EXPECT_TRUE(contains(tables, 10160));

    tables = mgr.rule_resolve(make_key(AF_INET, "198.52.100.7", nullptr));
    EXPECT_FALSE(contains(tables, 10160));
}

TEST(rule_table_mgr, exact_src_rule_remains_exact)
{
    rule_table_mgr_under_test mgr;

    struct rtnl_rule *rule = make_rule(AF_INET, 10161, 104);
    rule_set_src(rule, AF_INET, "10.9.9.9/32");
    mgr.parse(rule);
    rtnl_rule_put(rule);

    std::vector<uint32_t> tables = mgr.rule_resolve(make_key(AF_INET, "8.8.8.8", "10.9.9.9"));
    EXPECT_TRUE(contains(tables, 10161));

    tables = mgr.rule_resolve(make_key(AF_INET, "8.8.8.8", "10.9.9.8"));
    EXPECT_FALSE(contains(tables, 10161));
}

TEST(rule_table_mgr, zero_network_src_prefix_is_not_unconditional)
{
    rule_table_mgr_under_test mgr;

    // 'from 0.0.0.0/8': the network address is all zeros, but the rule still
    // selects only the 0.0.0.0/8 subnet, like the kernel.
    struct rtnl_rule *rule = make_rule(AF_INET, 10165, 107);
    rule_set_src(rule, AF_INET, "0.0.0.0/8");
    mgr.parse(rule);
    rtnl_rule_put(rule);

    std::vector<uint32_t> tables = mgr.rule_resolve(make_key(AF_INET, "8.8.8.8", "0.1.2.3"));
    EXPECT_TRUE(contains(tables, 10165));

    tables = mgr.rule_resolve(make_key(AF_INET, "8.8.8.8", "10.1.2.3"));
    EXPECT_FALSE(contains(tables, 10165));
}

TEST(rule_table_mgr, zero_network_dst_prefix_is_not_unconditional_ipv6)
{
    rule_table_mgr_under_test mgr;

    // 'to ::/1' selects only the lower half of the IPv6 space.
    struct rtnl_rule *rule = make_rule(AF_INET6, 10166, 108);
    rule_set_dst(rule, AF_INET6, "::/1");
    mgr.parse(rule);
    rtnl_rule_put(rule);

    std::vector<uint32_t> tables = mgr.rule_resolve(make_key(AF_INET6, "2001:db8::1", nullptr));
    EXPECT_TRUE(contains(tables, 10166));

    tables = mgr.rule_resolve(make_key(AF_INET6, "8000::1", nullptr));
    EXPECT_FALSE(contains(tables, 10166));
}

TEST(rule_table_mgr, src_prefix_rule_matches_ipv6_subnet)
{
    rule_table_mgr_under_test mgr;

    struct rtnl_rule *rule = make_rule(AF_INET6, 10162, 105);
    rule_set_src(rule, AF_INET6, "fd00:77::/32");
    mgr.parse(rule);
    rtnl_rule_put(rule);

    std::vector<uint32_t> tables =
        mgr.rule_resolve(make_key(AF_INET6, "2001:db8::1", "fd00:77::1"));
    EXPECT_TRUE(contains(tables, 10162));

    tables = mgr.rule_resolve(make_key(AF_INET6, "2001:db8::1", "fd00:78::1"));
    EXPECT_FALSE(contains(tables, 10162));
}
