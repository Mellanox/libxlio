/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef RULE_TABLE_MGR_H
#define RULE_TABLE_MGR_H

#include "core/proto/netlink_socket_mgr.h"
#include "route_rule_table_key.h"
#include "rule_entry.h"
#include "rule_val.h"

#include <vector>

typedef std::vector<rule_val> rule_table_t;

/*
 * This class manages routing rule related operation such as getting rules from kernel,
 * finding table ID for given destination info and cashing usage history for rule table.
 */
class rule_table_mgr : public netlink_socket_mgr,
                       public cache_table_mgr<route_rule_table_key, std::deque<rule_val *> *> {
public:
    rule_table_mgr();

    std::vector<uint32_t> rule_resolve(route_rule_table_key key);

protected:
    virtual void parse_entry(struct nl_object *nl_obj) override;
    virtual void update_tbl(nl_data_t data_type) override;

    rule_entry *create_new_entry(route_rule_table_key key, const observer *obs) override;

private:
    void parse_attr(struct rtnl_rule *rule, rule_val &val);
    void print_tbl();

    void update_entry(rule_entry *p_ent);

    bool find_rule_val(const route_rule_table_key &key, std::deque<rule_val *> *p_val);

    rule_table_t m_table_in4;
    rule_table_t m_table_in6;
};

extern rule_table_mgr *g_p_rule_table_mgr;

#endif /* RULE_TABLE_MGR_H */
