/*
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef RULE_TABLE_MGR_H
#define RULE_TABLE_MGR_H

#include "core/infra/cache_subject_observer.h"
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
    virtual void parse_entry(struct nlmsghdr *nl_header) override;
    virtual void update_tbl(nl_data_t data_type) override;

    rule_entry *create_new_entry(route_rule_table_key key, const observer *obs) override;

private:
    void parse_attr(struct rtattr *rt_attribute, rule_val &val);
    void print_tbl();

    void update_entry(rule_entry *p_ent);

    bool find_rule_val(const route_rule_table_key &key, std::deque<rule_val *> *p_val);

    rule_table_t m_table_in4;
    rule_table_t m_table_in6;
};

extern rule_table_mgr *g_p_rule_table_mgr;

#endif /* RULE_TABLE_MGR_H */
