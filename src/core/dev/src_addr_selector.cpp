/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include <cinttypes>
#include "src_addr_selector.h"
#include "net_device_table_mgr.h"
#include "vlogger/vlogger.h"

#define MODULE_NAME "src_sel"
DOCA_LOG_REGISTER(src_sel);

#define src_sel_logfunc __log_func

bool ipv6_source_addr_score::use_optimistic_addr() const
{
    sysctl_reader_t &ctl = sysctl_reader_t::instance();
    return (ctl.get_ipv6_conf_all_optimistic_dad() || m_dev->ipv6_optimistic_dad()) &&
        (ctl.get_ipv6_conf_all_use_optimistic() || m_dev->ipv6_use_optimistic());
}

int ipv6_source_addr_score::get_score(const ipv6_source_addr_score_dst &score_dst, int rule)
{
    if (rule <= m_last_rule) { // We assume that given rule is >= 0
        return m_rule_score[rule];
    }

    int rc = 0;
    switch (rule) {
    case IPV6_SADDR_RULE_INIT:
        // Rule 0: Initialization. Set initially 0 for max_score and 1 for first_score.
        rc = !!m_ip;
        break;
    case IPV6_SADDR_RULE_LOCAL:
        // Rule 1: Prefer same address
        rc = (m_ip->local_addr == score_dst.dst_addr ? 1 : 0);
        break;
    case IPV6_SADDR_RULE_SCOPE:
        // Rule 2: Prefer appropriate scope
        {
            rc = m_ip->scope;
            uint8_t scope = 0;
            ipv6_addr_type_scope(score_dst.dst_addr, scope);
            if (rc >= scope) {
                rc = -rc;
            } else {
                rc -= 128; /* 30 is enough */
            }
        }
        break;
    case IPV6_SADDR_RULE_PREFERRED:
        // Rule 3: Avoid deprecated and optimistic
        {
            uint8_t avoid = IFA_F_DEPRECATED;
            uint8_t unused = 0;

            if (!use_optimistic_addr()) {
                avoid |= IFA_F_OPTIMISTIC;
            }

            rc = ipv6_is_addr_type_preferred(ipv6_addr_type_scope(score_dst.dst_addr, unused)) ||
                !(m_ip->flags & avoid);
        }
        break;
    case IPV6_SADDR_RULE_HOA:
        // Rule 4: Prefer mobility home address
        {
            int prefhome = !(score_dst.select_flags & IPV6_PREFER_SRC_COA);
            rc = !(m_ip->flags & IFA_F_HOMEADDRESS) ^ prefhome;
        }
        break;
    case IPV6_SADDR_RULE_OIF:
        // Rule 5: Prefer outgoing interface
        rc = (!score_dst.dst_dev.get_if_idx() ||
              score_dst.dst_dev.get_if_idx() == m_dev->get_if_idx());
        break;
    case IPV6_SADDR_RULE_LABEL:
        // Rule 6: Prefer matching label
        // Currently not supported.
        rc = 0;
        break;
    case IPV6_SADDR_RULE_PRIVACY:
        // Rule 7: Prefer public address
        // Note: prefer temporary address if use_tempaddr >= 2
        {
            int preftmp = score_dst.select_flags & (IPV6_PREFER_SRC_PUBLIC | IPV6_PREFER_SRC_TMP)
                ? !!(score_dst.select_flags & IPV6_PREFER_SRC_TMP)
                : m_dev->ipv6_use_tempaddr() >= 2;
            rc = (!(m_ip->flags & IFA_F_TEMPORARY)) ^ preftmp;
        }
        break;
    case IPV6_SADDR_RULE_ORCHID:
        // Rule 8-: Prefer ORCHID vs ORCHID or non-ORCHID vs non-ORCHID
        // DEPRECATED
        break;
    case IPV6_SADDR_RULE_PREFIX:
        // Rule 8: Use longest matching prefix
        rc = m_ip->local_addr.get_max_equal_prefix(score_dst.dst_addr);
        if (rc > m_ip->prefixlen) {
            rc = m_ip->prefixlen;
        }
        break;
    case IPV6_SADDR_RULE_NOT_OPTIMISTIC:
        // Rule 9: Optimistic addresses have lower precedence than other preferred addresses.
        rc = !(m_ip->flags & IFA_F_OPTIMISTIC);

        // Using Optimistic address may require more modification.
        // See https://elixir.bootlin.com/linux/v5.18.12/source/net/ipv6/ip6_output.c#L1127
        break;
    default:
        break;
    }

    m_rule_score[rule] = rc;
    m_last_rule = rule;
    return rc;
}

void ipv6_source_addr_score::do_compare(ipv6_source_addr_score &&another,
                                        const ipv6_source_addr_score_dst &score_dst)
{
    for (int rule = 0; rule < IPV6_SADDR_RULE_MAX; ++rule) {
        int this_score = get_score(score_dst, rule);
        int another_score = another.get_score(score_dst, rule);

        if (this_score > another_score) { // this is bigger.
            break;
        }

        if (this_score < another_score) { // another is bigger.
            *this = another;
            src_sel_logfunc("Next selected address, %s, %s", m_dev->get_ifname(),
                            m_ip->local_addr.to_str(AF_INET6).c_str());
            return;
        }
    }
}

void src_addr_selector::ipv6_select_saddr_by_dev(const net_device_val &dev,
                                                 const ipv6_source_addr_score_dst &score_dst,
                                                 ipv6_source_addr_score &max_score)
{
    const auto &ip_arr = dev.get_ip_array(AF_INET6);
    for (const auto &ip_addr : ip_arr) {
        // Skip Tentative non-optimistic addresses.
        if ((ip_addr->flags & IFA_F_TENTATIVE) && !(ip_addr->flags & IFA_F_OPTIMISTIC)) {
            src_sel_logfunc("Tentative addr skipped: %s",
                            ip_addr->local_addr.to_str(AF_INET6).c_str());
            continue;
        }

        // Sanity check for illegal configuration.
        if (ip_addr->local_addr.is_mc(AF_INET6) || ip_addr->local_addr.is_anyaddr() ||
            ip_addr->local_addr.is_mapped_ipv4()) {
            src_sel_logfunc("Illegal addr skipped: %s",
                            ip_addr->local_addr.to_str(AF_INET6).c_str());
            continue;
        }

        max_score.do_compare(ipv6_source_addr_score(&dev, ip_addr.get()), score_dst);
    }
}

const ip_data *src_addr_selector::select_ip_src_addr(const net_device_val &dst_dev,
                                                     const ip_address &dst_addr, uint8_t flags,
                                                     sa_family_t family)
{
    const ip_data *rc = (family != AF_INET6 ? ipv4_select_saddr(dst_dev, dst_addr, flags)
                                            : ipv6_select_saddr(dst_dev, dst_addr, flags));

    src_sel_logfunc("Selected IPv6 address for: %s, %s is %s", dst_dev.get_ifname(),
                    dst_addr.to_str(AF_INET6).c_str(),
                    (rc ? rc->local_addr.to_str(family).c_str() : "ANY"));

    return rc;
}

const ip_data *src_addr_selector::ipv6_select_saddr(const net_device_val &dst_dev,
                                                    const ip_address &dst_addr, uint8_t flags)
{
    src_sel_logfunc("Selecting IPv6 address for: %s, %s, flags: %" PRIu8, dst_dev.get_ifname(),
                    dst_addr.to_str(AF_INET6).c_str(), flags);

    // Use only outgoing-if for multicast and link-local/loopback dst addresses.
    bool dst_net_dev_only = false;
    if (dst_addr.is_mc(AF_INET6)) {
        dst_net_dev_only = true;
    } else {
        bool is_link_local = IN6_IS_ADDR_LINKLOCAL(&dst_addr);
        bool is_node_local = IN6_IS_ADDR_LOOPBACK(&dst_addr);
        if (is_link_local || is_node_local) {
            dst_net_dev_only = true;
        }
    }

    ipv6_source_addr_score_dst score_dst(dst_dev, dst_addr, flags);
    ipv6_source_addr_score max_score(nullptr, nullptr);
    if (dst_net_dev_only) {
        ipv6_select_saddr_by_dev(dst_dev, score_dst, max_score);
    } else {
        // No master selection (bonding) support for now.

        local_dev_vector devices;
        g_p_net_device_table_mgr->get_net_devices(devices);

        for (const auto &devref : devices) {
            ipv6_select_saddr_by_dev(devref.get(), score_dst, max_score);
        }
    }

    return max_score.get_ip(); // May return nullptr, if no address found.
}

static inline uint32_t is_ip_match_subnet(in_addr ipv4_addr, class ip_data *ip)
{
    uint32_t mask = 0xffffffff << (32 - ip->prefixlen);
    return !(ntohl(ipv4_addr.s_addr ^ ip->local_addr.get_in4_addr().s_addr) & mask);
}

const ip_data *src_addr_selector::ipv4_select_saddr(const net_device_val &dst_dev,
                                                    const ip_address &dst_addr, uint8_t flags)
{
    NOT_IN_USE(flags);

    const auto &ip_arr = dst_dev.get_ip_array(AF_INET);
    for (auto iter = ip_arr.begin(); iter < ip_arr.end(); iter++) {
        if (is_ip_match_subnet(dst_addr.get_in4_addr(), iter->get())) {
            return iter->get();
        }
    }

    if (unlikely(ip_arr.size() == 0) || ip_arr[0]->local_addr.is_anyaddr()) {
        return nullptr;
    }

    return ip_arr[0].get();
}
