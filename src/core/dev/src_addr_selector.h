/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2022-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "net_device_val.h"

struct ipv6_source_addr_score_dst {
    ipv6_source_addr_score_dst(const net_device_val &indev, const ip_address &inaddr,
                               uint8_t inselect_flags)
        : dst_dev(indev)
        , dst_addr(inaddr)
        , select_flags(inselect_flags)
    {
    }

    const net_device_val &dst_dev;
    const ip_address &dst_addr;
    const uint8_t select_flags;
};

class ipv6_source_addr_score {
public:
    ipv6_source_addr_score(const net_device_val *dev, const ip_data *ip)
        : m_dev(dev)
        , m_ip(ip)
    {
    }

    void do_compare(ipv6_source_addr_score &&another, const ipv6_source_addr_score_dst &score_dst);

    ipv6_source_addr_score &operator=(const ipv6_source_addr_score &another)
    {
        memcpy(m_rule_score, another.m_rule_score, sizeof(m_rule_score));
        m_dev = another.m_dev;
        m_ip = another.m_ip;
        m_last_rule = another.m_last_rule;
        return *this;
    }

    const ip_data *get_ip() const { return m_ip; }

private:
    bool use_optimistic_addr() const;
    int get_score(const ipv6_source_addr_score_dst &score_dst, int rule);

    enum ipv6_score_rule {
        IPV6_SADDR_RULE_INIT = 0,
        IPV6_SADDR_RULE_LOCAL,
        IPV6_SADDR_RULE_SCOPE,
        IPV6_SADDR_RULE_PREFERRED,
        IPV6_SADDR_RULE_HOA,
        IPV6_SADDR_RULE_OIF,
        IPV6_SADDR_RULE_LABEL,
        IPV6_SADDR_RULE_PRIVACY,
        IPV6_SADDR_RULE_ORCHID,
        IPV6_SADDR_RULE_PREFIX,
        IPV6_SADDR_RULE_NOT_OPTIMISTIC,
        IPV6_SADDR_RULE_MAX
    };

    int m_rule_score[IPV6_SADDR_RULE_MAX] {0};
    const net_device_val *m_dev;
    const ip_data *m_ip;
    int8_t m_last_rule = -1;
};

class src_addr_selector {
public:
    static const ip_data *select_ip_src_addr(const net_device_val &dst_dev,
                                             const ip_address &dst_addr, uint8_t flags,
                                             sa_family_t family);

private:
    static const ip_data *ipv6_select_saddr(const net_device_val &dst_dev,
                                            const ip_address &dst_addr, uint8_t flags);

    static const ip_data *ipv4_select_saddr(const net_device_val &dst_dev,
                                            const ip_address &dst_addr, uint8_t flags);

    static void ipv6_select_saddr_by_dev(const net_device_val &dev,
                                         const ipv6_source_addr_score_dst &score_dst,
                                         ipv6_source_addr_score &max_score);
};
