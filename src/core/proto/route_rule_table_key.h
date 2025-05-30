/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef ROUTE_RULE_TABLE_KEY_H
#define ROUTE_RULE_TABLE_KEY_H

#include <stdio.h>
#include <string>
#include <cstring>

#include "core/util/vtypes.h"

/*
 * This class is used as key for route and rule table cashed history
 * and its consist from destination IP, source IP and TOS.
 */
class route_rule_table_key {
public:
    route_rule_table_key(const ip_address &dst_ip, const ip_address &src_ip, sa_family_t family,
                         uint8_t tos)
        : m_dst_ip(dst_ip)
        , m_src_ip(src_ip)
        , m_family(family)
        , m_tos(tos) {};
    ~route_rule_table_key() {};

    const std::string to_str() const
    {
        std::string rc;

        rc = "Destination IP:";
        rc += m_dst_ip.to_str(m_family);
        rc += " Source IP:";
        rc += m_src_ip.to_str(m_family);
        rc += " TOS:";
        rc += std::to_string(m_tos);

        return rc;
    }

    inline const ip_address &get_dst_ip() const { return m_dst_ip; };
    inline const ip_address &get_src_ip() const { return m_src_ip; };
    inline sa_family_t get_family() const { return m_family; }
    inline uint8_t get_tos() const { return m_tos; };

    bool operator==(const route_rule_table_key &rrk) const
    {
        return (m_dst_ip == rrk.get_dst_ip() && m_src_ip == rrk.get_src_ip() &&
                m_tos == rrk.get_tos());
    };

private:
    ip_address m_dst_ip;
    ip_address m_src_ip;
    sa_family_t m_family;
    uint8_t m_tos;
};

inline std::string to_string_val(const route_rule_table_key &k)
{
    return k.to_str();
}

namespace std {
template <> class hash<route_rule_table_key> {
public:
    size_t operator()(const route_rule_table_key &key) const
    {
        std::hash<uint64_t> _hash;
        uint64_t val;

        const uint64_t *p_src_ip = reinterpret_cast<const uint64_t *>(&key.get_src_ip());
        const uint64_t *p_dst_ip = reinterpret_cast<const uint64_t *>(&key.get_dst_ip());

        val = p_src_ip[0] ^ p_src_ip[1] ^ p_dst_ip[0] ^ p_dst_ip[1] ^
            (static_cast<uint64_t>(key.get_tos()) << 24U) ^
            (static_cast<uint64_t>(key.get_family()) << 30U);

        return _hash(val);
    }
};
} // namespace std

#endif /* ROUTE_RULE_TABLE_KEY_H */
