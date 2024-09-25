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

#ifndef IP_ADDRESS_H
#define IP_ADDRESS_H

#include <arpa/inet.h>
#include <string.h>
#include <string>
#include "core/util/vtypes.h"

// RH 7.6 does not support this flag
#ifndef IPV6_ADDR_PREFERENCES
// RFC5014: Source address selection
#define IPV6_ADDR_PREFERENCES 72
#endif

#define IPV6_ADDR_ANY       0x0000U
#define IPV6_ADDR_UNICAST   0x0001U
#define IPV6_ADDR_MULTICAST 0x0002U
#define IPV6_ADDR_LOOPBACK  0x0010U
#define IPV6_ADDR_LINKLOCAL 0x0020U
#define IPV6_ADDR_SITELOCAL 0x0040U
#define IPV6_ADDR_COMPATv4  0x0080U
#define IPV6_ADDR_MAPPED    0x1000U

#define IPV6_ADDR_SCOPE_MASK      0x000fU
#define IPV6_ADDR_SCOPE_NODELOCAL 0x01
#define IPV6_ADDR_SCOPE_LINKLOCAL 0x02
#define IPV6_ADDR_SCOPE_SITELOCAL 0x05
#define IPV6_ADDR_SCOPE_ORGLOCAL  0x08
#define IPV6_ADDR_SCOPE_GLOBAL    0x0e

#define IPV6_PREFER_SRC_COA            0x0004
#define IPV6_PREFER_SRC_TMP            0x0001
#define IPV6_PREFER_SRC_PUBLIC         0x0002
#define IPV6_PREFER_SRC_PUBTMP_DEFAULT 0x0100
#define IPV6_PREFER_SRC_HOME           0x0400
#define IPV6_PREFER_SRC_CGA            0x0008
#define IPV6_PREFER_SRC_NONCGA         0x0800

// This class must be compatible with sock_addr (see sock_addr.h) and should not contain any member
// except IPv4/IPv6 union and must now have virtual methods.
// Class ip_addr is an extension to this class (see below) which allows more members and vtable.
class ip_address {
public:
    ip_address() { m_ip6_64[0] = m_ip6_64[1] = 0U; };

    explicit ip_address(in_addr_t ip4)
    {
        m_ip6_64[0] = m_ip6_64[1] = 0U;
        m_ip = ip4;
    };

    ip_address(in_addr ip4)
    {
        m_ip6_64[0] = m_ip6_64[1] = 0U;
        m_ip4 = ip4;
    };

    ip_address(const in6_addr &ip6)
        : m_ip6(ip6)
    {
    }

    ip_address(const void *raw, sa_family_t family)
    {
        if (family == AF_INET) {
            m_ip6_64[0] = m_ip6_64[1] = 0U;
            m_ip = *reinterpret_cast<const in_addr_t *>(raw);
        } else {
            m_ip6 = *reinterpret_cast<const in6_addr *>(raw);
        }
    }

    ip_address(const ip_address &addr) { *this = addr; }

    ip_address(ip_address &&addr) { *this = std::move(addr); }

    const std::string to_str(sa_family_t family) const
    {
        char buffer[INET6_ADDRSTRLEN];
        std::string rc;

        if (family == AF_INET) {
            rc.reserve(32);
            if (inet_ntop(AF_INET, &m_ip4, buffer, sizeof(buffer))) {
                rc = buffer;
            }
        } else {
            rc.reserve(64);
            rc = '[';
            if (inet_ntop(AF_INET6, &m_ip6, buffer, sizeof(buffer))) {
                rc += buffer;
            }
            rc += ']';
        }

        return rc;
    }

    in_addr_t get_in_addr() const { return m_ip; };

    const in_addr &get_in4_addr() const { return m_ip4; };

    const in6_addr &get_in6_addr() const { return m_ip6; };

    bool is_mc(sa_family_t family) const
    {
        return (family == AF_INET ? IN_MULTICAST_N(m_ip) : IN6_IS_ADDR_MULTICAST(&m_ip6));
    };

    bool is_anyaddr() const { return *this == any_addr(); };

    bool is_linklocal(sa_family_t family) const
    {
        return family == AF_INET ? (ntohl(m_ip) & 0xFFFF0000U) == 0xA9FE0000U
                                 : IN6_IS_ADDR_LINKLOCAL(&m_ip6);
    }

    bool is_loopback_class(sa_family_t family) const
    {
        return (family == AF_INET ? LOOPBACK_N(m_ip) : *this == loopback6_addr());
    }

    bool is_mapped_ipv4() const
    {
        return (m_ip6_64[0] == 0U && m_ip6_16[4] == 0U && m_ip6_16[5] == 0xFFFFU);
    }

    bool is_equal_with_prefix(const ip_address &ip, unsigned prefix, sa_family_t family) const
    {
        if (prefix == 0) {
            return true;
        }

        if (family == AF_INET) {
            prefix = 32U - prefix;
            return (ntohl(m_ip) >> prefix) == (ntohl(ip.m_ip) >> prefix);
        } else {
            prefix = 128U - prefix;
            if (prefix >= 64U) {
                prefix -= 64U;
                return (ntohll(m_ip6_64[0]) >> prefix) == (ntohll(ip.m_ip6_64[0]) >> prefix);
            } else {
                return (m_ip6_64[0] == ip.m_ip6_64[0]) &&
                    ((ntohll(m_ip6_64[1]) >> prefix) == (ntohll(ip.m_ip6_64[1]) >> prefix));
            }
        }
    }

    uint8_t get_max_equal_prefix(const ip_address &ip) const
    {
        uint64_t xb = m_ip6_64[0] ^ ip.m_ip6_64[0];
        if (xb) {
            return static_cast<uint8_t>(__builtin_clzl(ntohll(xb)));
        }

        xb = m_ip6_64[1] ^ ip.m_ip6_64[1];
        if (xb) {
            return 64 + static_cast<uint8_t>(__builtin_clzl(ntohll(xb)));
        }

        return 128;
    }

    bool operator==(const ip_address &ip) const
    {
        return (m_ip6_64[0] == ip.m_ip6_64[0] && m_ip6_64[1] == ip.m_ip6_64[1]);
    };

    bool operator!=(const ip_address &ip) const
    {
        return (m_ip6_64[0] != ip.m_ip6_64[0] || m_ip6_64[1] != ip.m_ip6_64[1]);
    };

    ip_address &operator=(const ip_address &ip)
    {
        m_ip6 = ip.m_ip6;
        return *this;
    }

    ip_address &operator=(ip_address &&ip)
    {
        m_ip6 = ip.m_ip6;
        return *this;
    }

    // The ip_address is assumed to store Big-Endian. However performing ntohll frequently
    // may impact performance in some flows. For cases like map/hash where
    // the real order is insignificant, this methods performs comparision without ntohll.
    bool less_than_raw(const ip_address &other) const
    {
        return (likely(m_ip6_64[0] != other.m_ip6_64[0]) ? (m_ip6_64[0] < other.m_ip6_64[0])
                                                         : (m_ip6_64[1] < other.m_ip6_64[1]));
    }

    uint64_t hash() const
    {
        std::hash<uint64_t> _hash;
        return _hash(m_ip6_64[0] ^ m_ip6_64[1]);
    }

    ip_address to_mapped_ipv4() const
    {
        ip_address out = any_addr();
        uint16_t *addr_ptr = reinterpret_cast<uint16_t *>(&out.m_ip6);
        addr_ptr[5] = 0xFFFFU;
        memcpy(addr_ptr + 6, &m_ip4, sizeof(m_ip4));
        return out;
    }

    static const ip_address &any_addr()
    {
        static ip_address s_any_addr(in6addr_any);
        return s_any_addr;
    }

    static const ip_address &loopback4_addr()
    {
        static ip_address s_loopback4_addr(INADDR_LOOPBACK);
        return s_loopback4_addr;
    }

    static const ip_address &loopback6_addr()
    {
        static ip_address s_loopback6_addr(in6addr_loopback);
        return s_loopback6_addr;
    }

    static const ip_address &broadcast4_addr()
    {
        static ip_address s_broadcast4_addr(INADDR_BROADCAST);
        return s_broadcast4_addr;
    }

protected:
    union {
        in6_addr m_ip6;
        uint64_t m_ip6_64[2];
        uint16_t m_ip6_16[8];
        in_addr m_ip4;
        in_addr_t m_ip;
    };
};

// This class is an extension to the ip_address class. It allows more members and virtual methods.
// However, new members should be added with caution since this still may be used in hashes and
// performance oriented paths.
class ip_addr : public ip_address {
public:
    ip_addr(in_addr_t ip4)
        : ip_address(ip4)
        , m_family(AF_INET)
    {
    }

    ip_addr(in_addr ip4)
        : ip_address(ip4)
        , m_family(AF_INET)
    {
    }

    ip_addr(const in6_addr &ip6)
        : ip_address(ip6)
        , m_family(AF_INET6)
    {
    }

    ip_addr(const ip_address &ip, sa_family_t family)
        : ip_address(ip)
        , m_family(family)
    {
    }

    ip_addr(ip_address &&ip, sa_family_t family)
        : ip_address(std::forward<ip_address>(ip))
        , m_family(family)
    {
    }

    ip_addr(const ip_addr &addr)
        : ip_address(addr)
        , m_family(addr.m_family)
    {
    }

    ip_addr(ip_addr &&addr)
        : ip_address(addr)
        , m_family(addr.m_family)
    {
    }

    sa_family_t get_family() const { return m_family; }

    bool is_ipv4() const { return (m_family == AF_INET); }

    bool is_ipv6() const { return (m_family == AF_INET6); }

    bool is_mc() const { return ip_address::is_mc(m_family); }

    const std::string to_str() const { return ip_address::to_str(m_family); }

    bool operator==(const ip_addr &ip) const
    {
        return (ip_address::operator==(ip) && m_family == ip.m_family);
    };

    bool operator!=(const ip_addr &ip) const
    {
        return (ip_address::operator!=(ip) || m_family != ip.m_family);
    };

    ip_addr &operator=(const ip_addr &ip)
    {
        m_family = ip.m_family;
        ip_address::operator=(ip);
        return *this;
    }

    ip_addr &operator=(ip_addr &&ip)
    {
        m_family = ip.m_family;
        ip_address::operator=(std::forward<ip_address>(ip));
        return *this;
    }

    uint64_t hash() const
    {
        std::hash<uint64_t> _hash;
        return _hash(m_ip6_64[0] ^ m_ip6_64[1] ^ (static_cast<uint64_t>(m_family) << 30U));
    }

private:
    sa_family_t m_family;
};

namespace std {
template <> class hash<ip_address> {
public:
    size_t operator()(const ip_address &key) const { return key.hash(); }
};
template <> class hash<ip_addr> {
public:
    size_t operator()(const ip_addr &key) const { return key.hash(); }
};
} // namespace std

// We rely on that ip_address is exactly IPv6 address length, so we can cast it to uint64_t[2].
static_assert(sizeof(ip_address) == 16U, "ip_address must be 16 bytes (128 bits)");

#endif /* IP_ADDRESS_H */
