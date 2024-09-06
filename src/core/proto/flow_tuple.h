/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
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

#ifndef FLOW_TUPLE_H
#define FLOW_TUPLE_H

#include <list>
#include <netinet/in.h>
#include "core/util/libxlio.h"
#include "core/util/sock_addr.h"
#include "core/util/sys_vars.h"

// Looks at the packet in the ingress flow (in regards to dst and src)
// Practically a 'five tuple' key
class flow_tuple {
public:
    flow_tuple();
    flow_tuple(const ip_address &dst_ip, in_port_t dst_port, const ip_address &src_ip,
               in_port_t src_port, in_protocol_t protocol, sa_family_t family);
    flow_tuple(const flow_tuple &ft);
    flow_tuple(flow_tuple &&ft);
    virtual ~flow_tuple() {};

    const ip_address &get_dst_ip() const { return m_dst_ip; }
    const ip_address &get_src_ip() const { return m_src_ip; }
    in_port_t get_dst_port() const { return m_dst_port; }
    in_port_t get_src_port() const { return m_src_port; }
    in_protocol_t get_protocol() const { return m_protocol; }
    sa_family_t get_family() const { return m_family; }

    bool is_tcp() const { return (m_protocol == PROTO_TCP); }
    bool is_udp_uc() const;
    bool is_udp_mc() const;
    bool is_local_loopback() const { return m_dst_ip.is_loopback_class(m_family); }
    bool is_5_tuple() const;
    bool is_3_tuple() const;

    void set_src_port(in_port_t v) { m_src_port = v; }

    flow_tuple &operator=(const flow_tuple &ft);
    flow_tuple &operator=(flow_tuple &&ft);

    bool operator==(flow_tuple const &other) const
    {
        return (m_dst_port == other.m_dst_port) && (m_dst_ip == other.m_dst_ip) &&
            (m_src_port == other.m_src_port) && (m_src_ip == other.m_src_ip) &&
            (m_protocol == other.m_protocol) && (m_family == other.m_family);
    }

    bool operator<(flow_tuple const &other) const
    {
        if (m_dst_port != other.m_dst_port) {
            return m_dst_port < other.m_dst_port;
        }
        if (m_dst_ip != other.m_dst_ip) {
            return m_dst_ip.less_than_raw(other.m_dst_ip);
        }
        if (m_src_port != other.m_src_port) {
            return m_src_port < other.m_src_port;
        }
        if (m_src_ip != other.m_src_ip) {
            return m_src_ip.less_than_raw(other.m_src_ip);
        }
        if (m_family != other.m_family) {
            return m_family < other.m_family;
        }
        return m_protocol < other.m_protocol;
    }

    virtual size_t hash() const;
    virtual std::string to_str() const;

protected:
    ip_address m_dst_ip;
    ip_address m_src_ip;
    in_port_t m_dst_port;
    in_port_t m_src_port;
    in_protocol_t m_protocol;
    sa_family_t m_family;
};

typedef std::list<flow_tuple> flow_tuple_list_t;

// Adding the 'six tuple' element of local_if
// Required by sockinfo when handling MC groups attach/detach
class flow_tuple_with_local_if : public flow_tuple {
public:
    flow_tuple_with_local_if(const ip_address &dst_ip, in_port_t dst_port, const ip_address &src_ip,
                             in_port_t src_port, in_protocol_t protocol, sa_family_t family,
                             const ip_address &local_if)
        : flow_tuple(dst_ip, dst_port, src_ip, src_port, protocol, family)
        , m_local_if(local_if) {};

    const ip_address &get_local_if() const { return m_local_if; }

    bool operator==(flow_tuple_with_local_if const &other) const
    {
        return ((m_local_if == other.m_local_if) && flow_tuple::operator==(other));
    }

    bool operator<(flow_tuple_with_local_if const &other) const
    {
        if (m_local_if != other.m_local_if) {
            return m_local_if.less_than_raw(other.m_local_if);
        }

        return flow_tuple::operator<(other);
    }

    virtual size_t hash() const;
    virtual std::string to_str() const;

protected:
    // coverity[member_decl]
    ip_address m_local_if;
};

namespace std {
template <> class hash<flow_tuple_with_local_if> {
public:
    size_t operator()(const flow_tuple_with_local_if &key) const { return key.hash(); }
};
} // namespace std

namespace std {
template <> class hash<flow_tuple> {
public:
    size_t operator()(const flow_tuple &key) const { return key.hash(); }
};
} // namespace std
#endif /* FLOW_TUPLE_H */
