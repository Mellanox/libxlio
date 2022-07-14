/*
 * Copyright (c) 2001-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef SOCK_ADDR_H
#define SOCK_ADDR_H

#include <stdio.h>
#include <string.h>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "vma/util/vtypes.h"
#include "vma/util/ip_address.h"
#include "vma/util/sock_addr.h"

static inline sa_family_t get_sa_family(const struct sockaddr *addr)
{
    return addr->sa_family;
}

static inline in_port_t get_sa_port(const struct sockaddr *addr)
{
    return (get_sa_family(addr) == AF_INET
                ? reinterpret_cast<const struct sockaddr_in *>(addr)->sin_port
                : reinterpret_cast<const struct sockaddr_in6 *>(addr)->sin6_port);
}

static inline std::string sockport2str(const struct sockaddr *addr)
{
    return std::to_string(ntohs(get_sa_port(addr)));
}

static inline std::string sockaddr2str(const struct sockaddr *addr, bool port = false)
{
    char buffer[INET6_ADDRSTRLEN];
    std::string rc;

    if (get_sa_family(addr) == AF_INET) {
        rc.reserve(32);
        if (inet_ntop(AF_INET, &reinterpret_cast<const struct sockaddr_in *>(addr)->sin_addr,
                      buffer, sizeof(buffer))) {
            rc = buffer;
        }
    } else {
        rc.reserve(64);
        rc = '[';
        if (inet_ntop(AF_INET6, &reinterpret_cast<const struct sockaddr_in6 *>(addr)->sin6_addr,
                      buffer, sizeof(buffer))) {
            rc += buffer;
        }
        rc += ']';
    }

    if (port) {
        rc += ':' + sockport2str(addr);
    }

    return rc;
}

class sock_addr {
public:
    sock_addr() { clear_sa(); };

    sock_addr(const struct sockaddr *other, socklen_t size) { set_sockaddr(other, size); }

    sock_addr(const sock_addr &other) { *this = other; }

    // @param in_addr Should point either to in_addr or in6_addr according the family.
    sock_addr(sa_family_t f, const void *ip_addr, in_port_t p) { set_ip_port(f, ip_addr, p); };

    ~sock_addr() {};

    struct sockaddr *get_p_sa() { return &u_sa.m_sa; }
    const struct sockaddr *get_p_sa() const { return &u_sa.m_sa; }

    void get_sa(struct sockaddr *sa, socklen_t size) const
    {
        memcpy(sa, &u_sa.m_sa, std::min<size_t>(get_socklen(), size));
    }

    sa_family_t get_sa_family() const { return u_sa.m_sa.sa_family; }

    const ip_address &get_ip_addr() const
    {
        return *(get_sa_family() == AF_INET
                     ? reinterpret_cast<const ip_address *>(&u_sa.m_sa_in.sin_addr)
                     : reinterpret_cast<const ip_address *>(&u_sa.m_sa_in6.sin6_addr));
    }

    in_port_t get_in_port() const
    {
        return (get_sa_family() == AF_INET ? u_sa.m_sa_in.sin_port : u_sa.m_sa_in6.sin6_port);
    }

    socklen_t get_socklen() const
    {
        switch (get_sa_family()) {
        case AF_INET:
            return static_cast<socklen_t>(sizeof(struct sockaddr_in));
        case AF_INET6:
            return static_cast<socklen_t>(sizeof(struct sockaddr_in6));
        default:
            break;
        }
        return static_cast<socklen_t>(sizeof(u_sa));
    }

    bool is_supported() const
    {
        return (get_sa_family() == AF_INET || get_sa_family() == AF_INET6);
    }

    bool is_anyaddr() const { return get_ip_addr().is_anyaddr(); }

    bool is_anyport() const { return (INPORT_ANY == get_in_port()); }

    bool is_mc() const { return get_ip_addr().is_mc(get_sa_family()); };

    void set_sockaddr(const struct sockaddr *sa, socklen_t size)
    {
        clear_sa();
        memcpy(&u_sa.m_sa, sa, std::min<size_t>(sizeof(u_sa), size));
    }

    void set_ip_port(sa_family_t f, const void *ip_addr, in_port_t p)
    {
        clear_sa();
        u_sa.m_sa.sa_family = f;

        if (AF_INET == f) {
            u_sa.m_sa_in.sin_addr = *reinterpret_cast<const struct in_addr *>(ip_addr);
            u_sa.m_sa_in.sin_port = p;
        } else {
            u_sa.m_sa_in6.sin6_addr = *reinterpret_cast<const struct in6_addr *>(ip_addr);
            u_sa.m_sa_in6.sin6_port = p;
        }
    }

    void set_sa_family(const sa_family_t f) { u_sa.m_sa.sa_family = f; }

    void set_in_addr(const ip_address &ip)
    {
        if (get_sa_family() == AF_INET) {
            u_sa.m_sa_in.sin_addr = reinterpret_cast<const in_addr &>(ip);
        } else {
            u_sa.m_sa_in6.sin6_addr = reinterpret_cast<const in6_addr &>(ip);
        }
    }

    void set_in_port(in_port_t p)
    {
        if (AF_INET == get_sa_family()) {
            u_sa.m_sa_in.sin_port = p;
        } else {
            u_sa.m_sa_in6.sin6_port = p;
        }
    }

    sock_addr &operator=(const sock_addr &other)
    {
        u_sa.m_sa_in6 = other.u_sa.m_sa_in6;
        return *this;
    }

    sock_addr &operator=(const sock_addr &&other)
    {
        u_sa.m_sa_in6 = other.u_sa.m_sa_in6;
        return *this;
    }

    bool operator==(const sock_addr &other) const
    {
        return (0 == memcmp(&u_sa, &other.u_sa, sizeof(u_sa)));
    }

    bool operator<(sock_addr const &other) const
    {
        if (u_sa.m_sa.sa_family != other.u_sa.m_sa.sa_family) {
            return (u_sa.m_sa.sa_family < other.u_sa.m_sa.sa_family);
        }

        const ip_address &this_addr = get_ip_addr();
        const ip_address &other_addr = other.get_ip_addr();
        if (this_addr != other_addr) {
            return this_addr.less_than_raw(other_addr);
        }

        if (get_sa_family() == AF_INET) {
            return (u_sa.m_sa_in.sin_port < other.u_sa.m_sa_in.sin_port);
        } else {
            if (u_sa.m_sa_in6.sin6_port != other.u_sa.m_sa_in6.sin6_port) {
                return (u_sa.m_sa_in6.sin6_port < other.u_sa.m_sa_in6.sin6_port);
            }
            if (u_sa.m_sa_in6.sin6_flowinfo != other.u_sa.m_sa_in6.sin6_flowinfo) {
                return (u_sa.m_sa_in6.sin6_flowinfo < other.u_sa.m_sa_in6.sin6_flowinfo);
            }

            return (u_sa.m_sa_in6.sin6_scope_id < other.u_sa.m_sa_in6.sin6_scope_id);
        }
    }

    size_t hash(void) const
    {
        static size_t sz_size = sizeof(size_t);

        size_t csum = 0U;
        const uint8_t *pval = reinterpret_cast<const uint8_t *>(this);
        const uint8_t *pend = pval + get_socklen();
        while (pval + sz_size <= pend) {
            csum ^= *reinterpret_cast<const size_t *>(pval);
            pval += sz_size;
        }
        // For now we skip the last 4 bytes for sockaddr_in6 which is unused scope_id anyway.

        return csum;
    }

    std::string to_str_port() const { return sockport2str(&u_sa.m_sa); }

    std::string to_str_ip_port(bool port = false) const { return sockaddr2str(&u_sa.m_sa, port); }

private:
    void clear_sa() { memset(&u_sa, 0, sizeof(u_sa)); }

    union {
        struct sockaddr m_sa;
        struct sockaddr_in m_sa_in;
        struct sockaddr_in6 m_sa_in6;
    } u_sa;
};

namespace std {
template <> class hash<sock_addr> {
public:
    size_t operator()(const sock_addr &key) const { return key.hash(); }
};
} // namespace std

#endif /*SOCK_ADDR_H*/
