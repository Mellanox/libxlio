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

#ifndef HEADER_H
#define HEADER_H

#include <string.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/igmp.h>

#include "core/util/vtypes.h"
#include "L2_address.h"
#include "core/util/sys_vars.h"
#include "core/lwip/ip_addr.h"

class dst_entry;

// We align the frame so IP header will be 4 bytes align
// And we align the L2 headers so IP header on both transport
// types will be at the same offset from buffer start
#define NET_ETH_IP_ALIGN_SZ      6
#define NET_ETH_VLAN_IP_ALIGN_SZ 2
#define NET_ETH_VLAN_PCP_OFFSET  13

struct __attribute__((packed)) eth_hdr_template_t { // Offeset  Size
    char m_alignment[NET_ETH_IP_ALIGN_SZ]; //    0       6  =  6
    ethhdr m_eth_hdr; //    6      14  = 20
};

struct __attribute__((packed)) vlan_eth_hdr_template_t { // Offeset  Size
    char m_alignment[NET_ETH_VLAN_IP_ALIGN_SZ]; //    0       2  =  2
    ethhdr m_eth_hdr; //    2      14  = 16
    vlanhdr m_vlan_hdr; //   16       4  = 20
};

union l2_hdr_template_t {
    eth_hdr_template_t eth_hdr;
    vlan_eth_hdr_template_t vlan_eth_hdr;
};

#define FRAG_EXT_HLEN   8U
#define L2_ALIGNED_HLEN 20U
#define UDP_HLEN        8U
#ifndef TCP_HLEN
#define TCP_HLEN 20U
#endif

static_assert(sizeof(l2_hdr_template_t) == L2_ALIGNED_HLEN, "wrong struct size");
static_assert(sizeof(udphdr) == UDP_HLEN, "wrong struct size");
static_assert(sizeof(tcphdr) == TCP_HLEN, "wrong struct size");

struct __attribute__((packed, aligned)) tx_ipv4_hdr_template_t { // Offeset  Size
    l2_hdr_template_t m_l2_hdr; //    0      20
    iphdr m_ip_hdr; //   20      20
    union {
        udphdr m_udp_hdr; //   40      8
        tcphdr m_tcp_hdr; //   40	  20
    };
};

union tx_ipv4_packet_template_t {
    tx_ipv4_hdr_template_t hdr;
    uint32_t words[15]; // change in tx_hdr_template_t size may require to modify this array size
};

struct __attribute__((packed, aligned)) tx_ipv6_hdr_template_t { // Offeset  Size
    l2_hdr_template_t m_l2_hdr; //    0      20
    ip6_hdr m_ip_hdr; //   20      40
    union {
        udphdr m_udp_hdr; //   60       8
        tcphdr m_tcp_hdr; //   60	  20
    };
};

union tx_ipv6_packet_template_t {
    tx_ipv6_hdr_template_t hdr;
    uint32_t words[20]; // change in tx_hdr_template_t size may require to modify this array size
};

class header {
public:
    header();
    header(const header &h);
    virtual ~header() {};
    virtual void init();

    void configure_udp_header(uint16_t dest_port, uint16_t src_port);
    void configure_tcp_ports(uint16_t dest_port, uint16_t src_port);
    void configure_eth_headers(const L2_address &src, const L2_address &dst,
                               uint16_t encapsulated_proto);
    void configure_vlan_eth_headers(const L2_address &src, const L2_address &dst, uint16_t tci,
                                    uint16_t encapsulated_proto);
    void set_mac_to_eth_header(const L2_address &src, const L2_address &dst, ethhdr &eth_header);
    void set_mac_to_eth_header(const L2_address &src, const L2_address &dst);
    bool set_vlan_pcp(uint8_t pcp);
    void update_actual_hdr_addr();

    virtual void configure_ip_header(uint8_t protocol, const ip_address &src,
                                     const ip_address &dest, const dst_entry &_dst_entry,
                                     uint16_t packet_id = 0) = 0;
    virtual void set_ip_ttl_hop_limit(uint8_t ttl_hop_limit) = 0;
    virtual void set_ip_tos(uint8_t tos) { NOT_IN_USE(tos); };
    virtual void *get_hdr_addr() = 0;
    virtual l2_hdr_template_t *get_l2_hdr() = 0;
    virtual const l2_hdr_template_t *get_l2_hdr() const = 0;
    virtual uint16_t get_l4_protocol() const = 0;
    virtual void *get_ip_hdr() = 0;
    virtual udphdr *get_udp_hdr() = 0;
    virtual tcphdr *get_tcp_hdr() = 0;
    virtual void set_ip_len(uint16_t len) = 0;
    virtual void copy_l2_hdr(void *p_h) = 0;
    virtual void copy_l2_ip_hdr(void *p_h) = 0;
    virtual void copy_l2_ip_udp_hdr(void *p_h) = 0;
    virtual header *copy() = 0;

    uintptr_t m_actual_hdr_addr;
    uint16_t m_ip_header_len;
    uint16_t m_transport_header_len;
    uint16_t m_total_hdr_len;
    uint16_t m_aligned_l2_l3_len;
    uint16_t m_transport_header_tx_offset;
    bool m_is_vlan_enabled;
};

class header_ipv4 : public header {
public:
    header_ipv4();
    virtual ~header_ipv4() {};
    void init() override;

    void configure_ip_header(uint8_t protocol, const ip_address &src, const ip_address &dest,
                             const dst_entry &_dst_entry, uint16_t packet_id = 0) override;
    void set_ip_ttl_hop_limit(uint8_t ttl_hop_limit) override;
    void set_ip_tos(uint8_t tos) override;
    void *get_hdr_addr() override { return (static_cast<void *>(&m_header)); }
    l2_hdr_template_t *get_l2_hdr() override { return &m_header.hdr.m_l2_hdr; }
    const l2_hdr_template_t *get_l2_hdr() const override { return &m_header.hdr.m_l2_hdr; }
    virtual uint16_t get_l4_protocol() const override { return m_header.hdr.m_ip_hdr.protocol; }
    void *get_ip_hdr() override { return static_cast<void *>(&m_header.hdr.m_ip_hdr); }
    udphdr *get_udp_hdr() override { return &m_header.hdr.m_udp_hdr; }
    tcphdr *get_tcp_hdr() override { return &m_header.hdr.m_tcp_hdr; }
    void set_ip_len(uint16_t len) override { m_header.hdr.m_ip_hdr.tot_len = htons(len); }
    void copy_l2_ip_hdr(void *p_h) override;
    void copy_l2_ip_udp_hdr(void *p_h) override;
    void copy_l2_hdr(void *p_h) override;
    header *copy() override { return new header_ipv4(*this); }

private:
    tx_ipv4_packet_template_t m_header;
    header_ipv4(const header_ipv4 &h);
};

class header_ipv6 : public header {
public:
    header_ipv6();
    virtual ~header_ipv6() {};
    void init() override;

    void configure_ip_header(uint8_t protocol, const ip_address &src, const ip_address &dest);
    void configure_ip_header(uint8_t protocol, const ip_address &src, const ip_address &dest,
                             const dst_entry &_dst_entry, uint16_t packet_id = 0) override;
    void set_ip_ttl_hop_limit(uint8_t ttl_hop_limit) override;
    void *get_hdr_addr() override { return (static_cast<void *>(&m_header)); }
    l2_hdr_template_t *get_l2_hdr() override { return &m_header.hdr.m_l2_hdr; }
    const l2_hdr_template_t *get_l2_hdr() const override { return &m_header.hdr.m_l2_hdr; }
    virtual uint16_t get_l4_protocol() const override { return m_header.hdr.m_ip_hdr.ip6_nxt; }
    void *get_ip_hdr() override { return static_cast<void *>(&m_header.hdr.m_ip_hdr); }
    udphdr *get_udp_hdr() override { return &m_header.hdr.m_udp_hdr; }
    tcphdr *get_tcp_hdr() override { return &m_header.hdr.m_tcp_hdr; }
    void set_ip_len(uint16_t len) override
    {
        m_header.hdr.m_ip_hdr.ip6_plen = htons(len - IPV6_HLEN);
    }
    void copy_l2_hdr(void *p_h) override;
    void copy_l2_ip_hdr(void *p_h) override;
    void copy_l2_ip_udp_hdr(void *p_h) override;
    header *copy() override { return new header_ipv6(*this); }

private:
    tx_ipv6_packet_template_t m_header;
    header_ipv6(const header_ipv6 &h);
};

#ifndef IPV6_HLEN
#define IPV6_HLEN 40U
#endif

enum ip_version {
    IPV4 = 4,
    IPV6 = 6,
};

inline static enum ip_version ip_header_version(const void *p_ip_h)
{
    // IPv4 and IPv6 headers share the version field.
    return static_cast<enum ip_version>(reinterpret_cast<const struct iphdr *>(p_ip_h)->version);
}

template <typename T> inline void fill_hdrs(const void *pkt, void *&ip_hdr, void *&tcp_udp_hdr)
{
    // tcp and udp are union headers in tx_ipv4_hdr_template_t and tx_ipv6_hdr_template_t
    ip_hdr = (void *)(&(((T *)pkt)->m_ip_hdr));
    tcp_udp_hdr = (void *)(&(((T *)pkt)->m_tcp_hdr));

    NOT_IN_USE(ip_hdr);
    NOT_IN_USE(tcp_udp_hdr);
}

inline void get_ipv6_hdrs_frag_ext_ptr(tx_ipv6_hdr_template_t *pkt, ip6_hdr *&ip_hdr,
                                       ip6_frag *&frag_ext_hdr)
{
    // Assuming ip packets contains only a single extension header
    // which is the fragmentation header
    ip_hdr = &(pkt->m_ip_hdr);
    frag_ext_hdr = reinterpret_cast<ip6_frag *>(reinterpret_cast<uint8_t *>(ip_hdr) + IPV6_HLEN);
}

inline void get_ipv6_hdrs_frag_ext_udp_ptr(tx_ipv6_hdr_template_t *pkt, ip6_hdr *&ip_hdr,
                                           ip6_frag *&frag_ext_hdr, udphdr *&udp_hdr)
{
    get_ipv6_hdrs_frag_ext_ptr(pkt, ip_hdr, frag_ext_hdr);
    udp_hdr = reinterpret_cast<udphdr *>(reinterpret_cast<uint8_t *>(frag_ext_hdr) + FRAG_EXT_HLEN);
}

inline void copy_l2_hdr_words(uint32_t *to_words, uint32_t *from_words)
{
    to_words[0] = from_words[0]; // dummy(16) + l2(16) (mac / dummy)
    to_words[1] = from_words[1]; // l2 (32)            (mac / dummy)
    to_words[2] = from_words[2]; // l2 (32)            (mac / dummy)
    to_words[3] = from_words[3]; // l2 (32)            (mac / dummy)
    to_words[4] = from_words[4]; // l2 (32)            (mac / vlan / ipoib)
}

inline void set_ipv4_len(void *ip, uint16_t len)
{
    reinterpret_cast<iphdr *>(ip)->tot_len = len;
}

inline void set_ipv6_len(void *ip, uint16_t len)
{
    reinterpret_cast<ip6_hdr *>(ip)->ip6_plen = len;
}
#endif /* HEADER_H */
