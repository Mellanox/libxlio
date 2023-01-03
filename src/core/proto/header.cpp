/*
 * Copyright (c) 2001-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "header.h"
#include "dst_entry.h"

void header::init()
{
    m_ip_header_len = 0;
    m_transport_header_len = 0;
    m_total_hdr_len = 0;
    m_aligned_l2_l3_len = 0;
    m_is_vlan_enabled = false;
}

header::header()
    : m_actual_hdr_addr(0)
    , m_transport_header_tx_offset(0)
    , m_is_vlan_enabled(false)
    , m_transport_type(XLIO_TRANSPORT_UNKNOWN)
{
    header::init();
}

header::header(const header &h)
{
    m_ip_header_len = h.m_ip_header_len;
    m_transport_header_len = h.m_transport_header_len;
    m_total_hdr_len = h.m_total_hdr_len;
    m_aligned_l2_l3_len = h.m_aligned_l2_l3_len;
    m_transport_header_tx_offset = h.m_transport_header_tx_offset;
    m_is_vlan_enabled = h.m_is_vlan_enabled;
    m_transport_type = h.m_transport_type;
    m_actual_hdr_addr = 0;
}

void header::configure_udp_header(uint16_t dest_port, uint16_t src_port)
{
    udphdr *p_udp_hdr = get_udp_hdr();

    memset(p_udp_hdr, 0, (sizeof(*p_udp_hdr)));

    p_udp_hdr->dest = dest_port;
    p_udp_hdr->source = src_port;
    p_udp_hdr->check = 0;

    m_total_hdr_len += UDP_HLEN;
}

void header::configure_tcp_ports(uint16_t dest_port, uint16_t src_port)
{
    tcphdr *p_tcp_hdr = get_tcp_hdr();

    /* memset(p_tcp_hdr, 0 , (sizeof(*p_tcp_hdr))); */

    p_tcp_hdr->dest = dest_port;
    p_tcp_hdr->source = src_port;

    /* don't increase header len, as the tcp stack is not using these ports */
}

void header::set_mac_to_eth_header(const L2_address &src, const L2_address &dst, ethhdr &eth_header)
{
    // copy source and destination mac address to eth header
    memcpy(eth_header.h_source, src.get_address(), src.get_addrlen());
    memcpy(eth_header.h_dest, dst.get_address(), dst.get_addrlen());
    // sets the size of 'm_eth_hdr' in the 'eth_hdr_template' struct
    m_transport_header_len = sizeof(eth_header);
}

void header_ipv4::set_ip_ttl_hop_limit(uint8_t ttl_hop_limit)
{
    iphdr *p_hdr = &m_header.hdr.m_ip_hdr;

    p_hdr->ttl = ttl_hop_limit;
}

void header_ipv6::set_ip_ttl_hop_limit(uint8_t ttl_hop_limit)
{
    ip6_hdr *p_hdr = &m_header.hdr.m_ip_hdr;

    p_hdr->ip6_hlim = ttl_hop_limit;
}

void header_ipv4::set_ip_tos(uint8_t tos)
{
    iphdr *p_hdr = &m_header.hdr.m_ip_hdr;

    p_hdr->tos = tos;
}

void header::configure_eth_headers(const L2_address &src, const L2_address &dst,
                                   uint16_t encapsulated_proto)
{
    eth_hdr_template_t *p_eth_hdr = &get_l2_hdr()->eth_hdr;
    p_eth_hdr->m_eth_hdr.h_proto = htons(encapsulated_proto);
    m_is_vlan_enabled = false;
    set_mac_to_eth_header(src, dst, p_eth_hdr->m_eth_hdr);
    m_transport_header_tx_offset = sizeof(p_eth_hdr->m_alignment);
    m_total_hdr_len += m_transport_header_len;

    update_actual_hdr_addr();
}

void header::update_actual_hdr_addr()
{
    m_actual_hdr_addr =
        (uintptr_t)((((uint8_t *)(get_hdr_addr())) + (uint8_t)(m_transport_header_tx_offset)));
}

void header::configure_vlan_eth_headers(const L2_address &src, const L2_address &dst, uint16_t tos,
                                        uint16_t encapsulated_proto)
{
    vlan_eth_hdr_template_t *p_vlan_eth_hdr = &get_l2_hdr()->vlan_eth_hdr;
    set_mac_to_eth_header(src, dst, p_vlan_eth_hdr->m_eth_hdr);

    p_vlan_eth_hdr->m_vlan_hdr.h_vlan_TCI = htons(tos);
    p_vlan_eth_hdr->m_eth_hdr.h_proto = htons(ETH_P_8021Q);
    p_vlan_eth_hdr->m_vlan_hdr.h_vlan_encapsulated_proto = htons(encapsulated_proto);
    m_is_vlan_enabled = true;
    m_transport_header_tx_offset = sizeof(p_vlan_eth_hdr->m_alignment);
    m_transport_header_len += sizeof(p_vlan_eth_hdr->m_vlan_hdr);
    m_total_hdr_len += m_transport_header_len;
    update_actual_hdr_addr();
}

bool header::set_vlan_pcp(uint8_t pcp)
{
    if (!m_is_vlan_enabled) {
        return false;
    }
    vlan_eth_hdr_template_t *p_vlan_eth_hdr = &get_l2_hdr()->vlan_eth_hdr;
    // zero old pcp and set new one
    uint16_t vlan_pcp = ((uint16_t)pcp << NET_ETH_VLAN_PCP_OFFSET) |
        (htons(p_vlan_eth_hdr->m_vlan_hdr.h_vlan_TCI) & 0x1fff);
    p_vlan_eth_hdr->m_vlan_hdr.h_vlan_TCI = htons(vlan_pcp);

    return true;
}

void header_ipv4::init()
{
    header::init();
    m_aligned_l2_l3_len = IPV4_HDR_LEN_WITHOUT_OPTIONS + sizeof(l2_hdr_template_t); // 40
}

header_ipv4::header_ipv4()
    : header()
{
    header_ipv4::init();
}

header_ipv4::header_ipv4(const header_ipv4 &h)
    : header(h)
{
    m_header = h.m_header;
    update_actual_hdr_addr();
};

void header_ipv4::configure_ip_header(uint8_t protocol, const ip_address &src,
                                      const ip_address &dest, const dst_entry &_dst_entry,
                                      uint16_t packet_id)
{
    iphdr *p_hdr = &m_header.hdr.m_ip_hdr;
    memset(p_hdr, 0, (sizeof(*p_hdr)));

    // build ipv4 header
    p_hdr->ihl = IPV4_HDR_LEN_WITHOUT_OPTIONS /
        sizeof(uint32_t); // 5 * 4 bytes (32 bit words) = 20 bytes = regular iph length with out any
                          // optionals
    p_hdr->version = IPV4_VERSION;
    p_hdr->protocol = protocol;
    p_hdr->saddr = src.get_in_addr();
    p_hdr->daddr = dest.get_in_addr();
    p_hdr->tos = _dst_entry.get_tos();
    p_hdr->ttl = _dst_entry.get_ttl_hop_limit();
    p_hdr->id = packet_id;

    m_ip_header_len = IPV4_HDR_LEN_WITHOUT_OPTIONS;
    m_total_hdr_len += m_ip_header_len;
}

void header_ipv4::copy_l2_hdr(void *p_h)
{
    tx_ipv4_packet_template_t *p_hdr = (tx_ipv4_packet_template_t *)p_h;
    uint32_t *to_words = p_hdr->words;
    uint32_t *from_words = m_header.words;
    copy_l2_hdr_words(to_words, from_words);
}

void header_ipv4::copy_l2_ip_hdr(void *p_h)
{
    tx_ipv4_packet_template_t *p_hdr = reinterpret_cast<tx_ipv4_packet_template_t *>(p_h);
    p_hdr->words[0] = m_header.words[0]; // dummy(16) + l2(16) (mac / dummy)
    p_hdr->words[1] = m_header.words[1]; // l2 (32)            (mac / dummy)
    p_hdr->words[2] = m_header.words[2]; // l2 (32)            (mac / dummy)
    p_hdr->words[3] = m_header.words[3]; // l2 (32)            (mac / dummy)
    p_hdr->words[4] = m_header.words[4]; // l2 (32)            (mac / vlan / ipoib)
    p_hdr->words[5] = m_header.words[5]; // IP-> ver(4) + hdrlen(4) + tos(8) + totlen(16)
    p_hdr->words[6] = m_header.words[6]; // IP-> id(16) + frag(16)
    p_hdr->words[7] = m_header.words[7]; // IP-> ttl(8) + protocol(8) + checksum(16)
    p_hdr->words[8] = m_header.words[8]; // IP-> saddr(32)
    p_hdr->words[9] = m_header.words[9]; // IP-> daddr(32)
}

void header_ipv4::copy_l2_ip_udp_hdr(void *p_h)
{
    tx_ipv4_packet_template_t *p_hdr = reinterpret_cast<tx_ipv4_packet_template_t *>(p_h);
    p_hdr->words[0] = m_header.words[0]; // dummy(16) + l2(16) (mac / dummy)
    p_hdr->words[1] = m_header.words[1]; // l2 (32)            (mac / dummy)
    p_hdr->words[2] = m_header.words[2]; // l2 (32)            (mac / dummy)
    p_hdr->words[3] = m_header.words[3]; // l2 (32)            (mac / dummy)
    p_hdr->words[4] = m_header.words[4]; // l2 (32)            (mac / vlan / ipoib)
    p_hdr->words[5] = m_header.words[5]; // IP-> ver(4) + hdrlen(4) + tos(8) + totlen(16)
    p_hdr->words[6] = m_header.words[6]; // IP-> id(16) + frag(16)
    p_hdr->words[7] = m_header.words[7]; // IP-> ttl(8) + protocol(8) + checksum(16)
    p_hdr->words[8] = m_header.words[8]; // IP-> saddr(32)
    p_hdr->words[9] = m_header.words[9]; // IP-> daddr(32)
    p_hdr->words[10] = m_header.words[10]; // UDP-> sport(16) + dst_port(16)
    p_hdr->words[11] = m_header.words[11]; // UDP-> len(16) + check(16)
}

void header_ipv6::init()
{
    header::init();
    m_aligned_l2_l3_len = IPV6_HLEN + L2_ALIGNED_HLEN; // 60
}

header_ipv6::header_ipv6()
    : header()
{
    header_ipv6::init();
    update_actual_hdr_addr();
}

header_ipv6::header_ipv6(const header_ipv6 &h)
    : header(h)
{
    m_header = h.m_header;
};

void header_ipv6::configure_ip_header(uint8_t protocol, const ip_address &src,
                                      const ip_address &dest)
{
    ip6_hdr *p_hdr = &m_header.hdr.m_ip_hdr;
    memset(p_hdr, 0, (sizeof(*p_hdr)));

    // build ipv6 header
    p_hdr->ip6_vfc = IPV6_VERSION << 4;
    p_hdr->ip6_nxt = protocol;

    *reinterpret_cast<ip_address *>(&p_hdr->ip6_src) = src;
    *reinterpret_cast<ip_address *>(&p_hdr->ip6_dst) = dest;

    m_ip_header_len = IPV6_HLEN;
    m_total_hdr_len += m_ip_header_len;
}

void header_ipv6::configure_ip_header(uint8_t protocol, const ip_address &src,
                                      const ip_address &dest, const dst_entry &_dst_entry,
                                      uint16_t packet_id)
{
    NOT_IN_USE(packet_id);
    configure_ip_header(protocol, src, dest);
    set_ip_ttl_hop_limit(_dst_entry.get_ttl_hop_limit());
}

void header_ipv6::copy_l2_hdr(void *p_h)
{
    tx_ipv6_packet_template_t *p_hdr = reinterpret_cast<tx_ipv6_packet_template_t *>(p_h);
    uint32_t *to_words = p_hdr->words;
    uint32_t *from_words = m_header.words;
    copy_l2_hdr_words(to_words, from_words);
}

void header_ipv6::copy_l2_ip_hdr(void *p_h)
{
    tx_ipv6_packet_template_t *p_hdr = reinterpret_cast<tx_ipv6_packet_template_t *>(p_h);
    p_hdr->words[0] = m_header.words[0]; // dummy(16) + l2(16) (mac / dummy)
    p_hdr->words[1] = m_header.words[1]; // l2 (32)            (mac / dummy)
    p_hdr->words[2] = m_header.words[2]; // l2 (32)            (mac / dummy)
    p_hdr->words[3] = m_header.words[3]; // l2 (32)            (mac / dummy)
    p_hdr->words[4] = m_header.words[4]; // l2 (32)            (mac / vlan / ipoib)
    p_hdr->words[5] = m_header.words[5]; // IP-> version(4) + priority(4) + flow_lbl(24)
    p_hdr->words[6] = m_header.words[6]; // IP-> payload_len(16) + nexthdr(8) + hop_limit(8)
    p_hdr->words[7] = m_header.words[7]; // IP-> saddr(32)
    p_hdr->words[8] = m_header.words[8]; // IP-> saddr(32)
    p_hdr->words[9] = m_header.words[9]; // IP-> saddr(32)
    p_hdr->words[10] = m_header.words[10]; // IP-> saddr(32)
    p_hdr->words[11] = m_header.words[11]; // IP-> daddr(32)
    p_hdr->words[12] = m_header.words[12]; // IP-> daddr(32)
    p_hdr->words[13] = m_header.words[13]; // IP-> daddr(32)
    p_hdr->words[14] = m_header.words[14]; // IP-> daddr(32)
}

void header_ipv6::copy_l2_ip_udp_hdr(void *p_h)
{
    tx_ipv6_packet_template_t *p_hdr = reinterpret_cast<tx_ipv6_packet_template_t *>(p_h);
    p_hdr->words[0] = m_header.words[0]; // dummy(16) + l2(16) (mac / dummy)
    p_hdr->words[1] = m_header.words[1]; // l2 (32)            (mac / dummy)
    p_hdr->words[2] = m_header.words[2]; // l2 (32)            (mac / dummy)
    p_hdr->words[3] = m_header.words[3]; // l2 (32)            (mac / dummy)
    p_hdr->words[4] = m_header.words[4]; // l2 (32)            (mac / vlan / ipoib)
    p_hdr->words[5] = m_header.words[5]; // IP-> version(4) + priority(4) + flow_lbl(24)
    p_hdr->words[6] = m_header.words[6]; // IP-> payload_len(16) + nexthdr(8) + hop_limit(8)
    p_hdr->words[7] = m_header.words[7]; // IP-> saddr(32)
    p_hdr->words[8] = m_header.words[8]; // IP-> saddr(32)
    p_hdr->words[9] = m_header.words[9]; // IP-> saddr(32)
    p_hdr->words[10] = m_header.words[10]; // IP-> saddr(32)
    p_hdr->words[11] = m_header.words[11]; // IP-> daddr(32)
    p_hdr->words[12] = m_header.words[12]; // IP-> daddr(32)
    p_hdr->words[13] = m_header.words[13]; // IP-> daddr(32)
    p_hdr->words[14] = m_header.words[14]; // IP-> daddr(32)
    p_hdr->words[15] = m_header.words[15]; // UDP-> sport(16) + dst_port(16)
    p_hdr->words[16] = m_header.words[16]; // UDP-> len(16) + check(16)
}
