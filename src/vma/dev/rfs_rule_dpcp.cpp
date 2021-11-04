/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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

#include "vma/dev/rfs_rule_dpcp.h"

#if defined(DEFINED_DPCP) && (DEFINED_DPCP > 10113)

#include <cinttypes>
#include "vma/dev/rfs.h"

#define MODULE_NAME "rfs_rule_dpcp"

rfs_rule_dpcp::~rfs_rule_dpcp()
{
}

bool rfs_rule_dpcp::create(const vma_ibv_flow_attr& attrs, dpcp::tir& in_tir, dpcp::adapter& in_adapter)
{
    const attach_flow_data_eth_ipv4_tcp_udp_t::ibv_flow_attr_eth_ipv4_tcp_udp& attrs_tcpudp(
        reinterpret_cast<const attach_flow_data_eth_ipv4_tcp_udp_t::ibv_flow_attr_eth_ipv4_tcp_udp&>(attrs));
    
    dpcp::match_params mp;
    dpcp::match_params match_msk;
    
    memset(&mp, 0, sizeof(mp));
    memset(&match_msk, 0, sizeof(match_msk));

    memset(&match_msk.dst_mac, 0xFF, sizeof(match_msk.dst_mac));
    memcpy(&mp.dst_mac, attrs_tcpudp.eth.val.dst_mac, 
       min(sizeof(mp.dst_mac), sizeof(attrs_tcpudp.eth.val.dst_mac)));

    match_msk.ethertype = htons(attrs_tcpudp.eth.mask.ether_type);
    mp.ethertype = htons(attrs_tcpudp.eth.val.ether_type);
    match_msk.vlan_id = ntohs(attrs_tcpudp.eth.mask.vlan_tag);
    mp.vlan_id = ntohs(attrs_tcpudp.eth.val.vlan_tag);
    match_msk.dst_ip = ntohl(attrs_tcpudp.ipv4.mask.dst_ip);
    mp.dst_ip = ntohl(attrs_tcpudp.ipv4.val.dst_ip);
    match_msk.src_ip = ntohl(attrs_tcpudp.ipv4.mask.src_ip);
    mp.src_ip = ntohl(attrs_tcpudp.ipv4.val.src_ip);
    match_msk.dst_port = ntohs(attrs_tcpudp.tcp_udp.mask.dst_port);
    mp.dst_port = ntohs(attrs_tcpudp.tcp_udp.val.dst_port);
    match_msk.src_port = ntohs(attrs_tcpudp.tcp_udp.mask.src_port);
    mp.src_port = ntohs(attrs_tcpudp.tcp_udp.val.src_port);
    match_msk.protocol = 0xFF;
    mp.protocol = (attrs_tcpudp.tcp_udp.type == VMA_IBV_FLOW_SPEC_TCP ? 6U : 17U);
    match_msk.ip_version = 0xF;
    mp.ip_version = 4U;
    
    dpcp::flow_rule* new_rule = nullptr;
    dpcp::status status_out = in_adapter.create_flow_rule(attrs.priority, match_msk, new_rule);
	if (status_out != dpcp::DPCP_OK) {
        rfs_logerr("Failed dpcp_adpater::create_flow_rule(), Type: %u, Priority %" PRIu16 ", Status: %d" , 
            static_cast<unsigned int>(attrs.type), attrs.priority, static_cast<int>(status_out));
        return false;
    }

    rfs_logdbg("Succeeded dpcp_adpater::create_flow_rule(), Type: %u, Priority %" PRIu16 ", rfs_rule_dpcp %p, dpcp_flow: %p", 
            static_cast<unsigned int>(attrs.type), attrs.priority, this, new_rule);

    _dpcp_flow.reset(new_rule);

    status_out = _dpcp_flow->set_match_value(mp);
    if (status_out != dpcp::DPCP_OK) {
        rfs_logerr("Failed dpcp_flow_rule::set_match_value(), Status: %d, dpcp_flow: %p", static_cast<int>(status_out), new_rule);
        return false;
    }

    status_out = _dpcp_flow->add_dest_tir(&in_tir);
    if (status_out != dpcp::DPCP_OK) {
        rfs_logerr("Failed dpcp_flow_rule::add_dest_tir(), Status: %d, dpcp_flow: %p", static_cast<int>(status_out), new_rule);
        return false;
    } 
      
    uint32_t tirn = 0U;
    in_tir.get_id(tirn);
    rfs_logdbg("Added dpcp_flow_rule::add_dest_tir() TIR %" PRIu32 ", dpcp_flow: %p", tirn, new_rule);
    
    if (attrs_tcpudp.flow_tag.type == VMA_IBV_FLOW_SPEC_ACTION_TAG) {
        rfs_logdbg("Setting flow tag dpcp_adpater::set_flow_id(), Tag: %" PRIu32 ", dpcp_flow: %p", 
            attrs_tcpudp.flow_tag.tag_id, new_rule);

        status_out = _dpcp_flow->set_flow_id(attrs_tcpudp.flow_tag.tag_id);
        if (status_out != dpcp::DPCP_OK) {
            rfs_logerr("Failed dpcp_flow_rule::set_flow_id(), Status: %d, dpcp_flow: %p", static_cast<int>(status_out), new_rule);
            return false;
        }
    }
    
    status_out = _dpcp_flow->apply_settings();
    if (status_out != dpcp::DPCP_OK) {
        rfs_logerr("Failed dpcp_flow_rule::apply_settings(), Status: %d, dpcp_flow: %p", static_cast<int>(status_out), new_rule);
        return false;
    }

    return true;
}

#endif // defined(DEFINED_DPCP) && (DEFINED_DPCP > 10113)

