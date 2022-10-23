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

#include "utils/bullseye.h"
#include "util/utils.h"
#include "dev/rfs_mc.h"
#include "dev/ring_simple.h"

#define MODULE_NAME "rfs_mc"

rfs_mc::rfs_mc(flow_tuple *flow_spec_5t, ring_slave *p_ring,
               rfs_rule_filter *rule_filter /*= NULL*/, int flow_tag_id /*=0*/)
    : rfs(flow_spec_5t, p_ring, rule_filter, flow_tag_id)
{
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!m_flow_tuple.is_udp_mc()) {
        throw_xlio_exception("rfs_mc called with non mc destination ip");
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    if (m_p_ring->is_simple() && !prepare_flow_spec()) {
        throw_xlio_exception("IB multicast offload is not supported");
    }
}

bool rfs_mc::prepare_flow_spec()
{
    ring_simple *p_ring = dynamic_cast<ring_simple *>(m_p_ring);

    if (!p_ring) {
        rfs_logpanic("Incompatible ring type");
    }

    transport_type_t type = p_ring->get_transport_type();

    /*
     * todo note that ring is not locked here.
     * we touch members that should not change during the ring life.
     * the ring will not be deleted as we increased refcnt.
     * if one of these assumptions change, we must lock.
     */
    attach_flow_data_t *p_attach_flow_data = nullptr;
    xlio_ibv_flow_spec_eth *p_eth = nullptr;
    xlio_ibv_flow_spec_tcp_udp *p_tcp_udp = nullptr;

    switch (type) {
    case XLIO_TRANSPORT_ETH: {
        bool is_ipv4 = (m_flow_tuple.get_family() == AF_INET);
        if (is_ipv4) {
            prepare_flow_spec_by_ip<attach_flow_data_eth_ipv4_tcp_udp_t>(
                p_ring->m_p_qp_mgr, p_attach_flow_data, p_eth, p_tcp_udp);
        } else {
            prepare_flow_spec_by_ip<attach_flow_data_eth_ipv6_tcp_udp_t>(
                p_ring->m_p_qp_mgr, p_attach_flow_data, p_eth, p_tcp_udp);
        }

        if (!p_attach_flow_data) {
            return false;
        }

        uint8_t dst_mac[6];
        create_multicast_mac_from_ip(dst_mac, m_flow_tuple.get_dst_ip(), m_flow_tuple.get_family());
        ibv_flow_spec_eth_set(p_eth, dst_mac, htons(p_ring->m_p_qp_mgr->get_partiton()), is_ipv4);

        if (safe_mce_sys().eth_mc_l2_only_rules) {
            ibv_flow_spec_tcp_udp_set(p_tcp_udp, 0, 0, 0);
        } else {
            ibv_flow_spec_tcp_udp_set(p_tcp_udp, (m_flow_tuple.get_protocol() == PROTO_TCP),
                                      m_flow_tuple.get_dst_port(), m_flow_tuple.get_src_port());
        }

        break;
    }
        BULLSEYE_EXCLUDE_BLOCK_START
    default:
        rfs_logpanic("Incompatible transport type = %d", type);
        return false;
        break;
        BULLSEYE_EXCLUDE_BLOCK_END
    }

    m_attach_flow_data_vector.push_back(p_attach_flow_data);
    return true;
}

bool rfs_mc::rx_dispatch_packet(mem_buf_desc_t *p_rx_wc_buf_desc, void *pv_fd_ready_array)
{
    // Dispatching: Notify new packet to all registered receivers
    p_rx_wc_buf_desc->reset_ref_count();
    p_rx_wc_buf_desc->inc_ref_count();

    for (uint32_t i = 0; i < m_n_sinks_list_entries; ++i) {
        if (m_sinks_list[i]) {
            m_sinks_list[i]->rx_input_cb(p_rx_wc_buf_desc, pv_fd_ready_array);
        }
    }

    // Check packet ref_count to see if any receivers are interested in this packet
    if (p_rx_wc_buf_desc->dec_ref_count() > 1) {
        // The sink will be responsible to return the buffer to CQ for reuse
        return true;
    }

    // Reuse this data buffer & mem_buf_desc
    return false;
}
