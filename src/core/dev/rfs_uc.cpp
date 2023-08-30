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

#include "utils/bullseye.h"
#include "dev/rfs_uc.h"
#include "proto/L2_address.h"
#include "dev/ring_simple.h"
#include "util/instrumentation.h"
#include "sock/sock-redirect.h"

#define MODULE_NAME "rfs_uc"

rfs_uc::rfs_uc(flow_tuple *flow_spec_5t, ring_slave *p_ring, rfs_rule_filter *rule_filter,
               uint32_t flow_tag_id)
    : rfs(flow_spec_5t, p_ring, rule_filter, flow_tag_id)
{
    BULLSEYE_EXCLUDE_BLOCK_START
    if (m_flow_tuple.is_udp_mc()) {
        throw_xlio_exception("rfs_uc called with MC destination ip");
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    if (m_p_ring->is_simple() && !prepare_flow_spec()) {
        throw_xlio_exception("rfs_uc: Incompatible transport type");
    }
}

bool rfs_uc::prepare_flow_spec()
{
    ring_simple *p_ring = dynamic_cast<ring_simple *>(m_p_ring);

    if (!p_ring) {
        rfs_logpanic("Incompatible ring type");
    }

    /*
     * todo note that ring is not locked here.
     * we touch members that should not change during the ring life.
     * the ring will not be deleted as we increased refcnt.
     * if one of these assumptions change, we must lock.
     */
    attach_flow_data_t *p_attach_flow_data = nullptr;
    xlio_ibv_flow_spec_eth *p_eth = nullptr;
    xlio_ibv_flow_spec_tcp_udp *p_tcp_udp = nullptr;

    switch (p_ring->get_transport_type()) {
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

        ibv_flow_spec_eth_set(p_eth, p_ring->m_p_l2_addr->get_address(),
                              htons(p_ring->m_p_qp_mgr->get_partiton()), is_ipv4);

        break;
    }
        BULLSEYE_EXCLUDE_BLOCK_START
    default:
        return false;
        break;
        BULLSEYE_EXCLUDE_BLOCK_END
    }

    ibv_flow_spec_tcp_udp_set(p_tcp_udp, (m_flow_tuple.get_protocol() == PROTO_TCP),
                              m_flow_tuple.get_dst_port(), m_flow_tuple.get_src_port());

    if (m_flow_tuple.get_src_port() || !m_flow_tuple.get_src_ip().is_anyaddr()) {
        // set priority of 5-tuple to be higher than 3-tuple
        // to make sure 5-tuple have higher priority on ConnectX-4
        p_attach_flow_data->ibv_flow_attr.priority = 1;
    }
#if defined(DEFINED_NGINX)
    else if (g_p_app->type == APP_NGINX && g_p_app->workers_num > 0) {
        if (m_flow_tuple.get_protocol() != PROTO_UDP ||
            (g_map_udp_bounded_port.count(ntohs(m_flow_tuple.get_dst_port())))) {
            int src_port;
            if (g_p_app->add_second_4t_rule) {
                src_port = g_p_app->workers_num + g_worker_index;
            } else {
                src_port = g_worker_index;
            }
            p_tcp_udp->val.src_port = htons((uint16_t)src_port * safe_mce_sys().src_port_stride);
            p_tcp_udp->mask.src_port = htons((uint16_t)(
                (g_p_app->workers_pow2 * safe_mce_sys().src_port_stride) - 2));
            p_attach_flow_data->ibv_flow_attr.priority = 1;
            rfs_logdbg("safe_mce_sys().src_port_stride: %d safe_mce_sys().workers_num %d \n",
                       safe_mce_sys().src_port_stride, g_p_app->workers_num);
            rfs_logdbg("sp_tcp_udp->val.src_port: %d p_tcp_udp->mask.src_port %d \n",
                       ntohs(p_tcp_udp->val.src_port), ntohs(p_tcp_udp->mask.src_port));
            m_flow_tuple.set_src_port(p_tcp_udp->val.src_port);
        }
    }
#endif
#if defined(DEFINED_ENVOY)
    else if (g_p_app->type == APP_ENVOY &&  g_p_app->workers_num > 0 && g_p_app->get_worker_id() >= 0) {
        if (m_flow_tuple.get_protocol() != PROTO_UDP) {
            int src_port;
            if (g_p_app->add_second_4t_rule) {
                src_port = g_p_app->workers_num + g_p_app->get_worker_id();
            } else {
                src_port = g_p_app->get_worker_id();
            }
            p_tcp_udp->val.src_port = htons((uint16_t)src_port * g_p_app->src_port_stride);
            p_tcp_udp->mask.src_port =
                htons((uint16_t)((g_p_app->workers_pow2 * g_p_app->src_port_stride) - 2));
            p_attach_flow_data->ibv_flow_attr.priority = 1;
            rfs_logdbg("g_p_app->src_port_stride: %d g_p_app->workers_num %d \n",
                       g_p_app->src_port_stride, g_p_app->workers_num);
            rfs_logdbg("sp_tcp_udp->val.src_port: %d p_tcp_udp->mask.src_port %d \n",
                       ntohs(p_tcp_udp->val.src_port), ntohs(p_tcp_udp->mask.src_port));
            m_flow_tuple.set_src_port(p_tcp_udp->val.src_port);
        }
    }
#endif /* DEFINED_ENVOY */

    rfs_logfunc("transport type: %d, num_of_specs: %d flow_tag_id: %d",
                p_ring->get_transport_type(), p_attach_flow_data->ibv_flow_attr.num_of_specs,
                m_flow_tag_id);

    m_attach_flow_data_vector.push_back(p_attach_flow_data);
    return true;
}

bool rfs_uc::rx_dispatch_packet(mem_buf_desc_t *p_rx_wc_buf_desc, void *pv_fd_ready_array)
{
    assert(safe_mce_sys().enable_socketxtreme && (1 == m_n_sinks_list_entries));

    p_rx_wc_buf_desc->reset_ref_count();

    for (uint32_t i = 0; i < m_n_sinks_list_entries; ++i) {
        if (likely(m_sinks_list[i])) {
#ifdef RDTSC_MEASURE_RX_DISPATCH_PACKET
            RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_DISPATCH_PACKET]);
#endif // RDTSC_MEASURE_RX_DISPATCH_PACKET
            p_rx_wc_buf_desc->inc_ref_count();
            m_sinks_list[i]->rx_input_cb(p_rx_wc_buf_desc, pv_fd_ready_array);
#ifdef RDTSC_MEASURE_RX_DISPATCH_PACKET
            RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_DISPATCH_PACKET]);
#endif // RDTSC_MEASURE_RX_DISPATCH_PACKET
       // Check packet ref_count to see the last receiver is interested in this packet
            if (p_rx_wc_buf_desc->dec_ref_count() > 1) {
                // The sink will be responsible to return the buffer to CQ for reuse
                return true;
            }
        }
    }
    // Reuse this data buffer & mem_buf_desc
    return false;
}
