/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "utils/bullseye.h"
#include "dev/rfs_uc.h"
#include "proto/L2_address.h"
#include "dev/ring_simple.h"
#include "util/instrumentation.h"
#include "sock/sock-redirect.h"
#include "sock/sock-app.h"
#include "sock/sockinfo.h"

#define MODULE_NAME "rfs_uc"

#define rfs_logpanic   __log_info_panic
#define rfs_logerr     __log_info_err
#define rfs_logwarn    __log_info_warn
#define rfs_loginfo    __log_info_info
#define rfs_logdbg     __log_info_dbg
#define rfs_logfunc    __log_info_func
#define rfs_logfuncall __log_info_funcall

rfs_uc::rfs_uc(flow_tuple *flow_spec_5t, ring_slave *p_ring, rfs_rule_filter *rule_filter,
               uint32_t flow_tag_id)
    : rfs(flow_spec_5t, p_ring, rule_filter, flow_tag_id)
{
    BULLSEYE_EXCLUDE_BLOCK_START
    if (m_flow_tuple.is_udp_mc()) {
        throw_xlio_exception("rfs_uc called with MC destination ip");
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    if (m_p_ring->is_simple()) {
        prepare_flow_spec();
    }
}

void rfs_uc::prepare_flow_spec()
{
    if (!m_p_ring_simple) {
        rfs_logpanic("Incompatible ring type");
    }

    prepare_flow_spec_eth_ip(m_flow_tuple.get_dst_ip(), m_flow_tuple.get_src_ip());
    prepare_flow_spec_tcp_udp();

    memset(&m_match_mask.dst_mac, 0xFF, sizeof(m_match_mask.dst_mac));
    memcpy(&m_match_value.dst_mac, m_p_ring_simple->m_p_l2_addr->get_address(),
           sizeof(m_match_value.dst_mac));

    if (m_flow_tuple.get_src_port() || !m_flow_tuple.get_src_ip().is_anyaddr()) {
        // Set priority of 5-tuple to be higher than 3-tuple
        // to make sure 5-tuple have higher priority.
        m_priority = 1;
    }
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    else if (g_p_app->type != APP_NONE && g_p_app->get_worker_id() >= 0) {
#if defined(DEFINED_ENVOY)
        if (m_flow_tuple.get_protocol() != PROTO_UDP)
#else
        if (m_flow_tuple.get_protocol() != PROTO_UDP ||
            (g_map_udp_resue_port.count(((uint32_t)m_flow_tuple.get_family() << 16) |
                                        ntohs(m_flow_tuple.get_dst_port()))))
#endif
        {
            int src_port;
            if (g_p_app->add_second_4t_rule) {
                src_port = g_p_app->workers_num + g_p_app->get_worker_id();
            } else {
                src_port = g_p_app->get_worker_id();
            }

            m_match_mask.src_port =
                static_cast<uint16_t>((g_p_app->workers_pow2 * g_p_app->src_port_stride) - 2);
            m_match_value.src_port = static_cast<uint16_t>(src_port * g_p_app->src_port_stride);

            m_priority = 1;
            rfs_logdbg("src_port_stride: %d workers_num %d \n", g_p_app->src_port_stride,
                       g_p_app->workers_num);
            rfs_logdbg("sp_tcp_udp->val.src_port: %d p_tcp_udp->mask.src_port %d \n",
                       m_match_value.src_port, m_match_mask.src_port);

            m_flow_tuple.set_src_port(m_match_value.src_port);
        }
    }
#endif

    rfs_logfunc("Transport type: %d, flow_tag_id: %d", m_p_ring_simple->get_transport_type(),
                m_flow_tag_id);
}

bool rfs_uc::rx_dispatch_packet(mem_buf_desc_t *p_rx_wc_buf_desc, void *pv_fd_ready_array)
{
    p_rx_wc_buf_desc->reset_ref_count();
    for (uint32_t i = 0; i < m_n_sinks_list_entries; ++i) {
        if (likely(m_sinks_list[i])) {
            bool consumed = m_sinks_list[i]->rx_input_cb(p_rx_wc_buf_desc, pv_fd_ready_array);
            if (consumed) {
                // The sink will be responsible to return the buffer to CQ for reuse
                return true;
            }
        }
    }
    // Reuse this data buffer & mem_buf_desc
    return false;
}
