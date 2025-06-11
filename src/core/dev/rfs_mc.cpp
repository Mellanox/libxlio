/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "utils/bullseye.h"
#include "util/utils.h"
#include "dev/rfs_mc.h"
#include "dev/ring_simple.h"
#include "sock/sockinfo.h"

#define MODULE_NAME "rfs_mc"

#define rfs_logpanic   __log_info_panic
#define rfs_logerr     __log_info_err
#define rfs_logwarn    __log_info_warn
#define rfs_loginfo    __log_info_info
#define rfs_logdbg     __log_info_dbg
#define rfs_logfunc    __log_info_func
#define rfs_logfuncall __log_info_funcall

rfs_mc::rfs_mc(flow_tuple *flow_spec_5t, ring_simple *p_ring,
               rfs_rule_filter *rule_filter /*= NULL*/, int flow_tag_id /*=0*/)
    : rfs(flow_spec_5t, p_ring, rule_filter, flow_tag_id)
{
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!m_flow_tuple.is_udp_mc()) {
        throw_xlio_exception("rfs_mc called with non mc destination ip");
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    prepare_flow_spec();
}

void rfs_mc::prepare_flow_spec()
{
    const ip_address &dst_ip =
        (safe_mce_sys().eth_mc_l2_only_rules ? ip_address::any_addr() : m_flow_tuple.get_dst_ip());

    prepare_flow_spec_eth_ip(dst_ip, ip_address::any_addr());

    uint8_t dst_mac[6];
    create_multicast_mac_from_ip(dst_mac, m_flow_tuple.get_dst_ip(), m_flow_tuple.get_family());

    memset(&m_match_mask.dst_mac, 0xFF, sizeof(m_match_mask.dst_mac));
    memcpy(&m_match_value.dst_mac, dst_mac, sizeof(dst_mac));

    if (safe_mce_sys().eth_mc_l2_only_rules) {
        m_match_mask.dst_port = m_match_value.dst_port = m_match_mask.src_port =
            m_match_value.src_port = 0U;

        m_match_mask.protocol = 0xFF;
        m_match_value.protocol = IPPROTO_UDP;
    } else {
        prepare_flow_spec_tcp_udp();
    }
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
