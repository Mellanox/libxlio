/*
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

#include "dev/rfs_rule.h"
#include "dev/ib_ctx_handler.h"
#include <cinttypes>
#include "dev/rfs.h"

#define MODULE_NAME "rfs_rule"

#define rfs_logpanic   __log_info_panic
#define rfs_logerr     __log_info_err
#define rfs_logwarn    __log_info_warn
#define rfs_loginfo    __log_info_info
#define rfs_logdbg     __log_info_dbg
#define rfs_logfunc    __log_info_func
#define rfs_logfuncall __log_info_funcall

rfs_rule::~rfs_rule()
{
    if (m_doca_flow_entry) {
        doca_error_t rc = doca_flow_pipe_remove_entry(0, 0U, m_doca_flow_entry);
        if (DOCA_IS_ERROR(rc)) {
            PRINT_DOCA_ERR(rfs_logerr, rc, "doca_flow_pipe_rm_entry entry: %p", m_doca_flow_entry);
        }
    }
}

bool rfs_rule::create(doca_flow_match &match_val, doca_flow_match &match_msk, uint16_t rx_queue_id,
                      dpcp::match_params &match_value, dpcp::match_params &match_mask,
                      dpcp::tir &in_tir, uint16_t priority, uint32_t flow_tag,
                      ib_ctx_handler &in_dev)
{
    doca_flow_pipe *root_pipe = in_dev.get_doca_root_pipe();
    if (!root_pipe) {
        return false;
    }

    dpcp::adapter &in_adapter = *in_dev.get_dpcp_adapter();

    rfs_logdbg("Creating flow dpcp_adpater::create_flow_rule(), priority %" PRIu16
               ", flow_tag: %" PRIu32,
               priority, flow_tag);
    rfs_logdbg("match_mask:\n"
               "ethertype: 0x%04" PRIx16 ", vlan_id: 0x%04" PRIx16 ", protocol: 0x%02" PRIx8
               ", ip_version: 0x%02" PRIx8 "\n"
               "dst_port: 0x%04" PRIx16 ", src_ports: 0x%04" PRIx16 "\n"
               "src_ip: ipv4: 0x%08" PRIx32 ", ipv6: 0x%016" PRIx64 "%016" PRIx64 "\n"
               "dst_ip: ipv4: 0x%08" PRIx32 ", ipv6: 0x%016" PRIx64 "%016" PRIx64 "\n"
               "dst_mac: 0x%016" PRIx64,
               match_mask.ethertype, match_mask.vlan_id, match_mask.protocol, match_mask.ip_version,
               match_mask.dst_port, match_mask.src_port, match_mask.src.ipv4,
               *reinterpret_cast<uint64_t *>(match_mask.src.ipv6 + 8),
               *reinterpret_cast<uint64_t *>(match_mask.src.ipv6), match_mask.dst.ipv4,
               *reinterpret_cast<uint64_t *>(match_mask.dst.ipv6 + 8),
               *reinterpret_cast<uint64_t *>(match_mask.dst.ipv6),
               *reinterpret_cast<uint64_t *>(match_mask.dst_mac));
    rfs_logdbg("match_value:\n"
               "ethertype: 0x%04" PRIx16 ", vlan_id: %" PRIu16 ", protocol: %" PRIu8
               ", ip_version: %" PRIu8 "\n"
               "dst_port: %" PRIu16 ", src_ports: %" PRIu16 "\n"
               "src_ip: ipv4: 0x%08" PRIx32 ", ipv6: 0x%016" PRIx64 "%016" PRIx64 "\n"
               "dst_ip: ipv4: 0x%08" PRIx32 ", ipv6: 0x%016" PRIx64 "%016" PRIx64 "\n"
               "dst_mac: 0x%016" PRIx64,
               match_value.ethertype, match_value.vlan_id, match_value.protocol,
               match_value.ip_version, match_value.dst_port, match_value.src_port,
               match_value.src.ipv4, *reinterpret_cast<uint64_t *>(match_value.src.ipv6 + 8),
               *reinterpret_cast<uint64_t *>(match_value.src.ipv6), match_value.dst.ipv4,
               *reinterpret_cast<uint64_t *>(match_value.dst.ipv6 + 8),
               *reinterpret_cast<uint64_t *>(match_value.dst.ipv6),
               *reinterpret_cast<uint64_t *>(match_value.dst_mac));

    if (safe_mce_sys().doca_rx) { // Temporary check
        NOT_IN_USE(match_val);
        NOT_IN_USE(match_msk);
        NOT_IN_USE(rx_queue_id);
        doca_flow_fwd all_fwd;
        memset(&all_fwd, 0, sizeof(all_fwd));
        all_fwd.type = DOCA_FLOW_FWD_RSS;
        all_fwd.num_of_queues = 1;
        all_fwd.rss_queues = &rx_queue_id;
        all_fwd.rss_outer_flags =
            (match_value.ip_version = 4U ? DOCA_FLOW_RSS_IPV4 : DOCA_FLOW_RSS_IPV6);
        all_fwd.rss_outer_flags |=
            (match_value.protocol == IPPROTO_TCP ? DOCA_FLOW_RSS_TCP : DOCA_FLOW_RSS_UDP);

        doca_error_t rc = doca_flow_pipe_control_add_entry(
            0, priority, root_pipe, &match_val, &match_msk, nullptr, nullptr, nullptr, nullptr,
            nullptr, &all_fwd, nullptr, &m_doca_flow_entry);
        if (DOCA_IS_ERROR(rc)) {
            PRINT_DOCA_ERR(rfs_logerr, rc, "doca_flow_pipe_control_add_entry root_pipe: %p",
                           root_pipe);
            return false;
        }

        rc = doca_flow_entries_process(in_dev.get_doca_flow_port(), 0, 60000U, 2U);
        if (DOCA_IS_ERROR(rc)) {
            PRINT_DOCA_ERR(rfs_logerr, rc, "doca_flow_pipe_control_add_entry port/root_pipe: %p,%p",
                           in_dev.get_doca_flow_port(), root_pipe);
            return false;
        }

        rfs_logdbg("DOCA Flow Entry added (%p)", m_doca_flow_entry);

        return true; // [Temp] SKIP DPCP Rule.
    }

    dpcp::flow_rule *new_rule = nullptr;
    dpcp::status status_out = in_adapter.create_flow_rule(priority, match_mask, new_rule);
    if (status_out != dpcp::DPCP_OK) {
        rfs_logerr("Failed dpcp_adpater::create_flow_rule(), Priority %" PRIu16 ", Status: %d",
                   priority, static_cast<int>(status_out));
        return false;
    }

    rfs_logdbg("Succeeded dpcp_adpater::create_flow_rule(), Priority %" PRIu16
               ", rfs_rule %p, dpcp_flow: %p",
               priority, this, new_rule);

    _dpcp_flow.reset(new_rule);

    status_out = _dpcp_flow->set_match_value(match_value);
    if (status_out != dpcp::DPCP_OK) {
        rfs_logerr("Failed dpcp_flow_rule::set_match_value(), Status: %d, dpcp_flow: %p",
                   static_cast<int>(status_out), new_rule);
        return false;
    }

    status_out = _dpcp_flow->add_dest_tir(&in_tir);
    if (status_out != dpcp::DPCP_OK) {
        rfs_logerr("Failed dpcp_flow_rule::add_dest_tir(), Status: %d, dpcp_flow: %p",
                   static_cast<int>(status_out), new_rule);
        return false;
    }

    uint32_t tirn = 0U;
    in_tir.get_id(tirn);
    rfs_logdbg("Added dpcp_flow_rule::add_dest_tir() TIR %" PRIu32 ", dpcp_flow: %p", tirn,
               new_rule);

    if (flow_tag) {
        rfs_logdbg("Setting flow tag dpcp_adpater::set_flow_id(), Tag: %" PRIu32 ", dpcp_flow: %p",
                   flow_tag, new_rule);

        status_out = _dpcp_flow->set_flow_id(flow_tag);
        if (status_out != dpcp::DPCP_OK) {
            rfs_logerr("Failed dpcp_flow_rule::set_flow_id(), Status: %d, dpcp_flow: %p",
                       static_cast<int>(status_out), new_rule);
            return false;
        }
    }

    status_out = _dpcp_flow->apply_settings();
    if (status_out != dpcp::DPCP_OK) {
        rfs_logerr("Failed dpcp_flow_rule::apply_settings(), Status: %d, dpcp_flow: %p",
                   static_cast<int>(status_out), new_rule);
        return false;
    }

    return true;
}
