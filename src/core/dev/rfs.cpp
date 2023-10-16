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
#include "dev/rfs.h"
#include "dev/ring_simple.h"
#include "sock/sock-redirect.h"
#include "sock/sock-app.h"
#include <cinttypes>

#define MODULE_NAME "rfs"

#define rfs_logpanic   __log_info_panic
#define rfs_logerr     __log_info_err
#define rfs_logwarn    __log_info_warn
#define rfs_loginfo    __log_info_info
#define rfs_logdbg     __log_info_dbg
#define rfs_logfunc    __log_info_func
#define rfs_logfuncall __log_info_funcall

/**/
/** inlining functions can only help if they are implemented before their usage **/
/**/
inline void rfs::prepare_filter_attach(int &filter_counter,
                                       rule_filter_map_t::iterator &filter_iter)
{
    // If filter flow, need to attach flow only if this is the first request for this specific group
    // (i.e. counter == 1)
    if (!m_p_rule_filter) {
        return;
    }

    filter_iter = m_p_rule_filter->m_map.find(m_p_rule_filter->m_key);
    if (filter_iter == m_p_rule_filter->m_map.end()) {
        rfs_logdbg("No matching counter for filter");
        return;
    }

    filter_counter = filter_iter->second.counter;
    m_b_tmp_is_attached = (filter_counter > 1) || m_b_tmp_is_attached;
}

inline void rfs::filter_keep_attached(rule_filter_map_t::iterator &filter_iter)
{
    if (!m_p_rule_filter || filter_iter == m_p_rule_filter->m_map.end()) {
        return;
    }

    // save ibv_flow rule only for filter
    filter_iter->second.rfs_rule_holder = m_rfs_flow;
    rfs_logdbg(
        "filter_keep_attached copying rfs_flow, Tag: %" PRIu32 ", Flow: %s, Ptr: %p, Counter: %d",
        m_flow_tag_id, m_flow_tuple.to_str().c_str(), m_rfs_flow, filter_iter->second.counter);
}

inline void rfs::prepare_filter_detach(int &filter_counter, bool decrease_counter)
{
    // If filter, need to detach flow only if this is the last attached rule for this specific group
    // (i.e. counter == 0)
    if (!m_p_rule_filter) {
        return;
    }

    rule_filter_map_t::iterator filter_iter = m_p_rule_filter->m_map.find(m_p_rule_filter->m_key);
    if (filter_iter == m_p_rule_filter->m_map.end()) {
        rfs_logdbg("No matching counter for filter");
        return;
    }

    if (decrease_counter) {
        filter_iter->second.counter =
            filter_iter->second.counter > 0 ? filter_iter->second.counter - 1 : 0;
        rfs_logdbg("prepare_filter_detach decrement counter, Tag: %" PRIu32
                   ", Flow: %s, Counter: %d",
                   m_flow_tag_id, m_flow_tuple.to_str().c_str(), filter_iter->second.counter);
    }

    filter_counter = filter_iter->second.counter;
    // if we do not need to destroy rfs_rule, still mark this rfs as detached
    m_b_tmp_is_attached = (filter_counter == 0) && m_b_tmp_is_attached;
    if (filter_counter != 0) {
        return;
    }

    BULLSEYE_EXCLUDE_BLOCK_START
    if (m_rfs_flow && m_rfs_flow != filter_iter->second.rfs_rule_holder) {
        rfs_logerr("our assumption that there should be only one rule for filter group is wrong");
    } else if (filter_iter->second.rfs_rule_holder) {
        m_rfs_flow = filter_iter->second.rfs_rule_holder;
        rfs_logdbg("prepare_filter_detach copying rfs_flow, Tag: %" PRIu32
                   ", Flow: %s, Ptr: %p, Counter: %d",
                   m_flow_tag_id, m_flow_tuple.to_str().c_str(), m_rfs_flow,
                   filter_iter->second.counter);
    }
    BULLSEYE_EXCLUDE_BLOCK_END
}

rfs::rfs(flow_tuple *flow_spec_5t, ring_slave *p_ring, rfs_rule_filter *rule_filter /*= NULL*/,
         uint32_t flow_tag_id /*=0*/)
    : m_flow_tuple(rule_filter ? rule_filter->m_flow_tuple : *flow_spec_5t)
    , m_p_ring(p_ring)
    , m_p_ring_simple(dynamic_cast<ring_simple *>(p_ring))
    , m_p_rule_filter(rule_filter)
    , m_n_sinks_list_entries(0)
    , m_n_sinks_list_max_length(RFS_SINKS_LIST_DEFAULT_LEN)
    , m_flow_tag_id(flow_tag_id)
    , m_b_tmp_is_attached(false)
{
    memset(&m_match_value, 0, sizeof(m_match_value));
    memset(&m_match_mask, 0, sizeof(m_match_mask));

    m_sinks_list = new pkt_rcvr_sink *[m_n_sinks_list_max_length];

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    if (g_p_app->type != APP_NONE && g_p_app->get_worker_id() >= 0) {
        m_flow_tag_id = 0;
    }
#endif

    BULLSEYE_EXCLUDE_BLOCK_START
    if (m_sinks_list == NULL) {
        rfs_logpanic("sinks list allocation failed!");
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    memset(m_sinks_list, 0, sizeof(pkt_rcvr_sink *) * m_n_sinks_list_max_length);
}

rfs::~rfs()
{
    // If filter, need to detach flow only if this is the last attached rule for this specific
    // filter group (i.e. counter == 0)
    if (m_p_rule_filter && m_b_tmp_is_attached) {
        int counter = 0;
        prepare_filter_detach(counter, true);
        if (counter == 0) {
            if (m_p_ring->is_simple()) {
                destroy_flow();
            }
            m_p_rule_filter->m_map.erase(m_p_rule_filter->m_key);
        }
    } else if (m_b_tmp_is_attached) {
        if (m_p_ring->is_simple()) {
            destroy_flow();
        }
    }

    if (m_p_rule_filter) {
        delete m_p_rule_filter;
        m_p_rule_filter = NULL;
    }
    delete[] m_sinks_list;
}

bool rfs::add_sink(pkt_rcvr_sink *p_sink)
{
    uint32_t i;

    rfs_logfunc("called with sink (%p)", p_sink);

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    if (g_p_app->type != APP_NONE && g_p_app->add_second_4t_rule) {
        // if 4 tuple rules per worker is 2, no need to add same sink
        // second time
        return true;
    }
#endif

    // Check all sinks list array if already exists.
    for (i = 0; i < m_n_sinks_list_entries; ++i) {
        if (m_sinks_list[i] == p_sink) {
            rfs_logdbg("sink (%p) already registered!!!", p_sink);
            return true;
        }
    }
    if (m_n_sinks_list_entries == m_n_sinks_list_max_length) { // Sinks list array is full
        // Reallocate a new array with double size
        uint32_t tmp_sinks_list_length = 2 * m_n_sinks_list_max_length;
        pkt_rcvr_sink **tmp_sinks_list = new pkt_rcvr_sink *[tmp_sinks_list_length];

        BULLSEYE_EXCLUDE_BLOCK_START
        if (tmp_sinks_list == NULL) {
            rfs_logerr("sinks list allocation failed!");
            return false;
        }
        BULLSEYE_EXCLUDE_BLOCK_END

        memcpy(tmp_sinks_list, m_sinks_list, sizeof(pkt_rcvr_sink *) * m_n_sinks_list_max_length);
        delete[] m_sinks_list;
        m_sinks_list = tmp_sinks_list;
        m_n_sinks_list_max_length = tmp_sinks_list_length;
    }

    m_sinks_list[m_n_sinks_list_entries] = p_sink;
    ++m_n_sinks_list_entries;

    rfs_logdbg("Added new sink (%p), num of sinks is now: %d", p_sink, m_n_sinks_list_entries);
    return true;
}

bool rfs::del_sink(pkt_rcvr_sink *p_sink)
{
    uint32_t i;

    rfs_logdbg("called with sink (%p)", p_sink);

    // Find and remove sink
    for (i = 0; i < m_n_sinks_list_entries; ++i) {
        if (m_sinks_list[i] == p_sink) {

            // Found the sink location to remove
            // Remove this sink from list by shrinking it and keeping it in order
            for (/*continue i*/; i < (m_n_sinks_list_entries - 1); ++i) {
                m_sinks_list[i] = m_sinks_list[i + 1];
            }
            m_sinks_list[i] = NULL;

            m_n_sinks_list_entries--;
            rfs_logdbg("Removed sink (%p), num of sinks is now: %d", p_sink,
                       m_n_sinks_list_entries);

            if (m_n_sinks_list_entries == 0) {
                rfs_logdbg("rfs sinks list is now empty");
            }
            return true;
        }
    }
    rfs_logdbg("sink (%p) not found", p_sink);
    return false;
}

bool rfs::attach_flow(pkt_rcvr_sink *sink)
{
    bool ret;
    int filter_counter = 1;
    rule_filter_map_t::iterator filter_iter;

    prepare_filter_attach(filter_counter, filter_iter);

    // We also check if this is the FIRST sink so we need to call ibv_attach_flow
    if ((m_n_sinks_list_entries == 0) && (!m_b_tmp_is_attached) && (filter_counter == 1)) {
        if (m_p_ring->is_simple() && !create_flow()) {
            return false;
        }
        filter_keep_attached(filter_iter);
    } else {
        rfs_logdbg("rfs: Joining existing flow");
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
        if (g_p_app->type != APP_NONE && m_p_ring->is_simple() && g_p_app->add_second_4t_rule) {
            // This is second 4 tuple rule for the same worker (when number
            // of workers is not power of two)
            create_flow();
            rfs_logdbg("Added second rule to worker: %d", g_p_app->get_worker_id());
        }
#endif
    }

    if (sink) {
        ret = add_sink(sink);
    } else {
        rfs_logdbg("rfs: Attach flow was called with sink == NULL");
        ret = true;
    }

    return ret;
}

bool rfs::detach_flow(pkt_rcvr_sink *sink)
{
    bool ret = false;
    int filter_counter = 0;

    BULLSEYE_EXCLUDE_BLOCK_START
    if (sink) {
        ret = del_sink(sink);
    } else {
        rfs_logwarn("detach_flow() was called with sink == NULL");
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    prepare_filter_detach(filter_counter, false);

    // We also need to check if this is the LAST sink so we need to call ibv_attach_flow
    if (m_p_ring->is_simple() && (m_n_sinks_list_entries == 0) && (filter_counter == 0)) {
        ret = destroy_flow();
    }

    return ret;
}

#ifdef DEFINED_UTLS

rfs_rule *rfs::create_rule(xlio_tir *tir, const flow_tuple &flow_spec)
{
    if (!m_p_ring_simple) {
        rfs_logpanic("Incompatible ring type");
    }

    auto *hqrx = m_p_ring_simple->m_hqrx;

    dpcp::match_params match_value_tmp;
    dpcp::match_params match_mask_tmp;
    memcpy(&match_value_tmp, &m_match_value, sizeof(m_match_value));
    memcpy(&match_mask_tmp, &m_match_mask, sizeof(m_match_mask));

    if (!m_flow_tuple.is_5_tuple()) {
        // For UTLS, We need the most specific 5T rule (in case the current rule is 3T).

        if (match_value_tmp.ethertype == ETH_P_IP) {
            match_mask_tmp.src.ipv4 = flow_spec.get_src_ip().is_anyaddr() ? 0U : 0xFFFFFFFFU;
            match_value_tmp.src.ipv4 = ntohl(flow_spec.get_src_ip().get_in4_addr().s_addr);
        } else {
            memset(match_mask_tmp.src.ipv6, flow_spec.get_src_ip().is_anyaddr() ? 0U : 0xFFU,
                   sizeof(match_mask_tmp.src.ipv6));
            memcpy(match_value_tmp.src.ipv6, &flow_spec.get_src_ip().get_in6_addr(),
                   sizeof(match_value_tmp.src.ipv6));
        }

        match_mask_tmp.src_port = 0xFFFFU;
        match_value_tmp.src_port = ntohs(flow_spec.get_src_port());
    }

    // The highest priority to override TCP rule
    return hqrx->create_rfs_rule(match_value_tmp, match_mask_tmp, 0, m_flow_tag_id, tir);
}

#endif /* DEFINED_UTLS */

bool rfs::create_flow()
{
    if (!m_p_ring_simple) {
        rfs_logpanic("Incompatible ring type");
    }

    m_rfs_flow = m_p_ring_simple->m_hqrx->create_rfs_rule(m_match_value, m_match_mask, m_priority,
                                                          m_flow_tag_id, nullptr);
    if (!m_rfs_flow) {
        rfs_logerr("Create RFS flow failed, Tag: %" PRIu32 ", Flow: %s, Priority: %" PRIu16
                   ", errno: %d - %m",
                   m_flow_tag_id, m_flow_tuple.to_str().c_str(), m_priority, errno);
        return false;
    }

    m_b_tmp_is_attached = true;
    rfs_logdbg("Create RFS flow succeeded, Tag: %" PRIu32 ", Flow: %s", m_flow_tag_id,
               m_flow_tuple.to_str().c_str());

    return true;
}

bool rfs::destroy_flow()
{
    if (unlikely(!m_rfs_flow)) {
        rfs_logdbg("Destroy RFS flow failed, RFS flow was not created. "
                   "This is OK for MC same ip diff port scenario. Tag: %" PRIu32
                   ", Flow: %s, Priority: %" PRIu16,
                   m_flow_tag_id, m_flow_tuple.to_str().c_str(), m_priority);
    } else {
        delete m_rfs_flow;
        m_rfs_flow = nullptr;
    }

    m_b_tmp_is_attached = false;
    rfs_logdbg("Destroy RFS flow succeeded, Tag: %" PRIu32 ", Flow: %s", m_flow_tag_id,
               m_flow_tuple.to_str().c_str());

    return true;
}

void rfs::prepare_flow_spec_eth_ip(const ip_address &dst_ip, const ip_address &src_ip)
{
    if (!m_p_ring_simple) {
        rfs_logpanic("Incompatible ring type");
    }

    m_match_value.vlan_id = m_p_ring_simple->m_hqrx->get_vlan() & VLAN_VID_MASK;
    m_match_mask.vlan_id = (m_p_ring_simple->m_hqrx->get_vlan() ? VLAN_VID_MASK : 0);

    bool is_ipv4 = (m_flow_tuple.get_family() == AF_INET);
    if (is_ipv4) {
        m_match_mask.dst.ipv4 = dst_ip.is_anyaddr() ? 0U : 0xFFFFFFFFU;
        m_match_value.dst.ipv4 = ntohl(dst_ip.get_in4_addr().s_addr);
        m_match_mask.src.ipv4 = src_ip.is_anyaddr() ? 0U : 0xFFFFFFFFU;
        m_match_value.src.ipv4 = ntohl(src_ip.get_in4_addr().s_addr);
        m_match_mask.ip_version = 0xF;
        m_match_value.ip_version = 4U;
        m_match_mask.ethertype = 0xFFFFU;
        m_match_value.ethertype = ETH_P_IP;
    } else {
        memset(m_match_mask.dst.ipv6, dst_ip.is_anyaddr() ? 0U : 0xFFU,
               sizeof(m_match_mask.dst.ipv6));
        memcpy(m_match_value.dst.ipv6, &dst_ip.get_in6_addr(), sizeof(m_match_value.dst.ipv6));
        memset(m_match_mask.src.ipv6, src_ip.is_anyaddr() ? 0U : 0xFFU,
               sizeof(m_match_mask.src.ipv6));
        memcpy(m_match_value.src.ipv6, &src_ip.get_in6_addr(), sizeof(m_match_value.src.ipv6));
        m_match_mask.ip_version = 0xF;
        m_match_value.ip_version = 6U;
        m_match_mask.ethertype = 0xFFFFU;
        m_match_value.ethertype = ETH_P_IPV6;
    }
}

void rfs::prepare_flow_spec_tcp_udp()
{
    m_match_mask.dst_port = (m_flow_tuple.get_dst_port() ? 0xFFFFU : 0U);
    m_match_value.dst_port = ntohs(m_flow_tuple.get_dst_port());
    m_match_mask.src_port = (m_flow_tuple.get_src_port() ? 0xFFFFU : 0U);
    m_match_value.src_port = ntohs(m_flow_tuple.get_src_port());
    m_match_mask.protocol = 0xFF;
    m_match_value.protocol = (m_flow_tuple.get_protocol() == PROTO_TCP ? IPPROTO_TCP : IPPROTO_UDP);
}
