/*
 * Copyright (c) 2001-2022 Mellanox Technologies, Ltd. All rights reserved.
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
#include "vma/dev/rfs.h"
#include "vma/dev/qp_mgr.h"
#include "vma/dev/ring_simple.h"
#include "vma/sock/sock-redirect.h"
#include <cinttypes>

#define MODULE_NAME "rfs"

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

    // save all ibv_flow rules only for filter
    for (size_t i = 0; i < m_attach_flow_data_vector.size(); i++) {
        filter_iter->second.rfs_rule_vec.push_back(m_attach_flow_data_vector[i]->rfs_flow);
        rfs_logdbg("filter_keep_attached copying rfs_flow, Tag: %" PRIu32
                   ", Flow: %s, Index: %zu, Ptr: %p, Counter: %d",
                   m_flow_tag_id, m_flow_tuple.to_str().c_str(), i,
                   m_attach_flow_data_vector[i]->rfs_flow, filter_iter->second.counter);
    }
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
    if (filter_counter != 0 || filter_iter->second.rfs_rule_vec.empty()) {
        return;
    }

    BULLSEYE_EXCLUDE_BLOCK_START
    if (m_attach_flow_data_vector.size() != filter_iter->second.rfs_rule_vec.size()) {
        // sanity check for having the same number of qps on all rfs objects
        rfs_logerr("all rfs objects in the ring should have the same number of elements");
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    for (size_t i = 0; i < m_attach_flow_data_vector.size(); i++) {
        BULLSEYE_EXCLUDE_BLOCK_START
        if (m_attach_flow_data_vector[i]->rfs_flow &&
            m_attach_flow_data_vector[i]->rfs_flow != filter_iter->second.rfs_rule_vec[i]) {
            rfs_logerr(
                "our assumption that there should be only one rule for filter group is wrong");
        } else if (filter_iter->second.rfs_rule_vec[i]) {
            m_attach_flow_data_vector[i]->rfs_flow = filter_iter->second.rfs_rule_vec[i];
            rfs_logdbg("prepare_filter_detach copying rfs_flow, Tag: %" PRIu32
                       ", Flow: %s, Index: %zu, Ptr: %p, Counter: %d",
                       m_flow_tag_id, m_flow_tuple.to_str().c_str(), i,
                       m_attach_flow_data_vector[i]->rfs_flow, filter_iter->second.counter);
        }
        BULLSEYE_EXCLUDE_BLOCK_END
    }
}

rfs::rfs(flow_tuple *flow_spec_5t, ring_slave *p_ring, rfs_rule_filter *rule_filter /*= NULL*/,
         uint32_t flow_tag_id /*=0*/)
    : m_flow_tuple(rule_filter ? rule_filter->m_flow_tuple : *flow_spec_5t)
    , m_p_ring(p_ring)
    , m_p_rule_filter(rule_filter)
    , m_n_sinks_list_entries(0)
    , m_n_sinks_list_max_length(RFS_SINKS_LIST_DEFAULT_LEN)
    , m_flow_tag_id(flow_tag_id)
    , m_b_tmp_is_attached(false)
{
    m_sinks_list = new pkt_rcvr_sink *[m_n_sinks_list_max_length];

#if defined(DEFINED_NGINX)
    if (safe_mce_sys().actual_nginx_workers_num > 0) {
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

    while (m_attach_flow_data_vector.size() > 0) {
        delete m_attach_flow_data_vector.back();
        m_attach_flow_data_vector.pop_back();
    }
}

bool rfs::add_sink(pkt_rcvr_sink *p_sink)
{
    uint32_t i;

    rfs_logfunc("called with sink (%p)", p_sink);

#if defined(DEFINED_NGINX)
    if (g_b_add_second_4t_rule) { // if 4 tuple rules per worker is 2, no need to add same sink
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
#if defined(DEFINED_NGINX)
        if (g_b_add_second_4t_rule) { // This is second 4 tuple rule for the same worker (when num
                                      // of workers is not power of two)
            create_flow();
            rfs_logdbg("Added second rule to nginx worker: %d", g_worker_index);
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

template <typename T>
rfs_rule *create_rule_T(xlio_tir *tir, const flow_tuple &flow_spec, attach_flow_data_t *iter,
                        bool is5T)
{
    auto *p_attr =
        reinterpret_cast<typename T::ibv_flow_attr_eth_ip_tcp_udp *>(&iter->ibv_flow_attr);

    if (unlikely(p_attr->eth.type != VMA_IBV_FLOW_SPEC_ETH)) {
        // We support only ETH rules for now
        return NULL;
    }

    auto flow_attr(*p_attr);
    if (!is5T) {
        // For UTLS, We need the most specific 5T rule (in case the current rule is 3T).
        ibv_flow_spec_set_single_ip(flow_attr.ip.val.src_ip, flow_attr.ip.mask.src_ip,
                                    flow_spec.get_src_ip());
        flow_attr.tcp_udp.val.src_port = flow_spec.get_src_port();
        flow_attr.tcp_udp.mask.src_port = FS_MASK_ON_16;
    }
    // The highest priority to override TCP rule
    flow_attr.attr.priority = 0;
    return iter->p_qp_mgr->create_rfs_rule(flow_attr.attr, tir);
}

rfs_rule *rfs::create_rule(xlio_tir *tir, const flow_tuple &flow_spec)
{
    if (m_attach_flow_data_vector.size() == 1) {
        if (m_flow_tuple.get_family() == AF_INET) {
            return create_rule_T<attach_flow_data_eth_ipv4_tcp_udp_t>(
                tir, flow_spec, m_attach_flow_data_vector[0], m_flow_tuple.is_5_tuple());
        }

        return create_rule_T<attach_flow_data_eth_ipv6_tcp_udp_t>(
            tir, flow_spec, m_attach_flow_data_vector[0], m_flow_tuple.is_5_tuple());
    }

    return nullptr;
}

#endif /* DEFINED_UTLS */

bool rfs::create_flow()
{
    for (size_t i = 0; i < m_attach_flow_data_vector.size(); i++) {
        attach_flow_data_t *iter = m_attach_flow_data_vector[i];
        iter->rfs_flow = iter->p_qp_mgr->create_rfs_rule(iter->ibv_flow_attr, NULL);
        if (!iter->rfs_flow) {
            rfs_logerr("Create RFS flow failed, Tag: %" PRIu32 ", Flow: %s, Priority: %" PRIu16
                       ", errno: %d - %m",
                       m_flow_tag_id, m_flow_tuple.to_str().c_str(), iter->ibv_flow_attr.priority,
                       errno); // TODO ALEXR - Add info about QP, spec into log msg
            return false;
        }
    }

    m_b_tmp_is_attached = true;
    rfs_logdbg("Create RFS flow succeeded, Tag: %" PRIu32 ", Flow: %s", m_flow_tag_id,
               m_flow_tuple.to_str().c_str());

    return true;
}

bool rfs::destroy_flow()
{
    for (size_t i = 0; i < m_attach_flow_data_vector.size(); i++) {
        attach_flow_data_t *iter = m_attach_flow_data_vector[i];
        if (unlikely(!iter->rfs_flow)) {
            rfs_logdbg(
                "Destroy RFS flow failed, RFS flow was not created. "
                "This is OK for MC same ip diff port scenario. Tag: %" PRIu32
                ", Flow: %s, Priority: %" PRIu16,
                m_flow_tag_id, m_flow_tuple.to_str().c_str(),
                iter->ibv_flow_attr.priority); // TODO ALEXR - Add info about QP, spec into log msg
        } else {
            delete iter->rfs_flow;
            iter->rfs_flow = nullptr;
        }
    }

    m_b_tmp_is_attached = false;
    rfs_logdbg("Destroy RFS flow succeeded, Tag: %" PRIu32 ", Flow: %s", m_flow_tag_id,
               m_flow_tuple.to_str().c_str());

    return true;
}
