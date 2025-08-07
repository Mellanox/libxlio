/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef RFS_H
#define RFS_H

#include <vector>
#include <mellanox/dpcp.h>
#include "ib/base/verbs_extra.h"
#include "util/vtypes.h"
#include "dev/ring_simple.h"
#include "proto/mem_buf_desc.h"
#include "proto/flow_tuple.h"

#define RFS_SINKS_LIST_DEFAULT_LEN 32

class hw_queue_rx;
class sockinfo;

/*
 * Priority description:
 *  2 - 3T rules
 *  1 - 5T/4T rules
 *  0 - 5T TLS rules
 *
 * TLS rules must take over from TCP rules, but we want to keep the TCP rules in
 * shadow for socket reuse feature.
 */

class rfs_rule_filter {
public:
    rfs_rule_filter(rule_filter_map_t &map, const sock_addr &key, flow_tuple &flow_tuple)
        : m_map(map)
        , m_key(key)
        , m_flow_tuple(flow_tuple)
    {
    }
    rule_filter_map_t &m_map;
    sock_addr m_key;
    flow_tuple m_flow_tuple;
};

/**
 * @class rfs
 *
 * Object to manages the sink list
 * This object is used for maintaining the sink list and dispatching packets
 *
 */

class rfs {
public:
    rfs(flow_tuple *flow_spec_5t, ring_slave *p_ring, rfs_rule_filter *rule_filter = nullptr,
        uint32_t flow_tag_id = 0);
    virtual ~rfs();

    /**
     * Register/Unregister a sink with this rfs object
     * Get notifications about incoming packets using the sockinfo callback api
     * The rfs will call ibv_attach on the QP once when at least one receiver sink is registered
     * An ibv_detach is called when the last receiver sink is deleted from the registered list
     *
     */
    bool attach_flow(sockinfo *sink); // Add a sink. If this is the first sink --> map the sink
                                      // and attach flow to QP
    // Delete a sink. If this is the last sink --> delete it and detach flow from QP
    bool detach_flow(sockinfo *sink, rfs_rule **rule_extract);
#ifdef DEFINED_UTLS
    rfs_rule *create_rule(xlio_tir *tir,
                          const flow_tuple &flow_spec); // Create a duplicate rule which points to
                                                        // specific TIR, caller is owner of the rule
#endif /* DEFINED_UTLS */

    uint32_t get_num_of_sinks() const { return m_n_sinks_list_entries; }
    virtual bool rx_dispatch_packet(mem_buf_desc_t *p_rx_wc_buf_desc, void *pv_fd_ready_array) = 0;
    virtual void prepare_flow_spec_worker_thread_mode() = 0;
    virtual void prepare_flow_spec_secondary_rule() = 0;
    virtual bool if_secondary_rule_needed() = 0;

protected:
    flow_tuple m_flow_tuple;
    ring_slave *m_p_ring;
    ring_simple *m_p_ring_simple;
    rfs_rule_filter *m_p_rule_filter;
    rfs_rule *m_rfs_flow = nullptr;
    sockinfo **m_sinks_list;
    uint32_t m_n_sinks_list_entries; // Number of actual sinks in the array (we shrink the array if
                                     // a sink is removed)
    uint32_t m_n_sinks_list_max_length;
    uint32_t m_flow_tag_id; // Associated with this rule, set by attach_flow()

    // Rule priority indicator: lower values denote higher priority.
    // Priority levels:
    // 0 – Reserved for hardware HW TLS RX flow rules
    // 1 – Applied to 5-tuple rules
    // 2 – Applied to 4-tuple rules
    // 3 – Applied to 3-tuple rules
    uint16_t m_priority = 3U;

    bool m_b_tmp_is_attached; // Only temporary, while ibcm calls attach_flow with no sinks...

    dpcp::match_params m_match_value;
    dpcp::match_params m_match_mask;

    rfs_rule *m_rfs_rule_secondary = nullptr; // Second rule for odd number of xlio threads

    bool create_flow(); // Attach flow to all queues
    bool destroy_flow(rfs_rule **rule_extract); // Detach flow from all queues
    bool add_sink(sockinfo *p_sink);
    bool del_sink(sockinfo *p_sink);
    void prepare_flow_spec_eth_ip(const ip_address &dst_ip, const ip_address &src_ip);
    void prepare_flow_spec_tcp_udp();
    virtual void prepare_flow_spec() = 0;

private:
    rfs(); // I don't want anyone to use the default constructor
    inline void prepare_filter_attach(int &filter_counter,
                                      rule_filter_map_t::iterator &filter_iter);
    inline void filter_keep_attached(rule_filter_map_t::iterator &filter_iter);
    inline void prepare_filter_detach(int &filter_counter, bool decrease_counter);
};

#endif /* RFS_H */
