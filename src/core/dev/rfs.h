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

#ifndef RFS_H
#define RFS_H

#include <vector>

#include "ib/base/verbs_extra.h"
#include "util/vtypes.h"
#include "dev/ring_simple.h"
#include "proto/mem_buf_desc.h"
#include "proto/flow_tuple.h"

#define RFS_SINKS_LIST_DEFAULT_LEN 32

class hw_queue_rx;
class pkt_rcvr_sink;

/*
 * Priority description:
 *  2 - 3T rules
 *  1 - 5T/4T rules
 *  0 - 5T TLS rules
 *
 * TLS rules must take over from TCP rules, but we want to keep the TCP rules in
 * shadow for socket reuse feature.
 */

/* ETHERNET
 */

typedef struct ibv_flow_attr_eth {
    xlio_ibv_flow_attr attr;
    xlio_ibv_flow_spec_eth eth;
} ibv_flow_attr_eth;

template <typename T> struct attach_flow_data_eth_ip_tcp_udp_t {
    rfs_rule *rfs_flow;
    hw_queue_rx *hqrx_ptr;
    struct ibv_flow_attr_eth_ip_tcp_udp : public ibv_flow_attr_eth {
        T ip;
        xlio_ibv_flow_spec_tcp_udp tcp_udp;
        xlio_ibv_flow_spec_action_tag flow_tag; // must be the last as struct can be used without it

        ibv_flow_attr_eth_ip_tcp_udp()
        {
            memset(this, 0, sizeof(*this));
            attr.size = sizeof(T) - sizeof(flow_tag);
            attr.num_of_specs = 3;
            attr.type = XLIO_IBV_FLOW_ATTR_NORMAL;
            attr.priority = 2; // almost highest priority, 1 is used for 5-tuple later
            attr.port = 0;
        }
        inline void add_flow_tag_spec(void)
        {
            attr.num_of_specs++;
            attr.size += sizeof(flow_tag);
        }
    } ibv_flow_attr;
    attach_flow_data_eth_ip_tcp_udp_t(hw_queue_rx *hqrx)
        : rfs_flow(NULL)
        , hqrx_ptr(hqrx)
        , ibv_flow_attr()
    {
    }
};

typedef attach_flow_data_eth_ip_tcp_udp_t<xlio_ibv_flow_spec_ipv4>
    attach_flow_data_eth_ipv4_tcp_udp_t;
typedef attach_flow_data_eth_ip_tcp_udp_t<xlio_ibv_flow_spec_ipv6>
    attach_flow_data_eth_ipv6_tcp_udp_t;

typedef struct attach_flow_data_t {
    rfs_rule *rfs_flow;
    hw_queue_rx *hqrx_ptr;
    xlio_ibv_flow_attr ibv_flow_attr;
} attach_flow_data_t;

typedef std::vector<attach_flow_data_t *> attach_flow_data_vector_t;

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
    rfs(flow_tuple *flow_spec_5t, ring_slave *p_ring, rfs_rule_filter *rule_filter = NULL,
        uint32_t flow_tag_id = 0);
    virtual ~rfs();

    /**
     * Register/Unregister a sink with this rfs object
     * Get notifications about incoming packets using the pkt_rcvr_sink callback api
     * The rfs will call ibv_attach on the QP once when at least one receiver sink is registered
     * An ibv_detach is called when the last receiver sink is deleted from the registered list
     *
     */
    bool attach_flow(pkt_rcvr_sink *sink); // Add a sink. If this is the first sink --> map the sink
                                           // and attach flow to QP
    bool detach_flow(pkt_rcvr_sink *sink); // Delete a sink. If this is the last sink --> delete it
                                           // and detach flow from QP
#ifdef DEFINED_UTLS
    rfs_rule *create_rule(xlio_tir *tir,
                          const flow_tuple &flow_spec); // Create a duplicate rule which points to
                                                        // specific TIR, caller is owner of the rule
#endif /* DEFINED_UTLS */

    uint32_t get_num_of_sinks() const { return m_n_sinks_list_entries; }
    virtual bool rx_dispatch_packet(mem_buf_desc_t *p_rx_wc_buf_desc, void *pv_fd_ready_array) = 0;

protected:
    flow_tuple m_flow_tuple;
    ring_slave *m_p_ring;
    rfs_rule_filter *m_p_rule_filter;
    attach_flow_data_vector_t m_attach_flow_data_vector;
    pkt_rcvr_sink **m_sinks_list;
    uint32_t m_n_sinks_list_entries; // Number of actual sinks in the array (we shrink the array if
                                     // a sink is removed)
    uint32_t m_n_sinks_list_max_length;
    uint32_t m_flow_tag_id; // Associated with this rule, set by attach_flow()
    bool m_b_tmp_is_attached; // Only temporary, while ibcm calls attach_flow with no sinks...

    bool create_flow(); // Attach flow to all queues
    bool destroy_flow(); // Detach flow from all queues
    bool add_sink(pkt_rcvr_sink *p_sink);
    bool del_sink(pkt_rcvr_sink *p_sink);
    virtual bool prepare_flow_spec() = 0;

private:
    rfs(); // I don't want anyone to use the default constructor
    inline void prepare_filter_attach(int &filter_counter,
                                      rule_filter_map_t::iterator &filter_iter);
    inline void filter_keep_attached(rule_filter_map_t::iterator &filter_iter);
    inline void prepare_filter_detach(int &filter_counter, bool decrease_counter);
};

#endif /* RFS_H */
