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

#ifndef RFS_MC_H
#define RFS_MC_H

#include "dev/rfs.h"

/**
 * @class rfs_mc
 *
 * Object to manages the sink list of a MC flow
 * This object is used for maintaining the sink list and dispatching packets
 *
 */

class rfs_mc : public rfs {
public:
    rfs_mc(flow_tuple *flow_spec_5t, ring_slave *p_ring, rfs_rule_filter *rule_filter = NULL,
           int32_t flow_tag_id = 0);

    virtual bool rx_dispatch_packet(mem_buf_desc_t *p_rx_wc_buf_desc, void *pv_fd_ready_array);

protected:
    virtual bool prepare_flow_spec();

    template <typename T>
    void prepare_flow_spec_by_ip(attach_flow_data_t *&p_attach_flow_data,
                                 xlio_ibv_flow_spec_eth *&p_eth,
                                 xlio_ibv_flow_spec_tcp_udp *&p_tcp_udp);
};

template <typename T>
void rfs_mc::prepare_flow_spec_by_ip(attach_flow_data_t *&p_attach_flow_data,
                                     xlio_ibv_flow_spec_eth *&p_eth,
                                     xlio_ibv_flow_spec_tcp_udp *&p_tcp_udp)
{
    T *attach_flow_data_eth = new (std::nothrow) T();
    if (!attach_flow_data_eth) {
        return;
    }

    p_eth = &(attach_flow_data_eth->ibv_flow_attr.eth);
    p_tcp_udp = &(attach_flow_data_eth->ibv_flow_attr.tcp_udp);
    p_attach_flow_data = reinterpret_cast<attach_flow_data_t *>(attach_flow_data_eth);

    const ip_address &dst_ip =
        (safe_mce_sys().eth_mc_l2_only_rules ? ip_address::any_addr() : m_flow_tuple.get_dst_ip());

    ibv_flow_spec_ip_set(&(attach_flow_data_eth->ibv_flow_attr.ip), dst_ip, ip_address::any_addr());

    if (m_flow_tag_id) { // Will not attach flow_tag spec to rule for tag_id==0
        ibv_flow_spec_flow_tag_set(&(attach_flow_data_eth->ibv_flow_attr.flow_tag), m_flow_tag_id);
        attach_flow_data_eth->ibv_flow_attr.add_flow_tag_spec();
    }
}

#undef MODULE_NAME

#endif /* RFS_MC_H */
