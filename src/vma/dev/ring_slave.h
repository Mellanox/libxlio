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

#ifndef RING_SLAVE_H_
#define RING_SLAVE_H_

#include "ring.h"
#include <memory>
#include "vma/dev/net_device_table_mgr.h"
#include "vma/util/sock_addr.h"

class rfs;
struct iphdr;
struct ip6_hdr;

struct __attribute__((packed)) flow_spec_2t_key_ipv4 {
    in_addr_t dst_ip;
    in_port_t dst_port;

    flow_spec_2t_key_ipv4() { flow_spec_2t_key_helper(INADDR_ANY, INPORT_ANY); }
    flow_spec_2t_key_ipv4(const ip_address &d_ip, in_port_t d_port)
    {
        flow_spec_2t_key_helper(d_ip.get_in_addr(), d_port);
    }

    flow_spec_2t_key_ipv4(const sock_addr &dst)
    {
        flow_spec_2t_key_helper(dst.get_ip_addr().get_in_addr(), dst.get_in_port());
    }

    void flow_spec_2t_key_helper(in_addr_t d_ip, in_port_t d_port)
    {
        dst_ip = d_ip;
        dst_port = d_port;
    };

    size_t hash() const
    {
        std::hash<size_t> _hash;
        return _hash(static_cast<size_t>(dst_ip) | (static_cast<size_t>(dst_port) << 32));
    }
};

struct __attribute__((packed)) flow_spec_4t_key_ipv4 {
    in_addr_t dst_ip;
    in_addr_t src_ip;
    in_port_t dst_port;
    in_port_t src_port;

    flow_spec_4t_key_ipv4()
    {
        flow_spec_4t_key_helper(INADDR_ANY, INADDR_ANY, INPORT_ANY, INPORT_ANY);
    }

    flow_spec_4t_key_ipv4(const ip_address &d_ip, const ip_address &s_ip, in_port_t d_port,
                          in_port_t s_port)
    {
        flow_spec_4t_key_helper(d_ip.get_in_addr(), s_ip.get_in_addr(), d_port, s_port);
    }

    flow_spec_4t_key_ipv4(const sock_addr &dst, const sock_addr &src)
    {
        flow_spec_4t_key_helper(dst.get_ip_addr().get_in_addr(), src.get_ip_addr().get_in_addr(),
                                dst.get_in_port(), src.get_in_port());
    }

    void flow_spec_4t_key_helper(in_addr_t d_ip, in_addr_t s_ip, in_port_t d_port, in_port_t s_port)
    {
        dst_ip = d_ip;
        src_ip = s_ip;
        dst_port = d_port;
        src_port = s_port;
    };

    size_t hash() const
    {
        std::hash<size_t> _hash;
        return _hash((static_cast<size_t>(dst_ip) | (static_cast<size_t>(src_ip) << 32)) ^
                     (static_cast<size_t>(src_port) << 32) ^ static_cast<size_t>(dst_port));
    }
};

#pragma pack(1)

struct flow_spec_2t_key_ipv6 {
    ip_address dst_ip;
    in_port_t dst_port;

    flow_spec_2t_key_ipv6() { flow_spec_2t_key_helper(ip_address::any_addr(), INPORT_ANY); }

    flow_spec_2t_key_ipv6(const ip_address &d_ip, in_port_t d_port)
    {
        flow_spec_2t_key_helper(d_ip, d_port);
    }

    flow_spec_2t_key_ipv6(const sock_addr &dst)
    {
        flow_spec_2t_key_helper(dst.get_ip_addr(), dst.get_in_port());
    }

    void flow_spec_2t_key_helper(const ip_address &d_ip, in_port_t d_port)
    {
        dst_ip = d_ip;
        dst_port = d_port;
    };

    size_t hash() const
    {
        const uint64_t *dst_ip_p = reinterpret_cast<const uint64_t *>(&dst_ip);
        std::hash<size_t> _hash;
        return _hash(static_cast<size_t>(dst_ip_p[0]) ^ static_cast<size_t>(dst_ip_p[1]) ^
                     static_cast<size_t>(dst_port));
    }
};

struct flow_spec_4t_key_ipv6 {
    ip_address dst_ip;
    ip_address src_ip;
    in_port_t dst_port;
    in_port_t src_port;

    flow_spec_4t_key_ipv6()
    {
        flow_spec_4t_key_helper(ip_address::any_addr(), ip_address::any_addr(), INPORT_ANY,
                                INPORT_ANY);
    }

    flow_spec_4t_key_ipv6(const ip_address &d_ip, const ip_address &s_ip, in_port_t d_port,
                          in_port_t s_port)
    {
        flow_spec_4t_key_helper(d_ip, s_ip, d_port, s_port);
    }

    flow_spec_4t_key_ipv6(const sock_addr &dst, const sock_addr &src)
    {
        flow_spec_4t_key_helper(dst.get_ip_addr(), src.get_ip_addr(), dst.get_in_port(),
                                src.get_in_port());
    }

    void flow_spec_4t_key_helper(const ip_address &d_ip, const ip_address &s_ip, in_port_t d_port,
                                 in_port_t s_port)
    {
        dst_ip = d_ip;
        src_ip = s_ip;
        dst_port = d_port;
        src_port = s_port;
    };

    size_t hash() const
    {
        const uint64_t *dst_ip_p = reinterpret_cast<const uint64_t *>(&dst_ip);
        const uint64_t *src_ip_p = reinterpret_cast<const uint64_t *>(&src_ip);
        std::hash<size_t> _hash;
        return _hash(static_cast<size_t>(dst_ip_p[0]) ^ static_cast<size_t>(dst_ip_p[1]) ^
                     static_cast<size_t>(src_ip_p[0]) ^ static_cast<size_t>(src_ip_p[1]) ^
                     (static_cast<size_t>(src_port) << 32) ^ static_cast<size_t>(dst_port));
    }
};

#pragma pack()

namespace std {
template <> class hash<flow_spec_2t_key_ipv4> {
public:
    size_t operator()(const flow_spec_2t_key_ipv4 &key) const { return key.hash(); }
};
template <> class hash<flow_spec_4t_key_ipv4> {
public:
    size_t operator()(const flow_spec_4t_key_ipv4 &key) const { return key.hash(); }
};
template <> class hash<flow_spec_2t_key_ipv6> {
public:
    size_t operator()(const flow_spec_2t_key_ipv6 &key) const { return key.hash(); }
};
template <> class hash<flow_spec_4t_key_ipv6> {
public:
    size_t operator()(const flow_spec_4t_key_ipv6 &key) const { return key.hash(); }
};
} // namespace std

/* UDP flow to rfs object hash map */
inline bool operator==(flow_spec_2t_key_ipv4 const &key1, flow_spec_2t_key_ipv4 const &key2)
{
    return (key1.dst_port == key2.dst_port) && (key1.dst_ip == key2.dst_ip);
}

inline bool operator==(flow_spec_2t_key_ipv6 const &key1, flow_spec_2t_key_ipv6 const &key2)
{
    return (key1.dst_port == key2.dst_port) && (key1.dst_ip == key2.dst_ip);
}

/* TCP flow to rfs object hash map */
inline bool operator==(flow_spec_4t_key_ipv4 const &key1, flow_spec_4t_key_ipv4 const &key2)
{
    return (key1.src_port == key2.src_port) && (key1.src_ip == key2.src_ip) &&
        (key1.dst_port == key2.dst_port) && (key1.dst_ip == key2.dst_ip);
}

inline bool operator==(flow_spec_4t_key_ipv6 const &key1, flow_spec_4t_key_ipv6 const &key2)
{
    return (key1.src_port == key2.src_port) && (key1.src_ip == key2.src_ip) &&
        (key1.dst_port == key2.dst_port) && (key1.dst_ip == key2.dst_ip);
}

struct counter_and_ibv_flows {
    int counter;
    std::vector<rfs_rule *> rfs_rule_vec;
};

typedef std::unordered_map<sock_addr, struct counter_and_ibv_flows> rule_filter_map_t;

class ring_slave;

template <typename KEY4T, typename KEY2T, typename HDR> class steering_handler {
public:
    steering_handler(ring_slave &ring)
        : m_ring(ring)
    {
    }

    bool attach_flow(flow_tuple &flow_spec_5t, pkt_rcvr_sink *sink, bool force_5t = false);
    bool detach_flow(flow_tuple &flow_spec_5t, pkt_rcvr_sink *sink);

    inline bool rx_process_buffer_no_flow_id(mem_buf_desc_t *p_rx_wc_buf_desc,
                                             void *pv_fd_ready_array, HDR *p_ip_h);

    void flow_del_all_rfs();

#ifdef DEFINED_UTLS
    /* Call this method in an RX ring. */
    rfs_rule *tls_rx_create_rule(const flow_tuple &flow_spec_5t, xlio_tir *tir);
#endif /* DEFINED_UTLS */

private:
    typedef std::unordered_map<KEY4T, rfs *> flow_spec_4t_map;
    typedef std::unordered_map<KEY2T, rfs *> flow_spec_2t_map;

    flow_spec_4t_map m_flow_tcp_map;
    flow_spec_4t_map m_flow_udp_uc_map;
    flow_spec_2t_map m_flow_udp_mc_map;

    ring_slave &m_ring;
};

class ring_slave : public ring {
public:
    ring_slave(int if_index, ring *parent, ring_type_t type);
    virtual ~ring_slave();

    virtual void print_val();
    virtual void restart();
    virtual int get_num_resources() const { return 1; };
    virtual bool is_member(ring_slave *rng);
    virtual bool is_active_member(ring_slave *rng, ring_user_id_t id);
    virtual ring_user_id_t generate_id();
    virtual ring_user_id_t generate_id(const address_t src_mac, const address_t dst_mac,
                                       uint16_t eth_proto, uint16_t encap_proto,
                                       const ip_address &src_ip, const ip_address &dst_ip,
                                       uint16_t src_port, uint16_t dst_port);
    virtual bool is_up() = 0;
    virtual void inc_tx_retransmissions_stats(ring_user_id_t id);
    virtual bool rx_process_buffer(mem_buf_desc_t *p_rx_wc_buf_desc, void *pv_fd_ready_array);
    virtual int reclaim_recv_single_buffer(mem_buf_desc_t *rx_reuse) = 0;
    virtual void inc_cq_moderation_stats(size_t sz_data) = 0;

    virtual bool attach_flow(flow_tuple &flow_spec_5t, pkt_rcvr_sink *sink, bool force_5t = false);
    virtual bool detach_flow(flow_tuple &flow_spec_5t, pkt_rcvr_sink *sink);

#ifdef DEFINED_UTLS
    /* Call this method in an RX ring. */
    rfs_rule *tls_rx_create_rule(const flow_tuple &flow_spec_5t, xlio_tir *tir);
#endif /* DEFINED_UTLS */

    inline bool is_simple() const { return m_type != RING_TAP; }
    transport_type_t get_transport_type() const { return m_transport_type; }
    inline ring_type_t get_type() const { return m_type; }

    bool m_active; /* State indicator */

protected:
    bool request_more_tx_buffers(pbuf_type type, uint32_t count, uint32_t lkey);
    void flow_del_all_rfs();

    steering_handler<flow_spec_4t_key_ipv4, flow_spec_2t_key_ipv4, iphdr> m_steering_ipv4;
    steering_handler<flow_spec_4t_key_ipv6, flow_spec_2t_key_ipv6, ip6_hdr> m_steering_ipv6;

    // For IB MC flow, the port is zeroed in the ibv_flow_spec when calling to ibv_flow_spec().
    // It means that for every MC group, even if we have sockets with different ports - only one
    // rule in the HW. So the hash map below keeps track of the number of sockets per rule so we
    // know when to call ibv_attach and ibv_detach
    rule_filter_map_t m_l2_mc_ip_attach_map;
    rule_filter_map_t m_tcp_dst_port_attach_map;
    rule_filter_map_t m_udp_uc_dst_port_attach_map;

    lock_spin_recursive m_lock_ring_rx;
    lock_spin_recursive m_lock_ring_tx;

    descq_t m_tx_pool;
    descq_t m_zc_pool;
    transport_type_t m_transport_type; /* transport ETH/IB */
    std::unique_ptr<ring_stats_t> m_p_ring_stat;
    uint16_t m_partition;
    bool m_flow_tag_enabled;
    const bool m_b_sysvar_eth_mc_l2_only_rules;
    const bool m_b_sysvar_mc_force_flowtag;

    template <typename KEY4T, typename KEY2T, typename HDR> friend class steering_handler;

private:
    ring_type_t m_type; /* ring type */
};

#endif /* RING_SLAVE_H_ */
