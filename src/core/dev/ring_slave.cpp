/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <inttypes.h>
#include <netinet/ip6.h>
#include "ring_slave.h"
#include "proto/ip_frag.h"
#include "dev/rfs_mc.h"
#include "dev/rfs_uc_tcp_gro.h"
#include "sock/fd_collection.h"
#include "sock/sockinfo.h"

#undef MODULE_NAME
#define MODULE_NAME "ring_slave"
#undef MODULE_HDR
#define MODULE_HDR MODULE_NAME "%d:%s() "

// AF_INET address 0.0.0.0:0, used for 3T flow spec keys.
static const sock_addr s_sock_addrany;

static thread_local lock_dummy t_lock_dummy_ring;

static lock_base *get_new_lock(const char *name, bool real_lock)
{
    return (real_lock
                ? static_cast<lock_base *>(multilock::create_new_lock(MULTILOCK_RECURSIVE, name))
                : static_cast<lock_base *>(&t_lock_dummy_ring));
}

ring_slave::ring_slave(int if_index, ring *parent, ring_type_t type, bool use_locks)
    : ring()
    , m_steering_ipv4(*this)
    , m_steering_ipv6(*this)
    , m_lock_ring_rx(get_new_lock("ring_slave:lock_rx", use_locks))
    , m_lock_ring_tx(get_new_lock("ring_slave:lock_tx", use_locks))
    , m_p_ring_stat(new ring_stats_t)
    , m_vlan(0)
    , m_flow_tag_enabled(false)
    , m_b_sysvar_eth_mc_l2_only_rules(safe_mce_sys().eth_mc_l2_only_rules)
    , m_b_sysvar_mc_force_flowtag(safe_mce_sys().mc_force_flowtag)
    , m_type(type)
{
    net_device_val *p_ndev = nullptr;
    const slave_data_t *p_slave = nullptr;

    /* Configure ring() fields */
    set_parent(parent);
    set_if_index(if_index);

    /* Sanity check */
    p_ndev = g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());
    if (!p_ndev) {
        ring_logpanic("Invalid if_index = %d", if_index);
    }

    p_slave = p_ndev->get_slave(get_if_index());

    /* Configure ring_slave() fields */
    m_transport_type = p_ndev->get_transport_type();

    /* Set the same ring active status as related slave has for all ring types
     * excluding ring with type RING_TAP that does not have related slave device.
     * So it is marked as active just in case related netvsc device is absent.
     */
    m_active = p_slave ? p_slave->active : p_ndev->get_slave_array().empty();

    // use local copy of stats by default
    memset(m_p_ring_stat.get(), 0, sizeof(ring_stats_t));
    m_p_ring_stat->n_type = m_type;
    if (m_parent != this) {
        m_p_ring_stat->p_ring_master = m_parent;
    }

    m_tx_pool.set_id("ring_slave (%p) : m_tx_pool", this);
    m_zc_pool.set_id("ring_slave (%p) : m_zc_pool", this);

    xlio_stats_instance_create_ring_block(m_p_ring_stat.get());

    print_val();
}

ring_slave::~ring_slave()
{
    print_val();

    if (m_p_ring_stat) {
        xlio_stats_instance_remove_ring_block(m_p_ring_stat.get());
    }

    /* Release TX buffer poll */
    g_buffer_pool_tx->put_buffers_thread_safe(&m_tx_pool, m_tx_pool.size());
    g_buffer_pool_zc->put_buffers_thread_safe(&m_zc_pool, m_zc_pool.size());
}

void ring_slave::print_val()
{
    ring_logdbg("%d: %p: parent %p type %s", m_if_index, this,
                ((uintptr_t)this == (uintptr_t)m_parent ? nullptr : m_parent),
                ring_type_str[m_type]);
}

void ring_slave::restart()
{
    ring_logpanic("Can't restart a slave ring");
}

bool ring_slave::is_active_member(ring_slave *rng, ring_user_id_t)
{
    return (this == rng);
}

bool ring_slave::is_member(ring_slave *rng)
{
    return (this == rng);
}

ring_user_id_t ring_slave::generate_id()
{
    return 0;
}

ring_user_id_t ring_slave::generate_id(const address_t, const address_t, uint16_t, uint16_t,
                                       const ip_address &, const ip_address &, uint16_t, uint16_t)
{
    return 0;
}

void ring_slave::inc_tx_retransmissions_stats(ring_user_id_t)
{
    m_p_ring_stat->n_tx_retransmits++;
}

template <typename KEY4T, typename KEY2T, typename HDR>
bool steering_handler<KEY4T, KEY2T, HDR>::attach_flow(flow_tuple &flow_spec_5t, sockinfo *sink,
                                                      bool force_5t)
{
    rfs *p_rfs;
    rfs *p_tmp_rfs = nullptr;
    sockinfo *si = static_cast<sockinfo *>(sink);

    if (!si) {
        return false;
    }

    uint32_t flow_tag_id = si->get_flow_tag_val(); // spec will not be attached to rule
    if (!m_ring.m_flow_tag_enabled) {
        flow_tag_id = 0;
    }
    ring_logdbg("flow: %s, with sink (%p), flow tag id %d "
                "m_flow_tag_enabled: %d",
                flow_spec_5t.to_str().c_str(), si, flow_tag_id, m_ring.m_flow_tag_enabled);

    /* Get the appropriate hash map (tcp, uc or mc) from the 5t details
     * TODO: Consider unification of following code.
     */
    if (flow_spec_5t.is_udp_uc()) {
        KEY4T rfs_key(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_src_ip(),
                      flow_spec_5t.get_dst_port(), flow_spec_5t.get_src_port());
        sock_addr rule_key(flow_spec_5t.get_family(), &flow_spec_5t.get_dst_ip(),
                           flow_spec_5t.get_dst_port());
        rfs_rule_filter *dst_port_filter = nullptr;
        if (safe_mce_sys().udp_3t_rules) {
            auto dst_port_iter = m_ring.m_udp_uc_dst_port_attach_map.find(rule_key);
            if (dst_port_iter == m_ring.m_udp_uc_dst_port_attach_map.end()) {
                m_ring.m_udp_uc_dst_port_attach_map[rule_key].counter = 1;
            } else {
                m_ring.m_udp_uc_dst_port_attach_map[rule_key].counter =
                    ((dst_port_iter->second.counter) + 1);
            }
        }

        if (flow_tag_id && si->flow_in_reuse()) {
            flow_tag_id = FLOW_TAG_MASK;
            ring_logdbg("UC flow tag for socketinfo=%p is disabled: SO_REUSEADDR or SO_REUSEPORT "
                        "were enabled",
                        si);
        }

        auto itr = m_flow_udp_uc_map.find(rfs_key);
        if (itr == end(m_flow_udp_uc_map)) {
            // No rfs object exists so a new one must be created and inserted in the flow map
            if (safe_mce_sys().udp_3t_rules) {
                flow_tuple udp_3t_only(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port(),
                                       ip_address::any_addr(), 0, flow_spec_5t.get_protocol(),
                                       flow_spec_5t.get_family());
                dst_port_filter =
                    new rfs_rule_filter(m_ring.m_udp_uc_dst_port_attach_map, rule_key, udp_3t_only);
            }
            try {
                p_tmp_rfs =
                    new (std::nothrow) rfs_uc(&flow_spec_5t, &m_ring, dst_port_filter, flow_tag_id);
            } catch (xlio_exception &e) {
                ring_logerr("%s", e.message);
                return false;
            }
            BULLSEYE_EXCLUDE_BLOCK_START
            if (!p_tmp_rfs) {
                ring_logerr("Failed to allocate rfs!");
                return false;
            }
            BULLSEYE_EXCLUDE_BLOCK_END

            p_rfs = p_tmp_rfs;
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
            if (g_p_app->type == APP_NONE || !g_p_app->add_second_4t_rule)
#endif
            {
                m_flow_udp_uc_map[rfs_key] = p_rfs;
            }
        } else {
            p_rfs = itr->second;
        }
    } else if (flow_spec_5t.is_udp_mc()) {
        KEY2T key_udp_mc(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port());
        sock_addr rule_key(flow_spec_5t.get_family(), &flow_spec_5t.get_dst_ip(), 0U);
        if (flow_tag_id) {
            if (m_ring.m_b_sysvar_mc_force_flowtag || !si->flow_in_reuse()) {
                ring_logdbg("MC flow tag ID=%d for socketinfo=%p is enabled: force_flowtag=%d, "
                            "SO_REUSEADDR | SO_REUSEPORT=%d",
                            flow_tag_id, si, m_ring.m_b_sysvar_mc_force_flowtag,
                            si->flow_in_reuse());
            } else {
                flow_tag_id = FLOW_TAG_MASK;
                ring_logdbg("MC flow tag for socketinfo=%p is disabled: force_flowtag=0, "
                            "SO_REUSEADDR or SO_REUSEPORT were enabled",
                            si);
            }
        }
        // Note for CX3:
        // For IB MC flow, the port is zeroed in the ibv_flow_spec when calling to ibv_flow_spec().
        // It means that for every MC group, even if we have sockets with different ports - only one
        // rule in the HW. So the hash map below keeps track of the number of sockets per rule so we
        // know when to call ibv_attach and ibv_detach
        rfs_rule_filter *l2_mc_ip_filter = nullptr;
        if (m_ring.m_b_sysvar_eth_mc_l2_only_rules) {
            auto l2_mc_iter = m_ring.m_l2_mc_ip_attach_map.find(rule_key);
            // It means that this is the first time attach called with this MC ip
            if (l2_mc_iter == m_ring.m_l2_mc_ip_attach_map.end()) {
                m_ring.m_l2_mc_ip_attach_map[rule_key].counter = 1;
            } else {
                m_ring.m_l2_mc_ip_attach_map[rule_key].counter = ((l2_mc_iter->second.counter) + 1);
            }
        }

        auto itr = m_flow_udp_mc_map.find(key_udp_mc);
        if (itr == m_flow_udp_mc_map.end()) {
            // It means that no rfs object exists so I need to create a new one and insert it to
            // the flow map.
            if (m_ring.m_b_sysvar_eth_mc_l2_only_rules) {
                l2_mc_ip_filter =
                    new rfs_rule_filter(m_ring.m_l2_mc_ip_attach_map, rule_key, flow_spec_5t);
            }
            try {
                p_tmp_rfs = new rfs_mc(&flow_spec_5t, &m_ring, l2_mc_ip_filter, flow_tag_id);
            } catch (xlio_exception &e) {
                ring_logerr("%s", e.message);
                return false;
            } catch (const std::bad_alloc &e) {
                NOT_IN_USE(e);
                ring_logerr("Failed to allocate rfs!");
                return false;
            }

            p_rfs = p_tmp_rfs;
            m_flow_udp_mc_map[key_udp_mc] = p_rfs;
        } else {
            p_rfs = itr->second;
        }
    } else if (flow_spec_5t.is_tcp()) {
        KEY4T rfs_key(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_src_ip(),
                      flow_spec_5t.get_dst_port(), flow_spec_5t.get_src_port());
        sock_addr rule_key(flow_spec_5t.get_family(), &flow_spec_5t.get_dst_ip(),
                           flow_spec_5t.get_dst_port());
        rfs_rule_filter *dst_port_filter = nullptr;
        if (safe_mce_sys().tcp_3t_rules || safe_mce_sys().tcp_2t_rules) {
            if (safe_mce_sys().tcp_2t_rules) {
                rule_key.set_in_port(0);
            }
            auto dst_port_iter = m_ring.m_tcp_dst_port_attach_map.find(rule_key);
            if (dst_port_iter == m_ring.m_tcp_dst_port_attach_map.end()) {
                m_ring.m_tcp_dst_port_attach_map[rule_key].counter = 1;
            } else {
                m_ring.m_tcp_dst_port_attach_map[rule_key].counter =
                    ((dst_port_iter->second.counter) + 1);
            }
        }

        if (flow_tag_id &&
            (flow_spec_5t.is_3_tuple() || (!force_5t && safe_mce_sys().tcp_3t_rules) ||
             safe_mce_sys().tcp_2t_rules)) {
            ring_logdbg("flow tag id = %d is disabled for socket fd = %d to be processed on RFS!",
                        flow_tag_id, si->get_fd());
            flow_tag_id = FLOW_TAG_MASK;
        }

        auto itr = m_flow_tcp_map.find(rfs_key);
        if (itr == end(m_flow_tcp_map)) {
            // It means that no rfs object exists so I need to create a new one and insert it to
            // the flow map
            if (safe_mce_sys().tcp_2t_rules) {
                flow_tuple tcp_2t_only(flow_spec_5t.get_dst_ip(), 0, ip_address::any_addr(), 0,
                                       flow_spec_5t.get_protocol(), flow_spec_5t.get_family());
                dst_port_filter =
                    new rfs_rule_filter(m_ring.m_tcp_dst_port_attach_map, rule_key, tcp_2t_only);
            } else if (!force_5t && safe_mce_sys().tcp_3t_rules) {
                flow_tuple tcp_3t_only(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port(),
                                       ip_address::any_addr(), 0, flow_spec_5t.get_protocol(),
                                       flow_spec_5t.get_family());
                dst_port_filter =
                    new rfs_rule_filter(m_ring.m_tcp_dst_port_attach_map, rule_key, tcp_3t_only);
            }
            try {
                if (safe_mce_sys().gro_streams_max && m_ring.is_simple()) {
                    p_tmp_rfs = new (std::nothrow)
                        rfs_uc_tcp_gro(&flow_spec_5t, &m_ring, dst_port_filter, flow_tag_id);
                } else {
                    p_tmp_rfs = new (std::nothrow)
                        rfs_uc(&flow_spec_5t, &m_ring, dst_port_filter, flow_tag_id);
                }
            } catch (xlio_exception &e) {
                ring_logerr("%s", e.message);
                return false;
            }
            BULLSEYE_EXCLUDE_BLOCK_START
            if (!p_tmp_rfs) {
                ring_logerr("Failed to allocate rfs!");
                return false;
            }
            BULLSEYE_EXCLUDE_BLOCK_END

            p_rfs = p_tmp_rfs;
            si->set_rfs_ptr(p_rfs);
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
            if (g_p_app->type == APP_NONE || !g_p_app->add_second_4t_rule)
#endif
            {
                m_flow_tcp_map[rfs_key] = p_rfs;
            }
        } else {
            p_rfs = itr->second;
        }
        BULLSEYE_EXCLUDE_BLOCK_START
    } else {
        ring_logerr("Could not find map (TCP, UC or MC) for requested flow");
        return false;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    bool ret = p_rfs->attach_flow(sink);
    if (ret) {
        if (flow_tag_id && (flow_tag_id != FLOW_TAG_MASK)) {
            // A flow with FlowTag was attached succesfully, check stored rfs for fast path be
            // tag_id
            si->set_flow_tag(flow_tag_id);
            ring_logdbg("flow_tag: %d registration is done!", flow_tag_id);
        }
    } else {
        ring_logerr("attach_flow=%d failed!", ret);
    }

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    /* coverity[leaked_storage]
     * Storage leak happens due to g_p_app->add_second_4t_rule logic
     * created new rfs pointed by p_rfs is not stored in map
     * and as a result it is not destroyed
     */
#endif
    /* coverity[leaked_storage] */
    return ret;
}

bool ring_slave::attach_flow(flow_tuple &flow_spec_5t, sockinfo *sink, bool force_5t)
{
    std::lock_guard<decltype(m_lock_ring_rx)> lock(m_lock_ring_rx);

    return (flow_spec_5t.get_family() == AF_INET
                ? m_steering_ipv4.attach_flow(flow_spec_5t, sink, force_5t)
                : m_steering_ipv6.attach_flow(flow_spec_5t, sink, force_5t));
}

template <typename KEY4T, typename KEY2T, typename HDR>
bool steering_handler<KEY4T, KEY2T, HDR>::detach_flow(flow_tuple &flow_spec_5t, sockinfo *sink)
{
    rfs *p_rfs = nullptr;

    ring_logdbg("flow: %s, with sink (%p)", flow_spec_5t.to_str().c_str(), sink);

    /* Get the appropriate hash map (tcp, uc or mc) from the 5t details
     * TODO: Consider unification of following code.
     */
    if (flow_spec_5t.is_udp_uc()) {
        int keep_in_map = 1;
        KEY4T rfs_key(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_src_ip(),
                      flow_spec_5t.get_dst_port(), flow_spec_5t.get_src_port());
        sock_addr rule_key(flow_spec_5t.get_family(), &flow_spec_5t.get_dst_ip(),
                           flow_spec_5t.get_dst_port());
        if (safe_mce_sys().udp_3t_rules) {
            auto dst_port_iter = m_ring.m_udp_uc_dst_port_attach_map.find(rule_key);
            if (dst_port_iter == m_ring.m_udp_uc_dst_port_attach_map.end()) {
                ring_logdbg("Could not find matching counter for UDP src port!");
            } else {
                keep_in_map = m_ring.m_udp_uc_dst_port_attach_map[rule_key].counter =
                    std::max(0, ((dst_port_iter->second.counter) - 1));
            }
        }
        auto itr = m_flow_udp_uc_map.find(rfs_key);
        BULLSEYE_EXCLUDE_BLOCK_START
        if (itr == end(m_flow_udp_uc_map)) {
            ring_logdbg("Could not find rfs object to detach!");
            return false;
        }
        BULLSEYE_EXCLUDE_BLOCK_END

        p_rfs = itr->second;
        p_rfs->detach_flow(sink);
        if (!keep_in_map) {
            m_ring.m_udp_uc_dst_port_attach_map.erase(
                m_ring.m_udp_uc_dst_port_attach_map.find(rule_key));
        }
        if (p_rfs->get_num_of_sinks() == 0) {
            BULLSEYE_EXCLUDE_BLOCK_START
            m_flow_udp_uc_map.erase(itr);
            BULLSEYE_EXCLUDE_BLOCK_END
            delete p_rfs;
        }
    } else if (flow_spec_5t.is_udp_mc()) {
        int keep_in_map = 1;
        KEY2T key_udp_mc(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port());
        sock_addr rule_key(flow_spec_5t.get_family(), &flow_spec_5t.get_dst_ip(), 0U);
        if (m_ring.m_b_sysvar_eth_mc_l2_only_rules) {
            auto l2_mc_iter = m_ring.m_l2_mc_ip_attach_map.find(rule_key);
            BULLSEYE_EXCLUDE_BLOCK_START
            if (l2_mc_iter == m_ring.m_l2_mc_ip_attach_map.end()) {
                ring_logdbg("Could not find matching counter for the MC group!");
                BULLSEYE_EXCLUDE_BLOCK_END
            } else {
                keep_in_map = m_ring.m_l2_mc_ip_attach_map[rule_key].counter =
                    std::max(0, ((l2_mc_iter->second.counter) - 1));
            }
        }

        auto itr = m_flow_udp_mc_map.find(key_udp_mc);
        BULLSEYE_EXCLUDE_BLOCK_START
        if (itr == end(m_flow_udp_mc_map)) {
            ring_logdbg("Could not find rfs object to detach!");
            return false;
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        p_rfs = itr->second;
        p_rfs->detach_flow(sink);
        if (!keep_in_map) {
            m_ring.m_l2_mc_ip_attach_map.erase(m_ring.m_l2_mc_ip_attach_map.find(rule_key));
        }
        if (p_rfs->get_num_of_sinks() == 0) {
            BULLSEYE_EXCLUDE_BLOCK_START
            m_flow_udp_mc_map.erase(itr);
            BULLSEYE_EXCLUDE_BLOCK_END
            delete p_rfs;
        }
    } else if (flow_spec_5t.is_tcp()) {
        int keep_in_map = 1;
        KEY4T rfs_key(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_src_ip(),
                      flow_spec_5t.get_dst_port(), flow_spec_5t.get_src_port());
        sock_addr rule_key(flow_spec_5t.get_family(), &flow_spec_5t.get_dst_ip(),
                           flow_spec_5t.get_dst_port());
        if (safe_mce_sys().tcp_3t_rules || safe_mce_sys().tcp_2t_rules) {
            auto dst_port_iter = m_ring.m_tcp_dst_port_attach_map.find(rule_key);
            BULLSEYE_EXCLUDE_BLOCK_START
            if (dst_port_iter == m_ring.m_tcp_dst_port_attach_map.end()) {
                ring_logdbg("Could not find matching counter for TCP src port!");
                BULLSEYE_EXCLUDE_BLOCK_END
            } else {
                keep_in_map = m_ring.m_tcp_dst_port_attach_map[rule_key].counter =
                    std::max(0, ((dst_port_iter->second.counter) - 1));
            }
        }
        auto itr = m_flow_tcp_map.find(rfs_key);
        BULLSEYE_EXCLUDE_BLOCK_START
        if (itr == end(m_flow_tcp_map)) {
            ring_logdbg("Could not find rfs object to detach!");
            return false;
        }
        BULLSEYE_EXCLUDE_BLOCK_END

        p_rfs = itr->second;
        p_rfs->detach_flow(sink);
        if (!keep_in_map) {
            m_ring.m_tcp_dst_port_attach_map.erase(m_ring.m_tcp_dst_port_attach_map.find(rule_key));
        }
        if (p_rfs->get_num_of_sinks() == 0) {
            BULLSEYE_EXCLUDE_BLOCK_START
            m_flow_tcp_map.erase(itr);
            BULLSEYE_EXCLUDE_BLOCK_END
            delete p_rfs;
        }
        BULLSEYE_EXCLUDE_BLOCK_START
    } else {
        ring_logerr("Could not find map (TCP, UC or MC) for requested flow");
        return false;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return true;
}

bool ring_slave::detach_flow(flow_tuple &flow_spec_5t, sockinfo *sink)
{
    std::lock_guard<decltype(m_lock_ring_rx)> lock(m_lock_ring_rx);

    return (flow_spec_5t.get_family() == AF_INET ? m_steering_ipv4.detach_flow(flow_spec_5t, sink)
                                                 : m_steering_ipv6.detach_flow(flow_spec_5t, sink));
}

#ifdef DEFINED_UTLS
template <typename KEY4T, typename KEY2T, typename HDR>
rfs_rule *steering_handler<KEY4T, KEY2T, HDR>::tls_rx_create_rule(const flow_tuple &flow_spec_5t,
                                                                  xlio_tir *tir)
{
    KEY4T rfs_key(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_src_ip(), flow_spec_5t.get_dst_port(),
                  flow_spec_5t.get_src_port());
    auto itr = m_flow_tcp_map.find(rfs_key);
    if (itr == end(m_flow_tcp_map)) {
        ring_logerr("Could not find rfs for flow: %s", flow_spec_5t.to_str().c_str());
        return NULL;
    }
    rfs *p_rfs = itr->second;
    return p_rfs->create_rule(tir, flow_spec_5t);
}

rfs_rule *ring_slave::tls_rx_create_rule(const flow_tuple &flow_spec_5t, xlio_tir *tir)
{
    return (flow_spec_5t.get_family() == AF_INET
                ? m_steering_ipv4.tls_rx_create_rule(flow_spec_5t, tir)
                : m_steering_ipv6.tls_rx_create_rule(flow_spec_5t, tir));
}
#endif /* DEFINED_UTLS */

// calling sockinfo callback with RFS bypass
static inline bool check_rx_packet(sockinfo *si, mem_buf_desc_t *p_rx_wc_buf_desc,
                                   void *fd_ready_array)
{
    p_rx_wc_buf_desc->reset_ref_count();
    return si->rx_input_cb(p_rx_wc_buf_desc, fd_ready_array);
}

// All CQ wce come here for some basic sanity checks and then are distributed to the correct ring
// handler Return values: false = Reuse this data buffer & mem_buf_desc
bool ring_slave::rx_process_buffer(mem_buf_desc_t *p_rx_wc_buf_desc, void *pv_fd_ready_array)
{
    static uint16_t NET_ETH_P_IP = htons(ETH_P_IP);
    static uint16_t NET_ETH_P_IPV6 = htons(ETH_P_IPV6);
    static uint16_t NET_ETH_P_8021Q = htons(ETH_P_8021Q);

    size_t transport_header_len;
    struct ethhdr *p_eth_h = (struct ethhdr *)(p_rx_wc_buf_desc->p_buffer);

    // Validate buffer size
    size_t sz_data = p_rx_wc_buf_desc->sz_data;
    if (unlikely(sz_data > p_rx_wc_buf_desc->sz_buffer)) {
        if (sz_data == IP_FRAG_FREED) {
            ring_logfuncall("Rx buffer dropped - old fragment part");
        } else {
            ring_logwarn("Rx buffer dropped - buffer too small (%zu, %lu)", sz_data,
                         p_rx_wc_buf_desc->sz_buffer);
        }
        return false;
    }

    inc_cq_moderation_stats();

    m_p_ring_stat->n_rx_byte_count += sz_data;
    ++m_p_ring_stat->n_rx_pkt_count;

    // This is an internal function (within ring and 'friends'). No need for lock mechanism.
    if (likely(m_flow_tag_enabled && p_rx_wc_buf_desc->rx.flow_tag_id &&
               p_rx_wc_buf_desc->rx.flow_tag_id != FLOW_TAG_MASK &&
               !p_rx_wc_buf_desc->rx.is_sw_csum_need)) {
        sockinfo *si = nullptr;
        // trying to get sockinfo per flow_tag_id-1 as it was incremented at attach
        // to allow mapping sockfd=0
        assert(g_p_fd_collection);
        si = static_cast<sockinfo *>(
            g_p_fd_collection->get_sockfd(p_rx_wc_buf_desc->rx.flow_tag_id - 1));
        if (likely(si) && si->is_xlio_socket() &&
            unlikely(si->get_poll_group() == nullptr ||
                     si->get_poll_group() != this->get_poll_group())) {
            return false;
        }

        if (likely(si)) {
            // will process packets with set flow_tag_id and enabled for the socket
            if (p_eth_h->h_proto == NET_ETH_P_8021Q) {
                // Handle VLAN header as next protocol
                transport_header_len = ETH_VLAN_HDR_LEN;
            } else {
                transport_header_len = ETH_HDR_LEN;
            }

            const void *saddr, *daddr;
            sa_family_t family;
            uint16_t ip_payload_len;
            uint16_t ip_hdr_len;
            uint8_t protocol;

            struct iphdr *p_ip_h =
                (struct iphdr *)(p_rx_wc_buf_desc->p_buffer + transport_header_len);
            if (likely(p_ip_h->version == IPV4_VERSION)) { // IPv4
                ip_hdr_len = IP_HLEN; //(int)(p_ip_h->ihl)*4;
                ip_payload_len = ntohs(p_ip_h->tot_len) - ip_hdr_len;
                protocol = p_ip_h->protocol;
                saddr = &p_ip_h->saddr;
                daddr = &p_ip_h->daddr;
                family = AF_INET;
            } else {
                struct ip6_hdr *p_ip_h6 = reinterpret_cast<struct ip6_hdr *>(p_ip_h);
                ip_hdr_len = IPV6_HLEN;
                ip_payload_len = ntohs(p_ip_h6->ip6_plen);
                protocol = p_ip_h6->ip6_nxt;
                saddr = &p_ip_h6->ip6_src;
                daddr = &p_ip_h6->ip6_dst;
                family = AF_INET6;
            }
            // Remove ethernet padding from the data size
            p_rx_wc_buf_desc->sz_data = transport_header_len + ip_hdr_len + ip_payload_len;

            ring_logfunc("FAST PATH Rx packet info: transport_header_len: %d, IP_header_len: %d L3 "
                         "proto: %d flow_tag_id: %d",
                         transport_header_len, ip_hdr_len, protocol,
                         p_rx_wc_buf_desc->rx.flow_tag_id);

            if (likely(protocol == IPPROTO_TCP)) {
                struct tcphdr *p_tcp_h = (struct tcphdr *)((uint8_t *)p_ip_h + ip_hdr_len);

                // Update packet descriptor with datagram base address and length
                p_rx_wc_buf_desc->rx.frag.iov_base = (uint8_t *)p_tcp_h + sizeof(struct tcphdr);
                p_rx_wc_buf_desc->rx.frag.iov_len = ip_payload_len - sizeof(struct tcphdr);
                p_rx_wc_buf_desc->rx.sz_payload = ip_payload_len - p_tcp_h->doff * 4;

                p_rx_wc_buf_desc->rx.tcp.p_ip_h = p_ip_h;
                p_rx_wc_buf_desc->rx.tcp.p_tcp_h = p_tcp_h;
                p_rx_wc_buf_desc->rx.n_transport_header_len = transport_header_len;
                p_rx_wc_buf_desc->rx.n_frags = 1;

                ring_logfunc("FAST PATH Rx TCP segment info: src_port=%d, dst_port=%d, "
                             "flags='%s%s%s%s%s%s' seq=%u, ack=%u, win=%u, payload_sz=%u",
                             ntohs(p_tcp_h->source), ntohs(p_tcp_h->dest), p_tcp_h->urg ? "U" : "",
                             p_tcp_h->ack ? "A" : "", p_tcp_h->psh ? "P" : "",
                             p_tcp_h->rst ? "R" : "", p_tcp_h->syn ? "S" : "",
                             p_tcp_h->fin ? "F" : "", ntohl(p_tcp_h->seq), ntohl(p_tcp_h->ack_seq),
                             ntohs(p_tcp_h->window), p_rx_wc_buf_desc->rx.sz_payload);

                return si->get_rfs_ptr()->rx_dispatch_packet(p_rx_wc_buf_desc, pv_fd_ready_array);
            }

            if (likely(protocol == IPPROTO_UDP)) {
                struct udphdr *p_udp_h = (struct udphdr *)((uint8_t *)p_ip_h + ip_hdr_len);

                // Update the L3 and L4 info
                p_rx_wc_buf_desc->rx.src.set_ip_port(family, saddr, p_udp_h->source);
                p_rx_wc_buf_desc->rx.dst.set_ip_port(family, daddr, p_udp_h->dest);

                // Update packet descriptor with datagram base address and length
                p_rx_wc_buf_desc->rx.frag.iov_base = (uint8_t *)p_udp_h + sizeof(struct udphdr);
                p_rx_wc_buf_desc->rx.frag.iov_len = ip_payload_len - sizeof(struct udphdr);
                p_rx_wc_buf_desc->rx.sz_payload = ntohs(p_udp_h->len) - sizeof(struct udphdr);

                p_rx_wc_buf_desc->rx.udp.ifindex = m_parent->get_if_index();
                p_rx_wc_buf_desc->rx.n_frags = 1;

                ring_logfunc("FAST PATH Rx UDP datagram info: src_port=%d, dst_port=%d, "
                             "payload_sz=%d, csum=%#x",
                             ntohs(p_udp_h->source), ntohs(p_udp_h->dest),
                             p_rx_wc_buf_desc->rx.sz_payload, p_udp_h->check);

                return check_rx_packet(si, p_rx_wc_buf_desc, pv_fd_ready_array);
            }

            return false;
        }
    }

    // Validate transport type headers
    switch (m_transport_type) {
    case XLIO_TRANSPORT_ETH: {
        uint16_t h_proto = p_eth_h->h_proto;

        ring_logfunc("Rx buffer Ethernet dst=" ETH_HW_ADDR_PRINT_FMT
                     " <- src=" ETH_HW_ADDR_PRINT_FMT " type=%#x",
                     ETH_HW_ADDR_PRINT_ADDR(p_eth_h->h_dest),
                     ETH_HW_ADDR_PRINT_ADDR(p_eth_h->h_source), htons(h_proto));

        // Handle VLAN header as next protocol
        struct vlanhdr *p_vlan_hdr = nullptr;
        uint16_t packet_vlan = 0;
        if (h_proto == NET_ETH_P_8021Q) {
            p_vlan_hdr = (struct vlanhdr *)((uint8_t *)p_eth_h + ETH_HDR_LEN);
            transport_header_len = ETH_VLAN_HDR_LEN;
            h_proto = p_vlan_hdr->h_vlan_encapsulated_proto;
            packet_vlan = (htons(p_vlan_hdr->h_vlan_TCI) & VLAN_VID_MASK);
        } else {
            transport_header_len = ETH_HDR_LEN;
        }

        p_rx_wc_buf_desc->rx.n_transport_header_len = transport_header_len;

        // TODO: Remove this code when handling vlan in flow steering will be available. Change this
        // code if vlan stripping is performed.
        if ((m_vlan & VLAN_VID_MASK) != packet_vlan) {
            ring_logfunc("Rx buffer dropped- Mismatched vlan. Packet vlan = %d, Local vlan = %d",
                         packet_vlan, m_vlan & VLAN_VID_MASK);
            return false;
        }

        // Validate IP header as next protocol
        if (unlikely(h_proto != NET_ETH_P_IP) && unlikely(h_proto != NET_ETH_P_IPV6)) {
            ring_logwarn("Rx buffer dropped - Invalid Ethr Type (h_proto=%#x-p_eth_h->h_proto=%#x "
                         ": %#x, %#x)",
                         h_proto, p_eth_h->h_proto, NET_ETH_P_IP, NET_ETH_P_IPV6);
            return false;
        }
    } break;
    default:
        ring_logwarn("Rx buffer dropped - Unknown transport type %d", m_transport_type);
        return false;
    }

    // Jump to IP header - Skip Ethernet (MAC) header sizes
    sz_data -= transport_header_len;

    // Validate size for IPv4 header
    if (unlikely(sz_data < sizeof(struct iphdr))) {
        ring_logwarn("Rx buffer dropped - buffer too small for IPv4 header (%zu, %zu)", sz_data,
                     sizeof(struct iphdr));
        return false;
    }

    // Get the ip header pointer
    struct iphdr *p_ip_h = (struct iphdr *)(p_rx_wc_buf_desc->p_buffer + transport_header_len);

    if (likely(p_ip_h->version == IPV4_VERSION)) {
        return m_steering_ipv4.rx_process_buffer_no_flow_id(p_rx_wc_buf_desc, pv_fd_ready_array,
                                                            p_ip_h);
    }

    if (likely(p_ip_h->version == IPV6_VERSION)) {
        return m_steering_ipv6.rx_process_buffer_no_flow_id(p_rx_wc_buf_desc, pv_fd_ready_array,
                                                            reinterpret_cast<ip6_hdr *>(p_ip_h));
    }

    // Drop all non IPv4 packets
    ring_logwarn("Rx packet dropped - not IPV4/6 packet (got version: %#x)", p_ip_h->version);
    return false;
}

inline uint32_t hdr_get_tot_len(iphdr *p_ip_h)
{
    return ntohs(p_ip_h->tot_len);
}

inline uint32_t hdr_get_tot_len(ip6_hdr *p_ip_h)
{
    return ntohs(p_ip_h->ip6_plen) + IPV6_HLEN;
}

inline sa_family_t hdr_get_family(iphdr *p_ip_h)
{
    NOT_IN_USE(p_ip_h);
    return AF_INET;
}

inline sa_family_t hdr_get_family(ip6_hdr *p_ip_h)
{
    NOT_IN_USE(p_ip_h);
    return AF_INET6;
}

inline std::string hdr_get_id(iphdr *p_ip_h)
{
    return std::to_string(ntohs(p_ip_h->id));
}

inline std::string hdr_get_id(ip6_hdr *p_ip_h)
{
    return std::to_string(ntohs(p_ip_h->ip6_flow));
}

inline const void *hdr_get_saddr(iphdr *p_ip_h)
{
    return &p_ip_h->saddr;
}

inline const void *hdr_get_saddr(ip6_hdr *p_ip_h)
{
    return &p_ip_h->ip6_src;
}

inline const void *hdr_get_daddr(iphdr *p_ip_h)
{
    return &p_ip_h->daddr;
}

inline const void *hdr_get_daddr(ip6_hdr *p_ip_h)
{
    return &p_ip_h->ip6_dst;
}

// @param data Expected at least 8 bytes long buffer.
static inline int ipv6_ext_headers_parse(const void *data, size_t &ext_hdrs_len,
                                         uint8_t &next_header)
{
    switch (next_header) {
    case 51: // Authentication Header
        next_header = *reinterpret_cast<const uint8_t *>(data);
        ext_hdrs_len = (*(reinterpret_cast<const uint8_t *>(data) + 1) + 2ULL) * 4ULL;
        ext_hdrs_len += (8ULL - (ext_hdrs_len % 8ULL));
        break;
    case 0: // Hop by Hop
    case 43: // Routing
    case 60: // Destination Options for IPv6
    case 135: // Mobility Header
    case 139: // Host Identity Protocol
    case 140: // Shim6 Protocol
        next_header = *reinterpret_cast<const uint8_t *>(data);
        ext_hdrs_len = (1ULL + *(reinterpret_cast<const uint8_t *>(data) + 1)) * 8ULL;
        break;
    case IPPROTO_TCP:
    case IPPROTO_UDP:
    case 59:
        return 0; // No next header.
    case 44: // Fragment
             // [TODO IPv6 Parse and handle fragments]
    case 50: // Encapsulating Security Payload
    default:
        return -1; // Unknown ext header or L4 protocol. Ignore the packet.
    }

    return 1; // More ext headers.
}

struct ext_hdr_data {
    uint16_t ip_frag_off;
    uint16_t ip_hdr_len;
    uint8_t l4_protocol;
};

static inline void hdr_parse(iphdr *p_ip_h, ext_hdr_data &hdr_data, size_t buff_payload_size)
{
    NOT_IN_USE(buff_payload_size);
    hdr_data.ip_frag_off = ntohs(p_ip_h->frag_off);
    hdr_data.ip_hdr_len = (int)(p_ip_h->ihl) * 4;
    hdr_data.l4_protocol = p_ip_h->protocol;
}

static void hdr_parse(ip6_hdr *p_ip_h, ext_hdr_data &hdr_data, size_t buff_payload_size)
{
    hdr_data.ip_hdr_len = IPV6_HLEN;

    if (likely(p_ip_h->ip6_nxt == IPPROTO_TCP) || likely(p_ip_h->ip6_nxt == IPPROTO_UDP)) {
        hdr_data.ip_frag_off = 0U;
        hdr_data.l4_protocol = p_ip_h->ip6_nxt;
    } else { // Parse ext headers
        size_t ext_hdr_len = 0U;
        size_t norm_ext_hdr_len;
        uint8_t header_code = p_ip_h->ip6_nxt;
        const uint8_t *data = reinterpret_cast<const uint8_t *>(p_ip_h) + IPV6_HLEN;
        buff_payload_size -= IPV6_HLEN;

        while (likely(buff_payload_size >= 8U) &&
               likely(ipv6_ext_headers_parse(data, ext_hdr_len, header_code) == 1)) {
            norm_ext_hdr_len = std::min(buff_payload_size, ext_hdr_len);
            hdr_data.ip_hdr_len += norm_ext_hdr_len;
            data += norm_ext_hdr_len;
            buff_payload_size -= norm_ext_hdr_len;
        }

        hdr_data.l4_protocol = header_code; // Unknown protocol packet is dropped later.
        hdr_data.ip_frag_off = 0U;
    }
}

static inline uint16_t csum_hdr_len(iphdr *p_ip_h, const ext_hdr_data &ext_data)
{
    NOT_IN_USE(ext_data);
    return (p_ip_h->ihl << 2);
}

static inline uint16_t csum_hdr_len(ip6_hdr *p_ip_h, const ext_hdr_data &ext_data)
{
    NOT_IN_USE(p_ip_h);
    return (ext_data.ip_hdr_len - IPV6_HLEN);
}

template <typename KEY4T, typename KEY2T, typename HDR>
bool steering_handler<KEY4T, KEY2T, HDR>::rx_process_buffer_no_flow_id(
    mem_buf_desc_t *p_rx_wc_buf_desc, void *pv_fd_ready_array, HDR *p_ip_h)
{
    size_t ip_tot_len = hdr_get_tot_len(p_ip_h);
    size_t sz_data = p_rx_wc_buf_desc->sz_data - p_rx_wc_buf_desc->rx.n_transport_header_len;

    // Check that received buffer size is not smaller then the ip datagram total size
    if (unlikely(sz_data < ip_tot_len)) {
        ring_logwarn(
            "Rx packet dropped - buffer too small for received datagram (RxBuf:%zu IP:%zu)",
            sz_data, ip_tot_len);
        ring_loginfo("Rx packet info (buf->%p, bufsize=%zu), id=%s", p_rx_wc_buf_desc->p_buffer,
                     p_rx_wc_buf_desc->sz_data, hdr_get_id(p_ip_h).c_str());
        vlog_print_buffer(VLOG_INFO, "rx packet data: ", "\n",
                          (const char *)p_rx_wc_buf_desc->p_buffer,
                          std::min(112, (int)p_rx_wc_buf_desc->sz_data));
        return false;
    }

    // Read fragmentation parameters and extention headers for IPv6.
    ext_hdr_data hdr_data;
    hdr_parse(p_ip_h, hdr_data, sz_data);

    // Remove ethernet padding from the data size.
    p_rx_wc_buf_desc->sz_data -= (sz_data - ip_tot_len);

    uint16_t n_frag_offset = (hdr_data.ip_frag_off & IP_OFFMASK) * 8;

    ring_logfunc("Rx ip packet info: dst=%s, src=%s, packet_sz=%zu, offset=%" PRIu16
                 ", id=%s, proto=%s[%u" PRIu8 "]",
                 reinterpret_cast<const ip_address *>(hdr_get_daddr(p_ip_h))
                     ->to_str(hdr_get_family(p_ip_h))
                     .c_str(),
                 reinterpret_cast<const ip_address *>(hdr_get_saddr(p_ip_h))
                     ->to_str(hdr_get_family(p_ip_h))
                     .c_str(),
                 (sz_data > ip_tot_len ? ip_tot_len : sz_data), n_frag_offset,
                 hdr_get_id(p_ip_h).c_str(), iphdr_protocol_type_to_str(hdr_data.l4_protocol),
                 hdr_data.l4_protocol);

    // Check that the ip datagram has at least the udp header size for the first ip fragment
    // (besides the ip header)
    if (unlikely((n_frag_offset == 0) &&
                 (ip_tot_len < (hdr_data.ip_hdr_len + sizeof(struct udphdr))))) {
        ring_logwarn("Rx packet dropped - ip packet too small (%zu bytes) - udp header cut!",
                     ip_tot_len);
        return false;
    }

    // Handle fragmentation
    p_rx_wc_buf_desc->rx.n_frags = 1;

    // Currently we don't expect to receive fragments
    if (unlikely((hdr_data.ip_frag_off & IP_MF) || n_frag_offset)) {
        // Update fragments descriptor with datagram base address and length
        p_rx_wc_buf_desc->rx.frag.iov_base = (uint8_t *)p_ip_h + hdr_data.ip_hdr_len;
        p_rx_wc_buf_desc->rx.frag.iov_len = ip_tot_len - hdr_data.ip_hdr_len;

        // Add ip fragment packet to out fragment manager
        mem_buf_desc_t *new_buf = nullptr;
        int ret = -1;
        if (g_p_ip_frag_manager) {
            ret = g_p_ip_frag_manager->add_frag(p_ip_h, p_rx_wc_buf_desc, &new_buf);
        }
        if (ret < 0) { // Finished with error
            return false;
        }
        if (!new_buf) { // This is fragment
            return true;
        }

        // Re-calc all ip related values for new ip packet of head fragmentation list
        size_t transport_header_len = p_rx_wc_buf_desc->rx.n_transport_header_len;
        p_rx_wc_buf_desc = new_buf;
        p_ip_h = (HDR *)(p_rx_wc_buf_desc->p_buffer + transport_header_len);
        sz_data = p_rx_wc_buf_desc->sz_data - transport_header_len;
        hdr_parse(p_ip_h, hdr_data, sz_data);
        ip_tot_len = hdr_get_tot_len(p_ip_h);

        mem_buf_desc_t *tmp;
        for (tmp = p_rx_wc_buf_desc; tmp; tmp = tmp->p_next_desc) {
            ++p_rx_wc_buf_desc->rx.n_frags;
        }
    }

    if (p_rx_wc_buf_desc->rx.is_sw_csum_need && compute_ip_checksum(p_ip_h)) {
        return false; // false ip checksum
    }

    rfs *p_rfs = nullptr;
    size_t payload_len = ip_tot_len - hdr_data.ip_hdr_len;

    switch (hdr_data.l4_protocol) {
    case IPPROTO_UDP: {
        // Get the udp header pointer + udp payload size
        struct udphdr *p_udp_h = (struct udphdr *)((uint8_t *)p_ip_h + hdr_data.ip_hdr_len);

        // Update packet descriptor with datagram base address and length
        p_rx_wc_buf_desc->rx.frag.iov_base = (uint8_t *)p_udp_h + sizeof(struct udphdr);
        p_rx_wc_buf_desc->rx.frag.iov_len = payload_len - sizeof(struct udphdr);

        if (p_rx_wc_buf_desc->rx.is_sw_csum_need && p_udp_h->check &&
            compute_udp_checksum_rx(p_ip_h, p_udp_h, p_rx_wc_buf_desc)) {
            return false; // false udp checksum
        }

        size_t sz_payload = ntohs(p_udp_h->len) - sizeof(struct udphdr);
        ring_logfunc("Rx udp datagram info: src_port=%" PRIu16 ", dst_port=%" PRIu16
                     ", payload_sz=%zu, csum=%#x",
                     ntohs(p_udp_h->source), ntohs(p_udp_h->dest), sz_payload, p_udp_h->check);

        // Update the L3/L4 info
        p_rx_wc_buf_desc->rx.src.set_ip_port(hdr_get_family(p_ip_h), hdr_get_saddr(p_ip_h),
                                             p_udp_h->source);
        p_rx_wc_buf_desc->rx.dst.set_ip_port(hdr_get_family(p_ip_h), hdr_get_daddr(p_ip_h),
                                             p_udp_h->dest);
        p_rx_wc_buf_desc->rx.sz_payload = sz_payload;

        // Update the protocol info
        p_rx_wc_buf_desc->rx.udp.ifindex = m_ring.m_parent->get_if_index();

        // Find the relevant hash map and pass the packet to the rfs for dispatching
        if (!p_rx_wc_buf_desc->rx.dst.is_mc()) { // This is UDP UC packet
            auto itr =
                m_flow_udp_uc_map.find(KEY4T(p_rx_wc_buf_desc->rx.dst, p_rx_wc_buf_desc->rx.src));

            // If we didn't find a match for 5T, look for a match with 3T
            if (unlikely(itr == end(m_flow_udp_uc_map))) {
                auto itr3T =
                    m_flow_udp_uc_map.find(KEY4T(p_rx_wc_buf_desc->rx.dst, s_sock_addrany));
                if (likely(itr3T != end(m_flow_udp_uc_map))) {
                    p_rfs = itr3T->second;
                }
            } else {
                p_rfs = itr->second;
            }
        } else { // This is UDP MC packet
            auto itr = m_flow_udp_mc_map.find(KEY2T(p_rx_wc_buf_desc->rx.dst));
            if (likely(itr != end(m_flow_udp_mc_map))) {
                p_rfs = itr->second;
            }
        }
    } break;

    case IPPROTO_TCP: {
        // Get the tcp header pointer + tcp payload size
        struct tcphdr *p_tcp_h = (struct tcphdr *)((uint8_t *)p_ip_h + hdr_data.ip_hdr_len);

        if (p_rx_wc_buf_desc->rx.is_sw_csum_need &&
            compute_tcp_checksum(p_ip_h, (unsigned short *)p_tcp_h,
                                 csum_hdr_len(p_ip_h, hdr_data))) {
            return false; // false tcp checksum
        }

        size_t sz_payload = payload_len - p_tcp_h->doff * 4;
        ring_logfunc("Rx TCP segment info: src_port=%" PRIu16 ", dst_port=%" PRIu16
                     ", flags='%s%s%s%s%s%s' seq=%u, ack=%u, win=%" PRIu16 ", payload_sz=%zu",
                     ntohs(p_tcp_h->source), ntohs(p_tcp_h->dest), p_tcp_h->urg ? "U" : "",
                     p_tcp_h->ack ? "A" : "", p_tcp_h->psh ? "P" : "", p_tcp_h->rst ? "R" : "",
                     p_tcp_h->syn ? "S" : "", p_tcp_h->fin ? "F" : "", ntohl(p_tcp_h->seq),
                     ntohl(p_tcp_h->ack_seq), ntohs(p_tcp_h->window), sz_payload);

        // Update packet descriptor with datagram base address and length
        p_rx_wc_buf_desc->rx.frag.iov_base = (uint8_t *)p_tcp_h + sizeof(struct tcphdr);
        p_rx_wc_buf_desc->rx.frag.iov_len = payload_len - sizeof(struct tcphdr);

        // Update the L3/L4 info
        p_rx_wc_buf_desc->rx.src.set_ip_port(hdr_get_family(p_ip_h), hdr_get_saddr(p_ip_h),
                                             p_tcp_h->source);
        p_rx_wc_buf_desc->rx.dst.set_ip_port(hdr_get_family(p_ip_h), hdr_get_daddr(p_ip_h),
                                             p_tcp_h->dest);
        p_rx_wc_buf_desc->rx.sz_payload = sz_payload;

        // Update the protocol info
        p_rx_wc_buf_desc->rx.tcp.p_ip_h = p_ip_h;
        p_rx_wc_buf_desc->rx.tcp.p_tcp_h = p_tcp_h;

        // Find the relevant hash map and pass the packet to the rfs for dispatching
        auto itr = m_flow_tcp_map.find(KEY4T(p_rx_wc_buf_desc->rx.dst, p_rx_wc_buf_desc->rx.src));

        // If we didn't find a match for 5T, look for a match with 3T
        if (unlikely(itr == end(m_flow_tcp_map))) {
            auto itr3T = m_flow_tcp_map.find(KEY4T(p_rx_wc_buf_desc->rx.dst, s_sock_addrany));
            if (likely(itr3T != end(m_flow_tcp_map))) {
                p_rfs = itr3T->second;
            }
        } else {
            p_rfs = itr->second;
        }
    } break;

    default:
        ring_logwarn("Rx packet dropped - undefined protocol = %" PRIu8, hdr_data.l4_protocol);
        return false;
    }

    if (unlikely(!p_rfs)) {
        ring_logdbg("Rx packet dropped - rfs object not found: dst=%s, src=%s, proto=%s[%" PRIu8
                    "]",
                    p_rx_wc_buf_desc->rx.dst.to_str_ip_port().c_str(),
                    p_rx_wc_buf_desc->rx.src.to_str_ip_port().c_str(),
                    iphdr_protocol_type_to_str(hdr_data.l4_protocol), hdr_data.l4_protocol);

        return false;
    }

    return p_rfs->rx_dispatch_packet(p_rx_wc_buf_desc, pv_fd_ready_array);
}

template <typename T> void clear_rfs_map(T &rfs_map)
{
    auto itr = rfs_map.begin();
    while (itr != end(rfs_map)) {
        if (itr->second) {
            delete itr->second;
        }
        itr = rfs_map.erase(itr);
    }
}

template <typename KEY4T, typename KEY2T, typename HDR>
void steering_handler<KEY4T, KEY2T, HDR>::flow_del_all_rfs()
{
    clear_rfs_map(m_flow_tcp_map);
    clear_rfs_map(m_flow_udp_uc_map);
    clear_rfs_map(m_flow_udp_mc_map);
}

void ring_slave::flow_del_all_rfs()
{
    m_steering_ipv4.flow_del_all_rfs();
    m_steering_ipv6.flow_del_all_rfs();
}

bool ring_slave::request_more_tx_buffers(pbuf_type type, uint32_t count, uint32_t lkey)
{
    bool res;

    ring_logfuncall("Allocating additional %d buffers for internal use", count);

    if (type == PBUF_ZEROCOPY) {
        res = g_buffer_pool_zc->get_buffers_thread_safe(m_zc_pool, this, count, lkey);
    } else {
        res = g_buffer_pool_tx->get_buffers_thread_safe(m_tx_pool, this, count, lkey);
    }
    if (!res) {
        ring_logfunc("Out of mem_buf_desc from TX free pool for internal object pool");
        return false;
    }

    return true;
}
