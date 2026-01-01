/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "dst_entry_udp_mc.h"

#define MODULE_NAME "dst_mc"

#define dst_udp_mc_logpanic   __log_panic
#define dst_udp_mc_logerr     __log_err
#define dst_udp_mc_logwarn    __log_warn
#define dst_udp_mc_loginfo    __log_info
#define dst_udp_mc_logdbg     __log_info_dbg
#define dst_udp_mc_logfunc    __log_info_func
#define dst_udp_mc_logfuncall __log_info_funcall

dst_entry_udp_mc::dst_entry_udp_mc(const sock_addr &dst, uint16_t src_port,
                                   const ip_address &tx_if_ip, bool mc_b_loopback,
                                   socket_data &sock_data,
                                   resource_allocation_key &ring_alloc_logic)
    : dst_entry_udp(dst, src_port, sock_data, ring_alloc_logic)
    , m_mc_tx_src_ip(tx_if_ip)
    , m_b_mc_loopback_enabled(mc_b_loopback)
{
    dst_udp_mc_logdbg("%s", to_str().c_str());
}

dst_entry_udp_mc::~dst_entry_udp_mc()
{
    dst_udp_mc_logdbg("%s", to_str().c_str());

    if (m_p_net_dev_entry && m_p_net_dev_val) {
        // Registered in: dst_entry_udp_mc::resolve_net_dev
        // With: g_p_net_device_table_mgr->register_observer(ip_addr(m_mc_tx_src_ip.get_in_addr()),
        //                                                   this, &net_dev_entry).
        dst_udp_mc_logdbg("Unregistering net_dev MC observer if_index: %d",
                          m_p_net_dev_val->get_if_idx());
        if (!g_p_net_device_table_mgr->unregister_observer(m_p_net_dev_val->get_if_idx(), this)) {
            dst_udp_mc_logwarn("Failed to unregister observer (dst_entry_udp_mc) for if_index %d",
                               m_p_net_dev_val->get_if_idx());
        }
    }
}

void dst_entry_udp_mc::set_src_addr()
{
    if (!m_bound_ip.is_anyaddr()) {
        m_pkt_src_ip = m_bound_ip;
    } else if (!m_mc_tx_src_ip.is_anyaddr() && !m_mc_tx_src_ip.is_mc(m_family)) {
        m_pkt_src_ip = m_mc_tx_src_ip;
    } else {
        dst_entry::set_src_addr();
    }
}

// The following function supposed to be called under m_lock
bool dst_entry_udp_mc::resolve_net_dev()
{
    bool ret_val = false;
    cache_entry_subject<int, net_device_val *> *net_dev_entry = nullptr;

    if (!m_mc_tx_src_ip.is_anyaddr() && !m_mc_tx_src_ip.is_mc(m_family)) {
        if (!m_p_net_dev_entry) {
            net_device_val *mc_net_dev =
                g_p_net_device_table_mgr->get_net_device_val(ip_addr(m_mc_tx_src_ip, m_family));
            if (mc_net_dev) {
                if (g_p_net_device_table_mgr->register_observer(mc_net_dev->get_if_idx(), this,
                                                                &net_dev_entry)) {
                    m_p_net_dev_entry = dynamic_cast<net_device_entry *>(net_dev_entry);
                    dst_udp_mc_logdbg("Registered net_dev MC observer if_index: %d",
                                      mc_net_dev->get_if_idx());
                } else {
                    dst_udp_mc_logwarn(
                        "Failed to register observer (dst_entry_udp_mc) for if_index %d",
                        mc_net_dev->get_if_idx());
                }
            }
        }
        if (m_p_net_dev_entry) {
            m_p_net_dev_entry->get_val(m_p_net_dev_val);
            if (m_p_net_dev_val) {
                ret_val = alloc_transport_dep_res();
            } else {
                dst_udp_mc_logdbg("Valid netdev value not found");
            }
        } else {
            m_b_is_offloaded = false;
            dst_udp_mc_logdbg("Netdev is not offloaded fallback to OS");
        }
    } else {
        // XXX TODO: Why we dont pass is_connect to next resolve_net_dev call?
        ret_val = dst_entry::resolve_net_dev();
    }
    return ret_val;
}
