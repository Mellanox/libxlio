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
#include "dst_entry.h"
#include "core/dev/src_addr_selector.h"
#include "core/proto/rule_table_mgr.h"
#include "core/proto/route_table_mgr.h"
#include "core/util/utils.h"

#define MODULE_NAME "dst"

#define dst_logpanic   __log_panic
#define dst_logerr     __log_err
#define dst_logwarn    __log_warn
#define dst_loginfo    __log_info
#define dst_logdbg     __log_info_dbg
#define dst_logfunc    __log_info_func
#define dst_logfuncall __log_info_funcall

dst_entry::dst_entry(const sock_addr &dst, uint16_t src_port, socket_data &sock_data,
                     resource_allocation_key &ring_alloc_logic)
    : m_dst_ip(dst.get_ip_addr())
    , m_dst_port(dst.get_in_port())
    , m_family(dst.get_sa_family())
    , m_header((dst.get_sa_family() == AF_INET6) ? (header *)(new header_ipv6())
                                                 : (header *)(new header_ipv4()))
    , m_header_neigh((dst.get_sa_family() == AF_INET6) ? (header *)(new header_ipv6())
                                                       : (header *)(new header_ipv4()))
    , m_bound_ip(in6addr_any)
    , m_so_bindtodevice_ip(in6addr_any)
    , m_route_src_ip(in6addr_any)
    , m_pkt_src_ip(in6addr_any)
    , m_ring_alloc_logic(sock_data.fd, ring_alloc_logic, this)
    , m_p_tx_mem_buf_desc_list(NULL)
    , m_p_zc_mem_buf_desc_list(NULL)
    , m_b_tx_mem_buf_desc_list_pending(false)
    , m_ttl_hop_limit(sock_data.ttl_hop_limit)
    , m_tos(sock_data.tos)
    , m_pcp(sock_data.pcp)
    , m_id(0)
    , m_src_port(src_port)
{
    dst_logdbg("dst:%s:%d src: %d", m_dst_ip.to_str(m_family).c_str(), ntohs(m_dst_port),
               ntohs(m_src_port));
    init_members();
}

dst_entry::~dst_entry()
{
    dst_logdbg("%s", to_str().c_str());

    if (m_p_neigh_entry) {
        ip_address dst_addr = m_dst_ip;
        if (m_p_rt_val && !m_p_rt_val->get_gw_addr().is_anyaddr() && !dst_addr.is_mc(m_family)) {
            dst_addr = m_p_rt_val->get_gw_addr();
        }
        g_p_neigh_table_mgr->unregister_observer(
            neigh_key(ip_addr(dst_addr, m_family), m_p_net_dev_val), this);
    }

    if (m_p_rt_entry) {
        g_p_route_table_mgr->unregister_observer(
            route_rule_table_key(m_dst_ip, m_route_src_ip, m_family, m_tos), this);
        m_p_rt_entry = NULL;
    }

    if (m_p_ring) {
        if (m_sge) {
            delete[] m_sge;
            m_sge = NULL;
        }

        if (m_p_tx_mem_buf_desc_list) {
            m_p_ring->mem_buf_tx_release(m_p_tx_mem_buf_desc_list, true);
            m_p_tx_mem_buf_desc_list = NULL;
        }
        if (m_p_zc_mem_buf_desc_list) {
            m_p_ring->mem_buf_tx_release(m_p_zc_mem_buf_desc_list, true);
            m_p_zc_mem_buf_desc_list = NULL;
        }

        m_p_net_dev_val->release_ring(m_ring_alloc_logic.get_key());
        m_p_ring = NULL;
    }

    if (m_p_send_wqe_handler) {
        delete m_p_send_wqe_handler;
        m_p_send_wqe_handler = NULL;
    }

    if (m_p_neigh_val) {
        delete m_p_neigh_val;
        m_p_neigh_val = NULL;
    }

    if (m_header) {
        delete m_header;
        m_header = NULL;
    }

    if (m_header_neigh) {
        delete m_header_neigh;
        m_header_neigh = NULL;
    }

    dst_logdbg("Done %s", to_str().c_str());
}

void dst_entry::init_members()
{
    set_state(false);
    m_p_rt_val = NULL;
    m_p_net_dev_val = NULL;
    m_p_ring = NULL;
    m_p_net_dev_entry = NULL;
    m_p_neigh_entry = NULL;
    m_p_neigh_val = NULL;
    m_p_rt_entry = NULL;
    memset(&m_inline_send_wqe, 0, sizeof(m_inline_send_wqe));
    memset(&m_not_inline_send_wqe, 0, sizeof(m_not_inline_send_wqe));
    memset(&m_fragmented_send_wqe, 0, sizeof(m_not_inline_send_wqe));
    m_p_send_wqe_handler = NULL;
    m_sge = NULL;
    m_b_is_offloaded = true;
    m_b_is_initialized = false;
    m_p_send_wqe = NULL;
    m_max_inline = 0;
    m_max_ip_payload_size = 0;
    m_max_udp_payload_size = 0;
    m_b_force_os = false;
    m_src_sel_prefs = 0U;
}

void dst_entry::set_src_addr()
{
    if (!m_route_src_ip.is_anyaddr()) {
        m_pkt_src_ip = m_route_src_ip;
        dst_logfunc("Selected source address (bind): %s",
                    m_pkt_src_ip.to_str(get_sa_family()).c_str());
    } else if (get_routing_addr_sel_src(m_pkt_src_ip)) {
        dst_logfunc("Selected source address (rt_val): %s",
                    m_pkt_src_ip.to_str(get_sa_family()).c_str());
    } else {
        const ip_data *src_addr = nullptr;
        if (m_p_net_dev_val) {
            src_addr = src_addr_selector::select_ip_src_addr(*m_p_net_dev_val, get_dst_addr(),
                                                             m_src_sel_prefs, get_sa_family());
        }

        if (src_addr) {
            m_pkt_src_ip = src_addr->local_addr;
            dst_logfunc("Selected source address: %s",
                        m_pkt_src_ip.to_str(get_sa_family()).c_str());
        } else {
            m_pkt_src_ip = in6addr_any;
            dst_logfunc("Selected source address: any (net_dev=%p)", m_p_net_dev_val);
        }
    }
}

bool dst_entry::get_routing_addr_sel_src(ip_address &out_ip) const
{
    if (m_p_rt_val) {
        // For AF_INET we keep the legacy source selection logic which uses modified routing src
        out_ip =
            (m_family == AF_INET ? m_p_rt_val->get_src_addr() : m_p_rt_val->get_cfg_src_addr());
        return !out_ip.is_anyaddr();
    }

    return false;
}

bool dst_entry::update_net_dev_val()
{
    bool ret_val = false;

    net_device_val *new_nd_val = m_p_net_dev_val;
    if (!m_so_bindtodevice_ip.is_anyaddr() && g_p_net_device_table_mgr) {
        new_nd_val =
            g_p_net_device_table_mgr->get_net_device_val(ip_addr(m_so_bindtodevice_ip, m_family));
        // TODO should we register to g_p_net_device_table_mgr  with m_p_net_dev_entry?
        // what should we do with an old one?
        dst_logdbg("getting net_dev_val by bindtodevice ip");
    } else if (m_p_rt_entry) {
        new_nd_val = m_p_rt_entry->get_net_dev_val();
    }

    if (m_p_net_dev_val != new_nd_val) {
        dst_logdbg("updating net_device, new-if_name: %s",
                   new_nd_val ? new_nd_val->get_ifname() : "N/A");

        if (m_p_neigh_entry) {
            ip_address dst_addr = m_dst_ip;
            if (m_p_rt_val && !m_p_rt_val->get_gw_addr().is_anyaddr() &&
                !dst_addr.is_mc(m_family)) {
                dst_addr = m_p_rt_val->get_gw_addr();
            }
            g_p_neigh_table_mgr->unregister_observer(
                neigh_key(ip_addr(dst_addr, m_family), m_p_net_dev_val), this);
            m_p_neigh_entry = NULL;
        }

        // Change the net_device, clean old resources...
        release_ring();

        // Save the new net_device
        m_p_net_dev_val = new_nd_val;

        if (m_p_net_dev_val) {
            // more resource clean and alloc...
            ret_val = alloc_transport_dep_res();
        } else {
            dst_logdbg("Netdev is not offloaded fallback to OS");
        }
    } else {
        if (m_p_net_dev_val) {
            // Only if we already had a valid net_device_val which did not change
            dst_logdbg("no change in net_device");
            ret_val = true;
        } else {
            dst_logdbg("Netdev is not offloaded fallback to OS");
        }
    }

    return ret_val;
}

bool dst_entry::update_rt_val()
{
    bool ret_val = true;
    route_val *p_rt_val = NULL;

    if (m_p_rt_entry && m_p_rt_entry->get_val(p_rt_val)) {
        if (m_p_rt_val == p_rt_val) {
            dst_logdbg("no change in route_val");
        } else {
            dst_logdbg("updating route val");
            m_p_rt_val = p_rt_val;
        }
    } else {
        dst_logdbg("Route entry is not valid");
        ret_val = false;
    }

    return ret_val;
}

bool dst_entry::resolve_net_dev(bool is_connect)
{
    bool ret_val = false;

    cache_entry_subject<route_rule_table_key, route_val *> *p_ces = NULL;

    if (m_dst_ip.is_anyaddr()) {
        dst_logdbg(PRODUCT_NAME " does not offload zero net IP address");
        return ret_val;
    }

    if (m_dst_ip.is_loopback_class(get_sa_family())) {
        dst_logdbg(PRODUCT_NAME " does not offload local loopback IP address");
        return ret_val;
    }

    // When XLIO will support routing with OIF, we need to check changing in outgoing interface
    // Source address changes is not checked since multiple bind is not allowed on the same socket
    if (!m_p_rt_entry) {
        m_route_src_ip = m_bound_ip;
        route_rule_table_key rtk(m_dst_ip, m_route_src_ip, m_family, m_tos);
        dst_logfunc("Fetching rt_entry %s", m_route_src_ip.to_str(m_family).c_str());
        if (g_p_route_table_mgr->register_observer(rtk, this, &p_ces)) {
            // In case this is the first time we trying to resolve route entry,
            // means that register_observer was run
            m_p_rt_entry = dynamic_cast<route_entry *>(p_ces);

            // Routing entry src-addr is used for src-addr selection algorithm and not
            // as a key for matching routing rules. Moreover, this can be a forcefully
            // set src addr by XLIO. We keep this logic for IPv4 only for backward compliancy.
            if (m_family == AF_INET && is_connect && m_route_src_ip.is_anyaddr()) {
                dst_logfunc("Checking rt_entry src addr");
                route_val *p_rt_val = NULL;
                if (m_p_rt_entry && m_p_rt_entry->get_val(p_rt_val) &&
                    !p_rt_val->get_src_addr().is_anyaddr()) {
                    g_p_route_table_mgr->unregister_observer(rtk, this);
                    m_route_src_ip = p_rt_val->get_src_addr();

                    dst_logfunc("Chaning m_route_src_ip to %s",
                                m_route_src_ip.to_str(m_family).c_str());

                    route_rule_table_key new_rtk(m_dst_ip, m_route_src_ip, m_family, m_tos);
                    if (g_p_route_table_mgr->register_observer(new_rtk, this, &p_ces)) {
                        m_p_rt_entry = dynamic_cast<route_entry *>(p_ces);
                    } else {
                        dst_logdbg("Error in route resolving logic");
                        return ret_val;
                    }
                }
            }
        } else {
            dst_logdbg("Error in registering route entry");
            return ret_val;
        }
    }

    if (update_rt_val()) {
        ret_val = update_net_dev_val();
    }
    return ret_val;
}

bool dst_entry::resolve_neigh()
{
    dst_logdbg("");
    bool ret_val = false;
    ip_address dst_addr = m_dst_ip;

    if (m_p_rt_val && !m_p_rt_val->get_gw_addr().is_anyaddr() && !dst_addr.is_mc(m_family)) {
        dst_addr = m_p_rt_val->get_gw_addr();
    }
    cache_entry_subject<neigh_key, neigh_val *> *p_ces = NULL;
    if (m_p_neigh_entry ||
        g_p_neigh_table_mgr->register_observer(
            neigh_key(ip_addr(dst_addr, m_family), m_p_net_dev_val), this, &p_ces)) {
        if (m_p_neigh_entry == NULL) {
            m_p_neigh_entry = dynamic_cast<neigh_entry *>(p_ces);
        }
        if (m_p_neigh_entry) {
            if (m_p_neigh_entry->get_peer_info(m_p_neigh_val)) {
                dst_logdbg("neigh is valid");
                ret_val = true;
            } else {
                dst_logdbg("neigh is not valid");
            }
        }
    }
    return ret_val;
}

bool dst_entry::resolve_ring()
{
    bool ret_val = false;

    if (m_p_net_dev_val) {
        if (!m_p_ring) {
            dst_logdbg("getting a ring");
            m_p_ring =
                m_p_net_dev_val->reserve_ring(m_ring_alloc_logic.create_new_key(m_pkt_src_ip));
        }
        if (m_p_ring) {
            if (m_sge) {
                delete[] m_sge;
                m_sge = NULL;
            }
            m_sge = new (std::nothrow) struct ibv_sge[m_p_ring->get_max_send_sge()];
            if (!m_sge) {
                dst_logpanic("%s Failed to allocate send SGE", to_str().c_str());
            }
            m_max_inline = m_p_ring->get_max_inline_data();
            m_max_inline = std::min<uint32_t>(
                m_max_inline, get_route_mtu() + (uint32_t)m_header->m_transport_header_len);
            ret_val = true;
        }
    }
    return ret_val;
}

bool dst_entry::release_ring()
{
    bool ret_val = false;
    if (m_p_net_dev_val) {
        if (m_p_ring) {
            if (m_p_tx_mem_buf_desc_list) {
                m_p_ring->mem_buf_tx_release(m_p_tx_mem_buf_desc_list, true);
                m_p_tx_mem_buf_desc_list = NULL;
            }
            if (m_p_zc_mem_buf_desc_list) {
                m_p_ring->mem_buf_tx_release(m_p_zc_mem_buf_desc_list, true);
                m_p_zc_mem_buf_desc_list = NULL;
            }
            dst_logdbg("releasing a ring");
            m_p_net_dev_val->release_ring(m_ring_alloc_logic.get_key());
            m_p_ring = NULL;
        }
        ret_val = true;
    }
    return ret_val;
}

void dst_entry::notify_cb()
{
    dst_logdbg("");
    set_state(false);
}

void dst_entry::configure_ip_header(header *h, uint16_t packet_id)
{
    h->configure_ip_header(get_protocol_type(), m_pkt_src_ip, m_dst_ip, *this, packet_id);
}

bool dst_entry::conf_l2_hdr_and_snd_wqe_eth()
{
    bool ret_val = false;

    // Maybe we after invalidation so we free the wqe_handler since we are going to build it from
    // scratch
    if (m_p_send_wqe_handler) {
        delete m_p_send_wqe_handler;
        m_p_send_wqe_handler = NULL;
    }

    m_p_send_wqe_handler = new wqe_send_handler();
    if (!m_p_send_wqe_handler) {
        dst_logpanic("%s Failed to allocate send WQE handler", to_str().c_str());
    }
    m_p_send_wqe_handler->init_inline_wqe(m_inline_send_wqe, get_sge_lst_4_inline_send(),
                                          get_inline_sge_num());
    m_p_send_wqe_handler->init_not_inline_wqe(m_not_inline_send_wqe,
                                              get_sge_lst_4_not_inline_send(), 1);
    m_p_send_wqe_handler->init_wqe(m_fragmented_send_wqe, get_sge_lst_4_not_inline_send(), 1);

    net_device_val_eth *netdevice_eth = dynamic_cast<net_device_val_eth *>(m_p_net_dev_val);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (netdevice_eth) {
        BULLSEYE_EXCLUDE_BLOCK_END
        const L2_address *src = m_p_net_dev_val->get_l2_address();
        const L2_address *dst = m_p_neigh_val->get_l2_address();

        BULLSEYE_EXCLUDE_BLOCK_START
        if (src && dst) {
            BULLSEYE_EXCLUDE_BLOCK_END
            if (netdevice_eth->get_vlan()) { // vlan interface
                uint32_t prio = get_priority_by_tc_class(m_pcp);
                uint16_t vlan_tci = (prio << NET_ETH_VLAN_PCP_OFFSET) | netdevice_eth->get_vlan();
                m_header->configure_vlan_eth_headers(
                    *src, *dst, vlan_tci, (get_sa_family() == AF_INET6) ? ETH_P_IPV6 : ETH_P_IP);
            } else {
                m_header->configure_eth_headers(
                    *src, *dst, (get_sa_family() == AF_INET6) ? ETH_P_IPV6 : ETH_P_IP);
            }
            init_sge();
            ret_val = true;
        } else {
            dst_logerr("Can't build proper L2 header, L2 address is not available");
        }
    } else {
        dst_logerr("Dynamic cast failed, can't build proper L2 header");
    }

    return ret_val;
}

bool dst_entry::conf_hdrs_and_snd_wqe()
{
    transport_type_t tranposrt = XLIO_TRANSPORT_ETH;
    bool ret_val = true;

    dst_logdbg("dst_entry %s configuring the header template", to_str().c_str());

    configure_ip_header(m_header);

    if (m_p_net_dev_val) {
        tranposrt = m_p_net_dev_val->get_transport_type();
    }

    switch (tranposrt) {
    case XLIO_TRANSPORT_ETH:
        ret_val = conf_l2_hdr_and_snd_wqe_eth();
        break;
    default:
        ret_val = false;
        break;
    }
    return ret_val;
}

// Implementation of pure virtual function of neigh_observer
transport_type_t dst_entry::get_obs_transport_type() const
{
    if (m_p_net_dev_val) {
        return (m_p_net_dev_val->get_transport_type());
    }
    return XLIO_TRANSPORT_UNKNOWN;
}

bool dst_entry::offloaded_according_to_rules()
{
    bool ret_val = true;
    transport_t target_transport;

    sock_addr to(get_sa_family(), &m_dst_ip, m_dst_port);
    target_transport = get_transport(to);

    if (target_transport == TRANS_OS) {
        ret_val = false;
    }
    return ret_val;
}

bool dst_entry::prepare_to_send(struct xlio_rate_limit_t &rate_limit, bool skip_rules,
                                bool is_connect)
{
    bool resolved = false;
    m_slow_path_lock.lock();
    if (!m_b_is_initialized) {
        if ((!skip_rules) && (!offloaded_according_to_rules())) {
            dst_logdbg("dst_entry in BLACK LIST!");
            m_b_is_offloaded = false;
            m_b_force_os = true;
        }
        m_b_is_initialized = true;
    }
    dst_logdbg("%s", to_str().c_str());
    if (!m_b_force_os && !is_valid()) {
        bool b_is_offloaded = false;
        set_state(true);
        if (resolve_net_dev(is_connect)) {
            set_src_addr();
            // overwrite mtu from route if exists
            m_max_udp_payload_size =
                get_route_mtu() - ((get_sa_family() == AF_INET) ? IP_HLEN : IPV6_HLEN);
            m_max_ip_payload_size = m_max_udp_payload_size & ~0x7;
            if (resolve_ring()) {
                b_is_offloaded = true;
                modify_ratelimit(rate_limit);
                if (resolve_neigh()) {
                    if (get_obs_transport_type() == XLIO_TRANSPORT_ETH) {
                        dst_logdbg("local mac: %s peer mac: %s",
                                   m_p_net_dev_val->get_l2_address()->to_str().c_str(),
                                   m_p_neigh_val->get_l2_address()->to_str().c_str());
                    } else {
                        dst_logdbg("peer L2 address: %s",
                                   m_p_neigh_val->get_l2_address()->to_str().c_str());
                    }
                    configure_headers();
                    m_id = m_p_ring->generate_id(m_p_net_dev_val->get_l2_address()->get_address(),
                                                 m_p_neigh_val->get_l2_address()->get_address(),
                                                 /* if vlan, use vlan proto */
                                                 ((ethhdr *)(m_header->m_actual_hdr_addr))->h_proto,
                                                 htons(ETH_P_IP), m_pkt_src_ip, m_dst_ip,
                                                 m_src_port, m_dst_port);
                    if (m_p_tx_mem_buf_desc_list) {
                        m_p_ring->mem_buf_tx_release(m_p_tx_mem_buf_desc_list, true);
                        m_p_tx_mem_buf_desc_list = NULL;
                    }
                    if (m_p_zc_mem_buf_desc_list) {
                        m_p_ring->mem_buf_tx_release(m_p_zc_mem_buf_desc_list, true);
                        m_p_zc_mem_buf_desc_list = NULL;
                    }
                    resolved = true;
                }
            }
        }
        m_b_is_offloaded = b_is_offloaded;
        if (m_b_is_offloaded) {
            dst_logdbg("dst_entry is offloaded!");
        } else {
            dst_logdbg("dst_entry is NOT offloaded!");
        }
        if (!resolved) {
            set_state(false);
        }
    }
    m_slow_path_lock.unlock();

    return m_b_is_offloaded;
}

bool dst_entry::try_migrate_ring(lock_base &socket_lock)
{
    bool ret = false;
    if (m_ring_alloc_logic.is_logic_support_migration()) {
        if (!m_tx_migration_lock.trylock()) {
            if (m_ring_alloc_logic.should_migrate_ring()) {
                resource_allocation_key old_key(*m_ring_alloc_logic.get_key());
                do_ring_migration(socket_lock, old_key);
                ret = true;
            }
            m_tx_migration_lock.unlock();
        }
    }
    return ret;
}

int dst_entry::get_route_mtu()
{
    if (m_p_rt_val && m_p_rt_val->get_mtu() > 0) {
        return m_p_rt_val->get_mtu();
    }
    return m_p_net_dev_val->get_mtu();
}

void dst_entry::do_ring_migration(lock_base &socket_lock, resource_allocation_key &old_key)
{
    m_slow_path_lock.lock();

    if (!m_p_net_dev_val || !m_p_ring) {
        m_slow_path_lock.unlock();
        return;
    }

    uint64_t new_calc_id = m_ring_alloc_logic.calc_res_key_by_logic();
    resource_allocation_key *new_key = m_ring_alloc_logic.get_key();
    // Check again if migration is needed before migration
    if (old_key.get_user_id_key() == new_calc_id &&
        old_key.get_ring_alloc_logic() == new_key->get_ring_alloc_logic()) {
        m_slow_path_lock.unlock();
        return;
    }
    // Update key to new ID
    new_key->set_user_id_key(new_calc_id);
    m_slow_path_lock.unlock();
    socket_lock.unlock();

    ring *new_ring = m_p_net_dev_val->reserve_ring(new_key);
    if (!new_ring) {
        socket_lock.lock();
        return;
    }
    if (new_ring == m_p_ring) {
        if (m_p_net_dev_val->release_ring(&old_key) < 0) {
            dst_logerr("Failed to release ring for allocation key %s", old_key.to_str().c_str());
        }
        socket_lock.lock();
        return;
    }

    dst_logdbg("migrating from key=%s and ring=%p to key=%s and ring=%p", old_key.to_str().c_str(),
               m_p_ring, new_key->to_str().c_str(), new_ring);

    socket_lock.lock();
    /* coverity[double_lock] */
    m_slow_path_lock.lock();

    set_state(false);

    ring *old_ring = m_p_ring;
    m_p_ring = new_ring;
    if (m_sge) {
        delete[] m_sge;
        m_sge = NULL;
    }
    m_sge = new (std::nothrow) struct ibv_sge[m_p_ring->get_max_send_sge()];
    if (!m_sge) {
        dst_logpanic("%s Failed to allocate send SGE", to_str().c_str());
    }
    m_max_inline = m_p_ring->get_max_inline_data();
    m_max_inline = std::min<uint32_t>(m_max_inline,
                                      get_route_mtu() + (uint32_t)m_header->m_transport_header_len);

    mem_buf_desc_t *tmp_list = m_p_tx_mem_buf_desc_list;
    m_p_tx_mem_buf_desc_list = NULL;
    mem_buf_desc_t *tmp_list_zc = m_p_zc_mem_buf_desc_list;
    m_p_zc_mem_buf_desc_list = NULL;

    m_slow_path_lock.unlock();
    socket_lock.unlock();

    if (tmp_list) {
        old_ring->mem_buf_tx_release(tmp_list, true);
    }
    if (tmp_list_zc) {
        old_ring->mem_buf_tx_release(tmp_list_zc, true);
    }

    m_p_net_dev_val->release_ring(&old_key);

    socket_lock.lock();
}

void dst_entry::set_bound_addr(const ip_address &addr)
{
    dst_logdbg("");
    m_bound_ip = addr;
    set_state(false);
}

void dst_entry::set_so_bindtodevice_addr(const ip_address &addr)
{
    dst_logdbg("");
    m_so_bindtodevice_ip = addr;
    set_state(false);
}

const ip_address &dst_entry::get_dst_addr()
{
    return m_dst_ip;
}

uint16_t dst_entry::get_dst_port()
{
    return m_dst_port;
}

ssize_t dst_entry::pass_buff_to_neigh(const iovec *p_iov, size_t sz_iov, uint32_t packet_id)
{
    ssize_t ret_val = 0;

    dst_logdbg("");

    // For IPv4 - packet_id will be taken from header
    // For IPv6 - packet_id will be taken from neigh_send_info
    configure_ip_header(m_header_neigh, (uint16_t)(packet_id & 0xffff));

    if (m_p_neigh_entry) {
        neigh_send_info n_send_info(const_cast<iovec *>(p_iov), sz_iov, m_header_neigh,
                                    get_protocol_type(), get_route_mtu(), m_tos, packet_id);
        ret_val = m_p_neigh_entry->send(n_send_info);
    }

    return ret_val;
}

bool dst_entry::alloc_transport_dep_res()
{
    return alloc_neigh_val(get_obs_transport_type());
}

bool dst_entry::alloc_neigh_val(transport_type_t tranport)
{
    bool ret_val = false;

    if (m_p_neigh_val) {
        delete m_p_neigh_val;
        m_p_neigh_val = NULL;
    }

    switch (tranport) {
    case XLIO_TRANSPORT_ETH:
    default:
        m_p_neigh_val = new neigh_eth_val;
        break;
    }
    if (m_p_neigh_val) {
        ret_val = true;
    }
    return ret_val;
}

void dst_entry::return_buffers_pool()
{
    int count;

    if (m_p_tx_mem_buf_desc_list == NULL && m_p_zc_mem_buf_desc_list == NULL) {
        return;
    }

    if (m_b_tx_mem_buf_desc_list_pending && m_p_ring) {
        if (m_p_tx_mem_buf_desc_list != NULL) {
            count = m_p_ring->mem_buf_tx_release(m_p_tx_mem_buf_desc_list, true, true);
            if (count) {
                m_p_tx_mem_buf_desc_list = NULL;
            }
        }
        if (m_p_zc_mem_buf_desc_list != NULL) {
            count = m_p_ring->mem_buf_tx_release(m_p_zc_mem_buf_desc_list, true, true);
            if (count) {
                m_p_zc_mem_buf_desc_list = NULL;
            }
        }
    }
    set_tx_buff_list_pending(m_p_tx_mem_buf_desc_list != NULL || m_p_zc_mem_buf_desc_list != NULL);
}

int dst_entry::modify_ratelimit(struct xlio_rate_limit_t &rate_limit)
{
    if (m_p_ring) {
        return m_p_ring->modify_ratelimit(rate_limit);
    }
    return 0;
}

int dst_entry::get_priority_by_tc_class(uint32_t pcp)
{
    // translate class to priority
    if (m_p_net_dev_val) {
        return m_p_net_dev_val->get_priority_by_tc_class(pcp);
    }
    return DEFAULT_ENGRESS_MAP_PRIO;
}

bool dst_entry::update_ring_alloc_logic(int fd, lock_base &socket_lock,
                                        resource_allocation_key &ring_alloc_logic)
{
    resource_allocation_key old_key(*m_ring_alloc_logic.get_key());

    m_ring_alloc_logic = ring_allocation_logic_tx(fd, ring_alloc_logic, this);

    if (*m_ring_alloc_logic.get_key() != old_key) {
        std::lock_guard<decltype(m_tx_migration_lock)> locker(m_tx_migration_lock);
        do_ring_migration(socket_lock, old_key);
        return true;
    }

    return false;
}
