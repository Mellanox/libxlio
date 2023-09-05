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

#ifndef DST_ENTRY_H
#define DST_ENTRY_H

#include <unistd.h>
#include <sys/socket.h>
#include "core/util/if.h"
#include <netinet/in.h>

#include "vlogger/vlogger.h"
#include "utils/lock_wrapper.h"
#include "core/sock/socket_fd_api.h"
#include "core/proto/route_entry.h"
#include "core/proto/route_val.h"
#include "core/proto/neighbour_table_mgr.h"
#include "core/dev/net_device_val.h"
#include "core/dev/net_device_table_mgr.h"
#include "core/dev/wqe_send_handler.h"
#include "core/dev/ring.h"
#include "core/dev/ring_allocation_logic.h"
#include "core/infra/sender.h"
#include "header.h"
#include "core/util/ip_address.h"

/* Forward declarations */
class xlio_tis;

struct socket_data {
    int fd;
    uint8_t ttl_hop_limit;
    uint8_t tos;
    uint32_t pcp;
};

struct xlio_send_attr {
    xlio_wr_tx_packet_attr flags;
    uint16_t mss;
    size_t length;
    xlio_tis *tis;
};

class dst_entry : public cache_observer, public tostr, public neigh_observer {

public:
    dst_entry(const sock_addr &dst, uint16_t src_port, socket_data &sock_data,
              resource_allocation_key &ring_alloc_logic);
    virtual ~dst_entry();

    virtual void notify_cb();

    virtual bool prepare_to_send(struct xlio_rate_limit_t &rate_limit, bool skip_rules = false,
                                 bool is_connect = false);
    virtual ssize_t fast_send(const iovec *p_iov, const ssize_t sz_iov, xlio_send_attr attr) = 0;
    virtual ssize_t slow_send(const iovec *p_iov, const ssize_t sz_iov, xlio_send_attr attr,
                              struct xlio_rate_limit_t &rate_limit, int flags = 0,
                              socket_fd_api *sock = 0, tx_call_t call_type = TX_UNDEF) = 0;

    bool try_migrate_ring(lock_base &socket_lock);

    bool is_offloaded() { return m_b_is_offloaded; }
    void set_bound_addr(const ip_address &addr);
    void set_so_bindtodevice_addr(const ip_address &addr);
    const ip_address &get_dst_addr();
    uint16_t get_dst_port();
    inline const ip_address &get_src_addr() const { return m_pkt_src_ip; }
    int modify_ratelimit(struct xlio_rate_limit_t &rate_limit);
    bool update_ring_alloc_logic(int fd, lock_base &socket_lock,
                                 resource_allocation_key &ring_alloc_logic);

    virtual transport_type_t get_obs_transport_type() const;

    void return_buffers_pool();
    int get_route_mtu();
    inline void set_ip_ttl_hop_limit(uint8_t ttl_hop_limit)
    {
        m_header->set_ip_ttl_hop_limit(ttl_hop_limit);
    }
    inline void set_ip_tos(uint8_t tos) { m_header->set_ip_tos(tos); }
    inline bool set_pcp(uint32_t pcp)
    {
        return m_header->set_vlan_pcp(get_priority_by_tc_class(pcp));
    }
    inline void set_src_sel_prefs(uint8_t sel_flags) { m_src_sel_prefs = sel_flags; }
    inline ring *get_ring() { return m_p_ring; }
    inline ib_ctx_handler *get_ctx() { return m_p_ring->get_ctx(m_id); }
    inline sa_family_t get_sa_family() { return m_family; }
    uint8_t get_tos() const { return m_tos; }
    uint8_t get_ttl_hop_limit() const { return m_ttl_hop_limit; }
    void set_external_vlan_tag(uint16_t vlan_tag) { m_external_vlan_tag = vlan_tag; }
    void reset_inflight_zc_buffers_ctx(void *ctx)
    {
        m_p_ring->reset_inflight_zc_buffers_ctx(m_id, ctx);
    }

    inline bool is_the_same_ifname(const std::string &ifname)
    {
        return ifname.compare(m_p_net_dev_val->get_ifname()) == 0;
    }

    inline bool is_the_same_ifname(const std::string &&ifname)
    {
        return is_the_same_ifname(ifname);
    }

protected:
    ip_address m_dst_ip;
    in_port_t m_dst_port;
    sa_family_t m_family;
    header *m_header;
    header *m_header_neigh;
    ip_address m_bound_ip;
    ip_address m_so_bindtodevice_ip;
    ip_address m_route_src_ip; // source IP used to register in route manager
    ip_address m_pkt_src_ip; // source IP address copied into IP header
    lock_mutex_recursive m_slow_path_lock;
    lock_mutex m_tx_migration_lock;
    xlio_ibv_send_wr m_inline_send_wqe;
    xlio_ibv_send_wr m_not_inline_send_wqe;
    xlio_ibv_send_wr m_fragmented_send_wqe;
    wqe_send_handler *m_p_send_wqe_handler;
    ibv_sge *m_sge;
    route_entry *m_p_rt_entry;
    route_val *m_p_rt_val;
    net_device_entry *m_p_net_dev_entry;
    net_device_val *m_p_net_dev_val;
    neigh_entry *m_p_neigh_entry;
    neigh_val *m_p_neigh_val;

    ring *m_p_ring;
    ring_allocation_logic_tx m_ring_alloc_logic;
    mem_buf_desc_t *m_p_tx_mem_buf_desc_list;
    mem_buf_desc_t *m_p_zc_mem_buf_desc_list;
    int m_b_tx_mem_buf_desc_list_pending;
    uint8_t m_ttl_hop_limit;

    uint8_t m_tos;
    uint8_t m_pcp;
    bool m_b_is_initialized;

    xlio_ibv_send_wr *m_p_send_wqe;
    uint32_t m_max_inline;
    ring_user_id_t m_id;
    uint16_t m_max_ip_payload_size;
    uint16_t m_max_udp_payload_size;
    uint16_t m_external_vlan_tag;
    uint16_t m_src_port;
    bool m_b_is_offloaded;
    bool m_b_force_os;
    uint8_t m_src_sel_prefs;

    virtual transport_t get_transport(const sock_addr &to) = 0;
    virtual uint8_t get_protocol_type() const = 0;
    virtual uint32_t get_inline_sge_num() = 0;
    virtual ibv_sge *get_sge_lst_4_inline_send() = 0;
    virtual ibv_sge *get_sge_lst_4_not_inline_send() = 0;

    virtual bool offloaded_according_to_rules();
    virtual void init_members();
    virtual bool resolve_net_dev(bool is_connect = false);
    virtual void set_src_addr();
    bool update_net_dev_val();
    bool update_rt_val();
    virtual bool resolve_neigh();
    virtual bool resolve_ring();
    virtual bool release_ring();
    virtual ssize_t pass_buff_to_neigh(const iovec *p_iov, size_t sz_iov, uint32_t packet_id = 0);
    virtual void configure_ip_header(header *h, uint16_t packet_id = 0);
    virtual void configure_headers() { conf_hdrs_and_snd_wqe(); };
    bool conf_hdrs_and_snd_wqe();
    void configure_eth_headers(header *header, const L2_address &src, const L2_address &dst,
                               uint16_t dev_vlan);
    virtual bool conf_l2_hdr_and_snd_wqe_eth();
    virtual void init_sge() {};
    bool alloc_transport_dep_res();
    bool alloc_neigh_val(transport_type_t tranport);
    bool get_routing_addr_sel_src(ip_address &out_ip) const;
    void do_ring_migration(lock_base &socket_lock, resource_allocation_key &old_key);
    inline void set_tx_buff_list_pending(bool is_pending = true)
    {
        m_b_tx_mem_buf_desc_list_pending = is_pending;
    }
    uint32_t get_priority_by_tc_class(uint32_t tc_clas);
    inline void send_ring_buffer(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe,
                                 xlio_wr_tx_packet_attr attr)
    {
        if (unlikely(is_set(attr, XLIO_TX_PACKET_DUMMY))) {
            if (m_p_ring->get_hw_dummy_send_support(id, p_send_wqe)) {
                xlio_ibv_wr_opcode last_opcode =
                    m_p_send_wqe_handler->set_opcode(*p_send_wqe, XLIO_IBV_WR_NOP);
                m_p_ring->send_ring_buffer(id, p_send_wqe, attr);
                m_p_send_wqe_handler->set_opcode(*p_send_wqe, last_opcode);
            } else {
                /* free the buffer if dummy send is not supported */
                mem_buf_desc_t *p_mem_buf_desc = (mem_buf_desc_t *)(p_send_wqe->wr_id);
                m_p_ring->mem_buf_tx_release(p_mem_buf_desc, true);
            }
        } else {
            m_p_ring->send_ring_buffer(id, p_send_wqe, attr);
        }
    }
};

#endif /* DST_ENTRY_H */
