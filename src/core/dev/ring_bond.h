/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef RING_BOND_H
#define RING_BOND_H

#include "ring.h"

#include "dev/ring_tap.h"
#include "dev/net_device_table_mgr.h"

typedef std::vector<ring_slave *> ring_slave_vector_t;

struct flow_sink_t {
    flow_tuple flow;
    sockinfo *sink;
};

class ring_bond : public ring {

public:
    ring_bond(int if_index);
    virtual ~ring_bond();

    virtual void print_val();

    virtual int *get_rx_channel_fds(size_t &length) const
    {
        length = m_recv_rings.size();
        return m_p_n_rx_channel_fds;
    };
    virtual int request_notification(cq_type_t cq_type, uint64_t poll_sn);
    virtual bool poll_and_process_element_rx(uint64_t *p_cq_poll_sn,
                                             void *pv_fd_ready_array = nullptr);
    virtual int poll_and_process_element_tx(uint64_t *p_cq_poll_sn);
    virtual void adapt_cq_moderation();
    virtual bool reclaim_recv_buffers(descq_t *rx_reuse);
    virtual bool reclaim_recv_buffers(mem_buf_desc_t *rx_reuse_lst);
    virtual void mem_buf_rx_release(mem_buf_desc_t *p_mem_buf_desc);
    virtual int drain_and_proccess();
    virtual void wait_for_notification_and_process_element(uint64_t *p_cq_poll_sn,
                                                           void *pv_fd_ready_array = nullptr);
    virtual int get_num_resources() const { return m_bond_rings.size(); };
    virtual bool attach_flow(flow_tuple &flow_spec_5t, sockinfo *sink, bool force_5t = false);
    virtual bool detach_flow(flow_tuple &flow_spec_5t, sockinfo *sink);
    virtual void restart();
    virtual mem_buf_desc_t *mem_buf_tx_get(ring_user_id_t id, bool b_block, pbuf_type type,
                                           int n_num_mem_bufs = 1);
    virtual int mem_buf_tx_release(mem_buf_desc_t *p_mem_buf_desc_list, bool b_accounting,
                                   bool trylock = false);
    virtual void inc_tx_retransmissions_stats(ring_user_id_t id);
    virtual void send_ring_buffer(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe,
                                  xlio_wr_tx_packet_attr attr);
    virtual int send_lwip_buffer(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe,
                                 xlio_wr_tx_packet_attr attr, xlio_tis *tis);
    virtual void mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t *p_mem_buf_desc);
    virtual void mem_buf_desc_return_single_multi_ref(mem_buf_desc_t *p_mem_buf_desc, unsigned ref);
    virtual bool is_member(ring_slave *rng);
    virtual bool is_active_member(ring_slave *rng, ring_user_id_t id);
    virtual ring_user_id_t generate_id(const address_t src_mac, const address_t dst_mac,
                                       uint16_t eth_proto, uint16_t encap_proto,
                                       const ip_address &src_ip, const ip_address &dst_ip,
                                       uint16_t src_port, uint16_t dst_port);
    virtual bool get_hw_dummy_send_support(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe);
    virtual int modify_ratelimit(struct xlio_rate_limit_t &rate_limit);
    /* XXX TODO We have to support ring_bond for zerocopy. */
    virtual uint32_t get_tx_user_lkey(void *addr, size_t length)
    {
        NOT_IN_USE(addr);
        NOT_IN_USE(length);
        return LKEY_ERROR;
    }
    virtual uint32_t get_max_inline_data();
    ib_ctx_handler *get_ctx(ring_user_id_t id) { return m_xmit_rings[id]->get_ctx(0); }
    virtual uint32_t get_max_send_sge(void);
    virtual uint32_t get_max_payload_sz(void);
    virtual uint16_t get_max_header_sz(void);
    virtual uint32_t get_tx_lkey(ring_user_id_t id) { return m_xmit_rings[id]->get_tx_lkey(id); }
    virtual bool is_tso(void);
    int socketxtreme_poll(struct xlio_socketxtreme_completion_t *xlio_completions,
                          unsigned int ncompletions, int flags);
    virtual void slave_create(int if_index) = 0;
    virtual void slave_destroy(int if_index);

    void reset_inflight_zc_buffers_ctx(ring_user_id_t id, void *ctx)
    {
        m_xmit_rings[id]->reset_inflight_zc_buffers_ctx(id, ctx);
    }

protected:
    void update_cap(ring_slave *slave = nullptr);
    void update_rx_channel_fds();

    /* Fill m_xmit_rings array */
    void popup_xmit_rings();

    /* Fill m_recv_rings array */
    void popup_recv_rings();

private:
    void devide_buffers_helper(descq_t *rx_reuse, descq_t *buffer_per_ring);
    int devide_buffers_helper(mem_buf_desc_t *p_mem_buf_desc_list,
                              mem_buf_desc_t **buffer_per_ring);

protected:
    /* Array of all aggregated rings
     * Every ring can be Active or Backup
     */
    ring_slave_vector_t m_bond_rings;

    /* Array of rings used for data transmission
     * Every element in this array points to ring that actually used to transfer data
     * - active-backup or #1:
     *   Sets an active-backup policy for fault tolerance. Transmissions are received and sent
     *   out through the first available bonded slave interface.
     *   Another bonded slave interface is only used if the active bonded slave interface fails.
     * - 802.3ad or #4:
     *   Sets an IEEE 802.3ad dynamic link aggregation policy to load balance the traffic
     *   in addition to providing failover.
     */
    ring_slave_vector_t m_xmit_rings;

    /* Array of rings used for income data processing
     * - For RoCE LAG rings the only single is used with lag_tx_port_affinity=1
     */
    ring_slave_vector_t m_recv_rings;

    std::vector<struct flow_sink_t> m_rx_flows;
    uint32_t m_max_inline_data;
    uint32_t m_max_send_sge;

private:
    net_device_val::bond_type m_type;
    net_device_val::bond_xmit_hash_policy m_xmit_hash_policy;
    lock_mutex_recursive m_lock_ring_rx;
    lock_mutex_recursive m_lock_ring_tx;
};

class ring_bond_eth : public ring_bond {
public:
    ring_bond_eth(int if_index)
        : ring_bond(if_index)
    {
        net_device_val *p_ndev =
            g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());
        if (p_ndev) {
            const slave_data_vector_t &slaves = p_ndev->get_slave_array();
            update_cap();
            for (size_t i = 0; i < slaves.size(); i++) {
                slave_create(slaves[i]->if_index);
            }
        }
    }

protected:
    virtual void slave_create(int if_index);
};

class ring_bond_netvsc : public ring_bond {
public:
    ring_bond_netvsc(int if_index)
        : ring_bond(if_index)
    {
        net_device_val *p_ndev =
            g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());

        m_vf_ring = nullptr;
        m_tap_ring = nullptr;
        if (p_ndev) {
            const slave_data_vector_t &slaves = p_ndev->get_slave_array();
            update_cap();
            slave_create(p_ndev->get_if_idx());
            for (size_t i = 0; i < slaves.size(); i++) {
                slave_create(slaves[i]->if_index);
            }

            if (m_tap_ring && m_vf_ring) {
                ring_tap *p_ring_tap = dynamic_cast<ring_tap *>(m_tap_ring);
                if (p_ring_tap) {
                    p_ring_tap->set_vf_ring(m_vf_ring);
                }
            }
        }
    }

protected:
    virtual void slave_create(int if_index);

public:
    ring_slave *m_vf_ring;
    ring_slave *m_tap_ring;
};

#endif /* RING_BOND_H */
