/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef RING_SIMPLE_H
#define RING_SIMPLE_H

#include "ring.h"
#include <memory>
#include "dev/net_device_table_mgr.h"
#include "util/sock_addr.h"

#include <mutex>
#include <unordered_map>

#include "dev/gro_mgr.h"
#include "dev/hw_queue_tx.h"
#include "dev/hw_queue_rx.h"

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
    rfs_rule *rfs_rule_holder = nullptr;
};

typedef std::unordered_map<sock_addr, struct counter_and_ibv_flows> rule_filter_map_t;

class ring_simple;

template <typename KEY4T, typename KEY2T, typename HDR> class steering_handler {
public:
    steering_handler(ring_simple &ring)
        : m_ring(ring)
    {
    }

    bool attach_flow(flow_tuple &flow_spec_5t, sockinfo *sink, bool force_5t = false);
    bool detach_flow(flow_tuple &flow_spec_5t, sockinfo *sink);

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

    ring_simple &m_ring;
};

struct cq_moderation_info {
    uint32_t period;
    uint32_t count;
    uint64_t packets;
    uint64_t prev_packets;
    uint32_t missed_rounds;
};

/**
 * @class ring simple
 *
 * Object to manages the QP and CQ operation
 * This object is used for Rx & Tx at the same time
 *
 */
class ring_simple : public ring {
public:
    ring_simple(int if_index, ring *parent, bool use_locks);
    ~ring_simple() override;

    void print_val() override;
    void restart() override;
    bool is_member(ring *rng) override;
    bool is_active_member(ring *rng, ring_user_id_t id) override;
    ring_user_id_t generate_id(const address_t src_mac, const address_t dst_mac, uint16_t eth_proto,
                               uint16_t encap_proto, const ip_address &src_ip,
                               const ip_address &dst_ip, uint16_t src_port,
                               uint16_t dst_port) override;
    void inc_tx_retransmissions_stats(ring_user_id_t id) override;

    int request_notification(cq_type_t cq_type, uint64_t poll_sn) override;
    bool poll_and_process_element_rx(uint64_t *p_cq_poll_sn,
                                     void *pv_fd_ready_array = nullptr) override;
    int poll_and_process_element_tx(uint64_t *p_cq_poll_sn) override;
    void adapt_cq_moderation() override;
    bool reclaim_recv_buffers(descq_t *rx_reuse) override;
    bool reclaim_recv_buffers(mem_buf_desc_t *rx_reuse_lst) override;
    bool reclaim_recv_buffers_no_lock(mem_buf_desc_t *rx_reuse_lst) override; // No locks
    int reclaim_recv_single_buffer(mem_buf_desc_t *rx_reuse); // No locks
    void mem_buf_rx_release(mem_buf_desc_t *p_mem_buf_desc) override;
    int drain_and_proccess() override;
    void wait_for_notification_and_process_element(uint64_t *p_cq_poll_sn,
                                                   void *pv_fd_ready_array = nullptr) override;
    void mem_buf_desc_return_to_owner_tx(mem_buf_desc_t *p_mem_buf_desc);
    void mem_buf_desc_return_to_owner_rx(mem_buf_desc_t *p_mem_buf_desc,
                                         void *pv_fd_ready_array = nullptr);
    inline int send_buffer(xlio_ibv_send_wr *p_send_wqe, xlio_wr_tx_packet_attr attr,
                           xlio_tis *tis);
    bool is_up();
    void start_active_queue_tx();
    void start_active_queue_rx();
    void stop_active_queue_tx();
    void stop_active_queue_rx();
    mem_buf_desc_t *mem_buf_tx_get(ring_user_id_t id, bool b_block, pbuf_type type,
                                   int n_num_mem_bufs = 1) override;
    int mem_buf_tx_release(mem_buf_desc_t *p_mem_buf_desc_list, bool b_accounting,
                           bool trylock = false) override;
    void send_ring_buffer(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe,
                          xlio_wr_tx_packet_attr attr) override;
    int send_lwip_buffer(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe,
                         xlio_wr_tx_packet_attr attr, xlio_tis *tis) override;
    void mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t *p_mem_buf_desc) override;
    void mem_buf_desc_return_single_multi_ref(mem_buf_desc_t *p_mem_buf_desc,
                                              unsigned ref) override;
    void mem_buf_desc_return_single_locked(mem_buf_desc_t *buff);
    void return_tx_pool_to_global_pool();
    bool get_hw_dummy_send_support(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe) override;
    uint64_t get_rx_cq_out_of_buffer_drop() override;
    void convert_hw_time_to_system_time(uint64_t hwtime, struct timespec *systime)
    {
        m_p_ib_ctx->convert_hw_time_to_system_time(hwtime, systime);
    }
    int modify_ratelimit(struct xlio_rate_limit_t &rate_limit) override;
    uint32_t get_tx_user_lkey(void *addr, size_t length) override;
    uint32_t get_max_inline_data() override;
    ib_ctx_handler *get_ctx(ring_user_id_t id) override
    {
        NOT_IN_USE(id);
        return m_p_ib_ctx;
    }
    uint32_t get_max_send_sge(void) override;
    uint32_t get_max_payload_sz(void) override;
    uint16_t get_max_header_sz(void) override;
    uint32_t get_tx_lkey(ring_user_id_t id) override
    {
        NOT_IN_USE(id);
        return m_tx_lkey;
    }
    int *get_rx_channel_fds(size_t &length) const override
    {
        length = 1;
        return m_p_n_rx_channel_fds;
    }
    bool is_tso(void) override;
    bool rx_process_buffer(mem_buf_desc_t *p_rx_wc_buf_desc, void *pv_fd_ready_array);
    bool attach_flow(flow_tuple &flow_spec_5t, sockinfo *sink, bool force_5t = false) override;
    bool detach_flow(flow_tuple &flow_spec_5t, sockinfo *sink) override;

    transport_type_t get_transport_type() const { return m_transport_type; }
    struct ibv_comp_channel *get_tx_comp_event_channel() { return m_p_tx_comp_event_channel; }
    void modify_cq_moderation(uint32_t period, uint32_t count);

    void update_tso_stats(uint64_t bytes)
    {
        ++m_p_ring_stat->n_tx_tso_pkt_count;
        m_p_ring_stat->n_tx_tso_byte_count += bytes;
    }

#ifdef DEFINED_UTLS
    bool tls_tx_supported(void) override { return m_tls.tls_tx; }
    bool tls_rx_supported(void) override { return m_tls.tls_rx; }
    bool tls_sync_dek_supported() { return m_tls.tls_synchronize_dek; }
    /* Call this method in an RX ring. */
    rfs_rule *tls_rx_create_rule(const flow_tuple &flow_spec_5t, xlio_tir *tir);
    xlio_tis *tls_context_setup_tx(const xlio_tls_info *info) override
    {
        std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);

        xlio_tis *tis = m_hqtx->tls_context_setup_tx(info);
        if (likely(tis != NULL)) {
            ++m_p_ring_stat->n_tx_tls_contexts;
        }

        /* Do polling to speedup handling of the completion. */
        uint64_t dummy_poll_sn = 0;
        m_p_cq_mgr_tx->poll_and_process_element_tx(&dummy_poll_sn);

        return tis;
    }
    xlio_tir *tls_create_tir(bool cached) override
    {
        /*
         * This method can be called for either RX or TX ring.
         * Locking is required for TX ring with cached=true.
         */
        std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
        return m_hqrx->tls_create_tir(cached);
    }
    int tls_context_setup_rx(xlio_tir *tir, const xlio_tls_info *info, uint32_t next_record_tcp_sn,
                             xlio_comp_cb_t callback, void *callback_arg) override
    {
        /* Protect with TX lock since we post WQEs to the send queue. */
        std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);

        int rc =
            m_hqtx->tls_context_setup_rx(tir, info, next_record_tcp_sn, callback, callback_arg);
        if (likely(rc == 0)) {
            ++m_p_ring_stat->n_rx_tls_contexts;
        }

        /* Do polling to speedup handling of the completion. */
        uint64_t dummy_poll_sn = 0;
        m_p_cq_mgr_tx->poll_and_process_element_tx(&dummy_poll_sn);

        return rc;
    }
    void tls_context_resync_tx(const xlio_tls_info *info, xlio_tis *tis, bool skip_static) override
    {
        std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
        m_hqtx->tls_context_resync_tx(info, tis, skip_static);

        uint64_t dummy_poll_sn = 0;
        m_p_cq_mgr_tx->poll_and_process_element_tx(&dummy_poll_sn);
    }
    void tls_resync_rx(xlio_tir *tir, const xlio_tls_info *info, uint32_t hw_resync_tcp_sn) override
    {
        std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
        m_hqtx->tls_resync_rx(tir, info, hw_resync_tcp_sn);
    }
    void tls_get_progress_params_rx(xlio_tir *tir, void *buf, uint32_t lkey) override
    {
        std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
        if (lkey == LKEY_TX_DEFAULT) {
            lkey = m_tx_lkey;
        }
        m_hqtx->tls_get_progress_params_rx(tir, buf, lkey);
        /* Do polling to speedup handling of the completion. */
        uint64_t dummy_poll_sn = 0;
        m_p_cq_mgr_tx->poll_and_process_element_tx(&dummy_poll_sn);
    }
    void tls_release_tis(xlio_tis *tis) override
    {
        std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
        m_hqtx->tls_release_tis(tis);
    }
    void tls_release_tir(xlio_tir *tir) override
    {
        /* TIR objects are protected with TX lock */
        std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
        m_hqrx->tls_release_tir(tir);
    }
    void tls_tx_post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey,
                              bool first) override
    {
        std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
        if (lkey == LKEY_TX_DEFAULT) {
            lkey = m_tx_lkey;
        }
        m_hqtx->tls_tx_post_dump_wqe(tis, addr, len, lkey, first);
    }
#endif /* DEFINED_UTLS */

    std::unique_ptr<xlio_tis> create_tis(uint32_t flags) const override
    {
        std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
        return m_hqtx->create_tis(flags);
    }

    void post_nop_fence(void) override
    {
        std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
        m_hqtx->post_nop_fence();
    }

    void post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey,
                       bool is_first) override
    {
        std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
        m_hqtx->post_dump_wqe(tis, addr, len, lkey, is_first);
    }

    void reset_inflight_zc_buffers_ctx(ring_user_id_t id, void *ctx) override
    {
        std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
        NOT_IN_USE(id);
        m_hqtx->reset_inflight_zc_buffers_ctx(ctx);
    }

    bool credits_get(unsigned credits) override
    {
        std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
        return m_hqtx->credits_get(credits);
    }

    void credits_return(unsigned credits) override
    {
        std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
        m_hqtx->credits_return(credits);
    }

    friend class cq_mgr_rx;
    friend class cq_mgr_rx_regrq;
    friend class cq_mgr_rx_strq;
    friend class hw_queue_tx;
    friend class hw_queue_rx;
    friend class rfs;
    friend class rfs_uc;
    friend class rfs_uc_tcp_gro;
    friend class rfs_mc;
    friend class ring_bond;

private:
    bool request_more_tx_buffers(pbuf_type type, uint32_t count, uint32_t lkey);
    void flow_del_all_rfs();
    void create_resources();
    virtual void init_tx_buffers(uint32_t count);
    void inc_cq_moderation_stats();
    void set_tx_num_wr(uint32_t num_wr) { m_tx_num_wr = num_wr; }
    uint32_t get_tx_num_wr() { return m_tx_num_wr; }
    uint32_t get_mtu() { return m_mtu; }
    inline void send_status_handler(int ret, xlio_ibv_send_wr *p_send_wqe);
    inline mem_buf_desc_t *get_tx_buffers(pbuf_type type, uint32_t n_num_mem_bufs);
    inline int put_tx_buffer_helper(mem_buf_desc_t *buff);
    inline int put_tx_buffers(mem_buf_desc_t *buff_list);
    inline int put_tx_single_buffer(mem_buf_desc_t *buff);
    inline void return_to_global_pool();
    bool is_available_qp_wr(bool b_block, unsigned credits);
    void save_l2_address(const L2_address *p_l2_addr)
    {
        delete_l2_address();
        m_p_l2_addr = p_l2_addr->clone();
    };
    void delete_l2_address()
    {
        if (m_p_l2_addr) {
            delete m_p_l2_addr;
        }
        m_p_l2_addr = nullptr;
    };

    // Merged ring steering and flow management members
    steering_handler<flow_spec_4t_key_ipv4, flow_spec_2t_key_ipv4, iphdr> m_steering_ipv4;
    steering_handler<flow_spec_4t_key_ipv6, flow_spec_2t_key_ipv6, ip6_hdr> m_steering_ipv6;

    // For IB MC flow, the port is zeroed in the ibv_flow_spec when calling to ibv_flow_spec().
    // It means that for every MC group, even if we have sockets with different ports - only one
    // rule in the HW. So the hash map below keeps track of the number of sockets per rule so we
    // know when to call ibv_attach and ibv_detach
    rule_filter_map_t m_l2_mc_ip_attach_map;
    rule_filter_map_t m_tcp_dst_port_attach_map;
    rule_filter_map_t m_udp_uc_dst_port_attach_map;

    multilock m_lock_ring_rx;
    mutable multilock m_lock_ring_tx;

    descq_t m_tx_pool;
    descq_t m_zc_pool;
    transport_type_t m_transport_type; /* transport ETH/IB */
    std::unique_ptr<ring_stats_t> m_p_ring_stat;
    uint16_t m_vlan;
    bool m_flow_tag_enabled;
    bool m_active; /* State indicator */
    const bool m_b_sysvar_eth_mc_l2_only_rules;
    const bool m_b_sysvar_mc_force_flowtag;

    template <typename KEY4T, typename KEY2T, typename HDR> friend class steering_handler;

    ib_ctx_handler *m_p_ib_ctx;
    hw_queue_tx *m_hqtx = nullptr;
    hw_queue_rx *m_hqrx = nullptr;
    struct cq_moderation_info m_cq_moderation_info;
    cq_mgr_rx *m_p_cq_mgr_rx = nullptr;
    cq_mgr_tx *m_p_cq_mgr_tx = nullptr;
    std::unordered_map<void *, uint32_t> m_user_lkey_map;

    lock_mutex m_lock_ring_tx_buf_wait;
    uint32_t m_tx_num_bufs = 0U;
    uint32_t m_zc_num_bufs = 0U;
    uint32_t m_tx_num_wr = 0U;
    uint32_t m_missing_buf_ref_count = 0U;
    uint32_t m_tx_lkey = 0U; // this is the registered memory lkey for a given specific device for
                             // the buffer pool use
    gro_mgr m_gro_mgr;
    bool m_up_tx = false;
    bool m_up_rx = false;
    struct ibv_comp_channel *m_p_rx_comp_event_channel = nullptr;
    struct ibv_comp_channel *m_p_tx_comp_event_channel = nullptr;
    L2_address *m_p_l2_addr = nullptr;
    uint32_t m_mtu;

    struct {
        /* Maximum length of TCP payload for TSO */
        uint32_t max_payload_sz;

        /* Maximum length of header for TSO */
        uint16_t max_header_sz;
    } m_tso;
    struct {
        /* TLS TX offload is supported */
        bool tls_tx;
        /* TLS RX offload is supported */
        bool tls_rx;
        /* TLS DEK modify Crypto-Sync is supported */
        bool tls_synchronize_dek;
    } m_tls;
    struct {
        /* Indicates LRO support */
        bool cap;

        /* Indicate LRO support for segments with PSH flag */
        bool psh_flag;

        /* Indicate LRO support for segments with TCP timestamp option */
        bool time_stamp;

        /* The maximum message size mode
         * 0x0 - TCP header + TCP payload
         * 0x1 - L2 + L3 + TCP header + TCP payload
         */
        uint8_t max_msg_sz_mode;

        /* The minimal size of TCP segment required for coalescing */
        uint16_t min_mss_size;

        /* Array of supported LRO timer periods in microseconds. */
        uint8_t timer_supported_periods[4];

        /* Maximum length of TCP payload for LRO
         * It is calculated from max_msg_sz_mode and safe_mce_sys().rx_buf_size
         */
        uint32_t max_payload_sz;
    } m_lro;

    uint8_t m_padding[16]; // Consume full cache line
};

#endif /* RING_SIMPLE_H */
