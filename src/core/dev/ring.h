/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef RING_H
#define RING_H

#include <memory>
#include "ib/base/verbs_extra.h"
#include "dev/buffer_pool.h"
#include "dev/xlio_ti.h"
#include "proto/flow_tuple.h"
#include "proto/xlio_lwip.h"
#include "proto/L2_address.h"
#include "util/cached_obj_pool.h"
#include "lwip/tcp_impl.h"

/* Forward declarations */
struct xlio_tls_info;
class sockinfo;
class rfs_rule;
class poll_group;

#define ring_logpanic   __log_info_panic
#define ring_logerr     __log_info_err
#define ring_logwarn    __log_info_warn
#define ring_loginfo    __log_info_info
#define ring_logdbg     __log_info_dbg
#define ring_logfunc    __log_info_func
#define ring_logfuncall __log_info_funcall
#define ring_logfine    __log_info_fine

typedef enum { CQT_RX, CQT_TX } cq_type_t;

typedef size_t ring_user_id_t;

// Socketxtreme completion
struct ring_ec {
    struct xlio_socketxtreme_completion_t completion;
    ring_ec *next;
};

typedef cached_obj_pool<tcp_seg> tcp_seg_pool;
typedef cached_obj_pool<ring_ec> socketxtreme_ec_pool;

extern tcp_seg_pool *g_tcp_seg_pool;
extern socketxtreme_ec_pool *g_socketxtreme_ec_pool;

class ring {
public:
    ring();

    virtual ~ring();

    virtual void print_val();

    virtual bool attach_flow(flow_tuple &flow_spec_5t, sockinfo *sink, bool force_5t = false) = 0;
    virtual bool detach_flow(flow_tuple &flow_spec_5t, sockinfo *sink) = 0;

    virtual void restart() = 0;

    // Get/Release memory buffer descriptor with a linked data memory buffer
    virtual mem_buf_desc_t *mem_buf_tx_get(ring_user_id_t id, bool b_block, pbuf_type type,
                                           int n_num_mem_bufs = 1, bool tx_skip_poll = false) = 0;
    virtual int mem_buf_tx_release(mem_buf_desc_t *p_mem_buf_desc_list, bool b_accounting,
                                   bool trylock = false) = 0;
    virtual void mem_buf_rx_release(mem_buf_desc_t *p_mem_buf_desc)
    {
        buffer_pool::free_rx_lwip_pbuf_custom(&p_mem_buf_desc->lwip_pbuf);
    }
    virtual void send_ring_buffer(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe,
                                  xlio_wr_tx_packet_attr attr) = 0;
    virtual int send_lwip_buffer(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe,
                                 xlio_wr_tx_packet_attr attr, xlio_tis *tis) = 0;

    virtual int get_num_resources() const = 0;
    virtual int *get_rx_channel_fds(size_t &length) const
    {
        length = 1;
        return m_p_n_rx_channel_fds;
    }
    virtual int get_tx_channel_fd() const { return -1; }
    virtual bool get_hw_dummy_send_support(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe) = 0;
    virtual int request_notification(cq_type_t cq_type, uint64_t poll_sn) = 0;
    virtual bool reclaim_recv_buffers(descq_t *rx_reuse) = 0;
    virtual bool reclaim_recv_buffers(mem_buf_desc_t *rx_reuse_lst) = 0;
    virtual bool reclaim_recv_buffers_no_lock(mem_buf_desc_t *) { return false; }
    virtual int drain_and_proccess() = 0;
    virtual void wait_for_notification_and_process_element(uint64_t *p_cq_poll_sn,
                                                           void *pv_fd_ready_array = nullptr) = 0;
    virtual bool poll_and_process_element_rx(uint64_t *p_cq_poll_sn,
                                             void *pv_fd_ready_array = nullptr) = 0;
    virtual int poll_and_process_element_tx(uint64_t *p_cq_poll_sn) = 0;
    virtual void adapt_cq_moderation() = 0;
    virtual void mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t *p_mem_buf_desc) = 0;
    virtual void mem_buf_desc_return_single_multi_ref(mem_buf_desc_t *p_mem_buf_desc,
                                                      unsigned ref) = 0;

    virtual void inc_tx_retransmissions_stats(ring_user_id_t id) = 0;
    virtual bool is_member(ring_slave *rng) = 0;
    virtual bool is_active_member(ring_slave *rng, ring_user_id_t id) = 0;
    ring *get_parent() { return m_parent; }
    ring_user_id_t generate_id() { return 0; }
    virtual ring_user_id_t generate_id(const address_t src_mac, const address_t dst_mac,
                                       uint16_t eth_proto, uint16_t encap_proto,
                                       const ip_address &src_ip, const ip_address &dst_ip,
                                       uint16_t src_port, uint16_t dst_port) = 0;
    virtual int modify_ratelimit(struct xlio_rate_limit_t &rate_limit) = 0;
    virtual uint32_t get_tx_user_lkey(void *addr, size_t length) = 0;
    virtual uint32_t get_max_inline_data() = 0;
    virtual uint32_t get_max_send_sge(void) = 0;
    virtual uint32_t get_max_payload_sz(void) = 0;
    virtual uint16_t get_max_header_sz(void) = 0;
    virtual uint32_t get_tx_lkey(ring_user_id_t id) = 0;
    virtual bool is_tso(void) = 0;
    virtual ib_ctx_handler *get_ctx(ring_user_id_t id) = 0;

    virtual int socketxtreme_poll(struct xlio_socketxtreme_completion_t *xlio_completions,
                                  unsigned int ncompletions, int flags) = 0;

    inline int get_if_index() { return m_if_index; }

#ifdef DEFINED_UTLS
    virtual bool tls_tx_supported(void) { return false; }
    virtual bool tls_rx_supported(void) { return false; }
    virtual xlio_tis *tls_context_setup_tx(const xlio_tls_info *info)
    {
        NOT_IN_USE(info);
        return NULL;
    }
    virtual xlio_tir *tls_create_tir(bool cached)
    {
        NOT_IN_USE(cached);
        return NULL;
    }
    virtual int tls_context_setup_rx(xlio_tir *tir, const xlio_tls_info *info,
                                     uint32_t next_record_tcp_sn, xlio_comp_cb_t callback,
                                     void *callback_arg)
    {
        NOT_IN_USE(tir);
        NOT_IN_USE(info);
        NOT_IN_USE(next_record_tcp_sn);
        NOT_IN_USE(callback);
        NOT_IN_USE(callback_arg);
        return -1;
    }
    virtual rfs_rule *tls_rx_create_rule(const flow_tuple &flow_spec_5t, xlio_tir *tir)
    {
        NOT_IN_USE(flow_spec_5t);
        NOT_IN_USE(tir);
        return NULL;
    }
    virtual void tls_context_resync_tx(const xlio_tls_info *info, xlio_tis *tis, bool skip_static)
    {
        NOT_IN_USE(info);
        NOT_IN_USE(tis);
        NOT_IN_USE(skip_static);
    }
    virtual void tls_resync_rx(xlio_tir *tir, const xlio_tls_info *info, uint32_t hw_resync_tcp_sn)
    {
        NOT_IN_USE(tir);
        NOT_IN_USE(info);
        NOT_IN_USE(hw_resync_tcp_sn);
    }
    virtual void tls_get_progress_params_rx(xlio_tir *tir, void *buf, uint32_t lkey)
    {
        NOT_IN_USE(tir);
        NOT_IN_USE(buf);
        NOT_IN_USE(lkey);
    }
    virtual void tls_release_tis(xlio_tis *tis) { NOT_IN_USE(tis); }
    virtual void tls_release_tir(xlio_tir *tir) { NOT_IN_USE(tir); }
    virtual void tls_tx_post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey,
                                      bool first)
    {
        NOT_IN_USE(tis);
        NOT_IN_USE(addr);
        NOT_IN_USE(len);
        NOT_IN_USE(lkey);
        NOT_IN_USE(first);
    }
#endif /* DEFINED_UTLS */
    virtual std::unique_ptr<xlio_tis> create_tis(uint32_t flag) const
    {
        NOT_IN_USE(flag);
        return nullptr;
    }
    virtual void nvme_set_static_context(xlio_tis *tis, uint32_t config)
    {
        NOT_IN_USE(tis);
        NOT_IN_USE(config);
    }
    virtual void nvme_set_progress_context(xlio_tis *tis, uint32_t tcp_seqno)
    {
        NOT_IN_USE(tis);
        NOT_IN_USE(tcp_seqno);
    }

    enum {
        NVME_CRC_TX = 1 << 0,
        NVME_CRC_RX = 1 << 1,
        NVME_ZEROCOPY = 1 << 2,
    };

    virtual int get_supported_nvme_feature_mask() const { return 0; }
    virtual void post_nop_fence(void) {}
    virtual void post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey, bool first)
    {
        NOT_IN_USE(tis);
        NOT_IN_USE(addr);
        NOT_IN_USE(len);
        NOT_IN_USE(lkey);
        NOT_IN_USE(first);
    }

    virtual void reset_inflight_zc_buffers_ctx(ring_user_id_t id, void *ctx)
    {
        NOT_IN_USE(id);
        NOT_IN_USE(ctx);
    }

    // TODO Add id argument for bonding
    virtual bool credits_get(unsigned credits)
    {
        NOT_IN_USE(credits);
        return false;
    }
    virtual void credits_return(unsigned credits) { NOT_IN_USE(credits); }

    struct tcp_seg *get_tcp_segs(uint32_t num);
    void put_tcp_segs(struct tcp_seg *seg);

    ring_ec *socketxtreme_get_ecs(uint32_t num);
    void socketxtreme_put_ecs(struct ring_ec *ec);

    void socketxtreme_ec_clear_sock(sockinfo *sock);
    void socketxtreme_ec_sock_list_add(sockinfo *sock);
    bool socketxtreme_ec_pop_completion(xlio_socketxtreme_completion_t *completion);
    void socketxtreme_end_ec_operation();
    xlio_socketxtreme_completion_t &socketxtreme_start_ec_operation(sockinfo *sock,
                                                                    bool always_new);

    // XLIO ZC API
    void set_poll_group(poll_group *p_group) { m_p_group = p_group; }
    poll_group *get_poll_group() const { return m_p_group; }

protected:
    inline void set_parent(ring *parent) { m_parent = (parent ? parent : this); }
    inline void set_if_index(int if_index) { m_if_index = if_index; }

    int *m_p_n_rx_channel_fds = nullptr;
    ring *m_parent = nullptr;

    struct tcp_seg *m_tcp_seg_list = nullptr;
    ring_ec *m_socketxtreme_ec_list = nullptr;
    uint32_t m_tcp_seg_count = 0U;
    uint32_t m_socketxtreme_ec_count = 0U;
    lock_spin_recursive m_tcp_seg_lock;
    lock_spin_recursive m_ec_lock;

    struct {
        // Queue of ready sockets. Each socket can be added only once to this queue.
        sockinfo *ec_sock_list_start = nullptr;
        sockinfo *ec_sock_list_end = nullptr;

        // Thread-safety lock for get/put operations under the queue.
        lock_spin lock_ec_list;
    } m_socketxtreme;

    // XLIO ZC API
    poll_group *m_p_group = nullptr;

    int m_if_index = 0; /* Interface index */
};

#endif /* RING_H */
