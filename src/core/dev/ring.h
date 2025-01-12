/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

typedef cached_obj_pool<tcp_seg> tcp_seg_pool;

extern tcp_seg_pool *g_tcp_seg_pool;

class ring {
public:
    enum {
        NVME_CRC_TX = 1 << 0,
        NVME_CRC_RX = 1 << 1,
        NVME_ZEROCOPY = 1 << 2,
    };

    ring();
    virtual ~ring();

    virtual void print_val() = 0;
    virtual bool attach_flow(flow_tuple &flow_spec_5t, sockinfo *sink, bool force_5t = false) = 0;
    virtual bool detach_flow(flow_tuple &flow_spec_5t, sockinfo *sink) = 0;
    virtual void restart() = 0;

    // Get/Release memory buffer descriptor with a linked data memory buffer
    virtual mem_buf_desc_t *mem_buf_tx_get(ring_user_id_t id, pbuf_type type,
                                           uint32_t n_num_mem_bufs = 1) = 0;
    virtual int mem_buf_tx_release(mem_buf_desc_t *p_mem_buf_desc_list, bool trylock = false) = 0;
    virtual void mem_buf_rx_release(mem_buf_desc_t *p_mem_buf_desc) = 0;

    virtual void send_ring_buffer(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe,
                                  xlio_wr_tx_packet_attr attr) = 0;
    virtual int send_lwip_buffer(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe,
                                 xlio_wr_tx_packet_attr attr, xlio_tis *tis) = 0;
    virtual uint32_t send_doca_single(void *ptr, uint32_t len, mem_buf_desc_t *buff) = 0;
    virtual uint32_t send_doca_lso(struct iovec &h, struct pbuf *p, uint16_t mss,
                                   bool is_zerocopy) = 0;
    virtual int get_num_resources() const = 0;
    virtual size_t get_rx_channels_num() const = 0;
    virtual int get_rx_channel_fd(size_t ch_idx) const = 0;
    virtual int get_tx_channel_fd() const = 0;
    virtual bool get_hw_dummy_send_support(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe) = 0;
    virtual bool request_notification(cq_type_t cq_type) = 0;
    virtual bool reclaim_recv_buffers(descq_t *rx_reuse) = 0;
    virtual bool reclaim_recv_buffers(mem_buf_desc_t *rx_reuse_lst) = 0;
    virtual bool reclaim_recv_buffers_no_lock(mem_buf_desc_t *) = 0;
    virtual int drain_and_proccess() = 0;
    virtual void clear_rx_notification() = 0;
    virtual bool poll_and_process_element_rx(void *pv_fd_ready_array = nullptr) = 0;
    virtual void poll_and_process_element_tx() = 0;
    virtual void adapt_cq_moderation() = 0;
    virtual void mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t *p_mem_buf_desc) = 0;
    virtual void mem_buf_desc_return_single_multi_ref(mem_buf_desc_t *p_mem_buf_desc,
                                                      unsigned ref) = 0;
    virtual void inc_tx_retransmissions_stats(ring_user_id_t id) = 0;
    virtual bool is_member(ring_slave *rng) = 0;
    virtual bool is_active_member(ring_slave *rng, ring_user_id_t id) = 0;
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
    virtual bool is_tso() = 0;
    virtual ib_ctx_handler *get_ctx(ring_user_id_t id) = 0;
    virtual std::unique_ptr<xlio_tis> create_tis(uint32_t flag) const = 0;
    virtual void nvme_set_static_context(xlio_tis *tis, uint32_t config) = 0;
    virtual void nvme_set_progress_context(xlio_tis *tis, uint32_t tcp_seqno) = 0;
    virtual void reset_inflight_zc_buffers_ctx(ring_user_id_t id, void *ctx) = 0;
    virtual void flow_del_all_rfs_safe() = 0;
    virtual int get_supported_nvme_feature_mask() const = 0;
    virtual void post_nop_fence() = 0;
    virtual void post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey,
                               bool first) = 0;
    virtual bool credits_get(unsigned credits) = 0;
    virtual void credits_return(unsigned credits) = 0;

#ifdef DEFINED_UTLS
    virtual bool tls_tx_supported() = 0;
    virtual bool tls_rx_supported() = 0;
    virtual xlio_tis *tls_context_setup_tx(const xlio_tls_info *info) = 0;
    virtual xlio_tir *tls_create_tir(bool cached) = 0;
    virtual int tls_context_setup_rx(xlio_tir *tir, const xlio_tls_info *info,
                                     uint32_t next_record_tcp_sn, xlio_comp_cb_t callback,
                                     void *callback_arg) = 0;
    virtual rfs_rule *tls_rx_create_rule(const flow_tuple &flow_spec_5t, xlio_tir *tir) = 0;
    virtual void tls_context_resync_tx(const xlio_tls_info *info, xlio_tis *tis,
                                       bool skip_static) = 0;
    virtual void tls_resync_rx(xlio_tir *tir, const xlio_tls_info *info,
                               uint32_t hw_resync_tcp_sn) = 0;
    virtual void tls_get_progress_params_rx(xlio_tir *tir, void *buf, uint32_t lkey) = 0;
    virtual void tls_release_tis(xlio_tis *tis) = 0;
    virtual void tls_release_tir(xlio_tir *tir) = 0;
    virtual void tls_tx_post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey,
                                      bool first) = 0;

#endif /* DEFINED_UTLS */

    ring *get_parent() { return m_parent; }
    ring_user_id_t generate_id() { return 0; }
    int get_if_index() { return m_if_index; }
    struct tcp_seg *get_tcp_segs(uint32_t num);
    void put_tcp_segs(struct tcp_seg *seg);

protected:
    void set_parent(ring *parent) { m_parent = (parent ? parent : this); }
    void set_if_index(int if_index) { m_if_index = if_index; }

    ring *m_parent = nullptr;
    struct tcp_seg *m_tcp_seg_list = nullptr;
    lock_spin_recursive m_tcp_seg_lock;
    uint32_t m_tcp_seg_count = 0U;
    int m_if_index = 0; /* Interface index */
};

#endif /* RING_H */
