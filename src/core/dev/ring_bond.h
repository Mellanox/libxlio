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

#ifndef RING_BOND_H
#define RING_BOND_H

#include "ring_slave.h"
#include "dev/net_device_table_mgr.h"

typedef std::vector<ring_slave *> ring_slave_vector_t;

struct flow_sink_t {
    flow_tuple flow;
    sockinfo *sink;
};

class ring_bond : public ring {

public:
    ring_bond(int if_index);
    ~ring_bond() override;

    void print_val() override;
    size_t get_rx_channels_num() const override;
    int get_rx_channel_fd(size_t ch_idx) const override;
    int get_tx_channel_fd() const override;
    bool request_notification_rx() override;
    bool request_notification_tx() override;
    void clear_rx_notification() override;
    bool poll_and_process_element_rx(void *pv_fd_ready_array = nullptr) override;
    void poll_and_process_element_tx() override;
    void adapt_cq_moderation() override;
    bool reclaim_recv_buffers(descq_t *rx_reuse) override;
    bool reclaim_recv_buffers(mem_buf_desc_t *rx_reuse_lst) override;
    bool reclaim_recv_buffers_no_lock(mem_buf_desc_t *) override;
    void mem_buf_rx_release(mem_buf_desc_t *p_mem_buf_desc) override;
    int drain_and_proccess() override;
    bool attach_flow(flow_tuple &flow_spec_5t, sockinfo *sink, bool force_5t = false) override;
    bool detach_flow(flow_tuple &flow_spec_5t, sockinfo *sink) override;
    void restart() override;
    mem_buf_desc_t *mem_buf_tx_get(ring_user_id_t id, pbuf_type type,
                                   uint32_t n_num_mem_bufs = 1) override;
    int mem_buf_tx_release(mem_buf_desc_t *p_mem_buf_desc_list, bool trylock = false) override;
    void inc_tx_retransmissions_stats(ring_user_id_t id) override;
    void mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t *p_mem_buf_desc) override;
    void mem_buf_desc_return_single_multi_ref(mem_buf_desc_t *p_mem_buf_desc,
                                              unsigned ref) override;
    bool is_member(ring_slave *rng) override;
    bool is_active_member(ring_slave *rng, ring_user_id_t id) override;
    ring_user_id_t generate_id(const address_t src_mac, const address_t dst_mac, uint16_t eth_proto,
                               uint16_t encap_proto, const ip_address &src_ip,
                               const ip_address &dst_ip, uint16_t src_port, uint16_t dst_port);

    int modify_ratelimit(struct xlio_rate_limit_t &rate_limit) override;
    ib_ctx_handler *get_ctx(ring_user_id_t id) override;
    uint32_t get_max_payload_sz() override;
    uint16_t get_max_header_sz() override;
    bool is_tso() override;
    void flow_del_all_rfs_safe() override;
    bool tls_tx_supported() override;
    bool tls_rx_supported() override;
    void slave_create(int if_index);

#ifdef DEFINED_DPCP_PATH_TX
    void send_ring_buffer(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe,
                          xlio_wr_tx_packet_attr attr) override;
    int send_lwip_buffer(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe,
                         xlio_wr_tx_packet_attr attr, xlio_tis *tis) override;
    bool get_hw_dummy_send_support(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe) override;
    uint32_t get_tx_user_lkey(void *addr, size_t length) override;
    uint32_t get_max_inline_data() override;
    uint32_t get_max_send_sge() override;
    uint32_t get_tx_lkey(ring_user_id_t id) override;
    void reset_inflight_zc_buffers_ctx(ring_user_id_t id, void *ctx) override;
    std::unique_ptr<xlio_tis> create_tis(uint32_t flag) const override;
    void post_nop_fence() override;
    void post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey, bool first) override;
    bool credits_get(unsigned credits) override;
    void credits_return(unsigned credits) override;
#else // DEFINED_DPCP_PATH_TX
    uint32_t send_doca_single(void *ptr, uint32_t len, mem_buf_desc_t *buff) override;
    uint32_t send_doca_lso(struct iovec &h, struct pbuf *p, uint16_t mss,
                           bool is_zerocopy) override;
#endif // DEFINED_DPCP_PATH_TX

#if defined(DEFINED_DPCP_PATH_TX) && defined(DEFINED_UTLS)
    xlio_tis *tls_context_setup_tx(const xlio_tls_info *info) override;
    void tls_context_resync_tx(const xlio_tls_info *info, xlio_tis *tis, bool skip_static) override;
    void tls_release_tis(xlio_tis *tis) override;
    void tls_tx_post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey,
                              bool first) override;
#endif // DEFINED_DPCP_PATH_RX && DEFINED_DPCP_PATH_TX

#if defined(DEFINED_DPCP_PATH_ONLY) && defined(DEFINED_UTLS)
    xlio_tir *tls_create_tir(bool cached) override;
    int tls_context_setup_rx(xlio_tir *tir, const xlio_tls_info *info, uint32_t next_record_tcp_sn,
                             xlio_comp_cb_t callback, void *callback_arg) override;
    rfs_rule *tls_rx_create_rule(const flow_tuple &flow_spec_5t, xlio_tir *tir) override;
    void tls_resync_rx(xlio_tir *tir, const xlio_tls_info *info,
                       uint32_t hw_resync_tcp_sn) override;
    void tls_get_progress_params_rx(xlio_tir *tir, void *buf, uint32_t lkey) override;
    void tls_release_tir(xlio_tir *tir) override;
#endif // DEFINED_DPCP_PATH_ONLY && DEFINED_UTLS

protected:
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
    int *m_p_n_rx_channel_fds = nullptr;
#ifdef DEFINED_DPCP_PATH_TX
    void update_cap(ring_slave *slave = nullptr);
    uint32_t m_max_inline_data;
    uint32_t m_max_send_sge;
#endif // DEFINED_DPCP_PATH_TX

private:
    net_device_val::bond_type m_type;
    net_device_val::bond_xmit_hash_policy m_xmit_hash_policy;
    lock_mutex_recursive m_lock_ring_rx;
    lock_mutex_recursive m_lock_ring_tx;
};

#endif /* RING_BOND_H */
