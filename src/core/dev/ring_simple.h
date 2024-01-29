/*
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef RING_SIMPLE_H
#define RING_SIMPLE_H

#include "ring_slave.h"

#include <mutex>
#include <unordered_map>

#include "dev/gro_mgr.h"
#include "dev/hw_queue_tx.h"
#include "dev/hw_queue_rx.h"
#include "dev/net_device_table_mgr.h"

struct cq_moderation_info {
    uint32_t period;
    uint32_t count;
    uint64_t packets;
    uint64_t bytes;
    uint64_t prev_packets;
    uint64_t prev_bytes;
    uint32_t missed_rounds;
};

/**
 * @class ring simple
 *
 * Object to manages the QP and CQ operation
 * This object is used for Rx & Tx at the same time
 *
 */
class ring_simple : public ring_slave {
public:
    ring_simple(int if_index, ring *parent, ring_type_t type, bool use_locks);
    virtual ~ring_simple();

    int request_notification(cq_type_t cq_type, uint64_t poll_sn) override;
    int poll_and_process_element_rx(uint64_t *p_cq_poll_sn,
                                    void *pv_fd_ready_array = NULL) override;
    int poll_and_process_element_tx(uint64_t *p_cq_poll_sn) override;
    void adapt_cq_moderation() override;
    bool reclaim_recv_buffers(descq_t *rx_reuse) override;
    bool reclaim_recv_buffers(mem_buf_desc_t *rx_reuse_lst) override;
    bool reclaim_recv_buffers_no_lock(mem_buf_desc_t *rx_reuse_lst) override; // No locks
    int reclaim_recv_single_buffer(mem_buf_desc_t *rx_reuse) override; // No locks
    void mem_buf_rx_release(mem_buf_desc_t *p_mem_buf_desc) override;
    int socketxtreme_poll(struct xlio_socketxtreme_completion_t *xlio_completions,
                          unsigned int ncompletions, int flags) override;
    int drain_and_proccess() override;
    int wait_for_notification_and_process_element(int cq_channel_fd, uint64_t *p_cq_poll_sn,
                                                  void *pv_fd_ready_array = NULL) override;
    void mem_buf_desc_return_to_owner_tx(mem_buf_desc_t *p_mem_buf_desc);
    void mem_buf_desc_return_to_owner_rx(mem_buf_desc_t *p_mem_buf_desc,
                                         void *pv_fd_ready_array = NULL);
    inline int send_buffer(xlio_ibv_send_wr *p_send_wqe, xlio_wr_tx_packet_attr attr,
                           xlio_tis *tis);
    bool is_up() override;
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
    inline void convert_hw_time_to_system_time(uint64_t hwtime, struct timespec *systime)
    {
        m_p_ib_ctx->convert_hw_time_to_system_time(hwtime, systime);
    }
    int modify_ratelimit(struct xlio_rate_limit_t &rate_limit) override;
    int get_tx_channel_fd() const override
    {
        return m_p_tx_comp_event_channel ? m_p_tx_comp_event_channel->fd : -1;
    }
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
    bool is_tso(void) override;

    struct ibv_comp_channel *get_tx_comp_event_channel() { return m_p_tx_comp_event_channel; }
    void modify_cq_moderation(uint32_t period, uint32_t count);

#ifdef DEFINED_UTLS
    bool tls_tx_supported(void) override { return m_tls.tls_tx; }
    bool tls_rx_supported(void) override { return m_tls.tls_rx; }
    bool tls_sync_dek_supported() { return m_tls.tls_synchronize_dek; }
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
    int get_supported_nvme_feature_mask() const override
    {
        dpcp::adapter_hca_capabilities caps {};
        auto adapter = m_p_ib_ctx->get_dpcp_adapter();

        if (adapter == nullptr || (dpcp::DPCP_OK != adapter->get_hca_capabilities(caps)) ||
            !caps.nvmeotcp_caps.enabled) {
            return 0;
        }
        return (NVME_CRC_TX * caps.nvmeotcp_caps.crc_tx) |
            (NVME_CRC_RX * caps.nvmeotcp_caps.crc_rx) |
            (NVME_ZEROCOPY * caps.nvmeotcp_caps.zerocopy);
    }

    void nvme_set_static_context(xlio_tis *tis, uint32_t config) override
    {
        std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
        m_hqtx->nvme_set_static_context(tis, config);
    }

    void nvme_set_progress_context(xlio_tis *tis, uint32_t tcp_seqno) override
    {
        std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
        m_hqtx->nvme_set_progress_context(tis, tcp_seqno);
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

protected:
    void create_resources();
    virtual void init_tx_buffers(uint32_t count);
    void inc_cq_moderation_stats(size_t sz_data) override;
    inline void set_tx_num_wr(uint32_t num_wr) { m_tx_num_wr = num_wr; }
    inline uint32_t get_tx_num_wr() { return m_tx_num_wr; }
    inline uint32_t get_mtu() { return m_mtu; }

private:
    bool is_socketxtreme(void) override { return safe_mce_sys().enable_socketxtreme; }

    void put_ec(struct ring_ec *ec) override
    {
        m_socketxtreme.lock_ec_list.lock();
        list_add_tail(&ec->list, &m_socketxtreme.ec_list);
        m_socketxtreme.lock_ec_list.unlock();
    }

    void del_ec(struct ring_ec *ec) override
    {
        m_socketxtreme.lock_ec_list.lock();
        list_del_init(&ec->list);
        ec->clear();
        m_socketxtreme.lock_ec_list.unlock();
    }

    inline ring_ec *get_ec(void)
    {
        struct ring_ec *ec = NULL;

        m_socketxtreme.lock_ec_list.lock();
        if (!list_empty(&m_socketxtreme.ec_list)) {
            ec = list_entry(m_socketxtreme.ec_list.next, struct ring_ec, list);
            list_del_init(&ec->list);
        }
        m_socketxtreme.lock_ec_list.unlock();
        return ec;
    }
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
        m_p_l2_addr = NULL;
    };

protected:
    ib_ctx_handler *m_p_ib_ctx;
    hw_queue_tx *m_hqtx = nullptr;
    hw_queue_rx *m_hqrx = nullptr;
    struct cq_moderation_info m_cq_moderation_info;
    cq_mgr_rx *m_p_cq_mgr_rx = nullptr;
    cq_mgr_tx *m_p_cq_mgr_tx = nullptr;
    std::unordered_map<void *, uint32_t> m_user_lkey_map;

private:
    struct {
        /* queue of event completion elements
         * this queue is stored events related different sockinfo (sockets)
         * In current implementation every sockinfo (socket) can have single event
         * in this queue
         */
        struct list_head ec_list;

        /* Thread-safety lock for get/put operations under the queue */
        lock_spin lock_ec_list;
    } m_socketxtreme;

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
#ifdef DEFINED_UTLS
    struct {
        /* TLS TX offload is supported */
        bool tls_tx;
        /* TLS RX offload is supported */
        bool tls_rx;
        /* TLS DEK modify Crypto-Sync is supported */
        bool tls_synchronize_dek;
    } m_tls;
#endif /* DEFINED_UTLS */
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
};

class ring_eth : public ring_simple {
public:
    ring_eth(int if_index, ring *parent = NULL, ring_type_t type = RING_ETH,
             bool call_create_res = true, bool use_locks = true)
        : ring_simple(if_index, parent, type, use_locks)
    {
        net_device_val_eth *p_ndev = dynamic_cast<net_device_val_eth *>(
            g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index()));
        if (p_ndev) {
            m_vlan = p_ndev->get_vlan();

            if (call_create_res) {
                create_resources();
            }
        }
    }
};

#endif // RING_SIMPLE_H
