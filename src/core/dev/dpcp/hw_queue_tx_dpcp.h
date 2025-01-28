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

#ifndef HW_QUEUE_TX_DPCP_H
#define HW_QUEUE_TX_DPCP_H

#include "config.h"
#ifdef DEFINED_DPCP_PATH_TX
#include <list>
#include <vector>
#include "dev/xlio_ti.h"
#include "proto/mem_buf_desc.h"
#include "proto/xlio_lwip.h"
#include "util/cached_obj_pool.h"
#include "dev/dpcp/dm_mgr.h"
#include "dev/dpcp/cq_mgr_tx.h"
#include "util/sg_array.h"

#ifndef MAX_SUPPORTED_IB_INLINE_SIZE
#define MAX_SUPPORTED_IB_INLINE_SIZE 884
#endif

enum {
    SQ_CREDITS_UMR = 3U,
    SQ_CREDITS_SET_PSV = 1U,
    SQ_CREDITS_GET_PSV = 1U,
    SQ_CREDITS_DUMP = 1U,
    SQ_CREDITS_NOP = 1U,
    SQ_CREDITS_TLS_TX_CONTEXT = SQ_CREDITS_UMR + SQ_CREDITS_SET_PSV,
    SQ_CREDITS_TLS_RX_CONTEXT = SQ_CREDITS_UMR + SQ_CREDITS_SET_PSV,
    SQ_CREDITS_TLS_RX_RESYNC = SQ_CREDITS_UMR,
    SQ_CREDITS_TLS_RX_GET_PSV = SQ_CREDITS_GET_PSV,
};

/* WQE properties description. */
struct sq_wqe_prop {
    /* A buffer held by the WQE. This is NULL for control WQEs. */
    mem_buf_desc_t *buf;
    /* Number of credits (usually number of WQEBBs). */
    unsigned credits;
    /* Transport interface (TIS/TIR) current WQE holds reference to. */
    xlio_ti *ti;
    struct sq_wqe_prop *next;
};

struct slave_data_t;
struct xlio_tls_info;
class ring_simple;

// @class hw_queue_tx
// Object to manages the SQ operations. This object is used for Tx.
// Once created it requests from the system a CQ to work with.
class hw_queue_tx : public xlio_ti_owner {
    friend class ring_simple;
    friend class cq_mgr_tx;

public:
    hw_queue_tx(ring_simple *ring, const slave_data_t *slave,
                struct ibv_comp_channel *p_tx_comp_event_channel, const uint32_t tx_num_wr);
    virtual ~hw_queue_tx();

    virtual void ti_released(xlio_ti *ti) override;

    void up();
    void down();
    int modify_qp_ratelimit(struct xlio_rate_limit_t &rate_limit, uint32_t rl_changes);
    void dm_release_data(mem_buf_desc_t *buff) { m_dm_mgr.release_data(buff); }
    uint32_t is_ratelimit_change(struct xlio_rate_limit_t &rate_limit);

    void send_wqe(xlio_ibv_send_wr *p_send_wqe, xlio_wr_tx_packet_attr attr, xlio_tis *tis,
                  unsigned credits);

    // This function can be replaced with a parameter during ring creation.
    // chain of calls may serve as cache warm for dummy send feature.
    bool get_hw_dummy_send_support() { return m_hw_dummy_send_support; }
    cq_mgr_tx *get_tx_cq_mgr() const { return m_p_cq_mgr_tx; }
    uint32_t get_max_inline_data() const { return m_mlx5_qp.cap.max_inline_data; }
    uint32_t get_max_send_sge() const { return m_mlx5_qp.cap.max_send_sge; }

    void modify_queue_to_ready_state();
    void modify_queue_to_error_state();
    void release_tx_buffers();
    void post_nop_fence();
    void post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey, bool first);
    void reset_inflight_zc_buffers_ctx(void *ctx);
    void credits_return(unsigned credits) { m_sq_free_credits += credits; }

    /* Get a memory inside a wqebb at a wqebb_num offset from the m_sq_wqe_hot and account for
     * m_sq_wqe_counter wrap-around. Use offset_in_wqebb to for the internal address. Use the
     * template parameter to cast the resulting address to the required pointer type */
    template <typename T>
    constexpr inline T wqebb_get(size_t wqebb_num, size_t offset_in_wqebb = 0U)
    {
        return reinterpret_cast<T>(
            reinterpret_cast<uintptr_t>(
                &(*m_sq_wqes)[(m_sq_wqe_counter + wqebb_num) & (m_tx_num_wr - 1)]) +
            offset_in_wqebb);
    }

    bool credits_get(unsigned credits)
    {
        if (m_sq_free_credits >= credits) {
            m_sq_free_credits -= credits;
            return true;
        }
        return false;
    }

    unsigned credits_calculate(xlio_ibv_send_wr *p_send_wqe)
    {
        /* Credit is a logical value which is opaque for users. Only hw_queue_tx can interpret the
         * value and currently, one credit equals to one WQEBB in the SQ.
         *
         * Current method does best effort to predict how many WQEBBs will be used to send
         * p_send_wqe in send_to_wire(). The predicted value may be higher than actual, but
         * mustn't be lower.
         *
         * There are 3 branches in this order:
         *  1. Full non-TSO packet inline
         *  2. Non-TSO packet with scatter-gather elements and no inline data
         *  3. TSO packet with inline headers
         *
         * Formulas details:
         *  1. WQEBB is 64 bytes, the 1st WQEBB contains ctrl segment, eth segment and 18 bytes of
         *     inline data. So, we take the 1st WQEBB and number of WQEBBs for the packet minus 18
         *     bytes.
         *  2. Data segment for each scatter-gather element is 16 bytes. Therefore, WQEBB can hold
         *     up to 4 data segments. The 1st element fits into the 1st WQEBB after the eth segment.
         *     So, we take the 1st WQEBB and number of WQEBBs for scatter-gather elements minus 1.
         *  3. Inline header starts from offset 46 in WQE (2 bytes before 16 bytes alignment).
         *     Decrease inline header size by 2 to align it to 16 bytes boundary at the right edge.
         *     This compensates data segments alignment. Add the 2 bytes back and length of
         *     scatter-gather elements. Take into account that 18 bytes goes to the 1st WQEBB and
         *     add the 1st WQEBB to the result.
         */
        if (xlio_send_wr_opcode(*p_send_wqe) != XLIO_IBV_WR_TSO) {
            if (p_send_wqe->num_sge == 1 && p_send_wqe->sg_list->length <= 204) {
                return (p_send_wqe->sg_list->length + 63U - 18U) / 64U + 1U;
            } else {
                return (p_send_wqe->num_sge + 3U - 1U) / 4U + 1U;
            }
        } else {
            return (((p_send_wqe->tso.hdr_sz + 15U - 2U) & ~15U) + 2U + p_send_wqe->num_sge * 16U -
                    18U + 63U) /
                64U +
                1U;
        }
    }

#if defined(DEFINED_UTLS) && defined(DEFINED_DPCP_PATH_RX)
    int tls_context_setup_rx(xlio_tir *tir, const xlio_tls_info *info, uint32_t next_record_tcp_sn,
                             xlio_comp_cb_t callback, void *callback_arg);
    void tls_resync_rx(xlio_tir *tir, const xlio_tls_info *info, uint32_t hw_resync_tcp_sn);
    void tls_get_progress_params_rx(xlio_tir *tir, void *buf, uint32_t lkey);
#endif // DEFINED_UTLS && DEFINED_DPCP_PATH_RX
private:
    cq_mgr_tx *init_tx_cq_mgr(struct ibv_comp_channel *p_tx_comp_event_channel);

    int configure(const slave_data_t *slave, struct ibv_comp_channel *p_tx_comp_event_channel);
    int prepare_queue(xlio_ibv_qp_init_attr &qp_init_attr);
    void init_queue();
    void init_device_memory();
    void trigger_completion_for_all_sent_packets();
    void update_next_wqe_hot();
    void destroy_tis_cache();
    void put_tls_tis_in_cache(xlio_tis *tis);
    void set_unsignaled_count(void) { m_n_unsignaled_count = m_n_sysvar_tx_num_wr_to_signal - 1; }

    void send_to_wire(xlio_ibv_send_wr *p_send_wqe, xlio_wr_tx_packet_attr attr, bool request_comp,
                      xlio_tis *tis, unsigned credits);

    bool is_completion_need() const
    {
        return !m_n_unsignaled_count || (m_dm_enabled && m_dm_mgr.is_completion_need());
    }

    bool is_signal_requested_for_last_wqe()
    {
        return m_n_unsignaled_count == m_n_sysvar_tx_num_wr_to_signal - 1;
    }

    void dec_unsignaled_count(void)
    {
        if (m_n_unsignaled_count > 0) {
            --m_n_unsignaled_count;
        }
    }

    bool is_sq_wqe_prop_valid(sq_wqe_prop *p, sq_wqe_prop *prev)
    {
        unsigned p_i = p - m_sq_wqe_idx_to_prop;
        unsigned prev_i = prev - m_sq_wqe_idx_to_prop;
        return (p_i != m_sq_wqe_prop_last_signalled) &&
            ((m_tx_num_wr + p_i - m_sq_wqe_prop_last_signalled) % m_tx_num_wr <
             (m_tx_num_wr + prev_i - m_sq_wqe_prop_last_signalled) % m_tx_num_wr);
    }

    inline void store_current_wqe_prop(mem_buf_desc_t *wr_id, unsigned credits, xlio_ti *ti);
    inline int fill_wqe(xlio_ibv_send_wr *p_send_wqe);
    inline int fill_wqe_send(xlio_ibv_send_wr *pswr);
    inline int fill_wqe_lso(xlio_ibv_send_wr *pswr, int data_len);
    inline int fill_inl_segment(sg_array &sga, uint8_t *cur_seg, uint8_t *data_addr,
                                int max_inline_len, int inline_len);
    inline void ring_doorbell(int num_wqebb, bool skip_comp = false);

private:
    xlio_ib_mlx5_qp_t m_mlx5_qp;
    cq_mgr_tx *m_p_cq_mgr_tx;
    sq_wqe_prop *m_sq_wqe_idx_to_prop = nullptr;
    sq_wqe_prop *m_sq_wqe_prop_last = nullptr;
    struct mlx5_eth_wqe (*m_sq_wqes)[] = nullptr;
    struct mlx5_eth_wqe *m_sq_wqe_hot = nullptr;
    uint8_t *m_sq_wqes_end = nullptr;
    const uint32_t m_n_sysvar_tx_num_wr_to_signal;
    uint32_t m_tx_num_wr;
    unsigned m_sq_wqe_prop_last_signalled = 0U;
    unsigned m_sq_free_credits = 0U;
    uint32_t m_n_unsignaled_count = 0U;
    int m_sq_wqe_hot_index = 0;
    uint16_t m_sq_wqe_counter = 0U;
    uint8_t m_port_num;
    bool m_b_fence_needed = false;
    bool m_dm_enabled = false;
    bool m_hw_dummy_send_support = false;
    hw_queue_tx_stats_t m_hwq_tx_stats;
    ring_simple *m_p_ring;
    ib_ctx_handler *m_p_ib_ctx_handler;
    dm_mgr m_dm_mgr;
    struct xlio_rate_limit_t m_rate_limit;
    uint8_t m_doca_max_sge = 0U;
    bool m_notification_armed = false;
    // TIS cache. Protected by ring tx lock. TODO Move to ring.
    std::vector<xlio_tis *> m_tls_tis_cache;

#ifdef DEFINED_UTLS
public:
#define DPCP_TIS_FLAGS (dpcp::TIS_ATTR_TRANSPORT_DOMAIN | dpcp::TIS_ATTR_PD)
    xlio_tis *tls_context_setup_tx(const xlio_tls_info *info);
    void tls_release_tis(xlio_tis *tis);
    void tls_context_resync_tx(const xlio_tls_info *info, xlio_tis *tis, bool skip_static);
    void tls_tx_post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey, bool first);
    std::unique_ptr<xlio_tis> create_tis(uint32_t flags);
    std::unique_ptr<dpcp::tls_dek> get_new_tls_dek(const void *key, uint32_t key_size_bytes);
    std::unique_ptr<dpcp::tls_dek> get_tls_dek(const void *key, uint32_t key_size_bytes);
    void put_tls_dek(std::unique_ptr<dpcp::tls_dek> &&dek_obj);

private:
    inline void tls_fill_static_params_wqe(struct mlx5_wqe_tls_static_params_seg *params,
                                           const struct xlio_tls_info *info, uint32_t key_id,
                                           uint32_t resync_tcp_sn);
    inline void tls_post_static_params_wqe(xlio_ti *ti, const struct xlio_tls_info *info,
                                           uint32_t tis_tir_number, uint32_t key_id,
                                           uint32_t resync_tcp_sn, bool fence, bool is_tx);
    inline void tls_fill_progress_params_wqe(struct mlx5_wqe_tls_progress_params_seg *params,
                                             uint32_t tis_tir_number, uint32_t next_record_tcp_sn);
    inline void tls_post_progress_params_wqe(xlio_ti *ti, uint32_t tis_tir_number,
                                             uint32_t next_record_tcp_sn, bool fence, bool is_tx);
    inline void tls_get_progress_params_wqe(xlio_ti *ti, uint32_t tirn, void *buf, uint32_t lkey);

    std::list<std::unique_ptr<dpcp::tls_dek>> m_tls_dek_get_cache;
    std::list<std::unique_ptr<dpcp::tls_dek>> m_tls_dek_put_cache;
#endif
};

#endif // DEFINED_DPCP_PATH_TX
#endif // HW_QUEUE_TX_DPCP_H