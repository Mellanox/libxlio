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

#ifndef QP_MGR_ETH_MLX5_H
#define QP_MGR_ETH_MLX5_H

#include "qp_mgr.h"
#include "util/sg_array.h"
#include "dev/dm_mgr.h"
#include <list>
#include <vector>

#if defined(DEFINED_DIRECT_VERBS)

#define qp_logpanic   __log_info_panic
#define qp_logerr     __log_info_err
#define qp_logwarn    __log_info_warn
#define qp_loginfo    __log_info_info
#define qp_logdbg     __log_info_dbg
#define qp_logfunc    __log_info_func
#define qp_logfuncall __log_info_funcall

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
typedef struct sq_wqe_prop sq_wqe_prop;

class qp_mgr_eth_mlx5 : public qp_mgr_eth {
    friend class cq_mgr;
    friend class cq_mgr_regrq;

public:
    qp_mgr_eth_mlx5(struct qp_mgr_desc *desc, const uint32_t tx_num_wr, const uint16_t vlan,
                    bool call_configure = true);
    virtual ~qp_mgr_eth_mlx5();
    void up() override;
    void down() override;
    void post_recv_buffer(
        mem_buf_desc_t *p_mem_buf_desc) override; // Post for receive single mem_buf_desc
    xlio_ib_mlx5_qp_t m_mlx5_qp;

#ifdef DEFINED_UTLS
    xlio_tis *tls_context_setup_tx(const xlio_tls_info *info) override;
    xlio_tir *tls_create_tir(bool cached) override;
    int tls_context_setup_rx(xlio_tir *tir, const xlio_tls_info *info, uint32_t next_record_tcp_sn,
                             xlio_comp_cb_t callback, void *callback_arg) override;
    void tls_context_resync_tx(const xlio_tls_info *info, xlio_tis *tis, bool skip_static) override;
    void tls_resync_rx(xlio_tir *tir, const xlio_tls_info *info,
                       uint32_t hw_resync_tcp_sn) override;
    void tls_get_progress_params_rx(xlio_tir *tir, void *buf, uint32_t lkey) override;
    void tls_release_tis(xlio_tis *tis) override;
    void tls_release_tir(xlio_tir *tir) override;
    void tls_tx_post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey,
                              bool first) override;
#endif /* DEFINED_UTLS */
#ifdef DEFINED_DPCP
#define DPCP_TIS_FLAGS     (dpcp::TIS_ATTR_TRANSPORT_DOMAIN | dpcp::TIS_ATTR_PD)
#define DPCP_TIS_NVME_FLAG (dpcp::TIS_ATTR_NVMEOTCP)
    std::unique_ptr<xlio_tis> create_tis(uint32_t flags) const override;
    void nvme_set_static_context(xlio_tis *tis, uint32_t config) override;
    void nvme_set_progress_context(xlio_tis *tis, uint32_t tcp_seqno) override;
#else
#define DPCP_TIS_FLAGS     (0U)
#define DPCP_TIS_NVME_FLAG (0U)
#endif /* DEFINED_DPCP */
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

    void post_nop_fence(void) override;
    void post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey, bool first) override;

#if defined(DEFINED_UTLS)
    std::unique_ptr<dpcp::tls_dek> get_new_tls_dek(const void *key, uint32_t key_size_bytes);
    std::unique_ptr<dpcp::tls_dek> get_tls_dek(const void *key, uint32_t key_size_bytes);
    void put_tls_dek(std::unique_ptr<dpcp::tls_dek> &&dek_obj);
#endif

    void reset_inflight_zc_buffers_ctx(void *ctx) override;
    // TODO Make credits API inline.
    bool credits_get(unsigned credits) override
    {
        if (m_sq_free_credits >= credits) {
            m_sq_free_credits -= credits;
            return true;
        }
        return false;
    }
    void credits_return(unsigned credits) override { m_sq_free_credits += credits; }

protected:
    void post_recv_buffer_rq(mem_buf_desc_t *p_mem_buf_desc);
    void trigger_completion_for_all_sent_packets() override;
    bool init_rx_cq_mgr_prepare();
    void init_qp();
    void init_device_memory();
    cq_mgr *init_rx_cq_mgr(struct ibv_comp_channel *p_rx_comp_event_channel) override;
    cq_mgr *init_tx_cq_mgr(void) override;

    void put_tls_tir_in_cache(xlio_tir *tir);
    void put_tls_tis_in_cache(xlio_tis *tis);
    void ti_released(xlio_ti *ti);

    virtual bool is_rq_empty() const override { return (m_mlx5_qp.rq.head == m_mlx5_qp.rq.tail); }

    inline bool is_sq_wqe_prop_valid(sq_wqe_prop *p, sq_wqe_prop *prev)
    {
        unsigned p_i = p - m_sq_wqe_idx_to_prop;
        unsigned prev_i = prev - m_sq_wqe_idx_to_prop;
        return (p_i != m_sq_wqe_prop_last_signalled) &&
            ((m_tx_num_wr + p_i - m_sq_wqe_prop_last_signalled) % m_tx_num_wr <
             (m_tx_num_wr + prev_i - m_sq_wqe_prop_last_signalled) % m_tx_num_wr);
    }

    sq_wqe_prop *m_sq_wqe_idx_to_prop;
    sq_wqe_prop *m_sq_wqe_prop_last;
    unsigned m_sq_wqe_prop_last_signalled;
    unsigned m_sq_free_credits;
    uint64_t m_rq_wqe_counter;

private:
    void update_next_wqe_hot();

    bool is_completion_need() override
    {
        return !m_n_unsignaled_count || (m_dm_enabled && m_dm_mgr.is_completion_need());
    };
    void dm_release_data(mem_buf_desc_t *buff) override { m_dm_mgr.release_data(buff); }

    int send_to_wire(xlio_ibv_send_wr *p_send_wqe, xlio_wr_tx_packet_attr attr, bool request_comp,
                     xlio_tis *tis, unsigned credits) override;
    inline int fill_wqe(xlio_ibv_send_wr *p_send_wqe);
    inline void store_current_wqe_prop(mem_buf_desc_t *wr_id, unsigned credits, xlio_ti *ti);
    void destroy_tis_cache(void);
#if defined(DEFINED_UTLS)
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

protected:
    dpcp::tir *xlio_tir_to_dpcp_tir(xlio_tir *tir);
    virtual dpcp::tir *create_tir(bool is_tls = false)
    {
        NOT_IN_USE(is_tls);
        return NULL;
    }

private:
#endif /* DEFINED_UTLS */
    inline int fill_wqe_send(xlio_ibv_send_wr *pswr);
    inline int fill_wqe_lso(xlio_ibv_send_wr *pswr);
    inline void ring_doorbell(int db_method, int num_wqebb, int num_wqebb_top = 0,
                              bool skip_comp = false);
    inline int fill_inl_segment(sg_array &sga, uint8_t *cur_seg, uint8_t *data_addr,
                                int max_inline_len, int inline_len);

    struct mlx5_eth_wqe (*m_sq_wqes)[];
    struct mlx5_eth_wqe *m_sq_wqe_hot;
    uint8_t *m_sq_wqes_end;
    enum { MLX5_DB_METHOD_BF, MLX5_DB_METHOD_DB } m_db_method;

    int m_sq_wqe_hot_index;
    uint16_t m_sq_wqe_counter;

    bool m_b_fence_needed;

    bool m_dm_enabled;
    dm_mgr m_dm_mgr;
    /*
     * TIS cache. Protected by ring tx lock.
     * TODO Move to ring.
     */
    std::vector<xlio_tis *> m_tls_tis_cache;
    std::vector<xlio_tir *> m_tls_tir_cache;

#if defined(DEFINED_UTLS)
    std::list<std::unique_ptr<dpcp::tls_dek>> m_tls_dek_get_cache;
    std::list<std::unique_ptr<dpcp::tls_dek>> m_tls_dek_put_cache;
#endif
};
#endif // defined(DEFINED_DIRECT_VERBS)
#endif // QP_MGR_ETH_MLX5_H
