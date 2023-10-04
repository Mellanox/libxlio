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

#ifndef QP_MGR_H
#define QP_MGR_H

#include <memory>
#include <errno.h>
#include <ifaddrs.h>

#include "ib/base/verbs_extra.h"
#include "proto/xlio_lwip.h"
#include "vlogger/vlogger.h"
#include "utils/atomic.h"
#include "util/vtypes.h"
#include "util/sys_vars.h"
#include "util/libxlio.h"
#include "util/if.h"
#include "lwip/opt.h"
#include "proto/mem_buf_desc.h"
#include "infra/sender.h"
#include "dev/ib_ctx_handler.h"
#include "dev/cq_mgr_rx.h"
#include "dev/cq_mgr_tx.h"
#include "dev/rfs_rule.h"
#include "util/sg_array.h"
#include "dev/dm_mgr.h"
#include <list>
#include <vector>

/* Forward declarations */
struct xlio_tls_info;
class xlio_tis;
class xlio_tir;
class buffer_pool;
class cq_mgr_rx;
struct slave_data;
class ring;
class ring_simple;
class ring_eth_cb;

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

struct qp_mgr_desc {
    ring_simple *ring;
    const struct slave_data *slave;
    struct ibv_comp_channel *rx_comp_event_channel;
};

/* Work request completion callback */
/* TODO Add argument for completion status to handle errors. */
typedef void (*xlio_comp_cb_t)(void *);

class xlio_ti {
public:
    enum ti_type : uint8_t { UNKNOWN, TLS_TIS, TLS_TIR, NVME_TIS, NVME_TIR };

    xlio_ti(ti_type type = UNKNOWN)
        : m_type(type)
        , m_released(false)
        , m_ref(0)
        , m_callback(nullptr)
        , m_callback_arg(nullptr)
    {
    }
    virtual ~xlio_ti() {};

    inline void assign_callback(xlio_comp_cb_t callback, void *callback_arg)
    {
        m_callback = callback;
        m_callback_arg = callback_arg;
    }

    /*
     * Reference counting. m_ref must be protected by ring tx lock. Device
     * layer (QP, CQ) is responsible for the reference counting.
     */

    inline void get(void)
    {
        ++m_ref;
        assert(m_ref > 0);
    }

    inline uint32_t put(void)
    {
        assert(m_ref > 0);
        return --m_ref;
    }

    ti_type m_type;
    bool m_released;
    uint32_t m_ref;

    xlio_comp_cb_t m_callback;
    void *m_callback_arg;
};

class xlio_tis : public xlio_ti {
public:
    xlio_tis(std::unique_ptr<dpcp::tis> _tis, xlio_ti::ti_type type)
        : xlio_ti(type)
        , m_dek()
        , m_p_tis(std::move(_tis))
        , m_tisn(0U)
        , m_dek_id(0U)
    {
        dpcp::status ret = m_p_tis->get_tisn(m_tisn);
        assert(ret == dpcp::DPCP_OK);
        (void)ret;
    }

    ~xlio_tis() = default;

    std::unique_ptr<dpcp::dek> release_dek()
    {
        assert(m_ref == 0);
        m_released = false;
        return std::move(m_dek);
    }

    uint32_t get_tisn() noexcept { return m_tisn; }

    void assign_dek(std::unique_ptr<dpcp::dek> &&dek_ptr)
    {
        m_dek = std::move(dek_ptr);
        m_dek_id = m_dek->get_key_id();
    }

    uint32_t get_dek_id() noexcept { return m_dek_id; }

private:
    std::unique_ptr<dpcp::dek> m_dek;
    std::unique_ptr<dpcp::tis> m_p_tis;
    uint32_t m_tisn;
    uint32_t m_dek_id;
};

class xlio_tir : public xlio_ti {
public:
    xlio_tir(dpcp::tir *_tir, xlio_ti::ti_type type)
        : xlio_ti(type)
    {
        m_p_tir.reset(_tir);
        m_dek = NULL;
        m_tirn = 0;
        m_dek_id = 0;

        /* Cache the tir number. Mustn't fail for a valid TIR object. */
        m_tirn = m_p_tir->get_tirn();
        assert(m_tirn != 0);
    }

    ~xlio_tir() = default;

    std::unique_ptr<dpcp::dek> release_dek()
    {
        assert(m_ref == 0);
        m_released = false;
        return std::move(m_dek);
    }

    uint32_t get_tirn() { return m_tirn; }

    void assign_dek(void *dek_ptr)
    {
        m_dek.reset(reinterpret_cast<dpcp::dek *>(dek_ptr));
        m_dek_id = m_dek->get_key_id();
    }

    uint32_t get_dek_id() { return m_dek_id; }

    std::unique_ptr<dpcp::tir> m_p_tir;

private:
    std::unique_ptr<dpcp::dek> m_dek;
    uint32_t m_tirn;
    uint32_t m_dek_id;
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

/**
 * @class qp_mgr
 *
 * Object to manages the QP operation
 * This object is used for Rx & Tx at the same time
 * Once created it requests from the system a CQ to work with (for Rx & Tx separately)
 *
 * The qp_mgr object will manage the memory data buffers to be used for Rx & Tx.
 * A descriptor (mem_buf_desc_t) is used to point to each memory data buffers which is also menaged
 * by the qm_mgr.
 *
 * NOTE:
 * The idea here is to use the rdma_cma_id object to manage the QP
 * all we need is to rdma_resolve_addr() so we have the correct pkey in the cma_id object
 * the rest is a simple transition of the QP states that is hidden inside the rdma_cm
 *
 */
class qp_mgr {
    friend class cq_mgr_rx;
    friend class cq_mgr_rx_regrq;
    friend class cq_mgr_rx_strq;
    friend class cq_mgr_tx;

public:
    qp_mgr(struct qp_mgr_desc *desc, const uint32_t tx_num_wr, uint16_t vlan);
    ~qp_mgr();

    void up();
    void down();

    // Post for receive single mem_buf_desc
    void post_recv_buffer(mem_buf_desc_t *p_mem_buf_desc);

    // Post for receive a list of mem_buf_desc
    void post_recv_buffers(descq_t *p_buffers, size_t count);
    int send(xlio_ibv_send_wr *p_send_wqe, xlio_wr_tx_packet_attr attr, xlio_tis *tis,
             unsigned credits);

    inline uint32_t get_max_inline_data() const { return m_mlx5_qp.cap.max_inline_data; }
    inline uint32_t get_max_send_sge() const { return m_mlx5_qp.cap.max_send_sge; }
    int get_port_num() const { return m_port_num; }
    uint16_t get_partiton() const { return m_vlan; };
    struct ibv_qp *get_ibv_qp() const { return m_mlx5_qp.qp; };
    cq_mgr_tx *get_tx_cq_mgr() const { return m_p_cq_mgr_tx; }
    cq_mgr_rx *get_rx_cq_mgr() const { return m_p_cq_mgr_rx; }
    uint32_t get_rx_max_wr_num() { return m_rx_num_wr; }
    // This function can be replaced with a parameter during ring creation.
    // chain of calls may serve as cache warm for dummy send feature.
    inline bool get_hw_dummy_send_support() { return m_hw_dummy_send_support; }

    void modify_qp_to_ready_state();
    void modify_qp_to_error_state();

    void release_rx_buffers();
    void release_tx_buffers();
    uint32_t is_ratelimit_change(struct xlio_rate_limit_t &rate_limit);
    int modify_qp_ratelimit(struct xlio_rate_limit_t &rate_limit, uint32_t rl_changes);
    void dm_release_data(mem_buf_desc_t *buff) { m_dm_mgr.release_data(buff); }

    rfs_rule *create_rfs_rule(xlio_ibv_flow_attr &attrs, xlio_tir *tir_ext);

#ifdef DEFINED_UTLS
    xlio_tis *tls_context_setup_tx(const xlio_tls_info *info) override;
    xlio_tir *tls_create_tir(bool cached) override;
    int tls_context_setup_rx(xlio_tir *tir, const xlio_tls_info *info, uint32_t next_record_tcp_sn,
                             xlio_comp_cb_t callback, void *callback_arg);
    void tls_context_resync_tx(const xlio_tls_info *info, xlio_tis *tis, bool skip_static) override;
    void tls_resync_rx(xlio_tir *tir, const xlio_tls_info *info, uint32_t hw_resync_tcp_sn) override;
    void tls_get_progress_params_rx(xlio_tir *tir, void *buf, uint32_t lkey) override;
    void tls_release_tis(xlio_tis *tis) override;
    void tls_release_tir(xlio_tir *tir) override;
    void tls_tx_post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey, bool first) override;
#endif /* DEFINED_UTLS */

#define DPCP_TIS_FLAGS     (dpcp::TIS_ATTR_TRANSPORT_DOMAIN | dpcp::TIS_ATTR_PD)
#define DPCP_TIS_NVME_FLAG (dpcp::TIS_ATTR_NVMEOTCP)
    std::unique_ptr<xlio_tis> create_tis(uint32_t flags) const;
    void nvme_set_static_context(xlio_tis *tis, uint32_t config);
    void nvme_set_progress_context(xlio_tis *tis, uint32_t tcp_seqno);

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

    void post_nop_fence();
    void post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey, bool first);

#if defined(DEFINED_UTLS)
    std::unique_ptr<dpcp::tls_dek> get_new_tls_dek(const void *key, uint32_t key_size_bytes);
    std::unique_ptr<dpcp::tls_dek> get_tls_dek(const void *key, uint32_t key_size_bytes);
    void put_tls_dek(std::unique_ptr<dpcp::tls_dek> &&dek_obj);
#endif

    void reset_inflight_zc_buffers_ctx(void *ctx);

    void credits_return(unsigned credits) { m_sq_free_credits += credits; }

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
        /* Credit is a logical value which is opaque for users. Only qp_mgr can interpret the
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

protected:
    xlio_ib_mlx5_qp_t m_mlx5_qp;
    uint64_t *m_rq_wqe_idx_to_wrid = nullptr;

    ring_simple *m_p_ring;
    uint8_t m_port_num;
    ib_ctx_handler *m_p_ib_ctx_handler;

    uint32_t m_max_qp_wr = 0U;

    cq_mgr_rx *m_p_cq_mgr_rx;
    cq_mgr_tx *m_p_cq_mgr_tx;

    uint32_t m_rx_num_wr;
    uint32_t m_tx_num_wr;

    bool m_hw_dummy_send_support = false;

    uint32_t m_n_sysvar_rx_num_wr_to_post_recv;
    const uint32_t m_n_sysvar_tx_num_wr_to_signal;
    const uint32_t m_n_sysvar_rx_prefetch_bytes_before_poll;

    // recv_wr
    ibv_sge *m_ibv_rx_sg_array;
    ibv_recv_wr *m_ibv_rx_wr_array;
    uint32_t m_curr_rx_wr = 0U;
    uintptr_t m_last_posted_rx_wr_id = 0U; // Remember so in case we flush RQ we know to wait until
                                           // this WR_ID is received

    // send wr
    uint32_t m_n_unsignaled_count = 0U;

    mem_buf_desc_t *m_p_prev_rx_desc_pushed = nullptr;

    uint16_t m_vlan;
    struct xlio_rate_limit_t m_rate_limit;

    int configure(struct qp_mgr_desc *desc);
    int prepare_ibv_qp(xlio_ibv_qp_init_attr &qp_init_attr);
    void init_qp();
    void init_device_memory();
    bool init_rx_cq_mgr_prepare();
    void post_recv_buffer_rq(mem_buf_desc_t *p_mem_buf_desc);

    void set_unsignaled_count(void) { m_n_unsignaled_count = m_n_sysvar_tx_num_wr_to_signal - 1; }

    void dec_unsignaled_count(void)
    {
        if (m_n_unsignaled_count > 0) {
            --m_n_unsignaled_count;
        }
    }

    bool is_signal_requested_for_last_wqe()
    {
        return m_n_unsignaled_count == m_n_sysvar_tx_num_wr_to_signal - 1;
    }

    cq_mgr_rx *init_rx_cq_mgr(struct ibv_comp_channel *p_rx_comp_event_channel);
    cq_mgr_tx *init_tx_cq_mgr();

    int send_to_wire(xlio_ibv_send_wr *p_send_wqe, xlio_wr_tx_packet_attr attr, bool request_comp,
                     xlio_tis *tis, unsigned credits);

private:
    void trigger_completion_for_all_sent_packets();
    void update_next_wqe_hot();
    void destroy_tis_cache();
    void ti_released(xlio_ti *ti);
    void put_tls_tir_in_cache(xlio_tir *tir);
    void put_tls_tis_in_cache(xlio_tis *tis);
    void modify_rq_to_ready_state();
    bool prepare_rq(uint32_t cqn);
    bool configure_rq_dpcp();
    bool store_rq_mlx5_params(dpcp::basic_rq &new_rq);
    bool is_rq_empty() const { return (m_mlx5_qp.rq.head == m_mlx5_qp.rq.tail); }
    bool is_completion_need() const
    {
        return !m_n_unsignaled_count || (m_dm_enabled && m_dm_mgr.is_completion_need());
    }

    dpcp::tir *create_tir(bool is_tls = false);

    dpcp::tir *xlio_tir_to_dpcp_tir(xlio_tir *tir) { return tir->m_p_tir.get(); }

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
#endif /* DEFINED_UTLS */

    inline void store_current_wqe_prop(mem_buf_desc_t *wr_id, unsigned credits, xlio_ti *ti);
    inline int fill_wqe(xlio_ibv_send_wr *p_send_wqe);
    inline int fill_wqe_send(xlio_ibv_send_wr *pswr);
    inline int fill_wqe_lso(xlio_ibv_send_wr *pswr);
    inline int fill_inl_segment(sg_array &sga, uint8_t *cur_seg, uint8_t *data_addr,
                                int max_inline_len, int inline_len);
    inline void ring_doorbell(int db_method, int num_wqebb, int num_wqebb_top = 0,
                              bool skip_comp = false);

    bool is_sq_wqe_prop_valid(sq_wqe_prop *p, sq_wqe_prop *prev)
    {
        unsigned p_i = p - m_sq_wqe_idx_to_prop;
        unsigned prev_i = prev - m_sq_wqe_idx_to_prop;
        return (p_i != m_sq_wqe_prop_last_signalled) &&
            ((m_tx_num_wr + p_i - m_sq_wqe_prop_last_signalled) % m_tx_num_wr <
             (m_tx_num_wr + prev_i - m_sq_wqe_prop_last_signalled) % m_tx_num_wr);
    }

    sq_wqe_prop *m_sq_wqe_idx_to_prop = nullptr;
    sq_wqe_prop *m_sq_wqe_prop_last = nullptr;
    unsigned m_sq_wqe_prop_last_signalled = 0U;
    unsigned m_sq_free_credits = 0U;
    uint64_t m_rq_wqe_counter = 0U;

    struct mlx5_eth_wqe (*m_sq_wqes)[] = nullptr;
    struct mlx5_eth_wqe *m_sq_wqe_hot = nullptr;
    uint8_t *m_sq_wqes_end = nullptr;
    enum { MLX5_DB_METHOD_BF, MLX5_DB_METHOD_DB } m_db_method;

    int m_sq_wqe_hot_index = 0;
    uint16_t m_sq_wqe_counter = 0U;
    bool m_b_fence_needed = false;
    bool m_dm_enabled = false;
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

    std::unique_ptr<dpcp::tir> _tir = {nullptr};
    std::unique_ptr<dpcp::basic_rq> _rq = {nullptr};
    uint32_t _strq_wqe_reserved_seg = 0U;
};

#endif
