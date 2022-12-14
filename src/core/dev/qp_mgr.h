/*
 * Copyright (c) 2001-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include "dev/cq_mgr.h"
#include "dev/rfs_rule.h"

/* Forward declarations */
struct xlio_tls_info;
class xlio_tis;
class xlio_tir;
class buffer_pool;
class cq_mgr;
struct slave_data;
class ring;
class ring_simple;
class ring_eth_cb;

#ifndef MAX_SUPPORTED_IB_INLINE_SIZE
#define MAX_SUPPORTED_IB_INLINE_SIZE 884
#endif

struct qp_mgr_desc {
    ring_simple *ring;
    const struct slave_data *slave;
    struct ibv_comp_channel *rx_comp_event_channel;
};

/* Work request completion callback */
/* TODO Add argument for completion status to handle errors. */
typedef void (*xlio_comp_cb_t)(void *);

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
    friend class cq_mgr;
    friend class cq_mgr_mlx5;
    friend class cq_mgr_mlx5_strq;
    friend class cq_mgr_mp;

public:
    qp_mgr(struct qp_mgr_desc *desc, const uint32_t tx_num_wr);
    virtual ~qp_mgr();

    virtual void up();
    virtual void down();

    virtual void post_recv_buffer(
        mem_buf_desc_t *p_mem_buf_desc); // Post for receive single mem_buf_desc
    void post_recv_buffers(descq_t *p_buffers,
                           size_t count); // Post for receive a list of mem_buf_desc
    int send(xlio_ibv_send_wr *p_send_wqe, xlio_wr_tx_packet_attr attr, xlio_tis *tis);

    inline uint32_t get_max_inline_data() const { return m_qp_cap.max_inline_data; }
    inline uint32_t get_max_send_sge() const { return m_qp_cap.max_send_sge; }
    int get_port_num() const { return m_port_num; }
    virtual uint16_t get_partiton() const { return 0; };
    struct ibv_qp *get_ibv_qp() const { return m_qp; };
    class cq_mgr *get_tx_cq_mgr() const { return m_p_cq_mgr_tx; }
    class cq_mgr *get_rx_cq_mgr() const { return m_p_cq_mgr_rx; }
    virtual uint32_t get_rx_max_wr_num();
    // This function can be replaced with a parameter during ring creation.
    // chain of calls may serve as cache warm for dummy send feature.
    inline bool get_hw_dummy_send_support() { return m_hw_dummy_send_support; }

    virtual void modify_qp_to_ready_state() = 0;
    virtual void modify_qp_to_error_state();

    void release_rx_buffers();
    void release_tx_buffers();
    virtual void trigger_completion_for_all_sent_packets();
    uint32_t is_ratelimit_change(struct xlio_rate_limit_t &rate_limit);
    int modify_qp_ratelimit(struct xlio_rate_limit_t &rate_limit, uint32_t rl_changes);
    virtual void dm_release_data(mem_buf_desc_t *buff) { NOT_IN_USE(buff); }

    virtual rfs_rule *create_rfs_rule(xlio_ibv_flow_attr &attrs, xlio_tir *tir_ext);

#ifdef DEFINED_UTLS
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
    virtual void post_nop_fence(void) {}

    virtual void reset_inflight_zc_buffers_ctx(void *ctx) { NOT_IN_USE(ctx); }

protected:
    struct ibv_qp *m_qp;
    uint64_t *m_rq_wqe_idx_to_wrid;

    ring_simple *m_p_ring;
    uint8_t m_port_num;
    ib_ctx_handler *m_p_ib_ctx_handler;

    struct ibv_qp_cap m_qp_cap;
    uint32_t m_max_qp_wr;

    cq_mgr *m_p_cq_mgr_rx;
    cq_mgr *m_p_cq_mgr_tx;

    uint32_t m_rx_num_wr;
    uint32_t m_tx_num_wr;

    bool m_hw_dummy_send_support;

    uint32_t m_n_sysvar_rx_num_wr_to_post_recv;
    const uint32_t m_n_sysvar_tx_num_wr_to_signal;
    const uint32_t m_n_sysvar_rx_prefetch_bytes_before_poll;

    // recv_wr
    ibv_sge *m_ibv_rx_sg_array;
    ibv_recv_wr *m_ibv_rx_wr_array;
    uint32_t m_curr_rx_wr;
    uintptr_t m_last_posted_rx_wr_id; // Remember so in case we flush RQ we know to wait until this
                                      // WR_ID is received

    // send wr
    uint32_t m_n_unsignaled_count;
    mem_buf_desc_t *m_p_last_tx_mem_buf_desc; // Remembered so we can list several mem_buf_desc_t on
                                              // a single notification request

    mem_buf_desc_t *m_p_prev_rx_desc_pushed;

    // generating packet IDs
    uint16_t m_n_ip_id_base;
    uint16_t m_n_ip_id_offset;
    struct xlio_rate_limit_t m_rate_limit;

    int configure(struct qp_mgr_desc *desc);
    virtual int prepare_ibv_qp(xlio_ibv_qp_init_attr &qp_init_attr) = 0;
    inline void set_unsignaled_count(void)
    {
        m_n_unsignaled_count = m_n_sysvar_tx_num_wr_to_signal - 1;
        m_p_last_tx_mem_buf_desc = NULL;
    }

    virtual cq_mgr *init_rx_cq_mgr(struct ibv_comp_channel *p_rx_comp_event_channel);
    virtual cq_mgr *init_tx_cq_mgr(void);

    cq_mgr *handle_cq_initialization(uint32_t *num_wr, struct ibv_comp_channel *comp_event_channel,
                                     bool is_rx);

    virtual int send_to_wire(xlio_ibv_send_wr *p_send_wqe, xlio_wr_tx_packet_attr attr,
                             bool request_comp, xlio_tis *tis);
    virtual bool is_completion_need() { return !m_n_unsignaled_count; };
};

class qp_mgr_eth : public qp_mgr {
public:
    qp_mgr_eth(struct qp_mgr_desc *desc, const uint32_t tx_num_wr, const uint16_t vlan,
               bool call_configure = true)
        : qp_mgr(desc, tx_num_wr)
        , m_vlan(vlan)
    {
        if (call_configure && configure(desc)) {
            throw_xlio_exception("failed creating qp");
        }
    };

    virtual ~qp_mgr_eth() {}

    virtual void modify_qp_to_ready_state();
    virtual uint16_t get_partiton() const { return m_vlan; };

protected:
    virtual int prepare_ibv_qp(xlio_ibv_qp_init_attr &qp_init_attr);

private:
    const uint16_t m_vlan;
};

#endif
