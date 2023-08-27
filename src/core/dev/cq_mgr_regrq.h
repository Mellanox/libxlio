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

#ifndef CQ_MGR_REGRQ_H
#define CQ_MGR_REGRQ_H

#include "cq_mgr.h"
#include "qp_mgr_eth_mlx5.h"

#if defined(DEFINED_DIRECT_VERBS)

class qp_mgr_eth_mlx5;

/* Get CQE opcode. */
#define MLX5_CQE_OPCODE(op_own) ((op_own) >> 4)

/* Get CQE owner bit. */
#define MLX5_CQE_OWNER(op_own) ((op_own)&MLX5_CQE_OWNER_MASK)

class cq_mgr_regrq : public cq_mgr {
public:
    enum buff_status_e {
        BS_OK,
        BS_CQE_RESP_WR_IMM_NOT_SUPPORTED,
        BS_IBV_WC_WR_FLUSH_ERR,
        BS_CQE_INVALID,
        BS_GENERAL_ERR
    };

    cq_mgr_regrq(ring_simple *p_ring, ib_ctx_handler *p_ib_ctx_handler, uint32_t cq_size,
                struct ibv_comp_channel *p_comp_event_channel, bool is_rx,
                bool call_configure = true);
    virtual ~cq_mgr_regrq();

    virtual int drain_and_proccess(uintptr_t *p_recycle_buffers_last_wr_id = NULL);
    virtual mem_buf_desc_t *poll_and_process_socketxtreme();
    virtual int poll_and_process_element_rx(uint64_t *p_cq_poll_sn, void *pv_fd_ready_array = NULL);
    virtual int poll_and_process_element_tx(uint64_t *p_cq_poll_sn);

    mem_buf_desc_t *cqe_process_rx(mem_buf_desc_t *p_mem_buf_desc, enum buff_status_e status);
    virtual void add_qp_rx(qp_mgr *qp);
    void set_qp_rq(qp_mgr *qp);
    virtual void add_qp_tx(qp_mgr *qp);
    virtual uint32_t clean_cq();
    virtual void get_cq_event(int count = 1) { xlio_ib_mlx5_get_cq_event(&m_mlx5_cq, count); };

protected:
    qp_mgr_eth_mlx5 *m_qp;
    xlio_ib_mlx5_cq_t m_mlx5_cq;
    mem_buf_desc_t *m_rx_hot_buffer;

    inline struct xlio_mlx5_cqe *check_cqe(void);
    mem_buf_desc_t *poll(enum buff_status_e &status);

    inline struct xlio_mlx5_cqe *get_cqe_tx(uint32_t &num_polled_cqes);
    void log_cqe_error(struct xlio_mlx5_cqe *cqe);
    inline void cqe_to_mem_buff_desc(struct xlio_mlx5_cqe *cqe, mem_buf_desc_t *p_rx_wc_buf_desc,
                                     enum buff_status_e &status);
    inline void update_global_sn(uint64_t &cq_poll_sn, uint32_t rettotal);
    void lro_update_hdr(struct xlio_mlx5_cqe *cqe, mem_buf_desc_t *p_rx_wc_buf_desc);

private:
    void handle_sq_wqe_prop(unsigned index);
    int drain_and_proccess_socketxtreme(uintptr_t *p_recycle_buffers_last_wr_id);
    int drain_and_proccess_helper(mem_buf_desc_t *buff, buff_status_e status,
                                  uintptr_t *p_recycle_buffers_last_wr_id);

    virtual int req_notify_cq() { return xlio_ib_mlx5_req_notify_cq(&m_mlx5_cq, 0); };
};

inline void cq_mgr_regrq::update_global_sn(uint64_t &cq_poll_sn, uint32_t num_polled_cqes)
{
    if (num_polled_cqes > 0) {
        // spoil the global sn if we have packets ready
        union __attribute__((packed)) {
            uint64_t global_sn;
            struct {
                uint32_t cq_id;
                uint32_t cq_sn;
            } bundle;
        } next_sn;
        m_n_cq_poll_sn += num_polled_cqes;
        next_sn.bundle.cq_sn = m_n_cq_poll_sn;
        next_sn.bundle.cq_id = m_cq_id;

        m_n_global_sn = next_sn.global_sn;
    }

    cq_poll_sn = m_n_global_sn;
}

inline struct xlio_mlx5_cqe *cq_mgr_regrq::get_cqe_tx(uint32_t &num_polled_cqes)
{
    struct xlio_mlx5_cqe *cqe_ret = nullptr;
    struct xlio_mlx5_cqe *cqe =
        (struct xlio_mlx5_cqe *)(((uint8_t *)m_mlx5_cq.cq_buf) +
                                 ((m_mlx5_cq.cq_ci & (m_mlx5_cq.cqe_count - 1))
                                  << m_mlx5_cq.cqe_size_log));

    /* According to PRM, SW ownership bit flips with every CQ overflow. Since cqe_count is
     * a power of 2, we use it to get cq_ci bit just after the significant bits. The bit changes
     * with each CQ overflow and actually equals to the SW ownership bit.
     */
    while (((cqe->op_own & MLX5_CQE_OWNER_MASK) == !!(m_mlx5_cq.cq_ci & m_mlx5_cq.cqe_count)) &&
           ((cqe->op_own >> 4) != MLX5_CQE_INVALID)) {
        ++m_mlx5_cq.cq_ci;
        ++num_polled_cqes;
        cqe_ret = cqe;
        if (unlikely(cqe->op_own & 0x80)) {
            // This is likely an error CQE. Return it explicitly to log the errors.
            break;
        }
        cqe = (struct xlio_mlx5_cqe *)(((uint8_t *)m_mlx5_cq.cq_buf) +
                                       ((m_mlx5_cq.cq_ci & (m_mlx5_cq.cqe_count - 1))
                                        << m_mlx5_cq.cqe_size_log));
    }
    if (cqe_ret) {
        rmb();
        *m_mlx5_cq.dbrec = htonl(m_mlx5_cq.cq_ci);
    }
    return cqe_ret;
}

inline struct xlio_mlx5_cqe *cq_mgr_regrq::check_cqe(void)
{
    struct xlio_mlx5_cqe *cqe =
        (struct xlio_mlx5_cqe *)(((uint8_t *)m_mlx5_cq.cq_buf) +
                                 ((m_mlx5_cq.cq_ci & (m_mlx5_cq.cqe_count - 1))
                                  << m_mlx5_cq.cqe_size_log));
    /*
     * CQE ownership is defined by Owner bit in the CQE.
     * The value indicating SW ownership is flipped every
     *  time CQ wraps around.
     * */
    if (likely((MLX5_CQE_OPCODE(cqe->op_own)) != MLX5_CQE_INVALID) &&
        !((MLX5_CQE_OWNER(cqe->op_own)) ^ !!(m_mlx5_cq.cq_ci & m_mlx5_cq.cqe_count))) {
        return cqe;
    }

    return NULL;
}

#endif /* DEFINED_DIRECT_VERBS */
#endif // CQ_MGR_MLX5_H
