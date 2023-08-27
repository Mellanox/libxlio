/*
 * Copyright (c) 2001-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#if defined(DEFINED_DIRECT_VERBS)

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

    mem_buf_desc_t *cqe_process_rx(mem_buf_desc_t *p_mem_buf_desc, enum buff_status_e status); // MOVE
    virtual void add_qp_rx(qp_mgr *qp);
    void set_qp_rq(qp_mgr *qp); // MOVE
    virtual void add_qp_tx(qp_mgr *qp); // MOVE
    virtual uint32_t clean_cq();

protected:
    mem_buf_desc_t *m_rx_hot_buffer; // MOVE

    inline struct xlio_mlx5_cqe *check_cqe(void); // MOVE
    mem_buf_desc_t *poll(enum buff_status_e &status);

    inline void cqe_to_mem_buff_desc(struct xlio_mlx5_cqe *cqe, mem_buf_desc_t *p_rx_wc_buf_desc,
                                     enum buff_status_e &status);
    void lro_update_hdr(struct xlio_mlx5_cqe *cqe, mem_buf_desc_t *p_rx_wc_buf_desc); // MOVE

private:
    int drain_and_proccess_helper(mem_buf_desc_t *buff, buff_status_e status,
                                  uintptr_t *p_recycle_buffers_last_wr_id);
};

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
