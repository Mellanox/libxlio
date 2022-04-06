/*
 * Copyright (c) 2001-2022 Mellanox Technologies, Ltd. All rights reserved.
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

#ifndef CQ_MGR_MLX5_H
#define CQ_MGR_MLX5_H

#include "cq_mgr.h"
#include "qp_mgr_eth_mlx5.h"

#if defined(DEFINED_DIRECT_VERBS)

class qp_mgr_eth_mlx5;

/* Get CQE opcode. */
#define MLX5_CQE_OPCODE(op_own) ((op_own) >> 4)

/* Get CQE owner bit. */
#define MLX5_CQE_OWNER(op_own) ((op_own)&MLX5_CQE_OWNER_MASK)

class cq_mgr_mlx5 : public cq_mgr {
public:
    enum buff_status_e {
        BS_OK,
        BS_CQE_RESP_WR_IMM_NOT_SUPPORTED,
        BS_IBV_WC_WR_FLUSH_ERR,
        BS_CQE_INVALID,
        BS_GENERAL_ERR
    };

    cq_mgr_mlx5(ring_simple *p_ring, ib_ctx_handler *p_ib_ctx_handler, uint32_t cq_size,
                struct ibv_comp_channel *p_comp_event_channel, bool is_rx,
                bool call_configure = true);
    virtual ~cq_mgr_mlx5();

    virtual int drain_and_proccess(uintptr_t *p_recycle_buffers_last_wr_id = NULL);
    virtual int poll_and_process_element_rx(uint64_t *p_cq_poll_sn, void *pv_fd_ready_array = NULL);
    virtual int poll_and_process_element_rx(mem_buf_desc_t **p_desc_lst);

    virtual int poll_and_process_element_tx(uint64_t *p_cq_poll_sn);
    int poll_and_process_error_element_tx(struct vma_mlx5_cqe *cqe, uint64_t *p_cq_poll_sn);

    virtual mem_buf_desc_t *process_cq_element_rx(mem_buf_desc_t *p_mem_buf_desc,
                                                  enum buff_status_e status);
    virtual void add_qp_rx(qp_mgr *qp);
    void set_qp_rq(qp_mgr *qp);
    virtual void add_qp_tx(qp_mgr *qp);
    virtual uint32_t clean_cq();
    virtual void get_cq_event(int count = 1) { vma_ib_mlx5_get_cq_event(&m_mlx5_cq, count); };

protected:
    qp_mgr_eth_mlx5 *m_qp;
    vma_ib_mlx5_cq_t m_mlx5_cq;
    mem_buf_desc_t *m_rx_hot_buffer;
    const bool m_b_sysvar_enable_socketxtreme;

    inline struct vma_mlx5_cqe *check_cqe(void);
    virtual mem_buf_desc_t *poll(enum buff_status_e &status);
    int poll_and_process_error_element_rx(struct vma_mlx5_cqe *cqe, void *pv_fd_ready_array);

    inline struct vma_mlx5_cqe *get_cqe(struct vma_mlx5_cqe **cqe_err = NULL);
    inline void cqe_to_mem_buff_desc(struct vma_mlx5_cqe *cqe, mem_buf_desc_t *p_rx_wc_buf_desc,
                                     enum buff_status_e &status);
    void cqe_to_vma_wc(struct vma_mlx5_cqe *cqe, vma_ibv_wc *wc);
    inline struct vma_mlx5_cqe *check_error_completion(struct vma_mlx5_cqe *cqe, uint32_t *ci,
                                                       uint8_t op_own);
    inline void update_global_sn(uint64_t &cq_poll_sn, uint32_t rettotal);
    void lro_update_hdr(struct vma_mlx5_cqe *cqe, mem_buf_desc_t *p_rx_wc_buf_desc);

private:
    void handle_sq_wqe_prop(unsigned index);

    virtual int req_notify_cq() { return vma_ib_mlx5_req_notify_cq(&m_mlx5_cq, 0); };
};

inline void cq_mgr_mlx5::update_global_sn(uint64_t &cq_poll_sn, uint32_t num_polled_cqes)
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

inline struct vma_mlx5_cqe *cq_mgr_mlx5::check_error_completion(struct vma_mlx5_cqe *cqe,
                                                                uint32_t *ci, uint8_t op_own)
{
    switch (op_own >> 4) {
    case MLX5_CQE_REQ_ERR:
    case MLX5_CQE_RESP_ERR:
        ++(*ci);
        rmb();
        *m_mlx5_cq.dbrec = htonl((*ci));
        return cqe;

    case MLX5_CQE_INVALID:
    default:
        return NULL; /* No CQE */
    }
}

inline struct vma_mlx5_cqe *cq_mgr_mlx5::get_cqe(struct vma_mlx5_cqe **cqe_err)
{
    struct vma_mlx5_cqe *cqe =
        (struct vma_mlx5_cqe *)(((uint8_t *)m_mlx5_cq.cq_buf) +
                                ((m_mlx5_cq.cq_ci & (m_mlx5_cq.cqe_count - 1))
                                 << m_mlx5_cq.cqe_size_log));
    uint8_t op_own = cqe->op_own;

    /* Check ownership and invalid opcode
     * Return cqe_err for 0x80 - MLX5_CQE_REQ_ERR, MLX5_CQE_RESP_ERR or MLX5_CQE_INVALID
     */
    if (unlikely((op_own & MLX5_CQE_OWNER_MASK) == !(m_mlx5_cq.cq_ci & m_mlx5_cq.cqe_count))) {
        return NULL;
    } else if (unlikely((op_own >> 4) == MLX5_CQE_INVALID)) {
        return NULL;
    } else if (cqe_err && (op_own & 0x80)) {
        *cqe_err = check_error_completion(cqe, &m_mlx5_cq.cq_ci, op_own);
        return NULL;
    }

    ++m_mlx5_cq.cq_ci;
    rmb();
    *m_mlx5_cq.dbrec = htonl(m_mlx5_cq.cq_ci);

    return cqe;
}

#endif /* DEFINED_DIRECT_VERBS */
#endif // CQ_MGR_MLX5_H
