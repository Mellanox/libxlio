/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2023-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef CQ_MGR_TX_H
#define CQ_MGR_TX_H

#include "dev/ib_ctx_handler.h"

class hw_queue_tx;
class ring_simple;

class cq_mgr_tx {
public:
    cq_mgr_tx(ring_simple *p_ring, ib_ctx_handler *p_ib_ctx_handler, int cq_size,
              ibv_comp_channel *p_comp_event_channel);
    ~cq_mgr_tx();

    // Helper gunction to extract the cq_mgr_tx from the CQ event,
    // Since we have a single TX CQ comp channel for all cq_mgr_tx's, it might not be the active_cq
    // object
    static cq_mgr_tx *get_cq_mgr_from_cq_event(struct ibv_comp_channel *p_cq_channel);

    ibv_cq *get_ibv_cq_hndl() { return m_p_ibv_cq; }
    int get_channel_fd() { return m_comp_event_channel->fd; }

    void configure(int cq_size);
    void add_qp_tx(hw_queue_tx *hqtx_ptr);
    void del_qp_tx(hw_queue_tx *hqtx_ptr);

    /**
     * Arm the managed CQ's notification channel
     * Calling this more then once without get_event() will return without
     * doing anything (arm flag is changed to true on first call).
     * @return == true cq is armed (or already armed)
     *         false on error
     */
    bool request_notification();

    // @return Positive - Drained with completions, Negative - No completions.
    int poll_and_process_element_tx();

    void reset_notification_armed() { m_b_notification_armed = false; }

private:
    std::string wqe_to_hexstring(uint16_t wqe_index, uint32_t credits) const;
    void log_cqe_error(struct xlio_mlx5_cqe *cqe, uint16_t wqe_index, uint32_t credits) const;
    void handle_sq_wqe_prop(unsigned index);

    void get_cq_event(int count = 1) { xlio_ib_mlx5_get_cq_event(&m_mlx5_cq, count); };

    inline struct xlio_mlx5_cqe *get_cqe_tx();

    xlio_ib_mlx5_cq_t m_mlx5_cq;
    ring_simple *m_p_ring;
    ib_ctx_handler *m_p_ib_ctx_handler;
    ibv_comp_channel *m_comp_event_channel;
    hw_queue_tx *m_hqtx_ptr = nullptr;
    struct ibv_cq *m_p_ibv_cq = nullptr;
    bool m_b_notification_armed = false;
};

inline struct xlio_mlx5_cqe *cq_mgr_tx::get_cqe_tx()
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
    }
    return cqe_ret;
}

#endif // CQ_MGR_TX_H
