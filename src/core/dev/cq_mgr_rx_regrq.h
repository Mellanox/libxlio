/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef CQ_MGR_REGRQ_H
#define CQ_MGR_REGRQ_H

#include "cq_mgr_rx.h"

class cq_mgr_rx_regrq : public cq_mgr_rx {
public:
    cq_mgr_rx_regrq(ring_simple *p_ring, ib_ctx_handler *p_ib_ctx_handler, uint32_t cq_size,
                    struct ibv_comp_channel *p_comp_event_channel);

    virtual ~cq_mgr_rx_regrq() override;

    virtual int drain_and_proccess(uintptr_t *p_recycle_buffers_last_wr_id = nullptr) override;
    virtual int poll_and_process_element_rx(uint64_t *p_cq_poll_sn,
                                            void *pv_fd_ready_array = nullptr) override;

    virtual uint32_t clean_cq() override;

protected:
    mem_buf_desc_t *poll(enum buff_status_e &status);
    inline void cqe_to_mem_buff_desc(struct xlio_mlx5_cqe *cqe, mem_buf_desc_t *p_rx_wc_buf_desc,
                                     enum buff_status_e &status);
};

#endif // CQ_MGR_MLX5_H
