/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef CQ_MGR_RX_DUMMY_H
#define CQ_MGR_RX_DUMMY_H

#include "cq_mgr_rx.h"

/**
 * Minimal CQ manager used only for QP initialization in TX queues.
 * This CQ is never used for actual packet processing - it only provides
 * an ibv_cq handle required for QP creation.
 */
class cq_mgr_rx_dummy : public cq_mgr_rx {
public:
    cq_mgr_rx_dummy(ring_simple *p_ring, ib_ctx_handler *p_ib_ctx_handler, uint32_t cq_size,
                    struct ibv_comp_channel *p_comp_event_channel);

    virtual ~cq_mgr_rx_dummy() override = default;

    // These methods are never called - stub implementations
    virtual int drain_and_proccess(uintptr_t *p_recycle_buffers_last_wr_id = nullptr) override;
    virtual int poll_and_process_element_rx(void *pv_fd_ready_array = nullptr) override;
    virtual uint32_t clean_cq() override;
};

#endif // CQ_MGR_RX_DUMMY_H
