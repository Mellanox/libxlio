/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "cq_mgr_rx_dummy.h"

cq_mgr_rx_dummy::cq_mgr_rx_dummy(ring_simple *p_ring, ib_ctx_handler *p_ib_ctx_handler,
                                 uint32_t cq_size, struct ibv_comp_channel *p_comp_event_channel)
    : cq_mgr_rx(p_ring, p_ib_ctx_handler, cq_size, p_comp_event_channel)
{
}

int cq_mgr_rx_dummy::drain_and_proccess(uintptr_t * /*p_recycle_buffers_last_wr_id*/)
{
    // This CQ is never used for actual packet processing
    return 0;
}

int cq_mgr_rx_dummy::poll_and_process_element_rx(void * /*pv_fd_ready_array*/)
{
    // This CQ is never used for actual packet processing
    return 0;
}

uint32_t cq_mgr_rx_dummy::clean_cq()
{
    // This CQ is never used for actual packet processing
    return 0;
}
