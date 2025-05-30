/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef CQ_MGR_STRQ_H
#define CQ_MGR_STRQ_H

#include <config.h>
#include <vector>
#include "cq_mgr_rx.h"

class cq_mgr_rx_strq : public cq_mgr_rx {
public:
    cq_mgr_rx_strq(ring_simple *p_ring, ib_ctx_handler *p_ib_ctx_handler, uint32_t cq_size,
                   uint32_t stride_size_bytes, uint32_t strides_num,
                   struct ibv_comp_channel *p_comp_event_channel);

    virtual ~cq_mgr_rx_strq() override;

    virtual int drain_and_proccess(uintptr_t *p_recycle_buffers_last_wr_id = NULL) override;
    virtual mem_buf_desc_t *poll_and_process_socketxtreme() override;
    virtual bool poll_and_process_element_rx(uint64_t *p_cq_poll_sn,
                                             void *pv_fd_ready_array = NULL) override;
    virtual void add_hqrx(hw_queue_rx *qp) override;
    virtual uint32_t clean_cq() override;

protected:
    virtual void statistics_print() override;
    virtual void reclaim_recv_buffer_helper(mem_buf_desc_t *buff) override;

    mem_buf_desc_t *poll(enum buff_status_e &status, mem_buf_desc_t *&buff_stride);

private:
    mem_buf_desc_t *next_stride();
    void return_stride(mem_buf_desc_t *desc);

    inline bool set_current_hot_buffer();
    inline bool strq_cqe_to_mem_buff_desc(struct xlio_mlx5_cqe *cqe, enum buff_status_e &status,
                                          bool &is_filler);
    int drain_and_proccess_helper(mem_buf_desc_t *buff, mem_buf_desc_t *buff_wqe,
                                  buff_status_e status, uintptr_t *p_recycle_buffers_last_wr_id);
    mem_buf_desc_t *process_strq_cq_element_rx(mem_buf_desc_t *p_mem_buf_desc,
                                               enum buff_status_e status);

    descq_t _stride_cache;
    ring_slave *_owner_ring = nullptr;
    mem_buf_desc_t *_hot_buffer_stride = nullptr;
    const uint32_t _stride_size_bytes;
    const uint32_t _strides_num;
    const uint32_t _wqe_buff_size_bytes;
    uint32_t _current_wqe_consumed_bytes = 0U;
};

#endif
