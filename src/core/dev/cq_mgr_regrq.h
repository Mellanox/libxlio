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

class cq_mgr_regrq : public cq_mgr {
public:
    cq_mgr_regrq(ring_simple *p_ring, ib_ctx_handler *p_ib_ctx_handler, uint32_t cq_size,
                struct ibv_comp_channel *p_comp_event_channel);
    virtual ~cq_mgr_regrq();

    virtual int drain_and_proccess(uintptr_t *p_recycle_buffers_last_wr_id = NULL) override;
    virtual mem_buf_desc_t *poll_and_process_socketxtreme();
    virtual int poll_and_process_element_rx(uint64_t *p_cq_poll_sn, void *pv_fd_ready_array = NULL) override;

    virtual void add_qp_rx(qp_mgr *qp);
    virtual uint32_t clean_cq() override;

protected:
    mem_buf_desc_t *poll(enum buff_status_e &status);
    inline void cqe_to_mem_buff_desc(struct xlio_mlx5_cqe *cqe, mem_buf_desc_t *p_rx_wc_buf_desc,
                                     enum buff_status_e &status);

private:
    int drain_and_proccess_helper(mem_buf_desc_t *buff, buff_status_e status,
                                  uintptr_t *p_recycle_buffers_last_wr_id);
};

#endif // CQ_MGR_MLX5_H
