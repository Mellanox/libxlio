/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "ib/base/verbs_extra.h"

#ifndef IB_WQE_TEMPLATE_H
#define IB_WQE_TEMPLATE_H

class wqe_send_handler {
public:
    wqe_send_handler();
    virtual ~wqe_send_handler();

    void init_wqe(xlio_ibv_send_wr &wqe_to_init, struct ibv_sge *sge_list, uint32_t num_sge);
    void init_inline_wqe(xlio_ibv_send_wr &wqe_to_init, struct ibv_sge *sge_list, uint32_t num_sge);
    void init_not_inline_wqe(xlio_ibv_send_wr &wqe_to_init, struct ibv_sge *sge_list,
                             uint32_t num_sge);

    inline xlio_ibv_wr_opcode set_opcode(xlio_ibv_send_wr &wqe, xlio_ibv_wr_opcode opcode)
    {
        xlio_ibv_wr_opcode last_opcode = xlio_send_wr_opcode(wqe);
        xlio_send_wr_opcode(wqe) = opcode;
        return last_opcode;
    }

    inline void enable_tso(xlio_ibv_send_wr &wr, void *hdr, uint16_t hdr_sz, uint16_t mss)
    {
        xlio_send_wr_opcode(wr) = XLIO_IBV_WR_TSO;
        wr.tso.hdr = hdr;
        wr.tso.hdr_sz = hdr_sz;
        wr.tso.mss = mss;
    }

    inline void enable_inline(xlio_ibv_send_wr &send_wqe)
    {
        xlio_send_wr_send_flags(send_wqe) |= XLIO_IBV_SEND_INLINE;
    }
};

#endif /* IB_WQE_TEMPLATE_H */
