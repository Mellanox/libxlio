/*
 * Copyright (c) 2001-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
