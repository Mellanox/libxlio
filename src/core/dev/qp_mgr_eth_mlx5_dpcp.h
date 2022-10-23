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

#ifndef QP_MGR_ETH_MLX5_DPCP_H
#define QP_MGR_ETH_MLX5_DPCP_H

#include <config.h>

#if defined(DEFINED_DPCP)
#include <mellanox/dpcp.h>
#include <memory>
#include "dev/qp_mgr_eth_mlx5.h"

class qp_mgr_eth_mlx5_dpcp : public qp_mgr_eth_mlx5 {
public:
    qp_mgr_eth_mlx5_dpcp(struct qp_mgr_desc *desc, uint32_t tx_num_wr, uint16_t vlan);

    virtual ~qp_mgr_eth_mlx5_dpcp() override {}

    virtual void up() override;
    virtual void down() override;

    virtual rfs_rule *create_rfs_rule(xlio_ibv_flow_attr &attrs, xlio_tir *tir_ext) override;
    virtual void modify_qp_to_ready_state() override;
    virtual void modify_qp_to_error_state() override;
    virtual void post_recv_buffer(mem_buf_desc_t *p_mem_buf_desc) override;

protected:
    virtual cq_mgr *init_rx_cq_mgr(struct ibv_comp_channel *p_rx_comp_event_channel) override;

private:
#ifdef DEFINED_UTLS
    // TODO: Move UTLS related code to this class and remove qp_mgr_eth_mlx5::create_tir()
    dpcp::tir *create_tir(bool is_tls = false) override;
#else
    dpcp::tir *create_tir(bool is_tls = false);
#endif
    bool configure_rq_dpcp();
    bool prepare_rq(uint32_t cqn);
    bool store_rq_mlx5_params(dpcp::basic_rq &new_rq);
    void modify_rq_to_ready_state();
    void init_tir_rq();

    std::unique_ptr<dpcp::tir> _tir = {nullptr};
    std::unique_ptr<dpcp::basic_rq> _rq = {nullptr};
    uint32_t _strq_wqe_reserved_seg = 0U;
};

#endif // defined(DEFINED_DPCP)

#endif
