/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "util/valgrind.h"
#if defined(DEFINED_DIRECT_VERBS)

#include "util/valgrind.h"
#include "util/utils.h"
#include "ib/mlx5/ib_mlx5.h"

int xlio_ib_mlx5_get_qp_tx(xlio_ib_mlx5_qp_t *mlx5_qp)
{
    int ret = 0;
    struct mlx5dv_obj obj;
    struct mlx5dv_qp dqp;
    enum ibv_qp_attr_mask attr_mask = IBV_QP_CAP;
    struct ibv_qp_attr tmp_ibv_qp_attr;
    struct ibv_qp_init_attr tmp_ibv_qp_init_attr;

    memset(&obj, 0, sizeof(obj));
    memset(&dqp, 0, sizeof(dqp));

    obj.qp.in = mlx5_qp->qp;
    obj.qp.out = &dqp;
#if defined(DEFINED_DV_RAW_QP_HANDLES)
    dqp.comp_mask |= MLX5DV_QP_MASK_RAW_QP_HANDLES;
#endif /* DEFINED_DV_RAW_QP_HANDLES */
    ret = xlio_ib_mlx5dv_init_obj(&obj, MLX5DV_OBJ_QP);
    if (ret != 0) {
        goto out;
    }

    VALGRIND_MAKE_MEM_DEFINED(&dqp, sizeof(dqp));
    mlx5_qp->qpn = mlx5_qp->qp->qp_num;
    mlx5_qp->sq.dbrec = &dqp.dbrec[MLX5_SND_DBR];
    mlx5_qp->sq.buf = dqp.sq.buf;
    mlx5_qp->sq.wqe_cnt = dqp.sq.wqe_cnt;
    mlx5_qp->sq.stride = dqp.sq.stride;
    mlx5_qp->bf.reg = dqp.bf.reg;
#if defined(DEFINED_DV_RAW_QP_HANDLES)
    mlx5_qp->tisn = dqp.tisn;
    mlx5_qp->sqn = dqp.sqn;
#endif /* DEFINED_DV_RAW_QP_HANDLES */

    ret = ibv_query_qp(mlx5_qp->qp, &tmp_ibv_qp_attr, attr_mask, &tmp_ibv_qp_init_attr);
    if (ret != 0) {
        goto out;
    }

    VALGRIND_MAKE_MEM_DEFINED(&tmp_ibv_qp_attr, sizeof(tmp_ibv_qp_attr));
    mlx5_qp->cap.max_send_wr = tmp_ibv_qp_attr.cap.max_send_wr;
    mlx5_qp->cap.max_send_sge = tmp_ibv_qp_attr.cap.max_send_sge;
    mlx5_qp->cap.max_inline_data = tmp_ibv_qp_attr.cap.max_inline_data;

out:
    return ret;
}

int xlio_ib_mlx5_get_cq(struct ibv_cq *cq, xlio_ib_mlx5_cq_t *mlx5_cq)
{
    int ret = 0;
    struct mlx5dv_obj obj;
    struct mlx5dv_cq dcq;

    /* Initialization of cq can be done once to protect
     * internal data from corruption.
     * cq field is used to detect one time initialization
     * For example: this function can be called when QP is moved
     * from ERROR state to RESET so cq_ci or cq_sn should not be
     * updated
     */
    if (!mlx5_cq || mlx5_cq->cq == cq) {
        return 0;
    }

    memset(&obj, 0, sizeof(obj));
    memset(&dcq, 0, sizeof(dcq));

    obj.cq.in = cq;
    obj.cq.out = &dcq;
    ret = xlio_ib_mlx5dv_init_obj(&obj, MLX5DV_OBJ_CQ);
    if (ret != 0) {
        return ret;
    }
    VALGRIND_MAKE_MEM_DEFINED(&dcq, sizeof(dcq));
    mlx5_cq->cq = cq;
    mlx5_cq->cq_num = dcq.cqn;
    mlx5_cq->cq_ci = 0;
    mlx5_cq->cq_sn = 0;
    mlx5_cq->cqe_count = dcq.cqe_cnt;
    mlx5_cq->cqe_size = dcq.cqe_size;
    mlx5_cq->cqe_size_log = ilog_2(dcq.cqe_size);
    mlx5_cq->dbrec = dcq.dbrec;
    mlx5_cq->uar = dcq.cq_uar;

    /* Move buffer forward for 128b CQE, so we would get pointer to the 2nd
     * 64b when polling.
     */
    mlx5_cq->cq_buf = (uint8_t *)dcq.buf + dcq.cqe_size - sizeof(struct xlio_mlx5_cqe);

    return 0;
}

#endif /* DEFINED_DIRECT_VERBS */
