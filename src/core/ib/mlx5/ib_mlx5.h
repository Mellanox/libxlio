/*
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef _IB_MLX5_H_
#define _IB_MLX5_H_

#if defined(DEFINED_DIRECT_VERBS)

#include <infiniband/verbs.h>

#if (DEFINED_DIRECT_VERBS == 3)
extern "C" {
#include <infiniband/mlx5dv.h>
}
#else
#error "Unsupported Direct VERBS parameter"
#endif

#include <utils/asm.h>
#include <core/util/vtypes.h>

/* ib/mlx5 layer is used by other XLIO code that needs
 * direct access to mlx5 resources.
 * It hides differences in rdma-core(Upstream OFED) and mlx5(Mellanox OFED)
 * mlx5 provider implementations.
 * rdma-core(Upstream OFED) structures/macro/enum etc are taken as basis
 * inside this layer
 */

#ifndef DEVX_ST_SZ_BYTES
#define DEVX_ST_SZ_BYTES(typ) (sizeof(struct mlx5_ifc_##typ##_bits) / 8)
#endif

/**
 * Get internal verbs information.
 */
int xlio_ib_mlx5dv_init_obj(struct mlx5dv_obj *obj, uint64_t type);

enum { XLIO_IB_MLX5_CQ_SET_CI = 0, XLIO_IB_MLX5_CQ_ARM_DB = 1 };

/* Queue pair */
typedef struct xlio_ib_mlx5_qp {
    struct ibv_qp *qp;
    uint32_t qpn;
    struct ibv_qp_cap cap;
    struct {
        volatile uint32_t *dbrec;
        void *buf;
        uint32_t wqe_cnt;
        uint32_t stride;
    } sq;
    struct {
        volatile uint32_t *dbrec;
        void *buf;
        uint32_t wqe_cnt;
        uint32_t stride;
        uint32_t wqe_shift;
        unsigned head;
        unsigned tail;
    } rq;
    struct {
        void *reg;
        uint32_t size;
        uint32_t offset;
    } bf;
    uint32_t tirn;
    uint32_t tisn;
    uint32_t rqn;
    uint32_t sqn;
} xlio_ib_mlx5_qp_t;

/* Completion queue */
typedef struct xlio_ib_mlx5_cq {
    struct ibv_cq *cq;
    void *cq_buf;
    unsigned cq_num;
    unsigned cq_ci;
    unsigned cq_sn;
    unsigned cqe_count;
    unsigned cqe_size;
    unsigned cqe_size_log;
    volatile uint32_t *dbrec;
    void *uar;
} xlio_ib_mlx5_cq_t;

/* TLS PRM structures */

struct mlx5_ifc_tls_static_params_bits {
    uint8_t const_2[0x2];
    uint8_t tls_version[0x4];
    uint8_t const_1[0x2];
    uint8_t reserved_at_8[0x14];
    uint8_t encryption_standard[0x4];
    uint8_t reserved_at_20[0x20];
    uint8_t initial_record_number[0x40];
    uint8_t resync_tcp_sn[0x20];
    uint8_t gcm_iv[0x20];
    uint8_t implicit_iv[0x40];
    uint8_t reserved_at_100[0x8];
    uint8_t dek_index[0x18];
    uint8_t reserved_at_120[0xe0];
};

struct mlx5_ifc_tls_progress_params_bits {
    uint8_t next_record_tcp_sn[0x20];
    uint8_t hw_resync_tcp_sn[0x20];
    uint8_t record_tracker_state[0x2];
    uint8_t auth_state[0x2];
    uint8_t reserved_at_44[0x4];
    uint8_t hw_offset_record_number[0x18];
};

struct mlx5_mkey_seg {
    /* This is a two bit field occupying bits 31-30.
     * bit 31 is always 0,
     * bit 30 is zero for regular MRs and 1 (e.g free) for UMRs that do not have translation
     */
    uint8_t status;
    uint8_t pcie_control;
    uint8_t flags;
    uint8_t version;
    __be32 qpn_mkey7_0;
    uint8_t rsvd1[4];
    __be32 flags_pd;
    __be64 start_addr;
    __be64 len;
    __be32 bsfs_octo_size;
    uint8_t rsvd2[16];
    __be32 xlt_oct_size;
    uint8_t rsvd3[3];
    uint8_t log2_page_size;
    uint8_t rsvd4[4];
};

/* PRM static stransport params */
struct mlx5_ifc_transport_static_params_bits {
    uint8_t const_2[0x2];
    uint8_t tls_version[0x4];
    uint8_t const_1[0x2];
    uint8_t reserved_at_8[0x14];
    uint8_t acc_type[0x4];
    uint8_t reserved_at_20[0x20];
    uint8_t initial_record_number[0x40];
    uint8_t resync_tcp_sn[0x20];
    uint8_t gcm_iv[0x20];
    uint8_t implicit_iv[0x40];
    uint8_t reserved_at_100[0x8];
    uint8_t dek_index[0x18];
    uint8_t reserved_at_120[0x14];
    uint8_t const1[0x1];
    uint8_t ti[0x1];
    uint8_t zero_copy_en[0x1];
    uint8_t ddgst_offload_en[0x1];
    uint8_t hdgst_offload_en[0x1];
    uint8_t ddgst_en[0x1];
    uint8_t hddgst_en[0x1];
    uint8_t pda[0x5];
    uint8_t nvme_resync_tcp_sn[0x20];
    uint8_t reserved_at_160[0xa0];
};

#define MLX5_CTRL_SEGMENT_OPC_MOD_UMR_TIR_PARAMS 0x2
#define MLX5_CTRL_SEGMENT_OPC_MOD_UMR_TIS_PARAMS 0x1
#define MLX5_CTRL_SEGMENT_OPC_MOD_UMR_UMR        0x0

/* Bit mask for TCP PUSH flag in lro_tcppsh_abort_dupack field. */
#define MLX5_CQE_LRO_TCP_PUSH_MASK 0x40

typedef struct xlio_mlx5_cqe {
    uint8_t pkt_info;
    uint8_t rsvd0;
    __be16 wqe_id;
    uint8_t lro_tcppsh_abort_dupack;
    uint8_t lro_min_ttl;
    __be16 lro_tcp_win;
    __be32 lro_ack_seq_num;
    __be32 rx_hash_res;
    uint8_t rx_hash_type;
    uint8_t rsvd1[3];
    __be16 csum;
    uint8_t rsvd2[6];
    uint8_t hds_ip_ext;
    uint8_t l4_hdr_type_etc;
    __be16 vlan_info;
    uint8_t lro_num_seg;
    uint8_t rsvd3[3];
    __be32 flow_table_metadata;
    uint8_t rsvd4[4];
    __be32 byte_cnt;
    __be64 timestamp;
    __be32 sop_drop_qpn;
    __be16 wqe_counter;
    uint8_t rsvd5;
    uint8_t op_own;
} xlio_mlx5_cqe;

/* WQE segments structures */

typedef struct xlio_mlx5_wqe_ctrl_seg {
    __be32 opmod_idx_opcode;
    __be32 qpn_ds;
    uint8_t signature;
    uint8_t rsvd[2];
    uint8_t fm_ce_se;
    union {
        __be32 general_id;
        __be32 imm;
        __be32 umr_mkey;
        __be32 tis_tir_num;
    };
} xlio_mlx5_wqe_ctrl_seg;

/* Name collision with mlx5dv.h */
struct xlio_mlx5_wqe_umr_ctrl_seg {
    uint8_t flags;
    uint8_t rsvd0[3];
    __be16 xlt_octowords;
    union {
        __be16 xlt_offset;
        __be16 bsf_octowords;
    };
    __be64 mkey_mask;
    __be32 xlt_offset_47_16;
    uint8_t rsvd1[28];
};

typedef struct mlx5_wqe_tls_static_params_seg {
    uint8_t ctx[DEVX_ST_SZ_BYTES(tls_static_params)];
} mlx5_wqe_tls_static_params_seg;

typedef struct mlx5_wqe_tls_progress_params_seg {
    __be32 tis_tir_num;
    uint8_t ctx[DEVX_ST_SZ_BYTES(tls_progress_params)];
} mlx5_wqe_tls_progress_params_seg;

/* WQEs structures */

typedef struct mlx5_wqe {
    union {
        struct xlio_mlx5_wqe_ctrl_seg ctrl;
        uint32_t data[4];
    };
} mlx5_wqe;

typedef struct mlx5_eth_wqe {
    struct mlx5_wqe ctrl;
    struct mlx5_wqe_eth_seg eseg;
    struct mlx5_wqe_data_seg dseg;
} mlx5_eth_wqe;

typedef struct mlx5_set_tls_static_params_wqe {
    mlx5_wqe ctrl;
    xlio_mlx5_wqe_umr_ctrl_seg uctrl;
    mlx5_mkey_seg mkc;
    mlx5_wqe_tls_static_params_seg params;
} mlx5_set_tls_static_params_wqe;

typedef struct mlx5_set_tls_progress_params_wqe {
    struct mlx5_wqe ctrl;
    struct mlx5_wqe_tls_progress_params_seg params;
} mlx5_set_tls_progress_params_wqe;

struct mlx5_dump_wqe {
    struct mlx5_wqe ctrl;
    struct mlx5_wqe_data_seg data;
};

typedef struct xlio_mlx5_seg_get_psv {
    uint8_t rsvd[19];
    uint8_t num_psv;
    __be32 l_key;
    __be64 va;
    __be32 psv_index[4];
} xlio_mlx5_seg_get_psv;

typedef struct mlx5_get_tls_progress_params_wqe {
    struct mlx5_wqe ctrl;
    struct xlio_mlx5_seg_get_psv psv;
} mlx5_get_tls_progress_params_wqe;

/* WQEs sizes */
#define DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))
#define TLS_SET_STATIC_PARAMS_WQEBBS                                                               \
    (DIV_ROUND_UP(sizeof(mlx5_set_tls_static_params_wqe), MLX5_SEND_WQE_BB))
#define TLS_SET_PROGRESS_PARAMS_WQEBBS                                                             \
    (DIV_ROUND_UP(sizeof(mlx5_set_tls_progress_params_wqe), MLX5_SEND_WQE_BB))
#define TLS_GET_PROGRESS_WQEBBS                                                                    \
    (DIV_ROUND_UP(sizeof(mlx5_get_tls_progress_params_wqe), MLX5_SEND_WQE_BB))
#define XLIO_DUMP_WQEBBS (DIV_ROUND_UP(sizeof(struct mlx5_dump_wqe), MLX5_SEND_WQE_BB))

#define MLX5_CTRL_SEGMENT_OPC_MOD_UMR_NVMEOTCP_TIR_STATIC_PARAMS   0x2
#define MLX5_CTRL_SEGMENT_OPC_MOD_UMR_NVMEOTCP_TIS_STATIC_PARAMS   0x1
#define MLX5_CTRL_SEGMENT_OPC_MOD_UMR_NVMEOTCP_TIR_PROGRESS_PARAMS 0x4
#define MLX5_CTRL_SEGMENT_OPC_MOD_UMR_NVMEOTCP_TIS_PROGRESS_PARAMS 0x3

#define MLX5E_NVMEOTCP_PROGRESS_PARAMS_WQEBBS                                                      \
    (DIV_ROUND_UP(MLX5E_NVMEOTCP_PROGRESS_PARAMS_WQE_SZ, MLX5_SEND_WQE_BB))

#define MLX5E_TRANSPORT_SET_STATIC_PARAMS_WQEBBS                                                   \
    (DIV_ROUND_UP(sizeof(struct mlx5e_set_transport_static_params_wqe), MLX5_SEND_WQE_BB))

#define MLX5E_NVMEOTCP_PROGRESS_PARAMS_WQE_SZ                                                      \
    (sizeof(struct mlx5e_set_nvmeotcp_progress_params_wqe))

#define MLX5E_NVMEOTCP_PROGRESS_PARAMS_DS_CNT                                                      \
    DIV_ROUND_UP(MLX5E_NVMEOTCP_PROGRESS_PARAMS_WQE_SZ, MLX5_SEND_WQE_DS)

#define MLX5E_TRANSPORT_STATIC_PARAMS_WQE_SZ (sizeof(struct mlx5e_set_transport_static_params_wqe))

#define MLX5E_TRANSPORT_STATIC_PARAMS_DS_CNT                                                       \
    (DIV_ROUND_UP(MLX5E_TRANSPORT_STATIC_PARAMS_WQE_SZ, MLX5_SEND_WQE_DS))

#define MLX5E_TRANSPORT_STATIC_PARAMS_OCTWORD_SIZE                                                 \
    (DEVX_ST_SZ_BYTES(transport_static_params) / MLX5_SEND_WQE_DS)

struct mlx5_ifc_nvmeotcp_progress_params_bits {
    uint8_t next_pdu_tcp_sn[0x20];
    uint8_t hw_resync_tcp_sn[0x20];
    uint8_t pdu_tracker_state[0x2];
    uint8_t offloading_state[0x2];
    uint8_t reserved_at_44[0xc];
    uint8_t cccid_ttag[0x10];
};

enum {
    MLX5E_NVMEOTCP_PROGRESS_PARAMS_PDU_TRACKER_STATE_START = 0,
    MLX5E_NVMEOTCP_PROGRESS_PARAMS_PDU_TRACKER_STATE_TRACKING = 1,
    MLX5E_NVMEOTCP_PROGRESS_PARAMS_PDU_TRACKER_STATE_SEARCHING = 2,
};

enum {
    MLX5_TRANSPORT_STATIC_PARAMS_ACC_TYPE_NVMETCP = 0x2,
};

enum {
    MLX5_TRANSPORT_STATIC_PARAMS_TI_INITIATOR = 0x0,
    MLX5_TRANSPORT_STATIC_PARAMS_TI_TARGET = 0x1,
};

struct mlx5_seg_nvmeotcp_progress_params {
    __be32 tir_num;
    uint8_t ctx[DEVX_ST_SZ_BYTES(nvmeotcp_progress_params)];
};

struct mlx5e_set_nvmeotcp_progress_params_wqe {
    struct mlx5_wqe ctrl;
    struct mlx5_seg_nvmeotcp_progress_params params;
};

struct mlx5_wqe_transport_static_params_seg {
    uint8_t ctx[DEVX_ST_SZ_BYTES(transport_static_params)];
};

struct mlx5e_set_transport_static_params_wqe {
    mlx5_wqe ctrl;
    xlio_mlx5_wqe_umr_ctrl_seg uctrl;
    mlx5_mkey_seg mkc;
    mlx5_wqe_transport_static_params_seg params;
};

/* WQE control segment fence flags */
enum {
    MLX5_FENCE_MODE_NONE = 0 << 5,
    MLX5_FENCE_MODE_INITIATOR_SMALL = 1 << 5,
    MLX5_FENCE_MODE_FENCE = 2 << 5,
    MLX5_FENCE_MODE_STRONG_ORDERING = 3 << 5,
    MLX5_FENCE_MODE_SMALL_AND_FENCE = 4 << 5,
};

/* UMR WQE control segment flags */
enum {
    MLX5_UMR_TRANSLATION_OFFSET_EN = (1 << 4),

    MLX5_UMR_CHECK_NOT_FREE = (1 << 5),
    MLX5_UMR_CHECK_FREE = (2 << 5),

    MLX5_UMR_INLINE = (1 << 7),
};

/* WQE related sizes */
enum {
    MLX5_SEND_WQE_DS = 16,
    // MLX5_SEND_WQE_BB = 64,  // Declared in mlx5dv.h
};

/* TLS static parameters opmode */
enum {
    MLX5_OPC_MOD_TLS_TIS_STATIC_PARAMS = 0x1,
    MLX5_OPC_MOD_TLS_TIR_STATIC_PARAMS = 0x2,
};

/* TLS progress parameters opmode */
enum {
    MLX5_OPC_MOD_TLS_TIS_PROGRESS_PARAMS = 0x1,
    MLX5_OPC_MOD_TLS_TIR_PROGRESS_PARAMS = 0x2,
};

/* TLS static parameters TLS version */
enum {
    MLX5E_STATIC_PARAMS_CONTEXT_TLS_1_2 = 0x2,
    MLX5E_STATIC_PARAMS_CONTEXT_TLS_1_3 = 0x3,
};

/* TLS static parameters encryption standard */
enum {
    MLX5E_ENCRYPTION_STANDARD_TLS = 0x1,
};

/* TLS progress parameters */

enum {
    MLX5E_TLS_PROGRESS_PARAMS_AUTH_STATE_NO_OFFLOAD = 0,
    MLX5E_TLS_PROGRESS_PARAMS_AUTH_STATE_OFFLOAD = 1,
    MLX5E_TLS_PROGRESS_PARAMS_AUTH_STATE_AUTHENTICATION = 2,
};

enum {
    MLX5E_TLS_PROGRESS_PARAMS_RECORD_TRACKER_STATE_START = 0,
    MLX5E_TLS_PROGRESS_PARAMS_RECORD_TRACKER_STATE_TRACKING = 1,
    MLX5E_TLS_PROGRESS_PARAMS_RECORD_TRACKER_STATE_SEARCHING = 2,
};

/* WQE offsets */
#define MLX5_WQE_CTRL_DS_MASK             0x3f
#define MLX5_WQE_CTRL_QPN_MASK            0xffffff00
#define MLX5_WQE_CTRL_QPN_SHIFT           8
#define MLX5_WQE_DS_UNITS                 16
#define MLX5_WQE_CTRL_OPCODE_MASK         0xff
#define MLX5_WQE_CTRL_WQE_INDEX_MASK      0x00ffff00
#define MLX5_WQE_CTRL_WQE_INDEX_SHIFT     8
#define MLX5_WQE_CTRL_TIR_TIS_INDEX_SHIFT 8

/*
 * WQE opcode list.
 */
enum {
    XLIO_MLX5_OPCODE_SET_PSV = 0x20,
    XLIO_MLX5_OPCODE_GET_PSV = 0x21,
    XLIO_MLX5_OPCODE_DUMP = 0x23,
    XLIO_MLX5_OPCODE_UMR = 0x25,
};

/*
 * Parameters
 */
#define XLIO_MLX5_PARAMS_LRO_PAYLOAD_SIZE       (64U * 1024U)
#define XLIO_MLX5_PARAMS_LRO_TIMEOUT            32
#define XLIO_MLX5_PARAMS_LRO_TIMEOUT_ARRAY_SIZE 4

/*
 * Interfaces
 */
int xlio_ib_mlx5_get_qp_tx(xlio_ib_mlx5_qp_t *mlx5_qp);
int xlio_ib_mlx5_post_recv(xlio_ib_mlx5_qp_t *mlx5_qp, struct ibv_recv_wr *wr,
                           struct ibv_recv_wr **bad_wr);

int xlio_ib_mlx5_get_cq(struct ibv_cq *cq, xlio_ib_mlx5_cq_t *mlx5_cq);
int xlio_ib_mlx5_req_notify_cq(xlio_ib_mlx5_cq_t *mlx5_cq, int solicited);
void xlio_ib_mlx5_get_cq_event(xlio_ib_mlx5_cq_t *mlx5_cq, int count);

#endif /* DEFINED_DIRECT_VERBS */

#endif /* _IB_MLX5_H_ */
