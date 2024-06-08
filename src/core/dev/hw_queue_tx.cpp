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

#include <algorithm>
#include <sys/mman.h>
#include <netinet/ip.h>
#include "dev/hw_queue_tx.h"
#include "dev/ring_simple.h"
#include "dev/cq_mgr_rx_regrq.h"
#include "proto/tls.h"
#include "util/valgrind.h"

#undef MODULE_NAME
#define MODULE_NAME "hw_queue_tx"

#define hwqtx_logpanic   __log_info_panic
#define hwqtx_logerr     __log_info_err
#define hwqtx_logwarn    __log_info_warn
#define hwqtx_loginfo    __log_info_info
#define hwqtx_logdbg     __log_info_dbg
#define hwqtx_logfunc    __log_info_func
#define hwqtx_logfuncall __log_info_funcall

#if !defined(MLX5_ETH_INLINE_HEADER_SIZE)
#define MLX5_ETH_INLINE_HEADER_SIZE 18
#endif

#define OCTOWORD 16
#define WQEBB    64

//#define DBG_DUMP_WQE 1

#ifdef DBG_DUMP_WQE
#define dbg_dump_wqe(_addr, _size)                                                                 \
    {                                                                                              \
        uint32_t *_wqe = _addr;                                                                    \
        hwqtx_logfunc("Dumping %d bytes from %p", _size, _wqe);                                    \
        for (int i = 0; i < (int)_size / 4; i += 4) {                                              \
            qp_logfunc("%08x %08x %08x %08x", ntohl(_wqe[i + 0]), ntohl(_wqe[i + 1]),              \
                       ntohl(_wqe[i + 2]), ntohl(_wqe[i + 3]));                                    \
        }                                                                                          \
    }
#else
#define dbg_dump_wqe(_addr, _size)
#endif

static inline uint64_t align_to_octoword_up(uint64_t val)
{
    return ((val + 16 - 1) >> 4) << 4;
}

static inline uint64_t align_to_WQEBB_up(uint64_t val)
{
    return ((val + 4 - 1) >> 2) << 2;
}

static bool is_bf(struct ibv_context *ib_ctx)
{
    char *env;

    /* This limitation is done for RM: 1557652, 1894523, 1914464, 2069198 */
    if (safe_mce_sys().hypervisor != mce_sys_var::HYPER_NONE) {
        return false;
    }

    env = getenv("MLX5_SHUT_UP_BF");
    if (!env || !strcmp(env, "0")) {
        struct mlx5dv_devx_uar *uar = mlx5dv_devx_alloc_uar(ib_ctx, MLX5DV_UAR_ALLOC_TYPE_BF);
        if (uar) {
            mlx5dv_devx_free_uar(uar);
            return true;
        }
    }

    return false;
}

// Maps xlio_ibv_wr_opcode to real MLX5 opcode.
static inline uint32_t get_mlx5_opcode(xlio_ibv_wr_opcode verbs_opcode)
{
    switch (verbs_opcode) {
    case XLIO_IBV_WR_SEND:
        return MLX5_OPCODE_SEND;
    case XLIO_IBV_WR_TSO:
        return MLX5_OPCODE_TSO;
    case XLIO_IBV_WR_NOP:
        return MLX5_OPCODE_NOP;
    default:
        return MLX5_OPCODE_SEND;
    }
}

hw_queue_tx::hw_queue_tx(ring_simple *ring, const slave_data_t *slave, const uint32_t tx_num_wr)
    : m_p_ring(ring)
    , m_p_ib_ctx_handler(slave->p_ib_ctx)
    , m_n_sysvar_tx_num_wr_to_signal(safe_mce_sys().tx_num_wr_to_signal)
    , m_tx_num_wr(tx_num_wr)
    , m_port_num(slave->port_num)
{
    hwqtx_logfunc("");

    memset(&m_mlx5_qp, 0, sizeof(m_mlx5_qp));

    m_mlx5_qp.cap.max_inline_data = safe_mce_sys().tx_max_inline;
    m_mlx5_qp.cap.max_send_sge =
        (m_p_ring->is_tso() ? m_p_ib_ctx_handler->get_ibv_device_attr()->max_sge
                            : MCE_DEFAULT_TX_NUM_SGE);

    memset(&m_rate_limit, 0, sizeof(struct xlio_rate_limit_t));

    // Check device capabilities for dummy send support
    m_hw_dummy_send_support = xlio_is_nop_supported(m_p_ib_ctx_handler->get_ibv_device_attr());

    if (configure(slave)) {
        throw_xlio_exception("Failed to configure");
    }
}

hw_queue_tx::~hw_queue_tx()
{
    hwqtx_logfunc("");

    if (m_sq_wqe_idx_to_prop) {
        if (0 != munmap(m_sq_wqe_idx_to_prop, m_tx_num_wr * sizeof(*m_sq_wqe_idx_to_prop))) {
            hwqtx_logerr(
                "Failed deallocating memory with munmap m_sq_wqe_idx_to_prop (errno=%d %m)", errno);
        }
        m_sq_wqe_idx_to_prop = nullptr;
    }

    destroy_tis_cache();

    hwqtx_logdbg("calling ibv_destroy_qp(qp=%p)", m_mlx5_qp.qp);
    if (m_mlx5_qp.qp) {
        IF_VERBS_FAILURE_EX(ibv_destroy_qp(m_mlx5_qp.qp), EIO)
        {
            hwqtx_logdbg("QP destroy failure (errno = %d %m)", -errno);
        }
        ENDIF_VERBS_FAILURE;
        VALGRIND_MAKE_MEM_UNDEFINED(m_mlx5_qp.qp, sizeof(ibv_qp));
        m_mlx5_qp.qp = nullptr;
    }

    if (m_p_cq_mgr_tx) {
        delete m_p_cq_mgr_tx;
        m_p_cq_mgr_tx = nullptr;
    }

    if (m_p_cq_mgr_rx_unused) {
        delete m_p_cq_mgr_rx_unused;
        m_p_cq_mgr_rx_unused = nullptr;
    }

    hwqtx_logdbg("Destructor hw_queue_tx end");
}

int hw_queue_tx::configure(const slave_data_t *slave)
{
    hwqtx_logdbg("Creating QP of transport type '%s' on ibv device '%s' [%p] on port %d",
                 priv_xlio_transport_type_str(m_p_ring->get_transport_type()),
                 m_p_ib_ctx_handler->get_ibname(), m_p_ib_ctx_handler->get_ibv_device(),
                 m_port_num);
    hwqtx_logdbg("HW Dummy send support for QP = %d", m_hw_dummy_send_support);

    // Create associated cq_mgr_tx and unused cq_mgr_rx_regrq just for QP sake.
    BULLSEYE_EXCLUDE_BLOCK_START
    m_p_cq_mgr_tx = init_tx_cq_mgr();
    if (!m_p_cq_mgr_tx) {
        hwqtx_logerr("Failed allocating m_p_cq_mgr_tx (errno=%d %m)", errno);
        return -1;
    }
    m_p_cq_mgr_rx_unused = new cq_mgr_rx_regrq(m_p_ring, m_p_ib_ctx_handler, 2, nullptr);
    if (!m_p_cq_mgr_rx_unused) {
        hwqtx_logerr("Failed allocating m_p_cq_mgr_rx_unused (errno=%d %m)", errno);
        return -1;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    // Modify the cq_mgr_tx to use a non-blocking event channel
    set_fd_block_mode(m_p_cq_mgr_tx->get_channel_fd(), false);
    hwqtx_logdbg("cq tx: %p", m_p_cq_mgr_tx);

    // Create QP
    xlio_ibv_qp_init_attr qp_init_attr;
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));

    // TODO: m_tx_num_wr and m_rx_num_wr should be part of m_mlx5_qp.cap
    // and assigned as a result of ibv_query_qp()
    m_mlx5_qp.cap.max_send_wr = m_tx_num_wr;
    m_mlx5_qp.cap.max_recv_wr = 1;
    m_mlx5_qp.cap.max_recv_sge = 1;

    memcpy(&qp_init_attr.cap, &m_mlx5_qp.cap, sizeof(qp_init_attr.cap));
    qp_init_attr.recv_cq = m_p_cq_mgr_rx_unused->get_ibv_cq_hndl();
    qp_init_attr.send_cq = m_p_cq_mgr_tx->get_ibv_cq_hndl();
    qp_init_attr.sq_sig_all = 0;

    // In case of enabled TSO we need to take into account amount of SGE together with header inline
    // Per PRM maximum of CTRL + ETH + ETH_HEADER_INLINE+DATA_PTR*NUM_SGE+MAX_INLINE+INLINE_SIZE
    // MLX5 return 32678 WQEBBs at max so minimal number
    int max_wqe_sz =
        16 + 14 + 16 * qp_init_attr.cap.max_send_sge + qp_init_attr.cap.max_inline_data + 4;
    max_wqe_sz += (m_p_ring->is_tso() ? m_p_ring->m_tso.max_header_sz : 94);
    int num_wr = 32678 * 64 / max_wqe_sz;
    hwqtx_logdbg("calculated max_wqe_sz=%d num_wr=%d", max_wqe_sz, num_wr);
    if (num_wr < (signed)m_tx_num_wr) {
        qp_init_attr.cap.max_send_wr =
            num_wr; // force min for create_qp or you will have error of memory allocation
    }

    hwqtx_logdbg("Requested QP parameters: wre: tx = %d sge: tx = %d inline: %d",
                 qp_init_attr.cap.max_send_wr, qp_init_attr.cap.max_send_sge,
                 qp_init_attr.cap.max_inline_data);

    // Create the HW Queue
    if (prepare_queue(qp_init_attr)) {
        return -1;
    }

    hwqtx_logdbg("Configured QP parameters: wre: tx = %d sge: tx = %d inline: %d",
                 qp_init_attr.cap.max_send_wr, qp_init_attr.cap.max_send_sge,
                 qp_init_attr.cap.max_inline_data);

    /* Check initial parameters with actual */
    enum ibv_qp_attr_mask attr_mask = IBV_QP_CAP;
    struct ibv_qp_attr tmp_ibv_qp_attr;
    struct ibv_qp_init_attr tmp_ibv_qp_init_attr;
    IF_VERBS_FAILURE(ibv_query_qp(m_mlx5_qp.qp, &tmp_ibv_qp_attr, attr_mask, &tmp_ibv_qp_init_attr))
    {
        hwqtx_logerr("ibv_query_qp failed (errno=%d %m)", errno);
        return -1;
    }
    ENDIF_VERBS_FAILURE;
    m_mlx5_qp.cap.max_send_wr =
        std::min(tmp_ibv_qp_attr.cap.max_send_wr, m_mlx5_qp.cap.max_send_wr);
    m_mlx5_qp.cap.max_send_sge =
        std::min(tmp_ibv_qp_attr.cap.max_send_sge, m_mlx5_qp.cap.max_send_sge);
    m_mlx5_qp.cap.max_inline_data =
        std::min(tmp_ibv_qp_attr.cap.max_inline_data, m_mlx5_qp.cap.max_inline_data);

    hwqtx_logdbg("Used QP (num=%d) wre: tx = %d sge: tx = %d inline: %d", m_mlx5_qp.qp->qp_num,
                 m_mlx5_qp.cap.max_send_wr, m_mlx5_qp.cap.max_send_sge,
                 m_mlx5_qp.cap.max_inline_data);

#if defined(DEFINED_ROCE_LAG)
    if (slave && slave->lag_tx_port_affinity > 0) {
        struct mlx5dv_context attr_out;

        memset(&attr_out, 0, sizeof(attr_out));
        attr_out.comp_mask |= MLX5DV_CONTEXT_MASK_NUM_LAG_PORTS;
        if (!mlx5dv_query_device(slave->p_ib_ctx->get_ibv_context(), &attr_out)) {
            hwqtx_logdbg("QP ROCE LAG port: %d of %d", slave->lag_tx_port_affinity,
                         attr_out.num_lag_ports);

            if (!mlx5dv_modify_qp_lag_port(m_mlx5_qp.qp, slave->lag_tx_port_affinity)) {
                uint8_t current_port_num = 0;
                uint8_t active_port_num = 0;

                if (!mlx5dv_query_qp_lag_port(m_mlx5_qp.qp, &current_port_num, &active_port_num)) {
                    hwqtx_logdbg("QP ROCE LAG port affinity: %d => %d", current_port_num,
                                 active_port_num);
                }
            }
        }
    }
#endif /* DEFINED_ROCE_LAG */
    NOT_IN_USE(slave);
    return 0;
}

void hw_queue_tx::up()
{
    init_queue();

    // Add buffers
    hwqtx_logdbg("QP current state: %d", priv_ibv_query_qp_state(m_mlx5_qp.qp));

    m_p_cq_mgr_tx->add_qp_tx(this);

    release_tx_buffers();

    modify_queue_to_ready_state();

    init_device_memory();
}

void hw_queue_tx::down()
{
    if (m_dm_enabled) {
        m_dm_mgr.release_resources();
    }

    hwqtx_logdbg("QP current state: %d", priv_ibv_query_qp_state(m_mlx5_qp.qp));
    modify_queue_to_error_state();

    // free buffers from current active resource iterator
    trigger_completion_for_all_sent_packets();

    // let the QP drain all wqe's to flushed cqe's now that we moved
    // it to error state and post_sent final trigger for completion
    usleep(1000);

    release_tx_buffers();
    m_p_cq_mgr_tx->del_qp_tx(this);
}

void hw_queue_tx::release_tx_buffers()
{
    int ret;
    uint64_t poll_sn = 0;
    hwqtx_logdbg("draining cq_mgr_tx %p", m_p_cq_mgr_tx);
    while (m_p_cq_mgr_tx && m_mlx5_qp.qp &&
           ((ret = m_p_cq_mgr_tx->poll_and_process_element_tx(&poll_sn)) > 0) &&
           (errno != EIO && !m_p_ib_ctx_handler->is_removed())) {
        hwqtx_logdbg("draining completed on cq_mgr_tx (%d wce)", ret);
    }
    NOT_IN_USE(ret); // Suppress --enable-opt-log=high warning
}

void hw_queue_tx::send_wqe(xlio_ibv_send_wr *p_send_wqe, xlio_wr_tx_packet_attr attr, xlio_tis *tis,
                           unsigned credits)
{
    mem_buf_desc_t *p_mem_buf_desc = (mem_buf_desc_t *)p_send_wqe->wr_id;
    /* Control tx completions:
     * - XLIO_TX_WRE_BATCHING - The number of Tx Work Request Elements used
     *   until a completion signal is requested.
     * - ZCOPY packets should notify application as soon as possible to
     *   confirm one that user buffers are free to reuse. So force completion
     *   signal for such work requests.
     * - First call of send() should do completion. It means that
     *   m_n_unsignaled_count must be zero for this time.
     */
    bool request_comp = (p_mem_buf_desc->m_flags & mem_buf_desc_t::ZCOPY);

    hwqtx_logfunc("VERBS send, unsignaled_count: %d", m_n_unsignaled_count);

    send_to_wire(p_send_wqe, attr, request_comp, tis, credits);

    if (request_comp || is_signal_requested_for_last_wqe()) {
        uint64_t dummy_poll_sn = 0;
        int ret = m_p_cq_mgr_tx->poll_and_process_element_tx(&dummy_poll_sn);
        BULLSEYE_EXCLUDE_BLOCK_START
        if (ret < 0) {
            hwqtx_logerr("error from cq_mgr_tx->process_next_element (ret=%d %m)", ret);
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        hwqtx_logfunc("polling succeeded on cq_mgr_tx (%d wce)", ret);
    }
}

void hw_queue_tx::modify_queue_to_ready_state()
{
    hwqtx_logdbg("");
    int ret = 0;
    int qp_state = priv_ibv_query_qp_state(m_mlx5_qp.qp);
    if (qp_state != IBV_QPS_INIT) {
        BULLSEYE_EXCLUDE_BLOCK_START
        if ((ret = priv_ibv_modify_qp_from_err_to_init_raw(m_mlx5_qp.qp, m_port_num)) != 0) {
            hwqtx_logpanic("failed to modify QP from %d to RTS state (ret = %d)", qp_state, ret);
        }
        BULLSEYE_EXCLUDE_BLOCK_END
    }

    BULLSEYE_EXCLUDE_BLOCK_START
    if ((ret = priv_ibv_modify_qp_from_init_to_rts(m_mlx5_qp.qp)) != 0) {
        hwqtx_logpanic("failed to modify QP from INIT to RTS state (ret = %d)", ret);
    }

    BULLSEYE_EXCLUDE_BLOCK_END
}

void hw_queue_tx::modify_queue_to_error_state()
{
    hwqtx_logdbg("");

    BULLSEYE_EXCLUDE_BLOCK_START
    if (priv_ibv_modify_qp_to_err(m_mlx5_qp.qp)) {
        hwqtx_logdbg("ibv_modify_qp failure (errno = %d %m)", errno);
    }
    BULLSEYE_EXCLUDE_BLOCK_END
}

int hw_queue_tx::prepare_queue(xlio_ibv_qp_init_attr &qp_init_attr)
{
    hwqtx_logdbg("");
    int ret = 0;

    qp_init_attr.qp_type = IBV_QPT_RAW_PACKET;
    xlio_ibv_qp_init_attr_comp_mask(m_p_ib_ctx_handler->get_ibv_pd(), qp_init_attr);

    if (m_p_ring->is_tso()) {
        xlio_ibv_qp_init_attr_tso(qp_init_attr, m_p_ring->get_max_header_sz());
        hwqtx_logdbg("create qp with max_tso_header = %d", m_p_ring->get_max_header_sz());
    }

    m_mlx5_qp.qp = xlio_ibv_create_qp(m_p_ib_ctx_handler->get_ibv_pd(), &qp_init_attr);

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!m_mlx5_qp.qp) {
        hwqtx_logerr("ibv_create_qp failed (errno=%d %m)", errno);
        return -1;
    }
    VALGRIND_MAKE_MEM_DEFINED(m_mlx5_qp.qp, sizeof(ibv_qp));
    if ((ret = priv_ibv_modify_qp_from_err_to_init_raw(m_mlx5_qp.qp, m_port_num)) != 0) {
        hwqtx_logerr("failed to modify QP from ERR to INIT state (ret = %d)", ret);
        return ret;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return 0;
}

void hw_queue_tx::init_queue()
{
    if (0 != xlio_ib_mlx5_get_qp_tx(&m_mlx5_qp)) {
        hwqtx_logpanic("xlio_ib_mlx5_get_qp_tx failed (errno=%d %m)", errno);
    }

    m_sq_wqes = (struct mlx5_eth_wqe(*)[])(uintptr_t)m_mlx5_qp.sq.buf;
    m_sq_wqes_end =
        (uint8_t *)((uintptr_t)m_mlx5_qp.sq.buf + m_mlx5_qp.sq.wqe_cnt * m_mlx5_qp.sq.stride);
    m_sq_wqe_last = &(*m_sq_wqes)[0];
    m_sq_wqe_last_index = 0;
    m_sq_wqe_counter = 0;

    uint32_t old_wr_val = m_tx_num_wr;
    m_tx_num_wr = (m_sq_wqes_end - (uint8_t *)m_sq_wqe_last) / WQEBB;

    // We use the min between CQ size and the QP size (that might be increases by ibv creation).
    m_sq_free_credits = std::min(m_tx_num_wr, old_wr_val);

    /* Maximum BF inlining consists of:
     * - CTRL:
     *   - 1st WQEBB is mostly used for CTRL and ETH segment (where ETH header is inlined)
     *   - 4 bytes for size of inline data
     * - DATA:
     *   - 1 OCTOWORD from 1st WQEBB is used for data inlining, except for
     *     the 4 bytes used for stating the inline data size
     *   - 3 WQEBB are fully availabie for data inlining
     */
    m_mlx5_qp.cap.max_inline_data = OCTOWORD - 4 + 3 * WQEBB;

    if (!m_sq_wqe_idx_to_prop) {
        m_sq_wqe_idx_to_prop =
            (sq_wqe_prop *)mmap(nullptr, m_tx_num_wr * sizeof(*m_sq_wqe_idx_to_prop),
                                PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (m_sq_wqe_idx_to_prop == MAP_FAILED) {
            hwqtx_logerr("Failed allocating m_sq_wqe_idx_to_prop (errno=%d %m)", errno);
            return;
        }
        m_sq_wqe_prop_last_signalled = m_tx_num_wr - 1;
        m_sq_wqe_prop_last = nullptr;
    }

    hwqtx_logfunc("m_tx_num_wr=%d max_inline_data: %d m_sq_wqe_idx_to_prop=%p", m_tx_num_wr,
                  get_max_inline_data(), m_sq_wqe_idx_to_prop);

    hwqtx_logfunc("%p allocated for %d QPs sq_wqes:%p sq_wqes_end: %p and configured %d WRs "
                  "BlueFlame: %p",
                  m_mlx5_qp.qp, m_mlx5_qp.qpn, m_sq_wqes, m_sq_wqes_end, m_tx_num_wr,
                  m_mlx5_qp.bf.reg);
}

void hw_queue_tx::init_device_memory()
{
    /* This limitation is done because of a observation
     * that dm_copy takes a lot of time on VMs w/o BF (RM:1542628)
     */
    if (m_p_ib_ctx_handler->get_on_device_memory_size() > 0 &&
        is_bf(m_p_ib_ctx_handler->get_ibv_context())) {
        m_dm_enabled =
            m_dm_mgr.allocate_resources(m_p_ib_ctx_handler, m_p_ring->m_p_ring_stat.get());
    }
}

void hw_queue_tx::update_wqe_last()
{
    m_sq_wqe_last_index = m_sq_wqe_counter & (m_tx_num_wr - 1);
    m_sq_wqe_last = &(*m_sq_wqes)[m_sq_wqe_last_index];
}

cq_mgr_tx *hw_queue_tx::init_tx_cq_mgr()
{
    m_tx_num_wr = align32pow2(m_tx_num_wr);
    return new cq_mgr_tx(m_p_ring, m_p_ib_ctx_handler, m_tx_num_wr,
                         m_p_ring->get_tx_comp_event_channel());
}

inline void hw_queue_tx::ring_doorbell(int num_wqebb, bool skip_comp /*=false*/)
{
    uint64_t *dst = (uint64_t *)m_mlx5_qp.bf.reg;
    uint64_t *src = reinterpret_cast<uint64_t *>(m_sq_wqe_last);
    struct xlio_mlx5_wqe_ctrl_seg *ctrl = reinterpret_cast<struct xlio_mlx5_wqe_ctrl_seg *>(src);

    /* TODO Refactor m_n_unsignedled_count, is_completion_need(), set_unsignaled_count():
     * Some logic is hidden inside the methods and in one branch the field is changed directly.
     */
    if (!skip_comp && is_completion_need()) {
        ctrl->fm_ce_se |= MLX5_WQE_CTRL_CQ_UPDATE;
    }
    if (ctrl->fm_ce_se & MLX5_WQE_CTRL_CQ_UPDATE) {
        set_unsignaled_count();
    } else {
        dec_unsignaled_count();
    }
    if (unlikely(m_b_fence_needed)) {
        ctrl->fm_ce_se |= MLX5_FENCE_MODE_INITIATOR_SMALL;
        m_b_fence_needed = false;
    }

    m_sq_wqe_counter = (m_sq_wqe_counter + num_wqebb) & 0xFFFF;

    // Make sure that descriptors are written before
    // updating doorbell record and ringing the doorbell
    wmb();
    *m_mlx5_qp.sq.dbrec = htonl(m_sq_wqe_counter);

    // This wc_wmb ensures ordering between DB record and BF copy
    wc_wmb();
    *dst = *src;

    /* Use wc_wmb() to ensure write combining buffers are flushed out
     * of the running CPU.
     * sfence instruction affects only the WC buffers of the CPU that executes it
     */
    wc_wmb();
}

inline int hw_queue_tx::fill_inl_segment(sg_array &sga, uint8_t *cur_seg, uint8_t *data_addr,
                                         int max_inline_len, int inline_len)
{
    int wqe_inline_size = 0;
    while ((data_addr) && inline_len) {
        dbg_dump_wqe((uint32_t *)data_addr, inline_len);
        memcpy(cur_seg, data_addr, inline_len);
        wqe_inline_size += inline_len;
        cur_seg += inline_len;
        inline_len = max_inline_len - wqe_inline_size;
        data_addr = sga.get_data(&inline_len);
        hwqtx_logfunc("data_addr:%p cur_seg: %p inline_len: %d wqe_inline_size: %d", data_addr,
                      cur_seg, inline_len, wqe_inline_size);
    }
    return wqe_inline_size;
}

inline int hw_queue_tx::fill_wqe_inline(xlio_ibv_send_wr *pswr)
{
    sg_array sga(pswr->sg_list, pswr->num_sge);
    uint8_t *cur_seg = (uint8_t *)m_sq_wqe_last + sizeof(struct mlx5_wqe_ctrl_seg);
    int inline_len = MLX5_ETH_INLINE_HEADER_SIZE;
    int data_len = sga.length();
    int wqe_size = sizeof(struct mlx5_wqe_ctrl_seg) / OCTOWORD;
    int max_inline_len = get_max_inline_data();

    uint8_t *data_addr = sga.get_data(&inline_len); // data for inlining in ETH header

    m_sq_wqe_last->eseg.inline_hdr_sz = htons(MLX5_ETH_INLINE_HEADER_SIZE);

    data_len -= inline_len;
    hwqtx_logfunc(
        "wqe_last:%p num_sge: %d data_addr: %p data_len: %d max_inline_len: %d inline_len: %d",
        m_sq_wqe_last, pswr->num_sge, data_addr, data_len, max_inline_len, inline_len);

    // Fill Ethernet segment with header inline, static data
    // were populated in preset after previous packet send
    memcpy(cur_seg + offsetof(struct mlx5_wqe_eth_seg, inline_hdr_start), data_addr,
           MLX5_ETH_INLINE_HEADER_SIZE);
    cur_seg += sizeof(struct mlx5_wqe_eth_seg);
    wqe_size += sizeof(struct mlx5_wqe_eth_seg) / OCTOWORD;

    max_inline_len = data_len;
    // Filling inline data segment
    // size of BlueFlame buffer is 4*WQEBBs, 3*OCTOWORDS of the first
    // was allocated for control and ethernet segment so we have 3*WQEBB+16-4
    int rest_space = std::min((int)(m_sq_wqes_end - cur_seg - 4), (3 * WQEBB + OCTOWORD - 4));
    // Filling till the end of inline WQE segment or
    // to end of WQEs
    if (likely(max_inline_len <= rest_space)) {
        inline_len = max_inline_len;
        hwqtx_logfunc("data_addr:%p cur_seg: %p rest_space: %d inline_len: %d wqe_size: %d",
                      data_addr, cur_seg, rest_space, inline_len, wqe_size);
        // bypass inline size and fill inline data segment
        data_addr = sga.get_data(&inline_len);
        inline_len = fill_inl_segment(sga, cur_seg + 4, data_addr, max_inline_len, inline_len);

        // store inline data size and mark the data as inlined
        *(uint32_t *)((uint8_t *)m_sq_wqe_last + sizeof(struct mlx5_wqe_ctrl_seg) +
                      sizeof(struct mlx5_wqe_eth_seg)) = htonl(0x80000000 | inline_len);
        rest_space = align_to_octoword_up(inline_len + 4); // align to OCTOWORDs
        wqe_size += rest_space / OCTOWORD;
        // assert((data_len-inline_len)==0);
        // configuring control
        m_sq_wqe_last->ctrl.data[1] = htonl((m_mlx5_qp.qpn << 8) | wqe_size);
        rest_space = align_to_WQEBB_up(wqe_size) / 4;
        hwqtx_logfunc("data_len: %d inline_len: %d wqe_size: %d wqebbs: %d", data_len - inline_len,
                      inline_len, wqe_size, rest_space);
        ring_doorbell(rest_space);
        return rest_space;
    } else {
        // wrap around case, first filling till the end of m_sq_wqes
        int wrap_up_size = max_inline_len - rest_space;
        inline_len = rest_space;
        hwqtx_logfunc("WRAP_UP_SIZE: %d data_addr:%p cur_seg: %p rest_space: %d inline_len: %d "
                      "wqe_size: %d",
                      wrap_up_size, data_addr, cur_seg, rest_space, inline_len, wqe_size);

        data_addr = sga.get_data(&inline_len);
        inline_len = fill_inl_segment(sga, cur_seg + 4, data_addr, rest_space, inline_len);
        data_len -= inline_len;
        rest_space = align_to_octoword_up(inline_len + 4);
        wqe_size += rest_space / OCTOWORD;
        rest_space = align_to_WQEBB_up(rest_space / OCTOWORD) / 4; // size of 1st chunk at the end

        hwqtx_logfunc("END chunk data_addr: %p data_len: %d inline_len: %d wqe_size: %d wqebbs: %d",
                      data_addr, data_len, inline_len, wqe_size, rest_space);
        // Wrap around
        //
        cur_seg = (uint8_t *)m_sq_wqes;
        data_addr = sga.get_data(&wrap_up_size);

        wrap_up_size = fill_inl_segment(sga, cur_seg, data_addr, data_len, wrap_up_size);
        inline_len += wrap_up_size;
        max_inline_len = align_to_octoword_up(wrap_up_size);
        wqe_size += max_inline_len / OCTOWORD;
        max_inline_len = align_to_WQEBB_up(max_inline_len / OCTOWORD) / 4;
        // store inline data size
        *(uint32_t *)((uint8_t *)m_sq_wqe_last + sizeof(struct mlx5_wqe_ctrl_seg) +
                      sizeof(struct mlx5_wqe_eth_seg)) = htonl(0x80000000 | inline_len);
        hwqtx_logfunc("BEGIN_CHUNK data_addr: %p data_len: %d wqe_size: %d inline_len: %d "
                      "end_wqebbs: %d wqebbs: %d",
                      data_addr, data_len - wrap_up_size, wqe_size, inline_len + wrap_up_size,
                      rest_space, max_inline_len);
        // assert((data_len-wrap_up_size)==0);
        // configuring control
        m_sq_wqe_last->ctrl.data[1] = htonl((m_mlx5_qp.qpn << 8) | wqe_size);

        dbg_dump_wqe((uint32_t *)m_sq_wqe_last, rest_space * 4 * 16);
        dbg_dump_wqe((uint32_t *)m_sq_wqes, max_inline_len * 4 * 16);

        ring_doorbell(rest_space + max_inline_len);
        return rest_space + max_inline_len;
    }
}

//! Fill WQE dynamically, based on amount of free WQEBB in SQ
inline int hw_queue_tx::fill_wqe(xlio_ibv_send_wr *pswr)
{
    if (pswr->num_sge == 1 && pswr->sg_list[0].length <= get_max_inline_data() &&
        xlio_send_wr_opcode(*pswr) == XLIO_IBV_WR_SEND) {
        // Packet is fully inline
        return fill_wqe_inline(pswr);
    } else {
        if (xlio_send_wr_opcode(*pswr) == XLIO_IBV_WR_SEND) {
            // Data is bigger than max to inline
            return fill_wqe_send(pswr);
        } else {
            // Support XLIO_IBV_WR_SEND_TSO operation
            return fill_wqe_lso(pswr);
        }
    }
}

inline int hw_queue_tx::fill_wqe_send(xlio_ibv_send_wr *pswr)
{
    struct mlx5_wqe_eth_seg *eseg;
    struct mlx5_wqe_data_seg *dseg;
    int wqe_size = sizeof(mlx5_wqe_ctrl_seg) / OCTOWORD;

    eseg = (struct mlx5_wqe_eth_seg *)((uint8_t *)m_sq_wqe_last + sizeof(mlx5_wqe_ctrl_seg));

    /* Unlike Linux kernel, rdma-core defines mlx5_wqe_eth_seg as 32 bytes, because it contains
     * 18 bytes of inline header. We don't want to inline partial header to avoid an extra copy
     * and code complication. Therefore, we cannot rely on the structure definition and need to
     * hardcode 16 bytes here.
     */
    wqe_size += 1;
    dseg = (struct mlx5_wqe_data_seg *)((uintptr_t)eseg + OCTOWORD);

    for (int i = 0; i < pswr->num_sge; ++i) {
        if (unlikely((uintptr_t)dseg >= (uintptr_t)m_sq_wqes_end)) {
            dseg = (struct mlx5_wqe_data_seg *)m_sq_wqes;
        }
        if (likely(pswr->sg_list[i].length)) {
            dseg->byte_count = htonl(pswr->sg_list[i].length);
            /* Try to copy data to On Device Memory in first */
            if (!(m_dm_enabled &&
                  m_dm_mgr.copy_data(dseg, (uint8_t *)((uintptr_t)pswr->sg_list[i].addr),
                                     pswr->sg_list[i].length, (mem_buf_desc_t *)pswr->wr_id))) {
                dseg->lkey = htonl(pswr->sg_list[i].lkey);
                dseg->addr = htonll((uintptr_t)pswr->sg_list[i].addr);
            }
            ++dseg;
            wqe_size += sizeof(struct mlx5_wqe_data_seg) / OCTOWORD;
        }
    }

    m_sq_wqe_last->ctrl.data[1] = htonl((m_mlx5_qp.qpn << 8) | wqe_size);
    int wqebbs = align_to_WQEBB_up(wqe_size) / 4;
    ring_doorbell(wqebbs);

    return wqebbs;
}

//! Filling wqe for LSO
inline int hw_queue_tx::fill_wqe_lso(xlio_ibv_send_wr *pswr)
{
    struct mlx5_wqe_ctrl_seg *ctrl = nullptr;
    struct mlx5_wqe_eth_seg *eseg = nullptr;
    struct mlx5_wqe_data_seg *dpseg = nullptr;
    uint8_t *cur_seg = nullptr;
    uint8_t *p_hdr = (uint8_t *)pswr->tso.hdr;
    int inl_hdr_size = pswr->tso.hdr_sz;
    int inl_hdr_copy_size = 0;
    int max_inline_len = align_to_octoword_up(sizeof(struct mlx5_wqe_eth_seg) + inl_hdr_size -
                                              MLX5_ETH_INLINE_HEADER_SIZE);
    int wqe_size = sizeof(struct mlx5_wqe_ctrl_seg) / OCTOWORD;
    int rest = 0;
    int i = 0;

    ctrl = (struct mlx5_wqe_ctrl_seg *)m_sq_wqe_last;

    /* Do usual send operation in case payload less than mss */
    if (0 == pswr->tso.mss) {
        ctrl->opmod_idx_opcode =
            htonl(((m_sq_wqe_counter & 0xffff) << 8) | (get_mlx5_opcode(XLIO_IBV_WR_SEND) & 0xff));
    }

    eseg = (struct mlx5_wqe_eth_seg *)((uint8_t *)m_sq_wqe_last + sizeof(*ctrl));
    eseg->mss = htons(pswr->tso.mss);
    eseg->inline_hdr_sz = htons(inl_hdr_size);

    rest = (int)((uintptr_t)(void *)m_sq_wqes_end - (uintptr_t)(void *)eseg);
    cur_seg = (uint8_t *)eseg;

    if (likely(max_inline_len <= rest)) {
        // Fill Ethernet segment with full header inline
        inl_hdr_copy_size = inl_hdr_size;
        memcpy(eseg->inline_hdr_start, p_hdr, inl_hdr_copy_size);
        cur_seg += max_inline_len;
    } else {
        // wrap around SQ on inline ethernet header
        inl_hdr_copy_size = rest - offsetof(struct mlx5_wqe_eth_seg, inline_hdr_start);
        memcpy(eseg->inline_hdr_start, p_hdr, inl_hdr_copy_size);
        p_hdr += inl_hdr_copy_size;
        inl_hdr_copy_size = inl_hdr_size - inl_hdr_copy_size;
        memcpy(m_sq_wqes, p_hdr, inl_hdr_copy_size);
        max_inline_len = align_to_octoword_up(inl_hdr_copy_size);
        cur_seg = (uint8_t *)m_sq_wqes + max_inline_len;
        wqe_size += rest / OCTOWORD;
    }
    wqe_size += max_inline_len / OCTOWORD;
    hwqtx_logfunc("TSO: num_sge: %d max_inline_len: %d inl_hdr_size: %d rest: %d", pswr->num_sge,
                  max_inline_len, inl_hdr_size, rest);
    // Filling data pointer segments with payload by scatter-gather list elements
    dpseg = (struct mlx5_wqe_data_seg *)cur_seg;
    for (i = 0; i < pswr->num_sge; i++) {
        if (unlikely((uintptr_t)dpseg >= (uintptr_t)m_sq_wqes_end)) {
            dpseg = (struct mlx5_wqe_data_seg *)m_sq_wqes;
        }
        dpseg->addr = htonll((uint64_t)pswr->sg_list[i].addr);
        dpseg->lkey = htonl(pswr->sg_list[i].lkey);
        dpseg->byte_count = htonl(pswr->sg_list[i].length);

        hwqtx_logfunc("DATA_SEG: addr:%llx len: %d lkey: %x dp_seg: %p wqe_size: %d",
                      pswr->sg_list[i].addr, pswr->sg_list[i].length, dpseg->lkey, dpseg, wqe_size);

        dpseg++;
        wqe_size += sizeof(struct mlx5_wqe_data_seg) / OCTOWORD;
    }
    m_sq_wqe_last->ctrl.data[1] = htonl((m_mlx5_qp.qpn << 8) | wqe_size);

    int wqebbs = align_to_WQEBB_up(wqe_size) / 4;
    ring_doorbell(wqebbs);
    return wqebbs;
}

void hw_queue_tx::store_current_wqe_prop(mem_buf_desc_t *buf, unsigned credits, xlio_ti *ti)
{
    m_sq_wqe_idx_to_prop[m_sq_wqe_last_index] = sq_wqe_prop {
        .buf = buf,
        .credits = credits,
        .ti = ti,
        .next = m_sq_wqe_prop_last,
    };
    m_sq_wqe_prop_last = &m_sq_wqe_idx_to_prop[m_sq_wqe_last_index];
    if (ti) {
        ti->get();
    }
}

//! Send one RAW packet
void hw_queue_tx::send_to_wire(xlio_ibv_send_wr *p_send_wqe, xlio_wr_tx_packet_attr attr,
                               bool request_comp, xlio_tis *tis, unsigned credits)
{
    struct xlio_mlx5_wqe_ctrl_seg *ctrl;
    struct mlx5_wqe_eth_seg *eseg;
    uint32_t tisn = tis ? tis->get_tisn() : 0;

    update_wqe_last();
    memset(m_sq_wqe_last, 0, sizeof(*m_sq_wqe_last));

    ctrl = (struct xlio_mlx5_wqe_ctrl_seg *)m_sq_wqe_last;
    eseg = (struct mlx5_wqe_eth_seg *)((uint8_t *)m_sq_wqe_last + sizeof(*ctrl));

    /* Configure ctrl segment
     * qpn_ds or ctrl.data[1] is set inside fill_wqe()
     */
    ctrl->opmod_idx_opcode = htonl(((m_sq_wqe_counter & 0xffff) << 8) |
                                   (get_mlx5_opcode(xlio_send_wr_opcode(*p_send_wqe)) & 0xff));
    m_sq_wqe_last->ctrl.data[2] = 0;
    ctrl->fm_ce_se = (request_comp ? (uint8_t)MLX5_WQE_CTRL_CQ_UPDATE : 0);
    ctrl->tis_tir_num = htobe32(tisn << 8);

    /* Configure eth segment
     * reset rsvd0, cs_flags, rsvd1, mss and rsvd2 fields
     * checksum flags are set here
     */
    *((uint64_t *)eseg) = 0;
    eseg->rsvd2 = 0;
    eseg->cs_flags = (uint8_t)(attr & (XLIO_TX_PACKET_L3_CSUM | XLIO_TX_PACKET_L4_CSUM) & 0xff);

    /* Store buffer descriptor */
    store_current_wqe_prop(reinterpret_cast<mem_buf_desc_t *>(p_send_wqe->wr_id), credits, tis);

    /* Complete WQE */
    int wqebbs = fill_wqe(p_send_wqe);
    assert(wqebbs > 0 && (unsigned)wqebbs <= credits);
    NOT_IN_USE(wqebbs);

    hwqtx_logfunc(
        "m_sq_wqe_last: %p m_sq_wqe_last_index: %d wqe_counter: %d new_last_index: %d wr_id: %llx",
        m_sq_wqe_last, m_sq_wqe_last_index, m_sq_wqe_counter,
        (m_sq_wqe_counter & (m_tx_num_wr - 1)), p_send_wqe->wr_id);
}

std::unique_ptr<xlio_tis> hw_queue_tx::create_tis(uint32_t flags)
{
    dpcp::adapter *adapter = m_p_ib_ctx_handler->get_dpcp_adapter();
    bool is_tls = flags & dpcp::TIS_ATTR_TLS, is_nvme = flags & dpcp::TIS_ATTR_NVMEOTCP;
    if (unlikely(!adapter || (is_tls && is_nvme))) {
        return nullptr;
    }

    dpcp::tis::attr tis_attr = {
        .flags = flags,
        .tls_en = is_tls,
        .nvmeotcp = is_nvme,
        .transport_domain = adapter->get_td(),
        .pd = adapter->get_pd(),
    };

    dpcp::tis *dpcp_tis = nullptr;
    if (unlikely(adapter->create_tis(tis_attr, dpcp_tis) != dpcp::DPCP_OK)) {
        hwqtx_logerr("Failed to create TIS with NVME enabled");
        return nullptr;
    }

    auto tis_type = is_tls ? xlio_ti::ti_type::TLS_TIS : xlio_ti::ti_type::NVME_TIS;
    return std::make_unique<xlio_tis>(this, std::unique_ptr<dpcp::tis>(dpcp_tis), tis_type);
}

static inline void nvme_fill_static_params_control(xlio_mlx5_wqe_ctrl_seg *cseg,
                                                   xlio_mlx5_wqe_umr_ctrl_seg *ucseg,
                                                   uint32_t producer_index, uint32_t qpn,
                                                   uint32_t tisn, uint8_t fence_flags)
{
    memset(cseg, 0, sizeof(*cseg));
    memset(ucseg, 0, sizeof(*ucseg));
    cseg->opmod_idx_opcode =
        htobe32(((producer_index & 0xffff) << 8) | MLX5_OPCODE_UMR |
                (MLX5_CTRL_SEGMENT_OPC_MOD_UMR_NVMEOTCP_TIS_STATIC_PARAMS << 24));
    size_t num_wqe_ds = 12U;
    cseg->qpn_ds = htobe32((qpn << MLX5_WQE_CTRL_QPN_SHIFT) | num_wqe_ds);
    cseg->fm_ce_se = fence_flags;
    cseg->tis_tir_num = htobe32(tisn << MLX5_WQE_CTRL_TIR_TIS_INDEX_SHIFT);

    ucseg->flags = MLX5_UMR_INLINE;
    ucseg->bsf_octowords = htobe16(MLX5E_TRANSPORT_STATIC_PARAMS_OCTWORD_SIZE);
}

static inline void nvme_fill_static_params_transport_params(
    mlx5_wqe_transport_static_params_seg *params, uint32_t config)

{
    memset(params, 0, sizeof(*params));
    void *ctx = params->ctx;

    DEVX_SET(transport_static_params, ctx, const_1, 1);
    DEVX_SET(transport_static_params, ctx, const_2, 2);
    DEVX_SET(transport_static_params, ctx, acc_type, MLX5_TRANSPORT_STATIC_PARAMS_ACC_TYPE_NVMETCP);
    DEVX_SET(transport_static_params, ctx, nvme_resync_tcp_sn, 0);
    DEVX_SET(transport_static_params, ctx, pda, static_cast<uint8_t>(config & XLIO_NVME_PDA_MASK));
    DEVX_SET(transport_static_params, ctx, ddgst_en, bool(config & XLIO_NVME_DDGST_ENABLE));
    DEVX_SET(transport_static_params, ctx, ddgst_offload_en,
             bool(config & XLIO_NVME_DDGST_OFFLOAD));
    DEVX_SET(transport_static_params, ctx, hddgst_en, bool(config & XLIO_NVME_HDGST_ENABLE));
    DEVX_SET(transport_static_params, ctx, hdgst_offload_en,
             bool(config & XLIO_NVME_HDGST_OFFLOAD));
    DEVX_SET(transport_static_params, ctx, ti, MLX5_TRANSPORT_STATIC_PARAMS_TI_INITIATOR);
    DEVX_SET(transport_static_params, ctx, const1, 1);
    DEVX_SET(transport_static_params, ctx, zero_copy_en, 0);
}

static inline void nvme_fill_progress_wqe(mlx5e_set_nvmeotcp_progress_params_wqe *wqe,
                                          uint32_t producer_index, uint32_t qpn, uint32_t tisn,
                                          uint32_t tcp_seqno, uint8_t fence_flags)
{
    memset(wqe, 0, sizeof(*wqe));
    auto cseg = &wqe->ctrl.ctrl;

    size_t progres_params_ds = DIV_ROUND_UP(sizeof(*wqe), MLX5_SEND_WQE_DS);
    cseg->opmod_idx_opcode =
        htobe32(((producer_index & 0xffff) << 8) | XLIO_MLX5_OPCODE_SET_PSV |
                (MLX5_CTRL_SEGMENT_OPC_MOD_UMR_NVMEOTCP_TIS_PROGRESS_PARAMS << 24));
    cseg->qpn_ds = htobe32((qpn << MLX5_WQE_CTRL_QPN_SHIFT) | progres_params_ds);
    cseg->fm_ce_se = fence_flags;

    mlx5_seg_nvmeotcp_progress_params *params = &wqe->params;
    params->tir_num = htobe32(tisn);
    void *ctx = params->ctx;

    DEVX_SET(nvmeotcp_progress_params, ctx, next_pdu_tcp_sn, tcp_seqno);
    DEVX_SET(nvmeotcp_progress_params, ctx, pdu_tracker_state,
             MLX5E_NVMEOTCP_PROGRESS_PARAMS_PDU_TRACKER_STATE_START);
    /* if (is_tx) offloading state == 0*/
    DEVX_SET(nvmeotcp_progress_params, ctx, offloading_state, 0);
}

void hw_queue_tx::nvme_set_static_context(xlio_tis *tis, uint32_t config)
{
    update_wqe_last();

    auto *cseg = wqebb_get<xlio_mlx5_wqe_ctrl_seg *>(0U);
    auto *ucseg = wqebb_get<xlio_mlx5_wqe_umr_ctrl_seg *>(0U, sizeof(*cseg));

    nvme_fill_static_params_control(cseg, ucseg, m_sq_wqe_counter, m_mlx5_qp.qpn, tis->get_tisn(),
                                    0);
    memset(wqebb_get<void *>(1U), 0, sizeof(mlx5_mkey_seg));

    auto *params = wqebb_get<mlx5_wqe_transport_static_params_seg *>(2U);
    nvme_fill_static_params_transport_params(params, config);
    store_current_wqe_prop(nullptr, SQ_CREDITS_UMR, tis);
    ring_doorbell(MLX5E_TRANSPORT_SET_STATIC_PARAMS_WQEBBS);
}

void hw_queue_tx::nvme_set_progress_context(xlio_tis *tis, uint32_t tcp_seqno)
{
    update_wqe_last();

    auto *wqe = reinterpret_cast<mlx5e_set_nvmeotcp_progress_params_wqe *>(m_sq_wqe_last);
    nvme_fill_progress_wqe(wqe, m_sq_wqe_counter, m_mlx5_qp.qpn, tis->get_tisn(), tcp_seqno,
                           MLX5_FENCE_MODE_INITIATOR_SMALL);
    store_current_wqe_prop(nullptr, SQ_CREDITS_SET_PSV, tis);
    ring_doorbell(MLX5E_NVMEOTCP_PROGRESS_PARAMS_WQEBBS);
}

#if defined(DEFINED_UTLS)
std::unique_ptr<dpcp::tls_dek> hw_queue_tx::get_new_tls_dek(const void *key,
                                                            uint32_t key_size_bytes)
{
    dpcp::tls_dek *_dek = nullptr;
    dpcp::adapter *adapter = m_p_ib_ctx_handler->get_dpcp_adapter();
    if (likely(adapter)) {
        dpcp::status status;
        struct dpcp::dek_attr dek_attr;
        memset(&dek_attr, 0, sizeof(dek_attr));
        dek_attr.key_blob = (void *)key;
        dek_attr.key_blob_size = key_size_bytes;
        dek_attr.key_size = key_size_bytes;
        dek_attr.pd_id = adapter->get_pd();
        status = adapter->create_tls_dek(dek_attr, _dek);
        if (unlikely(status != dpcp::DPCP_OK)) {
            hwqtx_logwarn("Failed to create new DEK, status: %d", status);
            if (_dek) {
                delete _dek;
                _dek = nullptr;
            }
        }
    }

    return std::unique_ptr<dpcp::tls_dek>(_dek);
}

std::unique_ptr<dpcp::tls_dek> hw_queue_tx::get_tls_dek(const void *key, uint32_t key_size_bytes)
{
    dpcp::status status;
    dpcp::adapter *adapter = m_p_ib_ctx_handler->get_dpcp_adapter();

    if (unlikely(!adapter)) {
        return std::unique_ptr<dpcp::tls_dek>(nullptr);
    }

    // If the amount of available DEKs in m_dek_put_cache is smaller than
    // low-watermark we continue to create new DEKs. This is to avoid situations
    // where one DEKs is returned and then fetched in a throttlling manner
    // causing too frequent crypto-sync.
    // It is also possible that crypto-sync may have higher impact with higher number
    // of active connections.
    if (unlikely(!m_p_ring->tls_sync_dek_supported()) ||
        (unlikely(m_tls_dek_get_cache.empty()) &&
         (m_tls_dek_put_cache.size() <= safe_mce_sys().utls_low_wmark_dek_cache_size))) {
        return get_new_tls_dek(key, key_size_bytes);
    }

    if (unlikely(m_tls_dek_get_cache.empty())) {
        hwqtx_logdbg("Empty DEK get cache. Swapping caches and do Sync-Crypto. Put-Cache size: %zu",
                     m_tls_dek_put_cache.size());

        status = adapter->sync_crypto_tls();
        if (unlikely(status != dpcp::DPCP_OK)) {
            hwqtx_logwarn("Failed to flush DEK HW cache, status: %d", status);
            return get_new_tls_dek(key, key_size_bytes);
        }

        m_tls_dek_get_cache.swap(m_tls_dek_put_cache);
    }

    std::unique_ptr<dpcp::tls_dek> out_dek(std::move(m_tls_dek_get_cache.front()));
    m_tls_dek_get_cache.pop_front();

    struct dpcp::dek_attr dek_attr;
    memset(&dek_attr, 0, sizeof(dek_attr));
    dek_attr.key_blob = const_cast<void *>(key);
    dek_attr.key_blob_size = key_size_bytes;
    dek_attr.key_size = key_size_bytes;
    dek_attr.pd_id = adapter->get_pd();
    status = out_dek->modify(dek_attr);
    if (unlikely(status != dpcp::DPCP_OK)) {
        hwqtx_logwarn("Failed to modify DEK, status: %d", status);
        out_dek.reset(nullptr);
    }

    return out_dek;
}

void hw_queue_tx::put_tls_dek(std::unique_ptr<dpcp::tls_dek> &&tls_dek_obj)
{
    if (!tls_dek_obj) {
        return;
    }
    // We don't allow unlimited DEK cache to avoid system DEK starvation.
    if (likely(m_p_ring->tls_sync_dek_supported()) &&
        m_tls_dek_put_cache.size() < safe_mce_sys().utls_high_wmark_dek_cache_size) {
        m_tls_dek_put_cache.emplace_back(std::forward<std::unique_ptr<dpcp::tls_dek>>(tls_dek_obj));
    }
}

xlio_tis *hw_queue_tx::tls_context_setup_tx(const xlio_tls_info *info)
{
    std::unique_ptr<xlio_tis> tis;
    if (m_tls_tis_cache.empty()) {
        tis = create_tis(DPCP_TIS_FLAGS | dpcp::TIS_ATTR_TLS);
        if (unlikely(!tis)) {
            return nullptr;
        }
    } else {
        tis.reset(m_tls_tis_cache.back());
        m_tls_tis_cache.pop_back();
    }

    auto dek_obj = get_tls_dek(info->key, info->key_len);
    if (unlikely(!dek_obj)) {
        m_tls_tis_cache.push_back(tis.release());
        return nullptr;
    }

    tis->assign_dek(std::move(dek_obj));
    uint32_t tisn = tis->get_tisn();

    tls_post_static_params_wqe(tis.get(), info, tisn, tis->get_dek_id(), 0, false, true);
    tls_post_progress_params_wqe(tis.get(), tisn, 0, false, true);
    /* The 1st post after TLS configuration must be with fence. */
    m_b_fence_needed = true;

    assert(!tis->m_released);

    return tis.release();
}

void hw_queue_tx::tls_context_resync_tx(const xlio_tls_info *info, xlio_tis *tis, bool skip_static)
{
    uint32_t tisn = tis->get_tisn();

    if (!skip_static) {
        tls_post_static_params_wqe(tis, info, tisn, tis->get_dek_id(), 0, true, true);
    }
    tls_post_progress_params_wqe(tis, tisn, 0, skip_static, true);
    m_b_fence_needed = true;
}

int hw_queue_tx::tls_context_setup_rx(xlio_tir *tir, const xlio_tls_info *info,
                                      uint32_t next_record_tcp_sn, xlio_comp_cb_t callback,
                                      void *callback_arg)
{
    uint32_t tirn;
    dpcp::tls_dek *_dek;
    dpcp::status status;
    dpcp::adapter *adapter = m_p_ib_ctx_handler->get_dpcp_adapter();
    struct dpcp::dek_attr dek_attr;

    memset(&dek_attr, 0, sizeof(dek_attr));
    dek_attr.key_blob = (void *)info->key;
    dek_attr.key_blob_size = info->key_len;
    dek_attr.key_size = info->key_len;
    dek_attr.pd_id = adapter->get_pd();
    status = adapter->create_tls_dek(dek_attr, _dek);
    if (unlikely(status != dpcp::DPCP_OK)) {
        hwqtx_logerr("Failed to create DEK, status: %d", status);
        return -1;
    }
    tir->assign_dek(_dek);
    tir->assign_callback(callback, callback_arg);
    tirn = tir->get_tirn();

    tls_post_static_params_wqe(NULL, info, tirn, _dek->get_key_id(), 0, false, false);
    tls_post_progress_params_wqe(tir, tirn, next_record_tcp_sn, false, false);

    assert(!tir->m_released);

    return 0;
}

void hw_queue_tx::tls_resync_rx(xlio_tir *tir, const xlio_tls_info *info, uint32_t hw_resync_tcp_sn)
{
    tls_post_static_params_wqe(tir, info, tir->get_tirn(), tir->get_dek_id(), hw_resync_tcp_sn,
                               false, false);
}

void hw_queue_tx::tls_get_progress_params_rx(xlio_tir *tir, void *buf, uint32_t lkey)
{
    /* Address must be aligned by 64. */
    assert((uintptr_t)buf == ((uintptr_t)buf >> 6U << 6U));

    tls_get_progress_params_wqe(tir, tir->get_tirn(), buf, lkey);
}

inline void hw_queue_tx::tls_fill_static_params_wqe(struct mlx5_wqe_tls_static_params_seg *params,
                                                    const struct xlio_tls_info *info,
                                                    uint32_t key_id, uint32_t resync_tcp_sn)
{
    unsigned char *initial_rn, *iv;
    uint8_t tls_version;
    uint8_t *ctx;

    ctx = params->ctx;

    iv = DEVX_ADDR_OF(tls_static_params, ctx, gcm_iv);
    initial_rn = DEVX_ADDR_OF(tls_static_params, ctx, initial_record_number);

    memcpy(iv, info->salt, TLS_AES_GCM_SALT_LEN);
    memcpy(initial_rn, info->rec_seq, TLS_AES_GCM_REC_SEQ_LEN);
    if (info->tls_version == TLS_1_3_VERSION) {
        iv = DEVX_ADDR_OF(tls_static_params, ctx, implicit_iv);
        memcpy(iv, info->iv, TLS_AES_GCM_IV_LEN);
    }

    tls_version = (info->tls_version == TLS_1_2_VERSION) ? MLX5E_STATIC_PARAMS_CONTEXT_TLS_1_2
                                                         : MLX5E_STATIC_PARAMS_CONTEXT_TLS_1_3;

    DEVX_SET(tls_static_params, ctx, tls_version, tls_version);
    DEVX_SET(tls_static_params, ctx, const_1, 1);
    DEVX_SET(tls_static_params, ctx, const_2, 2);
    DEVX_SET(tls_static_params, ctx, encryption_standard, MLX5E_ENCRYPTION_STANDARD_TLS);
    DEVX_SET(tls_static_params, ctx, resync_tcp_sn, resync_tcp_sn);
    DEVX_SET(tls_static_params, ctx, dek_index, key_id);
}

inline void hw_queue_tx::tls_post_static_params_wqe(xlio_ti *ti, const struct xlio_tls_info *info,
                                                    uint32_t tis_tir_number, uint32_t key_id,
                                                    uint32_t resync_tcp_sn, bool fence, bool is_tx)
{
    update_wqe_last();

    struct mlx5_set_tls_static_params_wqe *wqe =
        reinterpret_cast<struct mlx5_set_tls_static_params_wqe *>(m_sq_wqe_last);
    struct xlio_mlx5_wqe_ctrl_seg *cseg = &wqe->ctrl.ctrl;
    xlio_mlx5_wqe_umr_ctrl_seg *ucseg = &wqe->uctrl;
    struct mlx5_mkey_seg *mkcseg = &wqe->mkc;
    struct mlx5_wqe_tls_static_params_seg *tspseg = &wqe->params;
    uint8_t opmod = is_tx ? MLX5_OPC_MOD_TLS_TIS_STATIC_PARAMS : MLX5_OPC_MOD_TLS_TIR_STATIC_PARAMS;

#define STATIC_PARAMS_DS_CNT DIV_ROUND_UP(sizeof(*wqe), MLX5_SEND_WQE_DS)

    /*
     * SQ wrap around handling information
     *
     * UMR WQE has the size of 3 WQEBBs.
     * The following are segments sizes the WQE contains.
     *
     * UMR WQE segments sizes:
     * sizeof(wqe->ctrl) = 16[B]
     * sizeof(wqe->uctrl) = 48[B]
     * sizeof(wqe->mkc) = 64[B]
     * sizeof(wqe->params) = 64[B]
     *
     * UMR WQEBBs to segments mapping:
     * WQEBB1: [wqe->ctrl(16[B]), wqe->uctrl(48[B])] -> 64[B]
     * WQEBB2: [wqe->mkc(64[B])]                     -> 64[B]
     * WQEBB3: [wqe->params(64[B])]                  -> 64[B]
     *
     * There are 3 cases:
     *     1. There is enough room in the SQ for 3 WQEBBs:
     *        3 WQEBBs posted from m_sq_wqe_last current location.
     *     2. There is enough room in the SQ for 2 WQEBBs:
     *        2 WQEBBs posted from m_sq_wqe_last current location till m_sq_wqes_end.
     *        1 WQEBB posted from m_sq_wqes beginning.
     *     3. There is enough room in the SQ for 1 WQEBB:
     *        1 WQEBB posted from m_sq_wqe_last current location till m_sq_wqes_end.
     *        2 WQEBBs posted from m_sq_wqes beginning.
     * The case of 0 WQEBBs room left in the SQ shouldn't happen, m_sq_wqe_last wrap around handling
     * done when setting next m_sq_wqe_last.
     *
     * In all the 3 cases, no need to change cseg and ucseg pointers, since they fit to
     * one WQEBB and will be posted before m_sq_wqes_end.
     */

    memset(m_sq_wqe_last, 0, sizeof(*m_sq_wqe_last));
    cseg->opmod_idx_opcode =
        htobe32(((m_sq_wqe_counter & 0xffff) << 8) | MLX5_OPCODE_UMR | (opmod << 24));
    cseg->qpn_ds = htobe32((m_mlx5_qp.qpn << MLX5_WQE_CTRL_QPN_SHIFT) | STATIC_PARAMS_DS_CNT);
    cseg->fm_ce_se = fence ? MLX5_FENCE_MODE_INITIATOR_SMALL : 0;
    cseg->tis_tir_num = htobe32(tis_tir_number << 8);

    ucseg->flags = MLX5_UMR_INLINE;
    ucseg->bsf_octowords = htobe16(DEVX_ST_SZ_BYTES(tls_static_params) / 16);

    int sq_wqebbs_room_left =
        (static_cast<int>(m_sq_wqes_end - reinterpret_cast<uint8_t *>(cseg)) / MLX5_SEND_WQE_BB);

    /* Case 1:
     * In this case we don't need to change
     * the pointers of the different segments, because there is enough room in the SQ.
     * Thus, no need to do special handling.
     */

    if (unlikely(sq_wqebbs_room_left == 2)) { // Case 2: Change tspseg pointer:
        tspseg = reinterpret_cast<struct mlx5_wqe_tls_static_params_seg *>(m_sq_wqes);
    } else if (unlikely(sq_wqebbs_room_left == 1)) { // Case 3: Change mkcseg and tspseg pointers:
        mkcseg = reinterpret_cast<struct mlx5_mkey_seg *>(m_sq_wqes);
        tspseg = reinterpret_cast<struct mlx5_wqe_tls_static_params_seg *>(
            reinterpret_cast<uint8_t *>(m_sq_wqes) + sizeof(*mkcseg));
    }

    memset(mkcseg, 0, sizeof(*mkcseg));
    memset(tspseg, 0, sizeof(*tspseg));

    tls_fill_static_params_wqe(tspseg, info, key_id, resync_tcp_sn);
    store_current_wqe_prop(nullptr, SQ_CREDITS_UMR, ti);

    ring_doorbell(TLS_SET_STATIC_PARAMS_WQEBBS, true);
    dbg_dump_wqe((uint32_t *)m_sq_wqe_last, sizeof(mlx5_set_tls_static_params_wqe));
}

inline void hw_queue_tx::tls_fill_progress_params_wqe(
    struct mlx5_wqe_tls_progress_params_seg *params, uint32_t tis_tir_number,
    uint32_t next_record_tcp_sn)
{
    uint8_t *ctx = params->ctx;

    params->tis_tir_num = htobe32(tis_tir_number);

    DEVX_SET(tls_progress_params, ctx, next_record_tcp_sn, next_record_tcp_sn);
    DEVX_SET(tls_progress_params, ctx, record_tracker_state,
             MLX5E_TLS_PROGRESS_PARAMS_RECORD_TRACKER_STATE_START);
    DEVX_SET(tls_progress_params, ctx, auth_state, MLX5E_TLS_PROGRESS_PARAMS_AUTH_STATE_NO_OFFLOAD);
}

inline void hw_queue_tx::tls_post_progress_params_wqe(xlio_ti *ti, uint32_t tis_tir_number,
                                                      uint32_t next_record_tcp_sn, bool fence,
                                                      bool is_tx)
{
    update_wqe_last();

    struct mlx5_set_tls_progress_params_wqe *wqe =
        reinterpret_cast<struct mlx5_set_tls_progress_params_wqe *>(m_sq_wqe_last);
    struct xlio_mlx5_wqe_ctrl_seg *cseg = &wqe->ctrl.ctrl;
    uint8_t opmod =
        is_tx ? MLX5_OPC_MOD_TLS_TIS_PROGRESS_PARAMS : MLX5_OPC_MOD_TLS_TIR_PROGRESS_PARAMS;

    memset(wqe, 0, sizeof(*wqe));

#define PROGRESS_PARAMS_DS_CNT DIV_ROUND_UP(sizeof(*wqe), MLX5_SEND_WQE_DS)

    cseg->opmod_idx_opcode =
        htobe32(((m_sq_wqe_counter & 0xffff) << 8) | XLIO_MLX5_OPCODE_SET_PSV | (opmod << 24));
    cseg->qpn_ds = htobe32((m_mlx5_qp.qpn << MLX5_WQE_CTRL_QPN_SHIFT) | PROGRESS_PARAMS_DS_CNT);
    /* Request completion for TLS RX offload to create TLS rule ASAP. */
    cseg->fm_ce_se =
        (fence ? MLX5_FENCE_MODE_INITIATOR_SMALL : 0) | (is_tx ? 0 : MLX5_WQE_CTRL_CQ_UPDATE);

    tls_fill_progress_params_wqe(&wqe->params, tis_tir_number, next_record_tcp_sn);
    store_current_wqe_prop(nullptr, SQ_CREDITS_SET_PSV, ti);

    ring_doorbell(TLS_SET_PROGRESS_PARAMS_WQEBBS);
    dbg_dump_wqe((uint32_t *)m_sq_wqe_last, sizeof(mlx5_set_tls_progress_params_wqe));
}

inline void hw_queue_tx::tls_get_progress_params_wqe(xlio_ti *ti, uint32_t tirn, void *buf,
                                                     uint32_t lkey)
{
    update_wqe_last();

    struct mlx5_get_tls_progress_params_wqe *wqe =
        reinterpret_cast<struct mlx5_get_tls_progress_params_wqe *>(m_sq_wqe_last);
    struct xlio_mlx5_wqe_ctrl_seg *cseg = &wqe->ctrl.ctrl;
    struct xlio_mlx5_seg_get_psv *psv = &wqe->psv;
    uint8_t opmod = MLX5_OPC_MOD_TLS_TIR_PROGRESS_PARAMS;

    memset(wqe, 0, sizeof(*wqe));

#define PROGRESS_PARAMS_DS_CNT DIV_ROUND_UP(sizeof(*wqe), MLX5_SEND_WQE_DS)

    cseg->opmod_idx_opcode =
        htobe32(((m_sq_wqe_counter & 0xffff) << 8) | XLIO_MLX5_OPCODE_GET_PSV | (opmod << 24));
    cseg->qpn_ds = htobe32((m_mlx5_qp.qpn << MLX5_WQE_CTRL_QPN_SHIFT) | PROGRESS_PARAMS_DS_CNT);
    cseg->fm_ce_se = MLX5_WQE_CTRL_CQ_UPDATE;

    psv->num_psv = 1U << 4U;
    psv->l_key = htobe32(lkey);
    psv->psv_index[0] = htobe32(tirn);
    psv->va = htobe64((uintptr_t)buf);

    store_current_wqe_prop(nullptr, SQ_CREDITS_GET_PSV, ti);

    ring_doorbell(TLS_GET_PROGRESS_WQEBBS);
}

void hw_queue_tx::tls_tx_post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey,
                                       bool first)
{
    post_dump_wqe(tis, addr, len, lkey, first);
}

void hw_queue_tx::tls_release_tis(xlio_tis *tis)
{
    assert(tis && tis->m_type == xlio_ti::ti_type::TLS_TIS);
    tis->m_released = true;
    if (tis->m_ref == 0) {
        put_tls_tis_in_cache(tis);
    }
}

void hw_queue_tx::put_tls_tis_in_cache(xlio_tis *tis)
{
    std::unique_ptr<dpcp::dek> dek = tis->release_dek();
    assert(dynamic_cast<dpcp::tls_dek *>(dek.get()));

    put_tls_dek(std::unique_ptr<dpcp::tls_dek>(dynamic_cast<dpcp::tls_dek *>(dek.release())));
    m_tls_tis_cache.push_back(tis);
}

void hw_queue_tx::ti_released(xlio_ti *ti)
{
    assert(ti->m_released);
    assert(ti->m_ref == 0);
    if (ti->m_type == xlio_ti::ti_type::TLS_TIS) {
        put_tls_tis_in_cache(static_cast<xlio_tis *>(ti));
    }
}

void hw_queue_tx::destroy_tis_cache(void)
{
    while (!m_tls_tis_cache.empty()) {
        xlio_tis *tis = m_tls_tis_cache.back();
        m_tls_tis_cache.pop_back();
        delete tis;
    }
}
#else /* DEFINED_UTLS */
void hw_queue_tx::ti_released(xlio_ti *) {};
void hw_queue_tx::destroy_tis_cache(void) {};
#endif /* defined(DEFINED_UTLS) */

void hw_queue_tx::post_nop_fence(void)
{
    update_wqe_last();

    struct mlx5_wqe *wqe = reinterpret_cast<struct mlx5_wqe *>(m_sq_wqe_last);
    struct xlio_mlx5_wqe_ctrl_seg *cseg = &wqe->ctrl;

    memset(wqe, 0, sizeof(*wqe));

    cseg->opmod_idx_opcode = htobe32(((m_sq_wqe_counter & 0xffff) << 8) | MLX5_OPCODE_NOP);
    cseg->qpn_ds = htobe32((m_mlx5_qp.qpn << MLX5_WQE_CTRL_QPN_SHIFT) | 0x01);
    cseg->fm_ce_se = MLX5_FENCE_MODE_INITIATOR_SMALL;

    store_current_wqe_prop(nullptr, SQ_CREDITS_NOP, nullptr);

    ring_doorbell(1);
}

void hw_queue_tx::post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey,
                                bool is_first)
{
    update_wqe_last();

    struct mlx5_dump_wqe *wqe = reinterpret_cast<struct mlx5_dump_wqe *>(m_sq_wqe_last);
    struct xlio_mlx5_wqe_ctrl_seg *cseg = &wqe->ctrl.ctrl;
    struct mlx5_wqe_data_seg *dseg = &wqe->data;
    uint32_t tisn = tis ? tis->get_tisn() : 0;
    uint16_t ds_cnt = sizeof(*wqe) / MLX5_SEND_WQE_DS;

    memset(wqe, 0, sizeof(*wqe));

    cseg->opmod_idx_opcode = htobe32(((m_sq_wqe_counter & 0xffff) << 8) | XLIO_MLX5_OPCODE_DUMP);
    cseg->qpn_ds = htobe32((m_mlx5_qp.qpn << MLX5_WQE_CTRL_QPN_SHIFT) | ds_cnt);
    cseg->fm_ce_se = is_first ? MLX5_FENCE_MODE_INITIATOR_SMALL : 0;
    cseg->tis_tir_num = htobe32(tisn << 8);

    dseg->addr = htobe64((uintptr_t)addr);
    dseg->lkey = htobe32(lkey);
    dseg->byte_count = htobe32(len);

    store_current_wqe_prop(nullptr, SQ_CREDITS_DUMP, tis);

    ring_doorbell(XLIO_DUMP_WQEBBS, true);
}

//! Handle releasing of Tx buffers
// Single post send with SIGNAL of a dummy packet
// NOTE: Since the QP is in ERROR state no packets will be sent on the wire!
// So we can post_send anything we want :)
void hw_queue_tx::trigger_completion_for_all_sent_packets()
{
    hwqtx_logfunc("unsignaled count=%d", m_n_unsignaled_count);

    if (!is_signal_requested_for_last_wqe()) {
        // Post a dummy WQE and request a signal to complete all the unsignaled WQEs in SQ
        hwqtx_logdbg("Need to send closing tx wr...");
        mem_buf_desc_t *p_mem_buf_desc = m_p_ring->mem_buf_tx_get(0, true, PBUF_RAM);
        // Align Tx buffer accounting since we will be bypassing the normal send calls
        m_p_ring->m_missing_buf_ref_count--;
        if (!p_mem_buf_desc) {
            hwqtx_logerr("no buffer in pool");
            return;
        }

        // Prepare dummy packet: zeroed payload ('0000').
        // For ETH it replaces the MAC header!! (Nothing is going on the wire, QP in error state)
        /* need to send at least eth+ip, since libmlx5 will drop just eth header */
        ethhdr *p_buffer_ethhdr = (ethhdr *)p_mem_buf_desc->p_buffer;
        memset(p_buffer_ethhdr, 0, sizeof(*p_buffer_ethhdr));
        p_buffer_ethhdr->h_proto = htons(ETH_P_IP);
        iphdr *p_buffer_iphdr = (iphdr *)(p_mem_buf_desc->p_buffer + sizeof(*p_buffer_ethhdr));
        memset(p_buffer_iphdr, 0, sizeof(*p_buffer_iphdr));

        ibv_sge sge[1];
        sge[0].length = sizeof(ethhdr) + sizeof(iphdr);
        sge[0].addr = (uintptr_t)(p_mem_buf_desc->p_buffer);
        sge[0].lkey = m_p_ring->m_tx_lkey;

        // Prepare send wr for (does not care if it is UD/IB or RAW/ETH)
        // UD requires AH+qkey, RAW requires minimal payload instead of MAC header.
        xlio_ibv_send_wr send_wr;

        memset(&send_wr, 0, sizeof(send_wr));
        send_wr.wr_id = (uintptr_t)p_mem_buf_desc;
        send_wr.wr.ud.ah = nullptr;
        send_wr.sg_list = sge;
        send_wr.num_sge = 1;
        send_wr.next = nullptr;
        xlio_send_wr_opcode(send_wr) = XLIO_IBV_WR_SEND;

        unsigned credits = credits_calculate(&send_wr);
        if (!credits_get(credits)) {
            // TODO Wait for available space in SQ to post the WQE. This method mustn't fail,
            // because we may want to wait until all the WQEs are completed and we need to post
            // something and request signal.
            hwqtx_logdbg("No space in SQ to trigger completions with a post operation");
            return;
        }

        send_to_wire(&send_wr,
                     (xlio_wr_tx_packet_attr)(XLIO_TX_PACKET_L3_CSUM | XLIO_TX_PACKET_L4_CSUM),
                     true, nullptr, credits);
    }
}

void hw_queue_tx::reset_inflight_zc_buffers_ctx(void *ctx)
{
    sq_wqe_prop *p = m_sq_wqe_prop_last;
    sq_wqe_prop *prev;
    if (p) {
        unsigned p_i = p - m_sq_wqe_idx_to_prop;
        if (p_i == m_sq_wqe_prop_last_signalled) {
            return;
        }
        do {
            mem_buf_desc_t *desc = p->buf;
            if (desc && desc->tx.zc.ctx == ctx) {
                desc->tx.zc.ctx = nullptr;
            }
            prev = p;
            p = p->next;
        } while (p && is_sq_wqe_prop_valid(p, prev));
    }
}

uint32_t hw_queue_tx::is_ratelimit_change(struct xlio_rate_limit_t &rate_limit)
{
    uint32_t rl_changes = 0;

    if (m_rate_limit.rate != rate_limit.rate) {
        rl_changes |= RL_RATE;
    }
    if (m_rate_limit.max_burst_sz != rate_limit.max_burst_sz) {
        rl_changes |= RL_BURST_SIZE;
    }
    if (m_rate_limit.typical_pkt_sz != rate_limit.typical_pkt_sz) {
        rl_changes |= RL_PKT_SIZE;
    }

    return rl_changes;
}

int hw_queue_tx::modify_qp_ratelimit(struct xlio_rate_limit_t &rate_limit, uint32_t rl_changes)
{
    int ret;

    ret = priv_ibv_modify_qp_ratelimit(m_mlx5_qp.qp, rate_limit, rl_changes);
    if (ret) {
        hwqtx_logdbg("failed to modify qp ratelimit ret %d (errno=%d %m)", ret, errno);
        return -1;
    }

    m_rate_limit = rate_limit;
    return 0;
}
