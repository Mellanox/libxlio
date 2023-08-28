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
#include "qp_mgr_eth_mlx5.h"

#if defined(DEFINED_DIRECT_VERBS)

#include <cstddef>
#include <sys/mman.h>
#include "cq_mgr_rx_regrq.h"
#include "proto/tls.h"
#include "util/utils.h"
#include "vlogger/vlogger.h"
#include "ring_simple.h"

#undef MODULE_NAME
#define MODULE_NAME "qpm_mlx5"

#if !defined(MLX5_ETH_INLINE_HEADER_SIZE)
#define MLX5_ETH_INLINE_HEADER_SIZE 18
#endif

#define OCTOWORD 16
#define WQEBB    64

//#define DBG_DUMP_WQE	1

#ifdef DBG_DUMP_WQE
#define dbg_dump_wqe(_addr, _size)                                                                 \
    {                                                                                              \
        uint32_t *_wqe = _addr;                                                                    \
        qp_logfunc("Dumping %d bytes from %p", _size, _wqe);                                       \
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
#if defined(DEFINED_DIRECT_VERBS) && (DEFINED_DIRECT_VERBS == 3) &&                                \
    defined(MLX5DV_UAR_ALLOC_TYPE_BF)
        struct mlx5dv_devx_uar *uar = mlx5dv_devx_alloc_uar(ib_ctx, MLX5DV_UAR_ALLOC_TYPE_BF);
        if (uar) {
            mlx5dv_devx_free_uar(uar);
            return true;
        }
#else
        NOT_IN_USE(ib_ctx);
#endif /* DEFINED_DIRECT_VERBS */
    }
    return false;
}

//! Maps xlio_ibv_wr_opcode to real MLX5 opcode.
//
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

qp_mgr_eth_mlx5::qp_mgr_eth_mlx5(struct qp_mgr_desc *desc, const uint32_t tx_num_wr,
                                 const uint16_t vlan, bool call_configure)
    : qp_mgr_eth(desc, tx_num_wr, vlan, false)
    , m_sq_wqe_idx_to_prop(NULL)
    , m_sq_wqe_prop_last(NULL)
    , m_sq_wqe_prop_last_signalled(0)
    , m_sq_free_credits(0)
    , m_rq_wqe_counter(0)
    , m_sq_wqes(NULL)
    , m_sq_wqe_hot(NULL)
    , m_sq_wqes_end(NULL)
    , m_sq_wqe_hot_index(0)
    , m_sq_wqe_counter(0)
    , m_b_fence_needed(false)
    , m_dm_enabled(false)
{
    // Check device capabilities for dummy send support
    m_hw_dummy_send_support = xlio_is_nop_supported(m_p_ib_ctx_handler->get_ibv_device_attr());

    if (call_configure && configure(desc)) {
        throw_xlio_exception("failed creating qp_mgr_eth");
    }

    memset(&m_mlx5_qp, 0, sizeof(m_mlx5_qp));
    m_db_method =
        (is_bf(((ib_ctx_handler *)desc->slave->p_ib_ctx)->get_ibv_context()) ? MLX5_DB_METHOD_BF
                                                                             : MLX5_DB_METHOD_DB);

    qp_logdbg("m_db_method=%d", m_db_method);
}

void qp_mgr_eth_mlx5::init_qp()
{
    if (0 != xlio_ib_mlx5_get_qp(m_qp, &m_mlx5_qp)) {
        qp_logpanic("xlio_ib_mlx5_get_qp failed (errno=%d %m)", errno);
    }

    m_sq_wqes = (struct mlx5_eth_wqe(*)[])(uintptr_t)m_mlx5_qp.sq.buf;
    m_sq_wqe_hot = &(*m_sq_wqes)[0];
    m_sq_wqes_end =
        (uint8_t *)((uintptr_t)m_mlx5_qp.sq.buf + m_mlx5_qp.sq.wqe_cnt * m_mlx5_qp.sq.stride);
    m_sq_wqe_counter = 0;

    m_sq_wqe_hot_index = 0;

    uint32_t old_wr_val = m_tx_num_wr;
    m_tx_num_wr = (m_sq_wqes_end - (uint8_t *)m_sq_wqe_hot) / WQEBB;

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
    m_qp_cap.max_inline_data = OCTOWORD - 4 + 3 * WQEBB;

    if (m_sq_wqe_idx_to_prop == NULL) {
        m_sq_wqe_idx_to_prop =
            (sq_wqe_prop *)mmap(NULL, m_tx_num_wr * sizeof(*m_sq_wqe_idx_to_prop),
                                PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (m_sq_wqe_idx_to_prop == MAP_FAILED) {
            qp_logerr("Failed allocating m_sq_wqe_idx_to_prop (errno=%d %m)", errno);
            return;
        }
        m_sq_wqe_prop_last_signalled = m_tx_num_wr - 1;
        m_sq_wqe_prop_last = NULL;
    }

    qp_logfunc("m_tx_num_wr=%d max_inline_data: %d m_sq_wqe_idx_to_prop=%p", m_tx_num_wr,
               get_max_inline_data(), m_sq_wqe_idx_to_prop);

    memset((void *)(uintptr_t)m_sq_wqe_hot, 0, sizeof(struct mlx5_eth_wqe));
    m_sq_wqe_hot->ctrl.data[0] = htonl(MLX5_OPCODE_SEND);
    m_sq_wqe_hot->ctrl.data[1] = htonl((m_mlx5_qp.qpn << 8) | 4);
    m_sq_wqe_hot->ctrl.data[2] = 0;
    m_sq_wqe_hot->eseg.inline_hdr_sz = htons(MLX5_ETH_INLINE_HEADER_SIZE);
    m_sq_wqe_hot->eseg.cs_flags = XLIO_TX_PACKET_L3_CSUM | XLIO_TX_PACKET_L4_CSUM;

    qp_logfunc("%p allocated for %d QPs sq_wqes:%p sq_wqes_end: %p and configured %d WRs "
               "BlueFlame: %p buf_size: %d offset: %d",
               m_qp, m_mlx5_qp.qpn, m_sq_wqes, m_sq_wqes_end, m_tx_num_wr, m_mlx5_qp.bf.reg,
               m_mlx5_qp.bf.size, m_mlx5_qp.bf.offset);
}

void qp_mgr_eth_mlx5::init_device_memory()
{
    /* This limitation is done because of a observation
     * that dm_copy takes a lot of time on VMs w/o BF (RM:1542628)
     */
    if (m_p_ib_ctx_handler->get_on_device_memory_size() > 0) {
        if (m_db_method == MLX5_DB_METHOD_BF) {
            m_dm_enabled =
                m_dm_mgr.allocate_resources(m_p_ib_ctx_handler, m_p_ring->m_p_ring_stat.get());

        } else {
#if defined(DEFINED_IBV_DM)
            VLOG_PRINTF_ONCE_THEN_DEBUG(
                VLOG_WARNING,
                "Device Memory functionality is not used on devices w/o Blue Flame support\n");
#endif /* DEFINED_IBV_DM */
        }
    }
}

void qp_mgr_eth_mlx5::up()
{
    init_qp();
    qp_mgr::up();
    init_device_memory();
}

void qp_mgr_eth_mlx5::down()
{
    if (m_dm_enabled) {
        m_dm_mgr.release_resources();
    }

    qp_mgr::down();
}

#if defined(DEFINED_UTLS)
void qp_mgr_eth_mlx5::destroy_tis_cache(void)
{
    while (!m_tls_tis_cache.empty()) {
        xlio_tis *tis = m_tls_tis_cache.back();
        m_tls_tis_cache.pop_back();
        delete tis;
    }
}
#endif /* defined(DEFINED_UTLS) */

void qp_mgr_eth_mlx5::update_next_wqe_hot()
{
    // Preparing next WQE as Ethernet send WQE and index:
    m_sq_wqe_hot = &(*m_sq_wqes)[m_sq_wqe_counter & (m_tx_num_wr - 1)];
    m_sq_wqe_hot_index = m_sq_wqe_counter & (m_tx_num_wr - 1);
    memset(m_sq_wqe_hot, 0, sizeof(mlx5_eth_wqe));

    // Fill Ethernet segment with header inline:
    struct mlx5_wqe_eth_seg *eth_seg =
        (struct mlx5_wqe_eth_seg *)((uint8_t *)m_sq_wqe_hot + sizeof(struct mlx5_wqe_ctrl_seg));
    eth_seg->inline_hdr_sz = htons(MLX5_ETH_INLINE_HEADER_SIZE);
}

//! Cleanup resources QP itself will be freed by base class DTOR
qp_mgr_eth_mlx5::~qp_mgr_eth_mlx5()
{
    if (m_rq_wqe_idx_to_wrid) {
        if (0 != munmap(m_rq_wqe_idx_to_wrid, m_rx_num_wr * sizeof(*m_rq_wqe_idx_to_wrid))) {
            qp_logerr("Failed deallocating memory with munmap m_rq_wqe_idx_to_wrid (errno=%d %m)",
                      errno);
        }
        m_rq_wqe_idx_to_wrid = NULL;
    }
    if (m_sq_wqe_idx_to_prop) {
        if (0 != munmap(m_sq_wqe_idx_to_prop, m_tx_num_wr * sizeof(*m_sq_wqe_idx_to_prop))) {
            qp_logerr("Failed deallocating memory with munmap m_sq_wqe_idx_to_prop (errno=%d %m)",
                      errno);
        }
        m_sq_wqe_idx_to_prop = NULL;
    }
    destroy_tis_cache();
}

void qp_mgr_eth_mlx5::post_recv_buffer(mem_buf_desc_t *p_mem_buf_desc)
{
    m_ibv_rx_sg_array[m_curr_rx_wr].addr = (uintptr_t)p_mem_buf_desc->p_buffer;
    m_ibv_rx_sg_array[m_curr_rx_wr].length = p_mem_buf_desc->sz_buffer;
    m_ibv_rx_sg_array[m_curr_rx_wr].lkey = p_mem_buf_desc->lkey;

    post_recv_buffer_rq(p_mem_buf_desc);
}

void qp_mgr_eth_mlx5::post_recv_buffer_rq(mem_buf_desc_t *p_mem_buf_desc)
{
    if (m_n_sysvar_rx_prefetch_bytes_before_poll) {
        if (m_p_prev_rx_desc_pushed) {
            m_p_prev_rx_desc_pushed->p_prev_desc = p_mem_buf_desc;
        }
        m_p_prev_rx_desc_pushed = p_mem_buf_desc;
    }

    m_ibv_rx_wr_array[m_curr_rx_wr].wr_id = (uintptr_t)p_mem_buf_desc;

    if (m_rq_wqe_idx_to_wrid) {
        uint32_t index = m_rq_wqe_counter & (m_rx_num_wr - 1);
        m_rq_wqe_idx_to_wrid[index] = (uintptr_t)p_mem_buf_desc;
        ++m_rq_wqe_counter;
    }

    if (m_curr_rx_wr == m_n_sysvar_rx_num_wr_to_post_recv - 1) {

        m_last_posted_rx_wr_id = (uintptr_t)p_mem_buf_desc;

        m_p_prev_rx_desc_pushed = NULL;
        p_mem_buf_desc->p_prev_desc = NULL;

        m_curr_rx_wr = 0;
        struct ibv_recv_wr *bad_wr = NULL;
        IF_VERBS_FAILURE(xlio_ib_mlx5_post_recv(&m_mlx5_qp, &m_ibv_rx_wr_array[0], &bad_wr))
        {
            uint32_t n_pos_bad_rx_wr =
                ((uint8_t *)bad_wr - (uint8_t *)m_ibv_rx_wr_array) / sizeof(struct ibv_recv_wr);
            qp_logerr("failed posting list (errno=%d %s)", errno, strerror(errno));
            qp_logerr("bad_wr is %d in submitted list (bad_wr=%p, m_ibv_rx_wr_array=%p, size=%zu)",
                      n_pos_bad_rx_wr, bad_wr, m_ibv_rx_wr_array, sizeof(struct ibv_recv_wr));
            qp_logerr("bad_wr info: wr_id=%#lx, next=%p, addr=%#lx, length=%d, lkey=%#x",
                      bad_wr[0].wr_id, bad_wr[0].next, bad_wr[0].sg_list[0].addr,
                      bad_wr[0].sg_list[0].length, bad_wr[0].sg_list[0].lkey);
            qp_logerr("QP current state: %d", priv_ibv_query_qp_state(m_qp));

            // Fix broken linked list of rx_wr
            if (n_pos_bad_rx_wr != (m_n_sysvar_rx_num_wr_to_post_recv - 1)) {
                m_ibv_rx_wr_array[n_pos_bad_rx_wr].next = &m_ibv_rx_wr_array[n_pos_bad_rx_wr + 1];
            }
            throw;
        }
        ENDIF_VERBS_FAILURE;
        qp_logfunc("Successful ibv_post_recv");
    } else {
        m_curr_rx_wr++;
    }
}

bool qp_mgr_eth_mlx5::init_rx_cq_mgr_prepare()
{
    m_rx_num_wr = align32pow2(m_rx_num_wr);

    m_rq_wqe_idx_to_wrid =
        (uint64_t *)mmap(NULL, m_rx_num_wr * sizeof(*m_rq_wqe_idx_to_wrid), PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (m_rq_wqe_idx_to_wrid == MAP_FAILED) {
        qp_logerr("Failed allocating m_rq_wqe_idx_to_wrid (errno=%d %m)", errno);
        return false;
    }

    return true;
}

cq_mgr_rx *qp_mgr_eth_mlx5::init_rx_cq_mgr(struct ibv_comp_channel *p_rx_comp_event_channel)
{
    return (!init_rx_cq_mgr_prepare() ? NULL
                                      : new cq_mgr_rx_regrq(m_p_ring, m_p_ib_ctx_handler, m_rx_num_wr,
                                                            p_rx_comp_event_channel));
}

cq_mgr_tx *qp_mgr_eth_mlx5::init_tx_cq_mgr()
{
    m_tx_num_wr = align32pow2(m_tx_num_wr);
    return new cq_mgr_tx(m_p_ring, m_p_ib_ctx_handler, m_tx_num_wr,
                         m_p_ring->get_tx_comp_event_channel());
}

inline void qp_mgr_eth_mlx5::ring_doorbell(int db_method, int num_wqebb, int num_wqebb_top,
                                           bool skip_comp /*=false*/)
{
    uint64_t *dst = (uint64_t *)((uint8_t *)m_mlx5_qp.bf.reg + m_mlx5_qp.bf.offset);
    uint64_t *src = reinterpret_cast<uint64_t *>(m_sq_wqe_hot);
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

    m_sq_wqe_counter = (m_sq_wqe_counter + num_wqebb + num_wqebb_top) & 0xFFFF;

    // Make sure that descriptors are written before
    // updating doorbell record and ringing the doorbell
    wmb();
    *m_mlx5_qp.sq.dbrec = htonl(m_sq_wqe_counter);

    // This wc_wmb ensures ordering between DB record and BF copy
    wc_wmb();
    if (likely(db_method == MLX5_DB_METHOD_BF)) {
        /* Copying src to BlueFlame register buffer by Write Combining cnt WQEBBs
         * Avoid using memcpy() to copy to BlueFlame page, since memcpy()
         * implementations may use move-string-buffer assembler instructions,
         * which do not guarantee order of copying.
         */
        while (num_wqebb--) {
            COPY_64B_NT(dst, src);
        }
        src = (uint64_t *)m_sq_wqes;
        while (num_wqebb_top--) {
            COPY_64B_NT(dst, src);
        }
    } else {
        *dst = *src;
    }

    /* Use wc_wmb() to ensure write combining buffers are flushed out
     * of the running CPU.
     * sfence instruction affects only the WC buffers of the CPU that executes it
     */
    wc_wmb();
    m_mlx5_qp.bf.offset ^= m_mlx5_qp.bf.size;
}

inline int qp_mgr_eth_mlx5::fill_inl_segment(sg_array &sga, uint8_t *cur_seg, uint8_t *data_addr,
                                             int max_inline_len, int inline_len)
{
    int wqe_inline_size = 0;
    while ((data_addr != NULL) && inline_len) {
        dbg_dump_wqe((uint32_t *)data_addr, inline_len);
        memcpy(cur_seg, data_addr, inline_len);
        wqe_inline_size += inline_len;
        cur_seg += inline_len;
        inline_len = max_inline_len - wqe_inline_size;
        data_addr = sga.get_data(&inline_len);
        qp_logfunc("data_addr:%p cur_seg: %p inline_len: %d wqe_inline_size: %d", data_addr,
                   cur_seg, inline_len, wqe_inline_size);
    }
    return wqe_inline_size;
}

//! Fill WQE dynamically, based on amount of free WQEBB in SQ
inline int qp_mgr_eth_mlx5::fill_wqe(xlio_ibv_send_wr *pswr)
{
    // control segment is mostly filled by preset after previous packet
    // we always inline ETH header
    sg_array sga(pswr->sg_list, pswr->num_sge);
    uint8_t *cur_seg = (uint8_t *)m_sq_wqe_hot + sizeof(struct mlx5_wqe_ctrl_seg);
    int inline_len = MLX5_ETH_INLINE_HEADER_SIZE;
    int data_len = sga.length();
    int wqe_size = sizeof(struct mlx5_wqe_ctrl_seg) / OCTOWORD;
    int max_inline_len = get_max_inline_data();

    // assume packet is full inline
    if (likely(data_len <= max_inline_len && xlio_send_wr_opcode(*pswr) == XLIO_IBV_WR_SEND)) {
        uint8_t *data_addr = sga.get_data(&inline_len); // data for inlining in ETH header
        data_len -= inline_len;
        qp_logfunc(
            "wqe_hot:%p num_sge: %d data_addr: %p data_len: %d max_inline_len: %d inline_len: %d",
            m_sq_wqe_hot, pswr->num_sge, data_addr, data_len, max_inline_len, inline_len);

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
            qp_logfunc("data_addr:%p cur_seg: %p rest_space: %d inline_len: %d wqe_size: %d",
                       data_addr, cur_seg, rest_space, inline_len, wqe_size);
            // bypass inline size and fill inline data segment
            data_addr = sga.get_data(&inline_len);
            inline_len = fill_inl_segment(sga, cur_seg + 4, data_addr, max_inline_len, inline_len);

            // store inline data size and mark the data as inlined
            *(uint32_t *)((uint8_t *)m_sq_wqe_hot + sizeof(struct mlx5_wqe_ctrl_seg) +
                          sizeof(struct mlx5_wqe_eth_seg)) = htonl(0x80000000 | inline_len);
            rest_space = align_to_octoword_up(inline_len + 4); // align to OCTOWORDs
            wqe_size += rest_space / OCTOWORD;
            // assert((data_len-inline_len)==0);
            // configuring control
            m_sq_wqe_hot->ctrl.data[1] = htonl((m_mlx5_qp.qpn << 8) | wqe_size);
            rest_space = align_to_WQEBB_up(wqe_size) / 4;
            qp_logfunc("data_len: %d inline_len: %d wqe_size: %d wqebbs: %d", data_len - inline_len,
                       inline_len, wqe_size, rest_space);
            ring_doorbell(m_db_method, rest_space);
            return rest_space;
        } else {
            // wrap around case, first filling till the end of m_sq_wqes
            int wrap_up_size = max_inline_len - rest_space;
            inline_len = rest_space;
            qp_logfunc("WRAP_UP_SIZE: %d data_addr:%p cur_seg: %p rest_space: %d inline_len: %d "
                       "wqe_size: %d",
                       wrap_up_size, data_addr, cur_seg, rest_space, inline_len, wqe_size);

            data_addr = sga.get_data(&inline_len);
            inline_len = fill_inl_segment(sga, cur_seg + 4, data_addr, rest_space, inline_len);
            data_len -= inline_len;
            rest_space = align_to_octoword_up(inline_len + 4);
            wqe_size += rest_space / OCTOWORD;
            rest_space =
                align_to_WQEBB_up(rest_space / OCTOWORD) / 4; // size of 1st chunk at the end

            qp_logfunc(
                "END chunk data_addr: %p data_len: %d inline_len: %d wqe_size: %d wqebbs: %d",
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
            *(uint32_t *)((uint8_t *)m_sq_wqe_hot + sizeof(struct mlx5_wqe_ctrl_seg) +
                          sizeof(struct mlx5_wqe_eth_seg)) = htonl(0x80000000 | inline_len);
            qp_logfunc("BEGIN_CHUNK data_addr: %p data_len: %d wqe_size: %d inline_len: %d "
                       "end_wqebbs: %d wqebbs: %d",
                       data_addr, data_len - wrap_up_size, wqe_size, inline_len + wrap_up_size,
                       rest_space, max_inline_len);
            // assert((data_len-wrap_up_size)==0);
            // configuring control
            m_sq_wqe_hot->ctrl.data[1] = htonl((m_mlx5_qp.qpn << 8) | wqe_size);

            dbg_dump_wqe((uint32_t *)m_sq_wqe_hot, rest_space * 4 * 16);
            dbg_dump_wqe((uint32_t *)m_sq_wqes, max_inline_len * 4 * 16);

            ring_doorbell(m_db_method, rest_space, max_inline_len);
            return rest_space + max_inline_len;
        }
    } else {
        if (xlio_send_wr_opcode(*pswr) == XLIO_IBV_WR_SEND) {
            /* data is bigger than max to inline we inlined only ETH header + uint from IP (18
             * bytes) the rest will be in data pointer segment adding data seg with pointer if there
             * still data to transfer
             */
            wqe_size = fill_wqe_send(pswr);
            return wqe_size;
        } else {
            /* Support XLIO_IBV_WR_SEND_TSO operation
             */
            wqe_size = fill_wqe_lso(pswr);
            return wqe_size;
        }
    }
    return 1;
}

inline int qp_mgr_eth_mlx5::fill_wqe_send(xlio_ibv_send_wr *pswr)
{
    struct mlx5_wqe_eth_seg *eseg;
    struct mlx5_wqe_data_seg *dseg;
    int wqe_size = sizeof(mlx5_wqe_ctrl_seg) / OCTOWORD;

    eseg = (struct mlx5_wqe_eth_seg *)((uint8_t *)m_sq_wqe_hot + sizeof(mlx5_wqe_ctrl_seg));
    eseg->inline_hdr_sz = 0;

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

    m_sq_wqe_hot->ctrl.data[1] = htonl((m_mlx5_qp.qpn << 8) | wqe_size);
    int wqebbs = align_to_WQEBB_up(wqe_size) / 4;
    /* TODO FIXME Split into top and bottom parts */
    ring_doorbell(m_db_method, wqebbs);

    return wqebbs;
}

//! Filling wqe for LSO
inline int qp_mgr_eth_mlx5::fill_wqe_lso(xlio_ibv_send_wr *pswr)
{
    struct mlx5_wqe_ctrl_seg *ctrl = NULL;
    struct mlx5_wqe_eth_seg *eseg = NULL;
    struct mlx5_wqe_data_seg *dpseg = NULL;
    uint8_t *cur_seg = NULL;
    uint8_t *p_hdr = (uint8_t *)pswr->tso.hdr;
    int inl_hdr_size = pswr->tso.hdr_sz;
    int inl_hdr_copy_size = 0;
    int max_inline_len = align_to_octoword_up(sizeof(struct mlx5_wqe_eth_seg) + inl_hdr_size -
                                              MLX5_ETH_INLINE_HEADER_SIZE);
    int wqe_size = sizeof(struct mlx5_wqe_ctrl_seg) / OCTOWORD;
    int rest = 0;
    int i = 0;

    ctrl = (struct mlx5_wqe_ctrl_seg *)m_sq_wqe_hot;

    /* Do usual send operation in case payload less than mss */
    if (0 == pswr->tso.mss) {
        ctrl->opmod_idx_opcode =
            htonl(((m_sq_wqe_counter & 0xffff) << 8) | (get_mlx5_opcode(XLIO_IBV_WR_SEND) & 0xff));
    }

    eseg = (struct mlx5_wqe_eth_seg *)((uint8_t *)m_sq_wqe_hot + sizeof(*ctrl));
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
        inl_hdr_copy_size = align_to_WQEBB_up(wqe_size) / 4;
    }
    wqe_size += max_inline_len / OCTOWORD;
    qp_logfunc("TSO: num_sge: %d max_inline_len: %d inl_hdr_size: %d rest: %d", pswr->num_sge,
               max_inline_len, inl_hdr_size, rest);
    // Filling data pointer segments with payload by scatter-gather list elements
    dpseg = (struct mlx5_wqe_data_seg *)cur_seg;
    for (i = 0; i < pswr->num_sge; i++) {
        if (unlikely((uintptr_t)dpseg >= (uintptr_t)m_sq_wqes_end)) {
            dpseg = (struct mlx5_wqe_data_seg *)m_sq_wqes;
            inl_hdr_copy_size = align_to_WQEBB_up(wqe_size) / 4;
        }
        dpseg->addr = htonll((uint64_t)pswr->sg_list[i].addr);
        dpseg->lkey = htonl(pswr->sg_list[i].lkey);
        dpseg->byte_count = htonl(pswr->sg_list[i].length);

        qp_logfunc("DATA_SEG: addr:%llx len: %d lkey: %x dp_seg: %p wqe_size: %d",
                   pswr->sg_list[i].addr, pswr->sg_list[i].length, dpseg->lkey, dpseg, wqe_size);

        dpseg++;
        wqe_size += sizeof(struct mlx5_wqe_data_seg) / OCTOWORD;
    }
    inl_hdr_size = align_to_WQEBB_up(wqe_size) / 4;
    m_sq_wqe_hot->ctrl.data[1] = htonl((m_mlx5_qp.qpn << 8) | wqe_size);

    // sending by BlueFlame or DoorBell covering wrap around
    // TODO Make a single doorbell call
    if (likely(inl_hdr_size <= 4)) {
        if (likely(inl_hdr_copy_size == 0)) {
            ring_doorbell(MLX5_DB_METHOD_DB, inl_hdr_size);
        } else {
            ring_doorbell(MLX5_DB_METHOD_DB, inl_hdr_copy_size, inl_hdr_size - inl_hdr_copy_size);
        }
    } else {
        ring_doorbell(MLX5_DB_METHOD_DB, inl_hdr_size);
    }
    return align_to_WQEBB_up(wqe_size) / 4;
}

void qp_mgr_eth_mlx5::store_current_wqe_prop(mem_buf_desc_t *buf, unsigned credits, xlio_ti *ti)
{
    m_sq_wqe_idx_to_prop[m_sq_wqe_hot_index] = sq_wqe_prop {
        .buf = buf,
        .credits = credits,
        .ti = ti,
        .next = m_sq_wqe_prop_last,
    };
    m_sq_wqe_prop_last = &m_sq_wqe_idx_to_prop[m_sq_wqe_hot_index];
    if (ti != NULL) {
        ti->get();
    }
}

//! Send one RAW packet by MLX5 BlueFlame
//
int qp_mgr_eth_mlx5::send_to_wire(xlio_ibv_send_wr *p_send_wqe, xlio_wr_tx_packet_attr attr,
                                  bool request_comp, xlio_tis *tis, unsigned credits)
{
    struct xlio_mlx5_wqe_ctrl_seg *ctrl = NULL;
    struct mlx5_wqe_eth_seg *eseg = NULL;
    uint32_t tisn = tis ? tis->get_tisn() : 0;

    ctrl = (struct xlio_mlx5_wqe_ctrl_seg *)m_sq_wqe_hot;
    eseg = (struct mlx5_wqe_eth_seg *)((uint8_t *)m_sq_wqe_hot + sizeof(*ctrl));

    /* Configure ctrl segment
     * qpn_ds or ctrl.data[1] is set inside fill_wqe()
     */
    ctrl->opmod_idx_opcode = htonl(((m_sq_wqe_counter & 0xffff) << 8) |
                                   (get_mlx5_opcode(xlio_send_wr_opcode(*p_send_wqe)) & 0xff));
    m_sq_wqe_hot->ctrl.data[2] = 0;
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

    update_next_wqe_hot();

    qp_logfunc(
        "m_sq_wqe_hot: %p m_sq_wqe_hot_index: %d wqe_counter: %d new_hot_index: %d wr_id: %llx",
        m_sq_wqe_hot, m_sq_wqe_hot_index, m_sq_wqe_counter, (m_sq_wqe_counter & (m_tx_num_wr - 1)),
        p_send_wqe->wr_id);

    return 0;
}

#ifdef DEFINED_UTLS

std::unique_ptr<dpcp::dek> qp_mgr_eth_mlx5::get_new_dek(const void *key, uint32_t key_size_bytes)
{
    dpcp::dek *_dek = nullptr;
    dpcp::adapter *adapter = m_p_ib_ctx_handler->get_dpcp_adapter();
    if (likely(adapter)) {
        dpcp::status status;
        struct dpcp::dek::attr dek_attr;
        memset(&dek_attr, 0, sizeof(dek_attr));
        dek_attr.flags = dpcp::DEK_ATTR_TLS;
        dek_attr.key = (void *)key;
        dek_attr.key_size_bytes = key_size_bytes;
        dek_attr.pd_id = adapter->get_pd();
        status = adapter->create_dek(dek_attr, _dek);
        if (unlikely(status != dpcp::DPCP_OK)) {
            qp_logwarn("Failed to create new DEK, status: %d", status);
            if (_dek) {
                delete _dek;
                _dek = nullptr;
            }
        }
    }

    return std::unique_ptr<dpcp::dek>(_dek);
}

std::unique_ptr<dpcp::dek> qp_mgr_eth_mlx5::get_dek(const void *key, uint32_t key_size_bytes)
{
    dpcp::status status;
    dpcp::adapter *adapter = m_p_ib_ctx_handler->get_dpcp_adapter();

    if (unlikely(!adapter)) {
        return std::unique_ptr<dpcp::dek>(nullptr);
    }

    // If the amount of available DEKs in m_dek_put_cache is smaller than
    // low-watermark we continue to create new DEKs. This is to avoid situations
    // where one DEKs is returned and then fetched in a throttlling manner
    // causing too frequent crypto-sync.
    // It is also possible that crypto-sync may have higher impact with higher number
    // of active connections.
    if (unlikely(!m_p_ring->tls_sync_dek_supported()) ||
        (unlikely(m_dek_get_cache.empty()) &&
         (m_dek_put_cache.size() <= safe_mce_sys().utls_low_wmark_dek_cache_size))) {
        return get_new_dek(key, key_size_bytes);
    }

    if (unlikely(m_dek_get_cache.empty())) {
        qp_logdbg("Empty DEK get cache. Swapping caches and do Sync-Crypto. Put-Cache size: %zu",
                  m_dek_put_cache.size());

        status = adapter->sync_crypto_tls();
        if (unlikely(status != dpcp::DPCP_OK)) {
            qp_logwarn("Failed to flush DEK HW cache, status: %d", status);
            return get_new_dek(key, key_size_bytes);
        }

        m_dek_get_cache.swap(m_dek_put_cache);
    }

    std::unique_ptr<dpcp::dek> out_dek(std::move(m_dek_get_cache.front()));
    m_dek_get_cache.pop_front();

    struct dpcp::dek::attr dek_attr;
    memset(&dek_attr, 0, sizeof(dek_attr));
    dek_attr.flags = dpcp::DEK_ATTR_TLS;
    dek_attr.key = const_cast<void *>(key);
    dek_attr.key_size_bytes = key_size_bytes;
    dek_attr.pd_id = adapter->get_pd();
    status = out_dek->modify(dek_attr);
    if (unlikely(status != dpcp::DPCP_OK)) {
        qp_logwarn("Failed to modify DEK, status: %d", status);
        out_dek.reset(nullptr);
    }

    return out_dek;
}

void qp_mgr_eth_mlx5::put_dek(std::unique_ptr<dpcp::dek> &&dek_obj)
{
    if (dek_obj == nullptr) {
        return;
    }
    // We don't allow unlimited DEK cache to avoid system DEK starvation.
    if (likely(m_p_ring->tls_sync_dek_supported()) &&
        m_dek_put_cache.size() < safe_mce_sys().utls_high_wmark_dek_cache_size) {
        m_dek_put_cache.emplace_back(std::forward<std::unique_ptr<dpcp::dek>>(dek_obj));
    }
}

xlio_tis *qp_mgr_eth_mlx5::tls_context_setup_tx(const xlio_tls_info *info)
{
    std::unique_ptr<xlio_tis> tis;
    if (m_tls_tis_cache.empty()) {
        tis = create_tis(DPCP_TIS_FLAGS | dpcp::TIS_ATTR_TLS);
        if (unlikely(tis == nullptr)) {
            return nullptr;
        }
    } else {
        tis.reset(m_tls_tis_cache.back());
        m_tls_tis_cache.pop_back();
    }

    auto dek_obj = get_dek(info->key, info->key_len);
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

void qp_mgr_eth_mlx5::tls_context_resync_tx(const xlio_tls_info *info, xlio_tis *tis,
                                            bool skip_static)
{
    uint32_t tisn = tis->get_tisn();

    if (!skip_static) {
        tls_post_static_params_wqe(tis, info, tisn, tis->get_dek_id(), 0, true, true);
    }
    tls_post_progress_params_wqe(tis, tisn, 0, skip_static, true);
    m_b_fence_needed = true;
}

xlio_tir *qp_mgr_eth_mlx5::tls_create_tir(bool cached)
{
    xlio_tir *tir = NULL;

    if (cached && !m_tls_tir_cache.empty()) {
        tir = m_tls_tir_cache.back();
        m_tls_tir_cache.pop_back();
    } else if (!cached) {
        dpcp::tir *_tir = create_tir(true);

        if (_tir != NULL) {
            tir = new xlio_tir(_tir, xlio_ti::ti_type::TLS_TIR);
        }
        if (unlikely(tir == NULL && _tir != NULL)) {
            delete _tir;
        }
    }
    return tir;
}

int qp_mgr_eth_mlx5::tls_context_setup_rx(xlio_tir *tir, const xlio_tls_info *info,
                                          uint32_t next_record_tcp_sn, xlio_comp_cb_t callback,
                                          void *callback_arg)
{
    uint32_t tirn;
    dpcp::dek *_dek;
    dpcp::status status;
    dpcp::adapter *adapter = m_p_ib_ctx_handler->get_dpcp_adapter();
    struct dpcp::dek::attr dek_attr;

    memset(&dek_attr, 0, sizeof(dek_attr));
    dek_attr.flags = dpcp::DEK_ATTR_TLS;
    dek_attr.key = (void *)info->key;
    dek_attr.key_size_bytes = info->key_len;
    dek_attr.pd_id = adapter->get_pd();
    status = adapter->create_dek(dek_attr, _dek);
    if (unlikely(status != dpcp::DPCP_OK)) {
        qp_logerr("Failed to create DEK, status: %d", status);
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

void qp_mgr_eth_mlx5::tls_resync_rx(xlio_tir *tir, const xlio_tls_info *info,
                                    uint32_t hw_resync_tcp_sn)
{
    tls_post_static_params_wqe(tir, info, tir->get_tirn(), tir->get_dek_id(), hw_resync_tcp_sn,
                               false, false);
}

void qp_mgr_eth_mlx5::tls_get_progress_params_rx(xlio_tir *tir, void *buf, uint32_t lkey)
{
    /* Address must be aligned by 64. */
    assert((uintptr_t)buf == ((uintptr_t)buf >> 6U << 6U));

    tls_get_progress_params_wqe(tir, tir->get_tirn(), buf, lkey);
}

inline void qp_mgr_eth_mlx5::tls_fill_static_params_wqe(
    struct mlx5_wqe_tls_static_params_seg *params, const struct xlio_tls_info *info,
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

inline void qp_mgr_eth_mlx5::tls_post_static_params_wqe(xlio_ti *ti,
                                                        const struct xlio_tls_info *info,
                                                        uint32_t tis_tir_number, uint32_t key_id,
                                                        uint32_t resync_tcp_sn, bool fence,
                                                        bool is_tx)
{
    struct mlx5_set_tls_static_params_wqe *wqe =
        reinterpret_cast<struct mlx5_set_tls_static_params_wqe *>(m_sq_wqe_hot);
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
     *        3 WQEBBs posted from m_sq_wqe_hot current location.
     *     2. There is enough room in the SQ for 2 WQEBBs:
     *        2 WQEBBs posted from m_sq_wqe_hot current location till m_sq_wqes_end.
     *        1 WQEBB posted from m_sq_wqes beginning.
     *     3. There is enough room in the SQ for 1 WQEBB:
     *        1 WQEBB posted from m_sq_wqe_hot current location till m_sq_wqes_end.
     *        2 WQEBBs posted from m_sq_wqes beginning.
     * The case of 0 WQEBBs room left in the SQ shouldn't happen, m_sq_wqe_hot wrap around handling
     * done when setting next m_sq_wqe_hot.
     *
     * In all the 3 cases, no need to change cseg and ucseg pointers, since they fit to
     * one WQEBB and will be posted before m_sq_wqes_end.
     */

    // XXX: We set inline_hdr_sz for every new hot wqe. This corrupts UMR WQE without memset().
    memset(m_sq_wqe_hot, 0, sizeof(*m_sq_wqe_hot));
    cseg->opmod_idx_opcode =
        htobe32(((m_sq_wqe_counter & 0xffff) << 8) | MLX5_OPCODE_UMR | (opmod << 24));
    cseg->qpn_ds = htobe32((m_mlx5_qp.qpn << MLX5_WQE_CTRL_QPN_SHIFT) | STATIC_PARAMS_DS_CNT);
    cseg->fm_ce_se = fence ? MLX5_FENCE_MODE_INITIATOR_SMALL : 0;
    cseg->tis_tir_num = htobe32(tis_tir_number << 8);

    ucseg->flags = MLX5_UMR_INLINE;
    ucseg->bsf_octowords = htobe16(DEVX_ST_SZ_BYTES(tls_static_params) / 16);

    int num_wqebbs = TLS_SET_STATIC_PARAMS_WQEBBS;
    int num_wqebbs_top = 0;
    int sq_wqebbs_room_left =
        (static_cast<int>(m_sq_wqes_end - reinterpret_cast<uint8_t *>(cseg)) / MLX5_SEND_WQE_BB);

    /* Case 1:
     * In this case we don't need to change
     * the pointers of the different segments, because there is enough room in the SQ.
     * Thus, no need to do special handling.
     */

    if (unlikely(sq_wqebbs_room_left == 2)) { // Case 2: Change tspseg pointer:
        tspseg = reinterpret_cast<struct mlx5_wqe_tls_static_params_seg *>(m_sq_wqes);
        num_wqebbs = 2;
        num_wqebbs_top = 1;
    } else if (unlikely(sq_wqebbs_room_left == 1)) { // Case 3: Change mkcseg and tspseg pointers:
        mkcseg = reinterpret_cast<struct mlx5_mkey_seg *>(m_sq_wqes);
        tspseg = reinterpret_cast<struct mlx5_wqe_tls_static_params_seg *>(
            reinterpret_cast<uint8_t *>(m_sq_wqes) + sizeof(*mkcseg));
        num_wqebbs = 1;
        num_wqebbs_top = 2;
    }

    memset(mkcseg, 0, sizeof(*mkcseg));
    memset(tspseg, 0, sizeof(*tspseg));

    tls_fill_static_params_wqe(tspseg, info, key_id, resync_tcp_sn);
    store_current_wqe_prop(nullptr, SQ_CREDITS_UMR, ti);

    ring_doorbell(MLX5_DB_METHOD_DB, num_wqebbs, num_wqebbs_top, true);
    dbg_dump_wqe((uint32_t *)m_sq_wqe_hot, sizeof(mlx5_set_tls_static_params_wqe));

    update_next_wqe_hot();
}

inline void qp_mgr_eth_mlx5::tls_fill_progress_params_wqe(
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

inline void qp_mgr_eth_mlx5::tls_post_progress_params_wqe(xlio_ti *ti, uint32_t tis_tir_number,
                                                          uint32_t next_record_tcp_sn, bool fence,
                                                          bool is_tx)
{
    uint16_t num_wqebbs = TLS_SET_PROGRESS_PARAMS_WQEBBS;

    struct mlx5_set_tls_progress_params_wqe *wqe =
        reinterpret_cast<struct mlx5_set_tls_progress_params_wqe *>(m_sq_wqe_hot);
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

    ring_doorbell(MLX5_DB_METHOD_DB, num_wqebbs);
    dbg_dump_wqe((uint32_t *)m_sq_wqe_hot, sizeof(mlx5_set_tls_progress_params_wqe));

    update_next_wqe_hot();
}

inline void qp_mgr_eth_mlx5::tls_get_progress_params_wqe(xlio_ti *ti, uint32_t tirn, void *buf,
                                                         uint32_t lkey)
{
    uint16_t num_wqebbs = TLS_GET_PROGRESS_WQEBBS;

    struct mlx5_get_tls_progress_params_wqe *wqe =
        reinterpret_cast<struct mlx5_get_tls_progress_params_wqe *>(m_sq_wqe_hot);
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

    ring_doorbell(MLX5_DB_METHOD_DB, num_wqebbs);

    update_next_wqe_hot();
}

void qp_mgr_eth_mlx5::tls_tx_post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey,
                                           bool first)
{
    post_dump_wqe(tis, addr, len, lkey, first);
}

void qp_mgr_eth_mlx5::tls_release_tis(xlio_tis *tis)
{
    assert(tis != nullptr && tis->m_type == xlio_ti::ti_type::TLS_TIS);
    tis->m_released = true;
    if (tis->m_ref == 0) {
        put_tls_tis_in_cache(tis);
    }
}

void qp_mgr_eth_mlx5::tls_release_tir(xlio_tir *tir)
{
    /* TODO We don't have to lock ring to destroy DEK object (a garbage collector?). */

    assert(tir != nullptr && tir->m_type == xlio_ti::ti_type::TLS_TIR);
    tir->m_released = true;
    tir->assign_callback(NULL, NULL);
    if (tir->m_ref == 0) {
        put_tls_tir_in_cache(tir);
    }
}

dpcp::tir *qp_mgr_eth_mlx5::xlio_tir_to_dpcp_tir(xlio_tir *tir)
{
    return tir->m_p_tir.get();
}
#else /* DEFINED_UTLS */
void qp_mgr_eth_mlx5::ti_released(xlio_ti *) {};
void qp_mgr_eth_mlx5::destroy_tis_cache(void) {};
#endif /* DEFINED_UTLS */

#ifdef DEFINED_DPCP
std::unique_ptr<xlio_tis> qp_mgr_eth_mlx5::create_tis(uint32_t flags) const
{
    dpcp::adapter *adapter = m_p_ib_ctx_handler->get_dpcp_adapter();
    bool is_tls = flags & dpcp::TIS_ATTR_TLS, is_nvme = flags & dpcp::TIS_ATTR_NVMEOTCP;
    if (unlikely(adapter == nullptr || (is_tls && is_nvme))) {
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
        qp_logerr("Failed to create TIS with NVME enabled");
        return nullptr;
    }

    auto tis_type = is_tls ? xlio_ti::ti_type::TLS_TIS : xlio_ti::ti_type::NVME_TIS;
    return std::make_unique<xlio_tis>(std::unique_ptr<dpcp::tis>(dpcp_tis), tis_type);
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

void qp_mgr_eth_mlx5::nvme_set_static_context(xlio_tis *tis, uint32_t config)
{
    auto *cseg = wqebb_get<xlio_mlx5_wqe_ctrl_seg *>(0U);
    auto *ucseg = wqebb_get<xlio_mlx5_wqe_umr_ctrl_seg *>(0U, sizeof(*cseg));

    nvme_fill_static_params_control(cseg, ucseg, m_sq_wqe_counter, m_mlx5_qp.qpn, tis->get_tisn(),
                                    0);
    memset(wqebb_get<void *>(1U), 0, sizeof(mlx5_mkey_seg));

    auto *params = wqebb_get<mlx5_wqe_transport_static_params_seg *>(2U);
    nvme_fill_static_params_transport_params(params, config);
    store_current_wqe_prop(nullptr, SQ_CREDITS_UMR, tis);
    ring_doorbell(MLX5_DB_METHOD_DB, MLX5E_TRANSPORT_SET_STATIC_PARAMS_WQEBBS);
    update_next_wqe_hot();
}

void qp_mgr_eth_mlx5::nvme_set_progress_context(xlio_tis *tis, uint32_t tcp_seqno)
{
    auto *wqe = reinterpret_cast<mlx5e_set_nvmeotcp_progress_params_wqe *>(m_sq_wqe_hot);
    nvme_fill_progress_wqe(wqe, m_sq_wqe_counter, m_mlx5_qp.qpn, tis->get_tisn(), tcp_seqno,
                           MLX5_FENCE_MODE_INITIATOR_SMALL);
    store_current_wqe_prop(nullptr, SQ_CREDITS_SET_PSV, tis);
    ring_doorbell(MLX5_DB_METHOD_DB, MLX5E_NVMEOTCP_PROGRESS_PARAMS_WQEBBS);
    update_next_wqe_hot();
}
#endif /* DEFINED_DPCP */

#if defined(DEFINED_UTLS)
void qp_mgr_eth_mlx5::ti_released(xlio_ti *ti)
{
    assert(ti->m_released);
    assert(ti->m_ref == 0);
    if (ti->m_type == xlio_ti::ti_type::TLS_TIS) {
        put_tls_tis_in_cache(static_cast<xlio_tis *>(ti));
    } else if (ti->m_type == xlio_ti::ti_type::TLS_TIR) {
        put_tls_tir_in_cache(static_cast<xlio_tir *>(ti));
    }
}

void qp_mgr_eth_mlx5::put_tls_tis_in_cache(xlio_tis *tis)
{
    put_dek(tis->release_dek());
    m_tls_tis_cache.push_back(tis);
}

void qp_mgr_eth_mlx5::put_tls_tir_in_cache(xlio_tir *tir)
{
    // Because the absense of TIR flush command, reusing a TIR
    // may result in undefined behaviour.
    // Until a flush command is available the TIR cache is disabled.
    // Re-enabling TIR cache should also add destroy_tir_cache on ring cleanup.
    // m_tls_tir_cache.push_back(tir);

    delete tir;
}
#endif /* defined(DEFINED_UTLS) */

void qp_mgr_eth_mlx5::post_nop_fence(void)
{
    struct mlx5_wqe *wqe = reinterpret_cast<struct mlx5_wqe *>(m_sq_wqe_hot);
    struct xlio_mlx5_wqe_ctrl_seg *cseg = &wqe->ctrl;

    memset(wqe, 0, sizeof(*wqe));

    cseg->opmod_idx_opcode = htobe32(((m_sq_wqe_counter & 0xffff) << 8) | MLX5_OPCODE_NOP);
    cseg->qpn_ds = htobe32((m_mlx5_qp.qpn << MLX5_WQE_CTRL_QPN_SHIFT) | 0x01);
    cseg->fm_ce_se = MLX5_FENCE_MODE_INITIATOR_SMALL;

    store_current_wqe_prop(nullptr, SQ_CREDITS_NOP, NULL);

    ring_doorbell(MLX5_DB_METHOD_DB, 1);

    update_next_wqe_hot();
}

void qp_mgr_eth_mlx5::post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey,
                                    bool is_first)
{
    struct mlx5_dump_wqe *wqe = reinterpret_cast<struct mlx5_dump_wqe *>(m_sq_wqe_hot);
    struct xlio_mlx5_wqe_ctrl_seg *cseg = &wqe->ctrl.ctrl;
    struct mlx5_wqe_data_seg *dseg = &wqe->data;
    uint32_t tisn = tis ? tis->get_tisn() : 0;
    uint16_t num_wqebbs = XLIO_DUMP_WQEBBS;
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

    ring_doorbell(MLX5_DB_METHOD_DB, num_wqebbs, 0, true);

    update_next_wqe_hot();
}

//! Handle releasing of Tx buffers
// Single post send with SIGNAL of a dummy packet
// NOTE: Since the QP is in ERROR state no packets will be sent on the wire!
// So we can post_send anything we want :)
void qp_mgr_eth_mlx5::trigger_completion_for_all_sent_packets()
{
    qp_logfunc("unsignaled count=%d", m_n_unsignaled_count);

    if (!is_signal_requested_for_last_wqe()) {
        // Post a dummy WQE and request a signal to complete all the unsignaled WQEs in SQ
        qp_logdbg("Need to send closing tx wr...");
        mem_buf_desc_t *p_mem_buf_desc = m_p_ring->mem_buf_tx_get(0, true, PBUF_RAM);
        // Align Tx buffer accounting since we will be bypassing the normal send calls
        m_p_ring->m_missing_buf_ref_count--;
        if (!p_mem_buf_desc) {
            qp_logerr("no buffer in pool");
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
        send_wr.wr.ud.ah = NULL;
        send_wr.sg_list = sge;
        send_wr.num_sge = 1;
        send_wr.next = NULL;
        xlio_send_wr_opcode(send_wr) = XLIO_IBV_WR_SEND;

        unsigned credits = credits_calculate(&send_wr);
        if (!credits_get(credits)) {
            // TODO Wait for available space in SQ to post the WQE. This method mustn't fail,
            // because we may want to wait until all the WQEs are completed and we need to post
            // something and request signal.
            qp_logdbg("No space in SQ to trigger completions with a post operation");
            return;
        }

        send_to_wire(&send_wr,
                     (xlio_wr_tx_packet_attr)(XLIO_TX_PACKET_L3_CSUM | XLIO_TX_PACKET_L4_CSUM),
                     true, nullptr, credits);
    }
}

void qp_mgr_eth_mlx5::reset_inflight_zc_buffers_ctx(void *ctx)
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

#endif /* DEFINED_DIRECT_VERBS */
