/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2023-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "dev/cq_mgr_tx.h"
#include <util/valgrind.h>
#include <sock/sock-redirect.h>
#include <sock/sock-app.h>
#include <iomanip>
#include "ring_simple.h"
#include "hw_queue_tx.h"

#define MODULE_NAME "cq_mgr_tx"

#define cq_logpanic   __log_info_panic
#define cq_logerr     __log_info_err
#define cq_logwarn    __log_info_warn
#define cq_loginfo    __log_info_info
#define cq_logdbg     __log_info_dbg
#define cq_logfunc    __log_info_func
#define cq_logfuncall __log_info_funcall

#define WQEBB_SIZE 64

atomic_t cq_mgr_tx::m_n_cq_id_counter_tx = ATOMIC_INIT(1);

uint64_t cq_mgr_tx::m_n_global_sn_tx = 0U;

cq_mgr_tx::cq_mgr_tx(ring_simple *p_ring, ib_ctx_handler *p_ib_ctx_handler, int cq_size,
                     ibv_comp_channel *p_comp_event_channel)
    : m_p_ring(p_ring)
    , m_p_ib_ctx_handler(p_ib_ctx_handler)
    , m_comp_event_channel(p_comp_event_channel)
{
    m_cq_id_tx = atomic_fetch_and_inc(&m_n_cq_id_counter_tx); // cq id is nonzero
    configure(cq_size);

    memset(&m_mlx5_cq, 0, sizeof(m_mlx5_cq));
}

cq_mgr_tx::~cq_mgr_tx()
{
    cq_logdbg("Destroying CQ as Tx");

    IF_VERBS_FAILURE_EX(ibv_destroy_cq(m_p_ibv_cq), EIO)
    {
        cq_logdbg("destroy cq failed (errno=%d %m)", errno);
    }
    ENDIF_VERBS_FAILURE;
    VALGRIND_MAKE_MEM_UNDEFINED(m_p_ibv_cq, sizeof(ibv_cq));
    cq_logdbg("Destroying CQ as Tx done");
}

void cq_mgr_tx::configure(int cq_size)
{
    struct ibv_context *context = m_p_ib_ctx_handler->get_ibv_context();
    int comp_vector = 0;
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    /*
     * For some scenario with forking usage we may want to distribute CQs across multiple
     * CPUs to improve CPS in case of multiple processes.
     */
    if (safe_mce_sys().app.distribute_cq_interrupts && g_p_app->get_worker_id() >= 0) {
        comp_vector = g_p_app->get_worker_id() % context->num_comp_vectors;
    }
#endif

    struct ibv_cq_init_attr_ex attr = {};
    struct mlx5dv_cq_init_attr dvattr = {};

    attr.cqe = cq_size - 1; // This parameter is incremented by 1 in libibverbs
    attr.cq_context = (void *)this;
    attr.channel = m_comp_event_channel;
    attr.comp_vector = comp_vector;
    attr.wc_flags = IBV_WC_STANDARD_FLAGS;
    attr.comp_mask = IBV_CQ_INIT_ATTR_MASK_FLAGS;
    attr.flags = IBV_CREATE_CQ_ATTR_IGNORE_OVERRUN;

    struct ibv_cq_ex *cq_ex = mlx5dv_create_cq(context, &attr, &dvattr);
    m_p_ibv_cq = ibv_cq_ex_to_cq(cq_ex);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!m_p_ibv_cq) {
        throw_xlio_exception("ibv_create_cq failed");
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    VALGRIND_MAKE_MEM_DEFINED(m_p_ibv_cq, sizeof(ibv_cq));

    cq_logdbg("Created CQ as Tx with fd[%d] and of size %d elements (ibv_cq_hndl=%p)",
              get_channel_fd(), cq_size, m_p_ibv_cq);
}

void cq_mgr_tx::add_qp_tx(hw_queue_tx *hqtx_ptr)
{
    // Assume locked!
    cq_logdbg("hqtx_ptr=%p", hqtx_ptr);
    m_hqtx_ptr = hqtx_ptr;

    if (0 != xlio_ib_mlx5_get_cq(m_p_ibv_cq, &m_mlx5_cq)) {
        cq_logpanic("xlio_ib_mlx5_get_cq failed (errno=%d %m)", errno);
    }

    cq_logfunc("hqtx_ptr=%p m_mlx5_cq.dbrec=%p m_mlx5_cq.cq_buf=%p", m_hqtx_ptr, m_mlx5_cq.dbrec,
               m_mlx5_cq.cq_buf);
}

void cq_mgr_tx::del_qp_tx(hw_queue_tx *hqtx_ptr)
{
    BULLSEYE_EXCLUDE_BLOCK_START
    if (m_hqtx_ptr != hqtx_ptr) {
        cq_logdbg("wrong hqtx_ptr=%p != m_hqtx_ptr=%p", hqtx_ptr, m_hqtx_ptr);
        return;
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    cq_logdbg("m_hqtx_ptr=%p", m_hqtx_ptr);
    m_hqtx_ptr = nullptr;
}

int cq_mgr_tx::request_notification(uint64_t poll_sn)
{
    int ret = -1;

    cq_logfuncall("");

    if ((m_n_global_sn_tx > 0 && poll_sn != m_n_global_sn_tx)) {
        // The cq_mgr_tx's has receive packets pending processing (or got processed since
        // cq_poll_sn)
        cq_logfunc("miss matched poll sn (user=0x%lx, cq=0x%lx)", poll_sn, m_n_cq_poll_sn_tx);
        return 1;
    }

    if (m_b_notification_armed == false) {

        cq_logfunc("arming cq_mgr_tx notification channel");

        // Arm the CQ notification channel
        IF_VERBS_FAILURE(xlio_ib_mlx5_req_notify_cq(&m_mlx5_cq, 0))
        {
            cq_logerr("Failure arming the TX notification channel (errno=%d %m)", errno);
        }
        else
        {
            ret = 0;
            m_b_notification_armed = true;
        }
        ENDIF_VERBS_FAILURE;
    } else {
        // cq_mgr_tx notification channel already armed
        ret = 0;
    }

    cq_logfuncall("returning with %d", ret);
    return ret;
}

cq_mgr_tx *cq_mgr_tx::get_cq_mgr_from_cq_event(struct ibv_comp_channel *p_cq_channel)
{
    cq_mgr_tx *p_cq_mgr = nullptr;
    struct ibv_cq *p_cq_hndl = nullptr;
    void *p_context; // deal with compiler warnings

    // read & ack the CQ event
    IF_VERBS_FAILURE(ibv_get_cq_event(p_cq_channel, &p_cq_hndl, &p_context))
    {
        vlog_printf(VLOG_INFO,
                    MODULE_NAME
                    ":%d: waiting on cq_mgr_tx event returned with error (errno=%d %m)\n",
                    __LINE__, errno);
    }
    else
    {
        p_cq_mgr = (cq_mgr_tx *)p_context; // Save the cq_mgr_tx
        p_cq_mgr->get_cq_event();
        ibv_ack_cq_events(p_cq_hndl, 1); // Ack the ibv event
    }
    ENDIF_VERBS_FAILURE;

    return p_cq_mgr;
}

std::string cq_mgr_tx::wqe_to_hexstring(uint16_t index, uint32_t credits) const
{
    const auto sq_start = static_cast<const uint8_t *>(m_hqtx_ptr->m_mlx5_qp.sq.buf);

    std::ostringstream oss;
    // see `calculate_credits` - credits is give or take the amount of WQEBBs per WQE
    for (uint32_t wqebb_i = 0; wqebb_i < credits; ++wqebb_i) {
        const uint32_t wqebb_wrapped_index = (index + wqebb_i) & (m_hqtx_ptr->m_tx_num_wr - 1);
        const auto current_wqebb_begin = sq_start + wqebb_wrapped_index * WQEBB_SIZE;

        for (uint8_t wqebb_inner_i = 0; wqebb_inner_i < WQEBB_SIZE; ++wqebb_inner_i) {
            const auto current_byte_ptr = current_wqebb_begin + wqebb_inner_i;
            oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<uint32_t>(*current_byte_ptr);
        }
    }

    return oss.str();
}

int cq_mgr_tx::poll_and_process_element_tx(uint64_t *p_cq_poll_sn)
{
    cq_logfuncall("");

    static auto is_error_opcode = [&](uint8_t opcode) {
        return opcode == MLX5_CQE_REQ_ERR || opcode == MLX5_CQE_RESP_ERR;
    };

    int ret = 0;
    uint32_t num_polled_cqes = 0;
    xlio_mlx5_cqe *cqe = get_cqe_tx(num_polled_cqes);

    if (likely(cqe)) {
        unsigned index = ntohs(cqe->wqe_counter) & (m_hqtx_ptr->m_tx_num_wr - 1);

        // All error opcodes have the most significant bit set.
        if (unlikely(cqe->op_own & 0x80) && is_error_opcode(cqe->op_own >> 4)) {
            // m_p_cq_stat->n_tx_cqe_error++; Future counter
            log_cqe_error(cqe, index, m_hqtx_ptr->m_sq_wqe_idx_to_prop[index].credits);

            m_hqtx_ptr->m_sq_wqe_idx_to_prop[index].buf->m_flags |= mem_buf_desc_t::HAD_CQE_ERROR;
        }

        handle_sq_wqe_prop(index);
        ret = 1;
    }
    update_global_sn_tx(*p_cq_poll_sn, num_polled_cqes);

    return ret;
}

void cq_mgr_tx::log_cqe_error(struct xlio_mlx5_cqe *cqe, uint16_t wqe_index, uint32_t credits) const
{
    struct mlx5_err_cqe *ecqe = (struct mlx5_err_cqe *)cqe;

    /* TODO We can also ask hw_queue_tx to log WQE fields from SQ. But at first, we need to remove
     * prefetch and memset of the next WQE there. Credit system will guarantee that we don't
     * reuse the WQE at this point.
     */

    if (MLX5_CQE_SYNDROME_WR_FLUSH_ERR != ecqe->syndrome) {
        cq_logwarn("cqe: syndrome=0x%x vendor=0x%x hw=0x%x (type=0x%x) wqe_opcode_qpn=0x%x "
                   "wqe_counter=0x%x wqe=%s",
                   ecqe->syndrome, ecqe->vendor_err_synd, *((uint8_t *)&ecqe->rsvd1 + 16),
                   *((uint8_t *)&ecqe->rsvd1 + 17), ntohl(ecqe->s_wqe_opcode_qpn),
                   ntohs(ecqe->wqe_counter), wqe_to_hexstring(wqe_index, credits).c_str());
    }
}

void cq_mgr_tx::handle_sq_wqe_prop(unsigned index)
{
    sq_wqe_prop *p = &m_hqtx_ptr->m_sq_wqe_idx_to_prop[index];
    sq_wqe_prop *prev;
    unsigned credits = 0;

    /*
     * TX completions can be signalled for a set of WQEs as an optimization.
     * Therefore, for every TX completion we may need to handle multiple
     * WQEs. Since every WQE can have various size and the WQE index is
     * wrapped around, we build a linked list to simplify things. Each
     * element of the linked list represents properties of a previously
     * posted WQE.
     *
     * We keep index of the last completed WQE and stop processing the list
     * when we reach the index. This condition is checked in
     * is_sq_wqe_prop_valid().
     */

    do {
        if (p->buf) {
            m_p_ring->mem_buf_desc_return_single_locked(p->buf);
        }
        if (p->ti) {
            xlio_ti *ti = p->ti;
            if (ti->m_callback) {
                ti->m_callback(ti->m_callback_arg);
            }

            ti->put();
            if (unlikely(ti->m_released && ti->m_ref == 0)) {
                ti->ti_released();
            }
        }
        credits += p->credits;

        prev = p;
        p = p->next;
    } while (p && m_hqtx_ptr->is_sq_wqe_prop_valid(p, prev));

    m_p_ring->return_tx_pool_to_global_pool();
    m_hqtx_ptr->credits_return(credits);
    m_hqtx_ptr->m_sq_wqe_prop_last_signalled = index;
}
