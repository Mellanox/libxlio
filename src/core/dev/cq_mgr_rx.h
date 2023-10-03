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

#ifndef CQ_MGR_RX_H
#define CQ_MGR_RX_H

#include "ib/base/verbs_extra.h"
#include "utils/atomic.h"
#include "dev/qp_mgr.h"
#include "dev/ib_ctx_handler.h"
#include "util/sys_vars.h"
#include "util/xlio_stats.h"
#include "proto/mem_buf_desc.h"
#include "proto/xlio_lwip.h"
#include "xlio_extra.h"

#if VLIST_DEBUG
#define VLIST_DEBUG_CQ_MGR_PRINT_ERROR_IS_MEMBER                                                   \
    do {                                                                                           \
        if (buff->buffer_node.is_list_member())                                                    \
            cq_logwarn("Buffer is already a member in a list! id=[%s]",                            \
                       buff->buffer_node.list_id());                                               \
    } while (0)
#else
#define VLIST_DEBUG_CQ_MGR_PRINT_ERROR_IS_MEMBER
#endif

class net_device_mgr;
class ring;
class qp_mgr;
class qp_mgr_eth_mlx5;
class ring_simple;

/* Get CQE opcode. */
#define MLX5_CQE_OPCODE(op_own) ((op_own) >> 4)

/* Get CQE owner bit. */
#define MLX5_CQE_OWNER(op_own) ((op_own)&MLX5_CQE_OWNER_MASK)

class cq_mgr_rx {
    friend class ring; // need to expose the m_n_global_sn_rx only to ring
    friend class ring_simple; // need to expose the m_n_global_sn_rx only to ring
    friend class ring_bond; // need to expose the m_n_global_sn_rx only to ring
    friend class rfs_uc_tcp_gro; // need for stats

public:
    enum buff_status_e {
        BS_OK,
        BS_CQE_RESP_WR_IMM_NOT_SUPPORTED,
        BS_IBV_WC_WR_FLUSH_ERR,
        BS_CQE_INVALID,
        BS_GENERAL_ERR
    };

    cq_mgr_rx(ring_simple *p_ring, ib_ctx_handler *p_ib_ctx_handler, int cq_size,
              struct ibv_comp_channel *p_comp_event_channel);
    virtual ~cq_mgr_rx();

    void configure(int cq_size);

    ibv_cq *get_ibv_cq_hndl() { return m_p_ibv_cq; }
    int get_channel_fd() { return m_comp_event_channel->fd; }

    /**
     * Arm the managed CQ's notification channel
     * Calling this more then once without get_event() will return without
     * doing anything (arm flag is changed to true on first call).
     * This call will also check if a wce was processes between the
     * last poll and this arm request - if true it will not arm the CQ
     * @return ==0 cq is armed
     *         ==1 cq not armed (cq poll_sn out of sync)
     *         < 0 on error
     */
    int request_notification(uint64_t poll_sn);

    /**
     * Block on the CQ's notification channel for the next event and process
     * it before exiting.
     *
     * @return >=0 number of processed wce
     *         < 0 error or if channel not armed or channel would block
     *             (on non-blocked channel) (some other thread beat you to it)
     */
    int wait_for_notification_and_process_element(uint64_t *p_cq_poll_sn,
                                                  void *pv_fd_ready_array = NULL);

    /**
     * This will poll n_num_poll time on the cq or stop early if it gets
     * a wce (work completion element). If a wce was found 'processing' will
     * occur.
     * @return >=0 number of wce processed
     *         < 0 error
     */
    virtual int poll_and_process_element_rx(uint64_t *p_cq_poll_sn,
                                            void *pv_fd_ready_array = NULL) = 0;
    virtual mem_buf_desc_t *poll_and_process_socketxtreme() { return nullptr; };

    /**
     * This will check if the cq was drained, and if it wasn't it will drain it.
     * @param restart - In case of restart - don't process any buffer
     * @return  >=0 number of wce processed
     *          < 0 error
     */
    virtual int drain_and_proccess(uintptr_t *p_recycle_buffers_last_wr_id = NULL) = 0;

    // CQ implements the Rx mem_buf_desc_owner.
    // These callbacks will be called for each Rx buffer that passed processed completion
    // Rx completion handling at the cq_mgr_rx level is forwarding the packet to the ib_comm_mgr
    // layer
    void mem_buf_desc_return_to_owner(mem_buf_desc_t *p_mem_buf_desc,
                                      void *pv_fd_ready_array = NULL);

    virtual void add_qp_rx(qp_mgr *qp);
    virtual void del_qp_rx(qp_mgr *qp);

    virtual uint32_t clean_cq() = 0;

    bool reclaim_recv_buffers(descq_t *rx_reuse);
    bool reclaim_recv_buffers(mem_buf_desc_t *rx_reuse_lst);
    bool reclaim_recv_buffers_no_lock(mem_buf_desc_t *rx_reuse_lst);
    int reclaim_recv_single_buffer(mem_buf_desc_t *rx_reuse);

    void get_cq_event(int count = 1) { xlio_ib_mlx5_get_cq_event(&m_mlx5_cq, count); };

protected:
    /**
     * Poll the CQ that is managed by this object
     * @p_wce pointer to array where to save the wce in
     * @num_entries Size of the p_wce (max number of wce to poll at once)
     * @p_cq_poll_sn global unique wce id that maps last wce polled
     * @return Number of successfully polled wce
     */
    void compensate_qp_poll_failed();
    void lro_update_hdr(struct xlio_mlx5_cqe *cqe, mem_buf_desc_t *p_rx_wc_buf_desc);
    inline void process_recv_buffer(mem_buf_desc_t *buff, void *pv_fd_ready_array = NULL);

    inline void update_global_sn_rx(uint64_t &cq_poll_sn, uint32_t rettotal);

    inline struct xlio_mlx5_cqe *check_cqe(void);

    mem_buf_desc_t *cqe_process_rx(mem_buf_desc_t *p_mem_buf_desc, enum buff_status_e status);

    virtual void reclaim_recv_buffer_helper(mem_buf_desc_t *buff);

    // Returns true if the given buffer was used,
    // false if the given buffer was not used.
    bool compensate_qp_poll_success(mem_buf_desc_t *buff);
    inline uint32_t process_recv_queue(void *pv_fd_ready_array = NULL);

    virtual void statistics_print();

    xlio_ib_mlx5_cq_t m_mlx5_cq;
    qp_mgr_eth_mlx5 *m_qp = nullptr;
    mem_buf_desc_t *m_rx_hot_buffer = nullptr;
    struct ibv_cq *m_p_ibv_cq = nullptr;
    descq_t m_rx_queue;
    static uint64_t m_n_global_sn_rx;
    uint32_t m_cq_id_rx = 0U;
    uint32_t m_n_cq_poll_sn_rx = 0U;
    ring_simple *m_p_ring;
    uint32_t m_n_wce_counter = 0U;
    bool m_b_was_drained = false;
    bool m_b_is_rx_hw_csum_on = false;
    int m_debt = 0;
    const uint32_t m_n_sysvar_cq_poll_batch_max;
    const uint32_t m_n_sysvar_progress_engine_wce_max;
    cq_stats_t *m_p_cq_stat;
    mem_buf_desc_t *m_p_next_rx_desc_poll = nullptr;
    uint32_t m_n_sysvar_rx_prefetch_bytes_before_poll;
    const uint32_t m_n_sysvar_rx_prefetch_bytes;
    size_t m_sz_transport_header = ETH_HDR_LEN;
    ib_ctx_handler *m_p_ib_ctx_handler;
    const uint32_t m_n_sysvar_rx_num_wr_to_post_recv;
    descq_t m_rx_pool;

    /* This fields are needed to track internal memory buffers
     * represented as struct xlio_buff_t
     * from user application by special XLIO extended API
     */
    mem_buf_desc_t *m_rx_buffs_rdy_for_free_head = nullptr;
    mem_buf_desc_t *m_rx_buffs_rdy_for_free_tail = nullptr;

private:
    struct ibv_comp_channel *m_comp_event_channel;
    bool m_b_notification_armed = false;
    const uint32_t m_n_sysvar_qp_compensation_level;
    const uint32_t m_rx_lkey;
    const bool m_b_sysvar_cq_keep_qp_full;
    cq_stats_t m_cq_stat_static;
    static atomic_t m_n_cq_id_counter_rx;

    // requests safe_mce_sys().qp_compensation_level buffers from global pool
    bool request_more_buffers() __attribute__((noinline));

    // returns safe_mce_sys().qp_compensation_level buffers to global pool
    void return_extra_buffers() __attribute__((noinline));
};

inline void cq_mgr_rx::update_global_sn_rx(uint64_t &cq_poll_sn, uint32_t num_polled_cqes)
{
    if (num_polled_cqes > 0) {
        // spoil the global sn if we have packets ready
        union __attribute__((packed)) {
            uint64_t global_sn;
            struct {
                uint32_t cq_id;
                uint32_t cq_sn;
            } bundle;
        } next_sn;
        m_n_cq_poll_sn_rx += num_polled_cqes;
        next_sn.bundle.cq_sn = m_n_cq_poll_sn_rx;
        next_sn.bundle.cq_id = m_cq_id_rx;

        m_n_global_sn_rx = next_sn.global_sn;
    }

    cq_poll_sn = m_n_global_sn_rx;
}

inline struct xlio_mlx5_cqe *cq_mgr_rx::check_cqe(void)
{
    struct xlio_mlx5_cqe *cqe =
        (struct xlio_mlx5_cqe *)(((uint8_t *)m_mlx5_cq.cq_buf) +
                                 ((m_mlx5_cq.cq_ci & (m_mlx5_cq.cqe_count - 1))
                                  << m_mlx5_cq.cqe_size_log));
    /*
     * CQE ownership is defined by Owner bit in the CQE.
     * The value indicating SW ownership is flipped every
     *  time CQ wraps around.
     * */
    if (likely((MLX5_CQE_OPCODE(cqe->op_own)) != MLX5_CQE_INVALID) &&
        !((MLX5_CQE_OWNER(cqe->op_own)) ^ !!(m_mlx5_cq.cq_ci & m_mlx5_cq.cqe_count))) {
        return cqe;
    }

    return NULL;
}

#endif // CQ_MGR_H
