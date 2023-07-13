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

#include <mutex>
#include "ring_simple.h"

#include "util/valgrind.h"
#include "util/sg_array.h"
#include "sock/fd_collection.h"
#if defined(DEFINED_DIRECT_VERBS)
#include "dev/qp_mgr_eth_mlx5.h"
#include "dev/qp_mgr_eth_mlx5_dpcp.h"
#endif

#undef MODULE_NAME
#define MODULE_NAME "ring_simple"
#undef MODULE_HDR
#define MODULE_HDR MODULE_NAME "%d:%s() "

#define ALIGN_WR_DOWN(_num_wr_) (std::max(32, ((_num_wr_) & ~(0xf))))
#define RING_TX_BUFS_COMPENSATE 256U

#define RING_LOCK_AND_RUN(__lock__, __func_and_params__)                                           \
    __lock__.lock();                                                                               \
    __func_and_params__;                                                                           \
    __lock__.unlock();

#define RING_TRY_LOCK_RUN_AND_UPDATE_RET(__lock__, __func_and_params__)                            \
    if (!__lock__.trylock()) {                                                                     \
        ret = __func_and_params__;                                                                 \
        __lock__.unlock();                                                                         \
    } else {                                                                                       \
        errno = EAGAIN;                                                                            \
    }

/**/
/** inlining functions can only help if they are implemented before their usage **/
/**/

inline void ring_simple::send_status_handler(int ret, xlio_ibv_send_wr *p_send_wqe)
{
    BULLSEYE_EXCLUDE_BLOCK_START
    if (unlikely(ret)) {
        // Error during post_send, reclaim the tx buffer
        if (p_send_wqe) {
            mem_buf_desc_t *p_mem_buf_desc = (mem_buf_desc_t *)(p_send_wqe->wr_id);
            mem_buf_tx_release(p_mem_buf_desc, true);
        }
    } else {
        // Update TX statistics
        sg_array sga(p_send_wqe->sg_list, p_send_wqe->num_sge);
        m_p_ring_stat->n_tx_byte_count += sga.length();
        ++m_p_ring_stat->n_tx_pkt_count;

        // Decrease counter in order to keep track of how many missing buffers we have when
        // doing ring->restart() and then drain_tx_buffers_to_buffer_pool()
        m_missing_buf_ref_count--;
    }
    BULLSEYE_EXCLUDE_BLOCK_END
}

qp_mgr *ring_eth::create_qp_mgr(struct qp_mgr_desc *desc)
{
#if defined(DEFINED_DPCP)
    if (safe_mce_sys().enable_dpcp_rq) {
        return new qp_mgr_eth_mlx5_dpcp(desc, get_tx_num_wr(), m_partition);
    }
#endif
    return new qp_mgr_eth_mlx5(desc, get_tx_num_wr(), m_partition);
}

ring_simple::ring_simple(int if_index, ring *parent, ring_type_t type, bool use_locks)
    : ring_slave(if_index, parent, type, use_locks)
    , m_p_ib_ctx(NULL)
    , m_p_qp_mgr(NULL)
    , m_p_cq_mgr_rx(NULL)
    , m_p_cq_mgr_tx(NULL)
    , m_lock_ring_tx_buf_wait("ring:lock_tx_buf_wait")
    , m_tx_num_bufs(0)
    , m_zc_num_bufs(0)
    , m_tx_num_wr(0)
    , m_missing_buf_ref_count(0)
    , m_tx_lkey(0)
    , m_gro_mgr(safe_mce_sys().gro_streams_max, MAX_GRO_BUFS)
    , m_up(false)
    , m_p_rx_comp_event_channel(NULL)
    , m_p_tx_comp_event_channel(NULL)
    , m_p_l2_addr(NULL)
{
    net_device_val *p_ndev = g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());
    const slave_data_t *p_slave = p_ndev->get_slave(get_if_index());

    ring_logdbg("new ring_simple()");

    /* m_p_ib_ctx, m_tx_lkey should be initialized to be used
     * in ring_eth_direct, ring_eth_cb constructors
     */
    BULLSEYE_EXCLUDE_BLOCK_START
    m_p_ib_ctx = p_slave->p_ib_ctx;
    if (m_p_ib_ctx == NULL) {
        ring_logpanic("m_p_ib_ctx = NULL. It can be related to wrong bonding configuration");
    }

    m_tx_lkey = g_buffer_pool_tx->find_lkey_by_ib_ctx_thread_safe(m_p_ib_ctx);
    if (m_tx_lkey == 0) {
        __log_info_panic("invalid lkey found %u", m_tx_lkey);
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    /* initialization basing on ndev information */
    m_mtu = p_ndev->get_mtu();

    memset(&m_cq_moderation_info, 0, sizeof(m_cq_moderation_info));
    memset(&m_tso, 0, sizeof(m_tso));
#ifdef DEFINED_UTLS
    memset(&m_tls, 0, sizeof(m_tls));
#endif /* DEFINED_UTLS */
    memset(&m_lro, 0, sizeof(m_lro));

    INIT_LIST_HEAD(&m_socketxtreme.ec_list);
}

ring_simple::~ring_simple()
{
    ring_logdbg("delete ring_simple()");

    // Go over all hash and for each flow: 1.Detach from qp 2.Delete related rfs object 3.Remove
    // flow from hash
    m_lock_ring_rx.lock();
    flow_del_all_rfs();
    m_lock_ring_rx.unlock();

    // Allow last few post sends to be sent by HCA.
    // Was done in order to allow iperf's FIN packet to be sent.
    usleep(25000);

    if (m_p_qp_mgr) {
        stop_active_qp_mgr();

        // Release QP/CQ resources
        delete m_p_qp_mgr;
        m_p_qp_mgr = NULL;
    }

    /* coverity[double_lock] TODO: RM#1049980 */
    m_lock_ring_rx.lock();
    m_lock_ring_tx.lock();

    delete_l2_address();

    // Delete the rx channel fd from the global fd collection
    if (g_p_fd_collection) {
        if (m_p_rx_comp_event_channel) {
            g_p_fd_collection->del_cq_channel_fd(m_p_rx_comp_event_channel->fd, true);
        }
        if (m_p_tx_comp_event_channel) {
            g_p_fd_collection->del_cq_channel_fd(m_p_tx_comp_event_channel->fd, true);
        }
    }

    if (m_p_rx_comp_event_channel) {
        IF_VERBS_FAILURE(ibv_destroy_comp_channel(m_p_rx_comp_event_channel))
        {
            ring_logdbg("destroy comp channel failed (errno=%d %m)", errno);
        }
        ENDIF_VERBS_FAILURE;
        VALGRIND_MAKE_MEM_UNDEFINED(m_p_rx_comp_event_channel, sizeof(struct ibv_comp_channel));
    }

    delete[] m_p_n_rx_channel_fds;

    ring_logdbg("Tx buffer poll: free count = %lu, sender_has = %u, total = %d, %s (%lu)",
                m_tx_pool.size() + m_zc_pool.size(), m_missing_buf_ref_count,
                m_tx_num_bufs + m_zc_num_bufs,
                ((m_tx_num_bufs + m_zc_num_bufs - m_tx_pool.size() - m_zc_pool.size() -
                  m_missing_buf_ref_count)
                     ? "bad accounting!!"
                     : "good accounting"),
                (m_tx_num_bufs + m_zc_num_bufs - m_tx_pool.size() - m_zc_pool.size() -
                 m_missing_buf_ref_count));
    ring_logdbg("Rx buffer pool: %lu free global buffers available", m_tx_pool.size());

    // Release verbs resources
    if (m_p_tx_comp_event_channel) {
        IF_VERBS_FAILURE(ibv_destroy_comp_channel(m_p_tx_comp_event_channel))
        {
            ring_logdbg("destroy comp channel failed (errno=%d %m)", errno);
        }
        ENDIF_VERBS_FAILURE;
        VALGRIND_MAKE_MEM_UNDEFINED(m_p_tx_comp_event_channel, sizeof(struct ibv_comp_channel));
        m_p_tx_comp_event_channel = NULL;
    }

    /* coverity[double_unlock] TODO: RM#1049980 */
    m_lock_ring_tx.unlock();
    m_lock_ring_rx.unlock();

    ring_logdbg("queue of event completion elements is %s",
                (list_empty(&m_socketxtreme.ec_list) ? "empty" : "not empty"));
    while (!list_empty(&m_socketxtreme.ec_list)) {
        struct ring_ec *ec = NULL;
        ec = get_ec();
        if (ec) {
            del_ec(ec);
        }
    }

    ring_logdbg("delete ring_simple() completed");
}

void ring_simple::create_resources()
{
    net_device_val *p_ndev = g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());
    const slave_data_t *p_slave = p_ndev->get_slave(get_if_index());

    save_l2_address(p_slave->p_L2_addr);
    m_p_tx_comp_event_channel = ibv_create_comp_channel(m_p_ib_ctx->get_ibv_context());
    if (m_p_tx_comp_event_channel == NULL) {
        VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(
            VLOG_ERROR, VLOG_DEBUG,
            "ibv_create_comp_channel for tx failed. m_p_tx_comp_event_channel = %p (errno=%d %m)",
            m_p_tx_comp_event_channel, errno);
        if (errno == EMFILE) {
            VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(VLOG_ERROR, VLOG_DEBUG,
                                              "did we run out of file descriptors? traffic may not "
                                              "be offloaded, increase ulimit -n");
        }
        throw_xlio_exception("create event channel failed");
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    VALGRIND_MAKE_MEM_DEFINED(m_p_tx_comp_event_channel, sizeof(struct ibv_comp_channel));
    // Check device capabilities for max QP work requests
    uint32_t max_qp_wr = ALIGN_WR_DOWN(m_p_ib_ctx->get_ibv_device_attr()->max_qp_wr);
    m_tx_num_wr = safe_mce_sys().tx_num_wr;
    if (m_tx_num_wr > max_qp_wr) {
        ring_logwarn(
            "Allocating only %d Tx QP work requests while user requested %s=%d for QP on interface",
            max_qp_wr, SYS_VAR_TX_NUM_WRE, m_tx_num_wr);
        m_tx_num_wr = max_qp_wr;
    }
    ring_logdbg("ring attributes: m_tx_num_wr = %d", m_tx_num_wr);

    /* Detect TSO capabilities */
    memset(&m_tso, 0, sizeof(m_tso));
    if ((safe_mce_sys().enable_tso == option_3::ON) ||
        ((safe_mce_sys().enable_tso == option_3::AUTO) && (1 == validate_tso(get_if_index())))) {
        if (xlio_check_dev_attr_tso(m_p_ib_ctx->get_ibv_device_attr())) {
            const xlio_ibv_tso_caps *caps =
                &xlio_get_tso_caps(m_p_ib_ctx->get_ibv_device_attr_ex());
            if (ibv_is_qpt_supported(caps->supported_qpts, IBV_QPT_RAW_PACKET)) {
                m_tso.max_payload_sz = caps->max_tso;
                /* ETH(14) + IP(20) + TCP(20) + TCP OPTIONS(40) */
                m_tso.max_header_sz = 94;
            }
        }
    }
    ring_logdbg("ring attributes: m_tso = %d", is_tso());
    ring_logdbg("ring attributes: m_tso:max_payload_sz = %d", get_max_payload_sz());
    ring_logdbg("ring attributes: m_tso:max_header_sz = %d", get_max_header_sz());

    /* Detect LRO capabilities */
    memset(&m_lro, 0, sizeof(m_lro));
    if ((safe_mce_sys().enable_lro == option_3::ON) ||
        ((safe_mce_sys().enable_lro == option_3::AUTO) && (1 == validate_lro(get_if_index())))) {
#if defined(DEFINED_DPCP)
        dpcp::adapter_hca_capabilities caps;

        if (m_p_ib_ctx->get_dpcp_adapter() &&
            (dpcp::DPCP_OK == m_p_ib_ctx->get_dpcp_adapter()->get_hca_capabilities(caps))) {
            m_lro.cap = caps.lro_cap;
            m_lro.psh_flag = caps.lro_psh_flag;
            m_lro.time_stamp = caps.lro_time_stamp;
            m_lro.max_msg_sz_mode = caps.lro_max_msg_sz_mode;
            m_lro.min_mss_size = caps.lro_min_mss_size;

            memcpy(m_lro.timer_supported_periods, caps.lro_timer_supported_periods,
                   sizeof(m_lro.timer_supported_periods));
            /* calculate possible payload size w/o using max_msg_sz_mode
             * because during memory buffer allocation L2+L3+L4 is reserved
             * adjust payload size to 256 bytes
             */
            uint32_t actual_buf_size =
                (!safe_mce_sys().rx_buf_size && safe_mce_sys().enable_striding_rq
                     ? std::min(65280U,
                                safe_mce_sys().strq_stride_num_per_rwqe *
                                    safe_mce_sys().strq_stride_size_bytes)
                     : safe_mce_sys().rx_buf_size);
            m_lro.max_payload_sz =
                std::min(actual_buf_size, XLIO_MLX5_PARAMS_LRO_PAYLOAD_SIZE) / 256U * 256U;
        }
#endif /* DEFINED_DPCP */
    }
    ring_logdbg("ring attributes: m_lro = %d", m_lro.cap);
    ring_logdbg("ring attributes: m_lro:psh_flag = %d", m_lro.psh_flag);
    ring_logdbg("ring attributes: m_lro:time_stamp = %d", m_lro.time_stamp);
    ring_logdbg("ring attributes: m_lro:max_msg_sz_mode = %d", m_lro.max_msg_sz_mode);
    ring_logdbg("ring attributes: m_lro:min_mss_size = %d", m_lro.min_mss_size);
    ring_logdbg("ring attributes: m_lro:timer_supported_periods = [%d:%d:%d:%d]",
                m_lro.timer_supported_periods[0], m_lro.timer_supported_periods[1],
                m_lro.timer_supported_periods[2], m_lro.timer_supported_periods[3]);
    ring_logdbg("ring attributes: m_lro:max_payload_sz = %d", m_lro.max_payload_sz);

#ifdef DEFINED_UTLS
    {
        dpcp::adapter_hca_capabilities caps;
        if (m_p_ib_ctx->get_dpcp_adapter() &&
            (dpcp::DPCP_OK == m_p_ib_ctx->get_dpcp_adapter()->get_hca_capabilities(caps))) {
            m_tls.tls_tx = caps.tls_tx;
            m_tls.tls_rx = caps.tls_rx;
            m_tls.tls_synchronize_dek = caps.synchronize_dek;
        }
        ring_logdbg("ring attributes: m_tls:tls_tx = %d", m_tls.tls_tx);
        ring_logdbg("ring attributes: m_tls:tls_rx = %d", m_tls.tls_rx);
        ring_logdbg("ring attributes: m_tls:tls_synchronize_dek = %d", m_tls.tls_synchronize_dek);
    }
#endif /* DEFINED_UTLS */

    m_flow_tag_enabled = !safe_mce_sys().disable_flow_tag && m_p_ib_ctx->get_flow_tag_capability();
#if defined(DEFINED_NGINX)
    if (safe_mce_sys().actual_nginx_workers_num > 0) {
        m_flow_tag_enabled = false;
    }
#endif // DEFINED_NGINX
    ring_logdbg("ring attributes: m_flow_tag_enabled = %d", m_flow_tag_enabled);

    m_p_rx_comp_event_channel = ibv_create_comp_channel(
        m_p_ib_ctx->get_ibv_context()); // ODED TODO: Adjust the ibv_context to be the exact one in
                                        // case of different devices
    BULLSEYE_EXCLUDE_BLOCK_START
    if (m_p_rx_comp_event_channel == NULL) {
        VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(
            VLOG_ERROR, VLOG_DEBUG,
            "ibv_create_comp_channel for rx failed. p_rx_comp_event_channel = %p (errno=%d %m)",
            m_p_rx_comp_event_channel, errno);
        if (errno == EMFILE) {
            VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(VLOG_ERROR, VLOG_DEBUG,
                                              "did we run out of file descriptors? traffic may not "
                                              "be offloaded, increase ulimit -n");
        }
        throw_xlio_exception("create event channel failed");
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    VALGRIND_MAKE_MEM_DEFINED(m_p_rx_comp_event_channel, sizeof(struct ibv_comp_channel));
    m_p_n_rx_channel_fds = new int[1];
    m_p_n_rx_channel_fds[0] = m_p_rx_comp_event_channel->fd;
    // Add the rx channel fd to the global fd collection
    if (g_p_fd_collection) {
        // Create new cq_channel info in the global fd collection
        g_p_fd_collection->add_cq_channel_fd(m_p_n_rx_channel_fds[0], this);
        g_p_fd_collection->add_cq_channel_fd(m_p_tx_comp_event_channel->fd, this);
    }

    struct qp_mgr_desc desc;
    memset(&desc, 0, sizeof(desc));
    desc.ring = this;
    desc.slave = p_slave;
    desc.rx_comp_event_channel = m_p_rx_comp_event_channel;
    m_p_qp_mgr = create_qp_mgr(&desc);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (m_p_qp_mgr == NULL) {
        ring_logerr("Failed to allocate qp_mgr!");
        throw_xlio_exception("create qp failed");
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    // save cq_mgr pointers
    m_p_cq_mgr_rx = m_p_qp_mgr->get_rx_cq_mgr();
    m_p_cq_mgr_tx = m_p_qp_mgr->get_tx_cq_mgr();

    init_tx_buffers(RING_TX_BUFS_COMPENSATE);

    if (safe_mce_sys().cq_moderation_enable) {
        modify_cq_moderation(safe_mce_sys().cq_moderation_period_usec,
                             safe_mce_sys().cq_moderation_count);
    }

    /* For RoCE LAG device income data is processed by single ring only
     * Consider using ring related slave with lag_tx_port_affinity = 1
     * even if slave is not active
     */
    if (p_slave->active || (p_slave->lag_tx_port_affinity == 1)) {
        start_active_qp_mgr();
    }

    ring_logdbg("new ring_simple() completed");
}

int ring_simple::request_notification(cq_type_t cq_type, uint64_t poll_sn)
{
    int ret = 1;
    if (likely(CQT_RX == cq_type)) {
        RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx,
                                         m_p_cq_mgr_rx->request_notification(poll_sn);
                                         ++m_p_ring_stat->simple.n_rx_interrupt_requests);
    } else {
        RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_tx,
                                         m_p_cq_mgr_tx->request_notification(poll_sn));
    }

    return ret;
}

int ring_simple::poll_and_process_element_rx(uint64_t *p_cq_poll_sn,
                                             void *pv_fd_ready_array /*NULL*/)
{
    int ret = 0;
    RING_TRY_LOCK_RUN_AND_UPDATE_RET(
        m_lock_ring_rx,
        m_p_cq_mgr_rx->poll_and_process_element_rx(p_cq_poll_sn, pv_fd_ready_array));
    return ret;
}

int ring_simple::poll_and_process_element_tx(uint64_t *p_cq_poll_sn)
{
    int ret = 0;
    RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_tx,
                                     m_p_cq_mgr_tx->poll_and_process_element_tx(p_cq_poll_sn));
    return ret;
}

int ring_simple::socketxtreme_poll(struct xlio_socketxtreme_completion_t *xlio_completions,
                                   unsigned int ncompletions, int flags)
{
    int ret = 0;
    int i = 0;

    if (likely(xlio_completions) && ncompletions) {

        if ((flags & SOCKETXTREME_POLL_TX) && list_empty(&m_socketxtreme.ec_list)) {
            uint64_t poll_sn = 0;
            const std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
            m_p_cq_mgr_tx->poll_and_process_element_tx(&poll_sn);
        }

        const std::lock_guard<decltype(m_lock_ring_rx)> lock(m_lock_ring_rx);
        while (!g_b_exit && (i < (int)ncompletions)) {
            /* Check list size to avoid locking */
            if (!list_empty(&m_socketxtreme.ec_list)) {
                ring_ec *ec = get_ec();
                if (ec) {
                    memcpy(xlio_completions, &ec->completion, sizeof(ec->completion));
                    ec->clear();
                    xlio_completions++;
                    i++;
                }
            } else {
                /* Internal thread can raise event on this stage before we
                 * start rx processing. In this case we can return event
                 * in right order. It is done to avoid locking and
                 * may be it is not so critical
                 */
                mem_buf_desc_t *desc = m_p_cq_mgr_rx->poll_and_process_socketxtreme();
                if (likely(desc)) {
                    rx_process_buffer(desc, NULL);
                } else {
                    m_gro_mgr.flush_all(NULL);
                    break;
                }
            }
        }

        ret = i;
    } else {
        ret = -1;
        errno = EINVAL;
    }

    return ret;
}

int ring_simple::wait_for_notification_and_process_element(int cq_channel_fd,
                                                           uint64_t *p_cq_poll_sn,
                                                           void *pv_fd_ready_array /*NULL*/)
{
    int ret = -1;
    if (m_p_cq_mgr_rx != NULL) {
        RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx,
                                         m_p_cq_mgr_rx->wait_for_notification_and_process_element(
                                             p_cq_poll_sn, pv_fd_ready_array);
                                         ++m_p_ring_stat->simple.n_rx_interrupt_received);
    } else {
        ring_logerr("Can't find rx_cq for the rx_comp_event_channel_fd (= %d)", cq_channel_fd);
    }

    return ret;
}

bool ring_simple::reclaim_recv_buffers(descq_t *rx_reuse)
{
    bool ret = false;
    RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx, m_p_cq_mgr_rx->reclaim_recv_buffers(rx_reuse));
    return ret;
}

bool ring_simple::reclaim_recv_buffers(mem_buf_desc_t *rx_reuse_lst)
{
    bool ret = false;
    RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx,
                                     m_p_cq_mgr_rx->reclaim_recv_buffers(rx_reuse_lst));
    return ret;
}

bool ring_simple::reclaim_recv_buffers_no_lock(mem_buf_desc_t *rx_reuse_lst)
{
    return m_p_cq_mgr_rx->reclaim_recv_buffers_no_lock(rx_reuse_lst);
}

int ring_simple::reclaim_recv_single_buffer(mem_buf_desc_t *rx_reuse)
{
    return m_p_cq_mgr_rx->reclaim_recv_single_buffer(rx_reuse);
}

void ring_simple::mem_buf_desc_return_to_owner_rx(mem_buf_desc_t *p_mem_buf_desc,
                                                  void *pv_fd_ready_array /*NULL*/)
{
    ring_logfuncall("");
    RING_LOCK_AND_RUN(
        m_lock_ring_rx,
        m_p_cq_mgr_rx->mem_buf_desc_return_to_owner(p_mem_buf_desc, pv_fd_ready_array));
}

void ring_simple::mem_buf_desc_return_to_owner_tx(mem_buf_desc_t *p_mem_buf_desc)
{
    ring_logfuncall("");
    RING_LOCK_AND_RUN(m_lock_ring_tx, put_tx_buffers(p_mem_buf_desc));
}

void ring_simple::mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t *p_mem_buf_desc)
{
    ring_logfuncall("");
    RING_LOCK_AND_RUN(m_lock_ring_tx, put_tx_single_buffer(p_mem_buf_desc));
}

void ring_simple::mem_buf_desc_return_single_multi_ref(mem_buf_desc_t *p_mem_buf_desc, unsigned ref)
{
    if (unlikely(ref == 0)) {
        return;
    }

    std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);

    p_mem_buf_desc->lwip_pbuf.pbuf.ref -=
        std::min<unsigned>(p_mem_buf_desc->lwip_pbuf.pbuf.ref, ref - 1);
    put_tx_single_buffer(p_mem_buf_desc);
}

// Call under m_lock_ring_tx lock
void ring_simple::mem_buf_desc_return_single_locked(mem_buf_desc_t *buff)
{
    put_tx_buffer_helper(buff);
}

int ring_simple::drain_and_proccess()
{
    int ret = 0;
    RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx, m_p_cq_mgr_rx->drain_and_proccess());
    return ret;
}

mem_buf_desc_t *ring_simple::mem_buf_tx_get(ring_user_id_t id, bool b_block, pbuf_type type,
                                            int n_num_mem_bufs /* default = 1 */)
{
    NOT_IN_USE(id);
    int ret = 0;
    mem_buf_desc_t *buff_list = NULL;
    uint64_t poll_sn = 0;

    ring_logfuncall("n_num_mem_bufs=%d", n_num_mem_bufs);

    m_lock_ring_tx.lock();
    buff_list = get_tx_buffers(type, n_num_mem_bufs);
    while (!buff_list) {

        // Try to poll once in the hope that we get a few freed tx mem_buf_desc
        ret = m_p_cq_mgr_tx->poll_and_process_element_tx(&poll_sn);
        if (ret < 0) {
            ring_logdbg("failed polling on tx cq_mgr (qp_mgr=%p, cq_mgr_tx=%p) (ret=%d %m)",
                        m_p_qp_mgr, m_p_cq_mgr_tx, ret);
            /* coverity[double_unlock] TODO: RM#1049980 */
            m_lock_ring_tx.unlock();
            return NULL;
        } else if (ret > 0) {
            ring_logfunc("polling succeeded on tx cq_mgr (%d wce)", ret);
            buff_list = get_tx_buffers(type, n_num_mem_bufs);
        } else if (b_block) { // (ret == 0)
            // Arm & Block on tx cq_mgr notification channel
            // until we get a few freed tx mem_buf_desc & data buffers

            // Only a single thread should block on next Tx cqe event, hence the dedicated lock!
            /* coverity[double_unlock] coverity[unlock] TODO: RM#1049980 */
            m_lock_ring_tx.unlock();
            m_lock_ring_tx_buf_wait.lock();
            /* coverity[double_lock] TODO: RM#1049980 */
            m_lock_ring_tx.lock();

            // poll once more (in the hope that we get a few freed tx mem_buf_desc)
            buff_list = get_tx_buffers(type, n_num_mem_bufs);
            if (!buff_list) {
                // Arm the CQ event channel for next Tx buffer release (tx cqe)
                ret = m_p_cq_mgr_tx->request_notification(poll_sn);
                if (ret < 0) {
                    // this is most likely due to cq_poll_sn out of sync, need to poll_cq again
                    ring_logdbg("failed arming tx cq_mgr (qp_mgr=%p, cq_mgr_tx=%p) (errno=%d %m)",
                                m_p_qp_mgr, m_p_cq_mgr_tx, errno);
                } else if (ret == 0) {

                    // prepare to block
                    // CQ is armed, block on the CQ's Tx event channel (fd)
                    struct pollfd poll_fd = {/*.fd=*/0, /*.events=*/POLLIN, /*.revents=*/0};
                    poll_fd.fd = get_tx_comp_event_channel()->fd;

                    // Now it is time to release the ring lock (for restart events to be handled
                    // while this thread block on CQ channel)
                    /* coverity[double_unlock] coverity[unlock] TODO: RM#1049980 */
                    m_lock_ring_tx.unlock();

                    ret = orig_os_api.poll(&poll_fd, 1, 100);
                    if (ret == 0) {
                        m_lock_ring_tx_buf_wait.unlock();
                        /* coverity[double_lock] TODO: RM#1049980 */
                        m_lock_ring_tx.lock();
                        buff_list = get_tx_buffers(type, n_num_mem_bufs);
                        continue;
                    } else if (ret < 0) {
                        ring_logdbg("failed blocking on tx cq_mgr (errno=%d %m)", errno);
                        m_lock_ring_tx_buf_wait.unlock();
                        return NULL;
                    }
                    /* coverity[double_lock] TODO: RM#1049980 */
                    m_lock_ring_tx.lock();

                    // Find the correct Tx cq_mgr from the CQ event,
                    // It might not be the active_cq object since we have a single TX CQ comp
                    // channel for all cq_mgr's
                    cq_mgr *p_cq_mgr_tx = get_cq_mgr_from_cq_event(get_tx_comp_event_channel());
                    if (p_cq_mgr_tx) {

                        // Allow additional CQ arming now
                        p_cq_mgr_tx->m_b_notification_armed = false;

                        // Perform a non blocking event read, clear the fd channel
                        ret = p_cq_mgr_tx->poll_and_process_element_tx(&poll_sn);
                        if (ret < 0) {
                            ring_logdbg("failed handling Tx cq_mgr channel (qp_mgr=%p, "
                                        "cq_mgr_tx=%p) (errno=%d %m)",
                                        m_p_qp_mgr, m_p_cq_mgr_tx, errno);
                            /* coverity[double_unlock] TODO: RM#1049980 */
                            m_lock_ring_tx.unlock();
                            m_lock_ring_tx_buf_wait.unlock();
                            return NULL;
                        }
                        ring_logfunc("polling/blocking succeeded on tx cq_mgr (we got %d wce)",
                                     ret);
                    }
                }
                buff_list = get_tx_buffers(type, n_num_mem_bufs);
            }
            /* coverity[double_unlock] TODO: RM#1049980 */
            m_lock_ring_tx.unlock();
            m_lock_ring_tx_buf_wait.unlock();
            /* coverity[double_lock] TODO: RM#1049980 */
            m_lock_ring_tx.lock();
        } else {
            // get out on non blocked socket
            m_lock_ring_tx.unlock();
            return NULL;
        }
    }

    // We got the buffers
    // Increase counter in order to keep track of how many buffers ring is missing when reclaiming
    // them during ring->restart()
    m_missing_buf_ref_count += n_num_mem_bufs;

    /* coverity[double_unlock] TODO: RM#1049980 */
    m_lock_ring_tx.unlock();
    return buff_list;
}

int ring_simple::mem_buf_tx_release(mem_buf_desc_t *p_mem_buf_desc_list, bool b_accounting,
                                    bool trylock /*=false*/)
{
    ring_logfuncall("");

    if (!trylock) {
        m_lock_ring_tx.lock();
    } else if (m_lock_ring_tx.trylock()) {
        return 0;
    }

    int accounting = put_tx_buffers(p_mem_buf_desc_list);
    if (b_accounting) {
        m_missing_buf_ref_count -= accounting;
    }
    m_lock_ring_tx.unlock();
    return accounting;
}

void ring_simple::mem_buf_rx_release(mem_buf_desc_t *p_mem_buf_desc)
{
    p_mem_buf_desc->p_next_desc = NULL;
    reclaim_recv_buffers(p_mem_buf_desc);
}

/* note that this function is inline, so keep it above the functions using it */
inline int ring_simple::send_buffer(xlio_ibv_send_wr *p_send_wqe, xlio_wr_tx_packet_attr attr,
                                    xlio_tis *tis)
{
    int ret = 0;
    unsigned credits = m_p_qp_mgr->credits_calculate(p_send_wqe);

    if (likely(m_p_qp_mgr->credits_get(credits)) ||
        is_available_qp_wr(is_set(attr, XLIO_TX_PACKET_BLOCK), credits)) {
        ret = m_p_qp_mgr->send(p_send_wqe, attr, tis, credits);
    } else {
        ring_logdbg("Silent packet drop, SQ is full!");
        ret = -1;
        reinterpret_cast<mem_buf_desc_t *>(p_send_wqe->wr_id)->p_next_desc = nullptr;
        ++m_p_ring_stat->simple.n_tx_dropped_wqes;
    }
    return ret;
}

bool ring_simple::get_hw_dummy_send_support(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe)
{
    NOT_IN_USE(id);
    NOT_IN_USE(p_send_wqe);

    return m_p_qp_mgr->get_hw_dummy_send_support();
}

void ring_simple::send_ring_buffer(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe,
                                   xlio_wr_tx_packet_attr attr)
{
    NOT_IN_USE(id);

    if (attr & XLIO_TX_SW_L4_CSUM) {
        compute_tx_checksum((mem_buf_desc_t *)(p_send_wqe->wr_id), attr & XLIO_TX_PACKET_L3_CSUM,
                            attr & XLIO_TX_PACKET_L4_CSUM);
        attr = (xlio_wr_tx_packet_attr)(attr & ~(XLIO_TX_PACKET_L4_CSUM));
    }

    std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
    int ret = send_buffer(p_send_wqe, attr, 0);
    send_status_handler(ret, p_send_wqe);
}

int ring_simple::send_lwip_buffer(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe,
                                  xlio_wr_tx_packet_attr attr, xlio_tis *tis)
{
    NOT_IN_USE(id);
    std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
    int ret = send_buffer(p_send_wqe, attr, tis);
    send_status_handler(ret, p_send_wqe);
    return ret;
}

/*
 * called under m_lock_ring_tx lock
 */
bool ring_simple::is_available_qp_wr(bool b_block, unsigned credits)
{
    bool granted;
    int ret;
    uint64_t poll_sn = 0;

    // TODO credits_get() does TX polling. Call current method only for bocking mode?

    do {
        // Try to poll once in the hope that we get space in SQ
        ret = m_p_cq_mgr_tx->poll_and_process_element_tx(&poll_sn);
        if (ret < 0) {
            ring_logdbg("failed polling on tx cq_mgr (qp_mgr=%p, cq_mgr_tx=%p) (ret=%d %m)",
                        m_p_qp_mgr, m_p_cq_mgr_tx, ret);
            /* coverity[missing_unlock] */
            return false;
        }
        granted = m_p_qp_mgr->credits_get(credits);
        if (granted) {
            break;
        }

        if (b_block) {
            // Arm & Block on tx cq_mgr notification channel until we get space in SQ

            // Only a single thread should block on next Tx cqe event, hence the dedicated lock!
            /* coverity[double_unlock] TODO: RM#1049980 */
            m_lock_ring_tx.unlock();
            m_lock_ring_tx_buf_wait.lock();
            /* coverity[double_lock] TODO: RM#1049980 */
            m_lock_ring_tx.lock();

            // TODO Resolve race window between previous polling and request_notification
            ret = m_p_cq_mgr_tx->request_notification(poll_sn);
            if (ret < 0) {
                // this is most likely due to cq_poll_sn out of sync, need to poll_cq again
                ring_logdbg("failed arming tx cq_mgr (qp_mgr=%p, cq_mgr_tx=%p) (errno=%d %m)",
                            m_p_qp_mgr, m_p_cq_mgr_tx, errno);
            } else if (ret == 0) {
                // prepare to block
                // CQ is armed, block on the CQ's Tx event channel (fd)
                struct pollfd poll_fd = {/*.fd=*/0, /*.events=*/POLLIN, /*.revents=*/0};
                poll_fd.fd = get_tx_comp_event_channel()->fd;

                // Now it is time to release the ring lock (for restart events to be handled
                // while this thread block on CQ channel)
                /* coverity[double_unlock] TODO: RM#1049980 */
                m_lock_ring_tx.unlock();

                ret = orig_os_api.poll(&poll_fd, 1, -1);
                if (ret <= 0) {
                    ring_logdbg("failed blocking on tx cq_mgr (errno=%d %m)", errno);
                    m_lock_ring_tx_buf_wait.unlock();
                    /* coverity[double_lock] TODO: RM#1049980 */
                    m_lock_ring_tx.lock();
                    /* coverity[missing_unlock] */
                    return false;
                }
                /* coverity[double_lock] TODO: RM#1049980 */
                m_lock_ring_tx.lock();

                // Find the correct Tx cq_mgr from the CQ event,
                // It might not be the active_cq object since we have a single TX CQ comp
                // channel for all cq_mgr's
                cq_mgr *p_cq_mgr_tx = get_cq_mgr_from_cq_event(get_tx_comp_event_channel());
                if (p_cq_mgr_tx) {

                    // Allow additional CQ arming now
                    p_cq_mgr_tx->m_b_notification_armed = false;

                    // Perform a non blocking event read, clear the fd channel
                    ret = p_cq_mgr_tx->poll_and_process_element_tx(&poll_sn);
                    if (ret < 0) {
                        ring_logdbg("failed handling Tx cq_mgr channel (qp_mgr=%p, "
                                    "cq_mgr_tx=%p) (errno=%d %m)",
                                    m_p_qp_mgr, m_p_cq_mgr_tx, errno);
                        /* coverity[double_unlock] TODO: RM#1049980 */
                        m_lock_ring_tx.unlock();
                        m_lock_ring_tx_buf_wait.unlock();
                        /* coverity[double_lock] TODO: RM#1049980 */
                        m_lock_ring_tx.lock();
                        return false;
                    }
                    ring_logfunc("polling/blocking succeeded on tx cq_mgr (we got %d wce)", ret);
                }
            }

            /* coverity[double_unlock] TODO: RM#1049980 */
            m_lock_ring_tx.unlock();
            m_lock_ring_tx_buf_wait.unlock();
            /* coverity[double_lock] TODO: RM#1049980 */
            m_lock_ring_tx.lock();
        }
    } while (b_block);

    /* coverity[missing_unlock] */
    return granted;
}

void ring_simple::init_tx_buffers(uint32_t count)
{
    request_more_tx_buffers(PBUF_RAM, count, m_tx_lkey);
    m_tx_num_bufs = m_tx_pool.size();
    request_more_tx_buffers(PBUF_ZEROCOPY, count, 0);
    m_zc_num_bufs = m_zc_pool.size();
}

void ring_simple::inc_cq_moderation_stats(size_t sz_data)
{
    m_cq_moderation_info.bytes += sz_data;
    ++m_cq_moderation_info.packets;
}

// call under m_lock_ring_tx lock
mem_buf_desc_t *ring_simple::get_tx_buffers(pbuf_type type, uint32_t n_num_mem_bufs)
{
    mem_buf_desc_t *head;
    descq_t &pool = type == PBUF_ZEROCOPY ? m_zc_pool : m_tx_pool;

    if (unlikely(pool.size() < n_num_mem_bufs)) {
        int count = std::max(RING_TX_BUFS_COMPENSATE, n_num_mem_bufs);
        if (request_more_tx_buffers(type, count, m_tx_lkey)) {
            /*
             * TODO Unify request_more_tx_buffers so ring_slave
             * keeps number of buffers instead of reinventing it in
             * ring_simple and ring_tap.
             */
            if (type == PBUF_ZEROCOPY) {
                m_zc_num_bufs += count;
            } else {
                m_tx_num_bufs += count;
            }
        }

        if (unlikely(pool.size() < n_num_mem_bufs)) {
            return NULL;
        }
    }

    head = pool.get_and_pop_back();
    head->lwip_pbuf.pbuf.ref = 1;
    assert(head->lwip_pbuf.pbuf.type == type);
    head->lwip_pbuf.pbuf.type = type;
    n_num_mem_bufs--;

    mem_buf_desc_t *next = head;
    while (n_num_mem_bufs) {
        next->p_next_desc = pool.get_and_pop_back();
        next = next->p_next_desc;
        next->lwip_pbuf.pbuf.ref = 1;
        assert(head->lwip_pbuf.pbuf.type == type);
        next->lwip_pbuf.pbuf.type = type;
        n_num_mem_bufs--;
    }
    next->p_next_desc = NULL;

    return head;
}

void ring_simple::return_to_global_pool()
{
    if (unlikely(m_tx_pool.size() > (m_tx_num_bufs / 2) &&
                 m_tx_num_bufs >= RING_TX_BUFS_COMPENSATE * 2)) {
        int return_bufs = m_tx_pool.size() / 2;
        m_tx_num_bufs -= return_bufs;
        g_buffer_pool_tx->put_buffers_thread_safe(&m_tx_pool, return_bufs);
    }
    if (unlikely(m_zc_pool.size() > (m_zc_num_bufs / 2) &&
                 m_zc_num_bufs >= RING_TX_BUFS_COMPENSATE * 2)) {
        int return_bufs = m_zc_pool.size() / 2;
        m_zc_num_bufs -= return_bufs;
        g_buffer_pool_zc->put_buffers_thread_safe(&m_zc_pool, return_bufs);
    }
}

void ring_simple::return_tx_pool_to_global_pool()
{
    return_to_global_pool();
}

int ring_simple::put_tx_buffer_helper(mem_buf_desc_t *buff)
{
    if (buff->tx.dev_mem_length) {
        m_p_qp_mgr->dm_release_data(buff);
    }

    // Potential race, ref is protected here by ring_tx lock, and in dst_entry_tcp &
    // sockinfo_tcp by tcp lock
    if (likely(buff->lwip_pbuf.pbuf.ref)) {
        buff->lwip_pbuf.pbuf.ref--;
    } else {
        ring_logerr("ref count of %p is already zero, double free??", buff);
    }

    if (buff->lwip_pbuf.pbuf.ref == 0) {
        descq_t &pool = buff->lwip_pbuf.pbuf.type == PBUF_ZEROCOPY ? m_zc_pool : m_tx_pool;
        buff->p_next_desc = nullptr;
        free_lwip_pbuf(&buff->lwip_pbuf);
        pool.push_back(buff);
        // Return number of freed buffers
        return 1;
    }
    return 0;
}

// call under m_lock_ring_tx lock
int ring_simple::put_tx_buffers(mem_buf_desc_t *buff_list)
{
    int count = 0;
    int freed = 0;

    while (buff_list) {
        mem_buf_desc_t *next = buff_list->p_next_desc;
        freed += put_tx_buffer_helper(buff_list);
        count++;
        buff_list = next;
    }

    return_to_global_pool();

    ring_logfunc("count: %d freed: %d\n", count, freed);
    NOT_IN_USE(freed);

    return count;
}

// call under m_lock_ring_tx lock
int ring_simple::put_tx_single_buffer(mem_buf_desc_t *buff)
{
    int count = 0;

    if (likely(buff)) {
        count = put_tx_buffer_helper(buff);
    }
    return_to_global_pool();

    return count;
}

void ring_simple::modify_cq_moderation(uint32_t period, uint32_t count)
{
    uint32_t period_diff = period > m_cq_moderation_info.period
        ? period - m_cq_moderation_info.period
        : m_cq_moderation_info.period - period;
    uint32_t count_diff = count > m_cq_moderation_info.count ? count - m_cq_moderation_info.count
                                                             : m_cq_moderation_info.count - count;

    if (period_diff < (m_cq_moderation_info.period / 20) &&
        (count_diff < m_cq_moderation_info.count / 20)) {
        return;
    }

    m_cq_moderation_info.period = period;
    m_cq_moderation_info.count = count;

    m_p_ring_stat->simple.n_rx_cq_moderation_period = period;
    m_p_ring_stat->simple.n_rx_cq_moderation_count = count;

    // todo all cqs or just active? what about HA?
    priv_ibv_modify_cq_moderation(m_p_cq_mgr_rx->get_ibv_cq_hndl(), period, count);
}

void ring_simple::adapt_cq_moderation()
{
    if (m_lock_ring_rx.trylock()) {
        ++m_cq_moderation_info.missed_rounds;
        return; // todo try again sooner?
    }

    uint32_t missed_rounds = m_cq_moderation_info.missed_rounds;

    // todo collect bytes and packets from all rings ??
    int64_t interval_bytes = m_cq_moderation_info.bytes - m_cq_moderation_info.prev_bytes;
    int64_t interval_packets = m_cq_moderation_info.packets - m_cq_moderation_info.prev_packets;

    m_cq_moderation_info.prev_bytes = m_cq_moderation_info.bytes;
    m_cq_moderation_info.prev_packets = m_cq_moderation_info.packets;
    m_cq_moderation_info.missed_rounds = 0;

    BULLSEYE_EXCLUDE_BLOCK_START
    if (interval_bytes < 0 || interval_packets < 0) {
        // rare wrap-around of 64 bit, just ignore
        m_lock_ring_rx.unlock();
        return;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    if (interval_packets == 0) {
        // todo if no traffic, set moderation to default?
        modify_cq_moderation(safe_mce_sys().cq_moderation_period_usec,
                             safe_mce_sys().cq_moderation_count);
        m_lock_ring_rx.unlock();
        return;
    }

    uint32_t avg_packet_size = interval_bytes / interval_packets;
    uint32_t avg_packet_rate =
        (interval_packets * 1000) / (safe_mce_sys().cq_aim_interval_msec * (1 + missed_rounds));

    uint32_t ir_rate = safe_mce_sys().cq_aim_interrupts_rate_per_sec;

    uint32_t count = std::min(avg_packet_rate / ir_rate, safe_mce_sys().cq_aim_max_count);
    uint32_t period = std::min<uint32_t>(
        safe_mce_sys().cq_aim_max_period_usec,
        ((1000000UL / ir_rate) - (1000000UL / std::max(avg_packet_rate, ir_rate))));

    if (avg_packet_size < 1024 && avg_packet_rate < 450000) {
        modify_cq_moderation(0, 0); // latency mode
        // todo latency for big messages is not good
        // the rate is affected by the moderation and the moderation by the rate..
        // so each cycle change from 0 to max, and max to 0, ..
    } else {
        modify_cq_moderation(period, count); // throughput mode
    }

    m_lock_ring_rx.unlock();
}

void ring_simple::start_active_qp_mgr()
{
    m_lock_ring_rx.lock();
    m_lock_ring_tx.lock();
    if (!m_up) {
        /* TODO: consider avoid using sleep */
        /* coverity[sleep] */
        m_p_qp_mgr->up();
        m_up = true;
    }
    m_lock_ring_tx.unlock();
    m_lock_ring_rx.unlock();
}

void ring_simple::stop_active_qp_mgr()
{
    m_lock_ring_rx.lock();
    m_lock_ring_tx.lock();
    if (m_up) {
        m_up = false;
        /* TODO: consider avoid using sleep */
        /* coverity[sleep] */
        m_p_qp_mgr->down();
    }
    m_lock_ring_tx.unlock();
    m_lock_ring_rx.unlock();
}

bool ring_simple::is_up()
{
    return m_up;
}

int ring_simple::modify_ratelimit(struct xlio_rate_limit_t &rate_limit)
{
    if (!m_p_ib_ctx->is_packet_pacing_supported(rate_limit.rate)) {
        ring_logwarn("Packet pacing is not supported for this device");
        return -1;
    }

    if ((rate_limit.max_burst_sz || rate_limit.typical_pkt_sz) &&
        !m_p_ib_ctx->get_burst_capability()) {
        ring_logwarn("Burst is not supported for this device");
        return -1;
    }

    uint32_t rl_changes = m_p_qp_mgr->is_ratelimit_change(rate_limit);

    if (m_up && rl_changes) {
        return m_p_qp_mgr->modify_qp_ratelimit(rate_limit, rl_changes);
    }

    return 0;
}

uint32_t ring_simple::get_tx_user_lkey(void *addr, size_t length, void *p_mapping /*=NULL*/)
{
    uint32_t lkey;

    /*
     * Current implementation supports 2 modes:
     * 1. Per ring registration cache where addr is the key
     * 2. Proxy query to an external mapping object
     *
     * The 1st mode is used for send zerocopy and the 2nd made is used for
     * sendfile offload. These 2 modes are differentiated by p_mapping
     * value. It is NULL in the 1st case.
     *
     * TODO In the 1st mode we don't support memory deregistration.
     */
    if (p_mapping == NULL) {
        auto iter = m_user_lkey_map.find(addr);
        if (iter != m_user_lkey_map.end()) {
            lkey = iter->second;
        } else {
            lkey = m_p_ib_ctx->user_mem_reg(addr, length, XLIO_IBV_ACCESS_LOCAL_WRITE);
            if (lkey == (uint32_t)(-1)) {
                ring_logerr("Can't register user memory addr %p len %lx", addr, length);
            } else {
                m_user_lkey_map[addr] = lkey;
            }
        }
    } else {
        mapping_t *mapping = (mapping_t *)p_mapping;
        lkey = mapping->get_lkey(NULL, m_p_ib_ctx, addr, length);
    }

    return lkey;
}

uint32_t ring_simple::get_max_inline_data()
{
    return m_p_qp_mgr->get_max_inline_data();
}

uint32_t ring_simple::get_max_send_sge(void)
{
    return m_p_qp_mgr->get_max_send_sge();
}

uint32_t ring_simple::get_max_payload_sz(void)
{
    return m_tso.max_payload_sz;
}

uint16_t ring_simple::get_max_header_sz(void)
{
    return m_tso.max_header_sz;
}

bool ring_simple::is_tso(void)
{
    return (m_tso.max_payload_sz && m_tso.max_header_sz);
}
