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

#include "cq_mgr_rx.h"
#include "cq_mgr_rx_inl.h"
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netinet/ip.h>

#include "utils/bullseye.h"
#include <util/vtypes.h>
#include <util/valgrind.h>
#include "util/instrumentation.h"
#include <sock/sock-redirect.h>
#include <sock/sock-app.h>
#include "ib/base/verbs_extra.h"

#include "buffer_pool.h"
#include "hw_queue_rx.h"
#include "ring_simple.h"

#define MODULE_NAME "cq_mgr_rx"

#define cq_logpanic   __log_info_panic
#define cq_logerr     __log_info_err
#define cq_logwarn    __log_info_warn
#define cq_loginfo    __log_info_info
#define cq_logdbg     __log_info_dbg
#define cq_logfunc    __log_info_func
#define cq_logfuncall __log_info_funcall

#define cq_logdbg_no_funcname(log_fmt, log_args...)                                                \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_DEBUG)                                                         \
            vlog_printf(VLOG_DEBUG, MODULE_NAME "[%p]:%d: " log_fmt "\n", __INFO__, __LINE__,      \
                        ##log_args);                                                               \
    } while (0)

atomic_t cq_mgr_rx::m_n_cq_id_counter_rx = ATOMIC_INIT(1);

uint64_t cq_mgr_rx::m_n_global_sn_rx = 0;

cq_mgr_rx::cq_mgr_rx(ring_simple *p_ring, ib_ctx_handler *p_ib_ctx_handler, int cq_size,
                     struct ibv_comp_channel *p_comp_event_channel)
    : m_p_ring(p_ring)
    , m_n_sysvar_cq_poll_batch_max(safe_mce_sys().cq_poll_batch_max)
    , m_n_sysvar_progress_engine_wce_max(safe_mce_sys().progress_engine_wce_max)
    , m_p_cq_stat(&m_cq_stat_static) // use local copy of stats by default
    , m_n_sysvar_rx_prefetch_bytes_before_poll(safe_mce_sys().rx_prefetch_bytes_before_poll)
    , m_n_sysvar_rx_prefetch_bytes(safe_mce_sys().rx_prefetch_bytes)
    , m_p_ib_ctx_handler(p_ib_ctx_handler)
    , m_n_sysvar_rx_num_wr_to_post_recv(safe_mce_sys().rx_num_wr_to_post_recv)
    , m_comp_event_channel(p_comp_event_channel)
    , m_n_sysvar_qp_compensation_level(safe_mce_sys().qp_compensation_level)
    , m_rx_lkey(g_buffer_pool_rx_rwqe->find_lkey_by_ib_ctx_thread_safe(m_p_ib_ctx_handler))
    , m_p_doca_mmap(g_buffer_pool_rx_rwqe->get_doca_mmap())
    , m_b_sysvar_cq_keep_qp_full(safe_mce_sys().cq_keep_qp_full)
{
    BULLSEYE_EXCLUDE_BLOCK_START
    if (m_rx_lkey == LKEY_ERROR) {
        __log_info_panic("invalid lkey found %u", m_rx_lkey);
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    memset(&m_cq_stat_static, 0, sizeof(m_cq_stat_static));

    m_rx_queue.set_id("cq_mgr_rx (%p) : m_rx_queue", this);
    m_rx_pool.set_id("cq_mgr_rx (%p) : m_rx_pool", this);
    m_cq_id_rx = atomic_fetch_and_inc(&m_n_cq_id_counter_rx); // cq id is nonzero
    configure(cq_size);

    memset(&m_mlx5_cq, 0, sizeof(m_mlx5_cq));
}

void cq_mgr_rx::configure(int cq_size)
{
    xlio_ibv_cq_init_attr attr;
    memset(&attr, 0, sizeof(attr));

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
    m_p_ibv_cq = xlio_ibv_create_cq(context, cq_size - 1, (void *)this, m_comp_event_channel,
                                    comp_vector, &attr);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!m_p_ibv_cq) {
        cq_logerr("Failed to create CQ, this: %p, ctx: %p size: %d compch: %p", this, context,
                  cq_size - 1, m_comp_event_channel);
        throw_xlio_exception("ibv_create_cq failed");
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    VALGRIND_MAKE_MEM_DEFINED(m_p_ibv_cq, sizeof(ibv_cq));

    xlio_stats_instance_create_cq_block(m_p_cq_stat);

    m_b_is_rx_hw_csum_on = xlio_is_rx_hw_csum_supported(m_p_ib_ctx_handler->get_ibv_device_attr());

    cq_logdbg("RX CSUM support = %d", m_b_is_rx_hw_csum_on);

    cq_logdbg("Created CQ as Rx with fd[%d] and of size %d elements (ibv_cq_hndl=%p)",
              get_channel_fd(), cq_size, m_p_ibv_cq);

    doca_error_t rc = doca_pe_create(&m_doca_pe);
    if (DOCA_IS_ERROR(rc)) {
        PRINT_DOCA_ERR(cq_logerr, rc, "doca_pe_create");
        throw_xlio_exception("doca_pe_create failed");
    }

    cq_logdbg("Created DOCA PE %p", m_doca_pe);
}

cq_mgr_rx::~cq_mgr_rx()
{
    cq_logdbg("Destroying Rx CQ");

    m_b_was_drained = true;
    if (m_rx_queue.size() + m_rx_pool.size()) {
        cq_logdbg("Returning %lu buffers to global Rx pool (ready queue %lu, free pool %lu))",
                  m_rx_queue.size() + m_rx_pool.size(), m_rx_queue.size(), m_rx_pool.size());

        g_buffer_pool_rx_rwqe->put_buffers_thread_safe(&m_rx_queue, m_rx_queue.size());
        m_p_cq_stat->n_rx_sw_queue_len = m_rx_queue.size();

        g_buffer_pool_rx_rwqe->put_buffers_thread_safe(&m_rx_pool, m_rx_pool.size());
        m_p_cq_stat->n_buffer_pool_len = m_rx_pool.size();
    }

    cq_logfunc("destroying ibv_cq");
    IF_VERBS_FAILURE_EX(ibv_destroy_cq(m_p_ibv_cq), EIO)
    {
        cq_logdbg("destroy cq failed (errno=%d %m)", errno);
    }
    ENDIF_VERBS_FAILURE;
    VALGRIND_MAKE_MEM_UNDEFINED(m_p_ibv_cq, sizeof(ibv_cq));

    statistics_print();
    xlio_stats_instance_remove_cq_block(m_p_cq_stat);

    cq_logdbg("Destroying Rx CQ done");

    if (m_doca_pe) {
        doca_error_t rc = doca_pe_destroy(m_doca_pe);
        if (DOCA_IS_ERROR(rc)) {
            PRINT_DOCA_ERR(cq_logerr, rc, "doca_pe_destroy PE:%p", m_doca_pe);
        }
    }
}

void cq_mgr_rx::statistics_print()
{
    if (m_p_cq_stat->n_rx_pkt_drop || m_p_cq_stat->n_rx_sw_queue_len ||
        m_p_cq_stat->n_rx_drained_at_once_max || m_p_cq_stat->n_buffer_pool_len) {
        cq_logdbg_no_funcname("Packets dropped: %12llu",
                              (unsigned long long int)m_p_cq_stat->n_rx_pkt_drop);
        cq_logdbg_no_funcname("Drained max: %17u", m_p_cq_stat->n_rx_drained_at_once_max);
        cq_logdbg_no_funcname("CQE errors: %18llu",
                              (unsigned long long int)m_p_cq_stat->n_rx_cqe_error);
    }
}

void cq_mgr_rx::add_hqrx(hw_queue_rx *hqrx_ptr)
{
    m_hqrx_ptr = hqrx_ptr;
    m_hqrx_ptr->m_rq_wqe_counter = 0; // In case of bonded hqrx, wqe_counter must be reset to zero
    m_rx_hot_buffer = nullptr;

    if (0 != xlio_ib_mlx5_get_cq(m_p_ibv_cq, &m_mlx5_cq)) {
        cq_logpanic("xlio_ib_mlx5_get_cq failed (errno=%d %m)", errno);
    }

    VALGRIND_MAKE_MEM_DEFINED(&m_mlx5_cq, sizeof(m_mlx5_cq));
    cq_logfunc("hqrx_ptr=%p m_mlx5_cq.dbrec=%p m_mlx5_cq.cq_buf=%p", hqrx_ptr, m_mlx5_cq.dbrec,
               m_mlx5_cq.cq_buf);

    descq_t temp_desc_list;
    temp_desc_list.set_id("cq_mgr_rx (%p) : temp_desc_list", this);

    m_p_cq_stat->n_rx_drained_at_once_max = 0;

    /* return_extra_buffers(); */ // todo??

    // Initial fill of receiver work requests
    uint32_t hqrx_wr_num = hqrx_ptr->get_rx_max_wr_num();
    cq_logdbg("Trying to push %d WRE to allocated hqrx (%p)", hqrx_wr_num, hqrx_ptr);
    while (hqrx_wr_num) {
        uint32_t n_num_mem_bufs = m_n_sysvar_rx_num_wr_to_post_recv;
        if (n_num_mem_bufs > hqrx_wr_num) {
            n_num_mem_bufs = hqrx_wr_num;
        }
        bool res = g_buffer_pool_rx_rwqe->get_buffers_thread_safe(temp_desc_list, m_p_ring,
                                                                  n_num_mem_bufs, m_rx_lkey);
        if (!res) {
            VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(
                VLOG_WARNING, VLOG_DEBUG,
                "WARNING Out of mem_buf_desc from Rx buffer pool for hqrx initialization "
                "(hqrx_ptr=%p),\n"
                "\tThis might happen due to wrong setting of XLIO_RX_BUFS and XLIO_RX_WRE. Please "
                "refer to README.txt for more info",
                hqrx_ptr);
            break;
        }

        hqrx_ptr->post_recv_buffers(&temp_desc_list, temp_desc_list.size());
        if (!temp_desc_list.empty()) {
            cq_logdbg("hqrx_ptr post recv is already full (push=%d, planned=%d)",
                      hqrx_ptr->get_rx_max_wr_num() - hqrx_wr_num, hqrx_ptr->get_rx_max_wr_num());
            g_buffer_pool_rx_rwqe->put_buffers_thread_safe(&temp_desc_list, temp_desc_list.size());
            break;
        }
        hqrx_wr_num -= n_num_mem_bufs;
    }

    cq_logdbg("Successfully post_recv hqrx with %d new Rx buffers (planned=%d)",
              hqrx_ptr->get_rx_max_wr_num() - hqrx_wr_num, hqrx_ptr->get_rx_max_wr_num());

    m_debt = 0;

    /*
    g_buffer_pool_rx_rwqe->get_buffers_thread_safe(temp_desc_list, m_p_ring, 32, m_rx_lkey);
    doca_error_t rc = doca_buf_inventory_create(32U, &temp_doca_inventory);
    if (DOCA_IS_ERROR(rc)) {
        PRINT_DOCA_ERR(cq_logerr, rc, "doca_buf_inventory_create");
    }

    rc = doca_buf_inventory_start(temp_doca_inventory);
    if (DOCA_IS_ERROR(rc)) {
        PRINT_DOCA_ERR(cq_logerr, rc, "doca_buf_inventory_start");
    }

    for (int i = 0; i < 32; ++i) {
        mem_buf_desc_t *mem_buf = temp_desc_list.get_and_pop_front();
        rc = doca_buf_inventory_buf_get_by_addr(temp_doca_inventory, m_p_doca_mmap,
                                                mem_buf->p_buffer, mem_buf->sz_buffer,
                                                temp_doca_bufs + i);
        if (DOCA_IS_ERROR(rc)) {
            PRINT_DOCA_ERR(cq_logerr, rc, "doca_buf_inventory_buf_get_by_data");
        }

        rc = doca_eth_rxq_task_recv_allocate_init(m_hqrx_ptr->m_doca_rxq.get(), temp_doca_bufs[i],
                                                  {.ptr = nullptr}, temp_doca_tasks + i);
        if (DOCA_IS_ERROR(rc)) {
            PRINT_DOCA_ERR(cq_logerr, rc, "doca_eth_rxq_task_recv_allocate_init");
        }

        rc = doca_task_submit(doca_eth_rxq_task_recv_as_doca_task(temp_doca_tasks[i]));
        if (DOCA_IS_ERROR(rc)) {
            PRINT_DOCA_ERR(cq_logerr, rc, "doca_eth_rxq_task_recv_as_doca_task");
        }
    }*/
}

void cq_mgr_rx::del_hqrx(hw_queue_rx *hqrx_ptr)
{
    BULLSEYE_EXCLUDE_BLOCK_START
    if (m_hqrx_ptr != hqrx_ptr) {
        cq_logdbg("wrong hqrx_ptr=%p != m_hqrx_ptr=%p", hqrx_ptr, m_hqrx_ptr);
        return;
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    cq_logdbg("m_hqrx_ptr=%p", m_hqrx_ptr);
    return_extra_buffers();

    clean_cq();
    m_hqrx_ptr = nullptr;
    m_debt = 0;
}

void cq_mgr_rx::lro_update_hdr(struct xlio_mlx5_cqe *cqe, mem_buf_desc_t *p_rx_wc_buf_desc)
{
    struct ethhdr *p_eth_h = (struct ethhdr *)(p_rx_wc_buf_desc->p_buffer);
    struct tcphdr *p_tcp_h;
    size_t transport_header_len = ETH_HDR_LEN;

    if (p_eth_h->h_proto == htons(ETH_P_8021Q)) {
        transport_header_len = ETH_VLAN_HDR_LEN;
    }

    if (0x02 == ((cqe->l4_hdr_type_etc >> 2) & 0x3)) {
        // CQE indicates IPv4 in the l3_hdr_type field
        struct iphdr *p_ip_h = (struct iphdr *)(p_rx_wc_buf_desc->p_buffer + transport_header_len);

        assert(p_ip_h->version == IPV4_VERSION);
        assert(p_ip_h->protocol == IPPROTO_TCP);

        p_ip_h->ttl = cqe->lro_min_ttl;
        p_ip_h->tot_len = htons(ntohl(cqe->byte_cnt) - transport_header_len);
        p_ip_h->check = 0; // Ignore.

        p_tcp_h = (struct tcphdr *)((uint8_t *)p_ip_h + (int)(p_ip_h->ihl) * 4);
    } else {
        // Assume LRO can happen for either IPv4 or IPv6 L3 protocol. Skip checking l3_hdr_type.
        struct ip6_hdr *p_ip6_h =
            (struct ip6_hdr *)(p_rx_wc_buf_desc->p_buffer + transport_header_len);

        assert(0x01 == ((cqe->l4_hdr_type_etc >> 2) & 0x3)); // IPv6 L3 header.
        assert(p_ip6_h->ip6_nxt == IPPROTO_TCP);
        assert(ntohl(cqe->byte_cnt) >= transport_header_len + IPV6_HLEN);

        p_ip6_h->ip6_hlim = cqe->lro_min_ttl;
        // Payload length doesn't include main header.
        p_ip6_h->ip6_plen = htons(ntohl(cqe->byte_cnt) - transport_header_len - IPV6_HLEN);

        // LRO doesn't create a session for packets with extension headers, so IPv6 header is 40b.
        p_tcp_h = (struct tcphdr *)((uint8_t *)p_ip6_h + IPV6_HLEN);
    }

    p_tcp_h->psh = !!(cqe->lro_tcppsh_abort_dupack & MLX5_CQE_LRO_TCP_PUSH_MASK);

    /* TCP packet <ACK> flag is set, and packet carries no data or
     * TCP packet <ACK> flag is set, and packet carries data
     */
    if ((0x03 == ((cqe->l4_hdr_type_etc >> 4) & 0x7)) ||
        (0x04 == ((cqe->l4_hdr_type_etc >> 4) & 0x7))) {
        p_tcp_h->ack = 1;
        p_tcp_h->ack_seq = cqe->lro_ack_seq_num;
        p_tcp_h->window = cqe->lro_tcp_win;
        p_tcp_h->check = 0; // Ignore.
    }
}

bool cq_mgr_rx::request_more_buffers()
{
    cq_logfuncall("Allocating additional %d buffers for internal use",
                  m_n_sysvar_qp_compensation_level);

    // Assume locked!
    // Add an additional free buffer descs to RX cq mgr
    bool res = g_buffer_pool_rx_rwqe->get_buffers_thread_safe(
        m_rx_pool, m_p_ring, m_n_sysvar_qp_compensation_level, m_rx_lkey);
    if (!res) {
        cq_logfunc("Out of mem_buf_desc from RX free pool for internal object pool");
        return false;
    };

    m_p_cq_stat->n_buffer_pool_len = m_rx_pool.size();
    return true;
}

void cq_mgr_rx::return_extra_buffers()
{
    if (m_rx_pool.size() < m_n_sysvar_qp_compensation_level * 2) {
        return;
    }
    int buff_to_rel = m_rx_pool.size() - m_n_sysvar_qp_compensation_level;

    cq_logfunc("releasing %d buffers to global rx pool", buff_to_rel);
    g_buffer_pool_rx_rwqe->put_buffers_thread_safe(&m_rx_pool, buff_to_rel);
    m_p_cq_stat->n_buffer_pool_len = m_rx_pool.size();
}

mem_buf_desc_t *cq_mgr_rx::cqe_process_rx(mem_buf_desc_t *p_mem_buf_desc, enum buff_status_e status)
{
    /* Assume locked!!! */
    cq_logfuncall("");

    if (unlikely(status != BS_OK)) {
        m_p_next_rx_desc_poll = nullptr;
        reclaim_recv_buffer_helper(p_mem_buf_desc);
        return nullptr;
    }

    if (m_n_sysvar_rx_prefetch_bytes_before_poll) {
        m_p_next_rx_desc_poll = p_mem_buf_desc->p_prev_desc;
        p_mem_buf_desc->p_prev_desc = nullptr;
    }

    VALGRIND_MAKE_MEM_DEFINED(p_mem_buf_desc->p_buffer, p_mem_buf_desc->sz_data);

    prefetch_range((uint8_t *)p_mem_buf_desc->p_buffer + m_sz_transport_header,
                   std::min(p_mem_buf_desc->sz_data - m_sz_transport_header,
                            (size_t)m_n_sysvar_rx_prefetch_bytes));

    return p_mem_buf_desc;
}

bool cq_mgr_rx::compensate_qp_poll_success(mem_buf_desc_t *buff_cur)
{
    // Assume locked!!!
    // Compensate QP for all completions that we found
    if (m_rx_pool.size() || request_more_buffers()) {
        size_t buffers = std::min<size_t>(m_debt, m_rx_pool.size());
        m_hqrx_ptr->post_recv_buffers(&m_rx_pool, buffers);
        m_debt -= buffers;
        m_p_cq_stat->n_buffer_pool_len = m_rx_pool.size();
    } else if (m_b_sysvar_cq_keep_qp_full || m_debt >= (int)m_hqrx_ptr->m_rx_num_wr) {
        m_p_cq_stat->n_rx_pkt_drop++;
        m_hqrx_ptr->post_recv_buffer(buff_cur);
        --m_debt;
        return true;
    }

    return false;
}

void cq_mgr_rx::compensate_qp_poll_failed()
{
    // Assume locked!!!
    // Compensate QP for all completions debt
    if (m_debt) {
        if (likely(m_rx_pool.size() || request_more_buffers())) {
            size_t buffers = std::min<size_t>(m_debt, m_rx_pool.size());
            m_hqrx_ptr->post_recv_buffers(&m_rx_pool, buffers);
            m_debt -= buffers;
            m_p_cq_stat->n_buffer_pool_len = m_rx_pool.size();
        }
    }
}

void cq_mgr_rx::reclaim_recv_buffer_helper(mem_buf_desc_t *buff)
{
    if (buff->dec_ref_count() <= 1 && (buff->lwip_pbuf.ref-- <= 1)) {
        if (likely(buff->p_desc_owner == m_p_ring)) {
            mem_buf_desc_t *temp = nullptr;
            while (buff) {
                VLIST_DEBUG_CQ_MGR_PRINT_ERROR_IS_MEMBER;
                temp = buff;
                assert(temp->lwip_pbuf.type != PBUF_ZEROCOPY);
                buff = temp->p_next_desc;
                temp->clear_transport_data();
                temp->p_next_desc = nullptr;
                temp->p_prev_desc = nullptr;
                temp->reset_ref_count();
                free_lwip_pbuf(&temp->lwip_pbuf);
                m_rx_pool.push_back(temp);
            }
            m_p_cq_stat->n_buffer_pool_len = m_rx_pool.size();
        } else {
            cq_logfunc("Buffer returned to wrong CQ");
            g_buffer_pool_rx_rwqe->put_buffers_thread_safe(buff);
        }
    }
}

// This method is called when ring release returns unposted buffers.
void cq_mgr_rx::mem_buf_desc_return_to_owner(mem_buf_desc_t *p_mem_buf_desc,
                                             void *pv_fd_ready_array /*=NULL*/)
{
    cq_logfuncall("");
    NOT_IN_USE(pv_fd_ready_array);
    cq_mgr_rx::reclaim_recv_buffer_helper(p_mem_buf_desc);
}

bool cq_mgr_rx::reclaim_recv_buffers(mem_buf_desc_t *rx_reuse_lst)
{
    reclaim_recv_buffer_helper(rx_reuse_lst);
    return_extra_buffers();

    return true;
}

bool cq_mgr_rx::reclaim_recv_buffers_no_lock(mem_buf_desc_t *rx_reuse_lst)
{
    if (likely(rx_reuse_lst)) {
        reclaim_recv_buffer_helper(rx_reuse_lst);
        return true;
    }
    return false;
}

bool cq_mgr_rx::reclaim_recv_buffers(descq_t *rx_reuse)
{
    cq_logfuncall("");
    // Called from outside cq_mgr_rx context which is not locked!!
    while (!rx_reuse->empty()) {
        mem_buf_desc_t *buff = rx_reuse->get_and_pop_front();
        reclaim_recv_buffer_helper(buff);
    }
    return_extra_buffers();

    return true;
}

int cq_mgr_rx::request_notification(uint64_t poll_sn)
{
    int ret = -1;

    cq_logfuncall("");

    if ((m_n_global_sn_rx > 0 && poll_sn != m_n_global_sn_rx)) {
        // The cq_mgr_rx's has receive packets pending processing (or got processed since
        // cq_poll_sn)
        cq_logfunc("miss matched poll sn (user=0x%lx, cq=0x%lx)", poll_sn, m_n_cq_poll_sn_rx);
        return 1;
    }

    if (m_b_notification_armed == false) {

        cq_logfunc("arming cq_mgr_rx notification channel");

        // Arm the CQ notification channel
        IF_VERBS_FAILURE(xlio_ib_mlx5_req_notify_cq(&m_mlx5_cq, 0))
        {
            cq_logerr("Failure arming the RX notification channel (errno=%d %m)", errno);
        }
        else
        {
            ret = 0;
            m_b_notification_armed = true;
        }
        ENDIF_VERBS_FAILURE;
    } else {
        // cq_mgr_rx notification channel already armed
        ret = 0;
    }

    cq_logfuncall("returning with %d", ret);
    return ret;
}

int cq_mgr_rx::wait_for_notification_and_process_element(uint64_t *p_cq_poll_sn,
                                                         void *pv_fd_ready_array)
{
    int ret = -1;

    cq_logfunc("");

    if (m_b_notification_armed) {
        cq_mgr_rx *p_cq_mgr_context = nullptr;
        struct ibv_cq *p_cq_hndl = nullptr;
        void *p; // deal with compiler warnings

        // Block on the cq_mgr_rx's notification event channel
        IF_VERBS_FAILURE(ibv_get_cq_event(m_comp_event_channel, &p_cq_hndl, &p))
        {
            cq_logfunc("waiting on cq_mgr_rx event returned with error (errno=%d %m)", errno);
        }
        else
        {
            get_cq_event();
            p_cq_mgr_context = (cq_mgr_rx *)p;
            if (p_cq_mgr_context != this) {
                cq_logerr("mismatch with cq_mgr_rx returned from new event (event->cq_mgr_rx->%p)",
                          p_cq_mgr_context);
                // this can be if we are using a single channel for several/all cq_mgrs
                // in this case we need to deliver the event to the correct cq_mgr_rx
            }

            // Ack event
            ibv_ack_cq_events(m_p_ibv_cq, 1);

            // Clear flag
            m_b_notification_armed = false;

            // Now try processing the ready element
            ret = poll_and_process_element_rx(p_cq_poll_sn, pv_fd_ready_array);
        }
        ENDIF_VERBS_FAILURE;
    } else {
        cq_logfunc("notification channel is not armed");
        errno = EAGAIN;
    }

    return ret;
}
