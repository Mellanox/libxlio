/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <inttypes.h>
#include <netinet/ip6.h>
#include <mutex>
#include "ring_simple.h"
#include "proto/ip_frag.h"
#include "dev/rfs_mc.h"
#include "dev/rfs_uc_tcp_gro.h"
#include "util/valgrind.h"
#include "util/sg_array.h"
#include "sock/fd_collection.h"
#include "sock/sockinfo.h"

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

// AF_INET address 0.0.0.0:0, used for 3T flow spec keys.
static const sock_addr s_sock_addrany;

static thread_local lock_dummy t_lock_dummy_ring;

static lock_base *get_new_lock(const char *name, bool real_lock)
{
    return (real_lock
                ? static_cast<lock_base *>(multilock::create_new_lock(MULTILOCK_RECURSIVE, name))
                : static_cast<lock_base *>(&t_lock_dummy_ring));
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

ring_simple::ring_simple(int if_index, ring *parent, bool use_locks)
    : ring()
    , m_steering_ipv4(*this)
    , m_steering_ipv6(*this)
    , m_lock_ring_rx(get_new_lock("ring_simple:lock_rx", use_locks))
    , m_lock_ring_tx(get_new_lock("ring_simple:lock_tx", use_locks))
    , m_p_ring_stat(new ring_stats_t())
    , m_vlan(0)
    , m_flow_tag_enabled(false)
    , m_b_sysvar_eth_mc_l2_only_rules(safe_mce_sys().eth_mc_l2_only_rules)
    , m_b_sysvar_mc_force_flowtag(safe_mce_sys().mc_force_flowtag)
    , m_lock_ring_tx_buf_wait("ring:lock_tx_buf_wait")
    , m_gro_mgr(safe_mce_sys().gro_streams_max, MAX_GRO_BUFS)
{
    /* Configure ring() fields */
    set_parent(parent);
    set_if_index(if_index);

    /* Sanity check */
    net_device_val *p_ndev = g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());
    if (!p_ndev) {
        ring_logpanic("Invalid if_index = %d", if_index);
    }

    const slave_data_t *p_slave = p_ndev->get_slave(get_if_index());

    m_transport_type = p_ndev->get_transport_type();

    /* Set the same ring active status as related slave has for all ring types
     * excluding ring with type RING_TAP that does not have related slave device.
     * So it is marked as active just in case related netvsc device is absent.
     */
    m_active = p_slave ? p_slave->active : p_ndev->get_slave_array().empty();

    // use local copy of stats by default
    memset(m_p_ring_stat.get(), 0, sizeof(ring_stats_t));
    if (m_parent != this) {
        m_p_ring_stat->p_ring_master = m_parent;
    }

    m_tx_pool.set_id("ring_simple (%p) : m_tx_pool", this);
    m_zc_pool.set_id("ring_simple (%p) : m_zc_pool", this);

    xlio_stats_instance_create_ring_block(m_p_ring_stat.get());

    print_val();

    /* m_p_ib_ctx, m_tx_lkey should be initialized to be used
     * in ring_eth_direct, ring_eth_cb constructors
     */
    BULLSEYE_EXCLUDE_BLOCK_START
    m_p_ib_ctx = p_slave->p_ib_ctx;
    if (!m_p_ib_ctx) {
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
    memset(&m_tls, 0, sizeof(m_tls));
    memset(&m_lro, 0, sizeof(m_lro));

    m_vlan = p_ndev->get_vlan();
    create_resources();
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

    if (m_hqtx) {
        stop_active_queue_tx();

        // Release QP/CQ resources
        delete m_hqtx;
        m_hqtx = nullptr;
    }

    if (m_hqrx) {
        stop_active_queue_rx();

        // Release QP/CQ resources
        delete m_hqrx;
        m_hqrx = nullptr;
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
        m_p_tx_comp_event_channel = nullptr;
    }

    /* coverity[double_unlock] TODO: RM#1049980 */
    m_lock_ring_tx.unlock();
    m_lock_ring_rx.unlock();

    ring_logdbg("delete ring_simple() completed");

    print_val();

    if (m_p_ring_stat) {
        xlio_stats_instance_remove_ring_block(m_p_ring_stat.get());
    }

    /* Release TX buffer poll */
    g_buffer_pool_tx->put_buffers_thread_safe(&m_tx_pool, m_tx_pool.size());
    g_buffer_pool_zc->put_buffers_thread_safe(&m_zc_pool, m_zc_pool.size());
}

void ring_simple::create_resources()
{
    net_device_val *p_ndev = g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!p_ndev) {
        // Coverity warning suppression
        throw_xlio_exception("Cannot find netdev for a ring");
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    const slave_data_t *p_slave = p_ndev->get_slave(get_if_index());

    save_l2_address(p_slave->p_L2_addr);
    m_p_tx_comp_event_channel = ibv_create_comp_channel(m_p_ib_ctx->get_ibv_context());
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!m_p_tx_comp_event_channel) {
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
                if (caps->max_tso && (caps->max_tso > MCE_DEFAULT_MAX_TSO_SIZE)) {
                    ring_logwarn("max_tso cap (=%u) is higher than default TSO size (=%u). "
                                 "Increase XLIO_MAX_TSO_SIZE to get full TSO potential.",
                                 caps->max_tso, MCE_DEFAULT_MAX_TSO_SIZE);
                }
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
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    if (g_p_app->type != APP_NONE && g_p_app->get_worker_id() >= 0) {
        m_flow_tag_enabled = false;
    }
#endif
    ring_logdbg("ring attributes: m_flow_tag_enabled = %d", m_flow_tag_enabled);

    m_p_rx_comp_event_channel = ibv_create_comp_channel(m_p_ib_ctx->get_ibv_context());
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!m_p_rx_comp_event_channel) {
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

    std::unique_ptr<hw_queue_tx> temp_hqtx(new hw_queue_tx(this, p_slave, get_tx_num_wr()));
    std::unique_ptr<hw_queue_rx> temp_hqrx(
        new hw_queue_rx(this, p_slave->p_ib_ctx, m_p_rx_comp_event_channel, m_vlan));
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!temp_hqtx || !temp_hqrx) {
        ring_logerr("Failed to allocate hw_queue_tx/hw_queue_rx!");
        throw_xlio_exception("Create hw_queue_tx/hw_queue_rx failed");
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    m_hqtx = temp_hqtx.release();
    m_hqrx = temp_hqrx.release();

    // save pointers
    m_p_cq_mgr_rx = m_hqrx->get_rx_cq_mgr();
    m_p_cq_mgr_tx = m_hqtx->get_tx_cq_mgr();

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
        start_active_queue_tx();
        start_active_queue_rx();
    }

    ring_logdbg("new ring_simple() completed");

    print_val();

    if (m_p_ring_stat) {
        xlio_stats_instance_remove_ring_block(m_p_ring_stat.get());
    }

    /* Release TX buffer poll */
    g_buffer_pool_tx->put_buffers_thread_safe(&m_tx_pool, m_tx_pool.size());
    g_buffer_pool_zc->put_buffers_thread_safe(&m_zc_pool, m_zc_pool.size());
}

void ring_simple::print_val()
{
    ring_logdbg("%d: %p: parent %p", m_if_index, this,
                ((uintptr_t)this == (uintptr_t)m_parent ? nullptr : m_parent));
}

void ring_simple::restart()
{
    ring_logpanic("Can't restart a slave ring");
}

bool ring_simple::is_active_member(ring *rng, ring_user_id_t)
{
    return (this == rng);
}

bool ring_simple::is_member(ring *rng)
{
    return (this == rng);
}

ring_user_id_t ring_simple::generate_id(const address_t, const address_t, uint16_t, uint16_t,
                                        const ip_address &, const ip_address &, uint16_t, uint16_t)
{
    return 0;
}

void ring_simple::inc_tx_retransmissions_stats(ring_user_id_t)
{
    m_p_ring_stat->n_tx_retransmits++;
}

template <typename KEY4T, typename KEY2T, typename HDR>
bool steering_handler<KEY4T, KEY2T, HDR>::attach_flow(flow_tuple &flow_spec_5t, sockinfo *sink,
                                                      bool force_5t)
{
    rfs *p_rfs;
    rfs *p_tmp_rfs = nullptr;
    sockinfo *si = static_cast<sockinfo *>(sink);

    if (!si) {
        return false;
    }

    uint32_t flow_tag_id = si->get_flow_tag_val(); // spec will not be attached to rule
    if (!m_ring.m_flow_tag_enabled) {
        flow_tag_id = 0;
    }
    ring_logdbg("flow: %s, with sink (%p), flow tag id %d "
                "m_flow_tag_enabled: %d",
                flow_spec_5t.to_str().c_str(), si, flow_tag_id, m_ring.m_flow_tag_enabled);

    /* Get the appropriate hash map (tcp, uc or mc) from the 5t details
     * TODO: Consider unification of following code.
     */
    if (flow_spec_5t.is_udp_uc()) {
        KEY4T rfs_key(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_src_ip(),
                      flow_spec_5t.get_dst_port(), flow_spec_5t.get_src_port());
        sock_addr rule_key(flow_spec_5t.get_family(), &flow_spec_5t.get_dst_ip(),
                           flow_spec_5t.get_dst_port());
        rfs_rule_filter *dst_port_filter = nullptr;
        if (safe_mce_sys().udp_3t_rules) {
            auto dst_port_iter = m_ring.m_udp_uc_dst_port_attach_map.find(rule_key);
            if (dst_port_iter == m_ring.m_udp_uc_dst_port_attach_map.end()) {
                m_ring.m_udp_uc_dst_port_attach_map[rule_key].counter = 1;
            } else {
                m_ring.m_udp_uc_dst_port_attach_map[rule_key].counter =
                    ((dst_port_iter->second.counter) + 1);
            }
        }

        if (flow_tag_id && si->flow_in_reuse()) {
            flow_tag_id = FLOW_TAG_MASK;
            ring_logdbg("UC flow tag for socketinfo=%p is disabled: SO_REUSEADDR or SO_REUSEPORT "
                        "were enabled",
                        si);
        }

        auto itr = m_flow_udp_uc_map.find(rfs_key);
        if (itr == end(m_flow_udp_uc_map)) {
            // No rfs object exists so a new one must be created and inserted in the flow map
            if (safe_mce_sys().udp_3t_rules) {
                flow_tuple udp_3t_only(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port(),
                                       ip_address::any_addr(), 0, flow_spec_5t.get_protocol(),
                                       flow_spec_5t.get_family());
                dst_port_filter =
                    new rfs_rule_filter(m_ring.m_udp_uc_dst_port_attach_map, rule_key, udp_3t_only);
            }
            try {
                p_tmp_rfs =
                    new (std::nothrow) rfs_uc(&flow_spec_5t, &m_ring, dst_port_filter, flow_tag_id);
            } catch (xlio_exception &e) {
                ring_logerr("%s", e.message);
                return false;
            }
            BULLSEYE_EXCLUDE_BLOCK_START
            if (!p_tmp_rfs) {
                ring_logerr("Failed to allocate rfs!");
                return false;
            }
            BULLSEYE_EXCLUDE_BLOCK_END

            p_rfs = p_tmp_rfs;
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
            if (g_p_app->type == APP_NONE || !g_p_app->add_second_4t_rule)
#endif
            {
                m_flow_udp_uc_map[rfs_key] = p_rfs;
            }
        } else {
            p_rfs = itr->second;
        }
    } else if (flow_spec_5t.is_udp_mc()) {
        KEY2T key_udp_mc(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port());
        sock_addr rule_key(flow_spec_5t.get_family(), &flow_spec_5t.get_dst_ip(), 0U);
        if (flow_tag_id) {
            if (m_ring.m_b_sysvar_mc_force_flowtag || !si->flow_in_reuse()) {
                ring_logdbg("MC flow tag ID=%d for socketinfo=%p is enabled: force_flowtag=%d, "
                            "SO_REUSEADDR | SO_REUSEPORT=%d",
                            flow_tag_id, si, m_ring.m_b_sysvar_mc_force_flowtag,
                            si->flow_in_reuse());
            } else {
                flow_tag_id = FLOW_TAG_MASK;
                ring_logdbg("MC flow tag for socketinfo=%p is disabled: force_flowtag=0, "
                            "SO_REUSEADDR or SO_REUSEPORT were enabled",
                            si);
            }
        }
        // Note for CX3:
        // For IB MC flow, the port is zeroed in the ibv_flow_spec when calling to ibv_flow_spec().
        // It means that for every MC group, even if we have sockets with different ports - only one
        // rule in the HW. So the hash map below keeps track of the number of sockets per rule so we
        // know when to call ibv_attach and ibv_detach
        rfs_rule_filter *l2_mc_ip_filter = nullptr;
        if (m_ring.m_b_sysvar_eth_mc_l2_only_rules) {
            auto l2_mc_iter = m_ring.m_l2_mc_ip_attach_map.find(rule_key);
            // It means that this is the first time attach called with this MC ip
            if (l2_mc_iter == m_ring.m_l2_mc_ip_attach_map.end()) {
                m_ring.m_l2_mc_ip_attach_map[rule_key].counter = 1;
            } else {
                m_ring.m_l2_mc_ip_attach_map[rule_key].counter = ((l2_mc_iter->second.counter) + 1);
            }
        }

        auto itr = m_flow_udp_mc_map.find(key_udp_mc);
        if (itr == m_flow_udp_mc_map.end()) {
            // It means that no rfs object exists so I need to create a new one and insert it to
            // the flow map.
            if (m_ring.m_b_sysvar_eth_mc_l2_only_rules) {
                l2_mc_ip_filter =
                    new rfs_rule_filter(m_ring.m_l2_mc_ip_attach_map, rule_key, flow_spec_5t);
            }
            try {
                p_tmp_rfs = new rfs_mc(&flow_spec_5t, &m_ring, l2_mc_ip_filter, flow_tag_id);
            } catch (xlio_exception &e) {
                ring_logerr("%s", e.message);
                return false;
            } catch (const std::bad_alloc &e) {
                NOT_IN_USE(e);
                ring_logerr("Failed to allocate rfs!");
                return false;
            }

            p_rfs = p_tmp_rfs;
            m_flow_udp_mc_map[key_udp_mc] = p_rfs;
        } else {
            p_rfs = itr->second;
        }
    } else if (flow_spec_5t.is_tcp()) {
        KEY4T rfs_key(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_src_ip(),
                      flow_spec_5t.get_dst_port(), flow_spec_5t.get_src_port());
        sock_addr rule_key(flow_spec_5t.get_family(), &flow_spec_5t.get_dst_ip(),
                           flow_spec_5t.get_dst_port());
        rfs_rule_filter *dst_port_filter = nullptr;
        if (safe_mce_sys().tcp_3t_rules || safe_mce_sys().tcp_2t_rules) {
            if (safe_mce_sys().tcp_2t_rules) {
                rule_key.set_in_port(0);
            }
            auto dst_port_iter = m_ring.m_tcp_dst_port_attach_map.find(rule_key);
            if (dst_port_iter == m_ring.m_tcp_dst_port_attach_map.end()) {
                m_ring.m_tcp_dst_port_attach_map[rule_key].counter = 1;
            } else {
                m_ring.m_tcp_dst_port_attach_map[rule_key].counter =
                    ((dst_port_iter->second.counter) + 1);
            }
        }

        if (flow_tag_id &&
            (flow_spec_5t.is_3_tuple() || (!force_5t && safe_mce_sys().tcp_3t_rules) ||
             safe_mce_sys().tcp_2t_rules)) {
            ring_logdbg("flow tag id = %d is disabled for socket fd = %d to be processed on RFS!",
                        flow_tag_id, si->get_fd());
            flow_tag_id = FLOW_TAG_MASK;
        }

        auto itr = m_flow_tcp_map.find(rfs_key);
        if (itr == end(m_flow_tcp_map)) {
            // It means that no rfs object exists so I need to create a new one and insert it to
            // the flow map
            if (safe_mce_sys().tcp_2t_rules) {
                flow_tuple tcp_2t_only(flow_spec_5t.get_dst_ip(), 0, ip_address::any_addr(), 0,
                                       flow_spec_5t.get_protocol(), flow_spec_5t.get_family());
                dst_port_filter =
                    new rfs_rule_filter(m_ring.m_tcp_dst_port_attach_map, rule_key, tcp_2t_only);
            } else if (!force_5t && safe_mce_sys().tcp_3t_rules) {
                flow_tuple tcp_3t_only(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port(),
                                       ip_address::any_addr(), 0, flow_spec_5t.get_protocol(),
                                       flow_spec_5t.get_family());
                dst_port_filter =
                    new rfs_rule_filter(m_ring.m_tcp_dst_port_attach_map, rule_key, tcp_3t_only);
            }
            try {
                if (safe_mce_sys().gro_streams_max) {
                    p_tmp_rfs = new (std::nothrow)
                        rfs_uc_tcp_gro(&flow_spec_5t, &m_ring, dst_port_filter, flow_tag_id);
                } else {
                    p_tmp_rfs = new (std::nothrow)
                        rfs_uc(&flow_spec_5t, &m_ring, dst_port_filter, flow_tag_id);
                }
            } catch (xlio_exception &e) {
                ring_logerr("%s", e.message);
                return false;
            }
            BULLSEYE_EXCLUDE_BLOCK_START
            if (!p_tmp_rfs) {
                ring_logerr("Failed to allocate rfs!");
                return false;
            }
            BULLSEYE_EXCLUDE_BLOCK_END

            p_rfs = p_tmp_rfs;
            si->set_rfs_ptr(p_rfs);
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
            if (g_p_app->type == APP_NONE || !g_p_app->add_second_4t_rule)
#endif
            {
                m_flow_tcp_map[rfs_key] = p_rfs;
            }
        } else {
            p_rfs = itr->second;
        }
        BULLSEYE_EXCLUDE_BLOCK_START
    } else {
        ring_logerr("Could not find map (TCP, UC or MC) for requested flow");
        return false;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    bool ret = p_rfs->attach_flow(sink);
    if (ret) {
        if (flow_tag_id && (flow_tag_id != FLOW_TAG_MASK)) {
            // A flow with FlowTag was attached succesfully, check stored rfs for fast path be
            // tag_id
            si->set_flow_tag(flow_tag_id);
            ring_logdbg("flow_tag: %d registration is done!", flow_tag_id);
        }
    } else {
        ring_logerr("attach_flow=%d failed!", ret);
    }

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    /* coverity[leaked_storage]
     * Storage leak happens due to g_p_app->add_second_4t_rule logic
     * created new rfs pointed by p_rfs is not stored in map
     * and as a result it is not destroyed
     */
#endif
    /* coverity[leaked_storage] */
    return ret;
}

bool ring_simple::attach_flow(flow_tuple &flow_spec_5t, sockinfo *sink, bool force_5t)
{
    std::lock_guard<decltype(m_lock_ring_rx)> lock(m_lock_ring_rx);

    return (flow_spec_5t.get_family() == AF_INET
                ? m_steering_ipv4.attach_flow(flow_spec_5t, sink, force_5t)
                : m_steering_ipv6.attach_flow(flow_spec_5t, sink, force_5t));
}

template <typename KEY4T, typename KEY2T, typename HDR>
bool steering_handler<KEY4T, KEY2T, HDR>::detach_flow(flow_tuple &flow_spec_5t, sockinfo *sink)
{
    rfs *p_rfs = nullptr;

    ring_logdbg("flow: %s, with sink (%p)", flow_spec_5t.to_str().c_str(), sink);

    /* Get the appropriate hash map (tcp, uc or mc) from the 5t details
     * TODO: Consider unification of following code.
     */
    if (flow_spec_5t.is_udp_uc()) {
        int keep_in_map = 1;
        KEY4T rfs_key(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_src_ip(),
                      flow_spec_5t.get_dst_port(), flow_spec_5t.get_src_port());
        sock_addr rule_key(flow_spec_5t.get_family(), &flow_spec_5t.get_dst_ip(),
                           flow_spec_5t.get_dst_port());
        if (safe_mce_sys().udp_3t_rules) {
            auto dst_port_iter = m_ring.m_udp_uc_dst_port_attach_map.find(rule_key);
            if (dst_port_iter == m_ring.m_udp_uc_dst_port_attach_map.end()) {
                ring_logdbg("Could not find matching counter for UDP src port!");
            } else {
                keep_in_map = m_ring.m_udp_uc_dst_port_attach_map[rule_key].counter =
                    std::max(0, ((dst_port_iter->second.counter) - 1));
            }
        }
        auto itr = m_flow_udp_uc_map.find(rfs_key);
        BULLSEYE_EXCLUDE_BLOCK_START
        if (itr == end(m_flow_udp_uc_map)) {
            ring_logdbg("Could not find rfs object to detach!");
            return false;
        }
        BULLSEYE_EXCLUDE_BLOCK_END

        p_rfs = itr->second;
        p_rfs->detach_flow(sink);
        if (!keep_in_map) {
            m_ring.m_udp_uc_dst_port_attach_map.erase(
                m_ring.m_udp_uc_dst_port_attach_map.find(rule_key));
        }
        if (p_rfs->get_num_of_sinks() == 0) {
            BULLSEYE_EXCLUDE_BLOCK_START
            m_flow_udp_uc_map.erase(itr);
            BULLSEYE_EXCLUDE_BLOCK_END
            delete p_rfs;
        }
    } else if (flow_spec_5t.is_udp_mc()) {
        int keep_in_map = 1;
        KEY2T key_udp_mc(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port());
        sock_addr rule_key(flow_spec_5t.get_family(), &flow_spec_5t.get_dst_ip(), 0U);
        if (m_ring.m_b_sysvar_eth_mc_l2_only_rules) {
            auto l2_mc_iter = m_ring.m_l2_mc_ip_attach_map.find(rule_key);
            BULLSEYE_EXCLUDE_BLOCK_START
            if (l2_mc_iter == m_ring.m_l2_mc_ip_attach_map.end()) {
                ring_logdbg("Could not find matching counter for the MC group!");
                BULLSEYE_EXCLUDE_BLOCK_END
            } else {
                keep_in_map = m_ring.m_l2_mc_ip_attach_map[rule_key].counter =
                    std::max(0, ((l2_mc_iter->second.counter) - 1));
            }
        }

        auto itr = m_flow_udp_mc_map.find(key_udp_mc);
        BULLSEYE_EXCLUDE_BLOCK_START
        if (itr == end(m_flow_udp_mc_map)) {
            ring_logdbg("Could not find rfs object to detach!");
            return false;
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        p_rfs = itr->second;
        p_rfs->detach_flow(sink);
        if (!keep_in_map) {
            m_ring.m_l2_mc_ip_attach_map.erase(m_ring.m_l2_mc_ip_attach_map.find(rule_key));
        }
        if (p_rfs->get_num_of_sinks() == 0) {
            BULLSEYE_EXCLUDE_BLOCK_START
            m_flow_udp_mc_map.erase(itr);
            BULLSEYE_EXCLUDE_BLOCK_END
            delete p_rfs;
        }
    } else if (flow_spec_5t.is_tcp()) {
        int keep_in_map = 1;
        KEY4T rfs_key(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_src_ip(),
                      flow_spec_5t.get_dst_port(), flow_spec_5t.get_src_port());
        sock_addr rule_key(flow_spec_5t.get_family(), &flow_spec_5t.get_dst_ip(),
                           flow_spec_5t.get_dst_port());
        if (safe_mce_sys().tcp_3t_rules || safe_mce_sys().tcp_2t_rules) {
            auto dst_port_iter = m_ring.m_tcp_dst_port_attach_map.find(rule_key);
            BULLSEYE_EXCLUDE_BLOCK_START
            if (dst_port_iter == m_ring.m_tcp_dst_port_attach_map.end()) {
                ring_logdbg("Could not find matching counter for TCP src port!");
                BULLSEYE_EXCLUDE_BLOCK_END
            } else {
                keep_in_map = m_ring.m_tcp_dst_port_attach_map[rule_key].counter =
                    std::max(0, ((dst_port_iter->second.counter) - 1));
            }
        }
        auto itr = m_flow_tcp_map.find(rfs_key);
        BULLSEYE_EXCLUDE_BLOCK_START
        if (itr == end(m_flow_tcp_map)) {
            ring_logdbg("Could not find rfs object to detach!");
            return false;
        }
        BULLSEYE_EXCLUDE_BLOCK_END

        p_rfs = itr->second;
        p_rfs->detach_flow(sink);
        if (!keep_in_map) {
            m_ring.m_tcp_dst_port_attach_map.erase(m_ring.m_tcp_dst_port_attach_map.find(rule_key));
        }
        if (p_rfs->get_num_of_sinks() == 0) {
            BULLSEYE_EXCLUDE_BLOCK_START
            m_flow_tcp_map.erase(itr);
            BULLSEYE_EXCLUDE_BLOCK_END
            delete p_rfs;
        }
        BULLSEYE_EXCLUDE_BLOCK_START
    } else {
        ring_logerr("Could not find map (TCP, UC or MC) for requested flow");
        return false;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return true;
}

bool ring_simple::detach_flow(flow_tuple &flow_spec_5t, sockinfo *sink)
{
    std::lock_guard<decltype(m_lock_ring_rx)> lock(m_lock_ring_rx);

    return (flow_spec_5t.get_family() == AF_INET ? m_steering_ipv4.detach_flow(flow_spec_5t, sink)
                                                 : m_steering_ipv6.detach_flow(flow_spec_5t, sink));
}

#ifdef DEFINED_UTLS
template <typename KEY4T, typename KEY2T, typename HDR>
rfs_rule *steering_handler<KEY4T, KEY2T, HDR>::tls_rx_create_rule(const flow_tuple &flow_spec_5t,
                                                                  xlio_tir *tir)
{
    KEY4T rfs_key(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_src_ip(), flow_spec_5t.get_dst_port(),
                  flow_spec_5t.get_src_port());
    auto itr = m_flow_tcp_map.find(rfs_key);
    if (itr == end(m_flow_tcp_map)) {
        ring_logerr("Could not find rfs for flow: %s", flow_spec_5t.to_str().c_str());
        return NULL;
    }
    rfs *p_rfs = itr->second;
    return p_rfs->create_rule(tir, flow_spec_5t);
}

rfs_rule *ring_simple::tls_rx_create_rule(const flow_tuple &flow_spec_5t, xlio_tir *tir)
{
    return (flow_spec_5t.get_family() == AF_INET
                ? m_steering_ipv4.tls_rx_create_rule(flow_spec_5t, tir)
                : m_steering_ipv6.tls_rx_create_rule(flow_spec_5t, tir));
}
#endif /* DEFINED_UTLS */

// calling sockinfo callback with RFS bypass
static inline bool check_rx_packet(sockinfo *si, mem_buf_desc_t *p_rx_wc_buf_desc,
                                   void *fd_ready_array)
{
    p_rx_wc_buf_desc->reset_ref_count();
    return si->rx_input_cb(p_rx_wc_buf_desc, fd_ready_array);
}

// All CQ wce come here for some basic sanity checks and then are distributed to the correct ring
// handler Return values: false = Reuse this data buffer & mem_buf_desc
bool ring_simple::rx_process_buffer(mem_buf_desc_t *p_rx_wc_buf_desc, void *pv_fd_ready_array)
{
    static uint16_t NET_ETH_P_IP = htons(ETH_P_IP);
    static uint16_t NET_ETH_P_IPV6 = htons(ETH_P_IPV6);
    static uint16_t NET_ETH_P_8021Q = htons(ETH_P_8021Q);

    size_t transport_header_len;
    struct ethhdr *p_eth_h = (struct ethhdr *)(p_rx_wc_buf_desc->p_buffer);

    // Validate buffer size
    size_t sz_data = p_rx_wc_buf_desc->sz_data;
    if (unlikely(sz_data > p_rx_wc_buf_desc->sz_buffer)) {
        if (sz_data == IP_FRAG_FREED) {
            ring_logfuncall("Rx buffer dropped - old fragment part");
        } else {
            ring_logwarn("Rx buffer dropped - buffer too small (%zu, %lu)", sz_data,
                         p_rx_wc_buf_desc->sz_buffer);
        }
        return false;
    }

    inc_cq_moderation_stats();

    m_p_ring_stat->n_rx_byte_count += sz_data;
    ++m_p_ring_stat->n_rx_pkt_count;

    // This is an internal function (within ring and 'friends'). No need for lock mechanism.
    if (likely(m_flow_tag_enabled && p_rx_wc_buf_desc->rx.flow_tag_id &&
               p_rx_wc_buf_desc->rx.flow_tag_id != FLOW_TAG_MASK &&
               !p_rx_wc_buf_desc->rx.is_sw_csum_need)) {
        sockinfo *si = nullptr;
        // trying to get sockinfo per flow_tag_id-1 as it was incremented at attach
        // to allow mapping sockfd=0
        assert(g_p_fd_collection);
        si = static_cast<sockinfo *>(
            g_p_fd_collection->get_sockfd(p_rx_wc_buf_desc->rx.flow_tag_id - 1));

        if (likely(si)) {
            // will process packets with set flow_tag_id and enabled for the socket
            if (p_eth_h->h_proto == NET_ETH_P_8021Q) {
                // Handle VLAN header as next protocol
                transport_header_len = ETH_VLAN_HDR_LEN;
            } else {
                transport_header_len = ETH_HDR_LEN;
            }

            const void *saddr, *daddr;
            sa_family_t family;
            uint16_t ip_payload_len;
            uint16_t ip_hdr_len;
            uint8_t protocol;

            struct iphdr *p_ip_h =
                (struct iphdr *)(p_rx_wc_buf_desc->p_buffer + transport_header_len);
            if (likely(p_ip_h->version == IPV4_VERSION)) { // IPv4
                ip_hdr_len = IP_HLEN; //(int)(p_ip_h->ihl)*4;
                ip_payload_len = ntohs(p_ip_h->tot_len) - ip_hdr_len;
                protocol = p_ip_h->protocol;
                saddr = &p_ip_h->saddr;
                daddr = &p_ip_h->daddr;
                family = AF_INET;
            } else {
                struct ip6_hdr *p_ip_h6 = reinterpret_cast<struct ip6_hdr *>(p_ip_h);
                ip_hdr_len = IPV6_HLEN;
                ip_payload_len = ntohs(p_ip_h6->ip6_plen);
                protocol = p_ip_h6->ip6_nxt;
                saddr = &p_ip_h6->ip6_src;
                daddr = &p_ip_h6->ip6_dst;
                family = AF_INET6;
            }
            // Remove ethernet padding from the data size
            p_rx_wc_buf_desc->sz_data = transport_header_len + ip_hdr_len + ip_payload_len;

            ring_logfunc("FAST PATH Rx packet info: transport_header_len: %d, IP_header_len: %d L3 "
                         "proto: %d flow_tag_id: %d",
                         transport_header_len, ip_hdr_len, protocol,
                         p_rx_wc_buf_desc->rx.flow_tag_id);

            if (likely(protocol == IPPROTO_TCP)) {
                struct tcphdr *p_tcp_h = (struct tcphdr *)((uint8_t *)p_ip_h + ip_hdr_len);

                // Update packet descriptor with datagram base address and length
                p_rx_wc_buf_desc->rx.frag.iov_base = (uint8_t *)p_tcp_h + sizeof(struct tcphdr);
                p_rx_wc_buf_desc->rx.frag.iov_len = ip_payload_len - sizeof(struct tcphdr);
                p_rx_wc_buf_desc->rx.sz_payload = ip_payload_len - p_tcp_h->doff * 4;

                p_rx_wc_buf_desc->rx.tcp.p_ip_h = p_ip_h;
                p_rx_wc_buf_desc->rx.tcp.p_tcp_h = p_tcp_h;
                p_rx_wc_buf_desc->rx.n_transport_header_len = transport_header_len;
                p_rx_wc_buf_desc->rx.n_frags = 1;

                ring_logfunc("FAST PATH Rx TCP segment info: src_port=%d, dst_port=%d, "
                             "flags='%s%s%s%s%s%s' seq=%u, ack=%u, win=%u, payload_sz=%u",
                             ntohs(p_tcp_h->source), ntohs(p_tcp_h->dest), p_tcp_h->urg ? "U" : "",
                             p_tcp_h->ack ? "A" : "", p_tcp_h->psh ? "P" : "",
                             p_tcp_h->rst ? "R" : "", p_tcp_h->syn ? "S" : "",
                             p_tcp_h->fin ? "F" : "", ntohl(p_tcp_h->seq), ntohl(p_tcp_h->ack_seq),
                             ntohs(p_tcp_h->window), p_rx_wc_buf_desc->rx.sz_payload);

                return si->get_rfs_ptr()->rx_dispatch_packet(p_rx_wc_buf_desc, pv_fd_ready_array);
            }

            if (likely(protocol == IPPROTO_UDP)) {
                struct udphdr *p_udp_h = (struct udphdr *)((uint8_t *)p_ip_h + ip_hdr_len);

                // Update the L3 and L4 info
                p_rx_wc_buf_desc->rx.src.set_ip_port(family, saddr, p_udp_h->source);
                p_rx_wc_buf_desc->rx.dst.set_ip_port(family, daddr, p_udp_h->dest);

                // Update packet descriptor with datagram base address and length
                p_rx_wc_buf_desc->rx.frag.iov_base = (uint8_t *)p_udp_h + sizeof(struct udphdr);
                p_rx_wc_buf_desc->rx.frag.iov_len = ip_payload_len - sizeof(struct udphdr);
                p_rx_wc_buf_desc->rx.sz_payload = ntohs(p_udp_h->len) - sizeof(struct udphdr);

                p_rx_wc_buf_desc->rx.udp.ifindex = m_parent->get_if_index();
                p_rx_wc_buf_desc->rx.n_frags = 1;

                ring_logfunc("FAST PATH Rx UDP datagram info: src_port=%d, dst_port=%d, "
                             "payload_sz=%d, csum=%#x",
                             ntohs(p_udp_h->source), ntohs(p_udp_h->dest),
                             p_rx_wc_buf_desc->rx.sz_payload, p_udp_h->check);

                return check_rx_packet(si, p_rx_wc_buf_desc, pv_fd_ready_array);
            }

            return false;
        }
    }

    // Validate transport type headers
    switch (m_transport_type) {
    case XLIO_TRANSPORT_ETH: {
        uint16_t h_proto = p_eth_h->h_proto;

        ring_logfunc("Rx buffer Ethernet dst=" ETH_HW_ADDR_PRINT_FMT
                     " <- src=" ETH_HW_ADDR_PRINT_FMT " type=%#x",
                     ETH_HW_ADDR_PRINT_ADDR(p_eth_h->h_dest),
                     ETH_HW_ADDR_PRINT_ADDR(p_eth_h->h_source), htons(h_proto));

        // Handle VLAN header as next protocol
        struct vlanhdr *p_vlan_hdr = nullptr;
        uint16_t packet_vlan = 0;
        if (h_proto == NET_ETH_P_8021Q) {
            p_vlan_hdr = (struct vlanhdr *)((uint8_t *)p_eth_h + ETH_HDR_LEN);
            transport_header_len = ETH_VLAN_HDR_LEN;
            h_proto = p_vlan_hdr->h_vlan_encapsulated_proto;
            packet_vlan = (htons(p_vlan_hdr->h_vlan_TCI) & VLAN_VID_MASK);
        } else {
            transport_header_len = ETH_HDR_LEN;
        }

        p_rx_wc_buf_desc->rx.n_transport_header_len = transport_header_len;

        // TODO: Remove this code when handling vlan in flow steering will be available. Change this
        // code if vlan stripping is performed.
        if ((m_vlan & VLAN_VID_MASK) != packet_vlan) {
            ring_logfunc("Rx buffer dropped- Mismatched vlan. Packet vlan = %d, Local vlan = %d",
                         packet_vlan, m_vlan & VLAN_VID_MASK);
            return false;
        }

        // Validate IP header as next protocol
        if (unlikely(h_proto != NET_ETH_P_IP) && unlikely(h_proto != NET_ETH_P_IPV6)) {
            ring_logwarn("Rx buffer dropped - Invalid Ethr Type (h_proto=%#x-p_eth_h->h_proto=%#x "
                         ": %#x, %#x)",
                         h_proto, p_eth_h->h_proto, NET_ETH_P_IP, NET_ETH_P_IPV6);
            return false;
        }
    } break;
    default:
        ring_logwarn("Rx buffer dropped - Unknown transport type %d", m_transport_type);
        return false;
    }

    // Jump to IP header - Skip Ethernet (MAC) header sizes
    sz_data -= transport_header_len;

    // Validate size for IPv4 header
    if (unlikely(sz_data < sizeof(struct iphdr))) {
        ring_logwarn("Rx buffer dropped - buffer too small for IPv4 header (%zu, %zu)", sz_data,
                     sizeof(struct iphdr));
        return false;
    }

    // Get the ip header pointer
    struct iphdr *p_ip_h = (struct iphdr *)(p_rx_wc_buf_desc->p_buffer + transport_header_len);

    if (likely(p_ip_h->version == IPV4_VERSION)) {
        return m_steering_ipv4.rx_process_buffer_no_flow_id(p_rx_wc_buf_desc, pv_fd_ready_array,
                                                            p_ip_h);
    }

    if (likely(p_ip_h->version == IPV6_VERSION)) {
        return m_steering_ipv6.rx_process_buffer_no_flow_id(p_rx_wc_buf_desc, pv_fd_ready_array,
                                                            reinterpret_cast<ip6_hdr *>(p_ip_h));
    }

    // Drop all non IPv4 packets
    ring_logwarn("Rx packet dropped - not IPV4/6 packet (got version: %#x)", p_ip_h->version);
    return false;
}

inline uint32_t hdr_get_tot_len(iphdr *p_ip_h)
{
    return ntohs(p_ip_h->tot_len);
}

inline uint32_t hdr_get_tot_len(ip6_hdr *p_ip_h)
{
    return ntohs(p_ip_h->ip6_plen) + IPV6_HLEN;
}

inline sa_family_t hdr_get_family(iphdr *p_ip_h)
{
    NOT_IN_USE(p_ip_h);
    return AF_INET;
}

inline sa_family_t hdr_get_family(ip6_hdr *p_ip_h)
{
    NOT_IN_USE(p_ip_h);
    return AF_INET6;
}

inline std::string hdr_get_id(iphdr *p_ip_h)
{
    return std::to_string(ntohs(p_ip_h->id));
}

inline std::string hdr_get_id(ip6_hdr *p_ip_h)
{
    return std::to_string(ntohs(p_ip_h->ip6_flow));
}

inline const void *hdr_get_saddr(iphdr *p_ip_h)
{
    return &p_ip_h->saddr;
}

inline const void *hdr_get_saddr(ip6_hdr *p_ip_h)
{
    return &p_ip_h->ip6_src;
}

inline const void *hdr_get_daddr(iphdr *p_ip_h)
{
    return &p_ip_h->daddr;
}

inline const void *hdr_get_daddr(ip6_hdr *p_ip_h)
{
    return &p_ip_h->ip6_dst;
}

// @param data Expected at least 8 bytes long buffer.
static inline int ipv6_ext_headers_parse(const void *data, size_t &ext_hdrs_len,
                                         uint8_t &next_header)
{
    switch (next_header) {
    case 51: // Authentication Header
        next_header = *reinterpret_cast<const uint8_t *>(data);
        ext_hdrs_len = (*(reinterpret_cast<const uint8_t *>(data) + 1) + 2ULL) * 4ULL;
        ext_hdrs_len += (8ULL - (ext_hdrs_len % 8ULL));
        break;
    case 0: // Hop by Hop
    case 43: // Routing
    case 60: // Destination Options for IPv6
    case 135: // Mobility Header
    case 139: // Host Identity Protocol
    case 140: // Shim6 Protocol
        next_header = *reinterpret_cast<const uint8_t *>(data);
        ext_hdrs_len = (1ULL + *(reinterpret_cast<const uint8_t *>(data) + 1)) * 8ULL;
        break;
    case IPPROTO_TCP:
    case IPPROTO_UDP:
    case 59:
        return 0; // No next header.
    case 44: // Fragment
             // [TODO IPv6 Parse and handle fragments]
    case 50: // Encapsulating Security Payload
    default:
        return -1; // Unknown ext header or L4 protocol. Ignore the packet.
    }

    return 1; // More ext headers.
}

struct ext_hdr_data {
    uint16_t ip_frag_off;
    uint16_t ip_hdr_len;
    uint8_t l4_protocol;
};

static inline void hdr_parse(iphdr *p_ip_h, ext_hdr_data &hdr_data, size_t buff_payload_size)
{
    NOT_IN_USE(buff_payload_size);
    hdr_data.ip_frag_off = ntohs(p_ip_h->frag_off);
    hdr_data.ip_hdr_len = (int)(p_ip_h->ihl) * 4;
    hdr_data.l4_protocol = p_ip_h->protocol;
}

static void hdr_parse(ip6_hdr *p_ip_h, ext_hdr_data &hdr_data, size_t buff_payload_size)
{
    hdr_data.ip_hdr_len = IPV6_HLEN;

    if (likely(p_ip_h->ip6_nxt == IPPROTO_TCP) || likely(p_ip_h->ip6_nxt == IPPROTO_UDP)) {
        hdr_data.ip_frag_off = 0U;
        hdr_data.l4_protocol = p_ip_h->ip6_nxt;
    } else { // Parse ext headers
        size_t ext_hdr_len = 0U;
        size_t norm_ext_hdr_len;
        uint8_t header_code = p_ip_h->ip6_nxt;
        const uint8_t *data = reinterpret_cast<const uint8_t *>(p_ip_h) + IPV6_HLEN;
        buff_payload_size -= IPV6_HLEN;

        while (likely(buff_payload_size >= 8U) &&
               likely(ipv6_ext_headers_parse(data, ext_hdr_len, header_code) == 1)) {
            norm_ext_hdr_len = std::min(buff_payload_size, ext_hdr_len);
            hdr_data.ip_hdr_len += norm_ext_hdr_len;
            data += norm_ext_hdr_len;
            buff_payload_size -= norm_ext_hdr_len;
        }

        hdr_data.l4_protocol = header_code; // Unknown protocol packet is dropped later.
        hdr_data.ip_frag_off = 0U;
    }
}

static inline uint16_t csum_hdr_len(iphdr *p_ip_h, const ext_hdr_data &ext_data)
{
    NOT_IN_USE(ext_data);
    return (p_ip_h->ihl << 2);
}

static inline uint16_t csum_hdr_len(ip6_hdr *p_ip_h, const ext_hdr_data &ext_data)
{
    NOT_IN_USE(p_ip_h);
    return (ext_data.ip_hdr_len - IPV6_HLEN);
}

template <typename KEY4T, typename KEY2T, typename HDR>
bool steering_handler<KEY4T, KEY2T, HDR>::rx_process_buffer_no_flow_id(
    mem_buf_desc_t *p_rx_wc_buf_desc, void *pv_fd_ready_array, HDR *p_ip_h)
{
    size_t ip_tot_len = hdr_get_tot_len(p_ip_h);
    size_t sz_data = p_rx_wc_buf_desc->sz_data - p_rx_wc_buf_desc->rx.n_transport_header_len;

    // Check that received buffer size is not smaller then the ip datagram total size
    if (unlikely(sz_data < ip_tot_len)) {
        ring_logwarn(
            "Rx packet dropped - buffer too small for received datagram (RxBuf:%zu IP:%zu)",
            sz_data, ip_tot_len);
        ring_loginfo("Rx packet info (buf->%p, bufsize=%zu), id=%s", p_rx_wc_buf_desc->p_buffer,
                     p_rx_wc_buf_desc->sz_data, hdr_get_id(p_ip_h).c_str());
        vlog_print_buffer(VLOG_INFO, "rx packet data: ", "\n",
                          (const char *)p_rx_wc_buf_desc->p_buffer,
                          std::min(112, (int)p_rx_wc_buf_desc->sz_data));
        return false;
    }

    // Read fragmentation parameters and extention headers for IPv6.
    ext_hdr_data hdr_data;
    hdr_parse(p_ip_h, hdr_data, sz_data);

    // Remove ethernet padding from the data size.
    p_rx_wc_buf_desc->sz_data -= (sz_data - ip_tot_len);

    uint16_t n_frag_offset = (hdr_data.ip_frag_off & IP_OFFMASK) * 8;

    ring_logfunc("Rx ip packet info: dst=%s, src=%s, packet_sz=%zu, offset=%" PRIu16
                 ", id=%s, proto=%s[%u" PRIu8 "]",
                 reinterpret_cast<const ip_address *>(hdr_get_daddr(p_ip_h))
                     ->to_str(hdr_get_family(p_ip_h))
                     .c_str(),
                 reinterpret_cast<const ip_address *>(hdr_get_saddr(p_ip_h))
                     ->to_str(hdr_get_family(p_ip_h))
                     .c_str(),
                 (sz_data > ip_tot_len ? ip_tot_len : sz_data), n_frag_offset,
                 hdr_get_id(p_ip_h).c_str(), iphdr_protocol_type_to_str(hdr_data.l4_protocol),
                 hdr_data.l4_protocol);

    // Check that the ip datagram has at least the udp header size for the first ip fragment
    // (besides the ip header)
    if (unlikely((n_frag_offset == 0) &&
                 (ip_tot_len < (hdr_data.ip_hdr_len + sizeof(struct udphdr))))) {
        ring_logwarn("Rx packet dropped - ip packet too small (%zu bytes) - udp header cut!",
                     ip_tot_len);
        return false;
    }

    // Handle fragmentation
    p_rx_wc_buf_desc->rx.n_frags = 1;

    // Currently we don't expect to receive fragments
    if (unlikely((hdr_data.ip_frag_off & IP_MF) || n_frag_offset)) {
        // Update fragments descriptor with datagram base address and length
        p_rx_wc_buf_desc->rx.frag.iov_base = (uint8_t *)p_ip_h + hdr_data.ip_hdr_len;
        p_rx_wc_buf_desc->rx.frag.iov_len = ip_tot_len - hdr_data.ip_hdr_len;

        // Add ip fragment packet to out fragment manager
        mem_buf_desc_t *new_buf = nullptr;
        int ret = -1;
        if (g_p_ip_frag_manager) {
            ret = g_p_ip_frag_manager->add_frag(p_ip_h, p_rx_wc_buf_desc, &new_buf);
        }
        if (ret < 0) { // Finished with error
            return false;
        }
        if (!new_buf) { // This is fragment
            return true;
        }

        // Re-calc all ip related values for new ip packet of head fragmentation list
        size_t transport_header_len = p_rx_wc_buf_desc->rx.n_transport_header_len;
        p_rx_wc_buf_desc = new_buf;
        p_ip_h = (HDR *)(p_rx_wc_buf_desc->p_buffer + transport_header_len);
        sz_data = p_rx_wc_buf_desc->sz_data - transport_header_len;
        hdr_parse(p_ip_h, hdr_data, sz_data);
        ip_tot_len = hdr_get_tot_len(p_ip_h);

        mem_buf_desc_t *tmp;
        for (tmp = p_rx_wc_buf_desc; tmp; tmp = tmp->p_next_desc) {
            ++p_rx_wc_buf_desc->rx.n_frags;
        }
    }

    if (p_rx_wc_buf_desc->rx.is_sw_csum_need && compute_ip_checksum(p_ip_h)) {
        return false; // false ip checksum
    }

    rfs *p_rfs = nullptr;
    size_t payload_len = ip_tot_len - hdr_data.ip_hdr_len;

    switch (hdr_data.l4_protocol) {
    case IPPROTO_UDP: {
        // Get the udp header pointer + udp payload size
        struct udphdr *p_udp_h = (struct udphdr *)((uint8_t *)p_ip_h + hdr_data.ip_hdr_len);

        // Update packet descriptor with datagram base address and length
        p_rx_wc_buf_desc->rx.frag.iov_base = (uint8_t *)p_udp_h + sizeof(struct udphdr);
        p_rx_wc_buf_desc->rx.frag.iov_len = payload_len - sizeof(struct udphdr);

        if (p_rx_wc_buf_desc->rx.is_sw_csum_need && p_udp_h->check &&
            compute_udp_checksum_rx(p_ip_h, p_udp_h, p_rx_wc_buf_desc)) {
            return false; // false udp checksum
        }

        size_t sz_payload = ntohs(p_udp_h->len) - sizeof(struct udphdr);
        ring_logfunc("Rx udp datagram info: src_port=%" PRIu16 ", dst_port=%" PRIu16
                     ", payload_sz=%zu, csum=%#x",
                     ntohs(p_udp_h->source), ntohs(p_udp_h->dest), sz_payload, p_udp_h->check);

        // Update the L3/L4 info
        p_rx_wc_buf_desc->rx.src.set_ip_port(hdr_get_family(p_ip_h), hdr_get_saddr(p_ip_h),
                                             p_udp_h->source);
        p_rx_wc_buf_desc->rx.dst.set_ip_port(hdr_get_family(p_ip_h), hdr_get_daddr(p_ip_h),
                                             p_udp_h->dest);
        p_rx_wc_buf_desc->rx.sz_payload = sz_payload;

        // Update the protocol info
        p_rx_wc_buf_desc->rx.udp.ifindex = m_ring.m_parent->get_if_index();

        // Find the relevant hash map and pass the packet to the rfs for dispatching
        if (!p_rx_wc_buf_desc->rx.dst.is_mc()) { // This is UDP UC packet
            auto itr =
                m_flow_udp_uc_map.find(KEY4T(p_rx_wc_buf_desc->rx.dst, p_rx_wc_buf_desc->rx.src));

            // If we didn't find a match for 5T, look for a match with 3T
            if (unlikely(itr == end(m_flow_udp_uc_map))) {
                auto itr3T =
                    m_flow_udp_uc_map.find(KEY4T(p_rx_wc_buf_desc->rx.dst, s_sock_addrany));
                if (likely(itr3T != end(m_flow_udp_uc_map))) {
                    p_rfs = itr3T->second;
                }
            } else {
                p_rfs = itr->second;
            }
        } else { // This is UDP MC packet
            auto itr = m_flow_udp_mc_map.find(KEY2T(p_rx_wc_buf_desc->rx.dst));
            if (likely(itr != end(m_flow_udp_mc_map))) {
                p_rfs = itr->second;
            }
        }
    } break;

    case IPPROTO_TCP: {
        // Get the tcp header pointer + tcp payload size
        struct tcphdr *p_tcp_h = (struct tcphdr *)((uint8_t *)p_ip_h + hdr_data.ip_hdr_len);

        if (p_rx_wc_buf_desc->rx.is_sw_csum_need &&
            compute_tcp_checksum(p_ip_h, (unsigned short *)p_tcp_h,
                                 csum_hdr_len(p_ip_h, hdr_data))) {
            return false; // false tcp checksum
        }

        size_t sz_payload = payload_len - p_tcp_h->doff * 4;
        ring_logfunc("Rx TCP segment info: src_port=%" PRIu16 ", dst_port=%" PRIu16
                     ", flags='%s%s%s%s%s%s' seq=%u, ack=%u, win=%" PRIu16 ", payload_sz=%zu",
                     ntohs(p_tcp_h->source), ntohs(p_tcp_h->dest), p_tcp_h->urg ? "U" : "",
                     p_tcp_h->ack ? "A" : "", p_tcp_h->psh ? "P" : "", p_tcp_h->rst ? "R" : "",
                     p_tcp_h->syn ? "S" : "", p_tcp_h->fin ? "F" : "", ntohl(p_tcp_h->seq),
                     ntohl(p_tcp_h->ack_seq), ntohs(p_tcp_h->window), sz_payload);

        // Update packet descriptor with datagram base address and length
        p_rx_wc_buf_desc->rx.frag.iov_base = (uint8_t *)p_tcp_h + sizeof(struct tcphdr);
        p_rx_wc_buf_desc->rx.frag.iov_len = payload_len - sizeof(struct tcphdr);

        // Update the L3/L4 info
        p_rx_wc_buf_desc->rx.src.set_ip_port(hdr_get_family(p_ip_h), hdr_get_saddr(p_ip_h),
                                             p_tcp_h->source);
        p_rx_wc_buf_desc->rx.dst.set_ip_port(hdr_get_family(p_ip_h), hdr_get_daddr(p_ip_h),
                                             p_tcp_h->dest);
        p_rx_wc_buf_desc->rx.sz_payload = sz_payload;

        // Update the protocol info
        p_rx_wc_buf_desc->rx.tcp.p_ip_h = p_ip_h;
        p_rx_wc_buf_desc->rx.tcp.p_tcp_h = p_tcp_h;

        // Find the relevant hash map and pass the packet to the rfs for dispatching
        auto itr = m_flow_tcp_map.find(KEY4T(p_rx_wc_buf_desc->rx.dst, p_rx_wc_buf_desc->rx.src));

        // If we didn't find a match for 5T, look for a match with 3T
        if (unlikely(itr == end(m_flow_tcp_map))) {
            auto itr3T = m_flow_tcp_map.find(KEY4T(p_rx_wc_buf_desc->rx.dst, s_sock_addrany));
            if (likely(itr3T != end(m_flow_tcp_map))) {
                p_rfs = itr3T->second;
            }
        } else {
            p_rfs = itr->second;
        }
    } break;

    default:
        ring_logwarn("Rx packet dropped - undefined protocol = %" PRIu8, hdr_data.l4_protocol);
        return false;
    }

    if (unlikely(!p_rfs)) {
        ring_logdbg("Rx packet dropped - rfs object not found: dst=%s, src=%s, proto=%s[%" PRIu8
                    "]",
                    p_rx_wc_buf_desc->rx.dst.to_str_ip_port().c_str(),
                    p_rx_wc_buf_desc->rx.src.to_str_ip_port().c_str(),
                    iphdr_protocol_type_to_str(hdr_data.l4_protocol), hdr_data.l4_protocol);

        return false;
    }

    return p_rfs->rx_dispatch_packet(p_rx_wc_buf_desc, pv_fd_ready_array);
}

template <typename T> void clear_rfs_map(T &rfs_map)
{
    auto itr = rfs_map.begin();
    while (itr != end(rfs_map)) {
        if (itr->second) {
            delete itr->second;
        }
        itr = rfs_map.erase(itr);
    }
}

template <typename KEY4T, typename KEY2T, typename HDR>
void steering_handler<KEY4T, KEY2T, HDR>::flow_del_all_rfs()
{
    clear_rfs_map(m_flow_tcp_map);
    clear_rfs_map(m_flow_udp_uc_map);
    clear_rfs_map(m_flow_udp_mc_map);
}

void ring_simple::flow_del_all_rfs()
{
    m_steering_ipv4.flow_del_all_rfs();
    m_steering_ipv6.flow_del_all_rfs();
}

bool ring_simple::request_more_tx_buffers(pbuf_type type, uint32_t count, uint32_t lkey)
{
    bool res;

    ring_logfuncall("Allocating additional %d buffers for internal use", count);

    if (type == PBUF_ZEROCOPY) {
        res = g_buffer_pool_zc->get_buffers_thread_safe(m_zc_pool, this, count, lkey);
    } else {
        res = g_buffer_pool_tx->get_buffers_thread_safe(m_tx_pool, this, count, lkey);
    }
    if (!res) {
        ring_logfunc("Out of mem_buf_desc from TX free pool for internal object pool");
        return false;
    }

    return true;
}

int ring_simple::request_notification(cq_type_t cq_type, uint64_t poll_sn)
{
    int ret = 1;
    if (likely(CQT_RX == cq_type)) {
        m_lock_ring_rx.lock();
        ret = m_p_cq_mgr_rx->request_notification(poll_sn);
        ++m_p_ring_stat->n_rx_interrupt_requests;
        m_lock_ring_rx.unlock();
    } else {
        m_lock_ring_tx.lock();
        ret = m_p_cq_mgr_tx->request_notification(poll_sn);
        m_lock_ring_tx.unlock();
    }

    return ret;
}

bool ring_simple::poll_and_process_element_rx(uint64_t *p_cq_poll_sn,
                                              void *pv_fd_ready_array /*NULL*/)
{
    bool ret = false; // CQ was not drained.
    if (!m_lock_ring_rx.trylock()) {
        ret = m_p_cq_mgr_rx->poll_and_process_element_rx(p_cq_poll_sn, pv_fd_ready_array);
        m_lock_ring_rx.unlock();
    }
    return ret;
}

int ring_simple::poll_and_process_element_tx(uint64_t *p_cq_poll_sn)
{
    int ret = 0;
    RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_tx,
                                     m_p_cq_mgr_tx->poll_and_process_element_tx(p_cq_poll_sn));
    return ret;
}

void ring_simple::wait_for_notification_and_process_element(uint64_t *p_cq_poll_sn,
                                                            void *pv_fd_ready_array /*NULL*/)
{
    m_lock_ring_rx.lock();
    m_p_cq_mgr_rx->wait_for_notification_and_process_element(p_cq_poll_sn, pv_fd_ready_array);
    ++m_p_ring_stat->n_rx_interrupt_received;
    m_lock_ring_rx.unlock();
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

    p_mem_buf_desc->lwip_pbuf.ref -= std::min<unsigned>(p_mem_buf_desc->lwip_pbuf.ref, ref - 1);
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
    mem_buf_desc_t *buff_list = nullptr;
    uint64_t poll_sn = 0;

    ring_logfuncall("n_num_mem_bufs=%d", n_num_mem_bufs);

    m_lock_ring_tx.lock();
    buff_list = get_tx_buffers(type, n_num_mem_bufs);
    while (!buff_list) {

        // Try to poll once in the hope that we get a few freed tx mem_buf_desc
        ret = m_p_cq_mgr_tx->poll_and_process_element_tx(&poll_sn);
        if (ret < 0) {
            ring_logdbg("failed polling on cq_mgr_tx (hqtx=%p, cq_mgr_tx=%p) (ret=%d %m)", m_hqtx,
                        m_p_cq_mgr_tx, ret);
            /* coverity[double_unlock] TODO: RM#1049980 */
            m_lock_ring_tx.unlock();
            return nullptr;
        } else if (ret > 0) {
            ring_logfunc("polling succeeded on cq_mgr_tx (%d wce)", ret);
            buff_list = get_tx_buffers(type, n_num_mem_bufs);
        } else if (b_block) { // (ret == 0)
            // Arm & Block on tx cq_mgr_tx notification channel
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
                    ring_logdbg("failed arming cq_mgr_tx (hqtx=%p, cq_mgr_tx=%p) (errno=%d %m)",
                                m_hqtx, m_p_cq_mgr_tx, errno);
                } else if (ret == 0) {

                    // prepare to block
                    // CQ is armed, block on the CQ's Tx event channel (fd)
                    struct pollfd poll_fd = {/*.fd=*/0, /*.events=*/POLLIN, /*.revents=*/0};
                    poll_fd.fd = get_tx_comp_event_channel()->fd;

                    // Now it is time to release the ring lock (for restart events to be handled
                    // while this thread block on CQ channel)
                    /* coverity[double_unlock] coverity[unlock] TODO: RM#1049980 */
                    m_lock_ring_tx.unlock();

                    ret = SYSCALL(poll, &poll_fd, 1, 100);
                    if (ret == 0) {
                        m_lock_ring_tx_buf_wait.unlock();
                        /* coverity[double_lock] TODO: RM#1049980 */
                        m_lock_ring_tx.lock();
                        buff_list = get_tx_buffers(type, n_num_mem_bufs);
                        continue;
                    } else if (ret < 0) {
                        ring_logdbg("failed blocking on cq_mgr_tx (errno=%d %m)", errno);
                        m_lock_ring_tx_buf_wait.unlock();
                        return nullptr;
                    }
                    /* coverity[double_lock] TODO: RM#1049980 */
                    m_lock_ring_tx.lock();

                    // Find the correct cq_mgr_tx from the CQ event,
                    // It might not be the active_cq object since we have a single TX CQ comp
                    // channel for all cq_mgr_tx's
                    cq_mgr_tx *p_cq_mgr_tx =
                        cq_mgr_tx::get_cq_mgr_from_cq_event(get_tx_comp_event_channel());
                    if (p_cq_mgr_tx) {

                        // Allow additional CQ arming now
                        p_cq_mgr_tx->reset_notification_armed();

                        // Perform a non blocking event read, clear the fd channel
                        ret = p_cq_mgr_tx->poll_and_process_element_tx(&poll_sn);
                        if (ret < 0) {
                            ring_logdbg("failed handling cq_mgr_tx channel (hqtx=%p "
                                        "cq_mgr_tx=%p) (errno=%d %m)",
                                        m_hqtx, m_p_cq_mgr_tx, errno);
                            /* coverity[double_unlock] TODO: RM#1049980 */
                            m_lock_ring_tx.unlock();
                            m_lock_ring_tx_buf_wait.unlock();
                            return nullptr;
                        }
                        ring_logfunc("polling/blocking succeeded on cq_mgr_tx (we got %d wce)",
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
            return nullptr;
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
    p_mem_buf_desc->p_next_desc = nullptr;
    reclaim_recv_buffers(p_mem_buf_desc);
}

/* note that this function is inline, so keep it above the functions using it */
inline int ring_simple::send_buffer(xlio_ibv_send_wr *p_send_wqe, xlio_wr_tx_packet_attr attr,
                                    xlio_tis *tis)
{
    int ret = 0;
    unsigned credits = m_hqtx->credits_calculate(p_send_wqe);

    if (likely(m_hqtx->credits_get(credits)) ||
        (!is_set(attr, XLIO_TX_SKIP_POLL) &&
         is_available_qp_wr(is_set(attr, XLIO_TX_PACKET_BLOCK), credits))) {
        m_hqtx->send_wqe(p_send_wqe, attr, tis, credits);
    } else {
        ring_logdbg("Silent packet drop, SQ is full!");
        ret = -1;
        reinterpret_cast<mem_buf_desc_t *>(p_send_wqe->wr_id)->p_next_desc = nullptr;
        ++m_p_ring_stat->n_tx_dropped_wqes;
    }
    return ret;
}

bool ring_simple::get_hw_dummy_send_support(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe)
{
    NOT_IN_USE(id);
    NOT_IN_USE(p_send_wqe);

    return m_hqtx->get_hw_dummy_send_support();
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
    int ret = send_buffer(p_send_wqe, attr, nullptr);
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
            ring_logdbg("failed polling on cq_mgr_tx (hqtx=%p, cq_mgr_tx=%p) (ret=%d %m)", m_hqtx,
                        m_p_cq_mgr_tx, ret);
            /* coverity[missing_unlock] */
            return false;
        }
        granted = m_hqtx->credits_get(credits);
        if (granted) {
            break;
        }

        if (b_block) {
            // Arm & Block on cq_mgr_tx notification channel until we get space in SQ

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
                ring_logdbg("failed arming cq_mgr_tx (hqtx=%p, cq_mgr_tx=%p) (errno=%d %m)", m_hqtx,
                            m_p_cq_mgr_tx, errno);
            } else if (ret == 0) {
                // prepare to block
                // CQ is armed, block on the CQ's Tx event channel (fd)
                struct pollfd poll_fd = {/*.fd=*/0, /*.events=*/POLLIN, /*.revents=*/0};
                poll_fd.fd = get_tx_comp_event_channel()->fd;

                // Now it is time to release the ring lock (for restart events to be handled
                // while this thread block on CQ channel)
                /* coverity[double_unlock] TODO: RM#1049980 */
                m_lock_ring_tx.unlock();

                ret = SYSCALL(poll, &poll_fd, 1, -1);
                if (ret <= 0) {
                    ring_logdbg("failed blocking on cq_mgr_tx (errno=%d %m)", errno);
                    m_lock_ring_tx_buf_wait.unlock();
                    /* coverity[double_lock] TODO: RM#1049980 */
                    m_lock_ring_tx.lock();
                    /* coverity[missing_unlock] */
                    return false;
                }
                /* coverity[double_lock] TODO: RM#1049980 */
                m_lock_ring_tx.lock();

                // Find the correct cq_mgr_tx from the CQ event,
                // It might not be the active_cq object since we have a single TX CQ comp
                // channel for all cq_mgr_tx's
                cq_mgr_tx *p_cq_mgr_tx =
                    cq_mgr_tx::get_cq_mgr_from_cq_event(get_tx_comp_event_channel());
                if (p_cq_mgr_tx) {

                    // Allow additional CQ arming now
                    p_cq_mgr_tx->reset_notification_armed();

                    // Perform a non blocking event read, clear the fd channel
                    ret = p_cq_mgr_tx->poll_and_process_element_tx(&poll_sn);
                    if (ret < 0) {
                        ring_logdbg("failed handling cq_mgr_tx channel (hqtx=%p "
                                    "cq_mgr_tx=%p) (errno=%d %m)",
                                    m_hqtx, m_p_cq_mgr_tx, errno);
                        /* coverity[double_unlock] TODO: RM#1049980 */
                        m_lock_ring_tx.unlock();
                        m_lock_ring_tx_buf_wait.unlock();
                        /* coverity[double_lock] TODO: RM#1049980 */
                        m_lock_ring_tx.lock();
                        return false;
                    }
                    ring_logfunc("polling/blocking succeeded on cq_mgr_tx (we got %d wce)", ret);
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
    m_p_ring_stat->n_tx_num_bufs = m_tx_num_bufs;
}

void ring_simple::inc_cq_moderation_stats()
{
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
             * TODO Unify request_more_tx_buffers implementation
             * keeps number of buffers instead of reinventing it in
             * ring_simple.
             */
            if (type == PBUF_ZEROCOPY) {
                m_zc_num_bufs += count;
                m_p_ring_stat->n_zc_num_bufs = m_zc_num_bufs;
            } else {
                m_tx_num_bufs += count;
                m_p_ring_stat->n_tx_num_bufs = m_tx_num_bufs;
            }
        }

        if (unlikely(pool.size() < n_num_mem_bufs)) {
            return nullptr;
        }
    }

    head = pool.get_and_pop_back();
    head->lwip_pbuf.ref = 1;
    assert(head->lwip_pbuf.type == type);
    head->lwip_pbuf.type = type;
    n_num_mem_bufs--;

    mem_buf_desc_t *next = head;
    while (n_num_mem_bufs) {
        next->p_next_desc = pool.get_and_pop_back();
        next = next->p_next_desc;
        next->lwip_pbuf.ref = 1;
        assert(head->lwip_pbuf.type == type);
        next->lwip_pbuf.type = type;
        n_num_mem_bufs--;
    }
    next->p_next_desc = nullptr;

    return head;
}

void ring_simple::return_to_global_pool()
{
    if (unlikely(m_tx_pool.size() > (m_tx_num_bufs / 2) &&
                 m_tx_num_bufs >= RING_TX_BUFS_COMPENSATE * 2)) {
        int return_bufs = m_tx_pool.size() / 2;
        m_tx_num_bufs -= return_bufs;
        m_p_ring_stat->n_tx_num_bufs = m_tx_num_bufs;
        g_buffer_pool_tx->put_buffers_thread_safe(&m_tx_pool, return_bufs);
    }
    if (unlikely(m_zc_pool.size() > (m_zc_num_bufs / 2) &&
                 m_zc_num_bufs >= RING_TX_BUFS_COMPENSATE * 2)) {
        int return_bufs = m_zc_pool.size() / 2;
        m_zc_num_bufs -= return_bufs;
        m_p_ring_stat->n_zc_num_bufs = m_zc_num_bufs;
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
        m_hqtx->dm_release_data(buff);
    }

    // Potential race, ref is protected here by ring_tx lock, and in dst_entry_tcp &
    // sockinfo_tcp by tcp lock
    if (likely(buff->lwip_pbuf.ref)) {
        buff->lwip_pbuf.ref--;
    } else {
        ring_logerr("ref count of %p is already zero, double free??", buff);
    }

    if (buff->lwip_pbuf.ref == 0) {
        descq_t &pool = buff->lwip_pbuf.type == PBUF_ZEROCOPY ? m_zc_pool : m_tx_pool;
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

    m_p_ring_stat->n_rx_cq_moderation_period = period;
    m_p_ring_stat->n_rx_cq_moderation_count = count;

    // todo all cqs or just active? what about HA?
    priv_ibv_modify_cq_moderation(m_p_cq_mgr_rx->get_ibv_cq_hndl(), period, count);
}

uint64_t ring_simple::get_rx_cq_out_of_buffer_drop()
{
    return m_p_cq_mgr_rx->get_n_rx_hw_pkt_drops();
}

void ring_simple::adapt_cq_moderation()
{
    if (m_lock_ring_rx.trylock()) {
        ++m_cq_moderation_info.missed_rounds;
        return; // todo try again sooner?
    }

    uint32_t missed_rounds = m_cq_moderation_info.missed_rounds;

    // todo collect bytes and packets from all rings ??
    int64_t interval_packets = m_cq_moderation_info.packets - m_cq_moderation_info.prev_packets;

    m_cq_moderation_info.prev_packets = m_cq_moderation_info.packets;
    m_cq_moderation_info.missed_rounds = 0;

    BULLSEYE_EXCLUDE_BLOCK_START
    if (interval_packets < 0) {
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

    uint32_t avg_packet_rate =
        (interval_packets * 1000) / (safe_mce_sys().cq_aim_interval_msec * (1 + missed_rounds));

    uint32_t ir_rate = safe_mce_sys().cq_aim_interrupts_rate_per_sec;

    uint32_t count = std::min(avg_packet_rate / ir_rate, safe_mce_sys().cq_aim_max_count);
    uint32_t period = std::min<uint32_t>(
        safe_mce_sys().cq_aim_max_period_usec,
        ((1000000UL / ir_rate) - (1000000UL / std::max(avg_packet_rate, ir_rate))));

    modify_cq_moderation(period, count);

    m_lock_ring_rx.unlock();
}

void ring_simple::start_active_queue_tx()
{
    m_lock_ring_tx.lock();
    if (!m_up_tx) {
        /* TODO: consider avoid using sleep */
        /* coverity[sleep] */
        m_hqtx->up();
        m_up_tx = true;
    }
    m_lock_ring_tx.unlock();
}

void ring_simple::start_active_queue_rx()
{
    m_lock_ring_rx.lock();
    if (!m_up_rx) {
        /* TODO: consider avoid using sleep */
        /* coverity[sleep] */
        m_hqrx->up();
        m_up_rx = true;
    }
    m_lock_ring_rx.unlock();
}

void ring_simple::stop_active_queue_tx()
{
    m_lock_ring_tx.lock();
    if (m_up_tx) {
        m_up_tx = false;
        /* TODO: consider avoid using sleep */
        /* coverity[sleep] */
        m_hqtx->down();
    }
    m_lock_ring_tx.unlock();
}
void ring_simple::stop_active_queue_rx()
{
    m_lock_ring_rx.lock();
    if (m_up_rx) {
        m_up_rx = false;
        /* TODO: consider avoid using sleep */
        /* coverity[sleep] */
        m_hqrx->down();
    }
    m_lock_ring_rx.unlock();
}

bool ring_simple::is_up()
{
    return m_up_tx && m_up_rx;
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

    uint32_t rl_changes = m_hqtx->is_ratelimit_change(rate_limit);

    if (m_up_tx && rl_changes) {
        return m_hqtx->modify_qp_ratelimit(rate_limit, rl_changes);
    }

    return 0;
}

uint32_t ring_simple::get_tx_user_lkey(void *addr, size_t length)
{
    uint32_t lkey;

    /*
     * Current implementation supports a ring registration cache where addr is the key.
     *
     * The mode is used for send zerocopy.
     *
     * TODO The mode doesnn't support memory deregistration.
     */
    auto iter = m_user_lkey_map.find(addr);
    if (iter != m_user_lkey_map.end()) {
        lkey = iter->second;
    } else {
        lkey = m_p_ib_ctx->user_mem_reg(addr, length, XLIO_IBV_ACCESS_LOCAL_WRITE);
        if (lkey == LKEY_ERROR) {
            ring_logerr("Can't register user memory addr %p len %lx", addr, length);
        } else {
            m_user_lkey_map[addr] = lkey;
        }
    }
    return lkey;
}

uint32_t ring_simple::get_max_inline_data()
{
    return m_hqtx->get_max_inline_data();
}

uint32_t ring_simple::get_max_send_sge(void)
{
    return m_hqtx->get_max_send_sge();
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
