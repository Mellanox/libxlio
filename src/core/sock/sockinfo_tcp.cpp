/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-3-Clause
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

#include <functional>
#include <numeric>
#include <thread>
#include <stdio.h>
#include <sys/time.h>
#include <netinet/tcp.h>
#include "util/if.h"

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "utils/lock_wrapper.h"
#include "utils/rdtsc.h"
#include "util/libxlio.h"
#include "util/instrumentation.h"
#include "util/list.h"
#include "util/agent.h"
#include "event/event_handler_manager.h"
#include "event/event_handler_manager_local.h"
#include "event/poll_group.h"
#include "proto/route_table_mgr.h"
#include "proto/xlio_lwip.h"
#include "proto/dst_entry_tcp.h"
#include "iomux/io_mux_call.h"
#include "sock-redirect.h"
#include "fd_collection.h"
#include "sockinfo_tcp.h"
#include "bind_no_port.h"
#include "xlio.h"
#include "core/dev/xlio_thread_manager.h"

#define UNLOCK_RET(_ret)                                                                           \
    unlock_tcp_con();                                                                              \
    return _ret;
// debugging macros
#define MODULE_NAME "si_tcp"

#undef MODULE_HDR_INFO
#define MODULE_HDR_INFO MODULE_NAME "[fd=%d]:%d:%s() "

#undef __INFO__
#define __INFO__ m_fd

#define si_tcp_logpanic   __log_info_panic
#define si_tcp_logerr     __log_info_err
#define si_tcp_logwarn    __log_info_warn
#define si_tcp_loginfo    __log_info_info
#define si_tcp_logdbg     __log_info_dbg
#define si_tcp_logfunc    __log_info_func
#define si_tcp_logfuncall __log_info_funcall

extern global_stats_t g_global_stat_static;

tcp_timers_collection *g_tcp_timers_collection = nullptr;
thread_local thread_local_tcp_timers g_thread_local_tcp_timers;
bind_no_port *g_bind_no_port = nullptr;
static thread_local lock_dummy t_lock_dummy_socket;

/*
 * The following socket options are inherited by a connected TCP socket from the listening socket:
 * SO_DEBUG, SO_DONTROUTE, SO_KEEPALIVE, SO_LINGER, SO_OOBINLINE, SO_RCVBUF, SO_RCVLOWAT, SO_SNDBUF,
 * SO_SNDLOWAT, TCP_MAXSEG, TCP_NODELAY.
 */
static bool is_inherited_option(int __level, int __optname)
{
    bool ret = false;
    if (__level == SOL_SOCKET) {
        switch (__optname) {
        case SO_DEBUG:
        case SO_DONTROUTE:
        case SO_KEEPALIVE:
        case SO_LINGER:
        case SO_OOBINLINE:
        case SO_RCVBUF:
        case SO_RCVLOWAT:
        case SO_SNDBUF:
        case SO_SNDLOWAT:
        case SO_XLIO_RING_ALLOC_LOGIC:
            ret = true;
        }
    } else if (__level == IPPROTO_TCP) {
        switch (__optname) {
        case TCP_MAXSEG:
        case TCP_NODELAY:
        case TCP_KEEPIDLE:
#if LWIP_TCP_KEEPALIVE
        case TCP_KEEPINTVL:
        case TCP_KEEPCNT:
#endif
        case TCP_USER_TIMEOUT:
            ret = true;
        }
    } else if (__level == IPPROTO_IP) {
        switch (__optname) {
        case IP_TTL:
            ret = true;
        }
    } else if (__level == IPPROTO_IPV6) {
        switch (__optname) {
        case IPV6_V6ONLY:
            ret = true;
        }
    }

    return ret;
}

event_handler_manager *sockinfo_tcp::get_event_mgr()
{
    if (is_xlio_socket()) {
        return m_p_group->get_event_handler();
    } else if (safe_mce_sys().tcp_ctl_thread ==
               option_tcp_ctl_thread::CTL_THREAD_DELEGATE_TCP_TIMERS) {
        return &g_event_handler_manager_local;
    } else {
        return g_p_event_handler_manager;
    }
}

tcp_timers_collection *sockinfo_tcp::get_tcp_timer_collection()
{
    if (is_xlio_socket()) {
        return m_p_group->get_tcp_timers();
    } else if (safe_mce_sys().tcp_ctl_thread ==
               option_tcp_ctl_thread::CTL_THREAD_DELEGATE_TCP_TIMERS) {
        return &g_thread_local_tcp_timers;
    } else {
        return g_tcp_timers_collection;
    }
}

static lock_base *get_new_tcp_lock()
{
    return (
        safe_mce_sys().tcp_ctl_thread != option_tcp_ctl_thread::CTL_THREAD_DELEGATE_TCP_TIMERS
            ? static_cast<lock_base *>(multilock::create_new_lock(MULTILOCK_RECURSIVE, "tcp_con"))
            : static_cast<lock_base *>(&t_lock_dummy_socket));
}

inline void sockinfo_tcp::lwip_pbuf_init_custom(mem_buf_desc_t *p_desc)
{
    if (!p_desc->lwip_pbuf.gro) {
        p_desc->lwip_pbuf.len = p_desc->lwip_pbuf.tot_len =
            (p_desc->sz_data - p_desc->rx.n_transport_header_len);
        p_desc->lwip_pbuf.ref = 1;
        p_desc->lwip_pbuf.next = nullptr;
        p_desc->lwip_pbuf.payload = (u8_t *)p_desc->p_buffer + p_desc->rx.n_transport_header_len;
    }
    p_desc->lwip_pbuf.gro = 0;
}

/* change default rx_wait impl to flow based one */
inline int sockinfo_tcp::rx_wait(int &poll_count, bool blocking)
{
    int ret_val = 0;
    unlock_tcp_con();
    ret_val = rx_wait_helper(poll_count, blocking);
    lock_tcp_con();
    return ret_val;
}

inline int sockinfo_tcp::rx_wait_lockless(int &poll_count, bool blocking)
{
    return rx_wait_helper(poll_count, blocking);
}

inline void sockinfo_tcp::return_pending_rx_buffs()
{
    // force reuse of buffers especially for avoiding deadlock in case all buffers were taken and we
    // can NOT get new FIN packets that will release buffers
    if (m_sysvar_buffer_batching_mode == BUFFER_BATCHING_NO_RECLAIM ||
        !m_rx_reuse_buff.n_buff_num) {
        return;
    }

    if (m_rx_reuse_buf_pending) {
        if (m_p_rx_ring && m_p_rx_ring->reclaim_recv_buffers(&m_rx_reuse_buff.rx_reuse)) {
        } else {
            g_buffer_pool_rx_ptr->put_buffers_after_deref_thread_safe(&m_rx_reuse_buff.rx_reuse);
        }
        m_rx_reuse_buff.n_buff_num = 0;
        set_rx_reuse_pending(false);
    } else {
        set_rx_reuse_pending(true);
    }
}

inline void sockinfo_tcp::return_pending_tx_buffs()
{
    if (m_sysvar_buffer_batching_mode == BUFFER_BATCHING_NO_RECLAIM || !m_p_connected_dst_entry) {
        return;
    }

    m_p_connected_dst_entry->return_buffers_pool();
}

// todo inline void sockinfo_tcp::return_pending_tcp_segs()

inline void sockinfo_tcp::reuse_buffer(mem_buf_desc_t *buff)
{
    /* Special case when ZC buffers are used in RX path. */
    if (buff->lwip_pbuf.type == PBUF_ZEROCOPY) {
        dst_entry_tcp *p_dst = (dst_entry_tcp *)(m_p_connected_dst_entry);
        mem_buf_desc_t *underlying = reinterpret_cast<mem_buf_desc_t *>(buff->lwip_pbuf.desc.mdesc);

        buff->lwip_pbuf.desc.mdesc = nullptr;
        if (likely(p_dst)) {
            p_dst->put_zc_buffer(buff);
        } else {
            g_buffer_pool_zc->put_buffers_thread_safe(buff);
        }

        if (underlying->lwip_pbuf.ref > 1) {
            --underlying->lwip_pbuf.ref;
            return;
        }
        /* Continue and release the underlying buffer. */
        buff = underlying;

        buff->lwip_pbuf.ref = 1;
        buff->lwip_pbuf.next = nullptr;
        buff->p_next_desc = nullptr;
    }

    if (safe_mce_sys().buffer_batching_mode == BUFFER_BATCHING_NONE) {
        if (!m_p_rx_ring || !m_p_rx_ring->reclaim_recv_buffers(buff)) {
            g_buffer_pool_rx_ptr->put_buffer_after_deref_thread_safe(buff);
        }
        return;
    }

    set_rx_reuse_pending(false);
    if (likely(m_p_rx_ring)) {
        m_rx_reuse_buff.n_buff_num += buff->rx.n_frags;
        m_rx_reuse_buff.rx_reuse.push_back(buff);
        if (m_rx_reuse_buff.n_buff_num < m_rx_num_buffs_reuse) {
            return;
        }
        if (m_rx_reuse_buff.n_buff_num >= 2 * m_rx_num_buffs_reuse) {
            if (m_p_rx_ring->reclaim_recv_buffers(&m_rx_reuse_buff.rx_reuse)) {
                m_rx_reuse_buff.n_buff_num = 0;
            } else {
                g_buffer_pool_rx_ptr->put_buffers_after_deref_thread_safe(
                    &m_rx_reuse_buff.rx_reuse);
                m_rx_reuse_buff.n_buff_num = 0;
            }
            m_rx_reuse_buf_postponed = false;
        } else {
            m_rx_reuse_buf_postponed = true;
        }
    } else {
        sockinfo::reuse_buffer(buff);
    }
}

static inline bool use_socket_ring_locks()
{
    return (safe_mce_sys().tcp_ctl_thread != option_tcp_ctl_thread::CTL_THREAD_DELEGATE_TCP_TIMERS);
}

sockinfo_tcp::sockinfo_tcp(int fd, int domain)
    : sockinfo(fd, domain, use_socket_ring_locks())
    , m_tcp_con_lock_app(get_new_tcp_lock())
    , m_tcp_con_lock(get_new_tcp_lock())
    , m_sysvar_buffer_batching_mode(safe_mce_sys().buffer_batching_mode)
    , m_sysvar_tx_segs_batch_tcp(safe_mce_sys().tx_segs_batch_tcp)
    , m_tcp_seg_list(nullptr)
    , m_sysvar_rx_poll_on_tx_tcp(safe_mce_sys().rx_poll_on_tx_tcp)
    , m_user_huge_page_mask(~((uint64_t)safe_mce_sys().user_huge_page_size - 1))
{
    si_tcp_logfuncall("");

    m_ops = m_ops_tcp = new sockinfo_tcp_ops(this);
    assert(m_ops != NULL); /* XXX */

    m_b_incoming = false;
    m_b_attached = false; // For socket reuse

    m_accepted_conns.set_id("sockinfo_tcp (%p), fd = %d : m_accepted_conns", this, m_fd);
    m_rx_pkt_ready_list.set_id("sockinfo_tcp (%p), fd = %d : m_rx_pkt_ready_list", this, m_fd);
    m_rx_cb_dropped_list.set_id("sockinfo_tcp (%p), fd = %d : m_rx_cb_dropped_list", this, m_fd);
    m_rx_ctl_packets_list.set_id("sockinfo_tcp (%p), fd = %d : m_rx_ctl_packets_list", this, m_fd);
    m_rx_ctl_reuse_list.set_id("sockinfo_tcp (%p), fd = %d : m_rx_ctl_reuse_list", this, m_fd);

    m_last_syn_tsc = 0;

    m_linger.l_linger = 0;
    m_linger.l_onoff = 0;

    m_protocol = PROTO_TCP;
    IF_STATS(m_p_socket_stats->socket_type = SOCK_STREAM);

    memset(&m_rx_timestamps, 0, sizeof(m_rx_timestamps));

    m_sock_state = TCP_SOCK_INITED;
    m_conn_state = TCP_CONN_INIT;
    m_conn_timeout = CONNECT_DEFAULT_TIMEOUT_MS;
    setPassthrough(false); // by default we try to accelerate
    si_tcp_logdbg("tcp socket created, lock_name=%s", m_tcp_con_lock.to_str());

    tcp_pcb_init(&m_pcb, TCP_PRIO_NORMAL, this);

    const tcp_keepalive_info keepalive_info = safe_mce_sys().sysctl_reader.get_tcp_keepalive_info();
    tcp_set_keepalive(&m_pcb, static_cast<u32_t>(1000U * keepalive_info.idle_secs),
                      static_cast<u32_t>(1000U * keepalive_info.interval_secs),
                      static_cast<u32_t>(keepalive_info.num_probes));

    si_tcp_logdbg("new pcb %p pcb state %d", &m_pcb, get_tcp_state(&m_pcb));
    tcp_arg(&m_pcb, this);
    tcp_ip_output(&m_pcb, sockinfo_tcp::ip_output);
    if (safe_mce_sys().enable_socketxtreme) {
        tcp_recv(&m_pcb, sockinfo_tcp::rx_lwip_cb_socketxtreme);
    } else {
        tcp_recv(&m_pcb, sockinfo_tcp::rx_lwip_cb);
    }
    tcp_err(&m_pcb, sockinfo_tcp::err_lwip_cb);
    tcp_sent(&m_pcb, sockinfo_tcp::ack_recvd_lwip_cb);

    m_parent = nullptr;
    m_iomux_ready_fd_array = nullptr;

    /* RCVBUF accounting */
    m_rcvbuff_max = safe_mce_sys().sysctl_reader.get_tcp_rmem()->default_value;

    m_rcvbuff_current = 0;
    m_rcvbuff_non_tcp_recved = 0;
    m_xlio_thr = false;

    m_ready_conn_cnt = 0;
    m_backlog = INT_MAX;
    report_connected = false;

    m_error_status = 0;

    m_tcp_seg_count = 0;
    m_tcp_seg_in_use = 0;
    m_tx_consecutive_eagain_count = 0;

    // Disable Nagle algorithm if XLIO_TCP_NODELAY flag was set.
    if (safe_mce_sys().tcp_nodelay) {
        try {
            int tcp_nodelay = 1;
            setsockopt(IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay, sizeof(tcp_nodelay));
        } catch (xlio_error &) {
            // We should not be here
        }
    }

    // Enable Quickack if XLIO_TCP_QUICKACK flag was set.
    if (safe_mce_sys().tcp_quickack) {
        try {
            int tcp_quickack = 1;
            setsockopt(IPPROTO_TCP, TCP_QUICKACK, &tcp_quickack, sizeof(tcp_quickack));
        } catch (xlio_error &) {
            // We should not be here
        }
    }

    if (g_p_agent) {
        g_p_agent->register_cb((agent_cb_t)&sockinfo_tcp::put_agent_msg, (void *)this);
    }
    si_tcp_logdbg("TCP PCB FLAGS: 0x%x", m_pcb.flags);
    si_tcp_logfunc("done");
}

void sockinfo_tcp::rx_add_ring_cb(ring *p_ring)
{
    if (m_p_group) {
        m_p_group->add_ring(p_ring, &m_ring_alloc_log_rx);
    }
    sockinfo::rx_add_ring_cb(p_ring);
}

void sockinfo_tcp::add_epoll_ctx_cb()
{
    if (m_p_group) {
        m_p_group->add_epoll_ctx(m_econtext, *this);
    }
}

void sockinfo_tcp::remove_epoll_ctx_cb(epfd_info *econtext)
{
    if (m_p_group) {
        m_p_group->remove_epoll_ctx(econtext);
        m_p_thread_ready_socket_list = nullptr;
    }
}

void sockinfo_tcp::set_xlio_socket_thread(poll_group *group)
{
    std::lock_guard<decltype(m_tcp_con_lock)> lock(m_tcp_con_lock);

    m_p_group = group;

    bool current_locks = m_ring_alloc_log_rx.get_use_locks();

    m_ring_alloc_log_rx.set_ring_alloc_logic(RING_LOGIC_PER_USER_ID);
    m_ring_alloc_log_rx.set_user_id_key(reinterpret_cast<uint64_t>(m_p_group));
    m_ring_alloc_log_rx.set_use_locks(current_locks ||
                                      (m_p_group->get_flags() & XLIO_GROUP_FLAG_SAFE));
    m_ring_alloc_logic_rx = ring_allocation_logic_rx(get_fd(), m_ring_alloc_log_rx);

    m_ring_alloc_log_tx.set_ring_alloc_logic(RING_LOGIC_PER_USER_ID);
    m_ring_alloc_log_tx.set_user_id_key(reinterpret_cast<uint64_t>(m_p_group));
    m_ring_alloc_log_tx.set_use_locks(current_locks ||
                                      (m_p_group->get_flags() & XLIO_GROUP_FLAG_SAFE));

    if (!current_locks && (m_p_group->get_flags() & XLIO_GROUP_FLAG_SAFE)) {
        m_tcp_con_lock = multilock::create_new_lock(MULTILOCK_RECURSIVE, "tcp_con");
    }

    tcp_recv(&m_pcb, sockinfo_tcp::rx_lwip_cb_thread_socket);
    tcp_err(&m_pcb, sockinfo_tcp::err_lwip_cb_thread_socket);
}

void sockinfo_tcp::set_xlio_socket(const struct xlio_socket_attr *attr)
{
    if (m_rx_epfd != -1) {
        // XLIO Socket API doesn't use per socket epfd
        // Closing it here leads to 2 extra syscalls per connection
        m_sock_wakeup_pipe.wakeup_set_epoll_fd(0);
        SYSCALL(close, m_rx_epfd);
        m_rx_epfd = -1;
    }

    m_xlio_socket_userdata = attr->userdata_sq;
    m_p_group = reinterpret_cast<poll_group *>(attr->group);

    bool current_locks = m_ring_alloc_log_rx.get_use_locks();

    m_ring_alloc_log_rx.set_ring_alloc_logic(RING_LOGIC_PER_USER_ID);
    m_ring_alloc_log_rx.set_user_id_key(reinterpret_cast<uint64_t>(m_p_group));
    m_ring_alloc_log_rx.set_use_locks(current_locks ||
                                      (m_p_group->get_flags() & XLIO_GROUP_FLAG_SAFE));
    m_ring_alloc_logic_rx = ring_allocation_logic_rx(get_fd(), m_ring_alloc_log_rx);

    m_ring_alloc_log_tx.set_ring_alloc_logic(RING_LOGIC_PER_USER_ID);
    m_ring_alloc_log_tx.set_user_id_key(reinterpret_cast<uint64_t>(m_p_group));
    m_ring_alloc_log_tx.set_use_locks(current_locks ||
                                      (m_p_group->get_flags() & XLIO_GROUP_FLAG_SAFE));

    if (!current_locks && (m_p_group->get_flags() & XLIO_GROUP_FLAG_SAFE)) {
        m_tcp_con_lock = multilock::create_new_lock(MULTILOCK_RECURSIVE, "tcp_con");
    }

    tcp_recv(&m_pcb, sockinfo_tcp::rx_lwip_cb_xlio_socket);
    tcp_err(&m_pcb, sockinfo_tcp::err_lwip_cb_xlio_socket);
    set_blocking(false);

    // Allow the queue to grow for non-zerocopy send operations.
    m_pcb.snd_queuelen_max = TCP_SNDQUEUELEN_OVERFLOW;
}

int sockinfo_tcp::update_xlio_socket(unsigned flags, uintptr_t userdata_sq)
{
    NOT_IN_USE(flags); // Currently unused.
    m_xlio_socket_userdata = userdata_sq;

    return 0;
}

int sockinfo_tcp::detach_xlio_group()
{
    std::lock_guard<decltype(m_tcp_con_lock)> lock(m_tcp_con_lock);

    // Only connected socket can be detached.
    if (!m_p_group || !m_p_connected_dst_entry || (m_rx_flow_map.empty() && safe_mce_sys().xlio_threads == 0U) ||
        get_tcp_state(&m_pcb) != ESTABLISHED) {
        si_tcp_logwarn("Unable to detach socket %p, state %s, group %p, dst_entry %p,"
                       " rx_flow_size %zu. Only connected attached socket can be detached.",
                       this, tcp_state_str[get_tcp_state(&m_pcb)], m_p_group,
                       m_p_connected_dst_entry, m_rx_flow_map.size());
        return -1;
    }

    // TODO replace lwip callbacks with drops

    remove_timer();

    // Unregister this receiver from all the rings
    for (auto rx_flow_iter = m_rx_flow_map.begin(); rx_flow_iter != m_rx_flow_map.end();
         rx_flow_iter = m_rx_flow_map.begin()) {
        flow_tuple_with_local_if flow = rx_flow_iter->first;
        bool result = detach_receiver(flow);
        if (!result) {
            si_tcp_logwarn("Detach receiver failed, migration may be spoiled");
        }
    }
    // TODO SO_BINDTODEVICE support

    delete m_p_connected_dst_entry;
    m_p_connected_dst_entry = nullptr;

    m_p_group->remove_socket(this);
    m_p_group = nullptr;

    return 0;
}

int sockinfo_tcp::attach_xlio_group(poll_group *group, bool xlio_thread)
{
    struct xlio_socket_attr attr = {
        .flags = 0, /* unused */
        .domain = (int)m_family,
        .group = reinterpret_cast<xlio_poll_group_t>(group),
        .userdata_sq = m_xlio_socket_userdata,
    };

    std::lock_guard<decltype(m_tcp_con_lock)> lock(m_tcp_con_lock);

    if (m_p_group) {
        si_tcp_logwarn("Attaching undetached XLIO socket %p, group %p, new-group %p",
                       this, m_p_group, group);
        return -1;
    }

    // TODO reinitialize lwip callbacks

    if (!xlio_thread) {
        set_xlio_socket(&attr);
    } else {
        set_xlio_socket_thread(group);
    }

    group->add_socket(this);

    create_dst_entry();
    if (!m_p_connected_dst_entry) {
        si_tcp_logwarn("Couldn't create dst_enrty, migration failed");
        errno = ENOMEM;
        return -1;
    }
    bool result = prepare_dst_to_send(is_incoming());
    if (!result) {
        si_tcp_logwarn("Couldn't attach TX, migration failed");
        errno = ENOTCONN;
        return -1;
    }

    result = attach_as_uc_receiver(role_t(NULL), true);
    if (!result) {
        si_tcp_logwarn("Couldn't attach RX, migration failed");
        errno = ECONNABORTED;
        return -1;
    }

    register_timer();

    return 0;
}

void sockinfo_tcp::add_tx_ring_to_group()
{
    ring *rng = get_tx_ring();
    if (m_p_group && rng) {
        m_p_group->add_ring(rng, &m_ring_alloc_log_tx);
    }
}

void sockinfo_tcp::xlio_socket_event(int event, int value)
{
    if (is_xlio_socket()) {
        /* poll_group::m_socket_event_cb must be always set. */
        m_p_group->m_socket_event_cb(reinterpret_cast<xlio_socket_t>(this), m_xlio_socket_userdata,
                                     event, value);
    }
}

/*static*/
err_t sockinfo_tcp::rx_lwip_cb_xlio_socket(void *arg, struct tcp_pcb *pcb, struct pbuf *p)
{
    sockinfo_tcp *conn = (sockinfo_tcp *)arg;

    NOT_IN_USE(pcb);
    assert((uintptr_t)pcb->my_container == (uintptr_t)arg);

    // if is FIN
    if (unlikely(!p)) {
        return conn->handle_fin(pcb);
    }

    tcp_recved(pcb, p->tot_len);

    if (conn->m_p_group->m_socket_rx_cb) {
        struct pbuf *ptmp = p;

        if (unlikely(conn->m_p_socket_stats)) {
            conn->m_p_socket_stats->counters.n_rx_bytes += p->tot_len;
            conn->m_p_socket_stats->counters.n_rx_data_pkts++;
            // Assume that all chained buffers are GRO packets.
            conn->m_p_socket_stats->counters.n_gro += !!p->next;
        }

        while (ptmp) {
            if (unlikely(conn->m_p_socket_stats)) {
                conn->m_p_socket_stats->counters.n_rx_frags++;
                // The 1st pbuf in the chain is already handled in the rx_input_cb().
                if (ptmp != p) {
                    conn->save_strq_stats(reinterpret_cast<mem_buf_desc_t *>(ptmp)->rx.strides_num);
                }
            }
            conn->m_p_group->m_socket_rx_cb(reinterpret_cast<xlio_socket_t>(conn),
                                            conn->m_xlio_socket_userdata, ptmp->payload, ptmp->len,
                                            mem_buf_desc_t::to_xlio_buf(ptmp));
            ptmp = ptmp->next;
        }
    } else {
        pbuf_free(p);
    }

    return ERR_OK;
}

err_t sockinfo_tcp::rx_lwip_cb_thread_socket(void *arg, struct tcp_pcb *pcb, struct pbuf *p)
{
    sockinfo_tcp *conn = (sockinfo_tcp *)arg;

    NOT_IN_USE(pcb);
    assert((uintptr_t)pcb->my_container == (uintptr_t)arg);

    // If FIN
    if (unlikely(!p)) {
        return conn->handle_fin(pcb);
    }

    struct mem_buf_desc_t *buff;
    struct pbuf *ptmp = p;

    if (unlikely(conn->m_p_socket_stats)) {
        conn->m_p_socket_stats->counters.n_rx_bytes += p->tot_len;
        conn->m_p_socket_stats->counters.n_rx_data_pkts++;
        // Assume that all chained buffers are GRO packets.
        conn->m_p_socket_stats->counters.n_gro += !!p->next;
    }

    while (ptmp) {
        buff = reinterpret_cast<mem_buf_desc_t *>(ptmp);
        if (unlikely(conn->m_p_socket_stats)) {
            conn->m_p_socket_stats->counters.n_rx_frags++;
            // The 1st pbuf in the chain is already handled in the rx_input_cb().
            if (ptmp != p) {
                conn->save_strq_stats(buff->rx.strides_num);
            }
        }

        conn->process_timestamps(buff);

        buff->p_next_desc = buff->p_prev_desc = nullptr;
        conn->m_rx_pkt_ready_list.push_back(buff);
        conn->m_n_rx_pkt_ready_list_count++;
        conn->m_rx_ready_byte_count += ptmp->len;

        ptmp = ptmp->next;
        buff->lwip_pbuf.next = nullptr;
    }

    // Notify on event
    NOTIFY_ON_EVENTS(conn, EPOLLIN);
    io_mux_call::update_fd_array(conn->m_iomux_ready_fd_array, conn->m_fd);

    // OLG: Now we should wakeup all threads that are sleeping on this socket.
    conn->m_sock_wakeup_pipe.do_wakeup();

    return ERR_OK;
}

void sockinfo_tcp::insert_thread_epoll_event(uint64_t events)
{
    if (likely(m_p_group && m_p_thread_ready_socket_list)) {
        if (!m_epoll_event_flags_atomic.fetch_or(static_cast<uint32_t>(events), std::memory_order::memory_order_acquire)) {
            m_p_thread_ready_socket_list->push_back(this);
        }
    } else {
        si_tcp_logwarn("Adding regular event for XLIO Thread socket");
        m_econtext->insert_epoll_event_cb(this, static_cast<uint32_t>(events));
    }
}

void sockinfo_tcp::err_lwip_cb_set_conn_err(err_t err)
{
    m_conn_state = TCP_CONN_FAILED;
    m_error_status = ECONNABORTED;
    if (err == ERR_TIMEOUT) {
        m_conn_state = TCP_CONN_TIMEOUT;
        m_error_status = ETIMEDOUT;
    } else if (err == ERR_RST) {
        if (m_sock_state == TCP_SOCK_ASYNC_CONNECT) {
            m_conn_state = TCP_CONN_ERROR;
            m_error_status = ECONNREFUSED;
        } else {
            m_conn_state = TCP_CONN_RESETED;
            m_error_status = ECONNRESET;
        }
    }

    // Avoid binding twice in case of calling connect again after previous call failed.
    if (m_sock_state != TCP_SOCK_BOUND) { // TODO: maybe we need to exclude more states?
        m_sock_state = TCP_SOCK_INITED;
    }
}

void sockinfo_tcp::err_lwip_cb_notify_conn_err(err_t err)
{
    /*
     * In case we got RST from the other end we need to marked this socket as ready to read for
     * epoll
     */
    if ((m_sock_state == TCP_SOCK_CONNECTED_RD ||
        m_sock_state == TCP_SOCK_CONNECTED_RDWR ||
        m_sock_state == TCP_SOCK_ASYNC_CONNECT ||
        m_conn_state == TCP_CONN_CONNECTING) &&
       PCB_IN_ACTIVE_STATE(&m_pcb)) {
       if (err == ERR_RST) {
           if (m_sock_state == TCP_SOCK_ASYNC_CONNECT) {
               NOTIFY_ON_EVENTS(this, (EPOLLIN | EPOLLERR | EPOLLHUP));
           } else {
               NOTIFY_ON_EVENTS(this, (EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP));
           }
           /* TODO what about no route to host type of errors, need to add EPOLLERR in this
            * case ?
            */
       } else { // ERR_TIMEOUT
           NOTIFY_ON_EVENTS(this, (EPOLLIN | EPOLLHUP));
       }

       // Currently XLIO-Thread does not support select/poll
       // For Socketxtreme m_iomux_ready_fd_array is null.
       io_mux_call::update_fd_array(m_iomux_ready_fd_array, m_fd);
   }
}

/*static*/
void sockinfo_tcp::err_lwip_cb_xlio_socket(void *pcb_container, err_t err)
{
    sockinfo_tcp *conn = reinterpret_cast<sockinfo_tcp *>(pcb_container);

    conn->err_lwip_cb_set_conn_err(err);

    if (conn->m_state != SOCKINFO_CLOSING) {
        conn->xlio_socket_event(XLIO_SOCKET_EVENT_ERROR, conn->m_error_status);
    }
}

void sockinfo_tcp::err_lwip_cb_thread_socket(void *pcb_container, err_t err)
{
    sockinfo_tcp *conn = reinterpret_cast<sockinfo_tcp *>(pcb_container);

    if (get_tcp_state(&conn->m_pcb) == LISTEN && err == ERR_RST) {
        vlog_printf(VLOG_ERROR, "listen socket should not receive RST\n");
        return;
    }

    // We got RST/error/timeout before the handshake is complete
    if (conn->m_parent) {
        conn->m_parent->handle_incoming_handshake_failure(conn); // TODO: Is this good?
        return;
    }

    conn->err_lwip_cb_notify_conn_err(err);

    conn->err_lwip_cb_set_conn_err(err);

    conn->m_sock_wakeup_pipe.do_wakeup();
}

sockinfo_tcp::~sockinfo_tcp()
{
    si_tcp_logfunc("");
    g_global_stat_static.socket_tcp_destructor_counter.fetch_add(1, std::memory_order_relaxed);

    lock_tcp_con();

    if (!is_closable()) {
        /* Force closing TCP connection
         * tcp state should be as CLOSED after finishing this call
         */
        prepare_to_close(true);
    }

    m_sock_wakeup_pipe.do_wakeup();

    if (m_ops_tcp != m_ops) {
        delete m_ops_tcp;
    }
    delete m_ops;
    m_ops = nullptr;

    // Return buffers released in the TLS layer destructor
    m_rx_reuse_buf_postponed = m_rx_reuse_buff.n_buff_num > 0;
    return_reuse_buffers_postponed();

    if (m_bind_no_port) {
        g_bind_no_port->release_port(m_bound, m_connected);
    }

    destructor_helper_tcp();

    if (m_tcp_seg_in_use) {
        si_tcp_logwarn("still %d tcp segs in use!", m_tcp_seg_in_use);
    }
    if (m_tcp_seg_list) {
        g_tcp_seg_pool->put_objs(m_tcp_seg_list);
    }

    while (!m_socket_options_list.empty()) {
        socket_option_t *opt = m_socket_options_list.front();
        m_socket_options_list.pop_front();
        delete (opt);
    }

    unlock_tcp_con();

    if (m_n_rx_pkt_ready_list_count || m_rx_ready_byte_count || m_rx_pkt_ready_list.size() ||
        m_rx_ring_map.size() || m_rx_reuse_buff.n_buff_num || m_rx_reuse_buff.rx_reuse.size() ||
        m_rx_cb_dropped_list.size() || m_rx_ctl_packets_list.size() || m_rx_peer_packets.size() ||
        m_rx_ctl_reuse_list.size()) {
        si_tcp_logerr(
            "not all buffers were freed. protocol=TCP. m_n_rx_pkt_ready_list_count=%d, "
            "m_rx_ready_byte_count=%lu, m_rx_pkt_ready_list.size()=%d, m_rx_ring_map.size()=%d, "
            "m_rx_reuse_buff.n_buff_num=%d, m_rx_reuse_buff.rx_reuse.size=%lu, "
            "m_rx_cb_dropped_list.size=%lu, m_rx_ctl_packets_list.size=%lu, "
            "m_rx_peer_packets.size=%lu, m_rx_ctl_reuse_list.size=%lu",
            m_n_rx_pkt_ready_list_count, m_rx_ready_byte_count, (int)m_rx_pkt_ready_list.size(),
            (int)m_rx_ring_map.size(), m_rx_reuse_buff.n_buff_num, m_rx_reuse_buff.rx_reuse.size(),
            m_rx_cb_dropped_list.size(), m_rx_ctl_packets_list.size(), m_rx_peer_packets.size(),
            m_rx_ctl_reuse_list.size());
    }

    if (g_p_agent) {
        g_p_agent->unregister_cb((agent_cb_t)&sockinfo_tcp::put_agent_msg, (void *)this);
    }
    si_tcp_logdbg("sock closed");

    xlio_socket_event(XLIO_SOCKET_EVENT_TERMINATED, 0);
}

void sockinfo_tcp::destructor_helper_tcp()
{
    // Release preallocated buffers
    tcp_tx_preallocted_buffers_free(&m_pcb);

    destructor_helper();
}

void sockinfo_tcp::clean_socket_obj()
{
    lock_tcp_con();

    if (is_cleaned()) {
        return;
    }
    m_is_cleaned = true;

    unlock_tcp_con();

    event_handler_manager *p_event_mgr = get_event_mgr();
    bool delegated_timers_exit = g_b_exit &&
        (safe_mce_sys().tcp_ctl_thread == option_tcp_ctl_thread::CTL_THREAD_DELEGATE_TCP_TIMERS);

    if (p_event_mgr->is_running() && !delegated_timers_exit) {
        p_event_mgr->unregister_socket_timer_and_delete(this);
    } else {
        delete this;
    }
}

bool sockinfo_tcp::prepare_listen_to_close()
{
    // assume locked by sockinfo_tcp lock

    // remove the sockets from the accepted connections list
    while (!m_accepted_conns.empty()) {
        sockinfo_tcp *new_sock = m_accepted_conns.get_and_pop_front();
        new_sock->m_sock_state = TCP_SOCK_INITED;
        remove_received_syn_socket(new_sock);
        m_ready_conn_cnt--;
        new_sock->lock_tcp_con();
        new_sock->m_parent = nullptr;
        new_sock->abort_connection();
        new_sock->unlock_tcp_con();
        close(new_sock->get_fd());
    }

    // remove the sockets from the syn_received connections list
    syn_received_map_t::iterator syn_received_itr;
    for (syn_received_itr = m_syn_received.begin(); syn_received_itr != m_syn_received.end();) {
        sockinfo_tcp *new_sock = (sockinfo_tcp *)(syn_received_itr->second->my_container);
        new_sock->m_sock_state = TCP_SOCK_INITED;
        syn_received_map_t::iterator syn_received_itr_erase = syn_received_itr;
        syn_received_itr++;
        m_syn_received.erase(syn_received_itr_erase);
        new_sock->lock_tcp_con();
        new_sock->m_parent = NULL;
        new_sock->abort_connection();
        new_sock->unlock_tcp_con();
        close(new_sock->get_fd());
    }

    return true;
}

bool sockinfo_tcp::prepare_to_close(bool process_shutdown /* = false */)
{
    si_tcp_logdbg("");

    lock_tcp_con();

    bool do_abort = safe_mce_sys().tcp_abort_on_close || m_n_rx_pkt_ready_list_count;
    bool is_listen_socket = is_server() || get_tcp_state(&m_pcb) == LISTEN;

    m_state = SOCKINFO_CLOSING;

    /*
     * consider process_shutdown:
     * workaround for LBM which does not close the listen sockets properly on process shutdown.
     * as a result they become ready for select, but calling accept return failure.
     * see RM#390019
     */

    // listen, accepted or connected socket
    if ((is_listen_socket && !process_shutdown) || m_sock_state == TCP_SOCK_CONNECTED_RD ||
        m_sock_state == TCP_SOCK_CONNECTED_WR || m_sock_state == TCP_SOCK_CONNECTED_RDWR) {
        m_sock_state = TCP_SOCK_BOUND;
    }

    m_rx_ready_byte_count += m_rx_pkt_ready_offset;
    IF_STATS(m_p_socket_stats->n_rx_ready_byte_count += m_rx_pkt_ready_offset);
    while (m_n_rx_pkt_ready_list_count) {
        mem_buf_desc_t *p_rx_pkt_desc = m_rx_pkt_ready_list.get_and_pop_front();
        m_n_rx_pkt_ready_list_count--;
        m_rx_ready_byte_count -= p_rx_pkt_desc->rx.sz_payload;
        if (m_p_socket_stats) {
            m_p_socket_stats->n_rx_ready_pkt_count--;
            m_p_socket_stats->n_rx_ready_byte_count -= p_rx_pkt_desc->rx.sz_payload;
        }
        reuse_buffer(p_rx_pkt_desc);
    }
    m_rx_pkt_ready_offset = 0;

    while (!m_rx_ctl_packets_list.empty()) {
        /* coverity[double_lock] TODO: RM#1049980 */
        m_rx_ctl_packets_list_lock.lock();
        if (m_rx_ctl_packets_list.empty()) {
            m_rx_ctl_packets_list_lock.unlock();
            break;
        }
        mem_buf_desc_t *p_rx_pkt_desc = m_rx_ctl_packets_list.get_and_pop_front();
        /* coverity[double_unlock] TODO: RM#1049980 */
        m_rx_ctl_packets_list_lock.unlock();
        reuse_buffer(p_rx_pkt_desc);
    }

    for (peer_map_t::iterator itr = m_rx_peer_packets.begin(); itr != m_rx_peer_packets.end();
         ++itr) {
        xlio_desc_list_t &peer_packets = itr->second;
        // loop on packets of a peer
        while (!peer_packets.empty()) {
            // get packet from list and reuse them
            mem_buf_desc_t *desc = peer_packets.get_and_pop_front();
            reuse_buffer(desc);
        }
    }
    m_rx_peer_packets.clear();

    while (!m_rx_ctl_reuse_list.empty()) {
        mem_buf_desc_t *p_rx_pkt_desc = m_rx_ctl_reuse_list.get_and_pop_front();
        reuse_buffer(p_rx_pkt_desc);
    }

    while (!m_rx_cb_dropped_list.empty()) {
        mem_buf_desc_t *p_rx_pkt_desc = m_rx_cb_dropped_list.get_and_pop_front();
        reuse_buffer(p_rx_pkt_desc);
    }

    return_reuse_buffers_postponed();

    if (m_b_zc && m_p_connected_dst_entry) {
        m_p_connected_dst_entry->reset_inflight_zc_buffers_ctx(this);
    }

    /* According to "UNIX Network Programming" third edition,
     * setting SO_LINGER with timeout 0 prior to calling close()
     * will cause the normal termination sequence not to be initiated.
     * If l_onoff is nonzero and l_linger is zero, TCP aborts the connection when it is closed.
     * That is, TCP discards any data still remaining in the socket
     * send buffer and sends an RST to the peer, not the normal four-packet connection
     * termination sequence
     * If process_shutdown is set as True do abort() with setting tcp state as CLOSED
     */
    if (!is_listen_socket &&
        (do_abort || process_shutdown || (m_linger.l_onoff && !m_linger.l_linger))) {
        abort_connection();
    } else {
        tcp_close(&m_pcb);

        if (is_listen_socket) {
            tcp_accept(&m_pcb, nullptr);
            tcp_syn_handled(&m_pcb, nullptr);
            tcp_clone_conn(&m_pcb, nullptr);
            tcp_accepted_pcb(&m_pcb, nullptr);
            prepare_listen_to_close(); // close pending to accept sockets
        } else {
            tcp_recv(&m_pcb, sockinfo_tcp::rx_drop_lwip_cb);
            tcp_sent(&m_pcb, nullptr);
            if (m_linger.l_onoff && m_linger.l_linger) {
                // TODO Should we do this each time we get into prepare_to_close?
                handle_socket_linger();
            }
        }
    }

    NOTIFY_ON_EVENTS(this, EPOLLHUP);
    m_sock_wakeup_pipe.do_wakeup();

    if (has_epoll_context()) {
        m_econtext->fd_closed(m_fd);
    }

    bool is_closable_state = is_closable();
    if (is_closable_state) {
        m_state = SOCKINFO_CLOSED;
        reset_ops();
    } else if (!is_listen_socket) {
        // This solution is good for current Nginx case however,
        // There is still possibility of race in case of multithreded polling.
        // Once we unlock this connection there are still two operations that are racebale:
        // 1. In fd_collection::del_sockfd after this method is done.
        // 2. In handle_close when fd_collection::del_sockfd is finished and we remove the
        //    socket from epfds.
        m_pcb.syn_tw_handled_cb = &sockinfo_tcp::syn_received_timewait_cb;
    }

    unlock_tcp_con();

    return is_closable_state;
}

void sockinfo_tcp::handle_socket_linger()
{
    timeval start, current, elapsed;
    long int linger_time_usec;
    int poll_cnt = 0;

    linger_time_usec =
        (!m_linger.l_onoff /*|| !m_b_blocking */) ? 0 : m_linger.l_linger * USEC_PER_SEC;
    si_tcp_logdbg("Going to linger for max time of %lu usec", linger_time_usec);
    memset(&elapsed, 0, sizeof(elapsed));
    gettime(&start);
    while ((tv_to_usec(&elapsed) <= linger_time_usec) && (m_pcb.unsent || m_pcb.unacked)) {
        /* SOCKETXTREME WA: Don't call rx_wait() in order not to miss events in socketxtreme_poll()
         * flow. TBD: find proper solution! rx_wait(poll_cnt, false);
         * */
        if (!safe_mce_sys().enable_socketxtreme) {
            rx_wait(poll_cnt, false);
        }
        tcp_output(&m_pcb);
        gettime(&current);
        tv_sub(&current, &start, &elapsed);
    }

    if (m_linger.l_onoff && (m_pcb.unsent || m_pcb.unacked)) {
        if (m_linger.l_linger > 0 /*&& m_b_blocking*/) {
            errno = ERR_WOULDBLOCK;
        }
    }
}

// This method will be on syn received on the passive side of a TCP connection
void sockinfo_tcp::create_dst_entry()
{
    if (!m_p_connected_dst_entry) {
        socket_data data = {m_fd, m_n_uc_ttl_hop_lim, m_pcb.tos, m_pcp};
        m_p_connected_dst_entry =
            new dst_entry_tcp(m_connected, m_bound.get_in_port(), data, m_ring_alloc_log_tx);

        BULLSEYE_EXCLUDE_BLOCK_START
        if (!m_p_connected_dst_entry) {
            si_tcp_logerr("Failed to allocate m_p_connected_dst_entry");
            return;
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        if (!m_bound.is_anyaddr()) {
            m_p_connected_dst_entry->set_bound_addr(m_bound.get_ip_addr());
        }
        if (!m_so_bindtodevice_ip.is_anyaddr()) {
            m_p_connected_dst_entry->set_so_bindtodevice_addr(m_so_bindtodevice_ip);
        }

        m_p_connected_dst_entry->set_src_sel_prefs(m_src_sel_flags);
        m_p_connected_dst_entry->set_external_vlan_tag(m_external_vlan_tag);
    }
}

void sockinfo_tcp::lock_rx_q()
{
    lock_tcp_con();
}

void sockinfo_tcp::unlock_rx_q()
{
    unlock_tcp_con();
}

void sockinfo_tcp::tcp_timer()
{
    if (m_state == SOCKINFO_DESTROYING) {
        return;
    }

    tcp_tmr(&m_pcb);

    return_pending_rx_buffs();
    return_pending_tx_buffs();
}

bool sockinfo_tcp::prepare_dst_to_send(bool is_accepted_socket /* = false */)
{
    bool ret_val = false;

    if (m_p_connected_dst_entry) {
        ret_val = m_p_connected_dst_entry->prepare_to_send(m_so_ratelimit, is_accepted_socket);
        if (ret_val) {
            /* dst_entry has resolved tx ring,
             * so it is a time to provide TSO information to PCB
             */
            auto *ring = m_p_connected_dst_entry->get_ring();
            uint32_t max_tso_sz = std::min(ring->get_max_payload_sz(), safe_mce_sys().max_tso_sz);
            m_pcb.tso.max_buf_sz = std::min(safe_mce_sys().tx_buf_size, max_tso_sz);
            m_pcb.tso.max_payload_sz = max_tso_sz;
            m_pcb.tso.max_header_sz = ring->get_max_header_sz();
            m_pcb.tso.max_send_sge = ring->get_max_send_sge();
        }
    }
    return ret_val;
}

unsigned sockinfo_tcp::tx_wait(bool blocking)
{
    unsigned sz = sndbuf_available();
    int poll_count = 0;
    si_tcp_logfunc("sz = %u rx_count=%d", sz, m_n_rx_pkt_ready_list_count);
    int err = 0;
    while (is_rts() && (sz = sndbuf_available()) == 0) {
        err = rx_wait(poll_count, blocking);
        // AlexV:Avoid from going to sleep, for the blocked socket of course, since
        // progress engine may consume an arrived credit and it will not wakeup the
        // transmit thread.
        if (unlikely(err < 0)) {
            return 0;
        }
        if (unlikely(g_b_exit)) {
            errno = EINTR;
            return 0;
        }
        if (blocking) {
            /* force out TCP data to avoid spinning in this loop
             * in case data is not seen on rx
             */
            tcp_output(&m_pcb);
            poll_count = 0;
        }
    }
    si_tcp_logfunc("end sz=%u rx_count=%d", sz, m_n_rx_pkt_ready_list_count);
    return sz;
}

static inline bool cannot_do_requested_dummy_send(const tcp_pcb &pcb,
                                                  const xlio_tx_call_attr_t &tx_arg)
{
    int flags = tx_arg.attr.flags;
    const iovec *p_iov = tx_arg.attr.iov;
    size_t sz_iov = tx_arg.attr.sz_iov;

    uint8_t optflags = TF_SEG_OPTS_DUMMY_MSG;
    uint16_t mss_local = std::min<uint16_t>(pcb.mss, pcb.snd_wnd_max / 2U);
    mss_local = mss_local ? mss_local : pcb.mss;

#if LWIP_TCP_TIMESTAMPS
    if ((pcb.flags & TF_TIMESTAMP)) {
        optflags |= TF_SEG_OPTS_TS;
        mss_local = std::max<uint16_t>(mss_local, LWIP_TCP_OPT_LEN_TS + 1U);
    }
#endif /* LWIP_TCP_TIMESTAMPS */

    u16_t max_len = mss_local - LWIP_TCP_OPT_LENGTH(optflags);

    // Calculate window size
    u32_t wnd = std::min(pcb.snd_wnd, pcb.cwnd);

    /* The functions asks the inverse of can do dummy send; thus the truth table might look like:
     * |                   |Is dummy|Not dummy|
     * |-------------------|--------|---------|
     * |Can't do dummy send| True   |  False  |
     * |Can do dummy send  | False  |  False  |
     *
     * !m_pcb.unsent - Unsent queue should be empty
     * !(flags & MSG_MORE) - MSG_MORE flag is not set
     * sz_iov == 1U - Prevent calling tcp_write() for scatter/gather element
     * p_iov->iov_len - There is data to send
     * p_iov->iov_len <= max_len - The data will not be split into more then one segment
     * wnd - The window is not empty
     * (p_iov->iov_len + m_pcb.snd_lbb - m_pcb.lastack) <= wnd - The window allows the dummy packet
     * it to be sent
     */
    bool can_do_dummy_send = !pcb.unsent && !(flags & MSG_MORE) && sz_iov == 1U && p_iov->iov_len &&
        p_iov->iov_len <= max_len && wnd && (p_iov->iov_len + pcb.snd_lbb - pcb.lastack) <= wnd;
    return IS_DUMMY_PACKET(flags) && !can_do_dummy_send;
}

void sockinfo_tcp::put_agent_msg(void *arg)
{
    sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)arg;
    struct xlio_msg_state data;

    /* Ignore listen socket at the moment */
    if (p_si_tcp->is_server() || get_tcp_state(&p_si_tcp->m_pcb) == LISTEN) {
        return;
    }
    if (unlikely(!g_p_agent)) {
        return;
    }

    data.hdr.code = XLIO_MSG_STATE;
    data.hdr.ver = XLIO_AGENT_VER;
    data.hdr.pid = getpid();
    data.hdr.status = 0;
    data.hdr.reserve[0] = 0; // suppress coverity warning
    data.fid = p_si_tcp->get_fd();
    data.state = get_tcp_state(&p_si_tcp->m_pcb);
    data.type = SOCK_STREAM;
    data.src.family = p_si_tcp->m_bound.get_sa_family();
    data.src.port = p_si_tcp->m_bound.get_in_port();
    if (data.src.family == AF_INET) {
        data.src.addr.ipv4 = p_si_tcp->m_bound.get_ip_addr().get_in4_addr().s_addr;
    } else {
        memcpy(&data.src.addr.ipv6[0], &p_si_tcp->m_bound.get_ip_addr().get_in6_addr(),
               sizeof(data.src.addr.ipv6));
    }
    data.dst.family = p_si_tcp->m_connected.get_sa_family();
    data.dst.port = p_si_tcp->m_connected.get_in_port();
    if (data.dst.family == AF_INET) {
        data.dst.addr.ipv4 = p_si_tcp->m_connected.get_ip_addr().get_in4_addr().s_addr;
    } else {
        memcpy(&data.dst.addr.ipv6[0], &p_si_tcp->m_connected.get_ip_addr().get_in6_addr(),
               sizeof(data.src.addr.ipv6));
    }

    g_p_agent->put((const void *)&data, sizeof(data), (intptr_t)data.fid);
}

ssize_t sockinfo_tcp::tx(xlio_tx_call_attr_t &tx_arg)
{
    return m_ops->tx(tx_arg);
}

#ifdef DEFINED_TCP_TX_WND_AVAILABILITY
#define TCP_WND_UNAVALABLE(pcb, total_iov_len) !tcp_is_wnd_available(&pcb, total_iov_len)
#else
#define TCP_WND_UNAVALABLE(pcb, total_iov_len) false
#endif

static inline bool is_invalid_iovec(const iovec *iov, size_t sz_iov)
{
    return !iov || sz_iov == 0;
}

/**
 * Handles transmission operations on a TCP socket, supporting various user actions such as
 * write, send, sendv, sendmsg, and sendfile. This function operates on both blocking and
 * non-blocking sockets, providing options for zero-copy send operations. When the socket is
 * configured for zero-copy send, it executes a fast-path send for non-blocking operations;
 * otherwise, it falls back to the tcp_tx_slow_path function.
 *
 * @param tx_arg    The TCP transmission arguments and parameters.
 * @return          Returns the number of bytes transmitted, or -1 on error with the errno set.
 */
ssize_t sockinfo_tcp::tcp_tx(xlio_tx_call_attr_t &tx_arg)
{
    iovec *p_iov = tx_arg.attr.iov;
    size_t sz_iov = tx_arg.attr.sz_iov;
    int flags = tx_arg.attr.flags;
    int errno_tmp = errno;
    int ret = 0;
    int poll_count = 0;
    err_t err;
    void *tx_ptr = nullptr;
    struct xlio_pd_key *pd_key_array = nullptr;

    /* Let allow OS to process all invalid scenarios to avoid any
     * inconsistencies in setting errno values
     */
    if (unlikely(m_sock_offload != TCP_SOCK_LWIP) || unlikely(is_invalid_iovec(p_iov, sz_iov))) {
        struct sockaddr *dst = tx_arg.attr.addr;
        socklen_t dstlen = tx_arg.attr.len;
        ret = tx_os(tx_arg.opcode, p_iov, sz_iov, flags, dst, dstlen);
        save_stats_tx_os(ret);
        return ret;
    }

    si_tcp_logfunc("tx: iov=%p niovs=%d", p_iov, sz_iov);

    if (m_sysvar_rx_poll_on_tx_tcp) {
        rx_wait_helper(poll_count, false);
    }

    bool is_dummy = IS_DUMMY_PACKET(flags);
    bool is_blocking = BLOCK_THIS_RUN(m_b_blocking, flags);
    bool is_packet_zerocopy = (flags & MSG_ZEROCOPY) && ((m_b_zc) || (tx_arg.opcode == TX_FILE));
    if (unlikely(is_dummy) || unlikely(!is_packet_zerocopy) || unlikely(is_blocking)) {
        return tcp_tx_slow_path(tx_arg);
    }

    bool is_non_file_zerocopy = tx_arg.opcode != TX_FILE;
    pd_key_array =
        (tx_arg.priv.attr == PBUF_DESC_MKEY ? (struct xlio_pd_key *)tx_arg.priv.opaque : nullptr);

    si_tcp_logfunc("tx: iov=%p niovs=%zu", p_iov, sz_iov);

    size_t total_iov_len =
        std::accumulate(&p_iov[0], &p_iov[sz_iov], 0U,
                        [](size_t sum, const iovec &curr) { return sum + curr.iov_len; });
    lock_tcp_con();

    if (unlikely(!is_connected_and_ready_to_send())) {
        return tcp_tx_handle_errno_and_unlock(errno);
    }
    if (TCP_WND_UNAVALABLE(m_pcb, total_iov_len)) {
        return tcp_tx_handle_errno_and_unlock(EAGAIN);
    }

    int total_tx = 0;
    for (size_t i = 0; i < sz_iov; i++) {
        si_tcp_logfunc("iov:%d base=%p len=%d", i, p_iov[i].iov_base, p_iov[i].iov_len);
        if (unlikely(!p_iov[i].iov_base)) {
            continue;
        }

        tx_ptr = p_iov[i].iov_base;
        if ((tx_arg.priv.attr == PBUF_DESC_MKEY) && pd_key_array) {
            tx_arg.priv.mkey = pd_key_array[i].mkey;
        }
        unsigned pos = 0;
        while (pos < p_iov[i].iov_len) {
            unsigned tx_size = sndbuf_available();

            if (tx_size == 0) {
                // force out TCP data before going on wait()
                tcp_output(&m_pcb);
                return tcp_tx_handle_sndbuf_unavailable(total_tx, is_dummy, is_non_file_zerocopy,
                                                        errno_tmp);
            }
            if (tx_arg.xlio_flags & TX_FLAG_NO_PARTIAL_WRITE) {
                /*
                 * With TX_FLAG_NO_PARTIAL_WRITE we can queue a single send operation beyond the
                 * TCP send buffer. However, avoid 32-bit snd_buf overflow.
                 */
                if (unlikely(total_iov_len > UINT32_MAX)) {
                    return tcp_tx_handle_errno_and_unlock(E2BIG);
                }
                tx_size = total_iov_len;
            }

            tx_size = std::min<size_t>(p_iov[i].iov_len - pos, tx_size);
            if (is_non_file_zerocopy) {
                /*
                 * For send zerocopy we don't support pbufs which
                 * cross huge page boundaries. To avoid forming
                 * such a pbuf, we have to adjust tx_size, so
                 * tcp_write receives a buffer which doesn't cross
                 * the boundary.
                 */
                unsigned remainder =
                    ~m_user_huge_page_mask + 1 - ((uint64_t)tx_ptr & ~m_user_huge_page_mask);
                tx_size = std::min(remainder, tx_size);
            }

            const struct iovec iov = {.iov_base = tx_ptr, .iov_len = tx_size};
            err = tcp_write_express(&m_pcb, &iov, 1, &tx_arg.priv);
            if (unlikely(err != ERR_OK)) {
                // tcp_write_express() can return only ERR_MEM error.
                return tcp_tx_handle_partial_send_and_unlock(total_tx, EAGAIN, is_dummy,
                                                             is_non_file_zerocopy, errno_tmp);
            }
            tx_ptr = (void *)((char *)tx_ptr + tx_size);
            pos += tx_size;
            total_tx += tx_size;
        }
    }

    return tcp_tx_handle_done_and_unlock(total_tx, errno_tmp, is_dummy, is_non_file_zerocopy);
}

ssize_t sockinfo_tcp::tcp_tx_thread(xlio_tx_call_attr_t &tx_arg)
{
    iovec *p_iov = tx_arg.attr.iov;
    size_t sz_iov = tx_arg.attr.sz_iov;
    char *addr = reinterpret_cast<char *>(p_iov[0].iov_base);
    size_t tosend = p_iov[0].iov_len;
    ssize_t sent = 0;

    if (sz_iov > 1) {
        errno = ENOTSUP;
        return -1;
    }

    lock_tcp_con();
    unsigned sndbuf = sndbuf_available();
//    m_pcb.snd_buf -= std::min<int>(sndbuf, tosend);
//  TODO decrease sndbuf and take into account sndbuf change in tcp_write
    unlock_tcp_con();

    while (sndbuf > 0 && tosend > 0) {
        mem_buf_desc_t *buf = m_p_group->get_tx_buffer();
        if (!buf) {
            break;
        }

        size_t buflen = std::min<size_t>(std::min<size_t>(tosend, sndbuf), buf->sz_buffer);
        memcpy(buf->p_buffer, addr, buflen);
        buf->sz_data = buflen;
        addr += buflen;
        sent += buflen;
        sndbuf -= buflen;
        tosend -= buflen;

        m_p_group->job_insert(this, buf);
    }

    /* TODO Handle disconnected socket */

    if (!sent) {
        errno = EAGAIN;
        sent = -1;
    }
    return sent;
}

/**
 * Handles transmission operations on a TCP socket similar to tcp_tx.
 * This is a fallback function when the operation is either blocking, not zero-copy, or the socket
 * wasn't configured for zero-copy operations.
 *
 * @param tx_arg    The TCP transmission arguments and parameters.
 * @return          Returns the number of bytes transmitted, or -1 on error with the errno set.
 */
ssize_t sockinfo_tcp::tcp_tx_slow_path(xlio_tx_call_attr_t &tx_arg)
{
    iovec *p_iov = tx_arg.attr.iov;
    size_t sz_iov = tx_arg.attr.sz_iov;
    int flags = tx_arg.attr.flags;
    int errno_tmp = errno;
    int poll_count = 0;
    uint16_t apiflags = 0;
    bool is_send_zerocopy = false;
    void *tx_ptr = nullptr;
    struct xlio_pd_key *pd_key_array = nullptr;

    if (tx_arg.opcode == TX_FILE) {
        /*
         * TX_FILE is a special operation which reads a single file.
         * Each p_iov item contains pointer to file offset and size
         * to be read. Pointer to the file descriptor is passed via
         * tx_arg.priv.
         */
        apiflags |= XLIO_TX_FILE;
    }

    bool is_dummy = IS_DUMMY_PACKET(flags);
    if (unlikely(is_dummy)) {
        apiflags |= XLIO_TX_PACKET_DUMMY;
    }

    /* To force zcopy flow there are two possible ways
     * - send() MSG_ZEROCOPY flag should be passed by user application
     * and SO_ZEROCOPY activated
     * - sendfile() MSG_ZEROCOPY flag set internally with opcode TX_FILE
     */
    if ((flags & MSG_ZEROCOPY) && ((m_b_zc) || (tx_arg.opcode == TX_FILE))) {
        apiflags |= XLIO_TX_PACKET_ZEROCOPY;
        is_send_zerocopy = tx_arg.opcode != TX_FILE;
        pd_key_array =
            (tx_arg.priv.attr == PBUF_DESC_MKEY ? (struct xlio_pd_key *)tx_arg.priv.opaque
                                                : nullptr);
    }

    si_tcp_logfunc("tx: iov=%p niovs=%zu", p_iov, sz_iov);

    lock_tcp_con();

    if (unlikely(!is_connected_and_ready_to_send())) {
        return tcp_tx_handle_errno_and_unlock(errno);
    }
    if (cannot_do_requested_dummy_send(m_pcb, tx_arg)) {
        return tcp_tx_handle_errno_and_unlock(EAGAIN);
    }

    int total_tx = 0;
    off64_t file_offset = 0;
    bool block_this_run = BLOCK_THIS_RUN(m_b_blocking, flags);
    for (size_t i = 0; i < sz_iov; i++) {
        si_tcp_logfunc("iov:%d base=%p len=%d", i, p_iov[i].iov_base, p_iov[i].iov_len);
        if (unlikely(!p_iov[i].iov_base)) {
            continue;
        }

        if ((tx_arg.opcode == TX_FILE) && !(apiflags & XLIO_TX_PACKET_ZEROCOPY)) {
            file_offset = *(off64_t *)p_iov[i].iov_base;
            tx_ptr = &file_offset;
        } else {
            tx_ptr = p_iov[i].iov_base;
            if ((tx_arg.priv.attr == PBUF_DESC_MKEY) && pd_key_array) {
                tx_arg.priv.mkey = pd_key_array[i].mkey;
            }
        }
        unsigned pos = 0;
        while (pos < p_iov[i].iov_len) {
            auto tx_size = sndbuf_available();

            /* Process a case when space is not available at the sending socket
             * to hold the message to be transmitted
             * Nonblocking socket:
             *    - no data is buffered: return (-1) and EAGAIN
             *    - some data is buffered: return number of bytes ready to be sent
             * Blocking socket:
             *    - block until space is available
             */
            if (tx_size == 0) {
                // force out TCP data before going on wait()
                tcp_output(&m_pcb);

                // non blocking socket should return in order not to tx_wait()
                if (!block_this_run) {
                    return tcp_tx_handle_sndbuf_unavailable(total_tx, is_dummy, is_send_zerocopy,
                                                            errno_tmp);
                }

                if (unlikely(g_b_exit)) {
                    return tcp_tx_handle_partial_send_and_unlock(total_tx, EINTR, is_dummy,
                                                                 is_send_zerocopy, errno_tmp);
                }

                tx_size = tx_wait(block_this_run);
                if (unlikely(!is_rts())) {
                    si_tcp_logdbg("TX on disconnected socket");
                    return tcp_tx_handle_errno_and_unlock(ECONNRESET);
                }
            }

            tx_size = std::min<size_t>(p_iov[i].iov_len - pos, tx_size);
            if (is_send_zerocopy) {
                /*
                 * For send zerocopy we don't support pbufs which
                 * cross huge page boundaries. To avoid forming
                 * such a pbuf, we have to adjust tx_size, so
                 * tcp_write receives a buffer which doesn't cross
                 * the boundary.
                 */
                unsigned remainder =
                    ~m_user_huge_page_mask + 1 - ((uint64_t)tx_ptr & ~m_user_huge_page_mask);
                tx_size = std::min(remainder, tx_size);
            }
            do {
                err_t err;
                if (apiflags & XLIO_TX_PACKET_ZEROCOPY) {
                    const struct iovec iov = {.iov_base = tx_ptr, .iov_len = tx_size};
                    err = tcp_write_express(&m_pcb, &iov, 1, &tx_arg.priv);
                } else {
                    err = tcp_write(&m_pcb, tx_ptr, tx_size, apiflags, &tx_arg.priv);
                }
                if (unlikely(err != ERR_OK)) {
                    if (unlikely(err == ERR_CONN)) { // happens when remote drops during big write
                        si_tcp_logdbg("connection closed: tx'ed = %d", total_tx);
                        shutdown(SHUT_WR);
                        return tcp_tx_handle_partial_send_and_unlock(total_tx, EPIPE, is_dummy,
                                                                     is_send_zerocopy, errno_tmp);
                    }
                    if (unlikely(err != ERR_MEM)) {
                        // we should not get here...
                        BULLSEYE_EXCLUDE_BLOCK_START
                        si_tcp_logpanic("tcp_write return: %d", err);
                        BULLSEYE_EXCLUDE_BLOCK_END
                    }
                    /* Set return values for nonblocking socket and finish processing */
                    if (!block_this_run) {
                        if (total_tx > 0) {
                            return tcp_tx_handle_done_and_unlock(total_tx, errno_tmp, is_dummy,
                                                                 is_send_zerocopy);
                        } else {
                            return tcp_tx_handle_errno_and_unlock(EAGAIN);
                        }
                    }

                    if (unlikely(g_b_exit)) {
                        return tcp_tx_handle_partial_send_and_unlock(total_tx, EINTR, is_dummy,
                                                                     is_send_zerocopy, errno_tmp);
                    }

                    rx_wait(poll_count, true);
                    if (unlikely(!is_rts())) {
                        si_tcp_logdbg("TX on disconnected socket");
                        return tcp_tx_handle_errno_and_unlock(ECONNRESET);
                    }

                    // AlexV:Avoid from going to sleep, for the blocked socket of course, since
                    // progress engine may consume an arrived credit and it will not wakeup the
                    // transmit thread.
                    poll_count = 0;

                    continue;
                }
                break;
            } while (true);
            if (tx_arg.opcode == TX_FILE && !(apiflags & XLIO_TX_PACKET_ZEROCOPY)) {
                file_offset += tx_size;
            } else {
                tx_ptr = (void *)((char *)tx_ptr + tx_size);
            }
            pos += tx_size;
            total_tx += tx_size;
        }
    }

    return tcp_tx_handle_done_and_unlock(total_tx, errno_tmp, is_dummy, is_send_zerocopy);
}

static bool inspect_socket_error_state(const mem_buf_desc_t *mem_buf_desc, struct tcp_pcb *pcb)
{
    // this means a retransmit happened - let's check the error_state we'll put if we got error
    // cqe
    if (mem_buf_desc->m_flags & mem_buf_desc_t::HAD_CQE_ERROR) {
        TCP_EVENT_ERR(pcb->errf, pcb->my_container, ERR_RST);
        return true;
    }

    return false;
}

/*
 * TODO Remove 'p' from the interface and use 'seg'.
 * There are multiple places where ip_output() is used without allocating
 * a tcp_seg object. Therefore, 'seg' may be NULL now. However, we can improve
 * those places in such a way:
 * - LwIP will always allocate a tcp_seg even to send a TCP header. The
 *   allocation must be a fast operation.
 * - ip_output() will accept only 'seg' without 'p'.
 * - Segments with empty pbuf list will be supported.
 * - tcp_seg contains a buffer for TCP header. This buffer will be used to hold
 *   TCP header for segments with 0 payload.
 * - The TCP/IP headers will be inlined into WQE.
 */
err_t sockinfo_tcp::ip_output(struct pbuf *p, struct tcp_seg *seg, void *v_p_conn, uint16_t flags)
{
    sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)(((struct tcp_pcb *)v_p_conn)->my_container);
    dst_entry *p_dst = p_si_tcp->m_p_connected_dst_entry;
    int max_count = p_si_tcp->m_pcb.tso.max_send_sge;
    tcp_iovec lwip_iovec[max_count];
    xlio_send_attr attr = {
        (xlio_wr_tx_packet_attr)(flags | (!!p_si_tcp->is_xlio_socket() * XLIO_TX_SKIP_POLL)),
        p_si_tcp->m_pcb.mss, 0, nullptr};
    int count = 0;
    void *cur_end;

    if (unlikely(flags & XLIO_TX_PACKET_REXMIT)) {
        if (unlikely(inspect_socket_error_state(reinterpret_cast<const mem_buf_desc_t *>(seg->p),
                                                reinterpret_cast<struct tcp_pcb *>(v_p_conn)))) {
            return ERR_RST;
        }
    }

    int rc = p_si_tcp->m_ops->postrouting(p, seg, attr);
    if (rc != 0) {
        return rc;
    }

    if (flags & TCP_WRITE_ZEROCOPY) {
        goto zc_fill_iov;
    }

    /* maximum number of sge can not exceed this value */
    while (p && (count < max_count)) {
        lwip_iovec[count].iovec.iov_base = p->payload;
        lwip_iovec[count].iovec.iov_len = p->len;
        lwip_iovec[count].p_desc = (mem_buf_desc_t *)p;
        attr.length += p->len;
        p = p->next;
        count++;
    }
    goto send_iov;

zc_fill_iov:
    /* For zerocopy, 1st pbuf contains pointer to TCP header */
    assert(p->type == PBUF_STACK);
    lwip_iovec[0].tcphdr = p->payload;
    attr.length += p->len;
    p = p->next;
    lwip_iovec[0].iovec.iov_base = p->payload;
    lwip_iovec[0].iovec.iov_len = p->len;
    lwip_iovec[0].p_desc = (mem_buf_desc_t *)p;
    attr.length += p->len;
    p = p->next;
    /*
     * Compact sequential memory buffers.
     * Assume here that ZC buffer doesn't cross huge-pages -> ZC lkey scheme works.
     */
    while (p && (count < max_count)) {
        cur_end =
            (void *)((uint64_t)lwip_iovec[count].iovec.iov_base + lwip_iovec[count].iovec.iov_len);
        if ((p->desc.attr == PBUF_DESC_NONE) && (cur_end == p->payload) &&
            ((uintptr_t)((uint64_t)lwip_iovec[count].iovec.iov_base &
                         p_si_tcp->m_user_huge_page_mask) ==
             (uintptr_t)((uint64_t)p->payload & p_si_tcp->m_user_huge_page_mask))) {
            lwip_iovec[count].iovec.iov_len += p->len;
        } else {
            count++;
            lwip_iovec[count].iovec.iov_base = p->payload;
            lwip_iovec[count].iovec.iov_len = p->len;
            lwip_iovec[count].p_desc = (mem_buf_desc_t *)p;
        }
        attr.length += p->len;
        p = p->next;
    }
    count++;

send_iov:
    /* Sanity check */
    if (unlikely(p)) {
        vlog_printf(VLOG_ERROR, "Number of buffers in request exceed  %d, so silently dropped.\n",
                    max_count);
        return ERR_OK;
    }

    ssize_t ret = likely((p_dst->is_valid()))
        ? p_dst->fast_send((struct iovec *)lwip_iovec, count, attr)
        : p_dst->slow_send((struct iovec *)lwip_iovec, count, attr, p_si_tcp->m_so_ratelimit);

    rc = p_si_tcp->m_ops->handle_send_ret(ret, seg);

    if (unlikely(safe_mce_sys().ring_migration_ratio_tx > 0)) { // Condition for cache optimization
        if (p_dst->try_migrate_ring_tx(p_si_tcp->m_tcp_con_lock.get_lock_base())) {
            IF_STATS_O(p_si_tcp, p_si_tcp->m_p_socket_stats->counters.n_tx_migrations++);
        }
    }

    if (unlikely(p_si_tcp->m_p_socket_stats && is_set(attr.flags, XLIO_TX_PACKET_REXMIT) && rc)) {
        p_si_tcp->m_p_socket_stats->counters.n_tx_retransmits++;
    }

    return (ret >= 0 ? ERR_OK : ERR_WOULDBLOCK);
}

err_t sockinfo_tcp::ip_output_syn_ack(struct pbuf *p, struct tcp_seg *seg, void *v_p_conn,
                                      uint16_t flags)
{
    iovec iovec[64];
    struct iovec *p_iovec = iovec;
    tcp_iovec tcp_iovec_temp; // currently we pass p_desc only for 1 size iovec, since for bigger
                              // size we allocate new buffers
    sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)(((struct tcp_pcb *)v_p_conn)->my_container);
    dst_entry *p_dst = p_si_tcp->m_p_connected_dst_entry;
    int count = 1;
    xlio_wr_tx_packet_attr attr;

    NOT_IN_USE(seg);
    // ASSERT_NOT_LOCKED(p_si_tcp->m_tcp_con_lock);

    if (likely(!p->next)) { // We should hit this case 99% of cases
        tcp_iovec_temp.iovec.iov_base = p->payload;
        tcp_iovec_temp.iovec.iov_len = p->len;
        tcp_iovec_temp.p_desc = (mem_buf_desc_t *)p;
        __log_dbg("p_desc=%p,p->len=%d ", p, p->len);
        p_iovec = (struct iovec *)&tcp_iovec_temp;
    } else {
        for (count = 0; count < 64 && p; ++count) {
            iovec[count].iov_base = p->payload;
            iovec[count].iov_len = p->len;
            p = p->next;
        }

        // We don't expect pbuf chain at all
        if (p) {
            vlog_printf(VLOG_ERROR, "pbuf chain size > 64!!! silently dropped.\n");
            return ERR_OK;
        }
    }

    attr = (xlio_wr_tx_packet_attr)flags;
    if (p_si_tcp->m_p_socket_stats && is_set(attr, XLIO_TX_PACKET_REXMIT)) {
        p_si_tcp->m_p_socket_stats->counters.n_tx_retransmits++;
    }

    ((dst_entry_tcp *)p_dst)->slow_send_neigh(p_iovec, count, p_si_tcp->m_so_ratelimit);

    return ERR_OK;
}

/*static*/ void sockinfo_tcp::tcp_state_observer(void *pcb_container, enum tcp_state new_state)
{
    sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)pcb_container;
    IF_STATS_O(p_si_tcp, p_si_tcp->m_p_socket_stats->tcp_state = new_state);

    if (p_si_tcp->m_state == SOCKINFO_CLOSING && (new_state == CLOSED || new_state == TIME_WAIT)) {
        /*
         * We don't need ULP for a closed socket. TLS layer releases
         * TIS/TIR/DEK objects on reset, so we try to do this in
         * the main thread to mitigate ring lock contention.
         */
        p_si_tcp->reset_ops();
    }

    /* Update daemon about actual state for offloaded connection */
    if (g_p_agent && likely(p_si_tcp->m_sock_offload == TCP_SOCK_LWIP)) {
        p_si_tcp->put_agent_msg((void *)p_si_tcp);
    }
}

uint16_t sockinfo_tcp::get_route_mtu(struct tcp_pcb *pcb)
{
    sockinfo_tcp *tcp_sock = (sockinfo_tcp *)pcb->my_container;
    // in case of listen m_p_connected_dst_entry is still NULL
    if (tcp_sock->m_p_connected_dst_entry) {
        return tcp_sock->m_p_connected_dst_entry->get_route_mtu();
    }

    route_result res;
    sa_family_t family = pcb->is_ipv6 ? AF_INET6 : AF_INET;
    auto rule_key =
        route_rule_table_key(reinterpret_cast<ip_address &>(pcb->local_ip),
                             reinterpret_cast<ip_address &>(pcb->remote_ip), family, pcb->tos);
    if (g_p_route_table_mgr->route_resolve(rule_key, res)) {
        if (res.mtu) {
            vlog_printf(VLOG_DEBUG, "Using route mtu %u\n", res.mtu);
            return res.mtu;
        }

        net_device_val *ndv = g_p_net_device_table_mgr->get_net_device_val(res.if_index);
        if (ndv && ndv->get_mtu() > 0) {
            return ndv->get_mtu();
        }
    }

    vlog_printf(VLOG_DEBUG, "Could not find device, mtu 0 is used\n");
    return 0;
}

void sockinfo_tcp::err_lwip_cb(void *pcb_container, err_t err)
{
    if (!pcb_container) {
        return;
    }

    sockinfo_tcp *conn = (sockinfo_tcp *)pcb_container;
    __log_dbg("[fd=%d] sock=%p lwip_pcb=%p err=%d", conn->m_fd, conn, &(conn->m_pcb), err);

    if (get_tcp_state(&conn->m_pcb) == LISTEN && err == ERR_RST) {
        vlog_printf(VLOG_ERROR, "listen socket should not receive RST\n");
        return;
    }

    // We got RST/error/timeout before the handshake is complete
    if (conn->m_parent) {
        conn->m_parent->handle_incoming_handshake_failure(conn);
        return;
    }

    conn->err_lwip_cb_notify_conn_err(err);

    conn->err_lwip_cb_set_conn_err(err);

    conn->m_sock_wakeup_pipe.do_wakeup();
}

bool sockinfo_tcp::process_peer_ctl_packets(xlio_desc_list_t &peer_packets)
{
    // 2.1 loop on packets of a peer
    while (!peer_packets.empty()) {
        // 2.1.1 get packet from list and find its pcb
        mem_buf_desc_t *desc = peer_packets.front();

        if (0 != m_tcp_con_lock.trylock()) {
            /* coverity[missing_unlock] */
            return false;
        }

        // Listen socket is 3T and so rx.src/dst are set as part of
        // rx_process_buffer_no_flow_id.
        struct tcp_pcb *pcb = get_syn_received_pcb(desc->rx.src, desc->rx.dst);

        // 2.1.2 get the pcb and sockinfo
        if (!pcb) {
            pcb = &m_pcb;
        }
        sockinfo_tcp *sock = (sockinfo_tcp *)pcb->my_container;

        if (sock == this) { // my socket - consider the backlog for the case I am listen socket
            if (m_syn_received.size() >= (size_t)m_backlog && desc->rx.tcp.p_tcp_h->syn) {
                m_tcp_con_lock.unlock();
                break; // skip to next peer
            } else if (safe_mce_sys().tcp_max_syn_rate && desc->rx.tcp.p_tcp_h->syn) {
                static tscval_t tsc_delay =
                    get_tsc_rate_per_second() / safe_mce_sys().tcp_max_syn_rate;
                tscval_t tsc_now;
                gettimeoftsc(&tsc_now);
                if (tsc_now - m_last_syn_tsc < tsc_delay) {
                    m_tcp_con_lock.unlock();
                    break;
                } else {
                    m_last_syn_tsc = tsc_now;
                }
            }
        } else { // child socket from a listener context - switch to child lock
            m_tcp_con_lock.unlock();
            if (sock->m_tcp_con_lock.trylock()) {
                break; // skip to next peer
            }
        }

        // 2.1.3 process the packet and remove it from list
        peer_packets.pop_front();
        sock->m_xlio_thr = true;
        // -- start loop
        desc->inc_ref_count();
        L3_level_tcp_input((pbuf *)desc, pcb);

        if (desc->dec_ref_count() <= 1) {
            sock->m_rx_ctl_reuse_list.push_back(desc); // under sock's lock
        }
        // -- end loop
        sock->m_xlio_thr = false;

        sock->m_tcp_con_lock.unlock();
    }
    return true;
}

void sockinfo_tcp::process_my_ctl_packets()
{
    si_tcp_logfunc("");

    // 0. fast swap of m_rx_ctl_packets_list with temp_list under lock
    xlio_desc_list_t temp_list;

    m_rx_ctl_packets_list_lock.lock();
    temp_list.splice_tail(m_rx_ctl_packets_list);
    m_rx_ctl_packets_list_lock.unlock();

    if (m_backlog == INT_MAX) { // this is a child - no need to demux packets
        process_peer_ctl_packets(temp_list);

        if (!temp_list.empty()) {
            m_rx_ctl_packets_list_lock.lock();
            m_rx_ctl_packets_list.splice_head(temp_list);
            m_rx_ctl_packets_list_lock.unlock();
        }
        return;
    }

    // 1. demux packets in the listener list to map of list per peer (for child this will be
    // skipped)
    while (!temp_list.empty()) {
        mem_buf_desc_t *desc = temp_list.get_and_pop_front();

        static const unsigned int MAX_SYN_RCVD = tcp_ctl_thread_on(safe_mce_sys().tcp_ctl_thread)
            ? safe_mce_sys().sysctl_reader.get_tcp_max_syn_backlog()
            : 0;
        // NOTE: currently, in case tcp_ctl_thread is disabled, only established backlog is
        // supported (no syn-rcvd backlog)
        unsigned int num_con_waiting = m_rx_peer_packets.size();

        if (num_con_waiting < MAX_SYN_RCVD) {
            m_rx_peer_packets[desc->rx.src].push_back(desc);
        } else { // map is full
            peer_map_t::iterator iter = m_rx_peer_packets.find(desc->rx.src);
            if (iter != m_rx_peer_packets.end()) {
                // entry already exists, we can concatenate our packet
                iter->second.push_back(desc);
            } else {
                // drop the packet
                if (desc->dec_ref_count() <= 1) {
                    si_tcp_logdbg("CTL packet drop. established-backlog=%d (limit=%d) "
                                  "num_con_waiting=%d (limit=%d)",
                                  (int)m_syn_received.size(), m_backlog, num_con_waiting,
                                  MAX_SYN_RCVD);
                    m_rx_ctl_reuse_list.push_back(desc);
                }
            }
        }
    }

    // 2. loop on map of peers and process list of packets per peer
    peer_map_t::iterator itr = m_rx_peer_packets.begin();
    while (itr != m_rx_peer_packets.end()) {
        xlio_desc_list_t &peer_packets = itr->second;
        if (!process_peer_ctl_packets(peer_packets)) {
            return;
        }
        // prepare for next map iteration
        if (peer_packets.empty()) {
            m_rx_peer_packets.erase(itr++); // // advance itr before invalidating it by erase
                                            // (itr++ returns the value before advance)
        } else {
            ++itr;
        }
    }
}

void sockinfo_tcp::process_children_ctl_packets()
{
    // handle children
    while (!m_ready_pcbs.empty()) {
        if (m_tcp_con_lock.trylock()) {
            return;
        }
        ready_pcb_map_t::iterator itr = m_ready_pcbs.begin();
        if (itr == m_ready_pcbs.end()) {
            /* coverity[double_unlock] TODO: RM#1049980 */
            m_tcp_con_lock.unlock();
            break;
        }
        sockinfo_tcp *sock = (sockinfo_tcp *)itr->first->my_container;
        /* coverity[double_unlock] TODO: RM#1049980 */
        m_tcp_con_lock.unlock();

        if (sock->m_tcp_con_lock.trylock()) {
            break;
        }
        sock->m_xlio_thr = true;

        while (!sock->m_rx_ctl_packets_list.empty()) {
            sock->m_rx_ctl_packets_list_lock.lock();
            if (sock->m_rx_ctl_packets_list.empty()) {
                sock->m_rx_ctl_packets_list_lock.unlock();
                break;
            }
            mem_buf_desc_t *desc = sock->m_rx_ctl_packets_list.get_and_pop_front();
            sock->m_rx_ctl_packets_list_lock.unlock();
            desc->inc_ref_count();
            L3_level_tcp_input((pbuf *)desc, &sock->m_pcb);
            if (desc->dec_ref_count() <= 1) { // todo reuse needed?
                sock->m_rx_ctl_reuse_list.push_back(desc);
            }
        }
        sock->m_xlio_thr = false;
        sock->m_tcp_con_lock.unlock();

        if (m_tcp_con_lock.trylock()) {
            break;
        }

        /* coverity[double_lock] TODO: RM#1049980 */
        sock->m_rx_ctl_packets_list_lock.lock();
        if (sock->m_rx_ctl_packets_list.empty()) {
            m_ready_pcbs.erase(&sock->m_pcb);
        }
        sock->m_rx_ctl_packets_list_lock.unlock();

        /* coverity[double_unlock] TODO: RM#1049980 */
        m_tcp_con_lock.unlock();
    }
}

void sockinfo_tcp::process_reuse_ctl_packets()
{
    while (!m_rx_ctl_reuse_list.empty()) {
        if (m_tcp_con_lock.trylock()) {
            return;
        }
        mem_buf_desc_t *desc = m_rx_ctl_reuse_list.get_and_pop_front();
        reuse_buffer(desc);
        /* coverity[double_unlock] TODO: RM#1049980 */
        m_tcp_con_lock.unlock();
    }
}

void sockinfo_tcp::process_rx_ctl_packets()
{
    si_tcp_logfunc("");

    process_my_ctl_packets();
    process_children_ctl_packets();
    process_reuse_ctl_packets();
}

// Execute TCP timers of this connection
void sockinfo_tcp::handle_timer_expired()
{
    si_tcp_logfunc("");

    if (tcp_ctl_thread_on(safe_mce_sys().tcp_ctl_thread)) {
        process_rx_ctl_packets();
    }

    tcp_timer();
}

void sockinfo_tcp::abort_connection()
{
    tcp_abort(&(m_pcb));
}

void sockinfo_tcp::handle_incoming_handshake_failure(sockinfo_tcp *child_conn)
{
    child_conn->unlock_tcp_con();

    lock_tcp_con(); // Lock the listen parent socket

    if (m_ready_pcbs.find(&child_conn->m_pcb) != m_ready_pcbs.end()) {
        m_ready_pcbs.erase(&child_conn->m_pcb);
    }

    remove_received_syn_socket(child_conn);

    si_tcp_logfunc("Received-RST/internal-error/timeout in SYN_RCVD state");
    if (m_p_socket_stats) {
        m_p_socket_stats->listen_counters.n_rx_fin++;
        m_p_socket_stats->listen_counters.n_conn_dropped++;
    }
    child_conn->m_parent = nullptr;
    unlock_tcp_con(); // Unlock the listen parent socket

    child_conn->lock_tcp_con();

    if (safe_mce_sys().tcp_ctl_thread != option_tcp_ctl_thread::CTL_THREAD_DELEGATE_TCP_TIMERS) {
        // Object destruction is expected to happen in internal thread. Unless XLIO is in late
        // terminating stage, in which case we don't expect to handle packets.
        // Calling close() under lock will prevent internal thread to delete the object before
        // we finish with the current processing.
        XLIO_CALL(close, child_conn->get_fd());
    } else {
        // With delegate mode calling close() will destroy the socket object and cause access
        // after free in the subsequent flows. Instead, we add the socket for postponed close
        // that will be as part of the delegate timer.
        g_event_handler_manager_local.add_close_postponed_socket(child_conn);
    }
}

err_t sockinfo_tcp::ack_recvd_lwip_cb(void *arg, struct tcp_pcb *tpcb, u16_t ack)
{
    sockinfo_tcp *conn = (sockinfo_tcp *)arg;

    NOT_IN_USE(tpcb); /* to suppress warning in case MAX_DEFINED_LOG_LEVEL */
    assert((uintptr_t)tpcb->my_container == (uintptr_t)arg);

    vlog_func_enter();

    ASSERT_LOCKED(conn->m_tcp_con_lock);

    IF_STATS_O(conn, conn->m_p_socket_stats->n_tx_ready_byte_count -= ack);

    if (conn->sndbuf_available()) {
        NOTIFY_ON_EVENTS(conn, EPOLLOUT);
    }
    vlog_func_exit();

    return ERR_OK;
}

void sockinfo_tcp::tcp_shutdown_rx()
{
    /* Call this method under connection lock */

    NOTIFY_ON_EVENTS(this, EPOLLIN | EPOLLRDHUP);

    /* SOCKETXTREME comment:
     * Add this fd to the ready fd list
     * Note: No issue is expected in case socketxtreme_poll() usage because 'pv_fd_ready_array' is
     * null in such case and as a result update_fd_array() call means nothing
     */
    io_mux_call::update_fd_array(m_iomux_ready_fd_array, m_fd);
    m_sock_wakeup_pipe.do_wakeup();

    tcp_shutdown(&m_pcb, 1, 0);

    if (is_rts() ||
        ((m_sock_state == TCP_SOCK_ASYNC_CONNECT) && (m_conn_state == TCP_CONN_CONNECTED))) {
        m_sock_state = TCP_SOCK_CONNECTED_WR;
    } else {
        m_sock_state = TCP_SOCK_BOUND;
    }
    /*
     * We got FIN or fatal error, means that we will not receive any new
     * data. Need to remove the callback functions
     */
    tcp_recv(&m_pcb, sockinfo_tcp::rx_drop_lwip_cb);
}

err_t sockinfo_tcp::rx_lwip_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p)
{
    sockinfo_tcp *conn = (sockinfo_tcp *)arg;
    uint32_t bytes_to_tcp_recved;
    int rcv_buffer_space;

    NOT_IN_USE(pcb);
    assert((uintptr_t)pcb->my_container == (uintptr_t)arg);

    vlog_func_enter();

    ASSERT_LOCKED(conn->m_tcp_con_lock);

    // if is FIN
    if (unlikely(!p)) {
        return conn->handle_fin(pcb);
    }

    conn->rx_lwip_process_chained_pbufs(p);
    conn->save_packet_info_in_ready_list(p);

    // notify io_mux
    NOTIFY_ON_EVENTS(conn, EPOLLIN);
    io_mux_call::update_fd_array(conn->m_iomux_ready_fd_array, conn->m_fd);

    // OLG: Now we should wakeup all threads that are sleeping on this socket.
    conn->m_sock_wakeup_pipe.do_wakeup();

    /*
     * RCVBUFF Accounting: tcp_recved here(stream into the 'internal' buffer) only if the user
     * buffer is not 'filled'
     */
    rcv_buffer_space = std::max(
        0, conn->m_rcvbuff_max - conn->m_rcvbuff_current - (int)conn->m_pcb.rcv_wnd_max_desired);
    bytes_to_tcp_recved = std::min(rcv_buffer_space, (int)p->tot_len);
    conn->m_rcvbuff_current += p->tot_len;

    conn->rx_lwip_shrink_rcv_wnd(p->tot_len, bytes_to_tcp_recved);

    vlog_func_exit();
    return ERR_OK;
}

inline void sockinfo_tcp::rx_lwip_cb_socketxtreme_helper(pbuf *p)
{
    xlio_socketxtreme_completion_t *completion =
        set_events_socketxtreme(XLIO_SOCKETXTREME_PACKET, false);

    mem_buf_desc_t *current_desc = reinterpret_cast<mem_buf_desc_t *>(p);

    // Is IPv4 only.
    assert(p);
    assert(current_desc->rx.src.get_sa_family() == AF_INET);
    assert(current_desc->rx.n_frags > 0);

    completion->packet.buff_lst = reinterpret_cast<xlio_buff_t *>(p);
    completion->packet.total_len = p->tot_len;
    completion->packet.num_bufs = current_desc->rx.n_frags;

    if (m_n_tsing_flags & SOF_TIMESTAMPING_RAW_HARDWARE) {
        completion->packet.hw_timestamp = current_desc->rx.timestamps.hw;
    }

    m_p_rx_ring->socketxtreme_end_ec_operation();
    save_stats_rx_offload(p->tot_len);
}

err_t sockinfo_tcp::handle_fin(struct tcp_pcb *pcb)
{
    if (is_server()) {
        vlog_printf(VLOG_ERROR, "listen socket should not receive FIN\n");
        return ERR_OK;
    }

    NOT_IN_USE(pcb);
    __log_dbg("[fd=%d] null pbuf sock(%p %p)", m_fd, &(m_pcb), pcb);
    tcp_shutdown_rx();

    return ERR_OK;
}

inline void sockinfo_tcp::rx_lwip_process_chained_pbufs(pbuf *p)
{
    mem_buf_desc_t *p_first_desc = reinterpret_cast<mem_buf_desc_t *>(p);
    p_first_desc->rx.sz_payload = p->tot_len;
    p_first_desc->rx.n_frags = 0;

    if (unlikely(m_p_socket_stats)) {
        m_p_socket_stats->counters.n_rx_bytes += p->tot_len;

        // We go over the p_first_desc again, so decrement what we did in rx_input_cb.
        m_p_socket_stats->strq_counters.n_strq_total_strides -=
            static_cast<uint64_t>(p_first_desc->rx.strides_num);
        m_p_socket_stats->counters.n_rx_data_pkts++;
        // Assume that all chained buffers are GRO packets
        m_p_socket_stats->counters.n_gro += !!p->next;
    }

    // To avoid reset ref count for first mem_buf_desc, save it and set after the while
    int head_ref = p_first_desc->get_ref_count();

    for (auto *p_curr_desc = p_first_desc; p_curr_desc;
         p = p->next, p_curr_desc = p_curr_desc->p_next_desc) {
        /* Here we reset ref count for all mem_buf_desc except for the head (p_first_desc).
        Chain of pbufs can contain some pbufs with ref count >=1 like in ooo or flow tag flows.
        While processing Rx packets we may split buffer chains and we increment ref count
        for the new head of the chain after the split. It will cause a wrong ref count,
        and the buffer won't be reclaimed. Resetting it here will migitate the issue.
        TODO: remove ref count for TCP. */
        p_curr_desc->reset_ref_count();

        save_strq_stats(p_curr_desc->rx.strides_num);
        p_curr_desc->rx.context = this;
        p_first_desc->rx.n_frags++;
        p_curr_desc->rx.frag.iov_base = p->payload;
        p_curr_desc->rx.frag.iov_len = p->len;
        p_curr_desc->p_next_desc = reinterpret_cast<mem_buf_desc_t *>(p->next);
    }

    // To avoid redundant checking for every packet a seperate loop runs
    // only in case timestamps are needed.
    if (m_b_rcvtstamp || m_n_tsing_flags) {
        for (auto *p_curr_desc = p_first_desc; p_curr_desc;
             p_curr_desc = p_curr_desc->p_next_desc) {
            process_timestamps(p_curr_desc);
        }
    }

    p_first_desc->set_ref_count(head_ref);

    IF_STATS(m_p_socket_stats->counters.n_rx_frags += p_first_desc->rx.n_frags);
}

inline void sockinfo_tcp::save_packet_info_in_ready_list(pbuf *p)
{
    m_rx_pkt_ready_list.push_back(reinterpret_cast<mem_buf_desc_t *>(p));
    m_n_rx_pkt_ready_list_count++;
    m_rx_ready_byte_count += p->tot_len;

    if (unlikely(m_p_socket_stats)) {
        m_p_socket_stats->n_rx_ready_byte_count += p->tot_len;
        m_p_socket_stats->n_rx_ready_pkt_count++;
        m_p_socket_stats->counters.n_rx_ready_pkt_max = std::max(
            (uint32_t)m_n_rx_pkt_ready_list_count, m_p_socket_stats->counters.n_rx_ready_pkt_max);
        m_p_socket_stats->counters.n_rx_ready_byte_max = std::max(
            (uint32_t)m_rx_ready_byte_count, m_p_socket_stats->counters.n_rx_ready_byte_max);
    }
}

inline void sockinfo_tcp::rx_lwip_shrink_rcv_wnd(size_t pbuf_tot_len, int bytes_received)
{
    if (likely(bytes_received > 0)) {
        tcp_recved(&(m_pcb), bytes_received);
    }

    int non_tcp_receved_bytes_remaining = pbuf_tot_len - bytes_received;

    if (non_tcp_receved_bytes_remaining > 0) {
        uint32_t bytes_to_shrink = 0;
        if (m_pcb.rcv_wnd_max > m_pcb.rcv_wnd_max_desired) {
            bytes_to_shrink = std::min(m_pcb.rcv_wnd_max - m_pcb.rcv_wnd_max_desired,
                                       static_cast<uint32_t>(non_tcp_receved_bytes_remaining));
            m_pcb.rcv_wnd_max -= bytes_to_shrink;
        }
        m_rcvbuff_non_tcp_recved += non_tcp_receved_bytes_remaining - bytes_to_shrink;
    }
}

err_t sockinfo_tcp::rx_lwip_cb_socketxtreme(void *arg, struct tcp_pcb *pcb, struct pbuf *p)
{
    sockinfo_tcp *conn = (sockinfo_tcp *)arg;

    NOT_IN_USE(pcb);
    assert((uintptr_t)pcb->my_container == (uintptr_t)arg);

    vlog_func_enter();

    ASSERT_LOCKED(conn->m_tcp_con_lock);

    // if is FIN
    if (unlikely(!p)) {
        return conn->handle_fin(pcb);
    }

    conn->rx_lwip_process_chained_pbufs(p);
    conn->rx_lwip_cb_socketxtreme_helper(p);

    /*
     * RCVBUFF Accounting: tcp_recved here(stream into the 'internal' buffer) only if the user
     * buffer is not 'filled'
     */
    int rcv_buffer_space = std::max(
        0, conn->m_rcvbuff_max - conn->m_rcvbuff_current - (int)conn->m_pcb.rcv_wnd_max_desired);
    uint32_t bytes_to_tcp_recved = std::min(rcv_buffer_space, (int)p->tot_len);
    conn->m_rcvbuff_current += p->tot_len;

    conn->rx_lwip_shrink_rcv_wnd(p->tot_len, bytes_to_tcp_recved);

    vlog_func_exit();
    return ERR_OK;
}

err_t sockinfo_tcp::rx_lwip_cb_recv_callback(void *arg, struct tcp_pcb *pcb, struct pbuf *p)
{
    sockinfo_tcp *conn = (sockinfo_tcp *)arg;

    NOT_IN_USE(pcb);
    assert((uintptr_t)pcb->my_container == (uintptr_t)arg);

    vlog_func_enter();

    ASSERT_LOCKED(conn->m_tcp_con_lock);

    // if is FIN
    if (unlikely(!p)) {
        return conn->handle_fin(pcb);
    }

    conn->rx_lwip_process_chained_pbufs(p);

    xlio_recv_callback_retval_t callback_retval = XLIO_PACKET_RECV;

    mem_buf_desc_t *p_first_desc = (mem_buf_desc_t *)p;
    if (conn->m_rx_callback && !conn->m_xlio_thr && !conn->m_n_rx_pkt_ready_list_count) {
        mem_buf_desc_t *tmp;
        xlio_info_t pkt_info;
        int nr_frags = 0;

        pkt_info.struct_sz = sizeof(pkt_info);
        pkt_info.packet_id = (void *)p_first_desc;
        pkt_info.src = conn->m_connected.get_p_sa();
        pkt_info.dst = conn->m_bound.get_p_sa();
        pkt_info.socket_ready_queue_pkt_count = conn->m_n_rx_pkt_ready_list_count;
        pkt_info.socket_ready_queue_byte_count = conn->m_rx_ready_byte_count;

        if (conn->m_n_tsing_flags & SOF_TIMESTAMPING_RAW_HARDWARE) {
            pkt_info.hw_timestamp = p_first_desc->rx.timestamps.hw;
        }
        if (p_first_desc->rx.timestamps.sw.tv_sec) {
            pkt_info.sw_timestamp = p_first_desc->rx.timestamps.sw;
        }

        // fill io vector array with data buffer pointers
        iovec iov[p_first_desc->rx.n_frags];
        nr_frags = 0;
        for (tmp = p_first_desc; tmp; tmp = tmp->p_next_desc) {
            iov[nr_frags++] = tmp->rx.frag;
        }

        // call user callback
        callback_retval =
            conn->m_rx_callback(conn->m_fd, nr_frags, iov, &pkt_info, conn->m_rx_callback_context);
    }

    if (callback_retval == XLIO_PACKET_DROP) {
        conn->m_rx_cb_dropped_list.push_back(p_first_desc);

        // In ZERO COPY case we let the user's application manage the ready queue
    } else {
        if (callback_retval == XLIO_PACKET_RECV) {
            // Save rx packet info in our ready list
            conn->save_packet_info_in_ready_list(p);
        }
        // notify io_mux
        NOTIFY_ON_EVENTS(conn, EPOLLIN);
        io_mux_call::update_fd_array(conn->m_iomux_ready_fd_array, conn->m_fd);

        if (callback_retval != XLIO_PACKET_HOLD) {
            // OLG: Now we should wakeup all threads that are sleeping on this socket.
            conn->m_sock_wakeup_pipe.do_wakeup();
        } else if (conn->m_p_socket_stats) {
            conn->m_p_socket_stats->n_rx_zcopy_pkt_count++;
        }
    }

    /*
     * RCVBUFF Accounting: tcp_recved here(stream into the 'internal' buffer) only if the user
     * buffer is not 'filled'
     */
    uint32_t bytes_to_tcp_recved;
    int rcv_buffer_space = std::max(
        0, conn->m_rcvbuff_max - conn->m_rcvbuff_current - (int)conn->m_pcb.rcv_wnd_max_desired);
    if (callback_retval == XLIO_PACKET_DROP) {
        bytes_to_tcp_recved = (int)p->tot_len;
    } else {
        bytes_to_tcp_recved = std::min(rcv_buffer_space, (int)p->tot_len);
        conn->m_rcvbuff_current += p->tot_len;
    }

    conn->rx_lwip_shrink_rcv_wnd(p->tot_len, bytes_to_tcp_recved);
    vlog_func_exit();
    return ERR_OK;
}

err_t sockinfo_tcp::rx_drop_lwip_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p)
{
    NOT_IN_USE(tpcb);
    NOT_IN_USE(arg);

    vlog_func_enter();

    if (!p) {
        return ERR_OK;
    }

    return ERR_CONN;
}

int sockinfo_tcp::handle_rx_error(bool blocking)
{
    int ret = -1;

    if (g_b_exit) {
        errno = EINTR;
        si_tcp_logdbg("returning with: EINTR");
    } else if (!is_rtr()) {
        lock_tcp_con();
        if (m_conn_state == TCP_CONN_INIT) {
            si_tcp_logdbg("RX on never connected socket");
            errno = ENOTCONN;
        } else if (m_conn_state == TCP_CONN_CONNECTING) {
            si_tcp_logdbg("RX while async-connect on socket");
            errno = EAGAIN;
        } else if (m_conn_state == TCP_CONN_RESETED) {
            si_tcp_logdbg("RX on reseted socket");
            m_conn_state = TCP_CONN_FAILED;
            errno = ECONNRESET;
        } else if (m_conn_state == TCP_CONN_TIMEOUT) {
            si_tcp_logdbg("RX on timed out socket");
            errno = ETIMEDOUT;
        } else {
            si_tcp_logdbg("RX on disconnected socket - EOF");
            ret = 0;
        }
        unlock_tcp_con();
    }

    if ((errno == EBUSY || errno == EWOULDBLOCK) && !blocking) {
        errno = EAGAIN;
    }

    if (m_p_socket_stats) {
        if (errno == EAGAIN) {
            m_p_socket_stats->counters.n_rx_eagain++;
        } else {
            m_p_socket_stats->counters.n_rx_errors++;
        }
    }

    return ret;
}

ssize_t sockinfo_tcp::rx(const rx_call_t call_type, iovec *p_iov, ssize_t sz_iov, int *p_flags,
    sockaddr *__from, socklen_t *__fromlen, struct msghdr *__msg)
{
    si_tcp_logfuncall("");
    int in_flags = *p_flags;
    if (unlikely(m_sock_offload != TCP_SOCK_LWIP)) {
        int ret = 0;
        ret = rx_os(call_type, p_iov, sz_iov, in_flags, __from, __fromlen, __msg);
        save_stats_rx_os(ret);
        return ret;
    }

    if (!is_xlio_socket()) {
        return rx_legacy(call_type, p_iov, sz_iov, p_flags, __from, __fromlen, __msg);
    }

    if (!p_iov || sz_iov <= 0U) {
        return 0;
    }

    int errno_tmp = errno;
    loops_timer rcv_timeout(m_loops_timer.get_timeout_msec());
    int rx_tot_size = 0;
    do {
        int rc = rx_xlio_socket_wait_for_data(in_flags, __msg, rcv_timeout);
        if (rc < 1) {
            // For MSG_WAITALL we could already read some data. We must return it.
            if (rc == 0 && (in_flags & MSG_WAITALL) && rx_tot_size > 0) {
                break;
            }
            return rc;
        }

        // Handle cmsg including TLS-RX only on the first received packet.
        rx_tot_size += rx_xlio_socket_fetch_ready_buffers(
            p_iov, p_iov + sz_iov, (rx_tot_size == 0 ? __msg : nullptr));
    } while (0);
    // Currently MSG_WAITALL and MSG_PEEK are not supported.
    // In case of MSG_WAITALL we should loop here until all data is received.
    // Error queue is not supported.

    if (__from && __fromlen) {
        // For TCP connected 5T fetch from m_connected.
        // For TCP flow-tag we avoid filling packet with src for performance.
        m_connected.get_sa_by_family(__from, *__fromlen, m_family);
    }

    si_tcp_logfunc("RX completed, %d bytes. tid: %d", rx_tot_size, gettid());

    // Restore errno on function entry in case success
    errno = errno_tmp;
    return rx_tot_size;
}

int sockinfo_tcp::rx_xlio_socket_wait_for_data(int in_flags, struct msghdr *__msg, loops_timer &rcv_timeout)
{
    // This conditions ensures that m_rx_pkt_ready_list.front() is not null later.
    if (m_rx_ready_byte_count < 1) {
        bool blocking = BLOCK_THIS_RUN(m_b_blocking, in_flags);
        if ((!blocking && (errno = EAGAIN)) ||
            (rx_xlio_socket_wait_blocking(rcv_timeout) < 1)) {
            int ret = handle_rx_error(blocking);
            if (__msg && ret == 0) {
                /* We don't return a control message in this case. */
                __msg->msg_controllen = 0;
            }
            return ret;
        }
    }

    return 1;
}

int sockinfo_tcp::rx_xlio_socket_wait_blocking(loops_timer &rcv_timeout)
{
    __log_info_func("");
    int32_t busy_loop_count = 0;

    while (m_rx_ready_byte_count < 1 &&
           (busy_loop_count < safe_mce_sys().rx_poll_num || safe_mce_sys().rx_poll_num == -1)) {
        if (unlikely(g_b_exit || !is_rtr())) {
            return -1;
        }

        // If in blocking accept state skip poll phase and go to sleep directly
        if (rcv_timeout.is_timeout()) {
            errno = EAGAIN;
            return -1;
        }

        if (safe_mce_sys().rx_poll_yield_loops > 0 &&
            static_cast<uint32_t>(busy_loop_count) > safe_mce_sys().rx_poll_yield_loops) {
            std::this_thread::yield();
        }

        //m_p_group->poll();

        busy_loop_count++;
        rmb(); // For the CPU to fetch m_rx_ready_byte_count which can be updated from another core.
    }

    lock_tcp_con();

    if (m_rx_ready_byte_count >= 1) {
        unlock_tcp_con();
        return 1;
    }

    // Go to sleep
    si_tcp_logfuncall("%d: Too many loops without data", m_fd);

    // Check if we have a packet in receive queue before we going to sleep and
    // update is_sleeping flag under the same lock to synchronize between
    // this code and wakeup mechanism.

    m_sock_wakeup_pipe.going_to_sleep();
    unlock_tcp_con();

    epoll_event rx_epfd_events[SI_RX_EPFD_EVENT_MAX];
    int ret = SYSCALL(epoll_wait, m_rx_epfd, rx_epfd_events, SI_RX_EPFD_EVENT_MAX, rcv_timeout.time_left_msec());

    lock_tcp_con();
    m_sock_wakeup_pipe.return_from_sleep();
    unlock_tcp_con();

    if (ret <= 0) {
        return ret;
    }

    // Remove wakeup fd only if its found to save syscalls.
    for (int event_idx = 0; event_idx < ret; event_idx++) {
        if (m_sock_wakeup_pipe.is_wakeup_fd(rx_epfd_events[event_idx].data.fd)) { // Wakeup event
            lock_tcp_con();
            m_sock_wakeup_pipe.remove_wakeup_fd();
            unlock_tcp_con();
            break;
        }
    }

    rmb(); // For the CPU to fetch m_rx_ready_byte_count which can be updated from another core.

    if (m_rx_ready_byte_count == 0U) { // Sanity check
        errno = EAGAIN;
        return -1;
    }

    return 1;
}

size_t sockinfo_tcp::rx_xlio_socket_fetch_ready_buffers(
    iovec *p_iov, iovec *p_iov_end, struct msghdr *__msg)
{
    std::lock_guard<decltype(m_tcp_con_lock_app)> lock_app(m_tcp_con_lock_app);
    decltype(m_rx_pkt_ready_list) temp_list;
    int temp_ready_byte_count;
    int temp_rx_ready_list_count;

    {
        // Take all available buffers in a quick shot
        std::lock_guard<decltype(m_tcp_con_lock)> lock(m_tcp_con_lock);
        temp_list.splice_head(m_rx_pkt_ready_list);
        temp_ready_byte_count = m_rx_ready_byte_count;
        temp_rx_ready_list_count = m_n_rx_pkt_ready_list_count;
        m_rx_ready_byte_count = 0U;
        m_n_rx_pkt_ready_list_count = 0;
    }

    mem_buf_desc_t *free_buf_last = nullptr;
    mem_buf_desc_t *free_buf_first;
    mem_buf_desc_t *partial_last = free_buf_first = temp_list.front();
    size_t prev_ready_byte_count = temp_ready_byte_count;
    size_t curr_iov_left = p_iov->iov_len;
    size_t curr_buf_left;
    uint8_t tls_type = partial_last ? partial_last->rx.tls_type : 0U;

    while (partial_last && partial_last->rx.tls_type == tls_type) {
        // we can work with m_rx_pkt_ready_offset outside the lock because only the
        // retriever updates the offset.
        curr_buf_left = partial_last->lwip_pbuf.len - m_rx_pkt_ready_offset;
        if (curr_buf_left > curr_iov_left) {
            memcpy(reinterpret_cast<char *>(p_iov->iov_base) + p_iov->iov_len - curr_iov_left,
                   reinterpret_cast<char *>(partial_last->lwip_pbuf.payload) + m_rx_pkt_ready_offset, curr_iov_left);
            temp_ready_byte_count -= curr_iov_left;
            m_rx_pkt_ready_offset += curr_iov_left;
            curr_iov_left = 0;
        } else {
            memcpy(reinterpret_cast<char *>(p_iov->iov_base) + p_iov->iov_len - curr_iov_left,
                   reinterpret_cast<char *>(partial_last->lwip_pbuf.payload) + m_rx_pkt_ready_offset, curr_buf_left);
            temp_ready_byte_count -= curr_buf_left;
            curr_iov_left -= curr_buf_left;
            temp_list.pop_front();
            free_buf_last = partial_last;
            --temp_rx_ready_list_count;
            m_rx_pkt_ready_offset = 0U;
            partial_last->p_next_desc = temp_list.front();
            partial_last = partial_last->p_next_desc;
        }

        if (!curr_iov_left) {
            if (++p_iov < p_iov_end) {
                curr_iov_left = p_iov->iov_len;
            } else {
                break;
            }
        }
    }

    if (__msg && __msg->msg_control && free_buf_first) {
        if (!rx_xlio_socket_tls_msg(__msg, free_buf_first)) {
            rx_xlio_handle_cmsg(__msg, free_buf_first);
        }
    }

    if (free_buf_last) {
        m_p_group->return_rx_buffers(free_buf_first, free_buf_last);
    }

    {
        std::lock_guard<decltype(m_tcp_con_lock)> lock(m_tcp_con_lock);
        if (!temp_list.empty()) {
            // If the buffers did not fit into iov return them back
            m_rx_pkt_ready_list.splice_head(temp_list);
            m_rx_ready_byte_count += temp_ready_byte_count;
            m_n_rx_pkt_ready_list_count += temp_rx_ready_list_count;
        }

        if (tcp_recved_no_output(&m_pcb, static_cast<uint32_t>(prev_ready_byte_count - temp_ready_byte_count))) {
            if (!m_ack_ready_list_node.is_stack_member()) {
                m_p_group->add_ack_ready_socket(*this);
            }
        }
    }

    return prev_ready_byte_count - temp_ready_byte_count;
}

bool sockinfo_tcp::rx_xlio_socket_tls_msg(struct msghdr *__msg, mem_buf_desc_t* out_buf_list)
{
#ifdef DEFINED_UTLS
    /*
     * kTLS API doesn't require to set TLS_GET_RECORD_TYPE control
     * message for application data records (type 0x17). However,
     * OpenSSL returns an error if we don't insert 0x17 record type.
     */
    if (out_buf_list && out_buf_list->rx.tls_type != 0 &&
        likely(__msg->msg_controllen >= CMSG_SPACE(1))) {
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(__msg);
        cmsg->cmsg_level = SOL_TLS;
        cmsg->cmsg_type = TLS_GET_RECORD_TYPE;
        cmsg->cmsg_len = CMSG_LEN(1);
        *CMSG_DATA(cmsg) = out_buf_list->rx.tls_type;
        __msg->msg_controllen = CMSG_SPACE(1);
        return true;
    }
#endif // DEFINED_UTLS
    return false;
}

void sockinfo_tcp::rx_xlio_handle_cmsg(struct msghdr *msg, mem_buf_desc_t* out_buf_list)
{
    struct cmsg_state cm_state;

    cm_state.mhdr = msg;
    cm_state.cmhdr = CMSG_FIRSTHDR(msg);
    cm_state.cmsg_bytes_consumed = 0;

    if (m_b_rcvtstamp || m_n_tsing_flags) {
        handle_recv_timestamping(&cm_state, &out_buf_list->rx.timestamps);
    }

    cm_state.mhdr->msg_controllen = cm_state.cmsg_bytes_consumed;
}

//
// FIXME: we should not require lwip lock for rx
//
ssize_t sockinfo_tcp::rx_legacy(const rx_call_t call_type, iovec *p_iov, ssize_t sz_iov, int *p_flags,
                                sockaddr *__from, socklen_t *__fromlen, struct msghdr *__msg)
{
    int errno_tmp = errno;
    int total_rx = 0;
    int poll_count = 0;
    int bytes_to_tcp_recved;
    size_t total_iov_sz = 0;
    int out_flags = 0;
    int in_flags = *p_flags;
    bool block_this_run = BLOCK_THIS_RUN(m_b_blocking, in_flags);

    m_loops_timer.start();

    si_tcp_logfuncall("");
    if (unlikely(m_sock_offload != TCP_SOCK_LWIP)) {
        int ret = 0;
        ret = rx_os(call_type, p_iov, sz_iov, in_flags, __from, __fromlen, __msg);
        save_stats_rx_os(ret);
        return ret;
    }

    /* In general, without any special flags, socket options, or ioctls being set,
     * a recv call on a blocking TCP socket will return any number of bytes less than
     * or equal to the size being requested. But unless the socket is closed remotely,
     * interrupted by signal, or in an error state,
     * it will block until at least 1 byte is available.
     * With MSG_ERRQUEUE flag user application can request just information from
     * error queue without any income data.
     */
    if (p_iov && (sz_iov > 0)) {
        total_iov_sz = 1;
        if (unlikely((in_flags & MSG_WAITALL) && !(in_flags & MSG_PEEK))) {
            total_iov_sz = 0;
            for (int i = 0; i < sz_iov; i++) {
                total_iov_sz += p_iov[i].iov_len;
            }
            if (total_iov_sz == 0) {
                return 0;
            }
        }
    }

    si_tcp_logfunc("rx: iov=%p niovs=%d", p_iov, sz_iov);

    /* poll rx queue till we have something */
    lock_tcp_con();

    /* error queue request should be handled first
     * It allows to return immediately during failure with correct
     * error notification without data processing
     */
    if (__msg && __msg->msg_control && (in_flags & MSG_ERRQUEUE)) {
        // coverity[MISSING_LOCK:FALSE] /*Turn off coverity check for missing lock*/
        if (m_error_queue.empty()) {
            errno = EAGAIN;
            unlock_tcp_con();
            return -1;
        }
    }
    return_reuse_buffers_postponed();
    unlock_tcp_con();

    while (m_rx_ready_byte_count < total_iov_sz) {
        if (unlikely(g_b_exit || !is_rtr() || (m_skip_cq_poll_in_rx && (errno = EAGAIN)) ||
                     (rx_wait_lockless(poll_count, block_this_run) < 0))) {
            int ret = handle_rx_error(block_this_run);
            if (__msg && ret == 0) {
                /* We don't return a control message in this case. */
                __msg->msg_controllen = 0;
            }
            return ret;
        }
    }

    lock_tcp_con();

    si_tcp_logfunc("something in rx queues: %d %p", m_n_rx_pkt_ready_list_count,
                   m_rx_pkt_ready_list.front());

    bool process_cmsg = true;
    if (total_iov_sz > 0) {
#ifdef DEFINED_UTLS
        /*
         * kTLS API doesn't require to set TLS_GET_RECORD_TYPE control
         * message for application data records (type 0x17). However,
         * OpenSSL returns an error if we don't insert 0x17 record type.
         */
        if (__msg && __msg->msg_control) {
            mem_buf_desc_t *pdesc = get_front_m_rx_pkt_ready_list();
            if (pdesc && pdesc->rx.tls_type != 0 &&
                likely(__msg->msg_controllen >= CMSG_SPACE(1))) {
                struct cmsghdr *cmsg = CMSG_FIRSTHDR(__msg);
                cmsg->cmsg_level = SOL_TLS;
                cmsg->cmsg_type = TLS_GET_RECORD_TYPE;
                cmsg->cmsg_len = CMSG_LEN(1);
                *CMSG_DATA(cmsg) = pdesc->rx.tls_type;
                __msg->msg_controllen = CMSG_SPACE(1);
                process_cmsg = false;
            }
        }
#endif /* DEFINED_UTLS */

        total_rx = dequeue_packet(p_iov, sz_iov, __from, __fromlen, in_flags, &out_flags);
        if (total_rx < 0) {
            unlock_tcp_con();
            return total_rx;
        }
    }

    /* Handle all control message requests */
    if (__msg && __msg->msg_control && process_cmsg) {
        handle_cmsg(__msg, in_flags);
    }

    /*
     * RCVBUFF Accounting: Going 'out' of the internal buffer: if some bytes are not tcp_recved
     * yet
     * - do that. The packet might not be 'acked' (tcp_recved)
     *
     */
    if (!(in_flags & (MSG_PEEK | MSG_XLIO_ZCOPY))) {
        m_rcvbuff_current -= total_rx;

        // data that was not tcp_recved should do it now.
        if (m_rcvbuff_non_tcp_recved > 0) {
            bytes_to_tcp_recved = std::min(m_rcvbuff_non_tcp_recved, total_rx);
            tcp_recved(&m_pcb, bytes_to_tcp_recved);
            m_rcvbuff_non_tcp_recved -= bytes_to_tcp_recved;
        }
    }

    unlock_tcp_con();

    si_tcp_logfunc("rx completed, %d bytes sent", total_rx);

    /* Restore errno on function entry in case success */
    errno = errno_tmp;

    return total_rx;
}

void sockinfo_tcp::register_timer()
{
    /* A reused time-wait socket will try to add a timer although it is already registered.
     * We should avoid calling register_socket_timer_event unnecessarily because it introduces
     * internal-thread locks contention.
     */
    if (!is_timer_registered()) {
        si_tcp_logdbg("Registering TCP socket timer: socket: %p, timer-col: %p, global-col: %p",
                      this, get_tcp_timer_collection(), g_tcp_timers_collection);

        set_timer_registered(true);
        get_event_mgr()->register_socket_timer_event(this);
    }
}

void sockinfo_tcp::remove_timer()
{
    if (is_timer_registered()) {
        si_tcp_logdbg("Removing TCP socket timer: socket: %p, timer-col: %p, global-col: %p", this,
                      get_tcp_timer_collection(), g_tcp_timers_collection);

        set_timer_registered(false);
        get_event_mgr()->unregister_socket_timer_event(this);
    }
}

void sockinfo_tcp::queue_rx_ctl_packet(struct tcp_pcb *pcb, mem_buf_desc_t *p_desc)
{
    /* in tcp_ctl_thread mode, always lock the child first*/
    p_desc->inc_ref_count();
    lwip_pbuf_init_custom(p_desc);

    sockinfo_tcp *sock = (sockinfo_tcp *)pcb->my_container;

    sock->m_rx_ctl_packets_list_lock.lock();
    sock->m_rx_ctl_packets_list.push_back(p_desc);
    sock->m_rx_ctl_packets_list_lock.unlock();

    if (sock != this) {
        m_ready_pcbs[pcb] = 1;
    }

    if (safe_mce_sys().tcp_ctl_thread == option_tcp_ctl_thread::CTL_THREAD_WITH_WAKEUP) {
        get_tcp_timer_collection()->register_wakeup_event();
    }

    return;
}

bool sockinfo_tcp::rx_input_cb(mem_buf_desc_t *p_rx_pkt_mem_buf_desc_info, void *pv_fd_ready_array)
{
    struct tcp_pcb *pcb = nullptr;
    int dropped_count = 0;

    lock_tcp_con();

    save_strq_stats(p_rx_pkt_mem_buf_desc_info->rx.strides_num);

    m_iomux_ready_fd_array = (fd_array_t *)pv_fd_ready_array;

    if (unlikely(get_tcp_state(&m_pcb) == LISTEN)) {
        // Listen socket is always 3T and so rx.src/dst are set as part of no-flow-id path.
        pcb = get_syn_received_pcb(p_rx_pkt_mem_buf_desc_info->rx.src,
                                   p_rx_pkt_mem_buf_desc_info->rx.dst);
        bool established_backlog_full = false;
        if (!pcb) {
            pcb = &m_pcb;

            /// respect TCP listen backlog - See redmine issue #565962
            /// distinguish between backlog of established sockets vs. backlog of syn-rcvd
            static const unsigned int MAX_SYN_RCVD =
                tcp_ctl_thread_on(safe_mce_sys().tcp_ctl_thread)
                ? safe_mce_sys().sysctl_reader.get_tcp_max_syn_backlog()
                : 0;
            // NOTE: currently, in case tcp_ctl_thread is disabled, only established backlog is
            // supported (no syn-rcvd backlog)

            unsigned int num_con_waiting = m_rx_peer_packets.size();

            // 1st - check established backlog
            if (num_con_waiting > 0 ||
                (m_syn_received.size() >= (size_t)m_backlog &&
                 p_rx_pkt_mem_buf_desc_info->rx.tcp.p_tcp_h->syn)) {
                established_backlog_full = true;
            }

            // 2nd - check that we allow secondary backlog (don't check map of peer packets to
            // avoid races)
            if (MAX_SYN_RCVD == 0 && established_backlog_full) {
                // TODO: consider check if we can now drain into Q of established
                si_tcp_logdbg("SYN/CTL packet drop. established-backlog=%d (limit=%d) "
                              "num_con_waiting=%d (limit=%d)",
                              (int)m_syn_received.size(), m_backlog, num_con_waiting, MAX_SYN_RCVD);
                unlock_tcp_con();
                return false; // return without inc_ref_count() => packet will be dropped
            }
        }

        // 2nd check only worth when MAX_SYN_RCVD>0 for non tcp_ctl_thread
        if (tcp_ctl_thread_on(safe_mce_sys().tcp_ctl_thread) || established_backlog_full) {
            queue_rx_ctl_packet(
                pcb, p_rx_pkt_mem_buf_desc_info); // TODO: need to trigger queue pulling from
                                                  // accept in case no tcp_ctl_thread
            unlock_tcp_con();
            return true;
        }
    } else {
        pcb = &m_pcb;
    }

    p_rx_pkt_mem_buf_desc_info->inc_ref_count();
    lwip_pbuf_init_custom(p_rx_pkt_mem_buf_desc_info);

    dropped_count = m_rx_cb_dropped_list.size();

    sockinfo_tcp *sock = (sockinfo_tcp *)pcb->my_container;
    if (sock != this) {
        sock->m_tcp_con_lock.lock();
    }

    sock->m_xlio_thr = p_rx_pkt_mem_buf_desc_info->rx.is_xlio_thr;
    L3_level_tcp_input((pbuf *)p_rx_pkt_mem_buf_desc_info, pcb);
    sock->m_xlio_thr = false;

    if (sock != this) {
        sock->m_tcp_con_lock.unlock();
    }

    m_iomux_ready_fd_array = nullptr;

    while (dropped_count--) {
        mem_buf_desc_t *p_rx_pkt_desc = m_rx_cb_dropped_list.get_and_pop_front();
        reuse_buffer(p_rx_pkt_desc);
    }

    unlock_tcp_con();

    return true;
}

void sockinfo_tcp::passthrough_unlock(const char *dbg)
{
    setPassthrough();
    unlock_tcp_con();
    si_tcp_logdbg("%s", dbg);
    NOT_IN_USE(dbg); // Suppress --enable-opt-log=high warning
}

/**
 *  try to connect to the dest over RDMA cm
 *  try fallback to the OS connect (TODO)
 */
int sockinfo_tcp::connect(const sockaddr *__to, socklen_t __tolen)
{
    int ret = 0;

    lock_tcp_con();

    /* Connection was closed by RST, timeout, ICMP error
     * or another process disconnected us.
     * Socket should be recreated.
     */
    if (report_connected && is_errorable(&ret)) {
        errno = ECONNABORTED;
        unlock_tcp_con();
        return -1;
    }

    // Calling connect more than once should return error codes
    if (m_sock_state > TCP_SOCK_BOUND) {
        switch (m_sock_state) {
        case TCP_SOCK_CONNECTED_RD:
        case TCP_SOCK_CONNECTED_WR:
        case TCP_SOCK_CONNECTED_RDWR:
            if (report_connected && !m_b_blocking) {
                report_connected = false;
                unlock_tcp_con();
                return 0;
            }
            errno = EISCONN;
            break;
        case TCP_SOCK_ASYNC_CONNECT:
            errno = EALREADY;
            break;
        default:
            // print error so we can better track apps not following our assumptions ;)
            si_tcp_logerr("socket is in wrong state for connect: %d", m_sock_state);
            errno = EADDRINUSE;
            break;
        }
        unlock_tcp_con();
        return -1;
    }

    // take local ip from new sock and local port from acceptor
    if (m_sock_state == TCP_SOCK_INITED && bind(m_bound.get_p_sa(), m_bound.get_socklen()) == -1) {
        passthrough_unlock("non offloaded socket --> connect only via OS");
        return -1;
    }

    m_connected.set_sockaddr(__to, __tolen);
    if (m_sock_state == TCP_SOCK_BOUND_NO_PORT) {
        if (bind(m_bound.get_p_sa(), m_bound.get_socklen()) == -1) {
            m_connected.clear_sa();
            passthrough_unlock("non offloaded socket --> connect only via OS");
            return -1;
        }
    }

    if (!validate_and_convert_mapped_ipv4(m_connected)) {
        passthrough_unlock("Mapped IPv4 on IPv6-Only socket --> connect only via OS");
        return -1;
    }

    create_dst_entry();
    if (!m_p_connected_dst_entry) {
        passthrough_unlock("non offloaded socket --> connect only via OS");
        return -1;
    }

    prepare_dst_to_send(false);

    bool bound_any_addr = m_bound.is_anyaddr();
    if (bound_any_addr) {
        const ip_address &ip = m_p_connected_dst_entry->get_src_addr();
        // The family of local_addr may change due to mapped IPv4.
        m_bound.set_ip_port(m_p_connected_dst_entry->get_sa_family(), &ip, m_bound.get_in_port());
    }

    IF_STATS(m_p_socket_stats->set_bound_if(m_bound));

    sock_addr remote_addr;
    remote_addr.set_sa_family(m_p_connected_dst_entry->get_sa_family());
    remote_addr.set_in_addr(m_p_connected_dst_entry->get_dst_addr());
    remote_addr.set_in_port(m_p_connected_dst_entry->get_dst_port());
    if (!m_p_connected_dst_entry->is_offloaded() ||
        find_target_family(ROLE_TCP_CLIENT, (sockaddr *)&remote_addr, m_bound.get_p_sa()) !=
            TRANS_XLIO) {
        passthrough_unlock("non offloaded socket --> connect only via OS");
        return -1;
    } else if (has_epoll_context()) {
        m_econtext->remove_fd_from_epoll_os(m_fd); // remove fd from os epoll
    }

    if (bound_any_addr) {
        tcp_bind(&m_pcb, reinterpret_cast<const ip_addr_t *>(&m_bound.get_ip_addr()),
                 ntohs(m_bound.get_in_port()), m_pcb.is_ipv6);
    }

    m_conn_state = TCP_CONN_CONNECTING;
    bool success = attach_as_uc_receiver((role_t)NULL, true);
    if (!success) {
        passthrough_unlock("non offloaded socket --> connect only via OS");
        return -1;
    }

    fit_rcv_wnd(true);
    report_connected = true;

    const ip_address &ip = m_connected.get_ip_addr();
    int err =
        tcp_connect(&m_pcb, reinterpret_cast<const ip_addr_t *>(&ip),
                    ntohs(m_connected.get_in_port()), m_pcb.is_ipv6, sockinfo_tcp::connect_lwip_cb);
    if (err != ERR_OK) {
        // todo consider setPassthrough and go to OS
        destructor_helper_tcp();
        m_conn_state = TCP_CONN_FAILED;
        errno = ECONNREFUSED;
        si_tcp_logerr("bad connect, err=%d", err);
        unlock_tcp_con();
        return -1;
    }

    // Now we should register socket to TCP timer.
    // It is important to register it before wait_for_conn_ready_blocking(),
    // since wait_for_conn_ready_blocking may block on epoll_wait and the timer sends SYN
    // rexmits.
    register_timer();

    if (!m_b_blocking) {
        errno = EINPROGRESS;
        m_error_status = EINPROGRESS;
        m_sock_state = TCP_SOCK_ASYNC_CONNECT;
        unlock_tcp_con();
        si_tcp_logdbg("NON blocking connect");
        return -1;
    }

    // Blocking Path
    int rc = wait_for_conn_ready_blocking();
    // Handle ret from blocking connect
    if (rc < 0) {
        // Interrupted wait for blocking socket currently considered as failure.
        if (errno == EINTR || errno == EAGAIN) {
            m_conn_state = TCP_CONN_FAILED;
        }

        // The errno is set inside wait_for_conn_ready_blocking
        // Following closing procedures may change/nullify errno, but this is not
        // the errno that we should return to the application, so we keep it.
        int keep_errno = errno;
        tcp_close(&m_pcb);

        destructor_helper_tcp();
        unlock_tcp_con();
        si_tcp_logdbg("Blocking connect error, m_sock_state=%d", static_cast<int>(m_sock_state));

        errno = keep_errno;
        return -1;
    }

    setPassthrough(false);
    unlock_tcp_con();

    return 0;
}

int sockinfo_tcp::bind(const sockaddr *__addr, socklen_t __addrlen)
{
    si_tcp_logfuncall("");

    int ret = 0;

    si_tcp_logdbg("to %s, m_bind_no_port=%d", sockaddr2str(__addr, __addrlen, true).c_str(),
                  m_bind_no_port);

    if (m_sock_state >= TCP_SOCK_BOUND) {
        // print error so we can better track apps not following our assumptions ;)
        si_tcp_logdbg("socket is in wrong state for bind: %d", m_sock_state);
        errno = EINVAL; // EADDRINUSE; //todo or EINVAL for RM BGATE 1545 case 1
        return -1;
    }
    in_port_t in_port = get_sa_port(__addr, __addrlen);

    lock_tcp_con();

    if (m_bind_no_port && handle_bind_no_port(ret, in_port, __addr, __addrlen)) {
        UNLOCK_RET(ret);
    }

    if (INPORT_ANY == in_port && (m_pcb.so_options & SOF_REUSEADDR)) {
        int reuse = 0;
        ret = SYSCALL(setsockopt, m_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        BULLSEYE_EXCLUDE_BLOCK_START
        if (ret) {
            si_tcp_logerr("Failed to disable SO_REUSEADDR option (ret=%d %m), connection will be "
                          "handled by OS",
                          ret);
            passthrough_unlock("socket bound only via OS");
            return ret;
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        ret = SYSCALL(bind, m_fd, __addr, __addrlen);
        reuse = 1;
        int rv = SYSCALL(setsockopt, m_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        BULLSEYE_EXCLUDE_BLOCK_START
        if (rv) {
            si_tcp_logerr("Failed to enable SO_REUSEADDR option (ret=%d %m)", rv);
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        if (ret < 0) {
            passthrough_unlock("socket bound only via OS");
            return ret;
        }
    } else {
        si_tcp_logdbg("OS bind to %s", sockaddr2str(__addr, __addrlen, true).c_str());
        ret = SYSCALL(bind, m_fd, __addr, __addrlen);
    }

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    if (g_p_app->type != APP_NONE && g_p_app->get_worker_id() >= 0) {
        // For worker ignore OS bind.
    } else
#endif
    {
        if (ret < 0) {
            UNLOCK_RET(ret);
        }
    }

    sock_addr addr;
    socklen_t addr_len = sizeof(addr);

    BULLSEYE_EXCLUDE_BLOCK_START
    if (SYSCALL(getsockname, m_fd, addr.get_p_sa(), &addr_len)) {
        si_tcp_logerr("get sockname failed");
        UNLOCK_RET(-1);
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    validate_and_convert_mapped_ipv4(addr);

    // TODO: mark socket as accepting both os and offloaded connections
    if (!addr.is_supported()) {
        si_tcp_logdbg("Illegal family %d", addr.get_sa_family());
        errno = EAFNOSUPPORT;
        UNLOCK_RET(-1);
    }
    m_pcb.is_ipv6 = (addr.get_sa_family() == AF_INET6);
    // coverity[copy_assignment_call:FALSE] /*Turn off coverity check for COPY_INSTEAD_OF_MOVE*/
    m_bound = addr;

    if (!m_bound.is_anyaddr() &&
        !g_p_net_device_table_mgr->get_net_device_val(
            ip_addr(m_bound.get_ip_addr(), m_bound.get_sa_family()))) {
        // if socket is not bound to INADDR_ANY and not offloaded socket- only bind OS
        m_sock_state = TCP_SOCK_BOUND;
        passthrough_unlock("socket bound only via OS");
        return 0;
    }

    const ip_address &ip = m_bound.get_ip_addr();
    if (ERR_OK !=
        tcp_bind(&m_pcb, reinterpret_cast<const ip_addr_t *>(&ip), ntohs(m_bound.get_in_port()),
                 m_pcb.is_ipv6)) {
        errno = EINVAL;
        UNLOCK_RET(-1);
    }

    m_sock_state = TCP_SOCK_BOUND;

    si_tcp_logdbg("socket bound");

    if (m_p_socket_stats) {
        m_p_socket_stats->set_bound_if(m_bound);
        m_p_socket_stats->bound_port = m_bound.get_in_port();
    }

    UNLOCK_RET(0);
}

int sockinfo_tcp::prepareListen()
{
    transport_t target_family;
    sock_addr addr;
    socklen_t addr_len;
    si_tcp_logfuncall("");

    if (m_sock_offload == TCP_SOCK_PASSTHROUGH) {
        return 1; // passthrough
    }

    if (unlikely(is_incoming())) {
        errno = EINVAL;
        return -1;
    }

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    if (g_p_app->type != APP_NONE) {
        if (m_sock_state == TCP_SOCK_LISTEN_READY) {
            return 0; // prepareListen() had been called before...
        }
    }
#endif

    if (is_server()) {
        return 0; // listen had been called before...
    }

    addr.set_sa_family(m_family);
    addr_len = addr.get_socklen();
    if (m_sock_state != TCP_SOCK_BOUND) {
        /* It is legal application behavior, listen was called without bind,
         * therefore need to call for bind() to get a random port from the OS
         */
        si_tcp_logdbg("listen was called without bind - calling for bind");

        if (bind(addr.get_p_sa(), addr_len) < 0) {
            si_tcp_logdbg("bind failed");
            return 1;
        }
    }

    getsockname(addr.get_p_sa(), &addr_len);
    validate_and_convert_mapped_ipv4(addr);

    lock_tcp_con();
    target_family =
        __xlio_match_tcp_server(TRANS_XLIO, safe_mce_sys().app_id, addr.get_p_sa(), addr_len);
    si_tcp_logdbg("TRANSPORT: %s, sock state = %d", __xlio_get_transport_str(target_family),
                  get_tcp_state(&m_pcb));

    if (target_family == TRANS_OS || m_sock_offload == TCP_SOCK_PASSTHROUGH) {
        setPassthrough();
        m_sock_state = TCP_SOCK_ACCEPT_READY;
    } else {

        // if (target_family == USE_XLIO || target_family == USE_ULP || arget_family ==
        // USE_DEFAULT)
        setPassthrough(false);
        m_sock_state = TCP_SOCK_LISTEN_READY;
    }

    unlock_tcp_con();
    return isPassthrough() ? 1 : 0;
}

int sockinfo_tcp::listen(int backlog)
{
    si_tcp_logfuncall("");

    int orig_backlog = backlog;

    /* Linux manual doesn't describe negative backlog value, however, kernel implementation treats
     * it as the maximum allowed backlog.
     * A backlog argument of 0 may allow the socket to accept connections, in which case the length
     * of the listen queue may be set to an implementation-defined minimum value.
     * Note: backlog behavior depends on safe_mce_sys().tcp_ctl_thread status.
     */
    if (backlog < 0) {
        backlog = safe_mce_sys().sysctl_reader.get_listen_maxconn();
        si_tcp_logdbg("changing listen backlog=%d to the maximum=%d", orig_backlog, backlog);
    } else if (backlog == 0) {
        backlog = 1;
        si_tcp_logdbg("changing listen backlog=%d to the minimum=%d", orig_backlog, backlog);
    } else {
        if (backlog >= 5 && backlog < 128) {
            backlog = 10 + 2 * backlog; // TODO: this place is not clear
        }
        /* If an application calls listen() with a backlog value larger than net.core.somaxconn,
         * then the backlog for that listener will be silently truncated to the somaxconn value.
         */
        if (backlog > safe_mce_sys().sysctl_reader.get_listen_maxconn()) {
            backlog = safe_mce_sys().sysctl_reader.get_listen_maxconn();
            si_tcp_logdbg("truncating listen backlog=%d to the maximun=%d", orig_backlog, backlog);
        }
    }
    lock_tcp_con();

    if (is_server()) {
        // if listen is called again - only update the backlog
        // TODO: check if need to drop item in existing queues
        m_backlog = backlog;
        unlock_tcp_con();
        return 0;
    }
    if (m_sock_state != TCP_SOCK_LISTEN_READY) {
        // print error so we can better track bugs in XLIO)
        si_tcp_logerr("socket is in wrong state for listen: %d", m_sock_state);
        errno = EINVAL;
        unlock_tcp_con();
        return -1;
    }

    m_backlog = backlog;
    m_ready_conn_cnt = 0;

    if (get_tcp_state(&m_pcb) != LISTEN) {

        // Now we know that it is listen socket so we have to treat m_pcb as listen pcb
        // and update the relevant fields of tcp_listen_pcb.
        struct tcp_pcb tmp_pcb;
        memcpy(&tmp_pcb, &m_pcb, sizeof(struct tcp_pcb));
        tcp_listen(&m_pcb, &tmp_pcb);
    }

    m_sock_state = TCP_SOCK_ACCEPT_READY;

    tcp_accept(&m_pcb, sockinfo_tcp::accept_lwip_cb);
    tcp_syn_handled(&m_pcb, sockinfo_tcp::syn_received_lwip_cb);
    tcp_clone_conn(&m_pcb, sockinfo_tcp::clone_conn_cb);
    tcp_accepted_pcb(&m_pcb, sockinfo_tcp::accepted_pcb_cb);

    bool success = attach_as_uc_receiver(ROLE_TCP_SERVER);

    if (!success) {
        /* we will get here if attach_as_uc_receiver failed */
        passthrough_unlock("Fallback the connection to os");
        return SYSCALL(listen, m_fd, orig_backlog);
    }

    // Calling to orig_listen() by default to monitor connection requests for not offloaded
    // sockets
    if (SYSCALL(listen, m_fd, orig_backlog)) {
        // NOTE: The attach_as_uc_receiver at this stage already created steering rules.
        // Packets may arrive into the queues and the application may theoreticaly
        // call accept() with success.
        si_tcp_logdbg("orig_listen failed");
        unlock_tcp_con();
        return -1;
    }

    if (m_rx_epfd != -1) {
        // Add the user's orig fd to the rx epfd handle
        epoll_event ev = {0, {nullptr}};
        ev.events = EPOLLIN;
        ev.data.fd = m_fd;
        int ret = SYSCALL(epoll_ctl, m_rx_epfd, EPOLL_CTL_ADD, ev.data.fd, &ev);
        if (unlikely(ret)) {
            if (errno == EEXIST) {
                si_tcp_logdbg("failed to add user's fd to internal epfd errno=%d (%m)", errno);
            } else {
                si_tcp_logerr("failed to add user's fd to internal epfd errno=%d (%m)", errno);
                destructor_helper_tcp();
                passthrough_unlock("Fallback the connection to os");
                return 0;
            }
        }
    }

    if (tcp_ctl_thread_on(safe_mce_sys().tcp_ctl_thread)) {
        g_p_event_handler_manager->register_socket_timer_event(this);
    }

    unlock_tcp_con();
    return 0;
}

int sockinfo_tcp::rx_verify_available_data()
{
    int poll_count = 0;

    // Poll cq to verify the latest amount of ready bytes
    int ret = rx_wait_helper(poll_count, false);

    if (ret >= 0 || errno == EAGAIN) {
        errno = 0;
        ret = m_rx_ready_byte_count;
    }

    return ret;
}

int sockinfo_tcp::accept_helper(struct sockaddr *__addr, socklen_t *__addrlen,
                                int __flags /* = 0 */)
{
    sockinfo_tcp *ns;
    // todo do one CQ poll and go to sleep even if infinite polling was set
    int poll_count = safe_mce_sys().rx_poll_num; // do one poll and go to sleep (if blocking)
    int ret;

    si_tcp_logfuncall("");

    // if in os pathrough just redirect to os
    if (m_sock_offload == TCP_SOCK_PASSTHROUGH) {
        si_tcp_logdbg("passthrough - go to OS accept()");
        if (__flags) {
            return SYSCALL(accept4, m_fd, __addr, __addrlen, __flags);
        } else {
            return SYSCALL(accept, m_fd, __addr, __addrlen);
        }
    }

    si_tcp_logdbg("socket accept, __addr = %p, __addrlen = %p, *__addrlen = %d", __addr, __addrlen,
                  __addrlen ? *__addrlen : 0);

    if (!is_server()) {
        // print error so we can better track apps not following our assumptions ;)
        si_tcp_logdbg("socket is in wrong state for accept: %d", m_sock_state);
        errno = EINVAL;
        return -1;
    }

    lock_tcp_con();

    si_tcp_logdbg("sock state = %d", get_tcp_state(&m_pcb));
    while (m_ready_conn_cnt == 0 && !g_b_exit) {
        if (m_sock_state != TCP_SOCK_ACCEPT_READY) {
            unlock_tcp_con();
            errno = EINVAL;
            return -1;
        }

        // todo instead of doing blind poll, check if waken-up by OS fd in rx_wait
        //
        // Always try OS accept()

        // Poll OS socket for pending connection
        // smart bit to switch between the two
        pollfd os_fd[1];
        os_fd[0].fd = m_fd;
        os_fd[0].events = POLLIN;
        ret = SYSCALL(poll, os_fd, 1, 0); // Zero timeout - just poll and return quickly
        if (unlikely(ret == -1)) {
            IF_STATS(m_p_socket_stats->counters.n_rx_os_errors++);
            si_tcp_logdbg("SYSCALL(poll) returned with error (errno=%d %m)", errno);
            unlock_tcp_con();
            return -1;
        }
        if (ret == 1) {
            si_tcp_logdbg("SYSCALL(poll) returned with packet");
            unlock_tcp_con();
            if (__flags) {
                return SYSCALL(accept4, m_fd, __addr, __addrlen, __flags);
            } else {
                return SYSCALL(accept, m_fd, __addr, __addrlen);
            }
        }

        if (rx_wait(poll_count, m_b_blocking) < 0) {
            si_tcp_logdbg("interrupted accept");
            unlock_tcp_con();
            return -1;
        }
    }
    if (g_b_exit) {
        si_tcp_logdbg("interrupted accept");
        unlock_tcp_con();
        errno = EINTR;
        return -1;
    }

    si_tcp_logdbg("sock state = %d", get_tcp_state(&m_pcb));
    si_tcp_logdbg("socket accept - has some!!!");
    ns = m_accepted_conns.get_and_pop_front();
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!ns) {
        si_tcp_logpanic("no socket in accepted queue!!! ready count = %d", m_ready_conn_cnt);
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    m_ready_conn_cnt--;
    IF_STATS(m_p_socket_stats->listen_counters.n_conn_backlog--);

    remove_received_syn_socket(ns);

    if (safe_mce_sys().tcp_ctl_thread == option_tcp_ctl_thread::CTL_THREAD_WITH_WAKEUP &&
        !m_rx_peer_packets.empty()) {
        get_tcp_timer_collection()->register_wakeup_event();
    }

    unlock_tcp_con();

    ns->lock_tcp_con();

    if (__addr && __addrlen) {
        if ((ret = ns->getpeername(__addr, __addrlen)) < 0) {
            int errno_tmp = errno;
            ns->unlock_tcp_con();
            close(ns->get_fd());
            errno = errno_tmp;

            /* According accept() man description ECONNABORTED is expected
             * error value in case connection was aborted.
             */
            switch (errno) {
            case ENOTCONN:
                /* accept() expected result
                 * If connection was established in background and client
                 * closed connection forcibly (using RST)
                 */
                errno = ECONNABORTED;
                break;
            default:
                break;
            }

            IF_STATS(m_p_socket_stats->listen_counters.n_conn_dropped++);
            return ret;
        }
    }

    IF_STATS(m_p_socket_stats->listen_counters.n_conn_accepted++);
    if (ns->m_p_socket_stats) {
        ns->m_p_socket_stats->set_connected_ip(ns->m_connected);
        ns->m_p_socket_stats->connected_port = ns->m_connected.get_in_port();
        ns->m_p_socket_stats->set_bound_if(ns->m_bound);
        ns->m_p_socket_stats->bound_port = ns->m_bound.get_in_port();
    }

    if (__flags & SOCK_NONBLOCK) {
        ns->fcntl(F_SETFL, O_NONBLOCK);
    }
    if (__flags & SOCK_CLOEXEC) {
        ns->fcntl(F_SETFD, FD_CLOEXEC);
    }

    ns->unlock_tcp_con();

    si_tcp_logdbg("CONN ACCEPTED: TCP PCB FLAGS: acceptor:0x%x newsock: fd=%d 0x%x new state: %d",
                  m_pcb.flags, ns->m_fd, ns->m_pcb.flags, get_tcp_state(&ns->m_pcb));

    if (safe_mce_sys().xlio_threads > 0) {
        poll_group *pg = ns->get_poll_group();
        if (0 == ns->detach_xlio_group()) {
            pg->poll();
            g_p_xlio_thread_manager->add_accepted_socket(ns);
        }
    }

    return ns->m_fd;
}

int sockinfo_tcp::accept(struct sockaddr *__addr, socklen_t *__addrlen)
{
    si_tcp_logfuncall("");

    return accept_helper(__addr, __addrlen);
}

int sockinfo_tcp::accept4(struct sockaddr *__addr, socklen_t *__addrlen, int __flags)
{
    si_tcp_logfuncall("");
    si_tcp_logdbg("socket accept4, flags=%d", __flags);

    return accept_helper(__addr, __addrlen, __flags);
}

sockinfo_tcp *sockinfo_tcp::accept_clone()
{
    sockinfo_tcp *si;
    int fd;

    // Clone is always called first when a SYN packet received by a listen socket.
    IF_STATS(m_p_socket_stats->listen_counters.n_rx_syn++);

    if (is_xlio_socket()) {
        struct xlio_socket_attr attr = {
            .flags = 0, /* unused */
            .domain = (int)m_family,
            .group = reinterpret_cast<xlio_poll_group_t>(m_p_group),
            .userdata_sq = 0,
        };
        xlio_socket_t sock;
        int rc = xlio_socket_create(&attr, &sock);
        if (rc != 0) {
            si_tcp_logdbg("Couldn't create XLIO socket (errno=%d)", errno);
            IF_STATS(m_p_socket_stats->listen_counters.n_conn_dropped++);
            return nullptr;
        }
        si = reinterpret_cast<sockinfo_tcp *>(sock);
    } else {
        // Create the socket object. We skip shadow sockets for incoming connections.
        fd = socket_internal(m_family, SOCK_STREAM, 0, false, false);
        if (fd < 0) {
            IF_STATS(m_p_socket_stats->listen_counters.n_conn_dropped++);
            return nullptr;
        }

        si = dynamic_cast<sockinfo_tcp *>(fd_collection_get_sockfd(fd));
        if (!si) {
            si_tcp_logwarn("Can not get accept socket from FD collection");
            XLIO_CALL(close, fd);
            return nullptr;
        }
    }

    // This method is called from a flow which assumes that the socket is locked
    // (tcp_listen_input, L3_level_tcp_input).
    // Since we created a new socket and we are about to add it to the timers,
    // we need to make sure it is also locked for further processing.
    si->lock_tcp_con();

    si->m_parent = this;
    si->m_b_incoming = true;

    si->m_sock_state = TCP_SOCK_BOUND;
    si->setPassthrough(false);

    // Inherit parent ring allocation logic
    if (si->m_ring_alloc_log_rx != m_ring_alloc_log_rx) {
        si->set_ring_logic_rx(m_ring_alloc_log_rx);
    }
    if (si->m_ring_alloc_log_tx != m_ring_alloc_log_tx) {
        si->set_ring_logic_tx(m_ring_alloc_log_tx);
    }

    if (tcp_ctl_thread_on(safe_mce_sys().tcp_ctl_thread)) {
        tcp_ip_output(&si->m_pcb, sockinfo_tcp::ip_output_syn_ack);
    }

    return si;
}

void sockinfo_tcp::accept_connection_xlio_socket(sockinfo_tcp *new_sock)
{
    remove_received_syn_socket(new_sock);
    m_p_group->m_socket_accept_cb(reinterpret_cast<xlio_socket_t>(new_sock),
                                  reinterpret_cast<xlio_socket_t>(this),
                                  m_xlio_socket_userdata);
}

void sockinfo_tcp::remove_received_syn_socket(sockinfo_tcp *accepted)
{
    class flow_tuple key;
    sockinfo_tcp::create_flow_tuple_key_from_pcb(key, &(accepted->m_pcb));

    // The PCB should be removed from the listen socket list of awaiting PCBs.
    if (!m_syn_received.erase(key)) {
        si_tcp_logwarn("Unable to find the established pcb in m_syn_received");
    }
}

// Must be taken under parent's tcp connection lock
void sockinfo_tcp::accept_connection_socketxtreme(sockinfo_tcp *parent, sockinfo_tcp *child)
{
    parent->remove_received_syn_socket(child);

    parent->unlock_tcp_con();
    child->lock_tcp_con();

    if (child->m_p_socket_stats) {
        child->m_p_socket_stats->set_connected_ip(child->m_connected);
        child->m_p_socket_stats->connected_port = child->m_connected.get_in_port();
        child->m_p_socket_stats->set_bound_if(child->m_bound);
        child->m_p_socket_stats->bound_port = child->m_bound.get_in_port();
    }

    xlio_socketxtreme_completion_t &completion =
        *(child->set_events_socketxtreme(XLIO_SOCKETXTREME_NEW_CONNECTION_ACCEPTED, false));
    completion.listen_fd = parent->get_fd();

    child->m_connected.get_sa(reinterpret_cast<sockaddr *>(&completion.src),
                              static_cast<socklen_t>(sizeof(completion.src)));
    child->m_p_rx_ring->socketxtreme_end_ec_operation();

    child->unlock_tcp_con();
    parent->lock_tcp_con();

    __log_dbg("CONN AUTO ACCEPTED: TCP PCB FLAGS: acceptor:0x%x newsock: fd=%d 0x%x new state: %d",
              parent->m_pcb.flags, child->m_fd, child->m_pcb.flags, get_tcp_state(&child->m_pcb));
}

err_t sockinfo_tcp::accept_lwip_cb(void *arg, struct tcp_pcb *child_pcb, err_t err)
{
    sockinfo_tcp *conn = (sockinfo_tcp *)(arg);
    sockinfo_tcp *new_sock;
    bool conn_nagle_disabled;

    if (!conn || !child_pcb) {
        return ERR_VAL;
    }

    __log_dbg("initial state=%x", get_tcp_state(&conn->m_pcb));
    __log_dbg("accept cb: arg=%p, new pcb=%p err=%d", arg, child_pcb, err);
    if (err != ERR_OK) {
        vlog_printf(VLOG_ERROR, "%s:%d: accept cb failed\n", __func__, __LINE__);
        return err;
    }
    if (conn->m_sock_state != TCP_SOCK_ACCEPT_READY) {
        __log_dbg("socket is not accept ready!");
        return ERR_RST;
    }
    // make new socket
    __log_dbg("new stateb4clone=%x", get_tcp_state(child_pcb));
    new_sock = (sockinfo_tcp *)child_pcb->my_container;

    if (!new_sock) {
        vlog_printf(VLOG_ERROR, "%s:%d: failed to clone socket\n", __func__, __LINE__);
        return ERR_RST;
    }

    tcp_ip_output(&new_sock->m_pcb, sockinfo_tcp::ip_output);
    tcp_arg(&new_sock->m_pcb, new_sock);

    if (new_sock->is_xlio_socket()) {
        tcp_recv(&new_sock->m_pcb, conn->m_pcb.recv);
    } else if (safe_mce_sys().enable_socketxtreme) {
        tcp_recv(&new_sock->m_pcb, sockinfo_tcp::rx_lwip_cb_socketxtreme);
    } else {
        tcp_recv(&new_sock->m_pcb, sockinfo_tcp::rx_lwip_cb);
    }

    if (new_sock->is_xlio_socket()) {
        tcp_err(&new_sock->m_pcb, sockinfo_tcp::err_lwip_cb_xlio_socket);
    } else {
        tcp_err(&new_sock->m_pcb, sockinfo_tcp::err_lwip_cb);
    }

    ASSERT_LOCKED(new_sock->m_tcp_con_lock);

    new_sock->m_sock_state = TCP_SOCK_CONNECTED_RDWR;

    __log_dbg("listen(fd=%d) state=%x: new sock(fd=%d) state=%x", conn->m_fd,
              get_tcp_state(&conn->m_pcb), new_sock->m_fd, get_tcp_state(&new_sock->m_pcb));

    /* Configure Nagle algorithm settings as they were set at the parent socket.
       This can happened if XLIO_TCP_NAGLE flag was set, but we disabled it for the parent
       socket.
     */
    if ((conn_nagle_disabled = tcp_nagle_disabled(&conn->m_pcb)) !=
        tcp_nagle_disabled(&new_sock->m_pcb)) {
        conn_nagle_disabled ? tcp_nagle_disable(&new_sock->m_pcb)
                            : tcp_nagle_enable(&new_sock->m_pcb);
    }

    if (new_sock->m_conn_state == TCP_CONN_INIT) {
        // in case m_conn_state is not in one of the error states
        new_sock->m_conn_state = TCP_CONN_CONNECTED;
    }

    /* if attach failed, we should continue getting traffic through the listen socket */
    // todo register as 3-tuple rule for the case the listener is gone?
    if (safe_mce_sys().xlio_threads == 0U) {
        if (!new_sock->m_b_attached) {
            new_sock->attach_as_uc_receiver(role_t(NULL), true);
            new_sock->m_b_attached = true;
        }
    }

    if (tcp_ctl_thread_on(safe_mce_sys().tcp_ctl_thread)) {
        new_sock->m_xlio_thr = true;

        // Before handling packets from flow steering the child should process everything it got
        // from parent
        while (!new_sock->m_rx_ctl_packets_list.empty()) {
            xlio_desc_list_t temp_list;
            new_sock->m_rx_ctl_packets_list_lock.lock();
            temp_list.splice_tail(new_sock->m_rx_ctl_packets_list);
            new_sock->m_rx_ctl_packets_list_lock.unlock();

            while (!temp_list.empty()) {
                mem_buf_desc_t *desc = temp_list.get_and_pop_front();
                if (likely(desc)) {
                    desc->inc_ref_count();
                    L3_level_tcp_input((pbuf *)desc, &new_sock->m_pcb);
                    if (desc->dec_ref_count() <= 1) { // todo reuse needed?
                        new_sock->m_rx_ctl_reuse_list.push_back(desc);
                    }
                }
            }
        }
        new_sock->m_xlio_thr = false;
    }

    // Set this before moving socket to m_accepted_conns.
    // In case of err_lwip_cb we will not handle new_sock as
    // half open but treat it the same as error on accept ready socket.
    new_sock->m_parent = nullptr;

    new_sock->unlock_tcp_con();

    conn->lock_tcp_con();

    // todo check that listen socket was not closed by now ? (is_server())
    conn->m_ready_pcbs.erase(&new_sock->m_pcb);

    if (conn->is_xlio_socket() && conn->m_p_group->m_socket_accept_cb) {
        conn->accept_connection_xlio_socket(new_sock);
    } else if (safe_mce_sys().enable_socketxtreme) {
        accept_connection_socketxtreme(conn, new_sock);
    } else {
        conn->m_accepted_conns.push_back(new_sock);
        conn->m_ready_conn_cnt++;

        NOTIFY_ON_EVENTS(conn, EPOLLIN);
    }

    if (conn->m_p_socket_stats) {
        conn->m_p_socket_stats->listen_counters.n_conn_established++;
        conn->m_p_socket_stats->listen_counters.n_conn_backlog++;
    }

    // Now we should wakeup all threads that are sleeping on this socket.
    conn->m_sock_wakeup_pipe.do_wakeup();
    // Now we should register the child socket to TCP timer

    conn->unlock_tcp_con();

    new_sock->lock_tcp_con();

    return ERR_OK;
}

void sockinfo_tcp::create_flow_tuple_key_from_pcb(flow_tuple &key, struct tcp_pcb *pcb)
{
    if (pcb->is_ipv6) {
        key =
            flow_tuple(ip_address((const in6_addr &)pcb->local_ip.ip6.addr), htons(pcb->local_port),
                       ip_address((const in6_addr &)pcb->remote_ip.ip6.addr),
                       htons(pcb->remote_port), PROTO_TCP, AF_INET6);
    } else {
        key = flow_tuple(ip_address(pcb->local_ip.ip4.addr), htons(pcb->local_port),
                         ip_address(pcb->remote_ip.ip4.addr), htons(pcb->remote_port), PROTO_TCP,
                         AF_INET);
    }
}

mem_buf_desc_t *sockinfo_tcp::get_front_m_rx_pkt_ready_list()
{
    return m_rx_pkt_ready_list.front();
}

size_t sockinfo_tcp::get_size_m_rx_pkt_ready_list()
{
    return m_rx_pkt_ready_list.size();
}

void sockinfo_tcp::pop_front_m_rx_pkt_ready_list()
{
    m_rx_pkt_ready_list.pop_front();
}

void sockinfo_tcp::push_back_m_rx_pkt_ready_list(mem_buf_desc_t *buff)
{
    m_rx_pkt_ready_list.push_back(buff);
}

struct tcp_pcb *sockinfo_tcp::get_syn_received_pcb(const flow_tuple &key) const
{
    struct tcp_pcb *ret_val = nullptr;
    syn_received_map_t::const_iterator itr;

    itr = m_syn_received.find(key);
    if (itr != m_syn_received.end()) {
        ret_val = itr->second;
    }
    return ret_val;
}

struct tcp_pcb *sockinfo_tcp::get_syn_received_pcb(const sock_addr &src, const sock_addr &dst)
{
    // Pay attention at the mixed dst and src order.
    flow_tuple key(dst.get_ip_addr(), dst.get_in_port(), src.get_ip_addr(), src.get_in_port(),
                   PROTO_TCP, dst.get_sa_family());
    return get_syn_received_pcb(key);
}

err_t sockinfo_tcp::clone_conn_cb(void *arg, struct tcp_pcb **newpcb)
{
    sockinfo_tcp *new_sock;
    err_t ret_val = ERR_OK;

    sockinfo_tcp *conn = (sockinfo_tcp *)((arg));

    if (!conn || !newpcb) {
        return ERR_VAL;
    }

    ASSERT_LOCKED(conn->m_tcp_con_lock);
    conn->m_tcp_con_lock.unlock();

    new_sock = conn->accept_clone();

    if (new_sock) {
        *newpcb = (struct tcp_pcb *)(&new_sock->m_pcb);
        new_sock->m_pcb.my_container = (void *)new_sock;
        /* XXX We have to search for correct listen socket every time,
         * because the listen socket may be closed and reopened. */
        new_sock->m_pcb.listen_sock = (void *)conn;
    } else {
        ret_val = ERR_MEM;
    }

    conn->m_tcp_con_lock.lock();

    return ret_val;
}

void sockinfo_tcp::accepted_pcb_cb(struct tcp_pcb *accepted_pcb)
{
    // A new pcb is always locked. When this callback is called the new pcb is ready
    // and all related processing is done. Now it must be unlocked.
    sockinfo_tcp *accepted_sock = reinterpret_cast<sockinfo_tcp *>(accepted_pcb->my_container);
    ASSERT_LOCKED(accepted_sock->m_tcp_con_lock);
    accepted_sock->unlock_tcp_con();
}

err_t sockinfo_tcp::syn_received_timewait_cb(void *arg, struct tcp_pcb *newpcb)
{
    sockinfo_tcp *listen_sock = (sockinfo_tcp *)((arg));

    if (unlikely(!listen_sock || !newpcb)) {
        return ERR_VAL;
    }

    sockinfo_tcp *new_sock = (sockinfo_tcp *)((newpcb->my_container));

    ASSERT_LOCKED(new_sock->m_tcp_con_lock);
    if (unlikely(!new_sock->is_incoming())) {
        return ERR_VAL;
    }

    /*
     * We reuse socket, so remove ULP. Currently there is no interface to
     * check whether an ULP is attached, therefore, we reset it
     * unconditionally.
     */
    new_sock->reset_ops();

    new_sock->m_b_blocking = true;

    /* Dump statistics of the previous incarnation of the socket. */
    IF_STATS_O(new_sock, print_full_stats(new_sock->m_p_socket_stats, nullptr, g_stats_file));

    new_sock->socket_stats_init();

    /* Reset zerocopy state */
    atomic_set(&new_sock->m_zckey, 0);
    new_sock->m_last_zcdesc = nullptr;
    new_sock->m_b_zc = false;

    new_sock->m_state = SOCKINFO_OPENED;
    new_sock->m_sock_state = TCP_SOCK_INITED;
    new_sock->m_conn_state = TCP_CONN_INIT;
    new_sock->m_parent = listen_sock;

    if (safe_mce_sys().enable_socketxtreme) {
        tcp_recv(&new_sock->m_pcb, sockinfo_tcp::rx_lwip_cb_socketxtreme);
    } else {
        tcp_recv(&new_sock->m_pcb, sockinfo_tcp::rx_lwip_cb);
    }

    tcp_err(&new_sock->m_pcb, sockinfo_tcp::err_lwip_cb);
    tcp_sent(&new_sock->m_pcb, sockinfo_tcp::ack_recvd_lwip_cb);
    new_sock->m_pcb.syn_tw_handled_cb = nullptr;
    new_sock->m_sock_wakeup_pipe.wakeup_clear();
    if (tcp_ctl_thread_on(safe_mce_sys().tcp_ctl_thread)) {
        tcp_ip_output(&new_sock->m_pcb, sockinfo_tcp::ip_output_syn_ack);
    }

    new_sock->m_rcvbuff_max = std::max(listen_sock->m_rcvbuff_max, 2 * new_sock->m_pcb.mss);
    new_sock->fit_rcv_wnd(true);

    new_sock->register_timer();

    listen_sock->m_tcp_con_lock.lock();
    new_sock->m_pcb.callback_arg = arg;
    // Socket socket options
    listen_sock->set_sock_options(new_sock);

    flow_tuple key;
    create_flow_tuple_key_from_pcb(key, newpcb);
    listen_sock->m_syn_received[key] = newpcb;

    IF_STATS_O(listen_sock, listen_sock->m_p_socket_stats->listen_counters.n_rx_syn_tw++);
    listen_sock->m_tcp_con_lock.unlock();
    assert(g_p_fd_collection);
    g_p_fd_collection->reuse_sockfd(new_sock->m_fd, new_sock);

    return ERR_OK;
}

err_t sockinfo_tcp::syn_received_lwip_cb(void *arg, struct tcp_pcb *newpcb)
{
    sockinfo_tcp *listen_sock = (sockinfo_tcp *)((arg));

    if (!listen_sock || !newpcb) {
        return ERR_VAL;
    }

    sockinfo_tcp *new_sock = (sockinfo_tcp *)((newpcb->my_container));

    ASSERT_LOCKED(listen_sock->m_tcp_con_lock);

    // Inherit properties from the parent.
    new_sock->set_conn_properties_from_pcb();

    new_sock->m_rcvbuff_max = std::max(listen_sock->m_rcvbuff_max, 2 * new_sock->m_pcb.mss);
    new_sock->fit_rcv_wnd(true);

    listen_sock->set_sock_options(new_sock);

    listen_sock->m_tcp_con_lock.unlock();

    new_sock->create_dst_entry();
    // Pass true for passive socket to skip the transport rules checking.
    bool is_new_offloaded =
        new_sock->m_p_connected_dst_entry && new_sock->prepare_dst_to_send(true);

    /* This can happen if there is no route back to the syn sender. So we just need to ignore it.
     * We set the state to close so we won't try to send fin when we don't have route.
     */
    if (!is_new_offloaded) {
        new_sock->setPassthrough();
        set_tcp_state(&new_sock->m_pcb, CLOSED);

        /* This method is called from a flow (tcp_listen_input, L3_level_tcp_input) which priorly
         * called clone_conn_cb which creates a locked new socket. Before we call to close() we
         * need to unlock the socket, so close() can perform as a regular close() call.
         */
        new_sock->unlock_tcp_con();

        close(new_sock->get_fd());
        listen_sock->m_tcp_con_lock.lock();
        IF_STATS_O(listen_sock, listen_sock->m_p_socket_stats->listen_counters.n_conn_dropped++);
        return ERR_ABRT;
    }

    new_sock->register_timer();

    listen_sock->m_tcp_con_lock.lock();

    flow_tuple key;
    create_flow_tuple_key_from_pcb(key, newpcb);

    listen_sock->m_syn_received[key] = newpcb;

    return ERR_OK;
}

err_t sockinfo_tcp::syn_received_drop_lwip_cb(void *arg, struct tcp_pcb *newpcb)
{
    sockinfo_tcp *listen_sock = (sockinfo_tcp *)((arg));

    if (!listen_sock || !newpcb) {
        return ERR_VAL;
    }

    sockinfo_tcp *new_sock = (sockinfo_tcp *)((newpcb->my_container));

    ASSERT_LOCKED(listen_sock->m_tcp_con_lock);
    listen_sock->m_tcp_con_lock.unlock();

    new_sock->set_conn_properties_from_pcb();
    new_sock->create_dst_entry();
    if (new_sock->m_p_connected_dst_entry) {
        new_sock->prepare_dst_to_send(
            true); // true for passive socket to skip the transport rules checking
        tcp_arg(&(new_sock->m_pcb), new_sock);
        new_sock->abort_connection();
    }

    // This method is called from a flow (tcp_listen_input, L3_level_tcp_input) which priorly
    // called clone_conn_cb which creates a locked new socket. Before we call to close() we need
    // to unlock the socket, so close() can perform as a regular close() call.
    new_sock->unlock_tcp_con();

    close(new_sock->get_fd());

    listen_sock->m_tcp_con_lock.lock();

    return ERR_ABRT;
}

void sockinfo_tcp::set_conn_properties_from_pcb()
{
    // setup peer address and local address
    if (m_pcb.is_ipv6) {
        m_connected.set_ip_port(AF_INET6, &m_pcb.remote_ip.ip6.addr, htons(m_pcb.remote_port));
        m_bound.set_ip_port(AF_INET6, &m_pcb.local_ip.ip6.addr, htons(m_pcb.local_port));
    } else {
        m_connected.set_ip_port(AF_INET, &m_pcb.remote_ip.ip4.addr, htons(m_pcb.remote_port));
        m_bound.set_ip_port(AF_INET, &m_pcb.local_ip.ip4.addr, htons(m_pcb.local_port));
    }
}

void sockinfo_tcp::set_sock_options(sockinfo_tcp *new_sock)
{
    si_tcp_logdbg("Applying all socket options on %p, fd %d", new_sock, new_sock->get_fd());

    for (const auto &opt : m_socket_options_list) {
        new_sock->setsockopt(opt->level, opt->optname, opt->optval, opt->optlen);
    }
    errno = 0;

    si_tcp_logdbg("set_sock_options completed");
}

err_t sockinfo_tcp::connect_lwip_cb(void *arg, struct tcp_pcb *tpcb, err_t err)
{
    sockinfo_tcp *conn = (sockinfo_tcp *)arg;
    bool is_connected = false;
    NOT_IN_USE(tpcb);

    __log_dbg("connect cb: arg=%p, pcp=%p err=%d", arg, tpcb, err);

    if (!conn || !tpcb) {
        return ERR_VAL;
    }

    conn->lock_tcp_con();

    if (conn->m_conn_state == TCP_CONN_TIMEOUT) {
        // tcp_si_logdbg("conn timeout");
        conn->m_error_status = ETIMEDOUT;
        conn->unlock_tcp_con();
        return ERR_OK;
    }
    if (err == ERR_OK) {
        conn->m_conn_state = TCP_CONN_CONNECTED;
        conn->m_sock_state = TCP_SOCK_CONNECTED_RDWR; // async connect verification
        conn->m_error_status = 0;
        if (conn->m_rcvbuff_max < 2 * conn->m_pcb.mss) {
            conn->m_rcvbuff_max = 2 * conn->m_pcb.mss;
        }
        conn->fit_rcv_wnd(false);
        is_connected = true;
    } else {
        conn->m_error_status = ECONNREFUSED;
        conn->m_conn_state = TCP_CONN_FAILED;
    }

    NOTIFY_ON_EVENTS(conn, EPOLLOUT);
    // OLG: Now we should wakeup all threads that are sleeping on this socket.
    conn->m_sock_wakeup_pipe.do_wakeup();

    if (conn->m_p_socket_stats) {
        conn->m_p_socket_stats->set_connected_ip(conn->m_connected);
        conn->m_p_socket_stats->connected_port = conn->m_connected.get_in_port();
    }

    conn->unlock_tcp_con();

    if (is_connected) {
        conn->xlio_socket_event(XLIO_SOCKET_EVENT_ESTABLISHED, 0);
    }
    return ERR_OK;
}

int sockinfo_tcp::wait_for_conn_ready_blocking()
{
    int poll_count = 0;

    si_tcp_logfuncall("");

    while (m_conn_state == TCP_CONN_CONNECTING && m_sock_state != TCP_SOCK_INITED) {
        /*In case of connect error err_lwip_cb is called and not connect_lwip_cb
         * therefore in this case the m_conn_state will not be changed only
         * m_sock_state
         */
        if (rx_wait(poll_count, true) < 0) {
            si_tcp_logdbg("connect interrupted");

            // Internally rx_wait uses epoll_wait wich may return unrecoverable error.
            // However, we do not want to expose internal errors due to epoll usage to the
            // outside. Consequently, since this method is used by blocking connect, we rewrite
            // the errno with one that is compatible with connect() API.
            if (errno != EINTR && errno != EAGAIN) {
                errno = EIO;
                m_conn_state = TCP_CONN_FAILED;
            }
            return -1;
        }

        if (unlikely(g_b_exit)) {
            errno = EINTR;
            return -1;
        }
    }
    if (m_sock_state == TCP_SOCK_INITED) {
        // we get here if err_lwip_cb() was called and set m_sock_state=TCP_SOCK_INITED
        m_conn_state = TCP_CONN_FAILED;
        errno = ECONNREFUSED;
        si_tcp_logdbg("got connection error");
        // if we got here, bind succeeded earlier (in connect()), so change m_sock_state back to
        // TCP_SOCK_BOUND to avoid binding again in case of recalling connect()
        m_sock_state = TCP_SOCK_BOUND;
        return -1;
    }
    if (m_conn_state != TCP_CONN_CONNECTED) {
        if (m_conn_state == TCP_CONN_TIMEOUT) {
            errno = ETIMEDOUT;
        } else {
            errno = ECONNREFUSED;
            if (m_conn_state < TCP_CONN_FAILED) {
                m_conn_state = TCP_CONN_FAILED;
            }
        }

        si_tcp_logdbg("bad connect -> timeout or none listening");
        return -1;
    }
    si_tcp_logdbg("+++ CONNECT OK!!!! ++++");
    m_sock_state = TCP_SOCK_CONNECTED_RDWR;
    si_tcp_logdbg("TCP PCB FLAGS: 0x%x", m_pcb.flags);
    return 0;
}

int sockinfo_tcp::os_epoll_wait(epoll_event *ep_events, int maxevents)
{
    return (
        likely(safe_mce_sys().tcp_ctl_thread !=
               option_tcp_ctl_thread::CTL_THREAD_DELEGATE_TCP_TIMERS)
            ? SYSCALL(epoll_wait, m_rx_epfd, ep_events, maxevents, m_loops_timer.time_left_msec())
            : os_epoll_wait_with_tcp_timers(ep_events, maxevents));
}

int sockinfo_tcp::os_epoll_wait_with_tcp_timers(epoll_event *ep_events, int maxevents)
{
    int rc;
    int sys_timer_resolution_msec = static_cast<int>(safe_mce_sys().tcp_timer_resolution_msec);
    do {
        int next_timeout =
            (m_loops_timer.time_left_msec() < 0 // Is infinite.
                 ? sys_timer_resolution_msec
                 : std::min(m_loops_timer.time_left_msec(), sys_timer_resolution_msec));

        rc = SYSCALL(epoll_wait, m_rx_epfd, ep_events, maxevents, next_timeout);

        if (rc != 0 || m_loops_timer.time_left_msec() == 0) {
            break;
        }

        // epol_wait timeout
        // We must run here TCP timers because we are in a mode when TCP timers are
        // handled by the context threads instead of the internal thread.
        g_event_handler_manager_local.do_tasks();
    } while (1);

    return rc;
}

bool sockinfo_tcp::is_readable(uint64_t *p_poll_sn, fd_array_t *p_fd_array)
{
    if (is_server()) {
        bool state;
        // tcp_si_logwarn("select on accept()");
        // m_conn_cond.lock();
        state = m_ready_conn_cnt == 0 ? false : true;
        if (state) {
            si_tcp_logdbg("accept ready");
            return true;
        }

        if (m_sock_state == TCP_SOCK_ACCEPT_SHUT) {
            return true;
        }

        return false;
    } else if (m_sock_state == TCP_SOCK_ASYNC_CONNECT) {
        // socket is not ready to read in this state!!!
        return false;
    }

    if (!is_rtr()) {
        // unconnected tcp sock is always ready for read!
        // return its fd as ready
        si_tcp_logdbg("block check on unconnected socket");
        return true;
    }

    if (m_n_rx_pkt_ready_list_count) {
        return true;
    }

    if (!p_poll_sn || m_skip_cq_poll_in_rx) {
        return false;
    }

    consider_rings_migration_rx();

    m_rx_ring_map_lock.lock();
    while (!g_b_exit && is_rtr()) {
        if (likely(m_p_rx_ring)) {
            // likely scenario: rx socket bound to specific cq
            int drained = m_p_rx_ring->poll_and_process_element_rx(p_poll_sn, p_fd_array);
            if (m_n_rx_pkt_ready_list_count || drained <= 0) {
                break;
            }
        } else if (!m_rx_ring_map.empty()) {
            rx_ring_map_t::iterator rx_ring_iter;
            for (rx_ring_iter = m_rx_ring_map.begin(); rx_ring_iter != m_rx_ring_map.end();
                 rx_ring_iter++) {
                if (rx_ring_iter->second->refcnt <= 0) {
                    continue;
                }
                ring *p_ring = rx_ring_iter->first;
                // g_p_lwip->do_timers();
                int drained = p_ring->poll_and_process_element_rx(p_poll_sn, p_fd_array);
                if (m_n_rx_pkt_ready_list_count || drained <= 0) {
                    break;
                }
            }
        } else {
            // No available rx rings, break loop.
            break;
        }
    }

    m_rx_ring_map_lock.unlock();
    return (m_n_rx_pkt_ready_list_count != 0);
}

bool sockinfo_tcp::is_readable_thread()
{
    if (unlikely(safe_mce_sys().xlio_threads == 0U)) {
        return is_readable(nullptr, nullptr);
    }

    if (is_server()) {
        bool state;
        // tcp_si_logwarn("select on accept()");
        // m_conn_cond.lock();
        state = m_ready_conn_cnt == 0 ? false : true;
        if (state) {
            si_tcp_logdbg("accept ready");
            return true;
        }

        if (m_sock_state == TCP_SOCK_ACCEPT_SHUT) {
            return true;
        }

        return false;
    } else if (m_sock_state == TCP_SOCK_ASYNC_CONNECT) {
        // socket is not ready to read in this state!!!
        return false;
    }

    if (!is_rtr()) {
        // unconnected tcp sock is always ready for read!
        // return its fd as ready
        si_tcp_logdbg("block check on unconnected socket");
        return true;
    }

    return (m_n_rx_pkt_ready_list_count != 0);
}

bool sockinfo_tcp::is_writeable()
{
    if (m_sock_state == TCP_SOCK_ASYNC_CONNECT) {
        if (m_conn_state == TCP_CONN_CONNECTED) {
            si_tcp_logdbg("++++ async connect ready");
            m_sock_state = TCP_SOCK_CONNECTED_RDWR;
            goto noblock;
        } else if (m_conn_state != TCP_CONN_CONNECTING) {
            // async connect failed for some reason. Reset our state and return ready fd
            si_tcp_logerr("async connect failed");
            if (m_sock_state != TCP_SOCK_BOUND) { // Avoid binding twice
                m_sock_state = TCP_SOCK_INITED;
            }
            goto noblock;
        }
        return false;
    }
    if (!is_rts()) {
        // unconnected tcp sock is always ready for write! - TODO: verify!
        // return its fd as ready
        si_tcp_logdbg("block check on unconnected socket");
        goto noblock;
    }

    if (sndbuf_available()) {
        goto noblock;
    }

    return false;

noblock:
    /*
           if (p_fd_array) {
                   p_fd_array->fd_list[p_fd_array->fd_count] = m_fd;
                   p_fd_array->fd_count++;
           }
    */
    __log_funcall("--->>> tcp_sndbuf(&m_pcb)=%ld", sndbuf_available());
    return true;
}
bool sockinfo_tcp::is_errorable(int *errors)
{
    *errors = 0;

    if (m_conn_state == TCP_CONN_ERROR || m_conn_state == TCP_CONN_TIMEOUT ||
        m_conn_state == TCP_CONN_RESETED || m_conn_state == TCP_CONN_FAILED) {
        *errors |= POLLHUP;
    }
    // coverity[MISSING_LOCK:FALSE] /*Turn off coverity check for missing lock*/
    if ((m_conn_state == TCP_CONN_ERROR) || (!m_error_queue.empty())) {
        *errors |= POLLERR;
    }

    return *errors;
}

/*
 * FIXME: need to split sock connected state in two: TCP_SOCK_CON_TX/RX
 */
int sockinfo_tcp::shutdown(int __how)
{
    err_t err = ERR_OK;

    int shut_rx, shut_tx;

    // if in os pathrough just redirect to os
    if (m_sock_offload == TCP_SOCK_PASSTHROUGH) {
        si_tcp_logdbg("passthrough - go to OS shutdown()");
        return SYSCALL(shutdown, m_fd, __how);
    }

    lock_tcp_con();

    shut_tx = shut_rx = 0;
    switch (__how) {
    case SHUT_RD:
        if (is_connected()) {
            m_sock_state = TCP_SOCK_CONNECTED_WR;
            NOTIFY_ON_EVENTS(this, EPOLLIN);
        } else if (is_rtr()) {
            m_sock_state = TCP_SOCK_BOUND;
            NOTIFY_ON_EVENTS(this, EPOLLIN | EPOLLHUP);
        } else if (m_sock_state == TCP_SOCK_ACCEPT_READY) {
            m_sock_state = TCP_SOCK_ACCEPT_SHUT;
        } else {
            goto bad_state;
        }
        shut_rx = 1;
        break;
    case SHUT_WR:
        if (is_connected()) {
            m_sock_state = TCP_SOCK_CONNECTED_RD;
        } else if (is_rts()) {
            m_sock_state = TCP_SOCK_BOUND;
            NOTIFY_ON_EVENTS(this, EPOLLHUP);
        } else if (is_server()) {
            // ignore SHUT_WR on listen socket
        } else {
            goto bad_state;
        }
        shut_tx = 1;
        break;
    case SHUT_RDWR:
        if (is_connected() || is_rts() || is_rtr()) {
            m_sock_state = TCP_SOCK_BOUND;
            NOTIFY_ON_EVENTS(this, EPOLLIN | EPOLLHUP);
        } else if (m_sock_state == TCP_SOCK_ACCEPT_READY) {
            m_sock_state = TCP_SOCK_ACCEPT_SHUT;
        } else {
            goto bad_state;
        }
        shut_rx = 1;
        shut_tx = 1;
        break;
        BULLSEYE_EXCLUDE_BLOCK_START
    default:
        si_tcp_logerr("unknow shutdown option %d", __how);
        break;
        BULLSEYE_EXCLUDE_BLOCK_END
    }

    if (is_server()) {
        if (shut_rx) {
            tcp_accept(&m_pcb, nullptr);
            tcp_syn_handled(&m_pcb, sockinfo_tcp::syn_received_drop_lwip_cb);
        }
    } else {
        if (get_tcp_state(&m_pcb) != LISTEN && shut_rx && m_n_rx_pkt_ready_list_count) {
            abort_connection();
        } else {
            err = tcp_shutdown(&m_pcb, shut_rx, shut_tx);
        }
    }

    m_sock_wakeup_pipe.do_wakeup();

    if (err == ERR_OK) {
        unlock_tcp_con();
        return 0;
    }

bad_state:
    unlock_tcp_con();
    errno = ENOTCONN;
    return -1;
}

int sockinfo_tcp::fcntl_helper(int __cmd, unsigned long int __arg, bool &bexit)
{
    switch (__cmd) {
    case F_SETFL: /* Set file status flags. */
        si_tcp_logdbg("cmd=F_SETFL, arg=%#lx", __arg);
        set_blocking(!(__arg & O_NONBLOCK));
        bexit = true;
        return 0;
    case F_GETFL: /* Get file status flags. */
        si_tcp_logdbg("cmd=F_GETFL");
        bexit = true;
        return O_NONBLOCK * !m_b_blocking;
    default:
        break;
    }

    bexit = false;
    return 0;
}

int sockinfo_tcp::fcntl(int __cmd, unsigned long int __arg)
{
    if (!safe_mce_sys().avoid_sys_calls_on_tcp_fd || !is_connected()) {
        return sockinfo::fcntl(__cmd, __arg);
    }

    bool bexit = false;
    int ret_val = fcntl_helper(__cmd, __arg, bexit);
    if (bexit) {
        return ret_val;
    }

    return sockinfo::fcntl(__cmd, __arg);
}

int sockinfo_tcp::fcntl64(int __cmd, unsigned long int __arg)
{
    if (!safe_mce_sys().avoid_sys_calls_on_tcp_fd || !is_connected()) {
        return sockinfo::fcntl64(__cmd, __arg);
    }

    bool bexit = false;
    int ret_val = fcntl_helper(__cmd, __arg, bexit);
    if (bexit) {
        return ret_val;
    }

    return sockinfo::fcntl64(__cmd, __arg);
}

int sockinfo_tcp::ioctl(unsigned long int __request, unsigned long int __arg)
{
    if (!safe_mce_sys().avoid_sys_calls_on_tcp_fd || !is_connected()) {
        return sockinfo::ioctl(__request, __arg);
    }

    int *p_arg = (int *)__arg;

    switch (__request) {
    case FIONBIO:
        si_tcp_logdbg("request=FIONBIO, arg=%d", *p_arg);
        set_blocking(!(*p_arg));
        return 0;
    default:
        break;
    }
    return sockinfo::ioctl(__request, __arg);
}

void sockinfo_tcp::fit_rcv_wnd(bool force_fit)
{
    m_pcb.rcv_wnd_max_desired = std::min(TCP_WND_SCALED(&m_pcb), m_rcvbuff_max);

    if (force_fit) {
        int rcv_wnd_max_diff = m_pcb.rcv_wnd_max_desired - m_pcb.rcv_wnd_max;

        m_pcb.rcv_wnd_max = m_pcb.rcv_wnd_max_desired;
        m_pcb.rcv_wnd = std::max(0, static_cast<int>(m_pcb.rcv_wnd) + rcv_wnd_max_diff);
        m_pcb.rcv_ann_wnd = std::max(0, static_cast<int>(m_pcb.rcv_ann_wnd) + rcv_wnd_max_diff);

        if (!m_pcb.rcv_wnd) {
            m_rcvbuff_non_tcp_recved = m_pcb.rcv_wnd_max;
        }
    } else if (m_pcb.rcv_wnd_max_desired > m_pcb.rcv_wnd_max) {
        uint32_t rcv_wnd_max_diff = m_pcb.rcv_wnd_max_desired - m_pcb.rcv_wnd_max;
        m_pcb.rcv_wnd_max = m_pcb.rcv_wnd_max_desired;
        m_pcb.rcv_wnd += rcv_wnd_max_diff;
        m_pcb.rcv_ann_wnd += rcv_wnd_max_diff;
    }
}

void sockinfo_tcp::fit_snd_bufs(unsigned int new_max_snd_buff)
{
    // snd_buf can become negative
    m_pcb.snd_buf += ((int)new_max_snd_buff - m_pcb.max_snd_buff);
    m_pcb.max_snd_buff = new_max_snd_buff;

    UPDATE_PCB_BY_MSS(&m_pcb, m_pcb.mss);
}

////////////////////////////////////////////////////////////////////////////////
bool sockinfo_tcp::try_un_offloading() // un-offload the socket if possible
{
    // be conservative and avoid off-loading a socket after it started connecting
    return m_conn_state == TCP_CONN_INIT ? sockinfo::try_un_offloading() : false;
}

////////////////////////////////////////////////////////////////////////////////
int sockinfo_tcp::setsockopt(int __level, int __optname, __const void *__optval, socklen_t __optlen)
{
    return m_ops->setsockopt(__level, __optname, __optval, __optlen);
}

////////////////////////////////////////////////////////////////////////////////
int sockinfo_tcp::tcp_setsockopt(int __level, int __optname, __const void *__optval,
                                 socklen_t __optlen)
{
    // todo check optlen and set proper errno on failure
    si_tcp_logfunc("level=%d, optname=%d", __level, __optname);

    int ret_opt;
    if ((ret_opt = sockinfo::setsockopt(__level, __optname, __optval, __optlen)) !=
        SOCKOPT_PASS_TO_OS) {
        if (!is_incoming() &&
            (ret_opt == SOCKOPT_INTERNAL_XLIO_SUPPORT || ret_opt == SOCKOPT_HANDLE_BY_OS) &&
            m_sock_state <= TCP_SOCK_ACCEPT_READY && __optval &&
            is_inherited_option(__level, __optname)) {
            socket_option_t *opt_curr = new socket_option_t(__level, __optname, __optval, __optlen);
            if (opt_curr) {
                m_socket_options_list.push_back(opt_curr);
            } else {
                si_tcp_logwarn("Unable to allocate memory for socket option level=%d, optname=%d",
                               __level, __optname);
            }
        }

        return (ret_opt == SOCKOPT_HANDLE_BY_OS
                    ? setsockopt_kernel(__level, __optname, __optval, __optlen, true, false)
                    : ret_opt);
    }

    int val = 0;
    bool supported = true;
    bool allow_privileged_sock_opt = false;
    bool pass_to_os_cond = true; // Pass to OS depending on a condition below
    bool pass_to_os_always = false; // Pass to OS regardless the condition below.
    int ret = 0;

    if (__level == IPPROTO_IP) {
        switch (__optname) {
        case IP_TOS: /* might be missing ECN logic */
            pass_to_os_always = true;
            if (__optlen == sizeof(int)) {
                val = *(int *)__optval;
            } else if (__optlen == sizeof(uint8_t)) {
                val = *(uint8_t *)__optval;
            } else {
                break;
            }
            val &= ~INET_ECN_MASK;
            val |= m_pcb.tos & INET_ECN_MASK;
            if (m_pcb.tos != val) {
                lock_tcp_con();
                m_pcb.tos = val;
                header_tos_updater du(m_pcb.tos);
                update_header_field(&du);
                // lists.openwall.net/netdev/2009/12/21/59
                int new_prio = ip_tos2prio[IPTOS_TOS(m_pcb.tos) >> 1];
                set_sockopt_prio(&new_prio, sizeof(new_prio));
                unlock_tcp_con();
            }
            break;
        default:
            pass_to_os_always = true;
            supported = false;
            break;
        }
    } else if (__level == IPPROTO_TCP) {
        switch (__optname) {
        case TCP_CORK:
            // We don't support TCP_CORK.
            break;
        case TCP_NODELAY:
            val = *(int *)__optval;
            lock_tcp_con();
            if (val) {
                tcp_nagle_disable(&m_pcb);
            } else {
                tcp_nagle_enable(&m_pcb);
            }
            unlock_tcp_con();
            si_tcp_logdbg("(TCP_NODELAY) nagle: %d", val);
            break;
        case TCP_QUICKACK:
            val = *(int *)__optval;
            lock_tcp_con();
            m_pcb.quickack = (uint8_t)(val > 0 ? val : 0);
            unlock_tcp_con();
            si_tcp_logdbg("(TCP_QUICKACK) value: %d", val);
            break;
        case TCP_ULP: {
            sockinfo_tcp_ops *ops {nullptr};
            if (__optval && __optlen >= 4 && strncmp((char *)__optval, "nvme", 4) == 0) {
                pass_to_os_cond = false;
                auto nvme_feature_mask = get_supported_nvme_feature_mask();
                if (nvme_feature_mask == 0U) {
                    errno = ENOTSUP;
                    ret = -1;
                    break;
                }
                ops = new sockinfo_tcp_ops_nvme(this, nvme_feature_mask);
                si_tcp_logdbg("(TCP_NVME) val: nvme");
            }
#ifdef DEFINED_UTLS
            else if (__optval && __optlen >= 3 && strncmp((char *)__optval, "tls", 3) == 0) {
                if (is_utls_supported(UTLS_MODE_TX | UTLS_MODE_RX)) {
                    si_tcp_logdbg("(TCP_ULP) val: tls");
                    if (unlikely(!is_rts())) {
                        errno = ENOTCONN;
                        ret = -1;
                        break;
                    }
                    ops = new sockinfo_tcp_ops_tls(this);
                }
            }
#endif /* DEFINED_UTLS */
            else {
                si_tcp_logdbg("(TCP_ULP) %s option is not supported", (char *)__optval);
                errno = ENOPROTOOPT;
                ret = -1;
                break;
            }

            if (unlikely(!ops)) {
                errno = ENOMEM;
                ret = -1;
                break;
            }

            lock_tcp_con();
            set_ops(ops);
            unlock_tcp_con();
            /* On success we call kernel setsockopt() in case this socket is not connected
               and is unoffloaded later.  */
            break;
        }
        case TCP_CONGESTION:
            if (__optval && __optlen > 0) {
                std::string cc_name((const char *)__optval,
                                    strnlen((const char *)__optval, __optlen));
                si_tcp_logdbg("TCP_CONGESTION value: %s", cc_name.c_str());
#if TCP_CC_ALGO_MOD
                struct cc_algo *algo = nullptr;
                if (cc_name == "reno" || cc_name == "newreno") {
                    algo = &lwip_cc_algo;
                } else if (cc_name == "cubic") {
                    algo = &cubic_cc_algo;
                } else if (cc_name == "none") {
                    algo = &none_cc_algo;
                }
                if (algo) {
                    lock_tcp_con();
                    cc_destroy(&m_pcb);
                    m_pcb.cc_algo = algo;
                    cc_init(&m_pcb);
                    cc_conn_init(&m_pcb);
                    unlock_tcp_con();
                } else {
                    errno = ENOENT;
                    ret = -1;
                }
#endif
            } else {
                // Meet Linux kernel behavior:
                errno = __optlen == 0 ? EINVAL : EFAULT;
                ret = -1;
            }
            break;
        case TCP_USER_TIMEOUT: {
            unsigned int user_timeout_ms = *(unsigned int *)__optval;
            si_tcp_logdbg("TCP_USER_TIMEOUT value: %u", user_timeout_ms);
            m_pcb.user_timeout_ms = user_timeout_ms;
        } break;
        case TCP_KEEPIDLE: {
            auto *int_ptr = reinterpret_cast<const int *>(__optval);
            if (__optlen < sizeof(int) || *int_ptr <= 0) {
                errno = EINVAL;
                ret = -1;
            } else {
                auto idle_sec = static_cast<unsigned int>(*int_ptr);
                si_tcp_logdbg("TCP_KEEPIDLE value: %us", idle_sec);
                m_pcb.keep_idle = idle_sec * 1000U;
            }
        } break;
#if LWIP_TCP_KEEPALIVE
        case TCP_KEEPINTVL: {
            auto *int_ptr = reinterpret_cast<const int *>(__optval);
            if (__optlen < sizeof(int) || *int_ptr <= 0) {
                errno = EINVAL;
                ret = -1;
            } else {
                auto keep_intvl = static_cast<unsigned int>(*int_ptr);
                si_tcp_logdbg("TCP_KEEPINTVL value: %us", keep_intvl);
                m_pcb.keep_intvl = keep_intvl * 1000U;
            }
        } break;
        case TCP_KEEPCNT: {
            auto *int_ptr = reinterpret_cast<const int *>(__optval);
            if (__optlen < sizeof(int) || *int_ptr <= 0) {
                errno = EINVAL;
                ret = -1;
            } else {
                auto keep_cnt = static_cast<unsigned int>(*int_ptr);
                si_tcp_logdbg("TCP_KEEPCNT value: %u", keep_cnt);
                m_pcb.keep_cnt = keep_cnt;
            }
        } break;
#endif /* LWIP_TCP_KEEPALIVE */
        default:
            pass_to_os_always = true;
            supported = false;
            break;
        }
    } else if (__level == SOL_SOCKET) {
        switch (__optname) {
        case SO_REUSEADDR:
            val = *(int *)__optval;
            lock_tcp_con();
            if (val) {
                m_pcb.so_options |= SOF_REUSEADDR;
            } else {
                m_pcb.so_options &= ~SOF_REUSEADDR;
            }
            pass_to_os_always = true; // SO_REUSEADDR is also relevant on OS
            unlock_tcp_con();
            si_tcp_logdbg("(SO_REUSEADDR) val: %d", val);
            break;
        case SO_KEEPALIVE:
            val = *(int *)__optval;
            lock_tcp_con();
            if (val) {
                m_pcb.so_options |= SOF_KEEPALIVE;
            } else {
                m_pcb.so_options &= ~SOF_KEEPALIVE;
            }
            unlock_tcp_con();
            si_tcp_logdbg("(SO_KEEPALIVE) val: %d", val);
            break;
        case SO_RCVBUF:
            val = std::min(*(int *)__optval, safe_mce_sys().sysctl_reader.get_net_core_rmem_max());
            lock_tcp_con();
            // OS allocates double the size of memory requested by the application - not sure we
            // need it.
            m_rcvbuff_max = std::max(2 * m_pcb.mss, 2 * val);

            fit_rcv_wnd(!is_connected());
            unlock_tcp_con();
            si_tcp_logdbg("setsockopt SO_RCVBUF: %d", m_rcvbuff_max);
            break;
        case SO_SNDBUF:
            val = std::min(*(int *)__optval, safe_mce_sys().sysctl_reader.get_net_core_wmem_max());
            lock_tcp_con();
            // OS allocates double the size of memory requested by the application - not sure we
            // need it.
            val = std::max(2 * m_pcb.mss, 2 * val);
            fit_snd_bufs(val);
            unlock_tcp_con();
            si_tcp_logdbg("setsockopt SO_SNDBUF: requested %d, set %d", *(int *)__optval, val);
            break;
        case SO_LINGER:
            if (__optlen < sizeof(struct linger)) {
                errno = EINVAL;
                ret = -1;
                break;
            }
            m_linger = *(struct linger *)__optval;
            si_tcp_logdbg("setsockopt SO_LINGER: l_onoff = %d, l_linger = %d", m_linger.l_onoff,
                          m_linger.l_linger);
            break;
        case SO_RCVTIMEO: {
            if (__optlen < sizeof(struct timeval)) {
                errno = EINVAL;
                ret = -1;
                break;
            }
            struct timeval *tv = (struct timeval *)__optval;
            if (tv->tv_sec || tv->tv_usec) {
                m_loops_timer.set_timeout_msec(tv->tv_sec * 1000 +
                                               (tv->tv_usec ? tv->tv_usec / 1000 : 0));
            } else {
                m_loops_timer.set_timeout_msec(-1);
            }
            si_tcp_logdbg("SOL_SOCKET: SO_RCVTIMEO=%d", m_loops_timer.get_timeout_msec());
            break;
        }
        case SO_BINDTODEVICE: {
            ip_addr addr {0};
            allow_privileged_sock_opt = safe_mce_sys().allow_privileged_sock_opt;
            if (__optlen == 0 || ((char *)__optval)[0] == '\0') {
                m_so_bindtodevice_ip = ip_addr(ip_address::any_addr(), m_family);
            } else if (get_ip_addr_from_ifname((char *)__optval, addr, m_family) &&
                       !(m_family == AF_INET6 && !m_is_ipv6only &&
                         !get_ip_addr_from_ifname((char *)__optval, addr, AF_INET))) {
                si_tcp_logdbg("SOL_SOCKET, SO_BINDTODEVICE - NOT HANDLED, cannot find if_name");
                errno = EINVAL;
                ret = -1;
                break;
            } else {
                // coverity[copy_assignment_call:FALSE] /*Turn off coverity COPY_INSTEAD_OF_MOVE*/
                m_so_bindtodevice_ip = addr;

                si_tcp_logdbg("SOL_SOCKET, %s='%s' (%s)", setsockopt_so_opt_to_str(__optname),
                              (char *)__optval, m_so_bindtodevice_ip.to_str().c_str());

                if (!is_connected()) {
                    /* Current implementation allows to create separate rings for tx and rx.
                     * tx ring is created basing on destination ip during connect() call,
                     * SO_BINDTODEVICE and routing table information
                     * whereas rx ring creation can be based on bound (local) ip
                     * As a result there are limitations in using this capability.
                     * Also we can not have bound information as
                     * (!m_bound.is_anyaddr() && !m_bound.is_local_loopback())
                     * and can not detect offload/non-offload socket
                     * Note:
                     * This inconsistency should be resolved.
                     */

                    lock_tcp_con();
                    /* We need to destroy this if attach/detach receiver is not called
                     * just reference counter for p_nd_resources is updated on attach/detach
                     */
                    if (NULL == create_nd_resources(m_so_bindtodevice_ip)) {
                        si_tcp_logdbg("Failed to get net device resources on ip %s",
                                      m_so_bindtodevice_ip.to_str().c_str());
                    }
                    unlock_tcp_con();
                }
            }
            // handle TX side
            if (m_p_connected_dst_entry) {
                if (m_p_connected_dst_entry->is_offloaded()) {
                    if (!m_p_connected_dst_entry->is_the_same_ifname(
                            std::string(reinterpret_cast<const char *>(__optval)))) {
                        si_tcp_logdbg(
                            "SO_BINDTODEVICE will not work on already offloaded TCP socket");
                        errno = EINVAL;
                        return -1;
                    }
                } else {
                    m_p_connected_dst_entry->set_so_bindtodevice_addr(m_so_bindtodevice_ip);
                }
            }
            // TODO handle RX side
            si_tcp_logdbg("(SO_BINDTODEVICE) interface=%s", (char *)__optval);
            break;
        }
        case SO_MAX_PACING_RATE: {
            struct xlio_rate_limit_t rate_limit;

            if (!__optval) {
                errno = EINVAL;
                ret = -1;
                break;
            }
            if (sizeof(struct xlio_rate_limit_t) == __optlen) {
                rate_limit = *(struct xlio_rate_limit_t *)__optval; // value is in Kbits per second
            } else if (sizeof(uint32_t) == __optlen) {
                // value is in bytes per second
                rate_limit.rate = BYTE_TO_KB(*(uint32_t *)__optval); // value is in bytes per second
                rate_limit.max_burst_sz = 0;
                rate_limit.typical_pkt_sz = 0;
            } else {
                errno = EINVAL;
                ret = -1;
                break;
            }

            lock_tcp_con();
            ret = modify_ratelimit(m_p_connected_dst_entry, rate_limit);
            unlock_tcp_con();
            if (ret) {
                si_tcp_logdbg("error setting setsockopt SO_MAX_PACING_RATE: %d bytes/second ",
                              rate_limit.rate);
            } else {
                si_tcp_logdbg("setsockopt SO_MAX_PACING_RATE: %d bytes/second ", rate_limit.rate);
            }
            return ret;
        }
        case SO_PRIORITY: {
            lock_tcp_con();
            if (set_sockopt_prio(__optval, __optlen)) {
                unlock_tcp_con();
                return -1;
            }
            unlock_tcp_con();
            pass_to_os_always = true;
            break;
        }
        case SO_ZEROCOPY:
            if (__optval) {
                lock_tcp_con();
                m_b_zc = *(bool *)__optval;
                unlock_tcp_con();
            }
            pass_to_os_always = true;
            si_tcp_logdbg("(SO_ZEROCOPY) m_b_zc: %d", m_b_zc);
            break;
        case SO_XLIO_EXT_VLAN_TAG:
            if (__optlen == sizeof(int)) {
                int tempval = *reinterpret_cast<const int *>(__optval);
                if (tempval >= 0 && tempval <= UINT16_MAX) {
                    m_external_vlan_tag = static_cast<uint16_t>(tempval);
                    pass_to_os_cond = false;
                    si_tcp_logdbg("(SO_XLIO_EXT_VLAN_TAG) m_external_vlan_tag: %" PRIu16,
                                  m_external_vlan_tag);
                    break;
                }
            }
            ret = -1;
            errno = EINVAL;
            break;
        case SO_XLIO_ISOLATE:
            // See option description in the extra API header.
            pass_to_os_cond = false;
            // We support SO_XLIO_ISOLATE only when no TX/RX rings are assigned.
            if (__optlen == sizeof(int) && !m_p_connected_dst_entry && m_rx_ring_map.empty()) {
                int tempval = *reinterpret_cast<const int *>(__optval);
                bool ring_isolated =
                    m_ring_alloc_log_rx.get_ring_alloc_logic() == RING_LOGIC_ISOLATE &&
                    m_ring_alloc_log_tx.get_ring_alloc_logic() == RING_LOGIC_ISOLATE;

                if (tempval == SO_XLIO_ISOLATE_DEFAULT && !ring_isolated) {
                    // Do nothing.
                    break;
                }
                if (tempval == SO_XLIO_ISOLATE_SAFE) {
                    if (safe_mce_sys().tcp_ctl_thread ==
                            option_tcp_ctl_thread::CTL_THREAD_DELEGATE_TCP_TIMERS &&
                        !ring_isolated) {
                        m_tcp_con_lock = multilock::create_new_lock(MULTILOCK_RECURSIVE, "tcp_con");
                    }
                    set_ring_logic_rx(ring_alloc_logic_attr(RING_LOGIC_ISOLATE, true));
                    set_ring_logic_tx(ring_alloc_logic_attr(RING_LOGIC_ISOLATE, true));
                    break;
                }
            }
            ret = -1;
            errno = EINVAL;
            break;
        default:
            pass_to_os_always = true;
            supported = false;
            break;
        }
    } else {
        // Unsupported level.
        pass_to_os_always = true;
        supported = false;
    }

    if (ret == -1) {
        // Avoid saving inherited option or calling kernel setsockopt() if XLIO fails
        // explicitly.
        return ret;
    }

    if (!is_incoming() && m_sock_state <= TCP_SOCK_ACCEPT_READY && __optval &&
        is_inherited_option(__level, __optname)) {
        m_socket_options_list.push_back(
            new socket_option_t(__level, __optname, __optval, __optlen));
    }

    if ((safe_mce_sys().avoid_sys_calls_on_tcp_fd && !pass_to_os_always && is_connected())) {
        pass_to_os_cond = false;
    }

    return ((pass_to_os_always || pass_to_os_cond)
                ? setsockopt_kernel(__level, __optname, __optval, __optlen, supported,
                                    allow_privileged_sock_opt)
                : ret);
}

void sockinfo_tcp::get_tcp_info(struct tcp_info *ti)
{
    int state = get_tcp_state(&m_pcb);

    memset(ti, 0, sizeof(*ti));

    static std::unordered_map<int, int> pcb_to_tcp_state = {
        {CLOSED, TCP_CLOSE},         {LISTEN, TCP_LISTEN},           {SYN_SENT, TCP_SYN_SENT},
        {SYN_RCVD, TCP_SYN_RECV},    {ESTABLISHED, TCP_ESTABLISHED}, {FIN_WAIT_1, TCP_FIN_WAIT1},
        {FIN_WAIT_2, TCP_FIN_WAIT2}, {CLOSE_WAIT, TCP_CLOSE_WAIT},   {CLOSING, TCP_CLOSING},
        {LAST_ACK, TCP_LAST_ACK},    {TIME_WAIT, TCP_TIME_WAIT}};

    assert(pcb_to_tcp_state.size() == TCP_STATE_NR);

    ti->tcpi_state = state < TCP_STATE_NR ? pcb_to_tcp_state[state] : 0;
    ti->tcpi_options = (!!(m_pcb.flags & TF_TIMESTAMP) * TCPI_OPT_TIMESTAMPS) |
        (!!(m_pcb.flags & TF_WND_SCALE) * TCPI_OPT_WSCALE);
    // We keep rto with TCP slow timer granularity and need to convert it to usec.
    ti->tcpi_rto = m_pcb.rto * safe_mce_sys().tcp_timer_resolution_msec * 2 * 1000U;
    ti->tcpi_advmss = m_pcb.advtsd_mss;
    ti->tcpi_snd_mss = m_pcb.mss;
    ti->tcpi_retransmits = m_pcb.nrtx;
    // ti->tcpi_retrans - we don't keep it and calculation would be O(N).
    ti->tcpi_snd_cwnd = m_pcb.cwnd / m_pcb.mss;
    ti->tcpi_snd_ssthresh = m_pcb.ssthresh / m_pcb.mss;

    // This will be incorrect if sockets number is bigger than safe_mce_sys().stats_fd_num_max.
    IF_STATS(ti->tcpi_total_retrans = m_p_socket_stats->counters.n_tx_retransmits);

    // Currently we miss per segment statistics and most of congestion control fields.
}

int sockinfo_tcp::getsockopt_offload(int __level, int __optname, void *__optval,
                                     socklen_t *__optlen)
{
    int ret = -1;

    if (!__optval || !__optlen) {
        errno = EFAULT;
        return ret;
    }

    if (0 == sockinfo::getsockopt(__level, __optname, __optval, __optlen)) {
        return 0;
    }

    switch (__level) {
    case IPPROTO_TCP:
        switch (__optname) {
        case TCP_NODELAY:
            if (*__optlen >= sizeof(int)) {
                *(int *)__optval = tcp_nagle_disabled(&m_pcb);
                si_tcp_logdbg("(TCP_NODELAY) nagle: %d", *(int *)__optval);
                ret = 0;
            } else {
                errno = EINVAL;
            }
            break;
        case TCP_QUICKACK:
            if (*__optlen >= sizeof(int)) {
                *(int *)__optval = m_pcb.quickack;
                si_tcp_logdbg("(TCP_QUICKACK) value: %d", *(int *)__optval);
                ret = 0;
            } else {
                errno = EINVAL;
            }
            break;
        case TCP_INFO:
            struct tcp_info ti;
            unsigned len;
            get_tcp_info(&ti);
            // Due to compatibility reasons TCP_INFO can return partial result.
            len = std::min<unsigned>(sizeof(ti), *__optlen);
            memcpy(__optval, &ti, len);
            *__optlen = len;
            ret = 0;
            break;
        case TCP_CONGESTION:
            const char *cc_name;
            socklen_t cc_len;
#if TCP_CC_ALGO_MOD
            cc_name = m_pcb.cc_algo ? m_pcb.cc_algo->name : "<NULL>";
#else
            cc_name = "lwip";
#endif
            if (strcmp(cc_name, "lwip") == 0) {
                // LwIP implements Reno mechanism by default.
                cc_name = "reno";
            }

            cc_len = std::min<socklen_t>(strlen(cc_name) + 1, *__optlen);
            strncpy((char *)__optval, cc_name, cc_len);
            *__optlen = cc_len;
            ret = 0;
            // XLIO doesn't meet Linux kernel behavior if (__optval == NULL && __optlen !=
            // NULL).
            break;
        case TCP_USER_TIMEOUT:
            if (*__optlen >= sizeof(unsigned int)) {
                *(unsigned int *)__optval = m_pcb.user_timeout_ms;
                *__optlen = sizeof(unsigned int);
                si_tcp_logdbg("TCP_USER_TIMEOUT value: %u", m_pcb.user_timeout_ms);
                ret = 0;
            } else {
                errno = EINVAL;
            }
            break;
        case TCP_KEEPIDLE:
            if (*__optlen >= sizeof(unsigned int)) {
                *(unsigned int *)__optval = m_pcb.keep_idle / 1000;
                *__optlen = sizeof(unsigned int);
                si_tcp_logdbg("TCP_KEEPIDLE value: %us", m_pcb.keep_idle / 1000);
                ret = 0;
            } else {
                errno = EINVAL;
            }
            break;
#if LWIP_TCP_KEEPALIVE
        case TCP_KEEPINTVL:
            if (*__optlen >= sizeof(unsigned int)) {
                *(unsigned int *)__optval = m_pcb.keep_intvl / 1000;
                *__optlen = sizeof(unsigned int);
                si_tcp_logdbg("TCP_KEEPINTVL value: %us", m_pcb.keep_intvl / 1000);
                ret = 0;
            } else {
                errno = EINVAL;
            }
            break;
        case TCP_KEEPCNT:
            if (*__optlen >= sizeof(unsigned int)) {
                *(unsigned int *)__optval = m_pcb.keep_cnt;
                *__optlen = sizeof(unsigned int);
                si_tcp_logdbg("TCP_KEEPCNT value: %us", m_pcb.keep_cnt);
                ret = 0;
            } else {
                errno = EINVAL;
            }
            break;
#endif /* LWIP_TCP_KEEPALIVE */
        default:
            ret = SOCKOPT_HANDLE_BY_OS;
            break;
        }
        break;
    case SOL_SOCKET:
        switch (__optname) {
        case SO_ERROR:
            if (*__optlen >= sizeof(int)) {
                *(int *)__optval = m_error_status;
                si_tcp_logdbg("(SO_ERROR) status: %d", m_error_status);
                m_error_status = 0;
                ret = 0;
            } else {
                errno = EINVAL;
            }
            break;
        case SO_REUSEADDR:
            if (*__optlen >= sizeof(int)) {
                *(int *)__optval = m_pcb.so_options & SOF_REUSEADDR;
                si_tcp_logdbg("(SO_REUSEADDR) reuse: %d", *(int *)__optval);
                ret = 0;
            } else {
                errno = EINVAL;
            }
            break;
        case SO_KEEPALIVE:
            if (*__optlen >= sizeof(int)) {
                *(int *)__optval = (bool)(m_pcb.so_options & SOF_KEEPALIVE);
                si_tcp_logdbg("(SO_KEEPALIVE) keepalive: %d", *(int *)__optval);
                ret = 0;
            } else {
                errno = EINVAL;
            }
            break;
        case SO_RCVBUF:
            if (*__optlen >= sizeof(int)) {
                *(int *)__optval = m_rcvbuff_max;
                si_tcp_logdbg("(SO_RCVBUF) rcvbuf=%d", m_rcvbuff_max);
                ret = 0;
            } else {
                errno = EINVAL;
            }
            break;
        case SO_SNDBUF:
            if (*__optlen >= sizeof(int)) {
                *(int *)__optval = m_pcb.max_snd_buff;
                si_tcp_logdbg("(SO_SNDBUF) sndbuf=%d", *(int *)__optval);
                ret = 0;
            } else {
                errno = EINVAL;
            }
            break;
        case SO_LINGER:
            if (*__optlen > 0) {
                memcpy(__optval, &m_linger, std::min<size_t>(*__optlen, sizeof(struct linger)));
                si_tcp_logdbg("(SO_LINGER) l_onoff = %d, l_linger = %d", m_linger.l_onoff,
                              m_linger.l_linger);
                ret = 0;
            } else {
                errno = EINVAL;
            }
            break;
        case SO_RCVTIMEO:
            if (*__optlen >= sizeof(struct timeval)) {
                struct timeval *tv = (struct timeval *)__optval;
                tv->tv_sec = m_loops_timer.get_timeout_msec() / 1000;
                tv->tv_usec = (m_loops_timer.get_timeout_msec() % 1000) * 1000;
                si_tcp_logdbg("(SO_RCVTIMEO) msec=%d", m_loops_timer.get_timeout_msec());
                ret = 0;
            } else {
                errno = EINVAL;
            }
            break;

        case SO_BINDTODEVICE:
            // todo add support
            errno = ENOPROTOOPT;
            break;
        case SO_MAX_PACING_RATE:
            ret = sockinfo::getsockopt(__level, __optname, __optval, __optlen);
            break;
        case SO_ZEROCOPY:
            if (*__optlen >= sizeof(int)) {
                *(int *)__optval = m_b_zc;
                si_tcp_logdbg("(SO_ZEROCOPY) m_b_zc: %d", m_b_zc);
                ret = 0;
            } else {
                errno = EINVAL;
            }
            break;
        case SO_XLIO_PD:
            if (__optlen && *__optlen >= sizeof(struct xlio_pd_attr)) {
                if (m_p_connected_dst_entry) {
                    ring *tx_ring = m_p_connected_dst_entry->get_ring();
                    if (tx_ring) {
                        /*
                         * For bonding we get context of the 1st slave. This approach
                         * works for RoCE LAG mode.
                         */
                        ib_ctx_handler *p_ib_ctx_h = (ib_ctx_handler *)tx_ring->get_ctx(0);
                        if (p_ib_ctx_h) {
                            struct xlio_pd_attr *pd_attr = (struct xlio_pd_attr *)__optval;
                            pd_attr->flags = 0;
                            pd_attr->ib_pd = (void *)p_ib_ctx_h->get_ibv_pd();
                            ret = 0;
                        }
                    }
                }
            }
            if (ret) {
                errno = EINVAL;
            }
            break;
        default:
            ret = SOCKOPT_HANDLE_BY_OS;
            break;
        }
        break;
    case IPPROTO_IP:
        switch (__optname) {
        default:
            ret = SOCKOPT_HANDLE_BY_OS;
            break;
        }
        break;
    default:
        ret = SOCKOPT_HANDLE_BY_OS;
        break;
    }

    BULLSEYE_EXCLUDE_BLOCK_START
    if (ret && ret != SOCKOPT_HANDLE_BY_OS) {
        si_tcp_logdbg("getsockopt failed (ret=%d %m)", ret);
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    return ret;
}

int sockinfo_tcp::getsockopt(int __level, int __optname, void *__optval, socklen_t *__optlen)
{
    int ret = getsockopt_offload(__level, __optname, __optval, __optlen);
    if (ret != SOCKOPT_HANDLE_BY_OS) {
        return ret;
    } else {
        char buf[256];
        snprintf(buf, sizeof(buf),
                 "unimplemented getsockopt __level=%#x, __optname=%#x, __optlen=%d",
                 (unsigned)__level, (unsigned)__optname, __optlen ? *__optlen : 0);
        buf[sizeof(buf) - 1] = '\0';

        VLOG_PRINTF_INFO(safe_mce_sys().exception_handling.get_log_severity(), "%s", buf);
        int rc = handle_exception_flow();
        switch (rc) {
        case -1:
            return rc;
        case -2:
            xlio_throw_object_with_msg(xlio_unsupported_api, buf);
        }
    }

    if (!is_shadow_socket_present()) {
        // Avoid getsockopt(2) syscall when there is no shadow socket.
        errno = ENOPROTOOPT;
        return -1;
    }

    ret = SYSCALL(getsockopt, m_fd, __level, __optname, __optval, __optlen);

    BULLSEYE_EXCLUDE_BLOCK_START
    if (ret) {
        si_tcp_logdbg("getsockopt failed (ret=%d %m)", ret);
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    return ret;
}

int sockinfo_tcp::getsockname(sockaddr *__name, socklen_t *__namelen)
{
    __log_info_func("");

    if (m_sock_offload == TCP_SOCK_PASSTHROUGH) {
        si_tcp_logdbg("passthrough - go to OS getsockname");
        return SYSCALL(getsockname, m_fd, __name, __namelen);
    }

    // according to man address should be truncated if given struct is too small
    if (__name && __namelen) {
        if ((int)*__namelen < 0) {
            si_tcp_logdbg("negative __namelen is not supported: %d", *__namelen);
            errno = EINVAL;
            return -1;
        }

        m_bound.get_sa_by_family(__name, *__namelen, m_family);
    }

    return 0;
}

int sockinfo_tcp::getpeername(sockaddr *__name, socklen_t *__namelen)
{
    __log_info_func("");

    if (m_sock_offload == TCP_SOCK_PASSTHROUGH) {
        si_tcp_logdbg("passthrough - go to OS getpeername");
        return SYSCALL(getpeername, m_fd, __name, __namelen);
    }

    if (m_conn_state < TCP_CONN_CONNECTED) {
        errno = ENOTCONN;
        return -1;
    }

    // according to man address should be truncated if given struct is too small
    if (__name && __namelen) {
        if ((int)*__namelen < 0) {
            si_tcp_logdbg("negative __namelen is not supported: %d", *__namelen);
            errno = EINVAL;
            return -1;
        }

        si_tcp_logfunc("m_connected: %s, family: %u", m_connected.to_str_ip_port(true).c_str(),
                       static_cast<unsigned int>(m_family));
        m_connected.get_sa_by_family(__name, *__namelen, m_family);
    }

    return 0;
}

int sockinfo_tcp::rx_wait_helper(int &poll_count, bool blocking)
{
    int ret;
    uint64_t poll_sn = 0;
    rx_ring_map_t::iterator rx_ring_iter;
    epoll_event rx_epfd_events[SI_RX_EPFD_EVENT_MAX];

    // poll for completion
    __log_info_func("");
    poll_count++;
    // if in listen state go directly to wait part

    consider_rings_migration_rx();

    // There's only one CQ
    m_rx_ring_map_lock.lock();

    // We need to consider what to do in case poll_and_process_element_rx fails on try_lock.
    // It can be too expansive for the application to get nothing just because of lock contention.
    // In this case it will be better to have a lock() version of poll_and_process_element_rx.
    // And then we should continue polling untill we have ready packets or we drained the CQ.
    int all_drained = -1;
    if (likely(m_p_rx_ring)) {
        all_drained = m_p_rx_ring->poll_and_process_element_rx(&poll_sn);
    } else { // There's more than one CQ, go over each one
        for (rx_ring_iter = m_rx_ring_map.begin(); rx_ring_iter != m_rx_ring_map.end();
             rx_ring_iter++) {
            if (unlikely(rx_ring_iter->second->refcnt <= 0)) {
                __log_err("Attempt to poll illegal cq");
                continue;
            }

            all_drained = std::max(all_drained, rx_ring_iter->first->poll_and_process_element_rx(&poll_sn));
        }
    }
    m_rx_ring_map_lock.unlock();
    lock_tcp_con(); // We must take a lock before checking m_n_rx_pkt_ready_list_count

    if (likely(m_n_rx_pkt_ready_list_count || all_drained > 0)) { // Got completions from CQ
        __log_entry_funcall("Ready %d packets. sn=%llu", m_n_rx_pkt_ready_list_count,
                            (unsigned long long)poll_sn);
        IF_STATS(m_p_socket_stats->counters.n_rx_poll_hit++);
        unlock_tcp_con();
        return 1;
    }

    IF_STATS(m_p_socket_stats->counters.n_rx_poll_miss++);
    bool is_timeout = m_loops_timer.is_timeout(); // We do this under lock.
    unlock_tcp_con(); // Must happen before g_event_handler_manager_local.do_tasks();

    if (safe_mce_sys().tcp_ctl_thread == option_tcp_ctl_thread::CTL_THREAD_DELEGATE_TCP_TIMERS) {
        // There are scenarios when rx_wait_helper is called in an infinite loop but exits before
        // OS epoll_wait. Delegated TCP timers must be attempted in such case.
        // This is a slow path. So calling chrono::now(), even with every iteration, is OK here.
        g_event_handler_manager_local.do_tasks();
    }

    // if in blocking accept state skip poll phase and go to sleep directly
    if (!blocking || is_timeout) {
        errno = EAGAIN;
        return -1;
    }

    if (poll_count < safe_mce_sys().rx_poll_num || safe_mce_sys().rx_poll_num == -1) {
        return 0;
    }

    // if we polling too much - go to sleep
    si_tcp_logfuncall("%d: too many polls without data blocking=%d", m_fd, blocking);
    if (g_b_exit) {
        errno = EINTR;
        return -1;
    }

    // arming CQs
    /* coverity[double_lock] */
    m_rx_ring_map_lock.lock();
    if (likely(m_p_rx_ring)) {
        ret = m_p_rx_ring->request_notification(CQT_RX, poll_sn);
        if (ret != 0) {
            m_rx_ring_map_lock.unlock();
            return 0;
        }
    } else {
        for (rx_ring_iter = m_rx_ring_map.begin(); rx_ring_iter != m_rx_ring_map.end();
             rx_ring_iter++) {
            if (rx_ring_iter->second->refcnt <= 0) {
                continue;
            }
            ring *p_ring = rx_ring_iter->first;
            if (p_ring) {
                ret = p_ring->request_notification(CQT_RX, poll_sn);
                if (ret != 0) {
                    m_rx_ring_map_lock.unlock();
                    return 0;
                }
            }
        }
    }
    m_rx_ring_map_lock.unlock();

    // Check if we have a packet in receive queue before we going to sleep and
    // update is_sleeping flag under the same lock to synchronize between
    // this code and wakeup mechanism.

    lock_tcp_con();
    if (!m_n_rx_pkt_ready_list_count && !m_ready_conn_cnt) {
        m_sock_wakeup_pipe.going_to_sleep();
        unlock_tcp_con();
    } else {
        unlock_tcp_con();
        return 0;
    }

    ret = os_wait_sock_rx_epfd(rx_epfd_events, SI_RX_EPFD_EVENT_MAX);

    lock_tcp_con();
    m_sock_wakeup_pipe.return_from_sleep();
    unlock_tcp_con();

    if (ret <= 0) {
        return ret;
    }

    // If there is a ready packet in a queue we want to return to user as quickest as possible
    if (m_n_rx_pkt_ready_list_count) {
        return 0;
    }

    for (int event_idx = 0; event_idx < ret; event_idx++) {
        int fd = rx_epfd_events[event_idx].data.fd;
        if (m_sock_wakeup_pipe.is_wakeup_fd(fd)) { // wakeup event
            lock_tcp_con();
            m_sock_wakeup_pipe.remove_wakeup_fd();
            unlock_tcp_con();
            continue;
        }

        // Check if OS fd is ready for reading
        if (fd == m_fd) {
            continue;
        }

        // poll cq. fd == cq channel fd.
        assert(g_p_fd_collection);
        cq_channel_info *p_cq_ch_info = g_p_fd_collection->get_cq_channel_fd(fd);
        if (p_cq_ch_info) {
            ring *p_ring = p_cq_ch_info->get_ring();
            if (p_ring) {
                p_ring->wait_for_notification_and_process_element(&poll_sn);
            }
        }
    }
    return ret;
}

mem_buf_desc_t *sockinfo_tcp::get_next_desc(mem_buf_desc_t *p_desc)
{
    m_rx_pkt_ready_list.pop_front();
    IF_STATS(m_p_socket_stats->n_rx_ready_pkt_count--);

    m_n_rx_pkt_ready_list_count--;
    if (p_desc->p_next_desc) {
        mem_buf_desc_t *prev = p_desc;
        p_desc = p_desc->p_next_desc;
        prev->rx.sz_payload = prev->lwip_pbuf.len;
        p_desc->rx.sz_payload = p_desc->lwip_pbuf.tot_len =
            prev->lwip_pbuf.tot_len - prev->lwip_pbuf.len;
        p_desc->rx.n_frags = --prev->rx.n_frags;
        p_desc->inc_ref_count();
        m_rx_pkt_ready_list.push_front(p_desc);
        m_n_rx_pkt_ready_list_count++;
        prev->lwip_pbuf.next = nullptr;
        prev->p_next_desc = nullptr;
        prev->rx.n_frags = 1;
        IF_STATS(m_p_socket_stats->n_rx_ready_pkt_count++);
        reuse_buffer(prev);
    } else {
        reuse_buffer(p_desc);
    }
    if (m_n_rx_pkt_ready_list_count) {
        return m_rx_pkt_ready_list.front();
    } else {
        return nullptr;
    }
}

mem_buf_desc_t *sockinfo_tcp::get_next_desc_peek(mem_buf_desc_t *pdesc, int &rx_pkt_ready_list_idx)
{

    if (unlikely(pdesc->p_next_desc)) {
        pdesc = pdesc->p_next_desc;
    } else if (rx_pkt_ready_list_idx < m_n_rx_pkt_ready_list_count) {
        pdesc = m_rx_pkt_ready_list[rx_pkt_ready_list_idx];
        rx_pkt_ready_list_idx++;
    } else {
        pdesc = nullptr;
    }

    return pdesc;
}

timestamps_t *sockinfo_tcp::get_socket_timestamps()
{
    return &m_rx_timestamps;
}

void sockinfo_tcp::post_dequeue(bool release_buff)
{
    NOT_IN_USE(release_buff);
}

int sockinfo_tcp::zero_copy_rx(iovec *p_iov, mem_buf_desc_t *pdesc, int *p_flags)
{
    NOT_IN_USE(p_flags);
    int total_rx = 0, offset = 0;
    int len = (int)p_iov[0].iov_len - sizeof(xlio_recvfrom_zcopy_packets_t) -
        sizeof(xlio_recvfrom_zcopy_packet_t) - sizeof(iovec);
    mem_buf_desc_t *p_desc_iter;
    mem_buf_desc_t *prev;

    // Make sure there is enough room for the header
    if (len < 0) {
        errno = ENOBUFS;
        return -1;
    }

    pdesc->rx.frag.iov_base = (uint8_t *)pdesc->rx.frag.iov_base + m_rx_pkt_ready_offset;
    pdesc->rx.frag.iov_len -= m_rx_pkt_ready_offset;
    p_desc_iter = pdesc;
    prev = pdesc;

    // Copy iov pointers to user buffer
    xlio_recvfrom_zcopy_packets_t *p_packets = (xlio_recvfrom_zcopy_packets_t *)p_iov[0].iov_base;
    p_packets->n_packet_num = 0;

    offset += sizeof(p_packets->n_packet_num); // skip n_packet_num size

    while (len >= 0 && m_n_rx_pkt_ready_list_count) {
        xlio_recvfrom_zcopy_packet_t *p_pkts =
            (xlio_recvfrom_zcopy_packet_t *)((char *)p_packets + offset);
        p_packets->n_packet_num++;
        p_pkts->packet_id = (void *)p_desc_iter;
        p_pkts->sz_iov = 0;
        while (len >= 0 && p_desc_iter) {

            p_pkts->iov[p_pkts->sz_iov++] = p_desc_iter->rx.frag;
            total_rx += p_desc_iter->rx.frag.iov_len;

            prev = p_desc_iter;
            p_desc_iter = p_desc_iter->p_next_desc;
            len -= sizeof(iovec);
            offset += sizeof(iovec);
        }

        m_rx_pkt_ready_list.pop_front();
        IF_STATS(m_p_socket_stats->n_rx_zcopy_pkt_count++);

        if (len < 0 && p_desc_iter) {
            // Update length of right side of chain after split - push to pkt_ready_list
            p_desc_iter->rx.sz_payload = p_desc_iter->lwip_pbuf.tot_len =
                prev->lwip_pbuf.tot_len - prev->lwip_pbuf.len;

            // Update length of left side of chain after split - return to app
            mem_buf_desc_t *p_desc_head = reinterpret_cast<mem_buf_desc_t *>(p_pkts->packet_id);
            // XXX TODO: subsequent buffers are not updated
            p_desc_head->lwip_pbuf.tot_len = p_desc_head->rx.sz_payload -=
                p_desc_iter->rx.sz_payload;

            p_desc_iter->rx.n_frags = p_desc_head->rx.n_frags - p_pkts->sz_iov;
            p_desc_head->rx.n_frags = p_pkts->sz_iov;
            p_desc_iter->inc_ref_count();

            prev->lwip_pbuf.next = nullptr;
            prev->p_next_desc = nullptr;

            m_rx_pkt_ready_list.push_front(p_desc_iter);
            break;
        }

        m_n_rx_pkt_ready_list_count--;
        IF_STATS(m_p_socket_stats->n_rx_ready_pkt_count--);

        if (m_n_rx_pkt_ready_list_count) {
            p_desc_iter = m_rx_pkt_ready_list.front();
        }

        len -= sizeof(xlio_recvfrom_zcopy_packet_t);
        offset += sizeof(xlio_recvfrom_zcopy_packet_t);
    }

    return total_rx;
}

void sockinfo_tcp::statistics_print(vlog_levels_t log_level /* = VLOG_DEBUG */)
{
    const char *const tcp_sock_state_str[] = {
        "NA",
        "TCP_SOCK_INITED",
        "TCP_SOCK_BOUND",
        "TCP_SOCK_LISTEN_READY",
        "TCP_SOCK_ACCEPT_READY",
        "TCP_SOCK_CONNECTED_RD",
        "TCP_SOCK_CONNECTED_WR",
        "TCP_SOCK_CONNECTED_RDWR",
        "TCP_SOCK_ASYNC_CONNECT",
        "TCP_SOCK_ACCEPT_SHUT",
    };

    const char *const tcp_conn_state_str[] = {
        "TCP_CONN_INIT",    "TCP_CONN_CONNECTING", "TCP_CONN_CONNECTED", "TCP_CONN_FAILED",
        "TCP_CONN_TIMEOUT", "TCP_CONN_ERROR",      "TCP_CONN_RESETED",
    };
    struct tcp_pcb pcb;
    tcp_sock_state_e sock_state;
    tcp_conn_state_e conn_state;
    u32_t last_unsent_seqno = 0, last_unacked_seqno = 0, first_unsent_seqno = 0,
          first_unacked_seqno = 0;
    u32_t last_unsent_len = 0, last_unacked_len = 0, first_unsent_len = 0, first_unacked_len = 0;
    int rcvbuff_max, rcvbuff_current, rcvbuff_non_tcp_recved, rx_pkt_ready_list_size,
        rx_ctl_packets_list_size, rx_ctl_reuse_list_size;

    sockinfo::statistics_print(log_level);

    // Prepare data
    lock_tcp_con();

    pcb = m_pcb;

    if (m_pcb.unsent) {
        first_unsent_seqno = m_pcb.unsent->seqno;
        first_unsent_len = m_pcb.unsent->len;

        if (m_pcb.last_unsent) {
            last_unsent_seqno = m_pcb.last_unsent->seqno;
            last_unsent_len = m_pcb.last_unsent->len;
        }
    }

    if (m_pcb.unacked) {
        first_unacked_seqno = m_pcb.unacked->seqno;
        first_unacked_len = m_pcb.unacked->len;

        if (m_pcb.last_unacked) {
            last_unacked_seqno = m_pcb.last_unacked->seqno;
            last_unacked_len = m_pcb.last_unacked->len;
        }
    }

    sock_state = m_sock_state;
    conn_state = m_conn_state;
    rcvbuff_max = m_rcvbuff_max;
    rcvbuff_current = m_rcvbuff_current;
    rcvbuff_non_tcp_recved = m_rcvbuff_non_tcp_recved;
    rx_pkt_ready_list_size = m_rx_pkt_ready_list.size();
    rx_ctl_packets_list_size = m_rx_ctl_packets_list.size();
    rx_ctl_reuse_list_size = m_rx_ctl_reuse_list.size();

    unlock_tcp_con();

    // Socket data
    vlog_printf(log_level, "Socket state : %s\n", tcp_sock_state_str[sock_state]);
    vlog_printf(log_level, "Connection state : %s\n", tcp_conn_state_str[conn_state]);
    vlog_printf(log_level,
                "Receive buffer : m_rcvbuff_current %d, m_rcvbuff_max %d, "
                "m_rcvbuff_non_tcp_recved %d\n",
                rcvbuff_current, rcvbuff_max, rcvbuff_non_tcp_recved);
    vlog_printf(log_level,
                "Rx lists size : m_rx_pkt_ready_list %d, m_rx_ctl_packets_list %d, "
                "m_rx_ctl_reuse_list %d\n",
                rx_pkt_ready_list_size, rx_ctl_packets_list_size, rx_ctl_reuse_list_size);

    // PCB data
    vlog_printf(log_level, "PCB state : %s\n", tcp_state_str[get_tcp_state(&pcb)]);
    vlog_printf(log_level, "PCB flags : 0x%x\n", pcb.flags);
    vlog_printf(log_level, "Segment size : mss %hu, advtsd_mss %hu\n", pcb.mss, pcb.advtsd_mss);

    // Window scaling
    if (pcb.flags & TF_WND_SCALE) {
        vlog_printf(log_level, "Window scaling : ENABLED, rcv_scale %u, snd_scale %u\n",
                    pcb.rcv_scale, pcb.snd_scale);

        // Receive and send windows
        vlog_printf(log_level,
                    "Receive window : rcv_wnd %u (%u), rcv_ann_wnd %u (%u), rcv_wnd_max %u (%u), "
                    "rcv_wnd_max_desired %u (%u)\n",
                    pcb.rcv_wnd, RCV_WND_SCALE(&pcb, pcb.rcv_wnd), pcb.rcv_ann_wnd,
                    RCV_WND_SCALE(&pcb, pcb.rcv_ann_wnd), pcb.rcv_wnd_max,
                    RCV_WND_SCALE(&pcb, pcb.rcv_wnd_max), pcb.rcv_wnd_max_desired,
                    RCV_WND_SCALE(&pcb, pcb.rcv_wnd_max_desired));

        vlog_printf(log_level, "Send window : snd_wnd %u (%u), snd_wnd_max %u (%u)\n", pcb.snd_wnd,
                    (pcb.snd_wnd >> pcb.snd_scale), pcb.snd_wnd_max,
                    (pcb.snd_wnd_max >> pcb.snd_scale));
    } else {
        vlog_printf(log_level, "Window scaling : DISABLED\n");

        // Receive and send windows
        vlog_printf(log_level,
                    "Receive window : rcv_wnd %u, rcv_ann_wnd %u, rcv_wnd_max %u, "
                    "rcv_wnd_max_desired %u\n",
                    pcb.rcv_wnd, pcb.rcv_ann_wnd, pcb.rcv_wnd_max, pcb.rcv_wnd_max_desired);

        vlog_printf(log_level, "Send window : snd_wnd %u, snd_wnd_max %u\n", pcb.snd_wnd,
                    pcb.snd_wnd_max);
    }

    // Congestion variable
    vlog_printf(log_level, "Congestion : cwnd %u\n", pcb.cwnd);

    // Receiver variables
    vlog_printf(log_level, "Receiver data : rcv_nxt %u, rcv_ann_right_edge %u\n", pcb.rcv_nxt,
                pcb.rcv_ann_right_edge);

    // Sender variables
    vlog_printf(log_level, "Sender data : snd_nxt %u, snd_wl1 %u, snd_wl2 %u\n", pcb.snd_nxt,
                pcb.snd_wl1, pcb.snd_wl2);

    // Send buffer
    vlog_printf(log_level, "Send buffer : snd_buf %d, max_snd_buff %u\n", pcb.snd_buf,
                pcb.max_snd_buff);

    // Retransmission
    vlog_printf(log_level, "Retransmission : rtime %hd, rto %u, nrtx %u\n", pcb.rtime, pcb.rto,
                pcb.nrtx);

    // RTT
    vlog_printf(log_level, "RTT variables : rttest %u, rtseq %u\n", pcb.rttest, pcb.rtseq);

    // First unsent
    if (first_unsent_seqno) {
        vlog_printf(log_level, "First unsent : seqno %u, len %hu, seqno + len %u\n",
                    first_unsent_seqno, first_unsent_len, first_unsent_seqno + first_unsent_len);

        // Last unsent
        if (last_unsent_seqno) {
            vlog_printf(log_level, "Last unsent : seqno %u, len %hu, seqno + len %u\n",
                        last_unsent_seqno, last_unsent_len, last_unsent_seqno + last_unsent_len);
        }
    } else {
        vlog_printf(log_level, "First unsent : NULL\n");
    }

    // First unsent
    if (first_unacked_seqno) {
        vlog_printf(log_level, "First unacked : seqno %u, len %hu, seqno + len %u\n",
                    first_unacked_seqno, first_unacked_len,
                    first_unacked_seqno + first_unacked_len);

        // Last unacked
        if (last_unacked_seqno) {
            vlog_printf(log_level, "Last unacked : seqno %u, len %hu, seqno + len %u\n",
                        last_unacked_seqno, last_unacked_len,
                        last_unacked_seqno + last_unacked_len);
        }
    } else {
        vlog_printf(log_level, "First unacked : NULL\n");
    }

    // Acknowledge
    vlog_printf(log_level, "Acknowledge : lastack %u\n", pcb.lastack);

    // TCP timestamp
#if LWIP_TCP_TIMESTAMPS
    if (pcb.flags & TF_TIMESTAMP) {
        vlog_printf(log_level, "Timestamp : ts_lastacksent %u, ts_recent %u\n", pcb.ts_lastacksent,
                    pcb.ts_recent);
    }
#endif
}

inline void sockinfo_tcp::non_tcp_recved(int rx_len)
{
    m_rcvbuff_current -= rx_len;
    // data that was not tcp_recved should do it now.
    if (m_rcvbuff_non_tcp_recved > 0) {
        int bytes_to_tcp_recved = std::min(m_rcvbuff_non_tcp_recved, rx_len);
        tcp_recved(&m_pcb, bytes_to_tcp_recved);
        m_rcvbuff_non_tcp_recved -= bytes_to_tcp_recved;
    }
}

int sockinfo_tcp::recvfrom_zcopy_free_packets(struct xlio_recvfrom_zcopy_packet_t *pkts,
                                              size_t count)
{
    int ret = 0;
    unsigned int index = 0;
    int total_rx = 0, offset = 0;
    mem_buf_desc_t *buff;
    char *buf = (char *)pkts;

    lock_tcp_con();
    for (index = 0; index < count; index++) {
        xlio_recvfrom_zcopy_packet_t *p_pkts = (xlio_recvfrom_zcopy_packet_t *)(buf + offset);
        buff = (mem_buf_desc_t *)p_pkts->packet_id;

        if (m_p_rx_ring && !m_p_rx_ring->is_member(buff->p_desc_owner)) {
            errno = ENOENT;
            ret = -1;
            break;
        } else if (m_rx_ring_map.find(buff->p_desc_owner->get_parent()) == m_rx_ring_map.end()) {
            errno = ENOENT;
            ret = -1;
            break;
        }

        total_rx += buff->rx.sz_payload;
        reuse_buffer(buff);
        IF_STATS(m_p_socket_stats->n_rx_zcopy_pkt_count--);

        offset += p_pkts->sz_iov * sizeof(iovec) + sizeof(xlio_recvfrom_zcopy_packet_t);
    }

    if (total_rx > 0) {
        non_tcp_recved(total_rx);
    }

    unlock_tcp_con();
    return ret;
}

void sockinfo_tcp::socketxtreme_recv_buffs_tcp(mem_buf_desc_t *desc, uint16_t len)
{
    lock_tcp_con();
    reuse_buffer(desc);
    non_tcp_recved(len);
    unlock_tcp_con();
}

mem_buf_desc_t *sockinfo_tcp::tcp_tx_mem_buf_alloc(pbuf_type type)
{
    dst_entry_tcp *p_dst = (dst_entry_tcp *)(m_p_connected_dst_entry);
    mem_buf_desc_t *desc = nullptr;

    if (likely(p_dst)) {
        /* Currently this method is called from TLS layer without locks */
        m_tcp_con_lock.lock();
        desc = p_dst->get_buffer(type, nullptr);
        m_tcp_con_lock.unlock();
    }
    return desc;
}

void sockinfo_tcp::tcp_rx_mem_buf_free(mem_buf_desc_t *p_desc)
{
    reuse_buffer(p_desc);
}

struct pbuf *sockinfo_tcp::tcp_tx_pbuf_alloc(void *p_conn, pbuf_type type, pbuf_desc *desc,
                                             struct pbuf *p_buff)
{
    sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)(((struct tcp_pcb *)p_conn)->my_container);
    dst_entry_tcp *p_dst = (dst_entry_tcp *)(p_si_tcp->m_p_connected_dst_entry);
    mem_buf_desc_t *p_desc = nullptr;

    if (likely(p_dst)) {
        p_desc = p_dst->get_buffer(type, desc);
    }
    if (likely(p_desc) && p_desc->lwip_pbuf.type == PBUF_ZEROCOPY) {
        if (p_desc->lwip_pbuf.desc.attr == PBUF_DESC_EXPRESS) {
            p_desc->m_flags |= mem_buf_desc_t::ZCOPY;
            p_desc->tx.zc.callback = tcp_express_zc_callback;
            if (p_buff) {
                mem_buf_desc_t *p_prev_desc = reinterpret_cast<mem_buf_desc_t *>(p_buff);
                p_desc->tx.zc.ctx = p_prev_desc->tx.zc.ctx;
            } else {
                p_desc->tx.zc.ctx = reinterpret_cast<void *>(p_si_tcp);
            }
        } else if ((p_desc->lwip_pbuf.desc.attr == PBUF_DESC_NONE) ||
                   (p_desc->lwip_pbuf.desc.attr == PBUF_DESC_MKEY) ||
                   (p_desc->lwip_pbuf.desc.attr == PBUF_DESC_NVME_TX)) {
            /* Prepare error queue fields for send zerocopy */
            if (p_buff) {
                /* It is a special case that can happen as a result
                 * of split operation of existing zc buffer
                 */
                mem_buf_desc_t *p_prev_desc = (mem_buf_desc_t *)p_buff;
                p_desc->m_flags |= mem_buf_desc_t::ZCOPY;
                p_desc->tx.zc.id = p_prev_desc->tx.zc.id;
                p_desc->tx.zc.count = p_prev_desc->tx.zc.count;
                p_desc->tx.zc.len = p_desc->lwip_pbuf.len;
                p_desc->tx.zc.ctx = p_prev_desc->tx.zc.ctx;
                p_desc->tx.zc.callback = tcp_tx_zc_callback;
                p_prev_desc->tx.zc.count = 0;
                if (p_si_tcp->m_last_zcdesc == p_prev_desc) {
                    p_si_tcp->m_last_zcdesc = p_desc;
                }
            } else {
                p_si_tcp->tcp_tx_zc_alloc(p_desc);
            }
        }
    }
    return (struct pbuf *)p_desc;
}

void sockinfo_tcp::tcp_rx_pbuf_free(struct pbuf *p_buff)
{
    mem_buf_desc_t *desc = (mem_buf_desc_t *)p_buff;

    if (desc->p_desc_owner && p_buff->type != PBUF_ZEROCOPY) {
        desc->p_desc_owner->mem_buf_rx_release(desc);
    } else {
        buffer_pool::free_rx_lwip_pbuf_custom(p_buff);
    }
}

// single buffer only
void sockinfo_tcp::tcp_tx_pbuf_free(void *p_conn, struct pbuf *p_buff)
{
    sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)(((struct tcp_pcb *)p_conn)->my_container);
    dst_entry_tcp *p_dst = (dst_entry_tcp *)(p_si_tcp->m_p_connected_dst_entry);

    if (likely(p_dst)) {
        p_dst->put_buffer((mem_buf_desc_t *)p_buff);
    } else if (p_buff) {
        mem_buf_desc_t *p_desc = (mem_buf_desc_t *)p_buff;

        // potential race, ref is protected here by tcp lock, and in ring by ring_tx lock
        if (likely(p_desc->lwip_pbuf_get_ref_count())) {
            p_desc->lwip_pbuf_dec_ref_count();
        } else {
            __log_err("ref count of %p is already zero, double free??", p_desc);
        }

        if (p_desc->lwip_pbuf.ref == 0) {
            p_desc->p_next_desc = nullptr;
            buffer_pool::free_tx_lwip_pbuf_custom(p_buff);
        }
    }
}

mem_buf_desc_t *sockinfo_tcp::tcp_tx_zc_alloc(mem_buf_desc_t *p_desc)
{
    p_desc->m_flags |= mem_buf_desc_t::ZCOPY;
    p_desc->tx.zc.id = atomic_read(&m_zckey);
    p_desc->tx.zc.count = 1;
    p_desc->tx.zc.len = p_desc->lwip_pbuf.len;
    p_desc->tx.zc.ctx = (void *)this;
    p_desc->tx.zc.callback = tcp_tx_zc_callback;

    if (m_last_zcdesc && (m_last_zcdesc != p_desc) && (m_last_zcdesc->lwip_pbuf.ref > 0) &&
        (m_last_zcdesc->tx.zc.id == p_desc->tx.zc.id)) {
        m_last_zcdesc->tx.zc.len = m_last_zcdesc->lwip_pbuf.len;
        m_last_zcdesc->tx.zc.count = 0;
    }
    m_last_zcdesc = p_desc;

    return p_desc;
}

/*static*/
void sockinfo_tcp::tcp_express_zc_callback(mem_buf_desc_t *p_desc)
{
    sockinfo_tcp *si = reinterpret_cast<sockinfo_tcp *>(p_desc->tx.zc.ctx);
    const uintptr_t opaque_op = reinterpret_cast<uintptr_t>(p_desc->lwip_pbuf.desc.opaque);

    if (opaque_op && si->m_p_group && si->m_p_group->m_socket_comp_cb) {
        si->m_p_group->m_socket_comp_cb(reinterpret_cast<xlio_socket_t>(si),
                                        si->m_xlio_socket_userdata, opaque_op);
    }
}

/*static*/
void sockinfo_tcp::tcp_tx_zc_callback(mem_buf_desc_t *p_desc)
{
    sockinfo_tcp *sock = nullptr;

    if (!p_desc) {
        return;
    }

    if (!p_desc->tx.zc.ctx || !p_desc->tx.zc.count) {
        goto cleanup;
    }

    sock = (sockinfo_tcp *)p_desc->tx.zc.ctx;

    if (sock->m_state != SOCKINFO_OPENED) {
        goto cleanup;
    }

    sock->tcp_tx_zc_handle(p_desc);

cleanup:
    /* Clean up */
    p_desc->m_flags &= ~mem_buf_desc_t::ZCOPY;
    memset(&p_desc->tx.zc, 0, sizeof(p_desc->tx.zc));
    if (sock && p_desc == sock->m_last_zcdesc) {
        sock->m_last_zcdesc = nullptr;
    }
}

void sockinfo_tcp::tcp_tx_zc_handle(mem_buf_desc_t *p_desc)
{
    uint32_t lo, hi;
    uint16_t count;
    uint32_t prev_lo, prev_hi;
    mem_buf_desc_t *err_queue = nullptr;
    sockinfo_tcp *sock = this;

    count = p_desc->tx.zc.count;
    lo = p_desc->tx.zc.id;
    hi = lo + count - 1;
    memset(&p_desc->ee, 0, sizeof(p_desc->ee));
    p_desc->ee.ee_errno = 0;
    p_desc->ee.ee_origin = SO_EE_ORIGIN_ZEROCOPY;
    p_desc->ee.ee_data = hi;
    p_desc->ee.ee_info = lo;
    //	p_desc->ee.ee_code |= SO_EE_CODE_ZEROCOPY_COPIED;

    m_error_queue_lock.lock();

    /* Update last error queue element in case it has the same type */
    err_queue = sock->m_error_queue.back();
    if (err_queue && (err_queue->ee.ee_origin == p_desc->ee.ee_origin) &&
        (err_queue->ee.ee_code == p_desc->ee.ee_code)) {
        uint64_t sum_count = 0;

        prev_hi = err_queue->ee.ee_data;
        prev_lo = err_queue->ee.ee_info;
        sum_count = prev_hi - prev_lo + 1ULL + count;

        if (lo == prev_lo) {
            if (hi > prev_hi) {
                err_queue->ee.ee_data = hi;
            }
        } else if ((sum_count >= (1ULL << 32)) || (lo != prev_hi + 1)) {
            err_queue = nullptr;
        } else {
            err_queue->ee.ee_data += count;
        }
    }

    /* Add  information into error queue element */
    if (!err_queue) {
        err_queue = p_desc->clone();
        sock->m_error_queue.push_back(err_queue);
    }

    m_error_queue_lock.unlock();

    /* Signal events on socket */
    NOTIFY_ON_EVENTS(sock, EPOLLERR);

    // Avoid cache access unnecessarily.
    // Non-blocking sockets are waked-up as part of mux handling.
    if (unlikely(is_blocking())) {
        sock->m_sock_wakeup_pipe.do_wakeup();
    }
}

struct tcp_seg *sockinfo_tcp::tcp_seg_alloc_direct(void *p_conn)
{
    sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)(((struct tcp_pcb *)p_conn)->my_container);
    return p_si_tcp->get_tcp_seg_direct();
}

struct tcp_seg *sockinfo_tcp::tcp_seg_alloc_cached(void *p_conn)
{
    sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)(((struct tcp_pcb *)p_conn)->my_container);
    return p_si_tcp->get_tcp_seg_cached();
}

void sockinfo_tcp::tcp_seg_free_direct(void *p_conn, struct tcp_seg *seg)
{
    sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)(((struct tcp_pcb *)p_conn)->my_container);
    p_si_tcp->put_tcp_seg_direct(seg);
}

void sockinfo_tcp::tcp_seg_free_cached(void *p_conn, struct tcp_seg *seg)
{
    sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)(((struct tcp_pcb *)p_conn)->my_container);
    p_si_tcp->put_tcp_seg_cached(seg);
}

void sockinfo_tcp::return_tcp_segs(struct tcp_seg *seg)
{
    (likely(m_p_rx_ring)) ? m_p_rx_ring->put_tcp_segs(seg) : g_tcp_seg_pool->put_objs(seg);
}

struct tcp_seg *sockinfo_tcp::get_tcp_seg_direct()
{
    return likely(m_p_rx_ring) ? m_p_rx_ring->get_tcp_segs(1U) : g_tcp_seg_pool->get_objs(1U);
}

struct tcp_seg *sockinfo_tcp::get_tcp_seg_cached()
{
    if (!m_tcp_seg_list) {
        m_tcp_seg_list = (likely(m_p_rx_ring))
            ? m_p_rx_ring->get_tcp_segs(m_sysvar_tx_segs_batch_tcp)
            : g_tcp_seg_pool->get_objs(m_sysvar_tx_segs_batch_tcp);

        if (unlikely(!m_tcp_seg_list)) {
            return nullptr;
        }
        m_tcp_seg_count += m_sysvar_tx_segs_batch_tcp;
    }

    tcp_seg *head = m_tcp_seg_list;
    m_tcp_seg_list = head->next;
    head->next = nullptr;
    ++m_tcp_seg_in_use;

    return head;
}

// Assumed seg != nullptr
void sockinfo_tcp::put_tcp_seg_direct(struct tcp_seg *seg)
{
    seg->next = nullptr; // Very important. We occasionaly get here trashed seg->next.
    return_tcp_segs(seg);
}

void sockinfo_tcp::put_tcp_seg_cached(struct tcp_seg *seg)
{
    if (unlikely(!seg)) {
        return;
    }

    seg->next = m_tcp_seg_list;
    m_tcp_seg_list = seg;
    --m_tcp_seg_in_use;
    if (m_tcp_seg_count > 2U * m_sysvar_tx_segs_batch_tcp &&
        m_tcp_seg_in_use < m_tcp_seg_count / 2U) {
        return_tcp_segs(tcp_seg_pool::split_obj_list((m_tcp_seg_count - m_tcp_seg_in_use) / 2U,
                                                     m_tcp_seg_list, m_tcp_seg_count));
    }
}

tcp_timers_collection::tcp_timers_collection()
    : tcp_timers_collection(safe_mce_sys().tcp_timer_resolution_msec /
                            safe_mce_sys().timer_resolution_msec)
{
}

tcp_timers_collection::tcp_timers_collection(int intervals)
{
    m_n_intervals_size = intervals;
    m_p_intervals.resize(m_n_intervals_size);
}

tcp_timers_collection::~tcp_timers_collection()
{
    free_tta_resources();
}

event_handler_manager *tcp_timers_collection::get_event_mgr()
{
    if (m_p_group) {
        return m_p_group->get_event_handler();
    } else if (safe_mce_sys().tcp_ctl_thread ==
               option_tcp_ctl_thread::CTL_THREAD_DELEGATE_TCP_TIMERS) {
        return &g_event_handler_manager_local;
    } else {
        return g_p_event_handler_manager;
    }
}

void tcp_timers_collection::free_tta_resources()
{
    for (auto &bucket : m_p_intervals) {
        while (!bucket.empty()) {
            remove_timer(bucket.front());
        }
    }

    if (m_n_count) {
        __log_dbg("Not all TCP socket timers have been removed, count=%d", m_n_count);
    }
}

void tcp_timers_collection::clean_obj()
{
    if (is_cleaned()) {
        return;
    }

    set_cleaned();
    m_timer_handle = nullptr;

    event_handler_manager *p_event_mgr = get_event_mgr();
    if (p_event_mgr->is_running()) {
        p_event_mgr->unregister_timers_event_and_delete(this);
    } else {
        cleanable_obj::clean_obj();
    }
}

void tcp_timers_collection::handle_timer_expired(void *user_data)
{
    NOT_IN_USE(user_data);
    sock_list &bucket = m_p_intervals[m_n_location];
    m_n_location = (m_n_location + 1) % m_n_intervals_size;

    auto iter = bucket.begin();
    while (iter != bucket.end()) {
        sockinfo_tcp *p_sock = *iter;
        // Must inc iter first bacause handle_timer_expired can erase
        // the socket that the iter points to, with delegated timers.
        iter++;

        /* It is not guaranteed that the same sockinfo object is met once
         * in this loop.
         * So in case sockinfo object is destroyed other processing
         * of the same object mast be ingored.
         * TODO Check on is_cleaned() is not safe completely.
         */
        if (!p_sock->trylock_tcp_con()) {
            bool destroyable = false;
            if (!p_sock->is_cleaned()) {
                p_sock->handle_timer_expired();
                destroyable = p_sock->is_destroyable_no_lock();
            }
            p_sock->unlock_tcp_con();
            if (destroyable) {
                g_p_fd_collection->destroy_sockfd(p_sock);
            }
        }
    }

    /* Processing all messages for the daemon */
    if (g_p_agent) {
        g_p_agent->progress();
    }
}

void tcp_timers_collection::add_new_timer(sockinfo_tcp *sock)
{
    if (!sock) {
        __log_warn("Trying to add timer for null TCP socket %p", sock);
        return;
    }

    sock_list &bucket = m_p_intervals[m_n_next_insert_bucket];
    bucket.emplace_back(sock);
    auto rc =
        m_sock_remove_map.emplace(sock, std::make_tuple(m_n_next_insert_bucket, --(bucket.end())));

    // If the socket already exists in m_sock_remove_map, emplace returns false in rc.second
    // Mainly for sanity check, we dont expect it.
    if (unlikely(!rc.second)) {
        __log_warn("Trying to add timer twice for TCP socket %p", sock);
        bucket.pop_back();
        return;
    }

    m_n_next_insert_bucket = (m_n_next_insert_bucket + 1) % m_n_intervals_size;
    if (0 == m_n_count++) {
        m_timer_handle = get_event_mgr()->register_timer_event(safe_mce_sys().timer_resolution_msec,
                                                               this, PERIODIC_TIMER, nullptr);
    }

    __log_dbg("New TCP socket [%p] timer was added", sock);
}

void tcp_timers_collection::remove_timer(sockinfo_tcp *sock)
{
    auto node = m_sock_remove_map.find(sock);
    if (node != m_sock_remove_map.end()) {
        m_p_intervals[std::get<0>(node->second)].erase(std::get<1>(node->second));
        m_sock_remove_map.erase(node);
        sock->set_timer_registered(false);

        if (!(--m_n_count)) {
            if (m_timer_handle) {
                get_event_mgr()->unregister_timer_event(this, m_timer_handle);
                m_timer_handle = nullptr;
            }
        }

        __log_dbg("TCP socket [%p] timer was removed", sock);
    } else {
        // Listen sockets are not added to timers.
        // As part of socket general unregister and destroy they will get here and will no be
        // found.
        __log_dbg("TCP socket [%p] timer was not found (listen socket)", sock);
    }
}

void tcp_timers_collection::register_wakeup_event()
{
    g_p_event_handler_manager->wakeup_timer_event(this, m_timer_handle);
}

thread_local_tcp_timers::thread_local_tcp_timers()
    : tcp_timers_collection(1)
{
}

thread_local_tcp_timers::~thread_local_tcp_timers()
{
    m_timer_handle = nullptr;
}

void sockinfo_tcp::update_header_field(data_updater *updater)
{
    lock_tcp_con();

    if (m_p_connected_dst_entry) {
        updater->update_field(*m_p_connected_dst_entry);
    }

    unlock_tcp_con();
}

bool sockinfo_tcp::is_utls_supported(int direction) const
{
    bool result = false;

#ifdef DEFINED_UTLS
    ring *p_ring = get_tx_ring();

    if (direction & UTLS_MODE_TX) {
        result = result || (safe_mce_sys().enable_utls_tx && p_ring && p_ring->tls_tx_supported());
    }
    if (direction & UTLS_MODE_RX) {
        /*
         * For RX support we still can use TX ring capabilities,
         * because it refers to the same NIC as RX ring.
         */
        result = result || (safe_mce_sys().enable_utls_rx && p_ring && p_ring->tls_rx_supported());
    }
#else
    NOT_IN_USE(direction);
#endif /* DEFINED_UTLS */
    return result;
}

int sockinfo_tcp::get_supported_nvme_feature_mask() const
{
    ring *p_ring = get_tx_ring();
    if (!p_ring) {
        return false;
    }
    return p_ring->get_supported_nvme_feature_mask();
}

inline bool sockinfo_tcp::handle_bind_no_port(int &bind_ret, in_port_t in_port,
                                              const sockaddr *__addr, socklen_t __addrlen)
{
#define RETURN_FROM_BIND   true
#define CONTINUE_WITH_BIND false

    if (in_port) {
        return CONTINUE_WITH_BIND;
    }

    if (m_sock_state == TCP_SOCK_BOUND_NO_PORT) {
        // bind call from connect()
        if ((bind_ret = g_bind_no_port->bind_and_set_port_map(m_bound, m_connected, m_fd))) {
            return RETURN_FROM_BIND;
        }
    } else {
        // first bind call with port 0, we set SO_REUSEPORT so we will be able to bind to a
        // specific port later when we reuse port
        int so_reuseport = 1;
        if ((bind_ret = SYSCALL(setsockopt, m_fd, SOL_SOCKET, SO_REUSEPORT, &so_reuseport,
                                sizeof(so_reuseport)))) {
            return RETURN_FROM_BIND;
        }
        m_bound.set_sockaddr(__addr, __addrlen);
        m_sock_state = TCP_SOCK_BOUND_NO_PORT;
        return RETURN_FROM_BIND;
    }

    return CONTINUE_WITH_BIND;
}

void sockinfo_tcp::make_dirty()
{
    if (!m_b_xlio_socket_dirty) {
        m_b_xlio_socket_dirty = true;
        m_p_group->add_dirty_socket(this);
    }
}

int sockinfo_tcp::tcp_tx_express(const struct iovec *iov, unsigned iov_len, uint32_t mkey,
                                 unsigned flags, void *opaque_op)
{
    pbuf_desc mdesc;

    switch (flags & XLIO_EXPRESS_OP_TYPE_MASK) {
    case XLIO_EXPRESS_OP_TYPE_DESC:
        mdesc.attr = PBUF_DESC_EXPRESS;
        break;
    case XLIO_EXPRESS_OP_TYPE_FILE_ZEROCOPY:
        mdesc.attr = PBUF_DESC_MDESC;
        break;
    default:
        return -1;
    };
    mdesc.mkey = mkey;
    mdesc.opaque = opaque_op;

    int bytes_written = 0;
    for (unsigned i = 0; i < iov_len; ++i) {
        bytes_written += iov[i].iov_len;
    }

    lock_tcp_con();

    if (unlikely(!is_connected_and_ready_to_send())) {
        return tcp_tx_handle_errno_and_unlock(errno);
    }

    err_t err = tcp_write_express(&m_pcb, iov, iov_len, &mdesc);
    if (unlikely(err != ERR_OK)) {
        // The only error in tcp_write_express() is a memory error.
        m_conn_state = TCP_CONN_ERROR;
        m_error_status = ENOMEM;
        return tcp_tx_handle_errno_and_unlock(ENOMEM);
    }
    if (!(flags & XLIO_EXPRESS_MSG_MORE)) {
        tcp_output(&m_pcb);
        m_b_xlio_socket_dirty = false;
    } else if (m_p_group) {
        make_dirty();
    }

    unlock_tcp_con();

    return bytes_written;
}

int sockinfo_tcp::tcp_tx_express_inline(const struct iovec *iov, unsigned iov_len, unsigned flags)
{
    pbuf_desc mdesc;
    int bytes_written = 0;

    memset(&mdesc, 0, sizeof(mdesc));
    mdesc.attr = PBUF_DESC_NONE;

    lock_tcp_con();

    if (unlikely(!is_connected_and_ready_to_send())) {
        return tcp_tx_handle_errno_and_unlock(errno);
    }

    for (unsigned i = 0; i < iov_len; ++i) {
        bytes_written += iov[i].iov_len;
        err_t err = tcp_write(&m_pcb, iov[i].iov_base, iov[i].iov_len, 0, &mdesc);
        if (unlikely(err != ERR_OK)) {
            // XXX tcp_write() can return multiple errors.
            // XXX tcp_write() can also fail due to queuelen limit, but this is unlikely.
            m_conn_state = TCP_CONN_ERROR;
            m_error_status = ENOMEM;
            return tcp_tx_handle_errno_and_unlock(ENOMEM);
        }
    }
    if (!(flags & XLIO_EXPRESS_MSG_MORE)) {
        m_b_xlio_socket_dirty = false;
        tcp_output(&m_pcb);
    } else if (m_p_group) {
        make_dirty();
    }

    unlock_tcp_con();

    return bytes_written;
}

void sockinfo_tcp::flush()
{
    lock_tcp_con();
    m_b_xlio_socket_dirty = false;
    tcp_output(&m_pcb);
    unlock_tcp_con();
}

ssize_t sockinfo_tcp::tcp_tx_handle_done_and_unlock(ssize_t total_tx, int errno_tmp, bool is_dummy,
                                                    bool is_send_zerocopy)
{
    tcp_output(&m_pcb); // force data out

    if (unlikely(m_p_socket_stats)) {
        if (unlikely(is_dummy)) {
            m_p_socket_stats->counters.n_tx_dummy++;
        } else if (total_tx) {
            m_p_socket_stats->counters.n_tx_sent_byte_count += total_tx;
            m_p_socket_stats->counters.n_tx_sent_pkt_count++;
            m_p_socket_stats->n_tx_ready_byte_count += total_tx;
        }
    }

    /* Each send call with MSG_ZEROCOPY that successfully sends
     * data increments the counter.
     * The counter is not incremented on failure or if called with length zero.
     */
    if (is_send_zerocopy && (total_tx > 0)) {
        if (m_last_zcdesc->tx.zc.id != (uint32_t)atomic_read(&m_zckey)) {
            /* si_tcp_logerr("Invalid tx zcopy operation"); */
        } else {
            atomic_fetch_and_inc(&m_zckey);
        }
    }

    unlock_tcp_con();

    /* Restore errno on function entry in case success */
    errno = errno_tmp;

    return total_tx;
}

ssize_t sockinfo_tcp::tcp_tx_handle_errno_and_unlock(int error_number)
{
    errno = error_number;

    // nothing send  nb mode or got some other error
    if (m_p_socket_stats) {
        if (errno == EAGAIN) {
            m_p_socket_stats->counters.n_tx_eagain++;
        } else {
            m_p_socket_stats->counters.n_tx_errors++;
        }
    }
    unlock_tcp_con();
    return -1;
}

ssize_t sockinfo_tcp::tcp_tx_handle_partial_send_and_unlock(ssize_t total_tx, int errno_to_report,
                                                            bool is_dummy, bool is_send_zerocopy,
                                                            int errno_to_restore)
{
    if (total_tx > 0) {
        return tcp_tx_handle_done_and_unlock(total_tx, errno_to_restore, is_dummy,
                                             is_send_zerocopy);
    }
    si_tcp_logdbg("Returning with: %d", errno_to_report);
    return tcp_tx_handle_errno_and_unlock(errno_to_report);
}

bool sockinfo_tcp::is_connected_and_ready_to_send()
{
    if (unlikely(!is_rts())) {
        if (m_conn_state == TCP_CONN_TIMEOUT) {
            si_tcp_logdbg("TX timed out");
            errno = ETIMEDOUT;
        } else if (m_conn_state == TCP_CONN_CONNECTING) {
            si_tcp_logdbg("TX while async-connect on socket return EAGAIN");
            errno = EAGAIN;
        } else if (m_conn_state == TCP_CONN_RESETED) {
            si_tcp_logdbg("TX on reseted socket");
            errno = ECONNRESET;
        } else if (m_conn_state == TCP_CONN_ERROR) {
            si_tcp_logdbg("TX on connection failed socket");
            errno = ECONNREFUSED;
        } else {
            si_tcp_logdbg("TX on unconnected socket");
            errno = EPIPE;
        }
        return false;
    }
    return true;
}

/* Process a case when space is not available at the sending socket
 * to hold the message to be transmitted
 * Nonblocking socket:
 *    - no data is buffered: return (-1) and EAGAIN
 *    - some data is buffered: return number of bytes ready to be sent
 */
ssize_t sockinfo_tcp::tcp_tx_handle_sndbuf_unavailable(ssize_t total_tx, bool is_dummy,
                                                       bool is_send_zerocopy, int errno_to_restore)
{
    // non blocking socket should return in order not to tx_wait()
    if (total_tx > 0) {
        m_tx_consecutive_eagain_count = 0;
        return tcp_tx_handle_done_and_unlock(total_tx, errno_to_restore, is_dummy,
                                             is_send_zerocopy);
    } else {
        m_tx_consecutive_eagain_count++;
        if (m_tx_consecutive_eagain_count >= TX_CONSECUTIVE_EAGAIN_THREASHOLD) {
            if (safe_mce_sys().tcp_ctl_thread ==
                option_tcp_ctl_thread::CTL_THREAD_DELEGATE_TCP_TIMERS) {
                // Slow path. We must attempt TCP timers here for applications that
                // do not check for EV_OUT.
                g_event_handler_manager_local.do_tasks();
            }
            // in case of zero sndbuf and non-blocking just try once polling CQ for
            // ACK
            int poll_count = 0;
            rx_wait(poll_count, false);
            m_tx_consecutive_eagain_count = 0;
        }
        return tcp_tx_handle_errno_and_unlock(EAGAIN);
    }
}

size_t sockinfo_tcp::handle_msg_trunc(size_t total_rx, size_t payload_size, int in_flags,
                                      int *p_out_flags)
{
    NOT_IN_USE(payload_size);
    NOT_IN_USE(in_flags);
    *p_out_flags &= ~MSG_TRUNC; // don't handle msg_trunc
    return total_rx;
}
