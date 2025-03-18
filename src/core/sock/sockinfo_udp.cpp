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

#include "sockinfo_udp.h"

#include <fcntl.h>
#include <unistd.h>
#include <ifaddrs.h>
#include "util/if.h"
#include <net/if_arp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <algorithm>

#include "utils/bullseye.h"
#include "utils/rdtsc.h"
#include "util/libxlio.h"
#include "sock/sock-redirect.h"
#include "sock/fd_collection.h"
#include "event/event_handler_manager.h"
#include "dev/buffer_pool.h"
#include "dev/ring.h"
#include "dev/ring_slave.h"
#include "dev/ring_bond.h"
#include "dev/ring_simple.h"
#include "proto/route_table_mgr.h"
#include "proto/rule_table_mgr.h"
#include "proto/dst_entry_tcp.h"
#include "proto/dst_entry_udp.h"
#include "proto/dst_entry_udp_mc.h"
#include "iomux/epfd_info.h"
#include "iomux/io_mux_call.h"
#include "util/instrumentation.h"
#include "dev/ib_ctx_handler_collection.h"

/* useful debugging macros */

#define MODULE_NAME "si_udp"
#undef MODULE_HDR_INFO
#define MODULE_HDR_INFO MODULE_NAME "[fd=%d]:%d:%s() "
#undef __INFO__
#define __INFO__ m_fd

#define si_udp_logpanic   __log_info_panic
#define si_udp_logerr     __log_info_err
#define si_udp_logwarn    __log_info_warn
#define si_udp_loginfo    __log_info_info
#define si_udp_logdbg     __log_info_dbg
#define si_udp_logfunc    __log_info_func
#define si_udp_logfuncall __log_info_funcall

/* For MCD */
#define UDP_MAP_ADD    101
#define UDP_MAP_REMOVE 102

/**/
/** inlining functions can only help if they are implemented before their usage **/
/**/

inline void sockinfo_udp::reuse_buffer(mem_buf_desc_t *buff)
{
    if (buff->dec_ref_count() <= 1) {
        buff->inc_ref_count();
        sockinfo::reuse_buffer(buff);
    }
}

inline int sockinfo_udp::poll_os()
{
    int ret;
    uint64_t pending_data = 0;

    m_rx_udp_poll_os_ratio_counter = 0;
    ret = SYSCALL(ioctl, m_fd, FIONREAD, &pending_data);
    if (unlikely(ret == -1)) {
        IF_STATS(m_p_socket_stats->counters.n_rx_os_errors++);
        si_udp_logdbg("SYSCALL(ioctl) returned with error in polling loop (errno=%d %m)", errno);
        return -1;
    }
    if (pending_data > 0) {
        IF_STATS(m_p_socket_stats->counters.n_rx_poll_os_hit++);
        return 1;
    }
    return 0;
}

inline int sockinfo_udp::rx_wait(bool blocking)
{
    ssize_t ret = 0;
    int32_t loops = 0;
    int32_t loops_to_go = blocking ? m_loops_to_go : 1;
    epoll_event rx_epfd_events[SI_RX_EPFD_EVENT_MAX];
    uint64_t poll_sn = 0;

    m_loops_timer.start();

    while (loops_to_go) {

        // Multi-thread polling support - let other threads have a go on this CPU
        if ((m_n_sysvar_rx_poll_yield_loops > 0) &&
            ((loops % m_n_sysvar_rx_poll_yield_loops) == (m_n_sysvar_rx_poll_yield_loops - 1))) {
            sched_yield();
        }

        // Poll socket for OS ready packets... (at a ratio of the offloaded sockets as defined in
        // m_n_sysvar_rx_udp_poll_os_ratio)
        if ((m_n_sysvar_rx_udp_poll_os_ratio > 0) &&
            (m_rx_udp_poll_os_ratio_counter >= m_n_sysvar_rx_udp_poll_os_ratio)) {
            ret = poll_os();
            if ((ret == -1) || (ret == 1)) {
                return ret;
            }
        }

        // Poll cq for offloaded ready packets ...
        m_rx_udp_poll_os_ratio_counter++;
        if (is_readable(&poll_sn)) {
            IF_STATS(m_p_socket_stats->counters.n_rx_poll_hit++);
            return 0;
        }

        loops++;
        if (!blocking || safe_mce_sys().rx_poll_num != -1) {
            loops_to_go--;
        }
        if (m_loops_timer.is_timeout()) {
            errno = EAGAIN;
            return -1;
        }

        if (unlikely(m_state == SOCKINFO_DESTROYING)) {
            errno = EBADFD;
            si_udp_logdbg("returning with: EBADFD");
            return -1;
        } else if (unlikely(g_b_exit)) {
            errno = EINTR;
            si_udp_logdbg("returning with: EINTR");
            return -1;
        }
    } // End polling loop

    IF_STATS(m_p_socket_stats->counters.n_rx_poll_miss++);

    while (blocking) {
        if (unlikely(m_state == SOCKINFO_DESTROYING)) {
            errno = EBADFD;
            si_udp_logdbg("returning with: EBADFD");
            return -1;
        } else if (unlikely(g_b_exit)) {
            errno = EINTR;
            si_udp_logdbg("returning with: EINTR");
            return -1;
        }

        if (rx_request_notification(poll_sn) > 0) {
            // Check if a wce became available while arming the cq's notification channel
            // A ready wce can be pending due to the drain logic
            if (is_readable(&poll_sn)) {
                return 0;
            }
            continue; // retry to arm cq notification channel in case there was no ready packet
        } else {
            // Check if we have a packet in receive queue before we go to sleep
            //(can happen if another thread was polling & processing the wce)
            // and update is_sleeping flag under the same lock to synchronize between
            // this code and wakeup mechanism.
            if (is_readable(nullptr)) {
                return 0;
            }
        }

        // Block with epoll_wait()
        // on all rx_cq's notification channels and the socket's OS fd until we get an ip packet
        // release lock so other threads that wait on this socket will not consume CPU
        /* coverity[double_lock] TODO: RM#1049980 */
        m_lock_rcv.lock();
        if (!m_n_rx_pkt_ready_list_count) {
            m_sock_wakeup_pipe.going_to_sleep();
            /* coverity[double_unlock] TODO: RM#1049980 */
            m_lock_rcv.unlock();
        } else {
            m_lock_rcv.unlock();
            continue;
        }

        ret = os_wait_sock_rx_epfd(rx_epfd_events, SI_RX_EPFD_EVENT_MAX);

        /* coverity[double_lock] TODO: RM#1049980 */
        m_lock_rcv.lock();
        m_sock_wakeup_pipe.return_from_sleep();
        /* coverity[double_unlock] TODO: RM#1049980 */
        m_lock_rcv.unlock();

        if (ret == 0) { // timeout
            errno = EAGAIN;
            return -1;
        }

        if (unlikely(ret == -1)) {
            if (errno == EINTR) {
                si_udp_logdbg("EINTR from blocked epoll_wait() (ret=%zd, errno=%d %s)", ret, errno,
                              strerror(errno));
            } else {
                si_udp_logdbg("error from blocked epoll_wait() (ret=%zd, errno=%d %s)", ret, errno,
                              strerror(errno));
            }

            IF_STATS(m_p_socket_stats->counters.n_rx_os_errors++);
            return -1;
        }

        if (ret > 0) {

            /* Quick check for a ready rx datagram on this sockinfo
             * (if some other sockinfo::rx might have added a rx ready packet to our pool
             *
             * This is the classical case of wakeup, but we don't want to
             * waist time on removing wakeup fd, it will be done next time
             */
            if (is_readable(nullptr)) {
                return 0;
            }

            // Run through all ready fd's
            for (int event_idx = 0; event_idx < ret; ++event_idx) {
                int fd = rx_epfd_events[event_idx].data.fd;
                if (m_sock_wakeup_pipe.is_wakeup_fd(fd)) {
                    /* coverity[double_lock] TODO: RM#1049980 */
                    m_lock_rcv.lock();
                    m_sock_wakeup_pipe.remove_wakeup_fd();
                    /* coverity[double_unlock] TODO: RM#1049980 */
                    m_lock_rcv.unlock();
                    continue;
                }

                // Check if OS fd is ready for reading
                if (fd == m_fd) {
                    m_rx_udp_poll_os_ratio_counter = 0;
                    return 1;
                }

                // All that is left is our CQ offloading channel fd's
                // poll cq. fd == cq channel fd.
                // Process one wce on the relevant CQ
                // The Rx CQ channel is non-blocking so this will always return quickly
                cq_channel_info *p_cq_ch_info = g_p_fd_collection->get_cq_channel_fd(fd);
                if (p_cq_ch_info) {
                    ring *p_ring = p_cq_ch_info->get_ring();
                    if (p_ring) {
                        p_ring->wait_for_notification_and_process_element(&poll_sn);
                    }
                }
            }
        }

        // Check for ready datagrams on this sockinfo
        // Our ring->poll_and_process_element might have got a ready rx datagram
        // ..or some other sockinfo::rx might have added a ready rx datagram to our list
        // In case of multiple frag we'de like to try and get all parts out of the corresponding
        // ring, so we do want to poll the cq besides the select notification
        if (is_readable(&poll_sn)) {
            return 0;
        }

    } // while (blocking)

    errno = EAGAIN;
    si_udp_logfunc("returning with: EAGAIN");
    return -1;
}

const char *setsockopt_ip_opt_to_str(int opt)
{
    switch (opt) {
    case IP_MULTICAST_IF:
        return "IP_MULTICAST_IF";
    case IP_MULTICAST_TTL:
        return "IP_MULTICAST_TTL";
    case IP_MULTICAST_LOOP:
        return "IP_MULTICAST_LOOP";
    case IP_ADD_MEMBERSHIP:
        return "IP_ADD_MEMBERSHIP";
    case IP_ADD_SOURCE_MEMBERSHIP:
        return "IP_ADD_SOURCE_MEMBERSHIP";
    case IP_DROP_MEMBERSHIP:
        return "IP_DROP_MEMBERSHIP";
    case IP_DROP_SOURCE_MEMBERSHIP:
        return "IP_DROP_SOURCE_MEMBERSHIP";
    case IPV6_MULTICAST_IF:
        return "IPV6_MULTICAST_IF";
    case IPV6_MULTICAST_HOPS:
        return "IPV6_MULTICAST_HOPS";
    case IPV6_MULTICAST_LOOP:
        return "IPV6_MULTICAST_LOOP";
    case IPV6_JOIN_GROUP:
        return "IPV6_JOIN_GROUP";
    case IPV6_LEAVE_GROUP:
        return "IPV6_LEAVE_GROUP";
    case MCAST_JOIN_GROUP:
        return "MCAST_JOIN_GROUP";
    case MCAST_LEAVE_GROUP:
        return "MCAST_LEAVE_GROUP";
    case MCAST_BLOCK_SOURCE:
        return "MCAST_BLOCK_SOURCE";
    case MCAST_UNBLOCK_SOURCE:
        return "MCAST_UNBLOCK_SOURCE";
    case MCAST_JOIN_SOURCE_GROUP:
        return "MCAST_JOIN_SOURCE_GROUP";
    case MCAST_LEAVE_SOURCE_GROUP:
        return "MCAST_LEAVE_SOURCE_GROUP";
    default:
        break;
    }
    return "UNKNOWN IP opt";
}

const char *setsockopt_level_to_str(int level)
{
    switch (level) {
    case IPPROTO_IPV6:
        return "IPPROTO_IPV6";
    case IPPROTO_IP:
        return "IPPROTO_IP";
    default:
        break;
    }
    return "UNKNOWN opt level";
}
// Throttle the amount of ring polling we do (remember last time we check for receive packets)
tscval_t g_si_tscv_last_poll = 0;

sockinfo_udp::sockinfo_udp(int fd, int domain)
    : sockinfo(fd, domain, true)
    , m_mc_tx_src_ip(in6addr_any, domain)
    , m_b_mc_tx_loop(
          safe_mce_sys().tx_mc_loopback_default) // default value is 'true'. User can change this
                                                 // with config parameter SYS_VAR_TX_MC_LOOPBACK
    , m_n_mc_ttl_hop_lim(m_family == AF_INET ? DEFAULT_MC_TTL : DEFAULT_MC_HOP_LIMIT)
    , m_loops_to_go(safe_mce_sys().rx_poll_num_init) // Start up with a init polling loops value
    , m_rx_udp_poll_os_ratio_counter(0)
    , m_sock_offload(true)
    , m_mc_num_grp_with_src_filter(0)
    , m_port_map_lock("sockinfo_udp::m_ports_map_lock")
    , m_port_map_index(0)
    , m_p_last_dst_entry(nullptr)
    , m_tos(0)
    , m_n_sysvar_rx_poll_yield_loops(safe_mce_sys().rx_poll_yield_loops)
    , m_n_sysvar_rx_udp_poll_os_ratio(safe_mce_sys().rx_udp_poll_os_ratio)
    , m_n_sysvar_rx_ready_byte_min_limit(safe_mce_sys().rx_ready_byte_min_limit)
    , m_n_sysvar_rx_cq_drain_rate_nsec(safe_mce_sys().rx_cq_drain_rate_nsec)
    , m_n_sysvar_rx_delta_tsc_between_cq_polls(safe_mce_sys().rx_delta_tsc_between_cq_polls)
    , m_sockopt_mapped(false)
    , m_is_connected(false)
    , m_multicast(false)
{
    si_udp_logfunc("");
    assert(is_shadow_socket_present());

    m_protocol = PROTO_UDP;
    if (m_p_socket_stats) {
        m_p_socket_stats->socket_type = SOCK_DGRAM;
        m_p_socket_stats->b_is_offloaded = m_sock_offload;

        // Update MC related stats (default values)
        m_p_socket_stats->mc_tx_if = m_mc_tx_src_ip;
        m_p_socket_stats->b_mc_loop = m_b_mc_tx_loop;
    }

    int n_so_rcvbuf_bytes = 0;
    socklen_t option_len = sizeof(n_so_rcvbuf_bytes);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (unlikely(
            SYSCALL(getsockopt, m_fd, SOL_SOCKET, SO_RCVBUF, &n_so_rcvbuf_bytes, &option_len))) {
        si_udp_logdbg("Failure in getsockopt (errno=%d %m)", errno);
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    si_udp_logdbg("Sockets RCVBUF = %d bytes", n_so_rcvbuf_bytes);
    rx_ready_byte_count_limit_update(n_so_rcvbuf_bytes);

    epoll_event ev = {0, {nullptr}};

    ev.events = EPOLLIN;

    // Add the user's orig fd to the rx epfd handle
    ev.data.fd = m_fd;

    BULLSEYE_EXCLUDE_BLOCK_START
    if (unlikely(SYSCALL(epoll_ctl, m_rx_epfd, EPOLL_CTL_ADD, ev.data.fd, &ev))) {
        si_udp_logpanic("failed to add user's fd to internal epfd errno=%d (%m)", errno);
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    si_udp_logfunc("done");
}

sockinfo_udp::~sockinfo_udp()
{
    si_udp_logfunc("");
    g_global_stat_static.socket_udp_destructor_counter.fetch_add(1, std::memory_order_relaxed);

    // Remove all RX ready queue buffers (Push into reuse queue per ring)
    si_udp_logdbg("Releasing %d ready rx packets (total of %lu bytes)", m_n_rx_pkt_ready_list_count,
                  m_rx_ready_byte_count);
    rx_ready_byte_count_limit_update(0);

    // Clear the dst_entry map
    dst_entry_map_t::iterator dst_entry_iter = m_dst_entry_map.begin();
    while (dst_entry_iter != m_dst_entry_map.end()) {
        delete dst_entry_iter
            ->second; // TODO ALEXR - should we check and delete the udp_mc in MC cases?
        m_dst_entry_map.erase(dst_entry_iter);
        dst_entry_iter = m_dst_entry_map.begin();
    }

    /* AlexR:
       We don't have to be nice and delete the fd. close() will do that any way.
       This save us the problem when closing in the clean-up case - if we get closed be the
       nameserver socket 53. if (unlikely( SYSCALL(epoll_ctl, m_rx_epfd, EPOLL_CTL_DEL, m_fd,
       NULL))) { if (errno == ENOENT) si_logfunc("failed to del users fd from internal epfd -
       probably clean up case (errno=%d %m)", errno); else si_logerr("failed to del users fd from
       internal epfd (errno=%d %m)", errno);
        }
    */
    m_lock_rcv.lock();
    m_sock_wakeup_pipe.do_wakeup();

    destructor_helper();

    m_lock_rcv.unlock();

    statistics_print();

    if (m_n_rx_pkt_ready_list_count || m_rx_ready_byte_count || m_rx_pkt_ready_list.size() ||
        m_rx_ring_map.size() || m_rx_reuse_buff.n_buff_num) {
        si_udp_logerr("not all buffers were freed. protocol=UDP. m_n_rx_pkt_ready_list_count=%d, "
                      "m_rx_ready_byte_count=%lu, m_rx_pkt_ready_list.size()=%d, "
                      "m_rx_ring_map.size()=%d, m_rx_reuse_buff.n_buff_num=%d",
                      m_n_rx_pkt_ready_list_count, m_rx_ready_byte_count,
                      (int)m_rx_pkt_ready_list.size(), (int)m_rx_ring_map.size(),
                      m_rx_reuse_buff.n_buff_num);
    }

    si_udp_logfunc("done");
}

int sockinfo_udp::bind_no_os()
{
    sock_addr addr;
    socklen_t addr_len = addr.get_socklen();

    int ret = getsockname(addr.get_p_sa(), &addr_len);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (ret) {
        si_udp_logdbg("getsockname failed (ret=%d %m)", ret);
        return -1;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    // save the bound info and then attach to offload flows
    validate_and_convert_mapped_ipv4(addr);
    on_sockname_change(addr.get_p_sa(), addr_len);
    si_udp_logdbg("bound to %s", m_bound.to_str_ip_port(true).c_str());

    if (!m_bound.is_anyaddr() && !m_bound.is_mc()) {
        auto bind_addr_to_dest_entry =
            [&](std::pair<const sock_addr, dst_entry *> dst_entry_key_val) {
                dst_entry_key_val.second->set_bound_addr(m_bound.get_ip_addr());
            };
        std::for_each(m_dst_entry_map.begin(), m_dst_entry_map.end(), bind_addr_to_dest_entry);
    }

    return 0;
}

int sockinfo_udp::bind(const struct sockaddr *__addr, socklen_t __addrlen)
{
    si_udp_logfunc("");

    // We always call the orig_bind which will check sanity of the user socket api
    // and the OS will also allocate a specific port that we can also use
    int ret = SYSCALL(bind, m_fd, __addr, __addrlen);
    if (ret) {
        si_udp_logdbg("orig bind failed (ret=%d %m)", ret);
        // TODO: Should we set errno again (maybe log write modified the orig.bind() errno)?
        return ret;
    }
    if (unlikely(m_state == SOCKINFO_DESTROYING) || unlikely(g_b_exit)) {
        errno = EBUSY;
        return -1; // zero returned from orig_bind()
    }

    return bind_no_os();
}

int sockinfo_udp::connect(const struct sockaddr *__to, socklen_t __tolen)
{
    sock_addr connect_to(__to, __tolen);
    si_udp_logdbg("to %s", connect_to.to_str_ip_port(true).c_str());
    validate_and_convert_mapped_ipv4(connect_to);

#if defined(DEFINED_NGINX)
    // check if we can skip "connect()" flow, to increase performance of redundant connect() calls
    // we will use it for dedicated sockets for socket pool
    // in case dst ip and port are the same as the last connect() call
    if (g_p_app->type == APP_NGINX && m_is_connected && m_is_for_socket_pool &&
        m_state != SOCKINFO_DESTROYING && m_connected == connect_to) {
        return 0;
    }
#endif

    // We always call the orig_connect which will check sanity of the user socket api
    // and the OS will also allocate a specific bound port that we can also use
    int ret = SYSCALL(connect, m_fd, __to, __tolen);
    if (ret) {
        si_udp_logdbg("orig connect failed (ret=%d, errno=%d %m)", ret, errno);
        return ret;
    }
    if (unlikely(m_state == SOCKINFO_DESTROYING) || unlikely(g_b_exit)) {
        errno = EBUSY;
        return -1; // zero returned from orig_connect()
    }

    std::lock_guard<decltype(m_lock_snd)> _lock(m_lock_snd);

    const ip_address &dst_ipaddr = connect_to.get_ip_addr();
    in_port_t dst_port = connect_to.get_in_port();

    // Check connect ip info
    if (!connect_to.is_anyaddr() && m_connected.get_ip_addr() != dst_ipaddr) {
        si_udp_logdbg("connected ip changed (%s -> %s)", m_connected.to_str_ip_port().c_str(),
                      connect_to.to_str_ip_port().c_str());
    }

    // Check connect port info
    if (dst_port != INPORT_ANY && m_connected.get_in_port() != dst_port) {
        si_udp_logdbg("connected port changed (%s -> %s)", m_connected.to_str_ip_port().c_str(),
                      connect_to.to_str_ip_port().c_str());
    }

    m_connected = connect_to;

    if (m_p_socket_stats) {
        m_p_socket_stats->set_connected_ip(connect_to);
        m_p_socket_stats->connected_port = dst_port;
    }

    // Connect can change the OS bound address,
    // lets check it and update our bound ip & port
    // Call on_sockname_change (this will save the bind information and attach to unicast flow)
    sock_addr addr;
    socklen_t addr_len = addr.get_socklen();

    ret = getsockname(addr.get_p_sa(), &addr_len);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (ret) {
        si_udp_logerr("getsockname failed (ret=%d %m)", ret);
        return 0; // zero returned from orig_connect()
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    m_is_connected = true; // will inspect for SRC
    on_sockname_change(addr.get_p_sa(), addr_len);

    si_udp_logdbg("bound to %s", m_bound.to_str_ip_port(true).c_str());
    in_port_t src_port = m_bound.get_in_port();

    if (TRANS_XLIO !=
        find_target_family(ROLE_UDP_CONNECT, m_connected.get_p_sa(), m_bound.get_p_sa())) {
        setPassthrough();
        return 0;
    }
    // Create the new dst_entry, delete if one already exists
    if (m_p_connected_dst_entry) {
        delete m_p_connected_dst_entry;
        m_p_connected_dst_entry = nullptr;
    }

    if (dst_ipaddr.is_mc(m_family)) {
        socket_data data = {m_fd, m_n_mc_ttl_hop_lim, m_tos, m_pcp};
        m_p_connected_dst_entry = new dst_entry_udp_mc(
            m_connected, src_port,
            m_mc_tx_src_ip.is_anyaddr() ? m_bound.get_ip_addr() : m_mc_tx_src_ip, m_b_mc_tx_loop,
            data, m_ring_alloc_log_tx);
    } else {
        socket_data data = {m_fd, m_n_uc_ttl_hop_lim, m_tos, m_pcp};
        m_p_connected_dst_entry =
            new dst_entry_udp(m_connected, src_port, data, m_ring_alloc_log_tx);
    }

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!m_p_connected_dst_entry) {
        si_udp_logerr("Failed to create dst_entry(dst:%s, src_port:%d)",
                      connect_to.to_str_ip_port(true).c_str(), ntohs(src_port));
        m_connected = sock_addr();

        // Special assignment - it should have been done by m_p_socket_stats->set_connected_ip()
        if (m_p_socket_stats) {
            m_p_socket_stats->connected_ip = ip_address(in6addr_any);
            m_p_socket_stats->connected_port = INPORT_ANY;
        }

        m_is_connected = false; // will skip inspection for SRC
        return 0;
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    if (!m_bound.is_anyaddr() && !m_bound.is_mc()) {
        m_p_connected_dst_entry->set_bound_addr(m_bound.get_ip_addr());
    }
    if (!m_so_bindtodevice_ip.is_anyaddr()) {
        m_p_connected_dst_entry->set_so_bindtodevice_addr(m_so_bindtodevice_ip);
    }
    m_p_connected_dst_entry->set_src_sel_prefs(m_src_sel_flags);
    m_p_connected_dst_entry->prepare_to_send(m_so_ratelimit, false);

    return 0;
}

int sockinfo_udp::shutdown(int __how)
{
    si_udp_logfunc("");
    int ret = SYSCALL(shutdown, m_fd, __how);
    if (ret) {
        si_udp_logdbg("shutdown failed (ret=%d %m)", ret);
    }
    return ret;
}

int sockinfo_udp::accept(struct sockaddr *__addr, socklen_t *__addrlen)
{
    si_udp_logfunc("");
    int ret = SYSCALL(accept, m_fd, __addr, __addrlen);
    if (ret < 0) {
        si_udp_logdbg("accept failed (ret=%d %m)", ret);
    }
    return ret;
}

int sockinfo_udp::accept4(struct sockaddr *__addr, socklen_t *__addrlen, int __flags)
{
    si_udp_logfunc("");
    int ret = SYSCALL(accept4, m_fd, __addr, __addrlen, __flags);
    if (ret < 0) {
        si_udp_logdbg("accept4 failed (ret=%d %m)", ret);
    }
    return ret;
}

int sockinfo_udp::listen(int backlog)
{
    si_udp_logfunc("");
    int ret = SYSCALL(listen, m_fd, backlog);
    if (ret < 0) {
        si_udp_logdbg("listen failed (ret=%d %m)", ret);
    }
    return ret;
}

int sockinfo_udp::getsockname(struct sockaddr *__name, socklen_t *__namelen)
{
    si_udp_logdbg("");

    if (unlikely(m_state == SOCKINFO_DESTROYING) || unlikely(g_b_exit)) {
        errno = EINTR;
        return -1;
    }

    return SYSCALL(getsockname, m_fd, __name, __namelen);
}

int sockinfo_udp::getpeername(sockaddr *__name, socklen_t *__namelen)
{
    si_udp_logfunc("");
    int ret = SYSCALL(getpeername, m_fd, __name, __namelen);
    if (ret) {
        si_udp_logdbg("getpeername failed (ret=%d %m)", ret);
    }
    return ret;
}

int sockinfo_udp::on_sockname_change(struct sockaddr *__name, socklen_t __namelen)
{
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!__name) {
        si_udp_logerr("invalid NULL __name");
        errno = EFAULT;
        return -1;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    sock_addr bindname(__name, __namelen);

    if (!bindname.is_supported()) {
        si_udp_logfunc("not supported family (%d)", bindname.get_sa_family());
        return 0;
    }

    std::lock_guard<decltype(m_lock_rcv)> _lock(m_lock_rcv);
    bool is_bound_modified = false;

    // Check & Save bind port info
    if (m_bound.get_in_port() != bindname.get_in_port()) {
        si_udp_logdbg("bound port defined (%s -> %d)", m_bound.to_str_port().c_str(),
                      ntohs(bindname.get_in_port()));
        IF_STATS(m_p_socket_stats->bound_port = bindname.get_in_port());
        is_bound_modified = true;
    }

    // Check & Save bind if info
    if (m_bound.get_ip_addr() != bindname.get_ip_addr()) {
        si_udp_logdbg("bound if changed (%s -> %s)", m_bound.to_str_ip_port().c_str(),
                      bindname.to_str_ip_port().c_str());
        IF_STATS(m_p_socket_stats->set_bound_if(bindname));
    }

    m_bound = bindname;

    // Check if this is the new 'name' (local port) of the socket
    if ((m_is_connected || is_bound_modified) && !bindname.is_anyport()) {

        // Attach UDP unicast port to offloaded interface
        // 1. Check if local_if is offloadable OR is on INADDR_ANY which means attach to ALL
        // 2. Verify not binding to MC address in the UC case
        // 3. if not offloaded then set a PassThrough
        if ((m_bound.is_anyaddr() ||
             g_p_net_device_table_mgr->get_net_device_val(
                 ip_addr(m_bound.get_ip_addr(), m_bound.get_sa_family())))) {
            attach_as_uc_receiver(ROLE_UDP_RECEIVER); // if failed, we will get RX from OS
        } else if (m_bound.is_mc()) {
            // MC address binding will happen later as part of the ADD_MEMBERSHIP in
            // handle_pending_mreq()
            si_udp_logdbg("bound to MC address, no need to attach to UC address as offloaded");
        } else {
            si_udp_logdbg("will be passed to OS for handling - not offload interface (%s)",
                          m_bound.to_str_ip_port(true).c_str());
            setPassthrough();
        }

        // Attach UDP port pending MC groups to offloaded interface (set by ADD_MEMBERSHIP before
        // bind() was called)
        handle_pending_mreq();
    }

    return 0;
}

////////////////////////////////////////////////////////////////////////////////
int sockinfo_udp::setsockopt(int __level, int __optname, __const void *__optval, socklen_t __optlen)
{
    si_udp_logfunc("level=%d, optname=%d", __level, __optname);

    if (unlikely(m_state == SOCKINFO_DESTROYING) || unlikely(g_b_exit)) {
        return SYSCALL(setsockopt, m_fd, __level, __optname, __optval, __optlen);
    }

    std::lock_guard<decltype(m_lock_snd)> lock_tx(m_lock_snd);
    std::lock_guard<decltype(m_lock_rcv)> lock_rx(m_lock_rcv);

    int ret = sockinfo::setsockopt(__level, __optname, __optval, __optlen);
    if (ret != SOCKOPT_PASS_TO_OS) {
        return (ret == SOCKOPT_HANDLE_BY_OS
                    ? setsockopt_kernel(__level, __optname, __optval, __optlen, true, false)
                    : ret);
    }

    bool supported = true;
    switch (__level) {

    case SOL_SOCKET: {
        switch (__optname) {

        case SO_BROADCAST:
            si_udp_logdbg("SOL_SOCKET, %s=%s", setsockopt_so_opt_to_str(__optname),
                          (*(bool *)__optval ? "true" : "false"));
            break;

        case SO_RCVBUF: {
            int n_so_rcvbuf_bytes = *(int *)__optval;
            // OS allocates double the size of memory requested by the application
            n_so_rcvbuf_bytes = n_so_rcvbuf_bytes * 2;

            si_udp_logdbg("SOL_SOCKET, %s=%d (x2)", setsockopt_so_opt_to_str(__optname),
                          n_so_rcvbuf_bytes);
            rx_ready_byte_count_limit_update(n_so_rcvbuf_bytes);
        } break;

        case SO_SNDBUF:
            si_udp_logdbg("SOL_SOCKET, %s=%d", setsockopt_so_opt_to_str(__optname),
                          *(int *)__optval);
            // this is supported without doing something special because send immediately
            // without buffering
            break;

        case SO_RCVTIMEO:
            if (__optval) {
                struct timeval *tv = (struct timeval *)__optval;
                if (tv->tv_sec || tv->tv_usec) {
                    m_loops_timer.set_timeout_msec(tv->tv_sec * 1000 +
                                                   (tv->tv_usec ? tv->tv_usec / 1000 : 0));
                } else {
                    m_loops_timer.set_timeout_msec(-1);
                }
                si_udp_logdbg("SOL_SOCKET: SO_RCVTIMEO=%d", m_loops_timer.get_timeout_msec());
            } else {
                si_udp_logdbg("SOL_SOCKET, %s=\"???\" - NOT HANDLED, optval == NULL",
                              setsockopt_so_opt_to_str(__optname));
            }
            break;

        case SO_BINDTODEVICE:
            if (__optval) {
                ip_addr addr {0};
                if (__optlen == 0 || ((char *)__optval)[0] == '\0') {
                    m_so_bindtodevice_ip = ip_addr(ip_address::any_addr(), m_family);
                } else if (!get_ip_addr_from_ifname((char *)__optval, addr, m_family) ||
                           (m_family == AF_INET6 && !m_is_ipv6only &&
                            !get_ip_addr_from_ifname((char *)__optval, addr, AF_INET))) {
                    // coverity[copy_assignment_call:FALSE] /*Turn off check COPY_INSTEAD_OF_MOVE*/
                    m_so_bindtodevice_ip = addr;
                } else {
                    si_udp_logdbg("SOL_SOCKET, %s=\"???\" - NOT HANDLED, cannot find if_name",
                                  setsockopt_so_opt_to_str(__optname));
                    break;
                }

                si_udp_logdbg("SOL_SOCKET, %s='%s' (%s)", setsockopt_so_opt_to_str(__optname),
                              (char *)__optval, m_so_bindtodevice_ip.to_str().c_str());

                // handle TX side
                if (m_p_connected_dst_entry) {
                    m_p_connected_dst_entry->set_so_bindtodevice_addr(m_so_bindtodevice_ip);
                } else {
                    dst_entry_map_t::iterator dst_entry_iter = m_dst_entry_map.begin();
                    while (dst_entry_iter != m_dst_entry_map.end()) {
                        dst_entry_iter->second->set_so_bindtodevice_addr(m_so_bindtodevice_ip);
                        dst_entry_iter++;
                    }
                }

                // handle RX side - TODO
            } else {
                si_udp_logdbg("SOL_SOCKET, %s=\"???\" - NOT HANDLED, optval == NULL",
                              setsockopt_so_opt_to_str(__optname));
            }
            break;

        case SO_MAX_PACING_RATE:
            if (__optval) {
                struct xlio_rate_limit_t val;

                if (sizeof(struct xlio_rate_limit_t) == __optlen) {
                    val = *(struct xlio_rate_limit_t *)__optval; // value is in Kbits per second
                } else if (sizeof(uint32_t) == __optlen) {
                    // value is in bytes per second
                    val.rate = BYTE_TO_KB(*(uint32_t *)__optval); // value is in bytes per second
                    val.max_burst_sz = 0;
                    val.typical_pkt_sz = 0;
                } else {
                    si_udp_logdbg("SOL_SOCKET, %s=\"???\" - bad length got %d",
                                  setsockopt_so_opt_to_str(__optname), __optlen);
                    return -1;
                }

                if (modify_ratelimit(m_p_connected_dst_entry, val) < 0) {
                    si_udp_logdbg("error setting setsockopt SO_MAX_PACING_RATE for connected "
                                  "dst_entry %p: %d bytes/second ",
                                  m_p_connected_dst_entry, val.rate);

                    // Do not fall back to kernel in this case.
                    // The kernel's support for packet pacing is of no consequence
                    // to the user and may only confuse the calling application.
                    return -1;
                }

                size_t dst_entries_not_modified = 0;
                dst_entry_map_t::iterator dst_entry_iter;
                for (dst_entry_iter = m_dst_entry_map.begin();
                     dst_entry_iter != m_dst_entry_map.end(); ++dst_entry_iter) {
                    dst_entry *p_dst_entry = dst_entry_iter->second;
                    if (modify_ratelimit(p_dst_entry, val) < 0) {
                        si_udp_logdbg("error setting setsockopt SO_MAX_PACING_RATE "
                                      "for dst_entry %p: %d bytes/second ",
                                      p_dst_entry, val.rate);
                        dst_entries_not_modified++;
                    }
                }
                // It is possible that the user has a setup with some NICs that support
                // packet pacing and some that don't.
                // Setting packet pacing fails only if all NICs do not support it.
                if (m_dst_entry_map.size() &&
                    (dst_entries_not_modified == m_dst_entry_map.size())) {
                    return -1;
                }
                return 0;
            } else {
                si_udp_logdbg("SOL_SOCKET, %s=\"???\" - NOT HANDLED, optval == NULL",
                              setsockopt_so_opt_to_str(__optname));
            }
            break;

        case SO_PRIORITY:
            if (set_sockopt_prio(__optval, __optlen)) {
                return -1;
            }
            break;
        default:
            si_udp_logdbg("SOL_SOCKET, optname=%s (%d)", setsockopt_so_opt_to_str(__optname),
                          __optname);
            supported = false;
            break;
        }
    } // case SOL_SOCKET
    break;

    case IPPROTO_IP: {
        switch (__optname) {
        case IP_MULTICAST_IF: {
            struct ip_mreqn mreqn;
            memset(&mreqn, 0, sizeof(mreqn));

            if (!__optval || __optlen < sizeof(struct in_addr)) {
                si_udp_loginfo("IPPROTO_IP, %s=\"???\", optlen:%d",
                               setsockopt_ip_opt_to_str(__optname), (int)__optlen);
                break;
            }

            if (__optlen >= sizeof(struct ip_mreqn)) {
                memcpy(&mreqn, __optval, sizeof(struct ip_mreqn));
            } else if (__optlen >= sizeof(struct ip_mreq)) {
                memcpy(&mreqn, __optval, sizeof(struct ip_mreq));
            } else {
                memcpy(&mreqn.imr_address, __optval, sizeof(struct in_addr));
            }

            // The aplication may pass here ip-address or an interface index.
            // If ip-address is passed we suppose that this is the source IP without
            // even any checks that this IP exists.
            // If index is passed we take the first IPv4 address of the interface.
            // However, Kernel Differentiate between src-addr and outgoing-if.
            // Also, in Kernel, the address selection is not the first one,
            // see p_route_output_key_hash_rcu -> inet_select_addr.

            if (mreqn.imr_ifindex) {
                local_ip_list_t lip_offloaded_list;
                g_p_net_device_table_mgr->get_ip_list(lip_offloaded_list, AF_INET,
                                                      mreqn.imr_ifindex);
                if (!lip_offloaded_list.empty()) {
                    mreqn.imr_address.s_addr =
                        lip_offloaded_list.front().get().local_addr.get_in_addr();
                } else {
                    ip_addr src_addr {0};
                    if (get_ip_addr_from_ifindex(mreqn.imr_ifindex, src_addr) == 0) {
                        mreqn.imr_address.s_addr = src_addr.get_in4_addr().s_addr;
                    } else {
                        si_udp_logdbg("setsockopt(%s) will be passed to OS for handling, can't get "
                                      "address of interface index %d ",
                                      setsockopt_ip_opt_to_str(__optname), mreqn.imr_ifindex);
                        break;
                    }
                }
            }

            m_mc_tx_src_ip = ip_addr(mreqn.imr_address.s_addr);

            si_udp_logdbg("IPPROTO_IP, %s=%s", setsockopt_ip_opt_to_str(__optname),
                          m_mc_tx_src_ip.to_str().c_str());
            IF_STATS(m_p_socket_stats->mc_tx_if = m_mc_tx_src_ip);
        } break;

        case IP_MULTICAST_TTL: {
            int n_mc_ttl = -1;
            if (__optlen == sizeof(m_n_mc_ttl_hop_lim)) {
                n_mc_ttl = *(char *)__optval;
            } else if (__optlen == sizeof(int)) {
                n_mc_ttl = *(int *)__optval;
            } else {
                break;
            }
            if (n_mc_ttl == -1) {
                n_mc_ttl = 1;
            }
            if (n_mc_ttl >= 0 && n_mc_ttl <= 255) {
                m_n_mc_ttl_hop_lim = n_mc_ttl;
                header_ttl_hop_limit_updater du(m_n_mc_ttl_hop_lim, true);
                update_header_field(&du);
                si_udp_logdbg("IPPROTO_IP, %s=%d", setsockopt_ip_opt_to_str(__optname),
                              m_n_mc_ttl_hop_lim);
            } else {
                si_udp_loginfo("IPPROTO_IP, %s=\"???\"", setsockopt_ip_opt_to_str(__optname));
            }
        } break;

        case IP_MULTICAST_LOOP: {
            if (__optval) {
                bool b_mc_loop = *(bool *)__optval;
                m_b_mc_tx_loop = b_mc_loop ? true : false;
                IF_STATS(m_p_socket_stats->b_mc_loop = m_b_mc_tx_loop);
                si_udp_logdbg("IPPROTO_IP, %s=%s", setsockopt_ip_opt_to_str(__optname),
                              (m_b_mc_tx_loop ? "true" : "false"));
            } else {
                si_udp_loginfo("IPPROTO_IP, %s=\"???\"", setsockopt_ip_opt_to_str(__optname));
            }
        } break;

        case IP_ADD_MEMBERSHIP:
        case IP_DROP_MEMBERSHIP:
        case IP_ADD_SOURCE_MEMBERSHIP:
        case IP_DROP_SOURCE_MEMBERSHIP: {
            // XXX TODO: refactor all ip structs to ip_address
            if (!m_sock_offload) {
                si_udp_logdbg("Rx Offload is Disabled! calling OS setsockopt() for IPPROTO_IP, %s",
                              setsockopt_ip_opt_to_str(__optname));
                break;
            }

            if (!__optval) {
                si_udp_logdbg("IPPROTO_IP, %s; Bad optval! calling OS setsockopt()",
                              setsockopt_ip_opt_to_str(__optname));
                break;
            }

            // There are 3 types of structs that we can receive, ip_mreq(2 members), ip_mreqn(3
            // members), ip_mreq_source(3 members) ip_mreq struct type and size depend on command
            // type, let verify all possibilities and continue below with safe logic.

            // NOTE: The ip_mreqn structure is available only since Linux 2.2. For compatibility,
            // the old ip_mreq structure (present since Linux 1.2) is still supported; it differs
            // from ip_mreqn only by not including the imr_ifindex field.
            if (__optlen < sizeof(struct ip_mreq)) {
                si_udp_logdbg("IPPROTO_IP, %s; Bad optlen! calling OS setsockopt() with optlen=%d "
                              "(required optlen=%zu)",
                              setsockopt_ip_opt_to_str(__optname), __optlen,
                              sizeof(struct ip_mreq));
                break;
            }
            // IP_ADD_SOURCE_MEMBERSHIP (and DROP) used ip_mreq_source which is same size struct as
            // ip_mreqn, but fields have different meaning
            if (((IP_ADD_SOURCE_MEMBERSHIP == __optname) ||
                 (IP_DROP_SOURCE_MEMBERSHIP == __optname)) &&
                (__optlen < sizeof(struct ip_mreq_source))) {
                si_udp_logdbg("IPPROTO_IP, %s; Bad optlen! calling OS setsockopt() with optlen=%d "
                              "(required optlen=%zu)",
                              setsockopt_ip_opt_to_str(__optname), __optlen,
                              sizeof(struct ip_mreq_source));
                break;
            }

            // Use  local variable for easy access
            in_addr_t mc_grp = ((struct ip_mreq *)__optval)->imr_multiaddr.s_addr;
            in_addr_t mc_if = ((struct ip_mreq *)__optval)->imr_interface.s_addr;

            // In case interface address is undefined[INADDR_ANY] we need to find the ip address to
            // use
            struct ip_mreq_source mreqprm = {{mc_grp}, {mc_if}, {0}};
            if ((IP_ADD_MEMBERSHIP == __optname) || (IP_DROP_MEMBERSHIP == __optname)) {
                if (__optlen >= sizeof(struct ip_mreqn)) {
                    struct ip_mreqn *p_mreqn = (struct ip_mreqn *)__optval;
                    if (p_mreqn->imr_ifindex) {
                        local_ip_list_t lip_offloaded_list;
                        g_p_net_device_table_mgr->get_ip_list(lip_offloaded_list, AF_INET,
                                                              p_mreqn->imr_ifindex);

                        // See comment inside IP_MULTICAST_IF regarding address selection.

                        if (!lip_offloaded_list.empty()) {
                            mreqprm.imr_interface.s_addr =
                                lip_offloaded_list.front().get().local_addr.get_in_addr();
                        } else {
                            ip_addr src_addr {0};
                            if (get_ip_addr_from_ifindex(p_mreqn->imr_ifindex, src_addr) == 0) {
                                mreqprm.imr_interface.s_addr = src_addr.get_in4_addr().s_addr;
                            } else {
                                si_udp_logdbg("setsockopt(%s) will be passed to OS for handling, "
                                              "can't get address of interface index %d ",
                                              setsockopt_ip_opt_to_str(__optname),
                                              p_mreqn->imr_ifindex);
                                break;
                            }
                        }
                    }
                }
            } else {
                // Save and use the user provided source address filter in case of
                // IP_ADD_SOURCE_MEMBERSHIP or IP_DROP_SOURCE_MEMBERSHIP
                mreqprm.imr_sourceaddr.s_addr =
                    ((struct ip_mreq_source *)__optval)->imr_sourceaddr.s_addr;
            }

            // Update interface IP in case it was changed above
            mc_if = mreqprm.imr_interface.s_addr;

            if (!IN_MULTICAST_N(mc_grp)) {
                si_udp_logdbg("setsockopt(%s) will be passed to OS for handling, IP %s is not MC ",
                              setsockopt_ip_opt_to_str(__optname),
                              ip_address(mc_grp).to_str(AF_INET).c_str());
                break;
            }

            // Find local interface for this MC ADD/DROP
            if (INADDR_ANY == mc_if) {
                ip_address resolved_ip;
                resolve_if_ip(0, ip_address(mc_grp), resolved_ip);
                mc_if = resolved_ip.get_in_addr();
            }

            si_udp_logdbg("IPPROTO_IP, %s=%s, mc_if:%s imr_sourceaddr:%s",
                          setsockopt_ip_opt_to_str(__optname),
                          ip_address(mc_grp).to_str(AF_INET).c_str(),
                          ip_address(mc_if).to_str(AF_INET).c_str(),
                          ip_address(mreqprm.imr_sourceaddr.s_addr).to_str(AF_INET).c_str());

            // Add multicast group membership
            if (mc_change_membership_start_helper_ip4(ip_address(mc_grp), __optname)) {
                return -1;
            }

            bool goto_os = false;
            // Check MC rules for not offloading
            sock_addr tmp_grp_addr(AF_INET, &mc_grp, m_bound.get_in_port());
            mc_pending_pram mcpram;
            mcpram.mc_grp = ip_address(mreqprm.imr_multiaddr);
            mcpram.mc_if = ip_address(mreqprm.imr_interface);
            mcpram.mc_src = ip_address(mreqprm.imr_sourceaddr);
            mcpram.optname = __optname;

            if (TRANS_OS ==
                __xlio_match_udp_receiver(TRANS_XLIO, safe_mce_sys().app_id,
                                          tmp_grp_addr.get_p_sa(), tmp_grp_addr.get_socklen())) {
                // call orig setsockopt() and don't try to offlaod
                si_udp_logdbg(
                    "setsockopt(%s) will be passed to OS for handling due to rule matching",
                    setsockopt_ip_opt_to_str(__optname));
                goto_os = true;
            }
            // Check if local_if is not offloadable
            else if (!g_p_net_device_table_mgr->get_net_device_val(ip_addr(mc_if))) {
                // call orig setsockopt() and don't try to offlaod
                si_udp_logdbg("setsockopt(%s) will be passed to OS for handling - not offload "
                              "interface (%s)",
                              setsockopt_ip_opt_to_str(__optname),
                              ip_address(mc_if).to_str(AF_INET).c_str());
                goto_os = true;
            }
            // offloaded, check if need to pend
            else if (m_bound.is_anyport()) {
                // Delay attaching to this MC group until we have bound UDP port
                ret = SYSCALL(setsockopt, m_fd, __level, __optname, __optval, __optlen);
                if (ret) {
                    return ret;
                }
                mc_change_pending_mreq(&mcpram);
            }
            // Handle attach to this MC group now
            else if (mc_change_membership_ip4(&mcpram)) {
                // Opps, failed in attaching??? call orig setsockopt()
                goto_os = true;
            }

            if (goto_os) {
                ret = SYSCALL(setsockopt, m_fd, __level, __optname, __optval, __optlen);
                if (ret) {
                    return ret;
                }
            }

            mc_change_membership_end_helper_ip4(ip_address(mc_grp), __optname,
                                                ip_address(mreqprm.imr_sourceaddr.s_addr));
            return 0;
        } break;
        case IP_PKTINFO:
            if (__optval) {
                if (*(int *)__optval) {
                    m_b_pktinfo = true;
                } else {
                    m_b_pktinfo = false;
                }
            }
            break;
        case IP_TOS: {
            int val;
            if (__optlen == sizeof(int)) {
                val = *(int *)__optval;
            } else if (__optlen == sizeof(uint8_t)) {
                val = *(uint8_t *)__optval;
            } else {
                break;
            }
            m_tos = (uint8_t)val;
            header_tos_updater du(m_tos);
            update_header_field(&du);
            // lists.openwall.net/netdev/2009/12/21/59
            int new_prio = ip_tos2prio[IPTOS_TOS(m_tos) >> 1];
            set_sockopt_prio(&new_prio, sizeof(new_prio));
        } break;
        default: {
            si_udp_logdbg("IPPROTO_IP, optname=%s (%d)", setsockopt_ip_opt_to_str(__optname),
                          __optname);
            supported = false;
        } break;
        }
    } // case IPPROTO_IP
    break;

    case IPPROTO_UDP:
        switch (__optname) {
        case UDP_MAP_ADD: {
            if (!__optval) {
                si_udp_loginfo("UDP_MAP_ADD __optval = NULL");
                break;
            }
            struct port_socket_t port_socket;
            port_socket.port = *(in_port_t *)__optval;
            m_port_map_lock.lock();
            if (std::find(m_port_map.begin(), m_port_map.end(), port_socket.port) ==
                m_port_map.end()) {
                port_socket.fd =
                    get_sock_by_L3_L4(PROTO_UDP, m_bound.get_ip_addr(), port_socket.port);
                if (port_socket.fd == -1) {
                    si_udp_logdbg("could not find UDP_MAP_ADD socket for port %d",
                                  ntohs(port_socket.port));
                    m_port_map_lock.unlock();
                    return -1;
                }
                if (m_port_map.empty()) {
                    m_sockopt_mapped = true;
                }
                si_udp_logdbg("found UDP_MAP_ADD socket fd for port %d. fd is %d",
                              ntohs(port_socket.port), port_socket.fd);
                m_port_map.push_back(port_socket);
            }
            m_port_map_lock.unlock();
            return 0;
        }
        case UDP_MAP_REMOVE: {
            if (!__optval) {
                si_udp_loginfo("UDP_MAP_REMOVE __optval = NULL");
                break;
            }
            in_port_t port = *(in_port_t *)__optval;
            si_udp_logdbg("stopping de-muxing packets to port %d", ntohs(port));
            m_port_map_lock.lock();
            std::vector<struct port_socket_t>::iterator iter =
                std::find(m_port_map.begin(), m_port_map.end(), port);
            if (iter != m_port_map.end()) {
                m_port_map.erase(iter);
                if (m_port_map.empty()) {
                    m_sockopt_mapped = false;
                }
            }
            m_port_map_lock.unlock();
            return 0;
        }
        default:
            si_udp_logdbg("IPPROTO_UDP, optname=%s (%d)", setsockopt_ip_opt_to_str(__optname),
                          __optname);
            supported = false;
            break;
        } // case IPPROTO_UDP
        break;

    case IPPROTO_IPV6:
        switch (__optname) {
        case IPV6_MULTICAST_IF: {
            if (!__optval || __optlen < sizeof(int)) {
                si_udp_logdbg("%s, %s=\"???\", optlen:%d", setsockopt_level_to_str(__level),
                              setsockopt_ip_opt_to_str(__optname), (int)__optlen);
                break;
            }

            int if_ix = (*reinterpret_cast<const int *>(__optval));
            if (if_ix == 0) {
                break;
            }

            if (!g_p_net_device_table_mgr->get_net_device_val(if_ix)) {
                si_udp_logdbg("IPPROTO_IPV6, %s: if_ix=%d does not exist",
                              setsockopt_ip_opt_to_str(__optname), if_ix);
                break;
            }

            // We take the first address of the interface.
            // However, Kernel Differentiate between src-addr and outgoing-if.
            // Also, in Kernel, the address selection is not the first one,
            // see p_route_output_key_hash_rcu -> inet_select_addr.
            local_ip_list_t lip_offloaded_list;
            g_p_net_device_table_mgr->get_ip_list(lip_offloaded_list, m_family, if_ix);
            if (!lip_offloaded_list.empty()) {
                m_mc_tx_src_ip = ip_addr(lip_offloaded_list.front().get().local_addr, m_family);
            } else {
                ip_addr src_addr {0};
                if (get_ip_addr_from_ifindex(if_ix, src_addr, AF_INET6) == 0) {
                    // coverity[copy_assignment_call:FALSE] /*Turn off check COPY_INSTEAD_OF_MOVE*/
                    m_mc_tx_src_ip = src_addr;
                } else {
                    si_udp_logdbg("IPPROTO_IPV6, setsockopt(%s) will be passed to OS for "
                                  "handling, can't get address "
                                  "of interface index %d ",
                                  setsockopt_ip_opt_to_str(__optname), if_ix);
                    break;
                }
            }

            si_udp_logdbg("IPPROTO_IPV6, %s=%s", setsockopt_ip_opt_to_str(__optname),
                          m_mc_tx_src_ip.to_str().c_str());
            IF_STATS(m_p_socket_stats->mc_tx_if = m_mc_tx_src_ip);
        } break;

        case IPV6_MULTICAST_LOOP: {
            if (__optval) {
                m_b_mc_tx_loop = *(bool *)__optval;
                IF_STATS(m_p_socket_stats->b_mc_loop = m_b_mc_tx_loop);
                si_udp_logdbg("IPV6_MULTICAST_LOOP, %s=%s", setsockopt_ip_opt_to_str(__optname),
                              (m_b_mc_tx_loop ? "true" : "false"));
            } else {
                si_udp_logdbg("%s, optval=NULL", setsockopt_ip_opt_to_str(__optname));
            }
        } break;

        case IPV6_MULTICAST_HOPS: {
            if (__optval && __optlen == sizeof(int)) {
                int val = (*reinterpret_cast<const int *>(__optval));
                if ((val >= -1) && (val <= 255)) {
                    m_n_mc_ttl_hop_lim = (val == -1) ? DEFAULT_MC_HOP_LIMIT : val;
                    header_ttl_hop_limit_updater du(m_n_mc_ttl_hop_lim, true);
                    update_header_field(&du);
                    si_udp_logdbg("IPV6_MULTICAST_HOPS, set to %u", m_n_mc_ttl_hop_lim);
                    break;
                }
            }
            si_udp_logdbg("IPV6_MULTICAST_HOPS, invalid value/length arguments. "
                          " val %p, len %zu, expected-len %zu",
                          __optval, static_cast<size_t>(__optlen), sizeof(int));
        } break;

        case IPV6_LEAVE_GROUP:
        case IPV6_JOIN_GROUP: {
            if (!__optval) {
                si_udp_logdbg("%s, %s=\"???\", optlen:%d", setsockopt_level_to_str(__level),
                              setsockopt_ip_opt_to_str(__optname), (int)__optlen);
                break;
            }

            if (__optlen < sizeof(struct ipv6_mreq)) {
                si_udp_logdbg("%s, %s; Bad optlen! calling OS setsockopt() with optlen=%d "
                              "(required optlen=%zu)",
                              setsockopt_level_to_str(__level), setsockopt_ip_opt_to_str(__optname),
                              __optlen, sizeof(struct ipv6_mreq));
                break;
            }

            if (multicast_membership_setsockopt_ip6(__optname, __optval, __optlen) < 0) {
                si_udp_logdbg("setsockopt(%s) will be passed to OS for handling",
                              setsockopt_ip_opt_to_str(__optname));
                break;
            }
            return 0;
        } break;
        case MCAST_JOIN_GROUP:
        case MCAST_LEAVE_GROUP: {
            if (!__optval) {
                si_udp_logdbg("%s, %s optval=NULL, optlen:%d", setsockopt_level_to_str(__level),
                              setsockopt_ip_opt_to_str(__optname), (int)__optlen);
                break;
            }
            if (__optlen < sizeof(struct group_req)) {
                si_udp_logdbg("%s, %s; Bad optlen! calling OS setsockopt() with optlen=%d "
                              "(required optlen=%zu)",
                              setsockopt_level_to_str(__level), setsockopt_ip_opt_to_str(__optname),
                              __optlen, sizeof(struct group_req));
                break;
            }

            const sock_addr *sock = reinterpret_cast<const sock_addr *>(
                &(reinterpret_cast<const struct group_req *>(__optval)->gr_group));
            if (sock->get_sa_family() != AF_INET6) {
                si_udp_logdbg(
                    "setsockopt(%s) will be passed to OS for handling, sa_family != AF_INET6 ",
                    setsockopt_ip_opt_to_str(__optname));
                break;
            }

            if (multicast_membership_setsockopt_ip6(__optname, __optval, __optlen) < 0) {
                si_udp_logdbg("setsockopt(%s) will be passed to OS for handling",
                              setsockopt_ip_opt_to_str(__optname));
                break;
            }
            return 0;
        } break;
        case MCAST_JOIN_SOURCE_GROUP:
        case MCAST_LEAVE_SOURCE_GROUP: {
            if (!__optval) {
                si_udp_logdbg("%s, %s optval=NULL, optlen:%d", setsockopt_level_to_str(__level),
                              setsockopt_ip_opt_to_str(__optname), (int)__optlen);
                break;
            }

            if (__optlen < sizeof(struct group_source_req)) {
                si_udp_logdbg("%s, %s; Bad optlen! calling OS setsockopt() with optlen=%d "
                              "(required optlen=%zu)",
                              setsockopt_level_to_str(__level), setsockopt_ip_opt_to_str(__optname),
                              __optlen, sizeof(struct group_source_req));
                break;
            }

            const sock_addr *grp = reinterpret_cast<const sock_addr *>(
                &(reinterpret_cast<const struct group_source_req *>(__optval)->gsr_group));
            const sock_addr *src = reinterpret_cast<const sock_addr *>(
                &(reinterpret_cast<const struct group_source_req *>(__optval)->gsr_source));
            if (grp->get_sa_family() != AF_INET6 || src->get_sa_family() != AF_INET6) {
                si_udp_logdbg(
                    "setsockopt(%s) will be passed to OS for handling, sa_family != AF_INET6 ",
                    setsockopt_ip_opt_to_str(__optname));
                break;
            }

            if (multicast_membership_setsockopt_ip6(__optname, __optval, __optlen) < 0) {
                si_udp_logdbg("setsockopt(%s) will be passed to OS for handling",
                              setsockopt_ip_opt_to_str(__optname));
                break;
            }
            return 0;
        } break;
        case IPV6_RECVPKTINFO:
            m_b_pktinfo = __optval && *(int *)__optval != 0;
            break;
        }
        break; // case IPPROTO_IPV6
    default: {
        si_udp_logdbg("level = %d, optname = %d", __level, __optname);
        supported = false;
    } break;
    }
    return setsockopt_kernel(__level, __optname, __optval, __optlen, supported, false);
}

int sockinfo_udp::multicast_membership_setsockopt_ip6(int optname, const void *optval,
                                                      socklen_t optlen)
{
    if (!m_sock_offload) {
        si_udp_logdbg("Rx Offload is Disabled!");
        return -1;
    }

    mc_pending_pram mcpram;
    if (fill_mc_structs_ip6(optname, optval, &mcpram) < 0) {
        return -1;
    }

    si_udp_logdbg("IPPROTO_IPV6, %s=%s, mc_if:%s, src_ip:%s", setsockopt_ip_opt_to_str(optname),
                  mcpram.mc_grp.to_str(m_family).c_str(), mcpram.mc_if.to_str(m_family).c_str(),
                  mcpram.mc_src.to_str(m_family).c_str());

    // Add multicast group membership
    if (mc_change_membership_start_helper_ip6(&mcpram)) {
        si_udp_logerr("IPPROTO_IPV6, %s failed due to wrong input",
                      setsockopt_ip_opt_to_str(optname));
        return -1;
    }

    bool goto_os = false;
    // Check MC rules for not offloading

    int ret {0};

    // Check if local_if is offloaded
    if (!g_p_net_device_table_mgr->get_net_device_val(ip_addr(mcpram.mc_if, m_family))) {
        // call orig setsockopt() and don't try to offlaod
        si_udp_logdbg("Not offloaded interface (%s)", mcpram.mc_if.to_str(m_family).c_str());
        goto_os = true;
    }

    // offloaded, check if need to pend
    else if (m_bound.is_anyport()) {
        // Delay attaching to this MC group until we have bound UDP port
        ret = SYSCALL(setsockopt, m_fd, IPPROTO_IPV6, optname, optval, optlen);
        if (ret) {
            return ret;
        }
        mc_change_pending_mreq(&mcpram);
    }

    // Handle attach to this MC group now
    else if (mc_change_membership_ip6(&mcpram)) {
        // Opps, failed in attaching??? call orig setsockopt()
        goto_os = true;
    }

    if (goto_os) {
        ret = SYSCALL(setsockopt, m_fd, IPPROTO_IPV6, optname, optval, optlen);
        if (ret) {
            return ret;
        }
    }

    if (mc_change_membership_end_helper_ip6(&mcpram) < 0) {
        si_udp_logerr("Unknown optname=%d", optname);
        return -1;
    }
    return 0;
}

int sockinfo_udp::resolve_if_ip(const int if_index, const ip_address &ip, ip_address &resolved_ip)
{
    if (if_index) {
        if (!g_p_net_device_table_mgr->get_net_device_val(if_index)) {
            si_udp_logdbg("if_index does not exist (%d)", if_index);
            return -1;
        }
        local_ip_list_t lip_offloaded_list;
        g_p_net_device_table_mgr->get_ip_list(lip_offloaded_list, m_family, if_index);
        if (!lip_offloaded_list.empty()) {
            resolved_ip = ip_addr(lip_offloaded_list.front().get().local_addr, m_family);
        } else {
            ip_addr src_addr {0};
            if (get_ip_addr_from_ifindex(if_index, src_addr, m_family) == 0) {
                // coverity[copy_assignment_call:FALSE] /*Turn off check COPY_INSTEAD_OF_MOVE*/
                resolved_ip = src_addr;
            } else {
                si_udp_logdbg("Can't find interface IP of interface index %d", if_index);
                return -1;
            }
        }
    } else {
        // In case if_index is 0 - find the correct interface from routing table
        route_result res;
        const ip_address &src_ip = (!m_bound.is_anyaddr() && !m_bound.is_mc())
            ? m_bound.get_ip_addr()
            : m_so_bindtodevice_ip;
        if (g_p_route_table_mgr->route_resolve(route_rule_table_key(ip, src_ip, m_family, m_tos),
                                               res)) {
            // Get the first IP to represent the interface.
            auto *device_val = g_p_net_device_table_mgr->get_net_device_val(res.if_index);
            if (device_val) {
                const auto &iparray = device_val->get_ip_array(m_family);
                if (iparray.size() == 0U) {
                    // Current implementation does not support interface without a representor IP.
                    si_udp_logdbg("No representor IP for interface: %d", res.if_index);
                    return -1;
                }

                resolved_ip =
                    (iparray.size() > 0U ? iparray.front()->local_addr : ip_address::any_addr());
                si_udp_logdbg("Selected representor IP %s for interface %d",
                              resolved_ip.to_str(m_family).c_str(), res.if_index);
            } else {
                si_udp_logdbg("Non offloadable device: %d", res.if_index);
                return -1;
            }
        } else {
            // If we could not resolve routing - pass to OS, MC will not be offloaded
            si_udp_logdbg("Route was not resolved for IP:%s", ip.to_str(m_family).c_str());
            return -1;
        }
    }

    return 0;
}

int sockinfo_udp::fill_mc_structs_ip6(int optname, const void *optval, mc_pending_pram *mcpram)
{
    const mc_req_all *mc_req = reinterpret_cast<const mc_req_all *>(optval);
    mcpram->is_ipv6 = true;
    mcpram->optname = optname;
    switch (optname) {
    case MCAST_JOIN_GROUP:
    case MCAST_LEAVE_GROUP:
        mcpram->pram_size = sizeof(struct group_req);
        mcpram->mc_grp = reinterpret_cast<const sock_addr *>(&mc_req->greq.gr_group)->get_ip_addr();
        mcpram->if_index = mc_req->greq.gr_interface;
        break;
    case IPV6_JOIN_GROUP:
    case IPV6_LEAVE_GROUP:
        mcpram->pram_size = sizeof(struct ipv6_mreq);
        mcpram->mc_grp = ip_address(mc_req->ip6_mreq.ipv6mr_multiaddr);
        mcpram->if_index = mc_req->ip6_mreq.ipv6mr_interface;
        break;
    case MCAST_JOIN_SOURCE_GROUP:
    case MCAST_LEAVE_SOURCE_GROUP:
    case MCAST_BLOCK_SOURCE:
    case MCAST_UNBLOCK_SOURCE:
        mcpram->pram_size = sizeof(struct group_source_req);
        mcpram->mc_grp =
            reinterpret_cast<const sock_addr *>(&mc_req->gsreq.gsr_group)->get_ip_addr();
        mcpram->if_index = mc_req->gsreq.gsr_interface;
        mcpram->mc_src =
            reinterpret_cast<const sock_addr *>(&mc_req->gsreq.gsr_source)->get_ip_addr();
        break;
    default:
        si_udp_logerr("Unknown optname=%d", optname);
        return -1;
    }

    if (resolve_if_ip(mcpram->if_index, mcpram->mc_grp, mcpram->mc_if) < 0) {
        si_udp_logdbg("Resolve IP failed for %s", mcpram->mc_grp.to_str(AF_INET6).c_str());
        return -1;
    }

    memcpy(&mcpram->req, optval, mcpram->pram_size);
    return 0;
}

int sockinfo_udp::getsockopt(int __level, int __optname, void *__optval, socklen_t *__optlen)
{
    si_udp_logfunc("level=%d, optname=%d", __level, __optname);

    int ret = SYSCALL(getsockopt, m_fd, __level, __optname, __optval, __optlen);

    if (unlikely(m_state == SOCKINFO_DESTROYING) || unlikely(g_b_exit)) {
        return ret;
    }

    if (0 == sockinfo::getsockopt(__level, __optname, __optval, __optlen)) {
        return 0;
    }

    std::lock_guard<decltype(m_lock_snd)> lock_tx(m_lock_snd);
    std::lock_guard<decltype(m_lock_rcv)> lock_rx(m_lock_rcv);

    bool supported = true;
    switch (__level) {
    case SOL_SOCKET: {
        switch (__optname) {

        case SO_RCVBUF: {
            uint32_t n_so_rcvbuf_bytes = *(int *)__optval;
            si_udp_logdbg("SOL_SOCKET, SO_RCVBUF=%d", n_so_rcvbuf_bytes);

            if (m_rx_ready_byte_count > n_so_rcvbuf_bytes) {
                si_udp_logdbg("Releasing at least %lu bytes from ready rx packets queue",
                              m_rx_ready_byte_count - n_so_rcvbuf_bytes);
            }

            rx_ready_byte_count_limit_update(n_so_rcvbuf_bytes);
        } break;

        case SO_SNDBUF:
            si_udp_logdbg("SOL_SOCKET, SO_SNDBUF=%d", *(int *)__optval);
            break;

        case SO_MAX_PACING_RATE:
            ret = sockinfo::getsockopt(__level, __optname, __optval, __optlen);
            break;

        default:
            si_udp_logdbg("SOL_SOCKET, optname=%d", __optname);
            supported = false;
            break;
        }

    } // case SOL_SOCKET
    break;

    default: {
        si_udp_logdbg("level = %d, optname = %d", __level, __optname);
        supported = false;
    } break;
    }

    if (!supported) {
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

    return ret;
}

void sockinfo_udp::rx_ready_byte_count_limit_update(size_t n_rx_ready_bytes_limit_new)
{
    si_udp_logfunc("new limit: %d Bytes (old: %d Bytes, min value %d Bytes)",
                   n_rx_ready_bytes_limit_new, m_rx_ready_byte_limit,
                   m_n_sysvar_rx_ready_byte_min_limit);
    if (n_rx_ready_bytes_limit_new > 0 &&
        n_rx_ready_bytes_limit_new < m_n_sysvar_rx_ready_byte_min_limit) {
        n_rx_ready_bytes_limit_new = m_n_sysvar_rx_ready_byte_min_limit;
    }
    m_rx_ready_byte_limit = n_rx_ready_bytes_limit_new;
    drop_rx_ready_byte_count(n_rx_ready_bytes_limit_new);

    return;
}

// Drop rx ready packets from head of queue
void sockinfo_udp::drop_rx_ready_byte_count(size_t n_rx_bytes_limit)
{
    m_lock_rcv.lock();
    while (m_n_rx_pkt_ready_list_count) {
        mem_buf_desc_t *p_rx_pkt_desc = m_rx_pkt_ready_list.front();
        if (m_rx_ready_byte_count > n_rx_bytes_limit || p_rx_pkt_desc->rx.sz_payload == 0U) {
            m_rx_pkt_ready_list.pop_front();
            m_n_rx_pkt_ready_list_count--;
            m_rx_ready_byte_count -= p_rx_pkt_desc->rx.sz_payload;
            if (m_p_socket_stats) {
                m_p_socket_stats->n_rx_ready_pkt_count--;
                m_p_socket_stats->n_rx_ready_byte_count -= p_rx_pkt_desc->rx.sz_payload;
            }

            reuse_buffer(p_rx_pkt_desc);
            return_reuse_buffers_postponed();
        } else {
            break;
        }
    }
    m_lock_rcv.unlock();
}

ssize_t sockinfo_udp::rx(const rx_call_t call_type, iovec *p_iov, ssize_t sz_iov, int *p_flags,
                         sockaddr *__from, socklen_t *__fromlen, struct msghdr *__msg)
{
    int errno_tmp = errno;
    int ret;
    uint64_t poll_sn = 0;
    int out_flags = 0;
    int in_flags = *p_flags;

    si_udp_logfunc("");

    m_lock_rcv.lock();

    if (unlikely(m_state == SOCKINFO_DESTROYING)) {
        errno = EBADFD;
        ret = -1;
        goto out;
    } else if (unlikely(g_b_exit)) {
        errno = EINTR;
        ret = -1;
        goto out;
    }

    save_stats_threadid_rx();

    int rx_wait_ret;

    return_reuse_buffers_postponed();

    // Drop lock to not starve other threads
    m_lock_rcv.unlock();

    // Poll socket for OS ready packets... (at a ratio of the offloaded sockets as defined in
    // m_n_sysvar_rx_udp_poll_os_ratio)
    if ((m_n_sysvar_rx_udp_poll_os_ratio > 0) &&
        (m_rx_udp_poll_os_ratio_counter >= m_n_sysvar_rx_udp_poll_os_ratio)) {
        ret = poll_os();
        if (ret == -1) {
            /* coverity[double_lock] TODO: RM#1049980 */
            m_lock_rcv.lock();
            goto out;
        }
        if (ret == 1) {
            /* coverity[double_lock] TODO: RM#1049980 */
            m_lock_rcv.lock();
            goto os;
        }
    }

    // First check if we have a packet in the ready list
    if ((m_n_rx_pkt_ready_list_count > 0 &&
         m_n_sysvar_rx_cq_drain_rate_nsec == MCE_RX_CQ_DRAIN_RATE_DISABLED) ||
        is_readable(&poll_sn)) {
        /* coverity[double_lock] TODO: RM#1049980 */
        m_lock_rcv.lock();
        m_rx_udp_poll_os_ratio_counter++;
        if (m_n_rx_pkt_ready_list_count > 0) {
            // Found a ready packet in the list
            if (__msg) {
                handle_cmsg(__msg, in_flags);
            }
            ret = dequeue_packet(p_iov, sz_iov, __from, __fromlen, in_flags, &out_flags);
            goto out;
        }
        /* coverity[double_unlock] TODO: RM#1049980 */
        m_lock_rcv.unlock();
    }

wait:
    /*
     * We (probably) do not have a ready packet.
     * Wait for RX to become ready.
     */
    si_udp_logfunc("rx_wait: %d", m_fd);
    rx_wait_ret = rx_wait(m_b_blocking && !(in_flags & MSG_DONTWAIT));

    m_lock_rcv.lock();

    if (likely(rx_wait_ret == 0)) {
        // Got 0, means we might have a ready packet
        if (m_n_rx_pkt_ready_list_count > 0) {
            if (__msg) {
                handle_cmsg(__msg, in_flags);
            }
            ret = dequeue_packet(p_iov, sz_iov, __from, __fromlen, in_flags, &out_flags);
            goto out;
        } else {
            m_lock_rcv.unlock();
            goto wait;
        }
    } else if (unlikely(rx_wait_ret < 0)) {
        // Got < 0, means an error occurred
        ret = rx_wait_ret;
        goto out;
    } // else - packet in OS

    /*
     * If we got here, either the socket is not offloaded or rx_wait() returned 1.
     */
os:
    if (in_flags & MSG_XLIO_ZCOPY_FORCE) {
        // Enable the next non-blocked read to check the OS
        m_rx_udp_poll_os_ratio_counter = m_n_sysvar_rx_udp_poll_os_ratio;
        errno = EIO;
        ret = -1;
        goto out;
    }

    in_flags &= ~MSG_XLIO_ZCOPY;
    ret = rx_os(call_type, p_iov, sz_iov, in_flags, __from, __fromlen, __msg);
    *p_flags = in_flags;
    save_stats_rx_os(ret);
    if (ret > 0) {
        // This will cause the next non-blocked read to check the OS again.
        // We do this only after a successful read.
        m_rx_udp_poll_os_ratio_counter = m_n_sysvar_rx_udp_poll_os_ratio;
    }

out:
    /* coverity[double_unlock] TODO: RM#1049980 */
    m_lock_rcv.unlock();

    if (__msg) {
        __msg->msg_flags |= out_flags & MSG_TRUNC;
    }

    if (ret < 0) {
        si_udp_logfunc("returning with: %d (errno=%d %m)", ret, errno);
    } else {
        /* Restore errno on function entry in case success */
        errno = errno_tmp;

        si_udp_logfunc("returning with: %d", ret);
    }
    return ret;
}

void sockinfo_udp::handle_ip_pktinfo(struct cmsg_state *cm_state)
{
    mem_buf_desc_t *p_desc = m_rx_pkt_ready_list.front();

    if (!p_desc) {
        return;
    }

    sa_family_t rx_family = p_desc->rx.dst.get_sa_family();
    if (rx_family != AF_INET6 && rx_family != AF_INET) {
        return;
    }

    if (get_family() == AF_INET && rx_family == AF_INET) {
        struct in_pktinfo pktinfo;
        pktinfo.ipi_ifindex = p_desc->rx.udp.ifindex;
        pktinfo.ipi_addr.s_addr = p_desc->rx.dst.get_ip_addr().get_in_addr();
        if (!p_desc->rx.dst.is_mc()) {
            pktinfo.ipi_spec_dst = pktinfo.ipi_addr;
        } else {
            pktinfo.ipi_spec_dst.s_addr = 0;
            for (auto iter = m_rx_nd_map.begin(); iter != m_rx_nd_map.end(); ++iter) {
                if (iter->second.p_ndv->get_if_idx() == pktinfo.ipi_ifindex) {
                    pktinfo.ipi_spec_dst.s_addr = iter->first.get_in_addr();
                    break;
                }
            }
        }
        insert_cmsg(cm_state, IPPROTO_IP, IP_PKTINFO, &pktinfo, sizeof(pktinfo));
    } else if (get_family() == AF_INET6) {
        ip_address addr_ipv6 = rx_family == AF_INET6
            ? p_desc->rx.dst.get_ip_addr()
            : p_desc->rx.dst.get_ip_addr().to_mapped_ipv4();
        struct in6_pktinfo pktinfo {
            addr_ipv6.get_in6_addr(), static_cast<unsigned int>(p_desc->rx.udp.ifindex)
        };
        insert_cmsg(cm_state, IPPROTO_IPV6, IPV6_PKTINFO, &pktinfo, sizeof(pktinfo));
    }
}

// This function is relevant only for non-blocking socket
void sockinfo_udp::set_immediate_os_sample()
{
    m_rx_udp_poll_os_ratio_counter = m_n_sysvar_rx_udp_poll_os_ratio;
}

// This function is relevant only for non-blocking socket
void sockinfo_udp::unset_immediate_os_sample()
{
    m_rx_udp_poll_os_ratio_counter = 0;
}

bool sockinfo_udp::is_readable(uint64_t *p_poll_sn, fd_array_t *p_fd_ready_array)
{
    si_udp_logfuncall("");

    // Check local list of ready rx packets
    // This is the quickest way back to the user with a ready packet (which will happen if we don't
    // force draining of the CQ)
    if (m_n_rx_pkt_ready_list_count > 0) {

        if (m_n_sysvar_rx_cq_drain_rate_nsec == MCE_RX_CQ_DRAIN_RATE_DISABLED) {
            si_udp_logfunc("=> true (ready count = %d packets / %d bytes)",
                           m_n_rx_pkt_ready_list_count, m_rx_ready_byte_count);
            return true;
        } else {
            tscval_t tsc_now = TSCVAL_INITIALIZER;
            gettimeoftsc(&tsc_now);
            if (tsc_now - g_si_tscv_last_poll < m_n_sysvar_rx_delta_tsc_between_cq_polls) {
                si_udp_logfunc("=> true (ready count = %d packets / %d bytes)",
                               m_n_rx_pkt_ready_list_count, m_rx_ready_byte_count);
                return true;
            }

            // Getting here means that although socket has rx
            // ready packets we still want to poll the CQ
            g_si_tscv_last_poll = tsc_now;
        }
    }

    // Loop on rx cq_list and process waiting wce (non blocking! polling only from this context)
    // AlexR todo: would be nice to start after the last cq_pos for better cq coverage
    if (p_poll_sn) {
        consider_rings_migration_rx();
        si_udp_logfuncall("try poll rx cq's");
        rx_ring_map_t::iterator rx_ring_iter;
        m_rx_ring_map_lock.lock();
        for (rx_ring_iter = m_rx_ring_map.begin(); rx_ring_iter != m_rx_ring_map.end();
             rx_ring_iter++) {
            if (rx_ring_iter->second->refcnt <= 0) {
                continue;
            }

            ring *p_ring = rx_ring_iter->first;
            while (1) {
                // We need here a lock() version of poll_and_process_element_rx.
                int was_drained = p_ring->poll_and_process_element_rx(p_poll_sn, p_fd_ready_array);

                if (m_n_rx_pkt_ready_list_count) {
                    // Get out of the CQ polling loop
                    si_udp_logfunc("=> polled true (ready count = %d packets / %d bytes)",
                                   m_n_rx_pkt_ready_list_count, m_rx_ready_byte_count);
                    m_rx_ring_map_lock.unlock();
                    return true;
                } else if (was_drained <= 0) {
                    break;
                }
            }
        }
        m_rx_ring_map_lock.unlock();
    }

    // Check local list of ready rx packets
    // This check is added in case we processed all wce and drained the cq
    // TODO: handle the scenario of 2 thread accessing the same socket - might need to lock
    // m_n_rx_pkt_ready_list_count
    if (m_n_rx_pkt_ready_list_count) {
        si_udp_logfunc("=> true (ready count = %d packets / %d bytes)", m_n_rx_pkt_ready_list_count,
                       m_rx_ready_byte_count);
        return true;
    }

    // Not ready packets in ready queue, return false
    si_udp_logfuncall("=> false (ready count = %d packets / %d bytes)", m_n_rx_pkt_ready_list_count,
                      m_rx_ready_byte_count);
    return false;
}

int sockinfo_udp::rx_request_notification(uint64_t poll_sn)
{
    si_udp_logfuncall("");
    int ring_ready_count = 0, ring_armed_count = 0;
    rx_ring_map_t::iterator rx_ring_iter;
    m_rx_ring_map_lock.lock();
    for (rx_ring_iter = m_rx_ring_map.begin(); rx_ring_iter != m_rx_ring_map.end();
         rx_ring_iter++) {
        ring *p_ring = rx_ring_iter->first;
        int ret = p_ring->request_notification(CQT_RX, poll_sn);
        if (ret > 0) {
            // cq not armed and might have ready completions for processing
            ring_ready_count++;
        } else if (ret == 0) {
            // cq armed
            ring_armed_count++;
        } else { // if (ret < 0)
            si_udp_logerr("failure from ring[%p]->request_notification() (errno=%d %m)", p_ring,
                          errno);
        }
    }
    m_rx_ring_map_lock.unlock();

    si_udp_logfunc("armed or busy %d ring(s) and %d ring are pending processing", ring_armed_count,
                   ring_ready_count);
    NOT_IN_USE(ring_armed_count);
    return ring_ready_count;
}

ssize_t sockinfo_udp::tx(xlio_tx_call_attr_t &tx_arg)
{
    const iovec *p_iov = tx_arg.attr.iov;
    const ssize_t sz_iov = tx_arg.attr.sz_iov;
    const int __flags = tx_arg.attr.flags;
    const struct sockaddr *__dst = tx_arg.attr.addr;
    const socklen_t __dstlen = tx_arg.attr.len;
    int errno_tmp = errno;
    int ret = 0;
    bool is_dummy = IS_DUMMY_PACKET(__flags);
    dst_entry *p_dst_entry = m_p_connected_dst_entry; // Default for connected() socket but we'll
                                                      // update it on a specific sendTO(__to) call

    si_udp_logfunc("");

    m_lock_snd.lock();

    save_stats_threadid_tx();

    /* Let allow OS to process all invalid scenarios to avoid any
     * inconsistencies in setting errno values.
     * Note: The field size sets a theoretical limit of 65,535 bytes
     * (8 byte header + 65,527 bytes of data) for a UDP datagram.
     * However the actual limit for the data length, which is imposed by
     * the underlying IPv4 protocol, is 65,507 bytes
     * (65,535 - 8 byte UDP header - 20 byte IP header).
     * For IPv6 it is 65527, since the IP header size is not included in
     * IPv6 length field.
     */
    ssize_t sz_data_payload = check_payload_size(p_iov, sz_iov);
    if (unlikely(m_state == SOCKINFO_DESTROYING) || unlikely(g_b_exit) || unlikely(!p_iov) ||
        unlikely(0 >= sz_iov) || unlikely(sz_data_payload < 0)) {
        goto tx_packet_to_os;
    }

    if (unlikely(__flags & MSG_OOB)) {
        si_udp_logdbg("MSG_OOB not supported in UDP (tx-ing to os)");
        goto tx_packet_to_os;
    }
    if (__dst) {
        sock_addr dst(__dst, __dstlen);
        if (!validate_and_convert_mapped_ipv4(dst)) {
            si_udp_logdbg("Mapped IPv4 on IPv6-Only socket");
            goto tx_packet_to_os;
        }

        if (unlikely(!dst.is_supported())) {
            si_udp_logdbg("to->sin_family is not supported (tx-ing to os)");
            goto tx_packet_to_os;
        }

        if (unlikely(get_sa_port(__dst, __dstlen) == 0)) {
            si_udp_logdbg("to->sin_port == 0 (tx-ing to os)");
            goto tx_packet_to_os;
        }

        if (dst == m_last_sock_addr && m_p_last_dst_entry) {
            p_dst_entry = m_p_last_dst_entry;
        } else {

            // Find dst_entry in map (create one if needed)
            dst_entry_map_t::iterator dst_entry_iter = m_dst_entry_map.find(dst);

            if (likely(dst_entry_iter != m_dst_entry_map.end())) {

                // Fast path
                // We found our target dst_entry object
                m_p_last_dst_entry = p_dst_entry = dst_entry_iter->second;
                // coverity[copy_assignment_call:FALSE] /*Turn off check COPY_INSTEAD_OF_MOVE*/
                m_last_sock_addr = dst;
            } else {
                // Slow path
                // We do not have the correct dst_entry in the map and need to create a one

                // Verify we are bounded (got a local port)
                // can happen in UDP sendto() directly after socket(DATAGRAM)
                if (m_bound.is_anyport()) {
                    sock_addr addr;
                    addr.set_sa_family(m_family);
                    if (bind(addr.get_p_sa(), addr.get_socklen())) {
                        errno = EAGAIN;
                        m_lock_snd.unlock();
                        return -1;
                    }
                }
                in_port_t src_port = m_bound.get_in_port();
                // Create the new dst_entry
                if (dst.is_mc()) {
                    socket_data data = {m_fd, m_n_mc_ttl_hop_lim, m_tos, m_pcp};
                    p_dst_entry = new dst_entry_udp_mc(
                        dst, src_port,
                        m_mc_tx_src_ip.is_anyaddr() ? m_bound.get_ip_addr() : m_mc_tx_src_ip,
                        m_b_mc_tx_loop, data, m_ring_alloc_log_tx);
                } else {
                    socket_data data = {m_fd, m_n_uc_ttl_hop_lim, m_tos, m_pcp};
                    p_dst_entry = new dst_entry_udp(dst, src_port, data, m_ring_alloc_log_tx);
                }
                BULLSEYE_EXCLUDE_BLOCK_START
                if (!p_dst_entry) {
                    si_udp_logerr("Failed to create dst_entry(dst_ip:%s, dst_port:%s, src_port:%d)",
                                  dst.to_str_ip_port().c_str(), dst.to_str_port().c_str(),
                                  ntohs(src_port));
                    goto tx_packet_to_os;
                }
                BULLSEYE_EXCLUDE_BLOCK_END
                if (!m_bound.is_anyaddr() && !m_bound.is_mc()) {
                    p_dst_entry->set_bound_addr(m_bound.get_ip_addr());
                }
                if (!m_so_bindtodevice_ip.is_anyaddr()) {
                    p_dst_entry->set_so_bindtodevice_addr(m_so_bindtodevice_ip);
                }

                p_dst_entry->set_src_sel_prefs(m_src_sel_flags);

                // Save new dst_entry in map
                m_dst_entry_map[dst] = p_dst_entry;
            }
        }
    } else if (unlikely(!p_dst_entry)) {
        si_udp_logdbg("going to os, __dst = %p, m_p_connected_dst_entry = %p", __dst,
                      m_p_connected_dst_entry);
        goto tx_packet_to_os;
    }

    {
        xlio_send_attr attr = {(xlio_wr_tx_packet_attr)0, 0, 0, nullptr};
        bool b_blocking = m_b_blocking;
        if (unlikely(__flags & MSG_DONTWAIT)) {
            b_blocking = false;
        }

        attr.length = static_cast<size_t>(sz_data_payload);
        attr.flags = (xlio_wr_tx_packet_attr)((b_blocking * XLIO_TX_PACKET_BLOCK) |
                                              (is_dummy * XLIO_TX_PACKET_DUMMY));
        if (likely(p_dst_entry->is_valid())) {
            // All set for fast path packet sending - this is our best performance flow
            ret = p_dst_entry->fast_send(p_iov, sz_iov, attr);
        } else {
            // updates the dst_entry internal information and packet headers
            ret = p_dst_entry->slow_send(p_iov, sz_iov, attr, m_so_ratelimit, __flags, this,
                                         tx_arg.opcode);
        }

        // Condition for cache optimization
        if (unlikely(safe_mce_sys().ring_migration_ratio_tx > 0)) {
            if (unlikely(p_dst_entry->try_migrate_ring_tx(m_lock_snd))) {
                IF_STATS(m_p_socket_stats->counters.n_tx_migrations++);
            }
        }

        // TODO ALEXR - still need to handle "is_dropped" in send path
        // For now we removed the support of this feature (AlexV & AlexR)
    }

    if (likely(p_dst_entry->is_offloaded())) {

        // MNY: Problematic in cases where packet was dropped because no tx buffers were available..
        // Yet we need to add this code to avoid deadlocks in case of EPOLLOUT ET.
        NOTIFY_ON_EVENTS(this, EPOLLOUT);

        save_stats_tx_offload(ret, is_dummy);

        m_lock_snd.unlock();

        /* Restore errno on function entry in case success */
        if (ret >= 0) {
            errno = errno_tmp;
        }

        return ret;
    } else {
        goto tx_packet_to_os_stats;
    }

tx_packet_to_os:
    // Calling OS transmit
    ret = tx_os(tx_arg.opcode, p_iov, sz_iov, __flags, __dst, __dstlen);

tx_packet_to_os_stats:
    save_stats_tx_os(ret);
    m_lock_snd.unlock();
    return ret;
}

ssize_t sockinfo_udp::check_payload_size(const iovec *p_iov, ssize_t sz_iov)
{
    // Calc user data payload size
    ssize_t sz_data_payload = 0;
    for (ssize_t i = 0; i < sz_iov; i++) {
        // Imitate Kernel behaviour.
        if (unlikely(!p_iov[i].iov_base) && unlikely(p_iov[i].iov_len)) {
            return -1;
        }

        sz_data_payload += p_iov[i].iov_len;
    }

    // See comment in sockinfo_udp::tx
    if (unlikely(sz_data_payload > 65507) && (m_family == AF_INET || sz_data_payload > 65527)) {
        si_udp_logfunc("sz_data_payload=%d exceeds max of 64KB - headers", sz_data_payload);
        return -1;
    }

    return sz_data_payload;
}

int sockinfo_udp::rx_verify_available_data()
{
    int ret;

    // Don't poll cq if offloaded data is ready
    if (!m_rx_pkt_ready_list.empty()) {
        std::lock_guard<decltype(m_lock_rcv)> locker(m_lock_rcv);
        if (!m_rx_pkt_ready_list.empty()) {
            return m_rx_pkt_ready_list.front()->rx.sz_payload;
        }
    }

    ret = rx_wait(false);

    if (ret == 0) {
        // Got 0, means we might have a ready packet
        std::lock_guard<decltype(m_lock_rcv)> locker(m_lock_rcv);
        if (!m_rx_pkt_ready_list.empty()) {
            ret = m_rx_pkt_ready_list.front()->rx.sz_payload;
        }
    } else if (ret == 1) {
        // Got 1, means we have a ready packet in OS
        uint64_t pending_data = 0;
        ret = SYSCALL(ioctl, m_fd, FIONREAD, &pending_data);
        if (ret >= 0) {
            // This will cause the next non-blocked read to check the OS again.
            // We do this only after a successful read.
            m_rx_udp_poll_os_ratio_counter = m_n_sysvar_rx_udp_poll_os_ratio;
            ret = pending_data;
        }
    } else if (errno == EAGAIN) {
        errno = 0;
        ret = 0;
    }

    return ret;
}

/**
 *	Performs inspection by registered user callback
 *
 */
inline xlio_recv_callback_retval_t sockinfo_udp::inspect_by_user_cb(mem_buf_desc_t *p_desc)
{
    xlio_info_t pkt_info;

    pkt_info.struct_sz = sizeof(pkt_info);
    pkt_info.packet_id = (void *)p_desc;
    pkt_info.src = p_desc->rx.src.get_p_sa();
    pkt_info.dst = p_desc->rx.dst.get_p_sa();
    pkt_info.socket_ready_queue_pkt_count = m_n_rx_pkt_ready_list_count;
    pkt_info.socket_ready_queue_byte_count = m_rx_ready_byte_count;

    if (m_n_tsing_flags & SOF_TIMESTAMPING_RAW_HARDWARE) {
        pkt_info.hw_timestamp = p_desc->rx.timestamps.hw;
    }
    if (p_desc->rx.timestamps.sw.tv_sec) {
        pkt_info.sw_timestamp = p_desc->rx.timestamps.sw;
    }

    // fill io vector array with data buffer pointers
    iovec iov[p_desc->rx.n_frags];
    int nr_frags = 0;

    for (mem_buf_desc_t *tmp = p_desc; tmp; tmp = tmp->p_next_desc) {
        iov[nr_frags++] = tmp->rx.frag;
    }

    // call user callback
    return m_rx_callback(m_fd, nr_frags, iov, &pkt_info, m_rx_callback_context);
}

/* Update completion with
 * XLIO_SOCKETXTREME_PACKET related data
 */
inline void sockinfo_udp::rx_udp_cb_socketxtreme_helper(mem_buf_desc_t *p_desc)
{
    // xlio_socketxtreme_completion_t is IPv4 only.
    assert(p_desc->rx.src.get_sa_family() == AF_INET);

    xlio_socketxtreme_completion_t *completion =
        set_events_socketxtreme(XLIO_SOCKETXTREME_PACKET, false);
    completion->packet.num_bufs = p_desc->rx.n_frags;
    completion->packet.total_len = 0;
    p_desc->rx.src.get_sa(reinterpret_cast<struct sockaddr *>(&completion->src),
                          sizeof(completion->src));

    if (m_n_tsing_flags & SOF_TIMESTAMPING_RAW_HARDWARE) {
        completion->packet.hw_timestamp = p_desc->rx.timestamps.hw;
    }

    for (mem_buf_desc_t *tmp_p = p_desc; tmp_p; tmp_p = tmp_p->p_next_desc) {
        completion->packet.total_len += tmp_p->rx.sz_payload;
        completion->packet.buff_lst = (struct xlio_buff_t *)tmp_p;
        completion->packet.buff_lst->next = (struct xlio_buff_t *)tmp_p->p_next_desc;
        completion->packet.buff_lst->payload = p_desc->rx.frag.iov_base;
        completion->packet.buff_lst->len = p_desc->rx.frag.iov_len;
    }

    save_stats_rx_offload(completion->packet.total_len);

    m_p_rx_ring->socketxtreme_end_ec_operation();
}

/**
 *	Performs packet processing for NON-SOCKETXTREME cases and store packet
 *	in ready queue.
 */
inline void sockinfo_udp::update_ready(mem_buf_desc_t *p_desc, void *pv_fd_ready_array,
                                       xlio_recv_callback_retval_t cb_ret)
{
    // In ZERO COPY case we let the user's application manage the ready queue
    if (cb_ret != XLIO_PACKET_HOLD) {
        m_lock_rcv.lock();
        // Save rx packet info in our ready list
        m_rx_pkt_ready_list.push_back(p_desc);
        m_n_rx_pkt_ready_list_count++;
        m_rx_ready_byte_count += p_desc->rx.sz_payload;
        if (unlikely(m_p_socket_stats)) {
            m_p_socket_stats->n_rx_ready_byte_count += p_desc->rx.sz_payload;
            m_p_socket_stats->n_rx_ready_pkt_count++;
            m_p_socket_stats->counters.n_rx_ready_pkt_max =
                std::max((uint32_t)m_n_rx_pkt_ready_list_count,
                         m_p_socket_stats->counters.n_rx_ready_pkt_max);
            m_p_socket_stats->counters.n_rx_ready_byte_max = std::max(
                (uint32_t)m_rx_ready_byte_count, m_p_socket_stats->counters.n_rx_ready_byte_max);
        }
        m_sock_wakeup_pipe.do_wakeup();
        m_lock_rcv.unlock();
    } else {
        IF_STATS(m_p_socket_stats->n_rx_zcopy_pkt_count++);
    }

    NOTIFY_ON_EVENTS(this, EPOLLIN);

    // Add this fd to the ready fd list
    /*
     * Note: No issue is expected in case socketxtreme_poll() usage because 'pv_fd_ready_array' is
     * null in such case and as a result update_fd_array() call means nothing
     */
    io_mux_call::update_fd_array((fd_array_t *)pv_fd_ready_array, m_fd);

    si_udp_logfunc("rx ready count = %d packets / %d bytes", m_n_rx_pkt_ready_list_count,
                   m_rx_ready_byte_count);
}

bool sockinfo_udp::packet_is_loopback(mem_buf_desc_t *p_desc)
{
    auto iter =
        m_rx_nd_map.find(ip_addr(p_desc->rx.src.get_ip_addr(), p_desc->rx.src.get_sa_family()));
    return (iter != m_rx_nd_map.end()) &&
        (iter->second.p_ndv->get_if_idx() == p_desc->rx.udp.ifindex);
}

bool sockinfo_udp::rx_input_cb(mem_buf_desc_t *p_desc, void *pv_fd_ready_array)
{
    if (unlikely((m_state == SOCKINFO_DESTROYING) || g_b_exit)) {
        si_udp_logfunc("rx packet discarded - fd closed");
        return false;
    }

    /* Check if sockinfo rx byte SO_RCVBUF reached - then disregard this packet */
    if (unlikely(m_rx_ready_byte_count >= m_rx_ready_byte_limit)) {
        si_udp_logfunc("rx packet discarded - socket limit reached (%d bytes)",
                       m_rx_ready_byte_limit);
        if (m_p_socket_stats) {
            m_p_socket_stats->counters.n_rx_ready_byte_drop += p_desc->rx.sz_payload;
            m_p_socket_stats->counters.n_rx_ready_pkt_drop++;
        }
        return false;
    }

    /* Check that sockinfo is bound to the packets dest port
     * This protects the case where a socket is closed and a new one is rapidly opened
     * receiving the same socket fd.
     * In this case packets arriving for the old sockets should be dropped.
     * This distinction assumes that the OS guarantees the old and new sockets to receive different
     * port numbers from bind().
     * If the user requests to bind the new socket to the same port number as the old one it will be
     * impossible to identify packets designated for the old socket in this way.
     */
    if (unlikely(p_desc->rx.dst.get_in_port() != m_bound.get_in_port())) {
        si_udp_logfunc("rx packet discarded - not socket's bound port (pkt: %s, sock: %s)",
                       p_desc->rx.dst.to_str_port().c_str(), m_bound.to_str_port().c_str());
        return false;
    }

    /* Inspects UDP packets in case socket was connected */
    if (m_is_connected && !m_connected.is_anyport() && !m_connected.is_anyaddr()) {
        if (unlikely(m_connected.get_in_port() != p_desc->rx.src.get_in_port())) {
            si_udp_logfunc("rx packet discarded - not socket's connected port (pkt: %s, sock: %s)",
                           p_desc->rx.src.to_str_port().c_str(), m_connected.to_str_port().c_str());
            return false;
        }

        if (unlikely(m_connected.get_ip_addr() != p_desc->rx.src.get_ip_addr())) {
            si_udp_logfunc(
                "rx packet discarded - not socket's connected addr (pkt: [%s], sock: [%s])",
                p_desc->rx.src.to_str_ip_port().c_str(), m_connected.to_str_ip_port().c_str());
            return false;
        }
    }

    /* Inspects multicast packets */
    if (m_multicast) {
        /* if loopback is disabled, discard loopback packets.
         * in linux, loopback control (set by setsockopt) is done in TX flow.
         * since we currently can't control it in TX, we behave like windows, which filter on RX
         */
        if (unlikely(!m_b_mc_tx_loop && packet_is_loopback(p_desc))) {
            si_udp_logfunc("rx packet discarded - loopback is disabled (pkt: [%s], sock: [%s])",
                           p_desc->rx.src.to_str_ip_port().c_str(),
                           m_bound.to_str_ip_port().c_str());
            return false;
        }
        if (m_mc_num_grp_with_src_filter) {
            const ip_address &mc_grp = p_desc->rx.dst.get_ip_addr();
            if (mc_grp.is_mc(m_family)) {
                const ip_address &mc_src = p_desc->rx.src.get_ip_addr();

                if (m_family == AF_INET) {
                    if ((m_mc_memberships_map.find(mc_grp) == m_mc_memberships_map.end()) ||
                        ((0 < m_mc_memberships_map[mc_grp].size()) &&
                         (m_mc_memberships_map[mc_grp].find(mc_src) ==
                          m_mc_memberships_map[mc_grp].end()))) {
                        si_udp_logfunc("rx packet discarded - multicast source mismatch");
                        return false;
                    }
                } else {
                    // here we would like to find relevant source filtering
                    // thus - src map size should not contain anyaddr src
                    size_t src_map_size {0};
                    bool mc_grp_exists {false};
                    bool mc_src_exists {false};
                    if (m_mc_memberships_map.find(mc_grp) != m_mc_memberships_map.end()) {
                        mc_grp_exists = true;
                        mc_src_exists = (m_mc_memberships_map[mc_grp].find(mc_src) !=
                                         m_mc_memberships_map[mc_grp].end());
                        src_map_size = m_mc_memberships_map[mc_grp].size();
                        if (m_mc_memberships_map[mc_grp].find(ip_address::any_addr()) !=
                            m_mc_memberships_map[mc_grp].end()) {
                            --src_map_size;
                        }
                    }

                    if (!mc_grp_exists || ((src_map_size > 0) && !mc_src_exists)) {
                        /* bug #3202713
                        || ((src_map_size > 0) && mc_src_exists &&
                        (m_mc_memberships_map[mc_grp][mc_src] == MCAST_EXCLUDE))) { */
                        si_udp_logfunc("rx packet discarded - multicast source mismatch");
                        return false;
                    }
                }
            }
        }
    }

    /* Process socket with option UDP_MAP_ADD */
    if (m_sockopt_mapped) {
        // Check port mapping - redirecting packets to another socket
        while (!m_port_map.empty()) {
            m_port_map_lock.lock();
            if (m_port_map.empty()) {
                m_port_map_lock.unlock();
                break;
            }
            m_port_map_index =
                ((m_port_map_index + 1) >= m_port_map.size() ? 0 : (m_port_map_index + 1));
            int new_port = m_port_map[m_port_map_index].port;
            sockinfo *sock_api = g_p_fd_collection->get_sockfd(m_port_map[m_port_map_index].fd);
            if (!sock_api || sock_api->get_type() != FD_TYPE_SOCKET) {
                m_port_map.erase(std::remove(m_port_map.begin(), m_port_map.end(),
                                             m_port_map[m_port_map_index].port));
                if (m_port_map_index) {
                    // coverity[underflow:FALSE] /*Turn off coverity check for underflow*/
                    m_port_map_index--;
                }
                m_port_map_lock.unlock();
                continue;
            }
            m_port_map_lock.unlock();
            p_desc->rx.dst.set_in_port(new_port);
            return ((sockinfo_udp *)sock_api)->rx_input_cb(p_desc, pv_fd_ready_array);
        }
    }

    process_timestamps(p_desc);

    xlio_recv_callback_retval_t cb_ret = XLIO_PACKET_RECV;
    if (m_rx_callback && ((cb_ret = inspect_by_user_cb(p_desc)) == XLIO_PACKET_DROP)) {
        si_udp_logfunc("rx packet discarded - by user callback");
        return false;
    }
    // Yes, we want to keep this packet!
    // And we must increment ref_counter before pushing this packet into the ready queue
    //  to prevent race condition with the 'if( (--ref_count) <= 0)' in ib_comm_mgr
    p_desc->inc_ref_count();
    save_strq_stats(p_desc->rx.strides_num);

    if (safe_mce_sys().enable_socketxtreme) {
        rx_udp_cb_socketxtreme_helper(p_desc);
    } else {
        update_ready(p_desc, pv_fd_ready_array, cb_ret);
    }
    return true;
}

void sockinfo_udp::rx_add_ring_cb(ring *p_ring)
{
    si_udp_logdbg("");
    sockinfo::rx_add_ring_cb(p_ring);

    // Now that we got at least 1 CQ attached enable the skip os mechanism.
    m_rx_udp_poll_os_ratio_counter = m_n_sysvar_rx_udp_poll_os_ratio;

    // Now that we got at least 1 CQ attached start polling the CQs
    if (m_b_blocking) {
        m_loops_to_go = safe_mce_sys().rx_poll_num;
    } else {
        m_loops_to_go = 1; // Force single CQ poll in case of non-blocking socket
    }
}

void sockinfo_udp::rx_del_ring_cb(ring *p_ring)
{
    si_udp_logdbg("");

    sockinfo::rx_del_ring_cb(p_ring);

    // If no more CQ's are attached on this socket, return CQ polling loops ot init state
    if (m_rx_ring_map.size() <= 0) {
        if (m_b_blocking) {
            m_loops_to_go = safe_mce_sys().rx_poll_num_init;
        } else {
            m_loops_to_go = 1;
        }
    }
}

void sockinfo_udp::set_blocking(bool is_blocked)
{
    sockinfo::set_blocking(is_blocked);

    if (m_b_blocking) {
        // Set the high CQ polling RX_POLL value
        // depending on where we have mapped offloaded MC gorups
        if (m_rx_ring_map.size() > 0) {
            m_loops_to_go = safe_mce_sys().rx_poll_num;
        } else {
            m_loops_to_go = safe_mce_sys().rx_poll_num_init;
        }
    } else {
        // Force single CQ poll in case of non-blocking socket
        m_loops_to_go = 1;
    }
}

void sockinfo_udp::handle_pending_mreq()
{
    si_udp_logdbg("Attaching to pending multicast groups");
    mc_pram_list_t::iterator mreq_iter, mreq_iter_temp;
    for (mreq_iter = m_pending_mreqs.begin(); mreq_iter != m_pending_mreqs.end();) {
        if (m_sock_offload) {
            // for delayed operations - os setsockopt was executed before
            if (m_family == AF_INET6) {
                mc_change_membership_ip6(&(*mreq_iter));
            } else {
                mc_change_membership_ip4(&(*mreq_iter));
            }
        }
        mreq_iter_temp = mreq_iter;
        ++mreq_iter;
        m_pending_mreqs.erase(mreq_iter_temp);
    }
}

int sockinfo_udp::mc_change_pending_mreq(const mc_pending_pram *p_mc_pram)
{
    si_udp_logdbg("setsockopt(%s) will be pending until bound to UDP port",
                  setsockopt_ip_opt_to_str(p_mc_pram->optname));

    mc_pram_list_t::iterator mc_pram_iter, mreq_iter_temp;
    bool erase_all_src = false;
    switch (p_mc_pram->optname) {
    case IP_ADD_MEMBERSHIP:
    case IP_ADD_SOURCE_MEMBERSHIP:
    case IPV6_JOIN_GROUP:
    case MCAST_JOIN_GROUP:
    case MCAST_JOIN_SOURCE_GROUP:
        m_pending_mreqs.push_back(*p_mc_pram);
        break;
    case MCAST_LEAVE_GROUP:
    case IP_DROP_MEMBERSHIP:
    case IPV6_LEAVE_GROUP:
        erase_all_src = true;
        // fallthrough
    case MCAST_LEAVE_SOURCE_GROUP:
    case IP_DROP_SOURCE_MEMBERSHIP:
        for (mc_pram_iter = m_pending_mreqs.begin(); mc_pram_iter != m_pending_mreqs.end();) {
            if ((mc_pram_iter->mc_grp == p_mc_pram->mc_grp) &&
                // In case of a IP_DROP_SOURCE_MEMBERSHIP/MCAST_LEAVE_SOURCE_GROUP
                // we should check source address and interface ix too
                (erase_all_src ||
                 ((mc_pram_iter->mc_src == p_mc_pram->mc_src) &&
                  (mc_pram_iter->if_index == p_mc_pram->if_index)))) {
                // We found the group, erase it
                mreq_iter_temp = mc_pram_iter;
                ++mc_pram_iter;
                m_pending_mreqs.erase(mreq_iter_temp);
            } else {
                ++mc_pram_iter;
            }
        }
        break;
        BULLSEYE_EXCLUDE_BLOCK_START
    default:
        si_udp_logerr("setsockopt(%s) illegal", setsockopt_ip_opt_to_str(p_mc_pram->optname));
        return -1;
        BULLSEYE_EXCLUDE_BLOCK_END
    }
    return 0;
}

int sockinfo_udp::mc_change_membership_start_helper_ip4(const ip_address &mc_grp, int optname)
{
    switch (optname) {
    case IP_ADD_MEMBERSHIP:
        if (m_mc_memberships_map.find(mc_grp) == m_mc_memberships_map.end() &&
            m_mc_memberships_map.size() >=
                (size_t)safe_mce_sys().sysctl_reader.get_igmp_max_membership()) {
            errno = ENOBUFS;
            return -1;
        }
        break;
    case IP_ADD_SOURCE_MEMBERSHIP:
        if (m_mc_memberships_map.find(mc_grp) != m_mc_memberships_map.end()) { // This group is
                                                                               // exist
            if (m_mc_memberships_map[mc_grp].size() >=
                (size_t)safe_mce_sys().sysctl_reader.get_igmp_max_source_membership()) {
                errno = ENOBUFS;
                return -1;
            }
        } else { // This group is not exist
            if (m_mc_memberships_map.size() >=
                (size_t)safe_mce_sys().sysctl_reader.get_igmp_max_membership()) {
                errno = ENOBUFS;
                return -1;
            }
        }
        break;
    case IP_DROP_MEMBERSHIP:
    case IP_DROP_SOURCE_MEMBERSHIP:
        break;
        BULLSEYE_EXCLUDE_BLOCK_START
    default:
        si_udp_logerr("setsockopt(%s) will be passed to OS for handling",
                      setsockopt_ip_opt_to_str(optname));
        return -1;
        BULLSEYE_EXCLUDE_BLOCK_END
    }
    return 0;
}

int sockinfo_udp::mc_change_membership_end_helper_ip4(const ip_address &mc_grp, int optname,
                                                      const ip_address &mc_src)
{
    switch (optname) {
    case IP_ADD_MEMBERSHIP:
        m_mc_memberships_map[mc_grp];
        break;
    case IP_ADD_SOURCE_MEMBERSHIP:
        m_mc_memberships_map[mc_grp][mc_src] = 1;
        if (1 == m_mc_memberships_map[mc_grp].size()) {
            ++m_mc_num_grp_with_src_filter;
        }
        break;
    case IP_DROP_MEMBERSHIP:
        m_mc_memberships_map.erase(mc_grp);
        break;
    case IP_DROP_SOURCE_MEMBERSHIP:
        if ((m_mc_memberships_map.find(mc_grp) != m_mc_memberships_map.end())) {
            m_mc_memberships_map[mc_grp].erase(mc_src);
            if (0 == m_mc_memberships_map[mc_grp].size()) {
                m_mc_memberships_map.erase(mc_grp);
                --m_mc_num_grp_with_src_filter;
            }
        }
        break;
        BULLSEYE_EXCLUDE_BLOCK_START
    default:
        si_udp_logerr("setsockopt(%s) will be passed to OS for handling",
                      setsockopt_ip_opt_to_str(optname));
        return -1;
        BULLSEYE_EXCLUDE_BLOCK_END
    }

    return 0;
}

int sockinfo_udp::mc_change_membership_ip4(const mc_pending_pram *p_mc_pram)
{
    const ip_address &mc_grp = p_mc_pram->mc_grp.get_in4_addr();
    ip_address mc_if = p_mc_pram->mc_if.get_in4_addr();

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!mc_grp.is_mc(AF_INET)) {
        si_udp_logerr("%s for non multicast (%s)", setsockopt_ip_opt_to_str(p_mc_pram->optname),
                      mc_grp.to_str(AF_INET).c_str());
        return -1;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    sock_addr tmp_grp_addr(AF_INET, &mc_grp, m_bound.get_in_port());
    if (__xlio_match_udp_receiver(TRANS_XLIO, safe_mce_sys().app_id, tmp_grp_addr.get_p_sa(),
                                  tmp_grp_addr.get_socklen()) == TRANS_OS) {
        // Break so we call orig setsockopt() and don't try to offload
        si_udp_logdbg("setsockopt(%s) will be passed to OS for handling due to rule matching",
                      setsockopt_ip_opt_to_str(p_mc_pram->optname));
        return -1;
    }

    if (mc_if.is_anyaddr()) {
        resolve_if_ip(0, ip_address(mc_grp), mc_if);
    }

    // Check if local_if is offloadable
    if (!g_p_net_device_table_mgr->get_net_device_val(ip_addr(mc_if, AF_INET))) {
        // Break so we call orig setsockopt() and try to offlaod
        si_udp_logdbg(
            "setsockopt(%s) will be passed to OS for handling - not offload interface (%s)",
            setsockopt_ip_opt_to_str(p_mc_pram->optname), mc_if.to_str(AF_INET).c_str());
        return -1;
    }

    int pram_size = sizeof(ip_mreq);
    struct ip_mreq_source mreq_src;
    mreq_src.imr_multiaddr.s_addr = p_mc_pram->mc_grp.get_in4_addr().s_addr;
    mreq_src.imr_interface.s_addr = p_mc_pram->mc_if.get_in4_addr().s_addr;
    mreq_src.imr_sourceaddr.s_addr = p_mc_pram->mc_src.get_in4_addr().s_addr;

    switch (p_mc_pram->optname) {
    case IP_ADD_MEMBERSHIP: {
        if ((m_mc_memberships_map.find(mc_grp) != m_mc_memberships_map.end()) &&
            (0 < m_mc_memberships_map[mc_grp].size())) {
            return -1; // Same group with source filtering is already exist
        }

        // The address specified in bind() has a filtering role.
        // i.e. sockets should discard datagrams which sent to an unbound ip address.
        if (!m_bound.is_anyaddr() && mc_grp != m_bound.get_ip_addr()) {
            // Ignore for socketXtreme because m_bound is used as part of the legacy implementation
            if (!safe_mce_sys().enable_socketxtreme) {
                return -1; // Socket was bound to a different ip address
            }
        }

        flow_tuple_with_local_if flow_key(mc_grp, m_bound.get_in_port(), m_connected.get_ip_addr(),
                                          m_connected.get_in_port(), PROTO_UDP, AF_INET, mc_if);
        if (!attach_receiver(flow_key)) {
            // we will get RX from OS
            return -1;
        }
        xlio_stats_mc_group_add(mc_grp, m_p_socket_stats ?: nullptr);
        original_os_setsockopt_helper(&mreq_src, pram_size, p_mc_pram->optname, IPPROTO_IP);
        m_multicast = true;
        break;
    }
    case IP_ADD_SOURCE_MEMBERSHIP: {
        flow_tuple_with_local_if flow_key(mc_grp, m_bound.get_in_port(), ip_address::any_addr(), 0,
                                          PROTO_UDP, AF_INET, mc_if);
        if (!attach_receiver(flow_key)) {
            // we will get RX from OS
            return -1;
        }
        xlio_stats_mc_group_add(mc_grp, m_p_socket_stats ?: nullptr);
        pram_size = sizeof(ip_mreq_source);
        original_os_setsockopt_helper(&mreq_src, pram_size, p_mc_pram->optname, IPPROTO_IP);
        m_multicast = true;
        break;
    }
    case IP_DROP_MEMBERSHIP: {
        flow_tuple_with_local_if flow_key(mc_grp, m_bound.get_in_port(), m_connected.get_ip_addr(),
                                          m_connected.get_in_port(), PROTO_UDP, AF_INET, mc_if);
        original_os_setsockopt_helper(&mreq_src, pram_size, p_mc_pram->optname, IPPROTO_IP);
        if (!detach_receiver(flow_key)) {
            return -1;
        }
        xlio_stats_mc_group_remove(mc_grp, m_p_socket_stats ?: nullptr);
        m_multicast = false;
        break;
    }
    case IP_DROP_SOURCE_MEMBERSHIP: {
        flow_tuple_with_local_if flow_key(mc_grp, m_bound.get_in_port(), ip_address::any_addr(), 0,
                                          PROTO_UDP, AF_INET, mc_if);
        pram_size = sizeof(ip_mreq_source);
        original_os_setsockopt_helper(&mreq_src, pram_size, p_mc_pram->optname, IPPROTO_IP);
        if (1 == m_mc_memberships_map[mc_grp].size()) { // Last source in the group
            if (!detach_receiver(flow_key)) {
                return -1;
            }
            xlio_stats_mc_group_remove(mc_grp, m_p_socket_stats ?: nullptr);
            m_multicast = false; // get out from MC group
        }
        break;
    }
        BULLSEYE_EXCLUDE_BLOCK_START
    default:
        si_udp_logerr("setsockopt(%s) will be passed to OS for handling",
                      setsockopt_ip_opt_to_str(p_mc_pram->optname));
        return -1;
        BULLSEYE_EXCLUDE_BLOCK_END
    }

    return 0;
}

int sockinfo_udp::mc_change_membership_start_helper_ip6(const mc_pending_pram *p_mc_pram)
{
    int optname = p_mc_pram->optname;
    const ip_address &mc_grp = p_mc_pram->mc_grp;
    const ip_address &mc_src = p_mc_pram->mc_src;

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!mc_grp.is_mc(AF_INET6)) {
        si_udp_logdbg("%s, mc group is not a multicast address (%s)",
                      setsockopt_ip_opt_to_str(optname), mc_grp.to_str(AF_INET6).c_str());
        return -1;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    sock_addr tmp_grp_addr(m_family, &mc_grp, m_bound.get_in_port());
    if (__xlio_match_udp_receiver(TRANS_XLIO, safe_mce_sys().app_id, tmp_grp_addr.get_p_sa(),
                                  tmp_grp_addr.get_socklen()) == TRANS_OS) {
        // Break so we call orig setsockopt() and don't try to offload
        si_udp_logdbg("Not offloading due to rule matching");
        return -1;
    }

    bool group_exists = (m_mc_memberships_map.find(mc_grp) != m_mc_memberships_map.end());
    bool src_exists = group_exists
        ? (m_mc_memberships_map[mc_grp].find(mc_src) != m_mc_memberships_map[mc_grp].end())
        : false;

    switch (optname) {
    case IPV6_JOIN_GROUP:
    case MCAST_JOIN_GROUP:
        if (group_exists) {
            si_udp_logdbg("MC group already exists");
            errno = EINVAL;
            return -1;
        }

        // The address specified in bind() has a filtering role.
        // i.e. sockets should discard datagrams which sent to an unbound ip address.
        if (!m_bound.is_anyaddr() && mc_grp != m_bound.get_ip_addr()) {
            si_udp_logdbg("Bound address != MC group");
            errno = EINVAL;
            return -1;
        }
        break;
    case IPV6_LEAVE_GROUP:
    case MCAST_LEAVE_GROUP:
        if (!group_exists) {
            si_udp_logdbg("MC group doesn't exist");
            errno = EADDRNOTAVAIL;
            return -1;
        }
        break;
    case MCAST_JOIN_SOURCE_GROUP: {
        if (group_exists) {
            if (m_mc_memberships_map[mc_grp].size() >=
                (size_t)safe_mce_sys().sysctl_reader.get_mld_max_source_membership()) {
                errno = ENOBUFS;
                return -1;
            }
        }
    } break;
    case MCAST_LEAVE_SOURCE_GROUP:
        if (!src_exists || (m_mc_memberships_map[mc_grp][mc_src] == MCAST_EXCLUDE)) {
            si_udp_logdbg("Wrong source IP");
            errno = EADDRNOTAVAIL;
            return -1;
        }
        break;
    case MCAST_BLOCK_SOURCE: {
        return -1;
        /* TODO: bug #3202713
        open MCAST_BLOCK_SOURCE and MCAST_UNBLOCK_SOURCE
        requires a fix in drop packet logic - see bug #3202713 above
        size_t max_cap = is_ipv6 ?
        (size_t)safe_mce_sys().sysctl_reader.get_mld_max_source_membership() :
        (size_t)safe_mce_sys().sysctl_reader.get_igmp_max_source_membership(); if (group_exists
        && !src_exists) {
            if (m_mc_memberships_map[mc_grp].size() >= max_cap) {
                errno = ENOBUFS;
                return -1;
            }
        } else {
            return -1;
        } */
    } break;
    case MCAST_UNBLOCK_SOURCE:
        return -1;
        /* TODO: bug #3202713
        open MCAST_BLOCK_SOURCE and MCAST_UNBLOCK_SOURCE
        requires a fix in drop packet logic - see bug #3202713 above
        if (!src_exists || (m_mc_memberships_map[mc_grp][mc_src] == MCAST_INCLUDE)) {
            return -1;
        }
        break; */
        BULLSEYE_EXCLUDE_BLOCK_START
    default:
        si_udp_logerr("Invalid optname=%d (%s)", optname, setsockopt_ip_opt_to_str(optname));
        return -1;
        BULLSEYE_EXCLUDE_BLOCK_END
    }
    return 0;
}

int sockinfo_udp::mc_change_membership_end_helper_ip6(const mc_pending_pram *p_mc_pram)
{
    const ip_address &mc_grp = p_mc_pram->mc_grp;
    const ip_address &mc_src = p_mc_pram->mc_src;

    bool has_any_addr_src = (m_mc_memberships_map[mc_grp].find(ip_address::any_addr()) !=
                             m_mc_memberships_map[mc_grp].end());
    switch (p_mc_pram->optname) {
    case IPV6_JOIN_GROUP:
    case MCAST_JOIN_GROUP:
        m_mc_memberships_map[mc_grp][m_connected.get_ip_addr()] = MCAST_INCLUDE;
        break;
    case MCAST_JOIN_SOURCE_GROUP:
        m_mc_memberships_map[mc_grp][mc_src] = MCAST_INCLUDE;
        if (1 == (m_mc_memberships_map[mc_grp].size() - (size_t)has_any_addr_src)) {
            ++m_mc_num_grp_with_src_filter;
        }
        break;
    case IPV6_LEAVE_GROUP:
    case MCAST_LEAVE_GROUP:
        m_mc_memberships_map[mc_grp].erase(ip_address::any_addr());
        if (m_mc_memberships_map[mc_grp].size()) {
            --m_mc_num_grp_with_src_filter;
        }
        m_mc_memberships_map.erase(mc_grp);
        break;
        /* TODO: bug #3202713
            case MCAST_BLOCK_SOURCE:
                m_mc_memberships_map[mc_grp][mc_src] = MCAST_EXCLUDE;
                if (1 == (m_mc_memberships_map[mc_grp].size() - (size_t)has_any_addr_src)) {
                    ++m_mc_num_grp_with_src_filter;
                }
                break;

            case MCAST_UNBLOCK_SOURCE:
        */
    case MCAST_LEAVE_SOURCE_GROUP:
        m_mc_memberships_map[mc_grp].erase(mc_src);
        if (has_any_addr_src) {
            if (1 == m_mc_memberships_map[mc_grp].size()) {
                --m_mc_num_grp_with_src_filter;
            }
        } else {
            if (0 == m_mc_memberships_map[mc_grp].size()) {
                m_mc_memberships_map.erase(mc_grp);
                --m_mc_num_grp_with_src_filter;
            }
        }
        break;
        BULLSEYE_EXCLUDE_BLOCK_START
    default:
        si_udp_logerr("Invalid optname=%d (%s)", p_mc_pram->optname,
                      setsockopt_ip_opt_to_str(p_mc_pram->optname));
        return -1;
        BULLSEYE_EXCLUDE_BLOCK_END
    }

    // IFTAH - TODO: should not be depended on m_b_mc_tx_loop
    // See "Inspects multicast packets" flow
    m_multicast = (m_mc_memberships_map.size() > 0) ? true : !m_b_mc_tx_loop;
    return 0;
}

// Assume input correct - checked by mc_change_membership_start_helper
int sockinfo_udp::mc_change_membership_ip6(const mc_pending_pram *p_mc_pram)
{
    const ip_address &mc_grp = p_mc_pram->mc_grp;
    bool detach_anyway = false;

    flow_tuple_with_local_if flow_key(mc_grp, m_bound.get_in_port(), ip_address::any_addr(), 0,
                                      PROTO_UDP, m_family, p_mc_pram->mc_if);
    switch (p_mc_pram->optname) {
    case IPV6_JOIN_GROUP:
    case MCAST_JOIN_GROUP:
    case MCAST_JOIN_SOURCE_GROUP: {
        // TODO: fix bug - cant join 2 times for the same group iwth different sources
        // attach will fail. should be like:
        // attach_receiver only if its the first time for the mc_grp
        // if (m_mc_memberships_map.find(mc_grp) == m_mc_memberships_map.end()) {
        if (!attach_receiver(flow_key)) {
            // we will get RX from OS
            return -1;
        }
        xlio_stats_mc_group_add(mc_grp, m_p_socket_stats ?: nullptr);
        original_os_setsockopt_helper(&p_mc_pram->req, p_mc_pram->pram_size, p_mc_pram->optname,
                                      IPPROTO_IPV6);
    } break;
    case IPV6_LEAVE_GROUP:
    case MCAST_LEAVE_GROUP:
        detach_anyway = true; // operation for all sources
        // fallthrough
    case MCAST_LEAVE_SOURCE_GROUP: {
        original_os_setsockopt_helper(&p_mc_pram->req, p_mc_pram->pram_size, p_mc_pram->optname,
                                      IPPROTO_IPV6);
        if (detach_anyway ||
            // Last source in the group
            (1 == m_mc_memberships_map[mc_grp].size())) {
            if (!detach_receiver(flow_key)) {
                return -1;
            }
            xlio_stats_mc_group_remove(mc_grp, m_p_socket_stats ?: nullptr);
        }
        break;
    }
        BULLSEYE_EXCLUDE_BLOCK_START
    default:
        si_udp_logerr("Invalid optname=%d (%s)", p_mc_pram->optname,
                      setsockopt_ip_opt_to_str(p_mc_pram->optname));
        return -1;
        BULLSEYE_EXCLUDE_BLOCK_END
    }

    return 0;
}

void sockinfo_udp::original_os_setsockopt_helper(const void *pram, int pram_size, int optname,
                                                 int level)
{
    si_udp_logdbg("calling orig_setsockopt(%s) for igmp support by OS",
                  setsockopt_ip_opt_to_str(optname));
    if (SYSCALL(setsockopt, m_fd, level, optname, pram, pram_size)) {
        si_udp_logdbg("orig setsockopt(%s) failed (errno=%d %m)", setsockopt_ip_opt_to_str(optname),
                      errno);
    }
}

void sockinfo_udp::statistics_print(vlog_levels_t log_level /* = VLOG_DEBUG */)
{
    sockinfo::statistics_print(log_level);

    // Socket data
    vlog_printf(log_level, "Rx ready list size : %zu\n", m_rx_pkt_ready_list.size());

    vlog_printf(
        log_level, "Socket timestamp : m_b_rcvtstamp %s, m_b_rcvtstampns %s, m_n_tsing_flags %u\n",
        m_b_rcvtstamp ? "true" : "false", m_b_rcvtstampns ? "true" : "false", m_n_tsing_flags);
}

void sockinfo_udp::save_stats_threadid_rx()
{
    // Save Thread Id for statistics module
    if (g_vlogger_level >= VLOG_DEBUG) {
        IF_STATS(m_p_socket_stats->threadid_last_rx = gettid());
    }
}

void sockinfo_udp::save_stats_threadid_tx()
{
    // Save Thread Id for statistics module
    if (g_vlogger_level >= VLOG_DEBUG) {
        IF_STATS(m_p_socket_stats->threadid_last_tx = gettid());
    }
}

void sockinfo_udp::save_stats_tx_offload(int bytes, bool is_dummy)
{
    if (unlikely(m_p_socket_stats)) {
        if (unlikely(is_dummy)) {
            m_p_socket_stats->counters.n_tx_dummy++;
        } else {
            if (bytes >= 0) {
                m_p_socket_stats->counters.n_tx_sent_byte_count += bytes;
                m_p_socket_stats->counters.n_tx_sent_pkt_count++;
            } else if (errno == EAGAIN) {
                m_p_socket_stats->counters.n_rx_os_eagain++;
            } else {
                m_p_socket_stats->counters.n_tx_errors++;
            }
        }
    }
}

int sockinfo_udp::recvfrom_zcopy_free_packets(struct xlio_recvfrom_zcopy_packet_t *pkts,
                                              size_t count)
{
    int ret = 0;
    unsigned int index = 0;
    mem_buf_desc_t *buff;

    m_lock_rcv.lock();
    for (index = 0; index < count; index++) {
        buff = (mem_buf_desc_t *)pkts[index].packet_id;
        if (m_rx_ring_map.find(buff->p_desc_owner->get_parent()) == m_rx_ring_map.end()) {
            errno = ENOENT;
            ret = -1;
            break;
        }
        reuse_buffer(buff);
        IF_STATS(m_p_socket_stats->n_rx_zcopy_pkt_count--);
    }
    m_lock_rcv.unlock();
    return ret;
}

mem_buf_desc_t *sockinfo_udp::get_next_desc(mem_buf_desc_t *p_desc)
{
    return p_desc->p_next_desc;
}

mem_buf_desc_t *sockinfo_udp::get_next_desc_peek(mem_buf_desc_t *p_desc, int &rx_pkt_ready_list_idx)
{
    NOT_IN_USE(rx_pkt_ready_list_idx);
    return p_desc->p_next_desc;
}

timestamps_t *sockinfo_udp::get_socket_timestamps()
{
    if (unlikely(m_rx_pkt_ready_list.empty())) {
        si_udp_logdbg("m_rx_pkt_ready_list empty");
        return nullptr;
    }
    return &m_rx_pkt_ready_list.front()->rx.timestamps;
}

void sockinfo_udp::post_dequeue(bool release_buff)
{
    mem_buf_desc_t *to_resue = m_rx_pkt_ready_list.get_and_pop_front();
    IF_STATS(m_p_socket_stats->n_rx_ready_pkt_count--);
    m_n_rx_pkt_ready_list_count--;
    if (release_buff) {
        reuse_buffer(to_resue);
    }
    m_rx_pkt_ready_offset = 0;
}

int sockinfo_udp::zero_copy_rx(iovec *p_iov, mem_buf_desc_t *p_desc, int *p_flags)
{
    mem_buf_desc_t *p_desc_iter;
    int total_rx = 0;
    int len = p_iov[0].iov_len - sizeof(xlio_recvfrom_zcopy_packets_t) -
        sizeof(xlio_recvfrom_zcopy_packet_t);

    // Make sure there is enough room for the header
    if (len < 0) {
        errno = ENOBUFS;
        return -1;
    }

    // Copy iov pointers to user buffer
    xlio_recvfrom_zcopy_packets_t *p_packets = (xlio_recvfrom_zcopy_packets_t *)p_iov[0].iov_base;
    p_packets->n_packet_num = 1;
    p_packets->pkts[0].packet_id = (void *)p_desc;
    p_packets->pkts[0].sz_iov = 0;
    for (p_desc_iter = p_desc; p_desc_iter; p_desc_iter = p_desc_iter->p_next_desc) {
        len -= sizeof(p_packets->pkts[0].iov[0]);
        if (len < 0) {
            *p_flags = MSG_TRUNC;
            break;
        }
        p_packets->pkts[0].iov[p_packets->pkts[0].sz_iov++] = p_desc_iter->rx.frag;
        total_rx += p_desc_iter->rx.frag.iov_len;
    }

    IF_STATS(m_p_socket_stats->n_rx_zcopy_pkt_count++);

    si_udp_logfunc("copied pointers to %d bytes to user buffer", total_rx);
    return total_rx;
}

size_t sockinfo_udp::handle_msg_trunc(size_t total_rx, size_t payload_size, int in_flags,
                                      int *p_out_flags)
{
    if (payload_size > total_rx) {
        m_rx_ready_byte_count -= (payload_size - total_rx);
        IF_STATS(m_p_socket_stats->n_rx_ready_byte_count -= (payload_size - total_rx));
        *p_out_flags |= MSG_TRUNC;
        if (in_flags & MSG_TRUNC) {
            return payload_size;
        }
    }

    return total_rx;
}

mem_buf_desc_t *sockinfo_udp::get_front_m_rx_pkt_ready_list()
{
    return m_rx_pkt_ready_list.front();
}

size_t sockinfo_udp::get_size_m_rx_pkt_ready_list()
{
    return m_rx_pkt_ready_list.size();
}

void sockinfo_udp::pop_front_m_rx_pkt_ready_list()
{
    m_rx_pkt_ready_list.pop_front();
}

void sockinfo_udp::push_back_m_rx_pkt_ready_list(mem_buf_desc_t *buff)
{
    m_rx_pkt_ready_list.push_back(buff);
}

bool sockinfo_udp::prepare_to_close(bool process_shutdown)
{
    m_lock_rcv.lock();
    m_sock_wakeup_pipe.do_wakeup();

    if (has_epoll_context()) {
        m_econtext->fd_closed(m_fd);
    }

    m_lock_rcv.unlock();

    NOT_IN_USE(process_shutdown);
    m_state = SOCKINFO_CLOSING;
    return is_closable();
}

void sockinfo_udp::update_header_field(data_updater *updater)
{
    dst_entry_map_t::iterator dst_entry_iter = m_dst_entry_map.begin();
    for (; dst_entry_iter != m_dst_entry_map.end(); dst_entry_iter++) {
        updater->update_field(*dst_entry_iter->second);
    }
    if (m_p_connected_dst_entry) {
        updater->update_field(*m_p_connected_dst_entry);
    }
}

#if defined(DEFINED_NGINX)
void sockinfo_udp::prepare_to_close_socket_pool(bool _push_pop)
{
    if (_push_pop) {
        /* we move to SOCKINFO_DESTROYING because
         * 1. in every socket API call we check that state.
         *    it will allow us to maintain most of socket API correct while we skip socket closure
         * 2. SOCKINFO_DESTROYING state will discard packets in rx_input_cb
         */
        m_state = SOCKINFO_DESTROYING;
        drop_rx_ready_byte_count(0);
    } else {
        m_state = SOCKINFO_OPENED;
    }
}
#endif
