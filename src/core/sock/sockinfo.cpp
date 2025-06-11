/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "sockinfo.h"

#include <sys/epoll.h>
#include <netdb.h>
#include <linux/sockios.h>
#include <cinttypes>

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "util/if.h"
#include "proto/route_table_mgr.h"
#include "sock-redirect.h"
#include "fd_collection.h"
#include "dev/ring_simple.h"

#define MODULE_NAME "si"
#undef MODULE_HDR_INFO
#define MODULE_HDR_INFO MODULE_NAME "[fd=%d]:%d:%s() "
#undef __INFO__
#define __INFO__ m_fd

#define si_logpanic   __log_info_panic
#define si_logerr     __log_info_err
#define si_logwarn    __log_info_warn
#define si_loginfo    __log_info_info
#define si_logdbg     __log_info_dbg
#define si_logfunc    __log_info_func
#define si_logfuncall __log_info_funcall

const char *sockinfo::setsockopt_so_opt_to_str(int opt)
{
    switch (opt) {
    case SO_REUSEADDR:
        return "SO_REUSEADDR";
    case SO_REUSEPORT:
        return "SO_REUSEPORT";
    case SO_BROADCAST:
        return "SO_BROADCAST";
    case SO_RCVBUF:
        return "SO_RCVBUF";
    case SO_SNDBUF:
        return "SO_SNDBUF";
    case SO_TIMESTAMP:
        return "SO_TIMESTAMP";
    case SO_TIMESTAMPNS:
        return "SO_TIMESTAMPNS";
    case SO_BINDTODEVICE:
        return "SO_BINDTODEVICE";
    case SO_ZEROCOPY:
        return "SO_ZEROCOPY";
    case SO_XLIO_RING_ALLOC_LOGIC:
        return "SO_XLIO_RING_ALLOC_LOGIC";
    case SO_MAX_PACING_RATE:
        return "SO_MAX_PACING_RATE";
    case SO_XLIO_SHUTDOWN_RX:
        return "SO_XLIO_SHUTDOWN_RX";
    case IPV6_V6ONLY:
        return "IPV6_V6ONLY";
    case IPV6_ADDR_PREFERENCES:
        return "IPV6_ADDR_PREFERENCES";
    default:
        break;
    }
    return "UNKNOWN SO opt";
}

sockinfo::sockinfo(int fd, int domain, bool use_ring_locks)
    : m_skip_cq_poll_in_rx(safe_mce_sys().skip_poll_in_rx == SKIP_POLL_IN_RX_ENABLE)
    , m_family(domain)
    , m_fd(fd)
    , m_rx_num_buffs_reuse(safe_mce_sys().rx_bufs_batch)
    , m_is_ipv6only(safe_mce_sys().sysctl_reader.get_ipv6_bindv6only())
    , m_n_uc_ttl_hop_lim(m_family == AF_INET
                             ? safe_mce_sys().sysctl_reader.get_net_ipv4_ttl()
                             : safe_mce_sys().sysctl_reader.get_net_ipv6_hop_limit())
    , m_lock_rcv(MULTILOCK_RECURSIVE, MODULE_NAME "::m_lock_rcv")
    , m_lock_snd(MODULE_NAME "::m_lock_snd")
    , m_so_bindtodevice_ip(ip_address::any_addr(), domain)
    , m_rx_ring_map_lock(MODULE_NAME "::m_rx_ring_map_lock")
    , m_ring_alloc_log_rx(safe_mce_sys().ring_allocation_logic_rx, use_ring_locks)
    , m_ring_alloc_log_tx(safe_mce_sys().ring_allocation_logic_tx, use_ring_locks)
{
    m_rx_epfd = SYSCALL(epoll_create, 128);
    if (unlikely(m_rx_epfd == -1)) {
        throw_xlio_exception("create internal epoll");
    }
    m_sock_wakeup_pipe.wakeup_set_epoll_fd(m_rx_epfd);
    if (m_fd == SOCKET_FAKE_FD) {
        m_fd = m_rx_epfd;
    }

    m_ring_alloc_logic_rx = ring_allocation_logic_rx(get_fd(), m_ring_alloc_log_rx);

    socket_stats_init();

    m_rx_reuse_buff.n_buff_num = 0;
    memset(&m_so_ratelimit, 0, sizeof(xlio_rate_limit_t));
    set_flow_tag(m_fd + 1);

    m_connected.set_sa_family(m_family);
    m_bound.set_sa_family(m_family);
}

/**
 * @brief Destructor for sockinfo class
 *
 * Cleans up all resources associated with the sockinfo object
 *
 * @note The coverity[UNCAUGHT_EXCEPT] was added as it's a False Positive
 */
// coverity[UNCAUGHT_EXCEPT]
sockinfo::~sockinfo()
{
    m_state = SOCKINFO_DESTROYING;

    if (!sockinfo::is_shadow_socket_present()) {
        // Don't let other destructors know about substituted fd
        m_fd = -1;
    }

    // Change to non-blocking socket so calling threads can exit
    m_b_blocking = false;
    if (m_rx_epfd != -1) {
        // This will wake up any blocked thread in rx() call to SYSCALL(epoll_wait, )
        SYSCALL(close, m_rx_epfd);
    }

    if (m_p_socket_stats) {
        xlio_stats_instance_remove_socket_block(m_p_socket_stats);
        sock_stats::instance().return_stats_obj(m_p_socket_stats);
    }

    bool toclose = (safe_mce_sys().deferred_close || is_xlio_socket()) && m_fd >= 0;

#if defined(DEFINED_NGINX)
    if (g_p_app->type == APP_NGINX) {
        // Sockets from a socket pool are not closed during close(), so do it now.
        toclose = toclose || (m_is_for_socket_pool && m_fd >= 0);
    }
#endif

    if (toclose) {
        int rc = SYSCALL(close, m_fd);
        if (rc != 0) {
            si_logdbg("close(fd=%d) failed with errno=%d", m_fd, errno);
        }
    }
}

void sockinfo::socket_stats_init()
{
    if (!m_p_socket_stats) { // This check is for listen sockets.
        m_p_socket_stats = sock_stats::instance().get_stats_obj();
        if (!m_p_socket_stats) {
            return;
        }

        // Save stats as local copy and allow state publisher to copy from this location
        xlio_stats_instance_create_socket_block(m_p_socket_stats);
    }

    m_p_socket_stats->reset();
    m_p_socket_stats->fd = m_fd;
    m_p_socket_stats->inode = fd2inode(m_fd);
    m_p_socket_stats->b_blocking = m_b_blocking;
    m_p_socket_stats->ring_alloc_logic_rx = m_ring_alloc_log_rx.get_ring_alloc_logic();
    m_p_socket_stats->ring_alloc_logic_tx = m_ring_alloc_log_tx.get_ring_alloc_logic();
    m_p_socket_stats->ring_user_id_rx = m_ring_alloc_logic_rx.calc_res_key_by_logic();
    m_p_socket_stats->ring_user_id_tx =
        ring_allocation_logic_tx(get_fd(), m_ring_alloc_log_tx).calc_res_key_by_logic();
    m_p_socket_stats->sa_family = m_family;
}

void sockinfo::set_blocking(bool is_blocked)
{
    si_logdbg("set socket to %s mode", is_blocked ? "blocked" : "non-blocking");
    m_b_blocking = is_blocked;
    IF_STATS(m_p_socket_stats->b_blocking = m_b_blocking);
}

int sockinfo::fcntl_helper(int __cmd, unsigned long int __arg, bool &bexit)
{
    int rc = 0;

    // Avoid fcntl(2) syscall if shadow socket is not present.
    bexit = !is_shadow_socket_present();

    switch (__cmd) {
    case F_SETFL: // Set file status flags.
        si_logdbg("cmd=F_SETFL, arg=%#lx", __arg);
        set_blocking(!(__arg & O_NONBLOCK));
        break;
    case F_GETFL: // Get file status flags.
        si_logfunc("cmd=F_GETFL, arg=%#x", __arg);
        rc = O_NONBLOCK * !m_b_blocking;
        break;

    case F_GETFD: // Get file descriptor flags.
        si_logfunc("cmd=F_GETFD, arg=%#x", __arg);
        break;
    case F_SETFD: // Set file descriptor flags.
        si_logfunc("cmd=F_SETFD, arg=%#x", __arg);
        break;

    default:
        char buf[128];
        snprintf(buf, sizeof(buf), "unimplemented fcntl cmd=%#x, arg=%#x", (unsigned)__cmd,
                 (unsigned)__arg);
        buf[sizeof(buf) - 1] = '\0';

        VLOG_PRINTF_INFO(safe_mce_sys().exception_handling.get_log_severity(), "%s", buf);
        rc = handle_exception_flow();
        switch (rc) {
        case 0:
            if (!is_shadow_socket_present()) {
                errno = ENOTSUP;
                rc = -1;
            }
            break;
        case -1:
            bexit = true;
            break;
        case -2:
            bexit = true;
            xlio_throw_object_with_msg(xlio_unsupported_api, buf);
        }
        break;
    }
    return rc;
}

int sockinfo::fcntl(int __cmd, unsigned long int __arg)
{
    bool bexit = false;
    int ret_val = fcntl_helper(__cmd, __arg, bexit);
    if (bexit) {
        return ret_val;
    }

    si_logdbg("going to OS for fcntl cmd=%d, arg=%#lx", __cmd, __arg);
    return SYSCALL(fcntl, m_fd, __cmd, __arg);
}

int sockinfo::fcntl64(int __cmd, unsigned long int __arg)
{
    bool bexit = false;
    int ret_val = fcntl_helper(__cmd, __arg, bexit);
    if (bexit) {
        return ret_val;
    }

    si_logdbg("going to OS for fcntl64 cmd=%d, arg=%#lx", __cmd, __arg);
    return SYSCALL(fcntl64, m_fd, __cmd, __arg);
}

int sockinfo::get_epoll_context_fd()
{
    return (has_epoll_context() ? m_econtext->get_epoll_fd() : 0);
}

void sockinfo::insert_epoll_event(uint64_t events)
{
    if (has_epoll_context()) {
        m_econtext->insert_epoll_event_cb(this, static_cast<uint32_t>(events));
    }
}

int sockinfo::set_ring_attr(xlio_ring_alloc_logic_attr *attr)
{
    if ((attr->comp_mask & XLIO_RING_ALLOC_MASK_RING_ENGRESS) && attr->engress) {
        if (set_ring_attr_helper(&m_ring_alloc_log_tx, attr)) {
            return SOCKOPT_NO_XLIO_SUPPORT;
        }
        ring_alloc_logic_updater du(get_fd(), m_lock_snd, m_ring_alloc_log_tx, m_p_socket_stats);
        update_header_field(&du);
        if (m_p_socket_stats) {
            m_p_socket_stats->ring_alloc_logic_tx = m_ring_alloc_log_tx.get_ring_alloc_logic();
            m_p_socket_stats->ring_user_id_tx =
                ring_allocation_logic_tx(get_fd(), m_ring_alloc_log_tx).calc_res_key_by_logic();
        }
    }
    if ((attr->comp_mask & XLIO_RING_ALLOC_MASK_RING_INGRESS) && attr->ingress) {
        ring_alloc_logic_attr old_key(*m_ring_alloc_logic_rx.get_key());

        if (set_ring_attr_helper(&m_ring_alloc_log_rx, attr)) {
            return SOCKOPT_NO_XLIO_SUPPORT;
        }
        m_ring_alloc_logic_rx = ring_allocation_logic_rx(get_fd(), m_ring_alloc_log_rx);

        if (m_rx_nd_map.size()) {
            std::lock_guard<decltype(m_rx_migration_lock)> locker(m_rx_migration_lock);
            do_rings_migration_rx(old_key);
        }

        if (m_p_socket_stats) {
            m_p_socket_stats->ring_alloc_logic_rx = m_ring_alloc_log_rx.get_ring_alloc_logic();
            m_p_socket_stats->ring_user_id_rx = m_ring_alloc_logic_rx.calc_res_key_by_logic();
        }
    }

    return SOCKOPT_INTERNAL_XLIO_SUPPORT;
}

int sockinfo::set_ring_attr_helper(ring_alloc_logic_attr *sock_attr,
                                   xlio_ring_alloc_logic_attr *user_attr)
{
    sock_attr->set_ring_alloc_logic(user_attr->ring_alloc_logic);

    if (user_attr->comp_mask & XLIO_RING_ALLOC_MASK_RING_USER_ID) {
        sock_attr->set_user_id_key(user_attr->user_id);
    }

    return 0;
}

void sockinfo::set_ring_logic_rx(ring_alloc_logic_attr ral)
{
    if (m_rx_ring_map.empty()) {
        m_ring_alloc_log_rx = ral;
        m_ring_alloc_logic_rx = ring_allocation_logic_rx(get_fd(), m_ring_alloc_log_rx);
        if (m_p_socket_stats) {
            m_p_socket_stats->ring_alloc_logic_rx = m_ring_alloc_log_rx.get_ring_alloc_logic();
            m_p_socket_stats->ring_user_id_rx = m_ring_alloc_logic_rx.calc_res_key_by_logic();
        }
    }
}

void sockinfo::set_ring_logic_tx(ring_alloc_logic_attr ral)
{
    if (!m_p_connected_dst_entry) {
        m_ring_alloc_log_tx = ral;
        if (m_p_socket_stats) {
            m_p_socket_stats->ring_alloc_logic_tx = m_ring_alloc_log_tx.get_ring_alloc_logic();
            m_p_socket_stats->ring_user_id_tx =
                ring_allocation_logic_tx(get_fd(), m_ring_alloc_log_tx).calc_res_key_by_logic();
        }
    }
}

int sockinfo::ioctl(unsigned long int __request, unsigned long int __arg)
{
    int *p_arg = (int *)__arg;
    int rc = 0;
    bool supported = false;

    switch (__request) {
    case FIONBIO:
        si_logdbg("request=FIONBIO, arg=%d", *p_arg);
        set_blocking(!(*p_arg));
        supported = true;
        break;
    case FIONREAD:
        si_logfunc("request=FIONREAD, arg=%d", *p_arg);
        rc = rx_verify_available_data();
        if (rc >= 0) {
            *p_arg = rc;
            return 0;
        }
        return rc;
    case SIOCGIFVLAN: /* prevent error print */
        break;
    default:
        char buf[128];
        snprintf(buf, sizeof(buf), "unimplemented ioctl request=%#x, flags=%#x",
                 (unsigned)__request, (unsigned)__arg);
        buf[sizeof(buf) - 1] = '\0';

        VLOG_PRINTF_INFO(safe_mce_sys().exception_handling.get_log_severity(), "%s", buf);
        rc = handle_exception_flow();
        switch (rc) {
        case -1:
            return rc;
        case -2:
            xlio_throw_object_with_msg(xlio_unsupported_api, buf);
        }
        break;
    }

    if (!is_shadow_socket_present()) {
        // Avoid ioctl(2) syscall is shadow socket is not present.
        errno = supported ? errno : ENOTSUP;
        return supported ? rc : -1;
    }

    si_logdbg("going to OS for ioctl request=%lu, flags=%#lx", __request, __arg);
    return SYSCALL(ioctl, m_fd, __request, __arg);
}

int sockinfo::setsockopt(int __level, int __optname, const void *__optval, socklen_t __optlen)
{
    size_t expected_len = 0U;
    int ret = SOCKOPT_PASS_TO_OS;

    if (__level == SOL_SOCKET) {
        switch (__optname) {
        case SO_REUSEADDR:
            if (__optval && __optlen == sizeof(int)) {
                m_reuseaddr = *(int *)__optval;
                si_logdbg("SOL_SOCKET, %s=%s", setsockopt_so_opt_to_str(__optname),
                          (m_reuseaddr ? "true" : "false"));
            } else {
                errno = EINVAL;
                ret = SOCKOPT_NO_XLIO_SUPPORT;
            }
            break;

        case SO_REUSEPORT:
            if (__optval && __optlen == sizeof(int)) {
                m_reuseport = *(bool *)__optval;
                si_logdbg("SOL_SOCKET, %s=%s", setsockopt_so_opt_to_str(__optname),
                          (m_reuseport ? "true" : "false"));
            } else {
                errno = EINVAL;
                ret = SOCKOPT_NO_XLIO_SUPPORT;
            }
            break;

        case SO_TIMESTAMP:
        case SO_TIMESTAMPNS:
            if (__optval) {
                m_b_rcvtstamp = *(bool *)__optval;
                if (__optname == SO_TIMESTAMPNS) {
                    m_b_rcvtstampns = m_b_rcvtstamp;
                }
                si_logdbg("SOL_SOCKET, %s=%s", setsockopt_so_opt_to_str(__optname),
                          (m_b_rcvtstamp ? "true" : "false"));
            } else {
                si_logdbg("SOL_SOCKET, %s=\"???\" - NOT HANDLED, optval == NULL",
                          setsockopt_so_opt_to_str(__optname));
            }
            break;

        case SO_TIMESTAMPING:
            if (__optval) {
                uint8_t val = *(uint8_t *)__optval;

                // SOF_TIMESTAMPING_TX_SOFTWARE and SOF_TIMESTAMPING_TX_HARDWARE is NOT supported.
                if (val & (SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_TX_HARDWARE)) {
                    ret = SOCKOPT_NO_XLIO_SUPPORT;
                    errno = EOPNOTSUPP;
                    si_logdbg(
                        "SOL_SOCKET, SOF_TIMESTAMPING_TX_SOFTWARE and SOF_TIMESTAMPING_TX_HARDWARE "
                        "is not supported, errno set to EOPNOTSUPP");
                }

                if (val & (SOF_TIMESTAMPING_RAW_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE)) {
                    if (g_p_net_device_table_mgr->get_ctx_time_conversion_mode() ==
                        TS_CONVERSION_MODE_DISABLE) {
                        if (safe_mce_sys().hw_ts_conversion_mode == TS_CONVERSION_MODE_DISABLE) {
                            ret = SOCKOPT_NO_XLIO_SUPPORT;
                            errno = EPERM;
                            si_logdbg("SOL_SOCKET, SOF_TIMESTAMPING_RAW_HARDWARE and "
                                      "SOF_TIMESTAMPING_RX_HARDWARE socket options were disabled "
                                      "(XLIO_HW_TS_CONVERSION = %d) , errno set to EPERM",
                                      TS_CONVERSION_MODE_DISABLE);
                        } else {
                            ret = SOCKOPT_NO_XLIO_SUPPORT;
                            errno = ENODEV;
                            si_logdbg("SOL_SOCKET, SOF_TIMESTAMPING_RAW_HARDWARE and "
                                      "SOF_TIMESTAMPING_RX_HARDWARE is not supported by device(s), "
                                      "errno set to ENODEV");
                        }
                    }
                }

                m_n_tsing_flags = val;
                si_logdbg("SOL_SOCKET, SO_TIMESTAMPING=%u", m_n_tsing_flags);
            } else {
                si_logdbg("SOL_SOCKET, %s=\"???\" - NOT HANDLED, optval == NULL",
                          setsockopt_so_opt_to_str(__optname));
            }
            break;
        case SO_XLIO_RING_ALLOC_LOGIC:
            if (__optval) {
                uint32_t val = ((xlio_ring_alloc_logic_attr *)__optval)->comp_mask;

                if (val &
                    (XLIO_RING_ALLOC_MASK_RING_USER_ID | XLIO_RING_ALLOC_MASK_RING_INGRESS |
                     XLIO_RING_ALLOC_MASK_RING_ENGRESS)) {
                    if (__optlen == sizeof(xlio_ring_alloc_logic_attr)) {
                        xlio_ring_alloc_logic_attr *attr = (xlio_ring_alloc_logic_attr *)__optval;
                        return set_ring_attr(attr);
                    } else {
                        ret = SOCKOPT_NO_XLIO_SUPPORT;
                        errno = EINVAL;
                        si_logdbg("SOL_SOCKET, %s=\"???\" - bad length expected %zu got %d",
                                  setsockopt_so_opt_to_str(__optname),
                                  sizeof(xlio_ring_alloc_logic_attr), __optlen);
                        break;
                    }
                } else {
                    ret = SOCKOPT_NO_XLIO_SUPPORT;
                    errno = EINVAL;
                    si_logdbg("SOL_SOCKET, %s=\"???\" - bad optval (%d)",
                              setsockopt_so_opt_to_str(__optname), val);
                }
            } else {
                ret = SOCKOPT_NO_XLIO_SUPPORT;
                errno = EINVAL;
                si_logdbg("SOL_SOCKET, %s=\"???\" - NOT HANDLED, optval == NULL",
                          setsockopt_so_opt_to_str(__optname));
            }
            break;
        case SO_XLIO_SHUTDOWN_RX:
            shutdown_rx();
            ret = SOCKOPT_INTERNAL_XLIO_SUPPORT;
            break;
        default:
            break;
        }
    } else if (__level == IPPROTO_IP) {
        switch (__optname) {
        case IP_TTL:
            if (__optlen < sizeof(m_n_uc_ttl_hop_lim)) {
                ret = SOCKOPT_NO_XLIO_SUPPORT;
                errno = EINVAL;
            } else {
                int val = __optlen < sizeof(val) ? (uint8_t) * (uint8_t *)__optval
                                                 : (int)*(int *)__optval;
                if (val != -1 && (val < 1 || val > 255)) {
                    ret = SOCKOPT_NO_XLIO_SUPPORT;
                    errno = EINVAL;
                } else {
                    m_n_uc_ttl_hop_lim = (val == -1)
                        ? safe_mce_sys().sysctl_reader.get_net_ipv4_ttl()
                        : (uint8_t)val;
                    header_ttl_hop_limit_updater du(m_n_uc_ttl_hop_lim, false);
                    update_header_field(&du);
                    si_logdbg("IPPROTO_IP, optname=IP_TTL (%d)", m_n_uc_ttl_hop_lim);
                }
            }
            break;
        case IP_BIND_ADDRESS_NO_PORT: {
            if (__optval && __optlen == sizeof(int)) {
                int val = *(int *)__optval;
                m_bind_no_port = !!val;
                // In TCP connect flow we don't call os.connect, as oposed to UDP connect flow.
                // Therefore, UDP flow can support IP_BIND_ADDRESS_NO_PORT out-of-box using kernel
                // calls.
                ret = (PROTO_TCP == get_protocol()) ? SOCKOPT_INTERNAL_XLIO_SUPPORT
                                                    : SOCKOPT_HANDLE_BY_OS;
                break;
            }
            ret = SOCKOPT_NO_XLIO_SUPPORT;
            errno = EINVAL;
            si_logdbg("IP_BIND_ADDRESS_NO_PORT - NOT HANDLED, optval or optlen are not valid");
            break;
        }
        default:
            break;
        }
    } else if (__level == IPPROTO_IPV6) {
        switch (__optname) {
        case IPV6_V6ONLY:
            ret = SOCKOPT_NO_XLIO_SUPPORT;
            expected_len = sizeof(int);
            if (__optval && __optlen == expected_len) {
                m_is_ipv6only = (*reinterpret_cast<const int *>(__optval) != 0);
                ret = SOCKOPT_HANDLE_BY_OS;
                si_logdbg("IPV6_V6ONLY, set to %d", m_is_ipv6only ? 1 : 0);
            }
            break;
        case IPV6_ADDR_PREFERENCES:
            ret = SOCKOPT_NO_XLIO_SUPPORT;
            expected_len = sizeof(int);
            if (__optval && __optlen == expected_len) {
                int val = *reinterpret_cast<const int *>(__optval);
                if (ipv6_set_addr_sel_pref(val)) {
                    ret = SOCKOPT_INTERNAL_XLIO_SUPPORT;
                    si_logdbg("IPV6_ADDR_PREFERENCES, val %d, src-sel-flags %" PRIu8, val,
                              m_src_sel_flags);
                }
            }
        default:
            break;
        }

        if (ret == SOCKOPT_NO_XLIO_SUPPORT) {
            errno = EINVAL;
            si_logdbg("%s, invalid value/length arguments. val %p, len %zu, expected-len %zu",
                      setsockopt_so_opt_to_str(__optname), __optval, static_cast<size_t>(__optlen),
                      expected_len);
        }
    }

    si_logdbg("ret (%d)", ret);
    return ret;
}

bool sockinfo::ipv6_set_addr_sel_pref(int val)
{
    unsigned int pref = 0;
    unsigned int prefmask = ~0;

    // Check PUBLIC/TMP/PUBTMP_DEFAULT conflicts
    int check_mask =
        (IPV6_PREFER_SRC_PUBLIC | IPV6_PREFER_SRC_TMP | IPV6_PREFER_SRC_PUBTMP_DEFAULT);
    switch (val & check_mask) {
    case IPV6_PREFER_SRC_PUBLIC:
        pref |= IPV6_PREFER_SRC_PUBLIC;
        prefmask &= ~(IPV6_PREFER_SRC_TMP);
        break;
    case IPV6_PREFER_SRC_TMP:
        pref |= IPV6_PREFER_SRC_TMP;
        prefmask &= ~(IPV6_PREFER_SRC_PUBLIC);
        break;
    case IPV6_PREFER_SRC_PUBTMP_DEFAULT:
        prefmask &= ~(IPV6_PREFER_SRC_PUBLIC | IPV6_PREFER_SRC_TMP);
        break;
    case 0:
        break;
    default:
        return false;
    }

    // Check HOME/COA conflicts
    check_mask = (IPV6_PREFER_SRC_HOME | IPV6_PREFER_SRC_COA);
    switch (val & check_mask) {
    case IPV6_PREFER_SRC_HOME:
        prefmask &= ~IPV6_PREFER_SRC_COA;
        break;
    case IPV6_PREFER_SRC_COA:
        pref |= IPV6_PREFER_SRC_COA;
        break;
    case 0:
        break;
    default:
        return false;
    }

    // Check CGA/NONCGA conflicts
    check_mask = (IPV6_PREFER_SRC_CGA | IPV6_PREFER_SRC_NONCGA);
    switch (val & check_mask) {
    case IPV6_PREFER_SRC_CGA:
    case IPV6_PREFER_SRC_NONCGA:
    case 0:
        break;
    default:
        return false;
    }

    m_src_sel_flags = static_cast<uint8_t>((m_src_sel_flags & prefmask) | pref);
    return true;
}

int sockinfo::ipv6_get_addr_sel_pref()
{
    int val = static_cast<int>(m_src_sel_flags);

    if (!(m_src_sel_flags & (IPV6_PREFER_SRC_TMP | IPV6_PREFER_SRC_PUBLIC))) {
        val |= IPV6_PREFER_SRC_PUBTMP_DEFAULT;
    }

    if (!(m_src_sel_flags & IPV6_PREFER_SRC_COA)) {
        val |= IPV6_PREFER_SRC_HOME;
    }

    return val;
}

int sockinfo::getsockopt(int __level, int __optname, void *__optval, socklen_t *__optlen)
{
    size_t expected_len = 0;
    int ret = -1;
    if (!__optlen || !__optval) {
        errno = EINVAL;
        return ret;
    }

    switch (__level) {
    case SOL_SOCKET:
        switch (__optname) {
        case SO_MAX_PACING_RATE:
            if (*__optlen == sizeof(struct xlio_rate_limit_t)) {
                *(struct xlio_rate_limit_t *)__optval = m_so_ratelimit;
                *__optlen = sizeof(struct xlio_rate_limit_t);
                si_logdbg("(SO_MAX_PACING_RATE) value: %d, %d, %d",
                          (*(struct xlio_rate_limit_t *)__optval).rate,
                          (*(struct xlio_rate_limit_t *)__optval).max_burst_sz,
                          (*(struct xlio_rate_limit_t *)__optval).typical_pkt_sz);
            } else if (*__optlen == sizeof(uint32_t)) {
                *(uint32_t *)__optval = KB_TO_BYTE(m_so_ratelimit.rate);
                *__optlen = sizeof(uint32_t);
                si_logdbg("(SO_MAX_PACING_RATE) value: %d", *(int *)__optval);
                ret = 0;
            } else {
                errno = EINVAL;
            }
            break;
        default:
            break;
        }
        break;
    case IPPROTO_IPV6: {
        switch (__optname) {
        case IPV6_V6ONLY:
            ret = SOCKOPT_NO_XLIO_SUPPORT;
            expected_len = sizeof(int);
            if (*__optlen == expected_len) {
                *reinterpret_cast<int *>(__optval) = (m_is_ipv6only ? 1 : 0);
                ret = 0;
                si_logerr("IPV6_V6ONLY, value is %d", m_is_ipv6only ? 1 : 0);
            }
            break;
        case IPV6_ADDR_PREFERENCES:
            ret = SOCKOPT_NO_XLIO_SUPPORT;
            expected_len = sizeof(int);
            if (*__optlen == expected_len) {
                int *valptr = reinterpret_cast<int *>(__optval);
                *valptr = ipv6_get_addr_sel_pref();
                ret = 0;
                si_logerr("IPV6_ADDR_PREFERENCES, value is %d", *valptr);
            }
        default:
            break;
        }

        if (ret == SOCKOPT_NO_XLIO_SUPPORT) {
            errno = EINVAL;
            si_logdbg("%s, invalid value/length arguments. val %p, len %zu, expected-len %zu",
                      setsockopt_so_opt_to_str(__optname), __optval, static_cast<size_t>(*__optlen),
                      expected_len);
        }

        break;
    }
    default:
        break;
    }

    return ret;
}

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
void sockinfo::copy_sockopt_fork(const sockinfo *copy_from)
{
    const sockinfo *skinfo = dynamic_cast<const sockinfo *>(copy_from);
    if (skinfo) {
        m_is_ipv6only = skinfo->m_is_ipv6only;
        m_back_log = skinfo->m_back_log;
    }
}
#endif

////////////////////////////////////////////////////////////////////////////////
bool sockinfo::try_un_offloading() // un-offload the socket if possible
{
    if (!isPassthrough() && is_shadow_socket_present()) {
        setPassthrough();
        if (isPassthrough()) {
            si_logdbg("Socket is unoffloaded");
        }
    }
    return true;
}

////////////////////////////////////////////////////////////////////////////////
int sockinfo::get_sock_by_L3_L4(in_protocol_t protocol, const ip_address &ip, in_port_t port)
{
    assert(g_p_fd_collection);
    int map_size = g_p_fd_collection->get_fd_map_size();
    for (int i = 0; i < map_size; i++) {
        sockinfo *p_sock_i = g_p_fd_collection->get_sockfd(i);
        if (!p_sock_i || p_sock_i->get_type() != FD_TYPE_SOCKET) {
            continue;
        }
        sockinfo *s = (sockinfo *)p_sock_i;
        if (protocol == s->m_protocol && ip == s->m_bound.get_ip_addr() &&
            port == s->m_bound.get_in_port()) {
            return i;
        }
    }
    return -1;
}

void sockinfo::save_stats_rx_offload(int nbytes)
{
    if (unlikely(m_p_socket_stats) && nbytes < 0) {
        if (errno == EAGAIN) {
            m_p_socket_stats->counters.n_rx_eagain++;
        } else {
            m_p_socket_stats->counters.n_rx_errors++;
        }
    }
}

void sockinfo::save_stats_rx_os(int bytes)
{
    if (m_p_socket_stats) {
        if (bytes >= 0) {
            m_p_socket_stats->counters.n_rx_os_bytes += bytes;
            m_p_socket_stats->counters.n_rx_os_packets++;
        } else if (errno == EAGAIN) {
            m_p_socket_stats->counters.n_rx_os_eagain++;
        } else {
            m_p_socket_stats->counters.n_rx_os_errors++;
        }
    }
}

void sockinfo::save_stats_tx_os(int bytes)
{
    if (m_p_socket_stats) {
        if (bytes >= 0) {
            m_p_socket_stats->counters.n_tx_os_bytes += bytes;
            m_p_socket_stats->counters.n_tx_os_packets++;
        } else if (errno == EAGAIN) {
            m_p_socket_stats->counters.n_rx_os_eagain++;
        } else {
            m_p_socket_stats->counters.n_tx_os_errors++;
        }
    }
}

bool sockinfo::attach_receiver(flow_tuple_with_local_if &flow_key)
{
    // This function should be called from within mutex protected context of the sockinfo!!!

    si_logdbg("Attaching to %s", flow_key.to_str().c_str());

    // Protect against local loopback used as local_if & peer_ip
    // rdma_cm will accept it but we don't want to offload it
    if (flow_key.is_local_loopback()) {
        si_logdbg(PRODUCT_NAME " does not offload local loopback IP address");
        return false;
    }

    if (m_rx_flow_map.find(flow_key) != m_rx_flow_map.end()) {
        si_logdbg("already attached %s", flow_key.to_str().c_str());
        return false;
    }

    // Allocate resources on specific interface (create ring)
    net_device_resources_t *p_nd_resources =
        create_nd_resources(ip_addr(flow_key.get_local_if(), flow_key.get_family()));
    if (!p_nd_resources) {
        // any error which occurred inside create_nd_resources() was already printed. No need to
        // reprint errors here
        return false;
    }

    // Map flow in local map
    m_rx_flow_map[flow_key] = p_nd_resources->p_ring;

    // Attach tuple
    BULLSEYE_EXCLUDE_BLOCK_START
    unlock_rx_q();
    if (!p_nd_resources->p_ring->attach_flow(flow_key, this, is_outgoing())) {
        lock_rx_q();
        si_logdbg("Failed to attach %s to ring %p", flow_key.to_str().c_str(),
                  p_nd_resources->p_ring);
        return false;
    }

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    if (g_p_app->type != APP_NONE && g_p_app->get_worker_id() >= 0) {
#if defined(DEFINED_ENVOY)
        if (flow_key.get_protocol() != PROTO_UDP)
#else
        if (flow_key.get_protocol() != PROTO_UDP ||
            (flow_key.get_protocol() == PROTO_UDP &&
             g_map_udp_resue_port.count(((uint32_t)flow_key.get_family() << 16) |
                                        ntohs(flow_key.get_dst_port()))))
#endif
        {
            if ((g_p_app->workers_num != g_p_app->workers_pow2) && flow_key.is_3_tuple()) {
                if (g_p_app->get_worker_id() < (g_p_app->workers_pow2 % g_p_app->workers_num)) {
                    g_p_app->add_second_4t_rule = true;
                    flow_tuple_with_local_if new_key(
                        flow_key.get_dst_ip(), flow_key.get_dst_port(), ip_address::any_addr(), 1,
                        flow_key.get_protocol(), flow_key.get_family(), flow_key.get_local_if());
                    p_nd_resources =
                        create_nd_resources(ip_addr(new_key.get_local_if(), new_key.get_family()));
                    if (!p_nd_resources->p_ring->attach_flow(new_key, this, false)) {
                        lock_rx_q();
                        si_logerr("Failed to attach %s to ring %p", new_key.to_str().c_str(),
                                  p_nd_resources->p_ring);
                        g_p_app->add_second_4t_rule = false;
                        return false;
                    }
                    m_rx_flow_map[new_key] = p_nd_resources->p_ring;
                    si_logdbg("Added second rule %s for index %d to ring %p",
                              new_key.to_str().c_str(), g_p_app->get_worker_id(),
                              p_nd_resources->p_ring);
                }
            }
            g_p_app->add_second_4t_rule = false;
        }
    }
#endif

    lock_rx_q();
    BULLSEYE_EXCLUDE_BLOCK_END

    // Registered as receiver successfully
    si_logdbg("Attached %s to ring %p", flow_key.to_str().c_str(), p_nd_resources->p_ring);

    // Verify 5 tuple over 3 tuple and replace flow rule with the strongest
    if (flow_key.is_5_tuple()) {
        // Check and remove lesser 3 tuple
        flow_tuple_with_local_if flow_key_3t(
            flow_key.get_dst_ip(), flow_key.get_dst_port(), ip_address::any_addr(), INPORT_ANY,
            flow_key.get_protocol(), flow_key.get_family(), flow_key.get_local_if());
        rx_flow_map_t::iterator rx_flow_iter = m_rx_flow_map.find(flow_key_3t);
        if (rx_flow_iter != m_rx_flow_map.end()) {
            si_logdbg("Removing (and detaching) 3 tuple now that we added a stronger 5 tuple");
            detach_receiver(flow_key_3t);
        }
    }

    return true;
}

bool sockinfo::detach_receiver(flow_tuple_with_local_if &flow_key, rfs_rule **rule_extract)
{
    si_logdbg("Unregistering receiver: %s", flow_key.to_str().c_str());

    // TODO ALEXR: DO we need to return a 3 tuple instead of a 5 tuple being removed?
    // if (peer_ip != INADDR_ANY && peer_port != INPORT_ANY);

    // Find ring associated with this tuple
    rx_flow_map_t::iterator rx_flow_iter = m_rx_flow_map.find(flow_key);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (rx_flow_iter == m_rx_flow_map.end()) {
        si_logdbg("Failed to find ring associated with: %s", flow_key.to_str().c_str());
        return false;
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    ring *p_ring = rx_flow_iter->second;

    si_logdbg("Detaching %s from ring %p", flow_key.to_str().c_str(), p_ring);

    // Detach tuple
    unlock_rx_q();
    p_ring->detach_flow(flow_key, this, rule_extract);
    lock_rx_q();

    // Un-map flow from local map
    m_rx_flow_map.erase(rx_flow_iter);

    return destroy_nd_resources(ip_addr(flow_key.get_local_if(), flow_key.get_family()));
}

net_device_resources_t *sockinfo::create_nd_resources(const ip_addr &ip_local)
{
    net_device_resources_t *p_nd_resources = nullptr;

    // Check if we are already registered to net_device with the local ip as observers
    rx_net_device_map_t::iterator rx_nd_iter = m_rx_nd_map.find(ip_local);
    if (rx_nd_iter == m_rx_nd_map.end()) {

        // Need to register as observer to net_device
        net_device_resources_t nd_resources;
        nd_resources.refcnt = 0;

        nd_resources.p_ndv = g_p_net_device_table_mgr->get_net_device_val(ip_local);
        if (!nd_resources.p_ndv) {
            si_logwarn("Failed to obtain device for local ip %s", ip_local.to_str().c_str());
            goto err;
        }

        unlock_rx_q();
        m_rx_migration_lock.lock();
        m_rx_ring_map_lock.lock();
        resource_allocation_key *key;
        /* Sockinfo object can use few different rx rings but all these rings should
         * have the same key and identical ring allocation logic otherwise
         * corruption happens during ring releasing
         * Exception: RING_LOGIC_PER_IP - different ip generate different keys
         */
        if (m_rx_ring_map.size() &&
            (m_ring_alloc_logic_rx.get_alloc_logic_type() != RING_LOGIC_PER_IP)) {
            key = m_ring_alloc_logic_rx.get_key();
        } else {
            key = m_ring_alloc_logic_rx.create_new_key(ip_local);
        }
        m_rx_ring_map_lock.unlock();
        nd_resources.p_ring = nd_resources.p_ndv->reserve_ring(key);
        m_rx_migration_lock.unlock();
        lock_rx_q();
        if (!nd_resources.p_ring) {
            si_logdbg("Failed to reserve ring for allocation key %s on ip %s",
                      m_ring_alloc_logic_rx.get_key()->to_str().c_str(), ip_local.to_str().c_str());
            goto err;
        }

        // Add new net_device to rx_map
        m_rx_nd_map[ip_local] = nd_resources;

        rx_nd_iter = m_rx_nd_map.find(ip_local);
        if (rx_nd_iter == m_rx_nd_map.end()) {
            si_logerr("Failed to find rx_nd_iter");
            goto err;
        }
    }

    // Now we have the net_device object (created or found)
    p_nd_resources = &rx_nd_iter->second;

    /* just increment reference counter on attach */
    p_nd_resources->refcnt++;

    // Save the new CQ from ring.
    rx_add_ring_cb(p_nd_resources->p_ring);

    return p_nd_resources;
err:
    return nullptr;
}

bool sockinfo::destroy_nd_resources(const ip_addr &ip_local)
{
    net_device_resources_t *p_nd_resources = nullptr;
    rx_net_device_map_t::iterator rx_nd_iter = m_rx_nd_map.find(ip_local);

    BULLSEYE_EXCLUDE_BLOCK_START
    if (rx_nd_iter == m_rx_nd_map.end()) {
        si_logerr("Failed to net_device associated with: %s", ip_local.to_str().c_str());
        return false;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    p_nd_resources = &(rx_nd_iter->second);

    p_nd_resources->refcnt--;

    // Release the new CQ from ring (dummy_flow_key is not used)
    rx_del_ring_cb(p_nd_resources->p_ring);

    if (p_nd_resources->refcnt == 0) {

        // Release ring reference
        unlock_rx_q();
        resource_allocation_key *key;
        if (m_ring_alloc_logic_rx.get_alloc_logic_type() != RING_LOGIC_PER_IP) {
            key = m_ring_alloc_logic_rx.get_key();
        } else {
            key = m_ring_alloc_logic_rx.create_new_key(ip_local);
        }
        if (p_nd_resources->p_ndv->release_ring(key) < 0) {
            lock_rx_q();
            si_logerr("Failed to release ring for allocation key %s on ip %s",
                      m_ring_alloc_logic_rx.get_key()->to_str().c_str(), ip_local.to_str().c_str());
            return false;
        }
        lock_rx_q();

        m_rx_nd_map.erase(rx_nd_iter);
    }

    return true;
}

void sockinfo::do_rings_migration_rx(resource_allocation_key &old_key)
{
    lock_rx_q();

    uint64_t new_calc_id = m_ring_alloc_logic_rx.calc_res_key_by_logic();
    uint64_t old_calc_id = old_key.get_user_id_key();
    resource_allocation_key *new_key = m_ring_alloc_logic_rx.get_key();
    // Check again if migration is needed before migration
    if (old_key.get_user_id_key() == new_calc_id &&
        old_key.get_ring_alloc_logic() == new_key->get_ring_alloc_logic()) {
        unlock_rx_q();
        return;
    }

    // Update key to new ID
    new_key->set_user_id_key(new_calc_id);
    rx_net_device_map_t::iterator rx_nd_iter = m_rx_nd_map.begin();
    while (rx_nd_iter != m_rx_nd_map.end()) {
        int rc = 0;
        descq_t descs_rx_ready;
        net_device_resources_t *p_nd_resources = &(rx_nd_iter->second);
        ring *p_old_ring = p_nd_resources->p_ring;
        unlock_rx_q();
        ring *new_ring = p_nd_resources->p_ndv->reserve_ring(new_key);
        if (new_ring == p_old_ring) {
            rc = p_nd_resources->p_ndv->release_ring(&old_key);
            if (rc < 0) {
                si_logerr("Failed to release ring for allocation key %s", old_key.to_str().c_str());
                new_key->set_user_id_key(old_calc_id);
                m_ring_alloc_logic_rx.disable_migration();
                si_logwarn("Migration is disabled due to failure");
            }
            lock_rx_q();
            rx_nd_iter++;
            continue;
        }
        BULLSEYE_EXCLUDE_BLOCK_START
        if (!new_ring) {
            ip_addr ip_local(rx_nd_iter->first);
            si_logerr("Failed to reserve ring for allocation key %s on lip %s",
                      new_key->to_str().c_str(), ip_local.to_str().c_str());
            new_key->set_user_id_key(old_calc_id);
            m_ring_alloc_logic_rx.disable_migration();
            si_logwarn("Migration is disabled due to failure");
            lock_rx_q();
            rx_nd_iter++;
            continue;
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        lock_rx_q();
        rx_flow_map_t::iterator rx_flow_iter = m_rx_flow_map.begin();
        while (rx_flow_iter != m_rx_flow_map.end()) {

            ring *p_ring = rx_flow_iter->second;
            if (p_ring != p_old_ring) {
                rx_flow_iter++; // Pop next flow rule
                continue;
            }

            flow_tuple_with_local_if flow_key = rx_flow_iter->first;
            // Save the new CQ from ring
            rx_add_ring_cb(new_ring);

            // Attach tuple
            BULLSEYE_EXCLUDE_BLOCK_START
            unlock_rx_q();
            if (!new_ring->attach_flow(flow_key, this, is_outgoing())) {
                si_logerr("Failed to attach %s to ring %p", flow_key.to_str().c_str(), new_ring);
                rx_del_ring_cb(new_ring);
                rc = p_nd_resources->p_ndv->release_ring(new_key);
                if (rc < 0) {
                    si_logerr("Failed to release ring for allocation key %s",
                              new_key->to_str().c_str());
                }
                new_ring = nullptr;
                break;
            }
            lock_rx_q();
            BULLSEYE_EXCLUDE_BLOCK_END

            rx_flow_iter->second = new_ring;

            // Registered as receiver successfully
            si_logdbg("Attached %s to ring %p", flow_key.to_str().c_str(), new_ring);

            si_logdbg("Detaching %s from ring %p", flow_key.to_str().c_str(), p_old_ring);
            // Detach tuple
            unlock_rx_q();
            p_old_ring->detach_flow(flow_key, this, nullptr);
            lock_rx_q();
            rx_del_ring_cb(p_old_ring);

            rx_flow_iter++; // Pop next flow rule;
        }

        if (!new_ring) {
            const ip_address &ip_local = rx_nd_iter->first;
            si_logerr("Failed to reserve ring for allocation key %s on lip %s",
                      new_key->to_str().c_str(), ip_local.to_str(m_family).c_str());
            new_key->set_user_id_key(old_calc_id);
            m_ring_alloc_logic_rx.disable_migration();
            si_logwarn("Migration is disabled due to failure");
            lock_rx_q();
            rx_nd_iter++;
            continue;
        }

        unlock_rx_q();
        m_rx_ring_map_lock.lock();
        lock_rx_q();
        if (!m_p_rx_ring && m_rx_ring_map.size() == 1) {
            m_p_rx_ring = m_rx_ring_map.begin()->first;
        }
        unlock_rx_q();
        m_rx_ring_map_lock.unlock();

        // Release ring reference
        BULLSEYE_EXCLUDE_BLOCK_START
        lock_rx_q();
        pop_descs_rx_ready(&descs_rx_ready, p_old_ring);
        unlock_rx_q();
        rc = p_nd_resources->p_ndv->release_ring(&old_key);
        if (rc == 0) {
            /* All buffers in m_rx_pkt_ready_list
             * related destroyed ring should be reclaimed explicitly to
             * avoid invalid dereferencing buff->p_desc_owner attempt doing
             * dequeue_packet()
             */
            reuse_descs(&descs_rx_ready);
        } else if (rc > 0) {
            /* It is special optimization to save income data
             * Try to avoid removing buffers from m_rx_pkt_ready_list
             * during migration because in some case after migration
             * ring can be valid and usable
             */
            lock_rx_q();
            push_descs_rx_ready(&descs_rx_ready);
            unlock_rx_q();
        } else if (rc < 0) {
            reuse_descs(&descs_rx_ready);

            const ip_address &ip_local = rx_nd_iter->first;
            si_logerr("Failed to release ring for allocation key %s on lip %s",
                      old_key.to_str().c_str(), ip_local.to_str(m_family).c_str());
        }
        lock_rx_q();
        BULLSEYE_EXCLUDE_BLOCK_END
        p_nd_resources->p_ring = new_ring;
        rx_nd_iter++;
    }

    unlock_rx_q();
    IF_STATS(m_p_socket_stats->counters.n_rx_migrations++);
}

void sockinfo::consider_rings_migration_rx()
{
    if (m_ring_alloc_logic_rx.is_logic_support_migration()) {
        if (!m_rx_migration_lock.trylock()) {
            if (m_ring_alloc_logic_rx.should_migrate_ring()) {
                ring_alloc_logic_attr old_key(*m_ring_alloc_logic_rx.get_key());
                do_rings_migration_rx(old_key);
            }
            m_rx_migration_lock.unlock();
        }
    }
}

int sockinfo::add_epoll_context(epfd_info *epfd)
{
    int ret = 0;
    rx_ring_map_t::const_iterator sock_ring_map_iter;

    m_rx_ring_map_lock.lock();
    lock_rx_q();

    if (!m_econtext) {
        // This socket is not registered to any epfd
        m_econtext = epfd;
    } else {
        // Currently XLIO does not support more then 1 epfd listed
        errno = (m_econtext == epfd) ? EEXIST : ENOMEM;
        ret = -1;
    }

    if (ret < 0) {
        goto unlock_locks;
    }

    if (safe_mce_sys().skip_poll_in_rx == SKIP_POLL_IN_RX_EPOLL_ONLY) {
        m_skip_cq_poll_in_rx = true;
    }

    sock_ring_map_iter = m_rx_ring_map.begin();
    while (sock_ring_map_iter != m_rx_ring_map.end()) {
        if (has_epoll_context()) {
            m_econtext->increase_ring_ref_count(sock_ring_map_iter->first);
        }
        sock_ring_map_iter++;
    }

unlock_locks:

    unlock_rx_q();
    m_rx_ring_map_lock.unlock();

    return ret;
}

void sockinfo::remove_epoll_context(epfd_info *epfd)
{
    m_rx_ring_map_lock.lock();
    lock_rx_q();

    if (!has_epoll_context() || m_econtext != epfd) {
        unlock_rx_q();
        m_rx_ring_map_lock.unlock();
        return;
    }

    rx_ring_map_t::const_iterator sock_ring_map_iter = m_rx_ring_map.begin();
    while (sock_ring_map_iter != m_rx_ring_map.end()) {
        m_econtext->decrease_ring_ref_count(sock_ring_map_iter->first);
        sock_ring_map_iter++;
    }

    if (m_econtext == epfd) {
        m_econtext = NULL;
    }

    if (safe_mce_sys().skip_poll_in_rx == SKIP_POLL_IN_RX_EPOLL_ONLY) {
        m_skip_cq_poll_in_rx = false;
    }

    unlock_rx_q();
    m_rx_ring_map_lock.unlock();
}

void sockinfo::statistics_print(vlog_levels_t log_level /* = VLOG_DEBUG */)
{
    const char *const in_protocol_str[] = {
        "PROTO_UNDEFINED",
        "PROTO_UDP",
        "PROTO_TCP",
        "PROTO_ALL",
    };

    const char *const m_state_str[] = {
        "SOCKINFO_OPENED",
        "SOCKINFO_CLOSING",
        "SOCKINFO_CLOSED",
        "SOCKINFO_DESTROYING",
    };

    bool b_any_activity = false;

    int epoll_fd = get_epoll_context_fd();

    // Socket data
    vlog_printf(log_level, "Fd number : %d\n", m_fd);
    if (epoll_fd) {
        vlog_printf(log_level, "Socket epoll Fd : %d\n", epoll_fd);
        vlog_printf(log_level, "Socket epoll flags : 0x%x\n", m_fd_rec.events);
    }

    vlog_printf(log_level, "Bind info : %s\n", m_bound.to_str_ip_port(true).c_str());
    vlog_printf(log_level, "Connection info : %s\n", m_connected.to_str_ip_port(true).c_str());
    vlog_printf(log_level, "Protocol : %s\n", in_protocol_str[m_protocol]);
    vlog_printf(log_level, "Is closed : %s\n", m_state_str[m_state]);
    vlog_printf(log_level, "Is blocking : %s\n", m_b_blocking ? "true" : "false");
    vlog_printf(log_level, "Rx reuse buffer pending : %s\n",
                m_rx_reuse_buf_pending ? "true" : "false");
    vlog_printf(log_level, "Rx reuse buffer postponed : %s\n",
                m_rx_reuse_buf_postponed ? "true" : "false");

    if (m_p_connected_dst_entry) {
        vlog_printf(log_level, "Is offloaded : %s\n",
                    m_p_connected_dst_entry->is_offloaded() ? "true" : "false");
    }

    if (!m_p_socket_stats) {
        return;
    }

    if (m_p_socket_stats->ring_alloc_logic_rx == RING_LOGIC_PER_USER_ID) {
        vlog_printf(log_level, "RX Ring User ID : %lu\n", m_p_socket_stats->ring_user_id_rx);
    }
    if (m_p_socket_stats->ring_alloc_logic_tx == RING_LOGIC_PER_USER_ID) {
        vlog_printf(log_level, "TX Ring User ID : %lu\n", m_p_socket_stats->ring_user_id_tx);
    }

    if (m_p_socket_stats->counters.n_tx_sent_byte_count ||
        m_p_socket_stats->counters.n_tx_sent_pkt_count || m_p_socket_stats->counters.n_tx_errors ||
        m_p_socket_stats->counters.n_tx_eagain) {
        vlog_printf(log_level,
                    "Tx Offload : %" PRIu64
                    " KB / %d / %d / %d [kilobytes/packets/eagains/errors]\n",
                    m_p_socket_stats->counters.n_tx_sent_byte_count / 1024,
                    m_p_socket_stats->counters.n_tx_sent_pkt_count,
                    m_p_socket_stats->counters.n_tx_eagain, m_p_socket_stats->counters.n_tx_errors);
        b_any_activity = true;
    }
    if (m_p_socket_stats->counters.n_tx_os_bytes || m_p_socket_stats->counters.n_tx_os_packets ||
        m_p_socket_stats->counters.n_tx_os_errors) {
        vlog_printf(log_level, "Tx OS info : %" PRIu64 " KB / %d / %d [kilobytes/packets/errors]\n",
                    m_p_socket_stats->counters.n_tx_os_bytes / 1024,
                    m_p_socket_stats->counters.n_tx_os_packets,
                    m_p_socket_stats->counters.n_tx_os_errors);
        b_any_activity = true;
    }
    if (m_p_socket_stats->counters.n_tx_dummy) {
        vlog_printf(log_level, "Tx Dummy messages : %d\n", m_p_socket_stats->counters.n_tx_dummy);
        b_any_activity = true;
    }
    if (m_p_socket_stats->counters.n_rx_bytes || m_p_socket_stats->counters.n_rx_packets ||
        m_p_socket_stats->counters.n_rx_errors || m_p_socket_stats->counters.n_rx_eagain ||
        m_p_socket_stats->n_rx_ready_pkt_count) {
        vlog_printf(
            log_level,
            "Rx Offload : %" PRIu64 " KB / %d / %d / %d [kilobytes/packets/eagains/errors]\n",
            m_p_socket_stats->counters.n_rx_bytes / 1024, m_p_socket_stats->counters.n_rx_packets,
            m_p_socket_stats->counters.n_rx_eagain, m_p_socket_stats->counters.n_rx_errors);
        vlog_printf(
            log_level,
            "Rx data packets: %" PRIu64 " / %u / %u / %u [kilobytes/packets/frags/chained]\n",
            m_p_socket_stats->counters.n_rx_bytes / 1024, m_p_socket_stats->counters.n_rx_data_pkts,
            m_p_socket_stats->counters.n_rx_frags, m_p_socket_stats->counters.n_gro);
        if (m_p_socket_stats->counters.n_rx_data_pkts) {
            vlog_printf(
                log_level, "Avg. aggr packet size: %" PRIu64 " fragments per packet: %.1f\n",
                m_p_socket_stats->counters.n_rx_bytes / m_p_socket_stats->counters.n_rx_data_pkts,
                static_cast<double>(m_p_socket_stats->counters.n_rx_frags) /
                    m_p_socket_stats->counters.n_rx_data_pkts);
        }

        if (m_p_socket_stats->counters.n_rx_packets) {
            float rx_drop_percentage = 0;
            if (m_p_socket_stats->n_rx_ready_pkt_count) {
                rx_drop_percentage =
                    (float)(m_p_socket_stats->counters.n_rx_ready_byte_drop * 100) /
                    (float)m_p_socket_stats->counters.n_rx_packets;
            }
            vlog_printf(log_level, "Rx byte : max %d / dropped %d (%2.2f%%)\n",
                        m_p_socket_stats->counters.n_rx_ready_byte_max,
                        m_p_socket_stats->counters.n_rx_ready_byte_drop, rx_drop_percentage);

            if (m_p_socket_stats->n_rx_ready_pkt_count) {
                rx_drop_percentage = (float)(m_p_socket_stats->counters.n_rx_ready_pkt_drop * 100) /
                    (float)m_p_socket_stats->counters.n_rx_packets;
            }
            vlog_printf(log_level, "Rx pkt : max %d / dropped %d (%2.2f%%)\n",
                        m_p_socket_stats->counters.n_rx_ready_pkt_max,
                        m_p_socket_stats->counters.n_rx_ready_pkt_drop, rx_drop_percentage);
        }

        b_any_activity = true;
    }
    if (m_p_socket_stats->strq_counters.n_strq_total_strides) {
        vlog_printf(log_level, "Rx RQ Strides: %" PRIu64 " / %u [total/max-per-packet]\n",
                    m_p_socket_stats->strq_counters.n_strq_total_strides,
                    m_p_socket_stats->strq_counters.n_strq_max_strides_per_packet);
    }
    if (m_p_socket_stats->counters.n_rx_os_bytes || m_p_socket_stats->counters.n_rx_os_packets ||
        m_p_socket_stats->counters.n_rx_os_errors || m_p_socket_stats->counters.n_rx_os_eagain) {
        vlog_printf(
            log_level,
            "Rx OS info : %" PRIu64 " KB / %d / %d / %d [kilobytes/packets/eagains/errors]\n",
            m_p_socket_stats->counters.n_rx_os_bytes / 1024,
            m_p_socket_stats->counters.n_rx_os_packets, m_p_socket_stats->counters.n_rx_os_eagain,
            m_p_socket_stats->counters.n_rx_os_errors);
        b_any_activity = true;
    }
    if (m_p_socket_stats->counters.n_rx_poll_miss || m_p_socket_stats->counters.n_rx_poll_hit) {
        float rx_poll_hit_percentage = (float)(m_p_socket_stats->counters.n_rx_poll_hit * 100) /
            (float)(m_p_socket_stats->counters.n_rx_poll_miss +
                    m_p_socket_stats->counters.n_rx_poll_hit);
        vlog_printf(log_level, "Rx poll : %d / %d (%2.2f%%) [miss/hit]\n",
                    m_p_socket_stats->counters.n_rx_poll_miss,
                    m_p_socket_stats->counters.n_rx_poll_hit, rx_poll_hit_percentage);
        b_any_activity = true;
    }
    if (b_any_activity == false) {
        vlog_printf(log_level, "Socket activity : Rx and Tx where not active\n");
    }
}

// Sleep on different CQs and OS listen socket
int sockinfo::os_wait_sock_rx_epfd(epoll_event *ep_events, int maxevents)
{
    if (unlikely(safe_mce_sys().rx_cq_wait_ctrl)) {
        add_cqfd_to_sock_rx_epfd(m_p_rx_ring);
        int ret =
            SYSCALL(epoll_wait, m_rx_epfd, ep_events, maxevents, m_loops_timer.time_left_msec());
        remove_cqfd_from_sock_rx_epfd(m_p_rx_ring);
        return ret;
    }

    return os_epoll_wait(ep_events, maxevents);
}

int sockinfo::os_epoll_wait(epoll_event *ep_events, int maxevents)
{
    return SYSCALL(epoll_wait, m_rx_epfd, ep_events, maxevents, m_loops_timer.time_left_msec());
}

// Add this new CQ channel fd to the rx epfd handle (no need to wake up any sleeping thread about
// this new fd)
void sockinfo::add_cqfd_to_sock_rx_epfd(ring *p_ring)
{
    if (unlikely(m_rx_epfd == -1)) {
        return;
    }

    epoll_event ev = {0, {nullptr}};
    ev.events = EPOLLIN;
    size_t num_ring_rx_fds;
    int *ring_rx_fds_array = p_ring->get_rx_channel_fds(num_ring_rx_fds);

    for (size_t i = 0; i < num_ring_rx_fds; i++) {
        ev.data.fd = ring_rx_fds_array[i];

        if (unlikely(SYSCALL(epoll_ctl, m_rx_epfd, EPOLL_CTL_ADD, ev.data.fd, &ev))) {
            si_logerr("failed to add cq channel fd to internal epfd errno=%d (%m)", errno);
        }
    }
}

void sockinfo::remove_cqfd_from_sock_rx_epfd(ring *base_ring)
{
    if (unlikely(m_rx_epfd == -1)) {
        return;
    }

    size_t num_ring_rx_fds;
    int *ring_rx_fds_array = base_ring->get_rx_channel_fds(num_ring_rx_fds);

    for (size_t i = 0; i < num_ring_rx_fds; i++) {
        if (unlikely(
                (SYSCALL(epoll_ctl, m_rx_epfd, EPOLL_CTL_DEL, ring_rx_fds_array[i], nullptr)) &&
                (!(errno == ENOENT || errno == EBADF)))) {
            si_logerr("failed to delete cq channel fd from internal epfd (errno=%d %s)", errno,
                      strerror(errno));
        }
    }
}

void sockinfo::rx_add_ring_cb(ring *p_ring)
{
    si_logdbg("");

    bool notify_epoll = false;

    // Add the rx ring to our rx ring map
    unlock_rx_q();
    m_rx_ring_map_lock.lock();
    lock_rx_q();
    rx_ring_map_t::iterator rx_ring_iter = m_rx_ring_map.find(p_ring->get_parent());
    if (rx_ring_iter == m_rx_ring_map.end()) {
        // First map of this cq mgr
        ring_info_t *p_ring_info = new ring_info_t();
        m_rx_ring_map[p_ring] = p_ring_info;
        p_ring_info->refcnt = 1;
        p_ring_info->rx_reuse_info.n_buff_num = 0;

        /* m_p_rx_ring is updated in following functions:
         *  - rx_add_ring_cb()
         *  - rx_del_ring_cb()
         *  - do_rings_migration_rx()
         */
        if (m_rx_ring_map.size() == 1) {
            m_p_rx_ring = m_rx_ring_map.begin()->first;
        }

        notify_epoll = true;

        // In case of many connections, adding the cq-fd to the epfd of each socket (Each socket has
        // its own epoll descriptor) introduces a long linear scan of the waiter to be awaken for
        // each event on the cq-fd. This causes high latency and increased CPU usage by the Kernel
        // which leads to decreased performance. For example, for 350K connections and a single
        // ring. there will be 350K epfds watching a single cq-fd. When this cq-fd has an event, the
        // Kernel loops through all the 350K epfds. By setting safe_mce_sys().rx_cq_wait_ctrl=true,
        // we add the cq-fd only to the epfds of the sockets that are going to sleep inside
        // sockinfo_tcp::rx_wait_helper/sockinfo_udp::rx_wait.
        if (!safe_mce_sys().rx_cq_wait_ctrl) {
            add_cqfd_to_sock_rx_epfd(p_ring);
        }

        // A ready wce can be pending due to the drain logic (cq channel will not wake up by itself)
        m_sock_wakeup_pipe.do_wakeup();
    } else {
        // Increase ref count on cq_mgr_rx object
        rx_ring_iter->second->refcnt++;
    }

    unlock_rx_q();
    m_rx_ring_map_lock.unlock();

    if (notify_epoll) {
        // todo m_econtext is not protected by socket lock because epfd->m_ring_map_lock should be
        // first in order. possible race between removal of fd from epoll (epoll_ctl del, or epoll
        // close) and here. need to add a third-side lock (fd_collection?) to sync between epoll and
        // socket.
        if (has_epoll_context()) {
            m_econtext->increase_ring_ref_count(p_ring);
        }
    }

    lock_rx_q();
}

void sockinfo::rx_del_ring_cb(ring *p_ring)
{
    si_logdbg("");

    bool notify_epoll = false;

    // Remove the rx cq_mgr_rx from our rx cq map
    unlock_rx_q();
    m_rx_ring_map_lock.lock();
    lock_rx_q();

    descq_t temp_rx_reuse;
    temp_rx_reuse.set_id("sockinfo (%p), fd = %d : rx_del_ring_cb temp_rx_reuse", this, m_fd);
    descq_t temp_rx_reuse_global;
    temp_rx_reuse_global.set_id("sockinfo (%p), fd = %d : rx_del_ring_cb temp_rx_reuse_global",
                                this, m_fd);

    ring *base_ring = p_ring->get_parent();
    rx_ring_map_t::iterator rx_ring_iter = m_rx_ring_map.find(base_ring);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (rx_ring_iter != m_rx_ring_map.end()) {
        BULLSEYE_EXCLUDE_BLOCK_END
        ring_info_t *p_ring_info = rx_ring_iter->second;
        // Decrease ref count on cq_mgr_rx object
        p_ring_info->refcnt--;

        // Is this the last reference to this cq_mgr_rx?
        if (p_ring_info->refcnt == 0) {

            // Move all cq_mgr_rx->rx_reuse buffers to temp reuse queue related to p_rx_cq_mgr
            move_descs(base_ring, &temp_rx_reuse, &p_ring_info->rx_reuse_info.rx_reuse, true);
            move_descs(base_ring, &temp_rx_reuse_global, &p_ring_info->rx_reuse_info.rx_reuse,
                       false);
            if (p_ring_info->rx_reuse_info.rx_reuse.size()) {
                si_logerr(
                    "possible buffer leak, p_ring_info->rx_reuse_buff still contain %lu buffers.",
                    p_ring_info->rx_reuse_info.rx_reuse.size());
            }

            if (!safe_mce_sys().rx_cq_wait_ctrl) {
                remove_cqfd_from_sock_rx_epfd(base_ring);
            }

            notify_epoll = true;

            m_rx_ring_map.erase(base_ring);
            delete p_ring_info;

            if (m_p_rx_ring == base_ring) {
                if (m_rx_ring_map.size() == 1) {
                    m_p_rx_ring = m_rx_ring_map.begin()->first;
                } else {
                    m_p_rx_ring = nullptr;
                }

                move_descs(base_ring, &temp_rx_reuse, &m_rx_reuse_buff.rx_reuse, true);
                move_descs(base_ring, &temp_rx_reuse_global, &m_rx_reuse_buff.rx_reuse, false);

                m_rx_reuse_buff.n_buff_num = m_rx_reuse_buff.rx_reuse.size();
            }
        }
    } else {
        si_logerr("oops, ring not found in map, so we can't remove it ???");
    }
    unlock_rx_q();
    m_rx_ring_map_lock.unlock();

    if (notify_epoll) {
        // todo m_econtext is not protected by socket lock because epfd->m_ring_map_lock should be
        // first in order. possible race between removal of fd from epoll (epoll_ctl del, or epoll
        // close) and here. need to add a third-side lock (fd_collection?) to sync between epoll and
        // socket.
        if (has_epoll_context()) {
            m_econtext->decrease_ring_ref_count(base_ring);
        }
    }

    // no need for m_lock_rcv since temp_rx_reuse is on the stack
    reuse_descs(&temp_rx_reuse, base_ring);

    if (temp_rx_reuse_global.size() > 0) {
        g_buffer_pool_rx_ptr->put_buffers_after_deref_thread_safe(&temp_rx_reuse_global);
    }

    lock_rx_q();
}

void sockinfo::move_descs(ring *p_ring, descq_t *toq, descq_t *fromq, bool own)
{
    // Assume locked by owner!!!
#define __xor(_a, _b) ((!(_a) && (_b)) || ((_a) && !(_b)))

    mem_buf_desc_t *temp;
    const size_t size = fromq->size();
    for (size_t i = 0; i < size; i++) {
        temp = fromq->front();
        fromq->pop_front();
        if (!__xor(own, p_ring->is_member(temp->p_desc_owner))) {
            toq->push_back(temp);
        } else {
            fromq->push_back(temp);
        }
    }
}

void sockinfo::pop_descs_rx_ready(descq_t *cache, ring *p_ring)
{
    // Assume locked by owner!!!
    mem_buf_desc_t *temp;
    const size_t size = get_size_m_rx_pkt_ready_list();

    for (size_t i = 0; i < size; i++) {
        temp = get_front_m_rx_pkt_ready_list();
        pop_front_m_rx_pkt_ready_list();
        if (p_ring && !p_ring->is_member(temp->p_desc_owner)) {
            push_back_m_rx_pkt_ready_list(temp);
            continue;
        }
        m_n_rx_pkt_ready_list_count--;
        m_rx_ready_byte_count -= temp->rx.sz_payload;
        if (m_p_socket_stats) {
            m_p_socket_stats->n_rx_ready_pkt_count--;
            m_p_socket_stats->n_rx_ready_byte_count -= temp->rx.sz_payload;
        }
        cache->push_back(temp);
    }
}

void sockinfo::push_descs_rx_ready(descq_t *cache)
{
    // Assume locked by owner!!!
    mem_buf_desc_t *temp;
    const size_t size = (cache ? cache->size() : 0);

    for (size_t i = 0; i < size; i++) {
        temp = cache->front();
        cache->pop_front();
        m_n_rx_pkt_ready_list_count++;
        m_rx_ready_byte_count += temp->rx.sz_payload;
        if (m_p_socket_stats) {
            m_p_socket_stats->n_rx_ready_pkt_count++;
            m_p_socket_stats->n_rx_ready_byte_count += temp->rx.sz_payload;
        }
        push_back_m_rx_pkt_ready_list(temp);
    }
}

void sockinfo::reuse_descs(descq_t *reuseq, ring *p_ring)
{
    if (reuseq && reuseq->size() > 0) {
        unsigned int counter = 1 << 20;
        while (reuseq->size() > 0 && p_ring && counter--) {
            if (p_ring->reclaim_recv_buffers(reuseq)) {
                break;
            }
            sched_yield();
        }
        if (reuseq->size() > 0) {
            g_buffer_pool_rx_ptr->put_buffers_after_deref_thread_safe(reuseq);
        }
    }
}

bool sockinfo::validate_and_convert_mapped_ipv4(sock_addr &sock) const
{
    if (sock.get_sa_family() == AF_INET6) {
        if (!m_is_ipv6only) {
            sock.strip_mapped_ipv4();
        } else if (sock.get_ip_addr().is_mapped_ipv4()) {
            return false;
        }
    }

    return true;
}

bool sockinfo::attach_as_uc_receiver(role_t role, bool skip_rules /* = false */)
{
    sock_addr addr(m_bound);
    ip_addr if_addr(m_bound.get_ip_addr(), m_bound.get_sa_family());
    bool ret = true;

    /* m_so_bindtodevice_ip has high priority */
    if (!m_so_bindtodevice_ip.is_anyaddr()) {
        if_addr = m_so_bindtodevice_ip;
        addr.set_sa_family(if_addr.get_family());
        addr.set_in_addr(if_addr);
        si_logdbg("Attaching using bind to device rule");
    } else {
        si_logdbg("Attaching using bind to ip rule");
    }

    if (!if_addr.is_anyaddr()) {
        si_logdbg("Attached to specific local if: %s addr: %s", if_addr.to_str().c_str(),
                  addr.to_str_ip_port(true).c_str());

        transport_t target_family = TRANS_XLIO;
        if (!skip_rules) {
            target_family = find_target_family(role, addr.get_p_sa());
        }
        if (target_family == TRANS_XLIO) {
            flow_tuple_with_local_if flow_key(addr.get_ip_addr(), addr.get_in_port(),
                                              m_connected.get_ip_addr(), m_connected.get_in_port(),
                                              m_protocol, addr.get_sa_family(), if_addr);
            ret = ret && attach_receiver(flow_key);
        }
    } else {
        si_logdbg("Attaching to all offload if addr: %s", addr.to_str_ip_port().c_str());

        ret &= attach_as_uc_receiver_anyip(AF_INET, role, skip_rules);
        ret &= attach_as_uc_receiver_anyip(AF_INET6, role, skip_rules);
    }

    return ret;
}

bool sockinfo::attach_as_uc_receiver_anyip(sa_family_t family, role_t role, bool skip_rules)
{
    bool ret = true;
    // We need to listen on any IP. So, select all IPv4 addresses. Plus IPv6 addresses if
    // the listen socket is IPv6. If the 'connected' address is not any and its family is
    // not equal to itr->local_addr, skip the address.
    if (((family == AF_INET && !m_is_ipv6only) || (family == m_bound.get_sa_family())) &&
        (m_connected.is_anyaddr() || m_connected.get_sa_family() == family)) {
        si_logfunc("Attaching offloaded IPs, family: %d", family);
        sock_addr addr(m_bound);
        local_ip_list_t addrvec;
        g_p_net_device_table_mgr->get_ip_list(addrvec, family);
        for (auto itr = addrvec.cbegin(); ret && addrvec.cend() != itr; ++itr) {
            si_logfunc("Attaching IP: %s", (*itr).get().local_addr.to_str(family).c_str());

            transport_t target_family = TRANS_XLIO;
            if (!skip_rules) {
                addr.set_sa_family(family);
                addr.set_in_addr((*itr).get().local_addr);
                target_family = find_target_family(role, addr.get_p_sa());
            }
            if (target_family == TRANS_XLIO) {
                // In case m_connected is any address we need to take the any ip_address
                // correctly, since the layout inside m_connected is different for A_INET
                // and AF_INET6 (Currently m_connected family can be different from
                // itr->local_addr).
                const ip_address &src_ip_address =
                    m_connected.is_anyaddr() ? ip_address::any_addr() : m_connected.get_ip_addr();

                flow_tuple_with_local_if flow_key((*itr).get().local_addr, addr.get_in_port(),
                                                  src_ip_address, m_connected.get_in_port(),
                                                  m_protocol, family, (*itr).get().local_addr);

                ret &= attach_receiver(flow_key);
            }
        }
    }

    return ret;
}

transport_t sockinfo::find_target_family(role_t role, const struct sockaddr *sock_addr_first,
                                         const struct sockaddr *sock_addr_second /* = NULL */)
{
    transport_t target_family = TRANS_DEFAULT;
    switch (role) {
    case ROLE_TCP_SERVER:
        target_family = __xlio_match_tcp_server(TRANS_XLIO, safe_mce_sys().app_id, sock_addr_first,
                                                sizeof(struct sockaddr));
        break;
    case ROLE_TCP_CLIENT:
        target_family = __xlio_match_tcp_client(TRANS_XLIO, safe_mce_sys().app_id, sock_addr_first,
                                                sizeof(struct sockaddr), sock_addr_second,
                                                sizeof(struct sockaddr));
        break;
    case ROLE_UDP_RECEIVER:
        target_family = __xlio_match_udp_receiver(TRANS_XLIO, safe_mce_sys().app_id,
                                                  sock_addr_first, sizeof(struct sockaddr));
        break;
    case ROLE_UDP_SENDER:
        target_family = __xlio_match_udp_sender(TRANS_XLIO, safe_mce_sys().app_id, sock_addr_first,
                                                sizeof(struct sockaddr));
        break;
    case ROLE_UDP_CONNECT:
        target_family = __xlio_match_udp_connect(TRANS_XLIO, safe_mce_sys().app_id, sock_addr_first,
                                                 sizeof(struct sockaddr), sock_addr_second,
                                                 sizeof(struct sockaddr));
        break;
        BULLSEYE_EXCLUDE_BLOCK_START
    default:
        break;
        BULLSEYE_EXCLUDE_BLOCK_END
    }
    return target_family;
}

void sockinfo::shutdown_rx()
{
    // Unregister this receiver from all ring's in our list
    rx_flow_map_t::iterator rx_flow_iter = m_rx_flow_map.begin();
    while (rx_flow_iter != m_rx_flow_map.end()) {
        flow_tuple_with_local_if detach_key = rx_flow_iter->first;
        detach_receiver(detach_key);
        rx_flow_iter = m_rx_flow_map.begin(); // Pop next flow rule
    }

    /* Destroy resources in case they are allocated using SO_BINDTODEVICE call */
    if (m_rx_nd_map.size()) {
        destroy_nd_resources(m_so_bindtodevice_ip);
    }
    si_logdbg("shutdown RX");
}

void sockinfo::destructor_helper()
{
    shutdown_rx();
    // Delete all dst_entry in our list
    if (m_p_connected_dst_entry) {
        delete m_p_connected_dst_entry;
    }
    m_p_connected_dst_entry = nullptr;
}

int sockinfo::modify_ratelimit(dst_entry *p_dst_entry, struct xlio_rate_limit_t &rate_limit)
{
    if (m_ring_alloc_log_tx.get_ring_alloc_logic() == RING_LOGIC_PER_SOCKET ||
        m_ring_alloc_log_tx.get_ring_alloc_logic() == RING_LOGIC_PER_USER_ID) {

        if (p_dst_entry) {
            int ret = p_dst_entry->modify_ratelimit(rate_limit);

            if (!ret) {
                m_so_ratelimit = rate_limit;
            }
            // value is in bytes (per second). we need to convert it to kilo-bits (per second)
            return ret;
        } else {
            m_so_ratelimit = rate_limit;
        }
        return 0;
    }
    si_logwarn(PRODUCT_NAME " is not configured with TX ring allocation logic per "
                            "socket or user-id.");
    return -1;
}

int sockinfo::setsockopt_kernel(int __level, int __optname, const void *__optval,
                                socklen_t __optlen, int supported, bool allow_privileged)
{
    if (!supported) {
        char buf[256];
        snprintf(buf, sizeof(buf),
                 "unimplemented setsockopt __level=%#x, __optname=%#x, [__optlen (%d) bytes of "
                 "__optval=%.*s]",
                 (unsigned)__level, (unsigned)__optname, __optlen, __optlen, (char *)__optval);
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
        // Avoid setsockopt(2) syscall if there is no shadow socket.
        if (!supported) {
            errno = ENOPROTOOPT;
            return -1;
        } else {
            return 0;
        }
    }

    si_logdbg("going to OS for setsockopt level %d optname %d", __level, __optname);
    int ret = SYSCALL(setsockopt, m_fd, __level, __optname, __optval, __optlen);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (ret) {
        if (EPERM == errno && allow_privileged) {
            si_logdbg("setsockopt failure is suppressed (ret=%d %m)", ret);
            ret = 0;
            errno = 0;
        } else {
            si_logdbg("setsockopt failed (ret=%d %m)", ret);
        }
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return ret;
}

int sockinfo::set_sockopt_prio(__const void *__optval, socklen_t __optlen)
{
    if (__optlen < sizeof(int)) {
        si_logdbg("bad parameter size in set_sockopt_prio");
        errno = EINVAL;
        return -1;
    }
    uint32_t val = *(uint32_t *)__optval;
    if (m_pcp != val) {
        m_pcp = val;
        si_logdbg("set socket pcp to be %d", m_pcp);
        header_pcp_updater du(m_pcp);
        update_header_field(&du);
    }
    return 0;
}

/**
 * Function to process SW & HW timestamps
 */
void sockinfo::process_timestamps(mem_buf_desc_t *p_desc)
{
    // keep the sw_timestamp the same to all sockets
    if ((m_b_rcvtstamp ||
         (m_n_tsing_flags & (SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE))) &&
        !p_desc->rx.timestamps.sw.tv_sec) {
        clock_gettime(CLOCK_REALTIME, &(p_desc->rx.timestamps.sw));
    }

    // convert hw timestamp to system time
    if (m_n_tsing_flags & SOF_TIMESTAMPING_RAW_HARDWARE) {
        ring_simple *owner_ring = (ring_simple *)p_desc->p_desc_owner;
        if (owner_ring) {
            owner_ring->convert_hw_time_to_system_time(p_desc->rx.timestamps.hw_raw,
                                                       &p_desc->rx.timestamps.hw);
        }
    }
}

void sockinfo::handle_recv_timestamping(struct cmsg_state *cm_state)
{
    struct {
        struct timespec systime;
        struct timespec hwtimetrans;
        struct timespec hwtimeraw;
    } tsing;

    memset(&tsing, 0, sizeof(tsing));

    timestamps_t *packet_timestamps = get_socket_timestamps();
    struct timespec *packet_systime = &packet_timestamps->sw;

    // Only fill in SO_TIMESTAMPNS if both requested.
    // This matches the kernel behavior.
    if (m_b_rcvtstampns) {
        insert_cmsg(cm_state, SOL_SOCKET, SO_TIMESTAMPNS, packet_systime, sizeof(*packet_systime));
    } else if (m_b_rcvtstamp) {
        struct timeval tv;
        tv.tv_sec = packet_systime->tv_sec;
        tv.tv_usec = packet_systime->tv_nsec / 1000;
        insert_cmsg(cm_state, SOL_SOCKET, SO_TIMESTAMP, &tv, sizeof(tv));
    }

    // Handle timestamping options
    // Only support rx time stamps at this time
    int support = m_n_tsing_flags & (SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RAW_HARDWARE);
    if (!support) {
        return;
    }

    if (m_n_tsing_flags & SOF_TIMESTAMPING_SOFTWARE) {
        tsing.systime = packet_timestamps->sw;
    }

    if (m_n_tsing_flags & SOF_TIMESTAMPING_RAW_HARDWARE) {
        tsing.hwtimeraw = packet_timestamps->hw;
    }

    insert_cmsg(cm_state, SOL_SOCKET, SO_TIMESTAMPING, &tsing, sizeof(tsing));
}

void sockinfo::insert_cmsg(struct cmsg_state *cm_state, int level, int type, void *data, int len)
{
    if (!cm_state->cmhdr || cm_state->mhdr->msg_flags & MSG_CTRUNC) {
        return;
    }

    // Ensure there is enough space for the data payload
    const unsigned int cmsg_len = CMSG_LEN(len);
    if (cmsg_len > cm_state->mhdr->msg_controllen - cm_state->cmsg_bytes_consumed) {
        cm_state->mhdr->msg_flags |= MSG_CTRUNC;
        return;
    }

    // Fill in the cmsghdr
    cm_state->cmhdr->cmsg_level = level;
    cm_state->cmhdr->cmsg_type = type;
    cm_state->cmhdr->cmsg_len = cmsg_len;
    memcpy(CMSG_DATA(cm_state->cmhdr), data, len);

    // Update bytes consumed to update msg_controllen later
    cm_state->cmsg_bytes_consumed += CMSG_SPACE(len);

    // Advance to next cmsghdr
    // can't simply use CMSG_NXTHDR() due to glibc bug 13500
    struct cmsghdr *next =
        (struct cmsghdr *)((char *)cm_state->cmhdr + CMSG_ALIGN(cm_state->cmhdr->cmsg_len));
    if ((char *)(next + 1) >
        ((char *)cm_state->mhdr->msg_control + cm_state->mhdr->msg_controllen)) {
        cm_state->cmhdr = nullptr;
    } else {
        cm_state->cmhdr = next;
    }
}

void sockinfo::handle_cmsg(struct msghdr *msg)
{
    struct cmsg_state cm_state;

    cm_state.mhdr = msg;
    cm_state.cmhdr = CMSG_FIRSTHDR(msg);
    cm_state.cmsg_bytes_consumed = 0;

    if (m_b_pktinfo) {
        handle_ip_pktinfo(&cm_state);
    }
    if (m_b_rcvtstamp || m_n_tsing_flags) {
        handle_recv_timestamping(&cm_state);
    }

    cm_state.mhdr->msg_controllen = cm_state.cmsg_bytes_consumed;
}

ssize_t sockinfo::rx_os(const rx_call_t call_type, iovec *p_iov, ssize_t sz_iov, const int flags,
                        sockaddr *__from, socklen_t *__fromlen, struct msghdr *__msg)
{
    errno = 0;
    switch (call_type) {
    case RX_READ:
        __log_info_func("calling os receive with orig read");
        return SYSCALL(read, m_fd, p_iov[0].iov_base, p_iov[0].iov_len);

    case RX_READV:
        __log_info_func("calling os receive with orig readv");
        return SYSCALL(readv, m_fd, p_iov, sz_iov);

    case RX_RECV:
        __log_info_func("calling os receive with orig recv");
        return SYSCALL(recv, m_fd, p_iov[0].iov_base, p_iov[0].iov_len, flags);

    case RX_RECVFROM:
        __log_info_func("calling os receive with orig recvfrom");
        return SYSCALL(recvfrom, m_fd, p_iov[0].iov_base, p_iov[0].iov_len, flags, __from,
                       __fromlen);

    case RX_RECVMSG: {
        __log_info_func("calling os receive with orig recvmsg");
        return SYSCALL(recvmsg, m_fd, __msg, flags);
    }
    }
    return (ssize_t)-1;
}

ssize_t sockinfo::tx_os(const tx_call_t call_type, const iovec *p_iov, const ssize_t sz_iov,
                        const int __flags, const sockaddr *__to, const socklen_t __tolen)
{
    errno = 0;

    // Ignore dummy messages for OS
    if (unlikely(IS_DUMMY_PACKET(__flags))) {
        errno = EINVAL;
        return -1;
    }

    switch (call_type) {
    case TX_WRITE:
        __log_info_func("calling os transmit with orig write");
        return SYSCALL(write, m_fd, p_iov[0].iov_base, p_iov[0].iov_len);

    case TX_WRITEV:
        __log_info_func("calling os transmit with orig writev");
        return SYSCALL(writev, m_fd, p_iov, sz_iov);

    case TX_SEND:
        __log_info_func("calling os transmit with orig send");
        return SYSCALL(send, m_fd, p_iov[0].iov_base, p_iov[0].iov_len, __flags);

    case TX_SENDTO:
        __log_info_func("calling os transmit with orig sendto");
        return SYSCALL(sendto, m_fd, p_iov[0].iov_base, p_iov[0].iov_len, __flags, __to, __tolen);

    case TX_SENDMSG: {
        msghdr __message;
        memset(&__message, 0, sizeof(__message));
        __message.msg_iov = (iovec *)p_iov;
        __message.msg_iovlen = sz_iov;
        __message.msg_name = (void *)__to;
        __message.msg_namelen = __tolen;

        __log_info_func("calling os transmit with orig sendmsg");
        return SYSCALL(sendmsg, m_fd, &__message, __flags);
    }
    default:
        __log_info_func("calling undefined os call type!");
        break;
    }
    return (ssize_t)-1;
}

int sockinfo::handle_exception_flow()
{
    if (safe_mce_sys().exception_handling.is_suit_un_offloading()) {
        try_un_offloading();
    }
    if (safe_mce_sys().exception_handling == xlio_exception_handling::MODE_RETURN_ERROR) {
        errno = EINVAL;
        return -1;
    }
    if (safe_mce_sys().exception_handling == xlio_exception_handling::MODE_ABORT) {
        return -2;
    }
    return 0;
}

bool sockinfo::skip_os_select()
{
    // If safe_mce_sys().select_poll_os_ratio == 0, it means that user configured XLIO not to poll
    // os (i.e. TRUE...)
    return (!safe_mce_sys().select_poll_os_ratio);
}

bool sockinfo::is_xlio_socket() const
{
    return m_is_xlio_socket;
}

poll_group *sockinfo::get_poll_group() const
{
    return m_p_group;
}
