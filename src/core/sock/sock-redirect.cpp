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

// sock-redirect-internal.h must be first
#include "sock-redirect-internal.h"
#include "sock-redirect.h"

#include <sys/time.h>
#include <dlfcn.h>
#include <iostream>
#include <fcntl.h>

#include "utils/compiler.h"
#include "utils/lock_wrapper.h"
#include <proto/ip_frag.h>
#include <dev/buffer_pool.h>
#include <event/thread_local_event_handler.h>
#include <event/vlogger_timer_handler.h>
#include <iomux/poll_call.h>
#include <iomux/select_call.h>
#include <iomux/epfd_info.h>
#include <iomux/epoll_wait_call.h>
#include <util/sys_vars.h>
#include <proto/mapping.h>
#include <proto/xlio_lwip.h>
#include <main.h>
#include "xlio_extra.h"

#include <sock/sockinfo_tcp.h>
#include <sock/sockinfo_udp.h>

#include "fd_collection.h"
#include "util/instrumentation.h"

using namespace std;

#define MODULE_NAME "srdr:"

#define srdr_logpanic   __log_panic
#define srdr_logerr     __log_err
#define srdr_logwarn    __log_warn
#define srdr_loginfo    __log_info
#define srdr_logdbg     __log_dbg
#define srdr_logfunc    __log_func
#define srdr_logfuncall __log_funcall

#define srdr_logdbg_entry     __log_entry_dbg
#define srdr_logfunc_entry    __log_entry_func
#define srdr_logfuncall_entry __log_entry_funcall

#define srdr_logdbg_exit  __log_exit_dbg
#define srdr_logfunc_exit __log_exit_func

#define EP_MAX_EVENTS (int)((INT_MAX / sizeof(struct epoll_event)))

#if defined(DEFINED_NGINX)
map_udp_bounded_port_t g_map_udp_bounded_port;
#endif
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
struct app_conf *g_p_app = NULL;
#endif /* DEFINED_ENVOY */

struct os_api orig_os_api;
struct sigaction g_act_prev;
sighandler_t g_sighandler = NULL;
class ring_simple;
class ring_eth_direct;

template <typename T> void assign_dlsym(T &ptr, const char *name)
{
    ptr = reinterpret_cast<T>(dlsym(RTLD_NEXT, name));
}

#define FD_MAP_SIZE (g_p_fd_collection ? g_p_fd_collection->get_fd_map_size() : 1024)

#define DO_GLOBAL_CTORS()                                                                          \
    do {                                                                                           \
        int __res = do_global_ctors();                                                             \
        if (__res) {                                                                               \
            vlog_printf(VLOG_ERROR, "%s " PRODUCT_NAME " failed to start errno: %s\n",             \
                        __FUNCTION__, strerror(errno));                                            \
            if (safe_mce_sys().exception_handling == xlio_exception_handling::MODE_EXIT) {         \
                exit(-1);                                                                          \
            }                                                                                      \
            return -1;                                                                             \
        }                                                                                          \
    } while (0)

#define GET_ORIG_FUNC(__name)                                                                      \
    if (!orig_os_api.__name) {                                                                     \
        dlerror();                                                                                 \
        assign_dlsym(orig_os_api.__name, #__name);                                                 \
        const char *fcntlstr = "fcntl64";                                                          \
        char *dlerror_str = dlerror();                                                             \
        if (!orig_os_api.__name || dlerror_str) {                                                  \
            if (strcmp(fcntlstr, #__name) != 0) {                                                  \
                __log_warn("dlsym returned with error '%s' when looking for '%s'",                 \
                           (!dlerror_str ? "" : dlerror_str), #__name);                            \
            } else {                                                                               \
                __log_dbg("dlsym returned with error '%s' when looking for '%s'",                  \
                          (!dlerror_str ? "" : dlerror_str), #__name);                             \
            }                                                                                      \
        } else {                                                                                   \
            __log_dbg("dlsym found %p for '%s()'", orig_os_api.__name, #__name);                   \
        }                                                                                          \
    }

#define SET_EXTRA_API(__dst, __func, __mask)                                                       \
    do {                                                                                           \
        xlio_api->__dst = __func;                                                                  \
        xlio_api->cap_mask |= __mask;                                                              \
    } while (0);

#define VERIFY_PASSTROUGH_CHANGED(__ret, __func_and_params__)                                      \
    do {                                                                                           \
        bool passthrough = p_socket_object->isPassthrough();                                       \
        __ret = __func_and_params__;                                                               \
        if (!passthrough && p_socket_object->isPassthrough()) {                                    \
            handle_close(__fd, false, true);                                                       \
        }                                                                                          \
    } while (0);

void get_orig_funcs()
{
    // Save pointer to original functions
    GET_ORIG_FUNC(socket);
    GET_ORIG_FUNC(close);
    GET_ORIG_FUNC(__res_iclose);
    GET_ORIG_FUNC(shutdown);
    GET_ORIG_FUNC(listen);
    GET_ORIG_FUNC(accept);
    GET_ORIG_FUNC(accept4);
    GET_ORIG_FUNC(bind);
    GET_ORIG_FUNC(connect);
    GET_ORIG_FUNC(setsockopt);
    GET_ORIG_FUNC(getsockopt);
    GET_ORIG_FUNC(fcntl);
    GET_ORIG_FUNC(fcntl64);
    GET_ORIG_FUNC(ioctl);
    GET_ORIG_FUNC(getsockname);
    GET_ORIG_FUNC(getpeername);
    GET_ORIG_FUNC(read);
    GET_ORIG_FUNC(__read_chk);
    GET_ORIG_FUNC(readv);
    GET_ORIG_FUNC(recv);
    GET_ORIG_FUNC(__recv_chk);
    GET_ORIG_FUNC(recvmsg);
    GET_ORIG_FUNC(recvmmsg);
    GET_ORIG_FUNC(recvfrom);
    GET_ORIG_FUNC(__recvfrom_chk);
    GET_ORIG_FUNC(write);
    GET_ORIG_FUNC(writev);
    GET_ORIG_FUNC(send);
    GET_ORIG_FUNC(sendmsg);
    GET_ORIG_FUNC(sendmmsg);
    GET_ORIG_FUNC(sendto);
    GET_ORIG_FUNC(sendfile);
    GET_ORIG_FUNC(sendfile64);
    GET_ORIG_FUNC(select);
    GET_ORIG_FUNC(pselect);
    GET_ORIG_FUNC(poll);
    GET_ORIG_FUNC(__poll_chk);
    GET_ORIG_FUNC(ppoll);
    GET_ORIG_FUNC(__ppoll_chk);
    GET_ORIG_FUNC(epoll_create);
    GET_ORIG_FUNC(epoll_create1);
    GET_ORIG_FUNC(epoll_ctl);
    GET_ORIG_FUNC(epoll_wait);
    GET_ORIG_FUNC(epoll_pwait);
    GET_ORIG_FUNC(socketpair);
    GET_ORIG_FUNC(pipe);
    GET_ORIG_FUNC(open);
    GET_ORIG_FUNC(creat);
    GET_ORIG_FUNC(dup);
    GET_ORIG_FUNC(dup2);
    GET_ORIG_FUNC(clone);
    GET_ORIG_FUNC(fork);
    GET_ORIG_FUNC(vfork);
    GET_ORIG_FUNC(daemon);
    GET_ORIG_FUNC(sigaction);
    GET_ORIG_FUNC(signal);
#if defined(DEFINED_NGINX)
    GET_ORIG_FUNC(setuid);
    GET_ORIG_FUNC(waitpid);
#endif // DEFINED_NGINX
}

const char *socket_get_domain_str(int domain)
{
    switch (domain) {
    case AF_INET:
        return "AF_INET";
    case AF_INET6:
        return "AF_INET6";
    case AF_UNSPEC:
        return "AF_UNSPEC";
    case AF_LOCAL:
        return "AF_LOCAL";
    default:
        break;
    }
    return "";
}

const char *socket_get_type_str(int type)
{
    switch (type) {
    case SOCK_STREAM:
        return "SOCK_STREAM";
    case SOCK_DGRAM:
        return "SOCK_DGRAM";
    case SOCK_RAW:
        return "SOCK_RAW";
    default:
        break;
    }
    return "";
}

// Format a sockaddr into a string for logging
char *sprintf_sockaddr(char *buf, int buflen, const struct sockaddr *_addr, socklen_t _addrlen)
{
    sock_addr sa(_addr, _addrlen);

    snprintf(buf, buflen, "%s, addr=%s", socket_get_domain_str(sa.get_sa_family()),
             sa.to_str_ip_port(true).c_str());
    return buf;
}

bool handle_close(int fd, bool cleanup, bool passthrough)
{
    bool to_close_now = true;
    bool is_for_udp_pool = false;

    srdr_logfunc("Cleanup fd=%d", fd);

    if (g_zc_cache) {
        g_zc_cache->handle_close(fd);
    }

    if (g_p_fd_collection) {
        // Remove fd from all existing epoll sets
        g_p_fd_collection->remove_from_all_epfds(fd, passthrough);

        socket_fd_api *sockfd = fd_collection_get_sockfd(fd);
        if (sockfd) {
            // Don't call close(2) for objects without a shadow socket (TCP incoming sockets).
            to_close_now = !passthrough && sockfd->is_shadow_socket_present();
#if defined(DEFINED_NGINX)
            // Save this value before pointer is destructed
            is_for_udp_pool = sockfd->m_is_for_socket_pool;
#endif
            g_p_fd_collection->del_sockfd(fd, cleanup, is_for_udp_pool);
            if (safe_mce_sys().deferred_close) {
                to_close_now = false;
            }
        }
        if (fd_collection_get_epfd(fd)) {
            g_p_fd_collection->del_epfd(fd, cleanup);
        }

#if defined(DEFINED_NGINX)
        if (g_p_app && g_p_app->type == APP_NGINX && is_for_udp_pool) {
            g_p_fd_collection->push_socket_pool(sockfd);
            to_close_now = false;
        }
#else
        NOT_IN_USE(is_for_udp_pool);
#endif
    }

    return to_close_now;
}

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)

static int init_worker(int worker_id, int listen_fd)
{
    srdr_logdbg("worker: %d fd: %d", worker_id, listen_fd);

    int ret = 0;
    socket_fd_api *child_sock_fd_api = nullptr;
    int parent_fd = listen_fd;
    fd_collection *p_fd_collection = (fd_collection *)g_p_app->context;

    /* Find information about parent socket
     * Envoy:
     * - g_p_fd_collection has all actual fds
     * - worker 0 has socket object in g_p_fd_collection (parent fd)
     * - Other workers should find parent fd to create child socket objects
     *   basing on parent socket objects.
     * Nginx:
     * - should use fd_collection from parent process stored at g_p_app->context
     */
    if (g_p_app->type == APP_ENVOY) {
        p_fd_collection = g_p_fd_collection;
        if (worker_id > 0) {
            parent_fd = -1;
            const auto itr = g_p_app->map_dup_fd.find(listen_fd);
            if (itr != g_p_app->map_dup_fd.end()) {
                parent_fd = itr->second;
            }
            if (parent_fd < 0) {
                return -1;
            }
        } else {
            ret = -1;
            child_sock_fd_api = p_fd_collection->get_sockfd(listen_fd);
            if (child_sock_fd_api) {
                ret = child_sock_fd_api->listen(child_sock_fd_api->m_back_log);
            }
            return ret;
        }
    }

    /* This part should be ignored by Envoy worker 0
     * Envoy: parent_fd is fd of parent socket
     * Nginx: parent_fd is equal to listen_fd
     */
    sockinfo *si;
    socket_fd_api *parent_sock_fd_api = p_fd_collection->get_sockfd(parent_fd);
    if (!parent_sock_fd_api || !(si = dynamic_cast<sockinfo *>(parent_sock_fd_api))) {
        srdr_logerr("parent sockinfo is not found");
        return -1;
    }

    int block_type = si->is_blocking() ? 0 : SOCK_NONBLOCK;
    sock_addr sa;
    socklen_t sa_len = sa.get_socklen();

    parent_sock_fd_api->getsockname(sa.get_p_sa(), &sa_len);
    if (PROTO_TCP == si->get_protocol()) {
        srdr_logdbg("found listen socket %d", parent_sock_fd_api->get_fd());
        g_p_fd_collection->addsocket(listen_fd, si->get_family(), SOCK_STREAM | block_type);
        child_sock_fd_api = g_p_fd_collection->get_sockfd(listen_fd);
        if (child_sock_fd_api) {
            child_sock_fd_api->copy_sockopt_fork(parent_sock_fd_api);

            ret = bind(listen_fd, sa.get_p_sa(), sa_len);
            if (ret < 0) {
                srdr_logerr("bind() error");
            }

            // is the socket really offloaded
            ret = child_sock_fd_api->prepareListen();
            if (ret < 0) {
                srdr_logerr("prepareListen error");
                child_sock_fd_api = nullptr;
            } else if (ret > 0) { // Pass-through
                handle_close(child_sock_fd_api->get_fd(), false, true);
                child_sock_fd_api = nullptr;
            } else {
                srdr_logdbg("Prepare listen successfully offloaded");
            }

            if (child_sock_fd_api) {
                ret = child_sock_fd_api->listen(child_sock_fd_api->m_back_log);
                if (ret < 0) {
                    srdr_logerr("Listen error");
                } else {
                    srdr_logdbg("Listen success");
                }
            }
        }
    }
    if (PROTO_UDP == si->get_protocol()) {
        sockinfo_udp *udp_sock = dynamic_cast<sockinfo_udp *>(parent_sock_fd_api);
        if (udp_sock) {
            std::unordered_map<uint16_t, uint16_t> udp_sockets_per_port;
            int reuse_port;
            socklen_t optlen = sizeof(reuse_port);
            uint16_t port = ntohs(sa.get_in_port());
            if ((port == 0) ||
                (udp_sock->getsockopt(SOL_SOCKET, SO_REUSEPORT, &reuse_port, &optlen) < 0)) {
                return -1;
            }

            /*
             * Specific NGINX implementation.
             *
             * In case of "reuseport" directive
             * NGINX master process creates a UDP socket per worker process per port before it
             * forks. Therefore, each worker process attaches a single UDP socket out of
             * #worker_processes.
             *
             * Without "reuseport" directive, NGINX master process creates a single UDP socket
             * before it forks. Therefore, all worker processes attach the UDP socket (single).
             */
            if ((reuse_port == 0) || (udp_sockets_per_port[port] == g_p_app->get_worker_id())) {
                srdr_logdbg("worker %d is using fd=%d. bound to port=%d", g_p_app->get_worker_id(),
                            listen_fd, port);
                g_p_fd_collection->addsocket(listen_fd, si->get_family(), SOCK_DGRAM | block_type);
                sockinfo_udp *new_udp_sock =
                    dynamic_cast<sockinfo_udp *>(g_p_fd_collection->get_sockfd(listen_fd));
                if (new_udp_sock) {
                    new_udp_sock->copy_sockopt_fork(udp_sock);

                    g_map_udp_bounded_port[port] = true;
                    // in order to create new steering rules we call bind()
                    // we skip os.bind since it always fails
                    new_udp_sock->bind_no_os();
                }
            }
            udp_sockets_per_port[port]++;
        }
    }

    return 0;
}

#endif

//-----------------------------------------------------------------------------
// extended API functions
//-----------------------------------------------------------------------------

extern "C" int xlio_register_recv_callback(int __fd, xlio_recv_callback_t __callback,
                                           void *__context)
{
    srdr_logfunc_entry("fd=%d", __fd);

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object && !safe_mce_sys().enable_socketxtreme) {
        p_socket_object->register_callback(__callback, __context);
        return 0;
    }
    errno = EINVAL;
    return -1;
}

extern "C" int xlio_recvfrom_zcopy(int __fd, void *__buf, size_t __nbytes, int *__flags,
                                   struct sockaddr *__from, socklen_t *__fromlen)
{
    srdr_logfuncall_entry("fd=%d", __fd);

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        struct iovec piov[1];
        piov[0].iov_base = __buf;
        piov[0].iov_len = __nbytes;
        *__flags |= MSG_XLIO_ZCOPY;
        return p_socket_object->rx(RX_RECVFROM, piov, 1, __flags, __from, __fromlen);
    }
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.recvfrom) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    return orig_os_api.recvfrom(__fd, __buf, __nbytes, *__flags, __from, __fromlen);
}

extern "C" int xlio_recvfrom_zcopy_free_packets(int __fd, struct xlio_recvfrom_zcopy_packet_t *pkts,
                                                size_t count)
{
    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        return p_socket_object->recvfrom_zcopy_free_packets(pkts, count);
    }

    errno = EINVAL;
    return -1;
}

static int dummy_xlio_socketxtreme_poll(int fd, struct xlio_socketxtreme_completion_t *completions,
                                        unsigned int ncompletions, int flags)
{
    NOT_IN_USE(fd);
    NOT_IN_USE(completions);
    NOT_IN_USE(ncompletions);
    NOT_IN_USE(flags);
    VLOG_PRINTF_ONCE_THEN_ALWAYS(
        VLOG_WARNING, VLOG_DEBUG,
        "socketXtreme was not enabled during runtime. Set %s to use. Ignoring...",
        SYS_VAR_SOCKETXTREME);
    errno = EOPNOTSUPP;
    return -1;
}

extern "C" int xlio_socketxtreme_poll(int fd, struct xlio_socketxtreme_completion_t *completions,
                                      unsigned int ncompletions, int flags)
{
    int ret_val = -1;
    cq_channel_info *cq_ch_info = NULL;

    cq_ch_info = g_p_fd_collection->get_cq_channel_fd(fd);

    if (safe_mce_sys().tcp_ctl_thread == option_tcp_ctl_thread::CTL_THREAD_DELEGATE_TCP_TIMERS) {
        g_thread_local_event_handler.do_tasks();
    }

    if (likely(cq_ch_info)) {
        ring *p_ring = cq_ch_info->get_ring();

        ret_val = p_ring->socketxtreme_poll(completions, ncompletions, flags);
#ifdef RDTSC_MEASURE_RX_PROCCESS_BUFFER_TO_RECIVEFROM
        RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_PROCCESS_RX_BUFFER_TO_RECIVEFROM]);
#endif // RDTSC_MEASURE_RX_PROCCESS_BUFFER_TO_RECIVEFROM

#ifdef RDTSC_MEASURE_RX_LWIP_TO_RECEVEFROM
        RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_LWIP_TO_RECEVEFROM]);
#endif // RDTSC_MEASURE_RX_LWIP_TO_RECEVEFROM

#ifdef RDTSC_MEASURE_RX_CQE_RECEIVEFROM
        RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM]);
#endif // RDTSC_MEASURE_RX_CQE_RECEIVEFROM

#ifdef RDTSC_MEASURE_RECEIVEFROM_TO_SENDTO
        RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_RECEIVEFROM_TO_SENDTO]);
#endif // RDTSC_MEASURE_RECEIVEFROM_TO_SENDTO
        return ret_val;
    } else {
        errno = EBADFD;
        return ret_val;
    }
}

static int dummy_xlio_socketxtreme_free_packets(struct xlio_socketxtreme_packet_desc_t *packets,
                                                int num)
{
    NOT_IN_USE(packets);
    NOT_IN_USE(num);
    VLOG_PRINTF_ONCE_THEN_ALWAYS(
        VLOG_WARNING, VLOG_DEBUG,
        "socketXtreme was not enabled during runtime. Set %s to use. Ignoring...",
        SYS_VAR_SOCKETXTREME);
    errno = EOPNOTSUPP;
    return -1;
}

extern "C" int xlio_socketxtreme_free_packets(struct xlio_socketxtreme_packet_desc_t *packets,
                                              int num)
{
    mem_buf_desc_t *desc = NULL;
    sockinfo_tcp *p_socket_object = NULL;

    if (likely(packets)) {
        for (int i = 0; i < num; i++) {
            desc = reinterpret_cast<mem_buf_desc_t *>(packets[i].buff_lst);
            if (likely(desc)) {
                p_socket_object = reinterpret_cast<sockinfo_tcp *>(desc->rx.context);
                if (likely(p_socket_object)) {
                    p_socket_object->socketxtreme_recv_buffs_tcp(desc, packets[i].total_len);
                } else {
                    ring_slave *rng = desc->p_desc_owner;
                    if (!rng || !rng->reclaim_recv_buffers(desc)) {
                        g_buffer_pool_rx_ptr->put_buffers_thread_safe(desc);
                    }
                }
            } else {
                goto err;
            }
        }
    } else {
        goto err;
    }

    return 0;

err:
    errno = EINVAL;
    return -1;
}

static int dummy_xlio_socketxtreme_ref_buff(xlio_buff_t *buff)
{
    NOT_IN_USE(buff);
    VLOG_PRINTF_ONCE_THEN_ALWAYS(
        VLOG_WARNING, VLOG_DEBUG,
        "socketXtreme was not enabled during runtime. Set %s to use. Ignoring...",
        SYS_VAR_SOCKETXTREME);
    errno = EOPNOTSUPP;
    return -1;
}

extern "C" int xlio_socketxtreme_ref_buff(xlio_buff_t *buff)
{
    int ret_val = 0;
    mem_buf_desc_t *desc = NULL;

    if (likely(buff)) {
        desc = (mem_buf_desc_t *)buff;
        ret_val = desc->lwip_pbuf_inc_ref_count();
    } else {
        errno = EINVAL;
        ret_val = -1;
    }
    return ret_val;
}

static int dummy_xlio_socketxtreme_free_buff(xlio_buff_t *buff)
{
    NOT_IN_USE(buff);
    VLOG_PRINTF_ONCE_THEN_ALWAYS(
        VLOG_WARNING, VLOG_DEBUG,
        "socketXtreme was not enabled during runtime. Set %s to use. Ignoring...",
        SYS_VAR_SOCKETXTREME);
    errno = EOPNOTSUPP;
    return -1;
}

extern "C" int xlio_socketxtreme_free_buff(xlio_buff_t *buff)
{
    int ret_val = 0;
    mem_buf_desc_t *desc = NULL;

    if (likely(buff)) {
        desc = (mem_buf_desc_t *)buff;
        ring_slave *rng = desc->p_desc_owner;
        ret_val = rng->reclaim_recv_single_buffer(desc);
    } else {
        errno = EINVAL;
        ret_val = -1;
    }
    return ret_val;
}

extern "C" int xlio_get_socket_rings_num(int fd)
{
    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(fd);
    if (p_socket_object && p_socket_object->check_rings()) {
        return p_socket_object->get_rings_num();
    }

    return 0;
}

extern "C" int xlio_get_socket_rings_fds(int fd, int *ring_fds, int ring_fds_sz)
{
    if (ring_fds_sz <= 0 || ring_fds == NULL) {
        errno = EINVAL;
        return -1;
    }

    socket_fd_api *p_socket_object = fd_collection_get_sockfd(fd);
    if (p_socket_object && p_socket_object->check_rings()) {
        int rings_num = 0;
        int *p_rings_fds = p_socket_object->get_rings_fds(rings_num);
        int num_rings_to_copy = min(ring_fds_sz, rings_num);
        std::copy(&p_rings_fds[0], &p_rings_fds[num_rings_to_copy], ring_fds);
        return num_rings_to_copy;
    }

    return 0;
}

extern "C" int xlio_add_conf_rule(const char *config_line)
{
    srdr_logdbg("adding conf rule: %s", config_line);

    int ret = __xlio_parse_config_line(config_line);

    if (*g_p_vlogger_level >= VLOG_DEBUG) {
        __xlio_print_conf_file(__instance_list);
    }

    return ret;
}

extern "C" int xlio_thread_offload(int offload, pthread_t tid)
{
    if (g_p_fd_collection) {
        g_p_fd_collection->offloading_rule_change_thread(offload, tid);
    } else {
        return -1;
    }

    return 0;
}

extern "C" int xlio_dump_fd_stats(int fd, int log_level)
{
    if (g_p_fd_collection) {
        g_p_fd_collection->statistics_print(fd, log_level::from_int(log_level));
        return 0;
    }
    return -1;
}

static inline struct cmsghdr *__cmsg_nxthdr(void *__ctl, size_t __size, struct cmsghdr *__cmsg)
{
    struct cmsghdr *__ptr;

    __ptr = (struct cmsghdr *)(((unsigned char *)__cmsg) + CMSG_ALIGN(__cmsg->cmsg_len));
    if ((unsigned long)((char *)(__ptr + 1) - (char *)__ctl) > __size) {
        return NULL;
    }

    return __ptr;
}

extern "C" int xlio_ioctl(void *cmsg_hdr, size_t cmsg_len)
{
    struct cmsghdr *cmsg = (struct cmsghdr *)cmsg_hdr;

    for (; cmsg; cmsg = __cmsg_nxthdr((struct cmsghdr *)cmsg_hdr, cmsg_len, cmsg)) {
        if (cmsg->cmsg_type == CMSG_XLIO_IOCTL_USER_ALLOC) {

            if (!g_init_global_ctors_done &&
                (cmsg->cmsg_len - CMSG_LEN(0)) ==
                    (sizeof(uint8_t) + sizeof(alloc_t) + sizeof(free_t))) {
                uint8_t *ptr = (uint8_t *)CMSG_DATA(cmsg);

                memcpy(&safe_mce_sys().m_ioctl.user_alloc.flags, ptr, sizeof(uint8_t));
                ptr += sizeof(uint8_t);
                memcpy(&safe_mce_sys().m_ioctl.user_alloc.memalloc, ptr, sizeof(alloc_t));
                ptr += sizeof(alloc_t);
                memcpy(&safe_mce_sys().m_ioctl.user_alloc.memfree, ptr, sizeof(free_t));
                if (!(safe_mce_sys().m_ioctl.user_alloc.memalloc &&
                      safe_mce_sys().m_ioctl.user_alloc.memfree)) {
                    srdr_logdbg("Invalid data for CMSG_XLIO_IOCTL_USER_ALLOC");
                    errno = EINVAL;
                    return -1;
                }
            } else {
                errno = EINVAL;
                return -1;
            }
        }
    }

    return 0;
}

//-----------------------------------------------------------------------------
//  replacement functions
//-----------------------------------------------------------------------------

/* Create a new socket of type TYPE in domain DOMAIN, using
   protocol PROTOCOL.  If PROTOCOL is zero, one is chosen automatically.
   Returns a file descriptor for the new socket, or -1 for errors.  */
extern "C" EXPORT_SYMBOL int socket(int __domain, int __type, int __protocol)
{
    return socket_internal(__domain, __type, __protocol, true, true);
}

/* Internal logic of socket() syscall implementation. It can be called from within XLIO, for
   example, to create a socket for an incoming TCP connection.  */
int socket_internal(int __domain, int __type, int __protocol, bool shadow, bool check_offload)
{
    int fd;
    bool offload_sockets = (__domain == AF_INET || __domain == AF_INET6) &&
        ((__type & 0xf) == SOCK_DGRAM || (__type & 0xf) == SOCK_STREAM);

    if (offload_sockets) {
        DO_GLOBAL_CTORS();
    }

    PROFILE_BLOCK("socket")
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.socket) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

#if defined(DEFINED_NGINX)
    bool add_to_udp_pool = false;
    if (g_p_app && g_p_app->type == APP_NGINX && g_p_fd_collection && offload_sockets &&
        g_p_fd_collection->pop_socket_pool(fd, add_to_udp_pool, __type & 0xf)) {
        return fd;
    }
#endif

    fd = SOCKET_FAKE_FD;
    if (shadow || !offload_sockets || !g_p_fd_collection) {
        fd = orig_os_api.socket(__domain, __type, __protocol);
        vlog_printf(VLOG_DEBUG, "ENTER: %s(domain=%s(%d), type=%s(%d), protocol=%d) = %d\n",
                    __func__, socket_get_domain_str(__domain), __domain,
                    socket_get_type_str(__type), __type, __protocol, fd);
        if (fd < 0) {
            return fd;
        }
    }

    if (g_p_fd_collection && offload_sockets) {
        // Create new sockinfo object for this socket
        int fd2 = g_p_fd_collection->addsocket(fd, __domain, __type, check_offload);
        if (fd == SOCKET_FAKE_FD) {
            fd = fd2;
        }
        /* If shadow socket is created, but XLIO object fails, we still return shadow socket
           fd and such a socket won't be offloaded.  */

#if defined(DEFINED_NGINX)
        if (g_p_app && g_p_app->type == APP_NGINX && add_to_udp_pool) {
            g_p_fd_collection->handle_socket_pool(fd);
        }
#endif
    }

    return fd;
}

extern "C" EXPORT_SYMBOL int close(int __fd)
{
    PROFILE_FUNC

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.close) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    srdr_logdbg_entry("fd=%d", __fd);

    bool toclose = handle_close(__fd);
    int rc = toclose ? orig_os_api.close(__fd) : 0;

    return rc;
}

extern "C" EXPORT_SYMBOL void __res_iclose(res_state statp, bool free_addr)
{
    PROFILE_FUNC

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.__res_iclose) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    /* Current implementation doesn't handle XLIO sockets without a shadow socket or from a socket
       pool. If such a socket is present in the nssocks list, system __res_iclose() will close the
       fd. This will break the socket functionality.
       Assume that resolver doesn't use the above scenarios.  */

    srdr_logdbg_entry("");
    for (int ns = 0; ns < statp->_u._ext.nscount; ns++) {
        int sock = statp->_u._ext.nssocks[ns];
        if (sock != -1) {
            handle_close(sock);
        }
    }
    orig_os_api.__res_iclose(statp, free_addr);
}

/* Shut down all or part of the connection open on socket FD.
   HOW determines what to shut down:
     SHUT_RD   = No more receptions;
     SHUT_WR   = No more transmissions;
     SHUT_RDWR = No more receptions or transmissions.
   Returns 0 on success, -1 for errors.  */
extern "C" EXPORT_SYMBOL int shutdown(int __fd, int __how)
{
    PROFILE_FUNC

    srdr_logdbg_entry("fd=%d, how=%d", __fd, __how);

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        return p_socket_object->shutdown(__how);
    }

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.shutdown) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return orig_os_api.shutdown(__fd, __how);
}

extern "C" EXPORT_SYMBOL int listen(int __fd, int backlog)
{
    PROFILE_FUNC

    srdr_logdbg_entry("fd=%d, backlog=%d", __fd, backlog);

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    if (g_p_app && g_p_app->type != APP_NONE) {
        /* Envoy:
         * Envoy uses dup() call for listen socket on workers_N (N > 0)
         * dup() call does not create socket object and does not store fd
         * in fd_collection in current implementation
         * so as a result duplicated fd is not returned by fd_collection_get_sockfd(__fd) and
         * listen() call for duplicated fds are ignored.
         * Original listen socket is not ignored by listen() function.
         *
         * Store all duplicated fd in map_listen_fd with tid
         * Store all listen fd in map_listen_fd with tid
         * Identify correct listen fd during epoll_ctl(ADD) call by tid. It should be different.
         *
         * Nginx:
         * Nginx store all listen fd in map_listen_fd to proceed later in children processes
         * after fork() call.
         */
        std::lock_guard<decltype(g_p_app->m_lock)> lock(g_p_app->m_lock);
        g_p_app->map_listen_fd[__fd] = gettid();
    }
#endif /* DEFINED_ENVOY */

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);

    if (p_socket_object) {
        // for verifying that the socket is really offloaded
        int ret = p_socket_object->prepareListen();
        if (ret < 0) {
            return ret; // error
        }
        if (ret > 0) { // Passthrough
            handle_close(__fd, false, true);
        } else {
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
            if (g_p_app->type != APP_NONE) {
                p_socket_object->m_back_log = backlog;
            } else
#endif
            {
                return p_socket_object->listen(backlog);
            }
        }
    }

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.listen) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    srdr_logdbg("OS listen fd=%d, backlog=%d", __fd, backlog);
    return orig_os_api.listen(__fd, backlog);
}

extern "C" EXPORT_SYMBOL int accept(int __fd, struct sockaddr *__addr, socklen_t *__addrlen)
{
    PROFILE_FUNC

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        return p_socket_object->accept(__addr, __addrlen);
    }

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.accept) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return orig_os_api.accept(__fd, __addr, __addrlen);
}

extern "C" EXPORT_SYMBOL int accept4(int __fd, struct sockaddr *__addr, socklen_t *__addrlen,
                                     int __flags)
{
    PROFILE_FUNC

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        return p_socket_object->accept4(__addr, __addrlen, __flags);
    }

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.accept4) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return orig_os_api.accept4(__fd, __addr, __addrlen, __flags);
}

/* Give the socket FD the local address ADDR (which is LEN bytes long).  */
extern "C" EXPORT_SYMBOL int bind(int __fd, const struct sockaddr *__addr, socklen_t __addrlen)
{
    int errno_tmp = errno;

    PROFILE_FUNC

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.bind) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    char buf[256];
    NOT_IN_USE(buf); /* to suppress warning in case MAX_DEFINED_LOG_LEVEL */
    srdr_logdbg_entry("fd=%d, %s", __fd, sprintf_sockaddr(buf, 256, __addr, __addrlen));

    int ret = 0;
    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        ret = p_socket_object->bind(__addr, __addrlen);
        if (p_socket_object->isPassthrough()) {
            handle_close(__fd, false, true);
            if (ret) {
                ret = orig_os_api.bind(__fd, __addr, __addrlen);
            }
        }
    } else {
        ret = orig_os_api.bind(__fd, __addr, __addrlen);
    }

    if (ret >= 0) {
        /* Restore errno on function entry in case success */
        errno = errno_tmp;
        srdr_logdbg_exit("returned with %d", ret);
    } else {
        srdr_logdbg_exit("failed (errno=%d %m)", errno);
    }

    return ret;
}

/* Open a connection on socket FD to peer at ADDR (which LEN bytes long).
   For connectionless socket types, just set the default address to send to
   and the only address from which to accept transmissions.
   Return 0 on success, -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C" EXPORT_SYMBOL int connect(int __fd, const struct sockaddr *__to, socklen_t __tolen)
{
    int errno_tmp = errno;

    PROFILE_FUNC

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.connect) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    char buf[256];
    NOT_IN_USE(buf); /* to suppress warning in case MAX_DEFINED_LOG_LEVEL */
    srdr_logdbg_entry("fd=%d, %s", __fd, sprintf_sockaddr(buf, 256, __to, __tolen));

    int ret = 0;
    socket_fd_api *p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object == nullptr) {
        srdr_logdbg_exit("Unable to get sock_fd_api");
        ret = orig_os_api.connect(__fd, __to, __tolen);
    } else if (__to == nullptr ||
               (get_sa_family(__to) != AF_INET && (get_sa_family(__to) != AF_INET6))) {
        p_socket_object->setPassthrough();
        ret = orig_os_api.connect(__fd, __to, __tolen);
    } else {
        ret = p_socket_object->connect(__to, __tolen);
        if (p_socket_object->isPassthrough()) {
            handle_close(__fd, false, true);
            if (ret) {
                ret = orig_os_api.connect(__fd, __to, __tolen);
            }
        }
    }
    if (ret >= 0) {
        /* Restore errno on function entry in case success */
        errno = errno_tmp;
        srdr_logdbg_exit("returned with %d", ret);
    } else {
        srdr_logdbg_exit("failed (errno=%d %m)", errno);
    }

    return ret;
}

/* Set socket FD's option OPTNAME at protocol level LEVEL
   to *OPTVAL (which is OPTLEN bytes long).
   Returns 0 on success, -1 for errors.  */
extern "C" EXPORT_SYMBOL int setsockopt(int __fd, int __level, int __optname,
                                        __const void *__optval, socklen_t __optlen)
{
    srdr_logdbg_entry("fd=%d, level=%d, optname=%d", __fd, __level, __optname);

    if (NULL == __optval) {
        errno = EFAULT;
        return -1;
    }

    PROFILE_FUNC

    int ret = 0;
    socket_fd_api *p_socket_object = NULL;

    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        VERIFY_PASSTROUGH_CHANGED(
            ret, p_socket_object->setsockopt(__level, __optname, __optval, __optlen));
    } else {
        BULLSEYE_EXCLUDE_BLOCK_START
        if (!orig_os_api.setsockopt) {
            get_orig_funcs();
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        ret = orig_os_api.setsockopt(__fd, __level, __optname, __optval, __optlen);
    }

    if (ret >= 0) {
        srdr_logdbg_exit("returned with %d", ret);
    } else {
        srdr_logdbg_exit("failed (errno=%d %m)", errno);
    }
    return ret;
}

/* Get socket FD's option OPTNAME at protocol level LEVEL
   to *OPTVAL (which is OPTLEN bytes long).
   Returns 0 on success, -1 for errors.  */
extern "C" EXPORT_SYMBOL int getsockopt(int __fd, int __level, int __optname, void *__optval,
                                        socklen_t *__optlen)
{
    PROFILE_FUNC

    srdr_logdbg_entry("fd=%d, level=%d, optname=%d", __fd, __level, __optname);

    if (__fd == -2 && __level == SOL_SOCKET && __optname == SO_XLIO_GET_API && __optlen &&
        *__optlen >= sizeof(struct xlio_api_t *)) {
        static struct xlio_api_t *xlio_api = NULL;

        srdr_logdbg("User request for " PRODUCT_NAME " Extra API pointers");

        if (NULL == xlio_api) {
            bool enable_socketxtreme = safe_mce_sys().enable_socketxtreme;

            xlio_api = new struct xlio_api_t();

            memset(xlio_api, 0, sizeof(struct xlio_api_t));
            xlio_api->magic = XLIO_MAGIC_NUMBER;
            xlio_api->cap_mask = 0;
            SET_EXTRA_API(register_recv_callback, xlio_register_recv_callback,
                          XLIO_EXTRA_API_REGISTER_RECV_CALLBACK);
            SET_EXTRA_API(recvfrom_zcopy, xlio_recvfrom_zcopy, XLIO_EXTRA_API_RECVFROM_ZCOPY);
            SET_EXTRA_API(recvfrom_zcopy_free_packets, xlio_recvfrom_zcopy_free_packets,
                          XLIO_EXTRA_API_RECVFROM_ZCOPY_FREE_PACKETS);
            SET_EXTRA_API(add_conf_rule, xlio_add_conf_rule, XLIO_EXTRA_API_ADD_CONF_RULE);
            SET_EXTRA_API(thread_offload, xlio_thread_offload, XLIO_EXTRA_API_THREAD_OFFLOAD);
            SET_EXTRA_API(get_socket_rings_num, xlio_get_socket_rings_num,
                          XLIO_EXTRA_API_GET_SOCKET_RINGS_NUM);
            SET_EXTRA_API(get_socket_rings_fds, xlio_get_socket_rings_fds,
                          XLIO_EXTRA_API_GET_SOCKET_RINGS_FDS);
            SET_EXTRA_API(
                socketxtreme_poll,
                enable_socketxtreme ? xlio_socketxtreme_poll : dummy_xlio_socketxtreme_poll,
                XLIO_EXTRA_API_SOCKETXTREME_POLL);
            SET_EXTRA_API(socketxtreme_free_packets,
                          enable_socketxtreme ? xlio_socketxtreme_free_packets
                                              : dummy_xlio_socketxtreme_free_packets,
                          XLIO_EXTRA_API_SOCKETXTREME_FREE_PACKETS);
            SET_EXTRA_API(
                socketxtreme_ref_buff,
                enable_socketxtreme ? xlio_socketxtreme_ref_buff : dummy_xlio_socketxtreme_ref_buff,
                XLIO_EXTRA_API_SOCKETXTREME_REF_XLIO_BUFF);
            SET_EXTRA_API(socketxtreme_free_buff,
                          enable_socketxtreme ? xlio_socketxtreme_free_buff
                                              : dummy_xlio_socketxtreme_free_buff,
                          XLIO_EXTRA_API_SOCKETXTREME_FREE_XLIO_BUFF);
            SET_EXTRA_API(dump_fd_stats, xlio_dump_fd_stats, XLIO_EXTRA_API_DUMP_FD_STATS);
            SET_EXTRA_API(ioctl, xlio_ioctl, XLIO_EXTRA_API_IOCTL);
        }

        *((xlio_api_t **)__optval) = xlio_api;
        *__optlen = sizeof(struct xlio_api_t *);
        return 0;
    }

    int ret = 0;
    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        VERIFY_PASSTROUGH_CHANGED(
            ret, p_socket_object->getsockopt(__level, __optname, __optval, __optlen));
    } else {
        BULLSEYE_EXCLUDE_BLOCK_START
        if (!orig_os_api.getsockopt) {
            get_orig_funcs();
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        ret = orig_os_api.getsockopt(__fd, __level, __optname, __optval, __optlen);
    }

    if (ret >= 0) {
        srdr_logdbg_exit("returned with %d", ret);
    } else {
        srdr_logdbg_exit("failed (errno=%d %m)", errno);
    }
    return ret;
}

/* Do the file control operation described by CMD on FD.
   The remaining arguments are interpreted depending on CMD.

   This function is a cancellation point and therefore not marked with
   __THROW.
   NOTE: XLIO throw will never occur during handling of any command.
   XLIO will only throw in case XLIO doesn't know to handle a command and the
   user requested explicitly that XLIO will throw an exception in such a case
   by setting XLIO_EXCEPTION_HANDLING accordingly (see README.txt)
   */
extern "C" EXPORT_SYMBOL int fcntl(int __fd, int __cmd, ...)
{
    PROFILE_FUNC

    srdr_logfunc_entry("fd=%d, cmd=%d", __fd, __cmd);

    int res = -1;
    va_list va;
    va_start(va, __cmd);
    unsigned long int arg = va_arg(va, unsigned long int);
    va_end(va);

    int ret = 0;
    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        VERIFY_PASSTROUGH_CHANGED(res, p_socket_object->fcntl(__cmd, arg));
    } else {
        BULLSEYE_EXCLUDE_BLOCK_START
        if (!orig_os_api.fcntl) {
            get_orig_funcs();
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        res = orig_os_api.fcntl(__fd, __cmd, arg);
    }

    if (__cmd == F_DUPFD) {
        handle_close(__fd);
    }

    if (ret >= 0) {
        srdr_logfunc_exit("returned with %d", ret);
    } else {
        srdr_logfunc_exit("failed (errno=%d %m)", errno);
    }
    return res;
}

/* Do the file control operation described by CMD on FD.
   The remaining arguments are interpreted depending on CMD.

   This function is a cancellation point and therefore not marked with
   __THROW.
   NOTE: XLIO throw will never occur during handling of any command.
   XLIO will only throw in case XLIO doesn't know to handle a command and the
   user requested explicitly that XLIO will throw an exception in such a case
   by setting XLIO_EXCEPTION_HANDLING accordingly (see README.txt)
   */

extern "C" EXPORT_SYMBOL int fcntl64(int __fd, int __cmd, ...)
{
    PROFILE_FUNC

    srdr_logfunc_entry("fd=%d, cmd=%d", __fd, __cmd);

    int res = -1;
    va_list va;
    va_start(va, __cmd);
    unsigned long int arg = va_arg(va, unsigned long int);
    va_end(va);

    int ret = 0;
    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.fcntl64) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    if (p_socket_object && orig_os_api.fcntl64) {
        VERIFY_PASSTROUGH_CHANGED(res, p_socket_object->fcntl64(__cmd, arg));
    } else {
        if (!orig_os_api.fcntl64) {
            srdr_logfunc_exit("failed (errno=%d %m)", errno);
            VLOG_PRINTF_ONCE_THEN_ALWAYS(VLOG_ERROR, VLOG_DEBUG,
                                         "fcntl64 was not found during runtime. Set %s to "
                                         "appripriate debug level to see datails. Ignoring...",
                                         SYS_VAR_LOG_LEVEL);
            errno = EOPNOTSUPP;
            return -1;
        } else {
            res = orig_os_api.fcntl64(__fd, __cmd, arg);
        }
    }

    if (__cmd == F_DUPFD) {
        handle_close(__fd);
    }

    if (ret >= 0) {
        srdr_logfunc_exit("returned with %d", ret);
    } else {
        srdr_logfunc_exit("failed (errno=%d %m)", errno);
    }
    return res;
}

/* Perform the I/O control operation specified by REQUEST on FD.
   One argument may follow; its presence and type depend on REQUEST.
   Return value depends on REQUEST.  Usually -1 indicates error. */
extern "C" EXPORT_SYMBOL int ioctl(int __fd, unsigned long int __request, ...)
{
    PROFILE_FUNC

    srdr_logfunc_entry("fd=%d, request=%d", __fd, __request);

    int res = -1;
    va_list va;
    va_start(va, __request);
    unsigned long int arg = va_arg(va, unsigned long int);
    va_end(va);

    int ret = 0;

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object && arg) {
        VERIFY_PASSTROUGH_CHANGED(res, p_socket_object->ioctl(__request, arg));
    } else {
        BULLSEYE_EXCLUDE_BLOCK_START
        if (!orig_os_api.ioctl) {
            get_orig_funcs();
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        res = orig_os_api.ioctl(__fd, __request, arg);
    }

    if (ret >= 0) {
        srdr_logfunc_exit("returned with %d", ret);
    } else {
        srdr_logfunc_exit("failed (errno=%d %m)", errno);
    }
    return res;
}

extern "C" EXPORT_SYMBOL int getsockname(int __fd, struct sockaddr *__name, socklen_t *__namelen)
{
    PROFILE_FUNC

    srdr_logdbg_entry("fd=%d", __fd);

    int ret = 0;
    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        ret = p_socket_object->getsockname(__name, __namelen);

        if (safe_mce_sys().trigger_dummy_send_getsockname) {
            char buf[264] = {0};
            struct iovec msg_iov = {&buf, sizeof(buf)};
            struct msghdr msg = {NULL, 0, &msg_iov, 1, NULL, 0, 0};
            int ret_send = sendmsg(__fd, &msg, XLIO_SND_FLAGS_DUMMY);
            srdr_logdbg("Triggered dummy message for socket fd=%d (ret_send=%d)", __fd, ret_send);
            NOT_IN_USE(ret_send);
        }
    } else {
        BULLSEYE_EXCLUDE_BLOCK_START
        if (!orig_os_api.getsockname) {
            get_orig_funcs();
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        ret = orig_os_api.getsockname(__fd, __name, __namelen);
    }

    if (ret >= 0) {
        srdr_logdbg_exit("returned with %d", ret);
    } else {
        srdr_logdbg_exit("failed (errno=%d %m)", errno);
    }
    return ret;
}

extern "C" EXPORT_SYMBOL int getpeername(int __fd, struct sockaddr *__name, socklen_t *__namelen)
{
    PROFILE_FUNC

    srdr_logdbg_entry("fd=%d", __fd);

    int ret = 0;
    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        ret = p_socket_object->getpeername(__name, __namelen);
    } else {
        BULLSEYE_EXCLUDE_BLOCK_START
        if (!orig_os_api.getpeername) {
            get_orig_funcs();
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        ret = orig_os_api.getpeername(__fd, __name, __namelen);
    }

    if (ret >= 0) {
        srdr_logdbg_exit("returned with %d", ret);
    } else {
        srdr_logdbg_exit("failed (errno=%d %m)", errno);
    }
    return ret;
}

/* Read NBYTES into BUF from FD.  Return the
   number read, -1 for errors or 0 for EOF.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C" EXPORT_SYMBOL ssize_t read(int __fd, void *__buf, size_t __nbytes)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d", __fd);

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        struct iovec piov[1];
        piov[0].iov_base = __buf;
        piov[0].iov_len = __nbytes;
        int dummy_flags = 0;
        return p_socket_object->rx(RX_READ, piov, 1, &dummy_flags);
    }

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.read) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return orig_os_api.read(__fd, __buf, __nbytes);
}

#if defined HAVE___READ_CHK
/* Checks that the buffer is big enough to contain the number of bytes
 * the user requests to read. If the buffer is too small, aborts,
 * else read NBYTES into BUF from FD.  Return the
   number read, -1 for errors or 0 for EOF.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C" EXPORT_SYMBOL ssize_t __read_chk(int __fd, void *__buf, size_t __nbytes, size_t __buflen)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d", __fd);

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        BULLSEYE_EXCLUDE_BLOCK_START
        if (__nbytes > __buflen) {
            srdr_logpanic("buffer overflow detected");
        }
        BULLSEYE_EXCLUDE_BLOCK_END

        struct iovec piov[1];
        piov[0].iov_base = __buf;
        piov[0].iov_len = __nbytes;
        int dummy_flags = 0;
        return p_socket_object->rx(RX_READ, piov, 1, &dummy_flags);
    }
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.__read_chk) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return orig_os_api.__read_chk(__fd, __buf, __nbytes, __buflen);
}
#endif

/* Read COUNT blocks into VECTOR from FD.  Return the
   number of bytes read, -1 for errors or 0 for EOF.

   This function is a cancellation point and therefore not marked with
   __THROW.  */

extern "C" EXPORT_SYMBOL ssize_t readv(int __fd, const struct iovec *iov, int iovcnt)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d", __fd);

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        struct iovec *piov = (struct iovec *)iov;
        int dummy_flags = 0;
        return p_socket_object->rx(RX_READV, piov, iovcnt, &dummy_flags);
    }
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.readv) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return orig_os_api.readv(__fd, iov, iovcnt);
}

/* Read N bytes into BUF from socket FD.
   Returns the number read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C" EXPORT_SYMBOL ssize_t recv(int __fd, void *__buf, size_t __nbytes, int __flags)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d", __fd);

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        struct iovec piov[1];
        piov[0].iov_base = __buf;
        piov[0].iov_len = __nbytes;
        return p_socket_object->rx(RX_RECV, piov, 1, &__flags);
    }
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.recv) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return orig_os_api.recv(__fd, __buf, __nbytes, __flags);
}

#if defined HAVE___RECV_CHK
/* Checks that the buffer is big enough to contain the number of bytes
   the user requests to read. If the buffer is too small, aborts,
   else read N bytes into BUF from socket FD.
   Returns the number read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C" EXPORT_SYMBOL ssize_t __recv_chk(int __fd, void *__buf, size_t __nbytes, size_t __buflen,
                                            int __flags)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d", __fd);

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        BULLSEYE_EXCLUDE_BLOCK_START
        if (__nbytes > __buflen) {
            srdr_logpanic("buffer overflow detected");
        }
        BULLSEYE_EXCLUDE_BLOCK_END

        struct iovec piov[1];
        piov[0].iov_base = __buf;
        piov[0].iov_len = __nbytes;
        return p_socket_object->rx(RX_RECV, piov, 1, &__flags);
    }
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.__recv_chk) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return orig_os_api.__recv_chk(__fd, __buf, __nbytes, __buflen, __flags);
}
#endif

/* Receive a message as described by MESSAGE from socket FD.
   Returns the number of bytes read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C" EXPORT_SYMBOL ssize_t recvmsg(int __fd, struct msghdr *__msg, int __flags)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d", __fd);

    if (__msg == NULL) {
        srdr_logdbg("NULL msghdr");
        errno = EINVAL;
        return -1;
    }

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        __msg->msg_flags = 0;
        return p_socket_object->rx(RX_RECVMSG, __msg->msg_iov, __msg->msg_iovlen, &__flags,
                                   (__SOCKADDR_ARG)__msg->msg_name,
                                   (socklen_t *)&__msg->msg_namelen, __msg);
    }
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.recvmsg) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return orig_os_api.recvmsg(__fd, __msg, __flags);
}

/* The following definitions are for kernels previous to 2.6.32 which dont support recvmmsg */
#ifndef HAVE_STRUCT_MMSGHDR
#ifndef __INTEL_COMPILER
struct mmsghdr {
    struct msghdr msg_hdr; // Message header
    unsigned int msg_len; // Number of received bytes for header
};
#endif
#endif

#ifndef MSG_WAITFORONE
#define MSG_WAITFORONE 0x10000 // recvmmsg(): block until 1+ packets avail
#endif

/* Receive multiple messages as described by MESSAGE from socket FD.
   Returns the number of messages received or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C" EXPORT_SYMBOL
#ifdef RECVMMSG_WITH_CONST_TIMESPEC
    int
    recvmmsg(int __fd, struct mmsghdr *__mmsghdr, unsigned int __vlen, int __flags,
             const struct timespec *__timeout)
#else
    int
    recvmmsg(int __fd, struct mmsghdr *__mmsghdr, unsigned int __vlen, int __flags,
             struct timespec *__timeout)
#endif
{
    PROFILE_FUNC

    int num_of_msg = 0;
    struct timespec start_time = TIMESPEC_INITIALIZER, current_time = TIMESPEC_INITIALIZER,
                    delta_time = TIMESPEC_INITIALIZER;

    srdr_logfuncall_entry("fd=%d, mmsghdr length=%d flags=%x", __fd, __vlen, __flags);

    if (__mmsghdr == NULL) {
        srdr_logdbg("NULL mmsghdr");
        errno = EINVAL;
        return -1;
    }

    if (__timeout) {
        gettime(&start_time);
    }
    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        int ret = 0;
        for (unsigned int i = 0; i < __vlen; i++) {
            int flags = __flags;
            __mmsghdr[i].msg_hdr.msg_flags = 0;
            ret = p_socket_object->rx(
                RX_RECVMSG, __mmsghdr[i].msg_hdr.msg_iov, __mmsghdr[i].msg_hdr.msg_iovlen, &flags,
                (__SOCKADDR_ARG)__mmsghdr[i].msg_hdr.msg_name,
                (socklen_t *)&__mmsghdr[i].msg_hdr.msg_namelen, &__mmsghdr[i].msg_hdr);
            if (ret < 0) {
                break;
            }
            num_of_msg++;
            __mmsghdr[i].msg_len = ret;
            if ((i == 0) && (flags & MSG_WAITFORONE)) {
                __flags |= MSG_DONTWAIT;
            }
            if (__timeout) {
                gettime(&current_time);
                ts_sub(&current_time, &start_time, &delta_time);
                if (ts_cmp(&delta_time, __timeout, >)) {
                    break;
                }
            }
        }
        if (num_of_msg || ret == 0) {
            // todo save ret for so_error if ret != 0(see kernel)
            return num_of_msg;
        } else {
            return ret;
        }
    }
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.recvmmsg) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return orig_os_api.recvmmsg(__fd, __mmsghdr, __vlen, __flags, __timeout);
}

/* Read N bytes into BUF through socket FD.
   If ADDR is not NULL, fill in *ADDR_LEN bytes of it with tha address of
   the sender, and store the actual size of the address in *ADDR_LEN.
   Returns the number of bytes read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C" EXPORT_SYMBOL ssize_t recvfrom(int __fd, void *__buf, size_t __nbytes, int __flags,
                                          struct sockaddr *__from, socklen_t *__fromlen)
{
    ssize_t ret_val = 0;

    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d", __fd);

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        struct iovec piov[1];
        piov[0].iov_base = __buf;
        piov[0].iov_len = __nbytes;
        ret_val = p_socket_object->rx(RX_RECVFROM, piov, 1, &__flags, __from, __fromlen);
    } else {
        BULLSEYE_EXCLUDE_BLOCK_START
        if (!orig_os_api.recvfrom) {
            get_orig_funcs();
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        ret_val = orig_os_api.recvfrom(__fd, __buf, __nbytes, __flags, __from, __fromlen);
    }
#ifdef RDTSC_MEASURE_RX_PROCCESS_BUFFER_TO_RECIVEFROM
    RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_PROCCESS_RX_BUFFER_TO_RECIVEFROM]);
#endif // RDTSC_MEASURE_RX_PROCCESS_BUFFER_TO_RECIVEFROM

#ifdef RDTSC_MEASURE_RX_LWIP_TO_RECEVEFROM
    RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_LWIP_TO_RECEVEFROM]);
#endif // RDTSC_MEASURE_RX_LWIP_TO_RECEVEFROM

#ifdef RDTSC_MEASURE_RX_CQE_RECEIVEFROM
    RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM]);
#endif // RDTSC_MEASURE_RX_CQE_RECEIVEFROM

#ifdef RDTSC_MEASURE_RECEIVEFROM_TO_SENDTO
    RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_RECEIVEFROM_TO_SENDTO]);
#endif // RDTSC_MEASURE_RECEIVEFROM_TO_SENDTO
    return ret_val;
}

#if defined HAVE___RECVFROM_CHK
/* Checks that the buffer is big enough to contain the number of bytes
   the user requests to read. If the buffer is too small, aborts,
   else read N bytes into BUF through socket FD.
   If ADDR is not NULL, fill in *ADDR_LEN bytes of it with tha address of
   the sender, and store the actual size of the address in *ADDR_LEN.
   Returns the number of bytes read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C" EXPORT_SYMBOL ssize_t __recvfrom_chk(int __fd, void *__buf, size_t __nbytes,
                                                size_t __buflen, int __flags,
                                                struct sockaddr *__from, socklen_t *__fromlen)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d", __fd);

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        BULLSEYE_EXCLUDE_BLOCK_START
        if (__nbytes > __buflen) {
            srdr_logpanic("buffer overflow detected");
        }
        BULLSEYE_EXCLUDE_BLOCK_END

        struct iovec piov[1];
        piov[0].iov_base = __buf;
        piov[0].iov_len = __nbytes;
        return p_socket_object->rx(RX_RECVFROM, piov, 1, &__flags, __from, __fromlen);
    }
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.__recvfrom_chk) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return orig_os_api.__recvfrom_chk(__fd, __buf, __nbytes, __buflen, __flags, __from, __fromlen);
}
#endif

/* Write N bytes of BUF to FD.  Return the number written, or -1.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C" EXPORT_SYMBOL ssize_t write(int __fd, __const void *__buf, size_t __nbytes)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d, nbytes=%d", __fd, __nbytes);

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        struct iovec piov[1] = {{(void *)__buf, __nbytes}};
        xlio_tx_call_attr_t tx_arg;

        tx_arg.opcode = TX_WRITE;
        tx_arg.attr.iov = piov;
        tx_arg.attr.sz_iov = 1;

        return p_socket_object->tx(tx_arg);
    }
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.write) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return orig_os_api.write(__fd, __buf, __nbytes);
}

/* Write IOCNT blocks from IOVEC to FD.  Return the number written, or -1.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C" EXPORT_SYMBOL ssize_t writev(int __fd, const struct iovec *iov, int iovcnt)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d, %d iov blocks", __fd, iovcnt);

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        xlio_tx_call_attr_t tx_arg;

        tx_arg.opcode = TX_WRITEV;
        tx_arg.attr.iov = (struct iovec *)iov;
        tx_arg.attr.sz_iov = iovcnt;

        return p_socket_object->tx(tx_arg);
    }
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.writev) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return orig_os_api.writev(__fd, iov, iovcnt);
}

/* Send N bytes of BUF to socket FD.  Returns the number sent or -1.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C" EXPORT_SYMBOL ssize_t send(int __fd, __const void *__buf, size_t __nbytes, int __flags)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d, nbytes=%d", __fd, __nbytes);

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        struct iovec piov[1] = {{(void *)__buf, __nbytes}};
        xlio_tx_call_attr_t tx_arg;

        tx_arg.opcode = TX_SEND;
        tx_arg.attr.iov = piov;
        tx_arg.attr.sz_iov = 1;
        tx_arg.attr.flags = __flags;

        return p_socket_object->tx(tx_arg);
    }

    // Ignore dummy messages for OS
    if (unlikely(IS_DUMMY_PACKET(__flags))) {
        errno = EINVAL;
        return -1;
    }
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.send) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return orig_os_api.send(__fd, __buf, __nbytes, __flags);
}

/* Sends a message as described by MESSAGE to socket FD.
   Returns the number of bytes read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C" EXPORT_SYMBOL ssize_t sendmsg(int __fd, __const struct msghdr *__msg, int __flags)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d", __fd);

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        xlio_tx_call_attr_t tx_arg;

        tx_arg.opcode = TX_SENDMSG;
        tx_arg.attr.iov = __msg->msg_iov;
        tx_arg.attr.sz_iov = (ssize_t)__msg->msg_iovlen;
        tx_arg.attr.flags = __flags;
        tx_arg.attr.addr = (struct sockaddr *)(__CONST_SOCKADDR_ARG)__msg->msg_name;
        tx_arg.attr.len = (socklen_t)__msg->msg_namelen;
        tx_arg.attr.hdr = __msg;
        tx_arg.priv.attr = PBUF_NONE;

        if (0 < __msg->msg_controllen) {
            struct cmsghdr *cmsg = CMSG_FIRSTHDR((struct msghdr *)__msg);
            if ((cmsg->cmsg_level == SOL_SOCKET) &&
                (cmsg->cmsg_type == SCM_XLIO_PD || cmsg->cmsg_type == SCM_XLIO_NVME_PD)) {
                if ((tx_arg.attr.flags & MSG_ZEROCOPY) &&
                    (__msg->msg_iovlen ==
                     ((cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(struct xlio_pd_key)))) {
                    tx_arg.priv.attr =
                        (cmsg->cmsg_type == SCM_XLIO_PD) ? PBUF_DESC_MKEY : PBUF_DESC_NVME_TX;
                    tx_arg.priv.map = (void *)CMSG_DATA(cmsg);
                } else {
                    errno = EINVAL;
                    return -1;
                }
            }
        }

        return p_socket_object->tx(tx_arg);
    }

    // Ignore dummy messages for OS
    if (unlikely(IS_DUMMY_PACKET(__flags))) {
        errno = EINVAL;
        return -1;
    }
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.sendmsg) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return orig_os_api.sendmsg(__fd, __msg, __flags);
}

/* Send multiple messages as described by MESSAGE from socket FD.
   Returns the number of messages sent or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C" EXPORT_SYMBOL int sendmmsg(int __fd, struct mmsghdr *__mmsghdr, unsigned int __vlen,
                                      int __flags)
{
    int num_of_msg = 0;

    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d, mmsghdr length=%d flags=%x", __fd, __vlen, __flags);

    if (__mmsghdr == NULL) {
        srdr_logdbg("NULL mmsghdr");
        errno = EINVAL;
        return -1;
    }

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        for (unsigned int i = 0; i < __vlen; i++) {
            xlio_tx_call_attr_t tx_arg;

            tx_arg.opcode = TX_SENDMSG;
            tx_arg.attr.iov = __mmsghdr[i].msg_hdr.msg_iov;
            tx_arg.attr.sz_iov = (ssize_t)__mmsghdr[i].msg_hdr.msg_iovlen;
            tx_arg.attr.flags = __flags;
            tx_arg.attr.addr = (struct sockaddr *)(__SOCKADDR_ARG)__mmsghdr[i].msg_hdr.msg_name;
            tx_arg.attr.len = (socklen_t)__mmsghdr[i].msg_hdr.msg_namelen;
            tx_arg.attr.hdr = &__mmsghdr[i].msg_hdr;

            int ret = p_socket_object->tx(tx_arg);
            if (ret < 0) {
                if (num_of_msg) {
                    return num_of_msg;
                } else {
                    return ret;
                }
            }
            num_of_msg++;
            __mmsghdr[i].msg_len = ret;
        }
        return num_of_msg;
    }

    // Ignore dummy messages for OS
    if (unlikely(IS_DUMMY_PACKET(__flags))) {
        errno = EINVAL;
        return -1;
    }
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.sendmmsg) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return orig_os_api.sendmmsg(__fd, __mmsghdr, __vlen, __flags);
}

/* Send N bytes of BUF on socket FD to peer at address ADDR (which is
   ADDR_LEN bytes long).  Returns the number sent, or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C" EXPORT_SYMBOL ssize_t sendto(int __fd, __const void *__buf, size_t __nbytes, int __flags,
                                        const struct sockaddr *__to, socklen_t __tolen)
{
    PROFILE_FUNC

#ifdef RDTSC_MEASURE_TX_SENDTO_TO_AFTER_POST_SEND
    RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_SENDTO_TO_AFTER_POST_SEND]);
#endif // RDTSC_MEASURE_TX_SENDTO_TO_AFTER_POST_SEND

#ifdef RDTSC_MEASURE_RECEIVEFROM_TO_SENDTO
    RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RECEIVEFROM_TO_SENDTO]);
#endif // RDTSC_MEASURE_TX_SENDTO_TO_AFTER_POST_SEND
    srdr_logfuncall_entry("fd=%d, nbytes=%d", __fd, __nbytes);

    socket_fd_api *p_socket_object = NULL;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        struct iovec piov[1] = {{(void *)__buf, __nbytes}};
        xlio_tx_call_attr_t tx_arg;

        tx_arg.opcode = TX_SENDTO;
        tx_arg.attr.iov = piov;
        tx_arg.attr.sz_iov = 1;
        tx_arg.attr.flags = __flags;
        tx_arg.attr.addr = (struct sockaddr *)__to;
        tx_arg.attr.len = __tolen;

        return p_socket_object->tx(tx_arg);
    }

    // Ignore dummy messages for OS
    if (unlikely(IS_DUMMY_PACKET(__flags))) {
        errno = EINVAL;
        return -1;
    }
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.sendto) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return orig_os_api.sendto(__fd, __buf, __nbytes, __flags, __to, __tolen);
}

static ssize_t sendfile_helper(socket_fd_api *p_socket_object, int in_fd, __off64_t *offset,
                               size_t count)
{
    ssize_t totSent = 0;
    struct stat64 stat_buf;
    __off64_t orig_offset = 0;
    __off64_t cur_offset;
    struct iovec piov[1];
    xlio_tx_call_attr_t tx_arg;
    sockinfo *s = (sockinfo *)p_socket_object;

    if (p_socket_object->get_type() != FD_TYPE_SOCKET) {
        errno = EBADF;
        return -1;
    }

    if (offset == NULL) {
        orig_offset = lseek64(in_fd, 0, SEEK_CUR);
        if (orig_offset < 0) {
            errno = ESPIPE;
            return -1;
        }
        cur_offset = orig_offset;
    } else {
        cur_offset = *offset;
    }

    if (PROTO_TCP == s->get_protocol()) {
        mapping_t *mapping;
        int rc;

        /* Get mapping from the cache */
        mapping = g_zc_cache->get_mapping(in_fd);
        if (mapping == NULL) {
            srdr_logdbg("Couldn't allocate mapping object");
            goto fallback;
        }

        if ((__off64_t)mapping->m_size < (__off64_t)(cur_offset + count)) {
            struct stat st_buf;

            /*
             * This is slow path, we check fstat(2) to handle the
             * scenario when user changes the file while respective
             * mapping exists and the file becomes larger.
             * As workaround, fallback to preadv() implementation.
             */
            mapping->put();
            rc = fstat(in_fd, &st_buf);
            if ((rc == 0) && (st_buf.st_size >= (off_t)(cur_offset + count))) {
                s->m_p_socket_stats->counters.n_tx_sendfile_overflows++;
                goto fallback;
            } else {
                errno = EOVERFLOW;
                return -1;
            }
        }

        piov[0].iov_base = (char *)mapping->m_addr + cur_offset;
        piov[0].iov_len = count;

        tx_arg.opcode = TX_FILE;
        tx_arg.attr.iov = piov;
        tx_arg.attr.sz_iov = 1;
        tx_arg.attr.flags = MSG_ZEROCOPY;
        tx_arg.priv.attr = PBUF_DESC_MAP;
        tx_arg.priv.map = (void *)mapping;
        totSent = p_socket_object->tx(tx_arg);

        mapping->put();
    fallback:
        /* Fallback to readv() implementation */
        if (totSent == 0) {
            s->m_p_socket_stats->counters.n_tx_sendfile_fallbacks++;
            tx_arg.clear();
            tx_arg.opcode = TX_FILE;
            tx_arg.attr.iov = piov;
            tx_arg.attr.sz_iov = 1;
            tx_arg.priv.attr = PBUF_DESC_FD;
            tx_arg.priv.fd = in_fd;
            piov[0].iov_base = (void *)&cur_offset;
            piov[0].iov_len = count;
            totSent = p_socket_object->tx(tx_arg);
        }
    } else {
        __off64_t pa_offset = 0;
        size_t pa_count = 0;
        struct flock64 lock;

        if ((fstat64(in_fd, &stat_buf) == -1) ||
            ((__off64_t)stat_buf.st_size < (__off64_t)(cur_offset + count))) {
            errno = EOVERFLOW;
            return -1;
        }

        tx_arg.opcode = TX_WRITE;
        tx_arg.attr.iov = piov;
        tx_arg.attr.sz_iov = 1;

        /* The off argument of mmap() is constrained to be aligned and
         * sized according to the value returned by sysconf()
         */
        pa_offset = cur_offset & ~(sysconf(_SC_PAGE_SIZE) - 1);
        pa_count = count + cur_offset - pa_offset;

        lock.l_type = F_RDLCK;
        lock.l_whence = SEEK_SET;
        lock.l_start = pa_offset;
        lock.l_len = pa_count;
        lock.l_pid = 0;

        /* try to use mmap() approach */
        if (-1 != (fcntl(in_fd, F_SETLK, &lock))) {
            void *addr = NULL;
            addr = mmap64(NULL, pa_count, PROT_READ, MAP_SHARED | MAP_NORESERVE, in_fd, pa_offset);
            if (MAP_FAILED != addr) {
                ssize_t toRead, numSent = 0;

                while (count > 0) {
                    toRead = min(sysconf(_SC_PAGE_SIZE), (ssize_t)count);

                    piov[0].iov_base = (void *)((uintptr_t)addr + cur_offset - pa_offset + totSent);
                    piov[0].iov_len = toRead;

                    numSent = p_socket_object->tx(tx_arg);
                    if (numSent == -1) {
                        break;
                    }

                    count -= numSent;
                    totSent += numSent;
                }
                (void)munmap(addr, pa_count);
            }
            lock.l_type = F_UNLCK;
            (void)fcntl(in_fd, F_SETLK, &lock);
        }

        /* fallback on read() approach */
        if (totSent == 0) {
            char buf[sysconf(_SC_PAGE_SIZE)];
            ssize_t toRead, numRead, numSent = 0;

            s->m_p_socket_stats->counters.n_tx_sendfile_fallbacks++;

            while (count > 0) {
                toRead = min(sizeof(buf), count);
                numRead = pread(in_fd, buf, toRead, cur_offset + totSent);
                if (numRead <= 0) {
                    if (numRead < 0 && totSent == 0) {
                        totSent = -1;
                    }
                    break;
                }

                piov[0].iov_base = (void *)buf;
                piov[0].iov_len = numRead;

                numSent = p_socket_object->tx(tx_arg);
                if (numSent == -1) {
                    break;
                }

                count -= numSent;
                totSent += numSent;
            }
        }
    }

    if (totSent > 0) {
        if (offset != NULL) {
            *offset = *offset + totSent;
        } else {
            (void)lseek64(in_fd, (orig_offset + totSent), SEEK_SET);
        }
    }

    return totSent;
}

extern "C" EXPORT_SYMBOL ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("out_fd=%d, in_fd=%d, offset=%p, *offset=%zu, count=%d", out_fd, in_fd,
                          offset, offset ? *offset : 0, count);

    socket_fd_api *p_socket_object = fd_collection_get_sockfd(out_fd);
    if (!p_socket_object) {
        if (!orig_os_api.sendfile) {
            get_orig_funcs();
        }
        return orig_os_api.sendfile(out_fd, in_fd, offset, count);
    }

    return sendfile_helper(p_socket_object, in_fd, offset, count);
}

extern "C" EXPORT_SYMBOL ssize_t sendfile64(int out_fd, int in_fd, __off64_t *offset, size_t count)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("out_fd=%d, in_fd=%d, offset=%p, *offset=%zu, count=%d", out_fd, in_fd,
                          offset, offset ? *offset : 0, count);

    socket_fd_api *p_socket_object = fd_collection_get_sockfd(out_fd);
    if (!p_socket_object) {
        if (!orig_os_api.sendfile64) {
            get_orig_funcs();
        }
        return orig_os_api.sendfile64(out_fd, in_fd, offset, count);
    }

    return sendfile_helper(p_socket_object, in_fd, offset, count);
}

// Format a fd_set into a string for logging
// Check nfd to know how many 32 bits hexs do we want to sprintf into user buffer
const char *dbg_sprintf_fdset(char *buf, int buflen, int __nfds, fd_set *__fds)
{
    if (buflen < 1) {
        return "(null)";
    }
    buf[0] = '\0';

    if ((__nfds <= 0) || (__fds == NULL)) {
        return "(null)";
    }

    int fdsize = 1 + ((__nfds - 1) / (8 * sizeof(uint32_t)));
    switch (fdsize) {
    case 1:
        snprintf(buf, buflen, "%08x", ((uint32_t *)__fds)[0]);
        break;
    case 2:
        snprintf(buf, buflen, "%08x %08x", ((uint32_t *)__fds)[1], ((uint32_t *)__fds)[0]);
        break;
    case 3:
        snprintf(buf, buflen, "%08x %08x %08x", ((uint32_t *)__fds)[2], ((uint32_t *)__fds)[1],
                 ((uint32_t *)__fds)[0]);
        break;
    case 4:
        snprintf(buf, buflen, "%08x %08x %08x %08x", ((uint32_t *)__fds)[3], ((uint32_t *)__fds)[2],
                 ((uint32_t *)__fds)[1], ((uint32_t *)__fds)[0]);
        break;
    case 5:
        snprintf(buf, buflen, "%08x %08x %08x %08x %08x", ((uint32_t *)__fds)[4],
                 ((uint32_t *)__fds)[3], ((uint32_t *)__fds)[2], ((uint32_t *)__fds)[1],
                 ((uint32_t *)__fds)[0]);
        break;
    case 6:
        snprintf(buf, buflen, "%08x %08x %08x %08x %08x %08x", ((uint32_t *)__fds)[5],
                 ((uint32_t *)__fds)[4], ((uint32_t *)__fds)[3], ((uint32_t *)__fds)[2],
                 ((uint32_t *)__fds)[1], ((uint32_t *)__fds)[0]);
        break;
    default:
        buf[0] = '\0';
    }
    return buf;
}

/* Check the first NFDS descriptors each in READFDS (if not NULL) for read
   readiness, in WRITEFDS (if not NULL) for write readiness, and in EXCEPTFDS
   (if not NULL) for exceptional conditions.  If TIMis not NULL, time out
   after waiting the interval specified therein.  Returns the number of ready
   descriptors, or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
static int select_helper(int __nfds, fd_set *__readfds, fd_set *__writefds, fd_set *__exceptfds,
                         struct timeval *__timeout, const sigset_t *__sigmask = NULL)
{
    int off_rfds_buffer[__nfds];
    io_mux_call::offloaded_mode_t off_modes_buffer[__nfds];

    if (g_vlogger_level >= VLOG_FUNC) {
        const int tmpbufsize = 256;
        char tmpbuf[tmpbufsize], tmpbuf2[tmpbufsize];
        NOT_IN_USE(tmpbufsize); /* to suppress warning in case MAX_DEFINED_LOG_LEVEL */
        NOT_IN_USE(tmpbuf); /* to suppress warning in case MAX_DEFINED_LOG_LEVEL */
        NOT_IN_USE(tmpbuf2); /* to suppress warning in case MAX_DEFINED_LOG_LEVEL */
        srdr_logfunc("readfds: %s, writefds: %s",
                     dbg_sprintf_fdset(tmpbuf, tmpbufsize, __nfds, __readfds),
                     dbg_sprintf_fdset(tmpbuf2, tmpbufsize, __nfds, __writefds));
    }

    try {
        select_call scall(off_rfds_buffer, off_modes_buffer, __nfds, __readfds, __writefds,
                          __exceptfds, __timeout, __sigmask);
        int rc = scall.call();

        if (g_vlogger_level >= VLOG_FUNC) {
            const int tmpbufsize = 256;
            char tmpbuf[tmpbufsize], tmpbuf2[tmpbufsize];
            NOT_IN_USE(tmpbufsize); /* to suppress warning in case MAX_DEFINED_LOG_LEVEL */
            NOT_IN_USE(tmpbuf); /* to suppress warning in case MAX_DEFINED_LOG_LEVEL */
            NOT_IN_USE(tmpbuf2); /* to suppress warning in case MAX_DEFINED_LOG_LEVEL */
            srdr_logfunc_exit("readfds: %s, writefds: %s",
                              dbg_sprintf_fdset(tmpbuf, tmpbufsize, __nfds, __readfds),
                              dbg_sprintf_fdset(tmpbuf2, tmpbufsize, __nfds, __writefds));
        }

        return rc;
    } catch (io_mux_call::io_error &) {
        srdr_logfunc_exit("io_mux_call::io_error (errno=%d %m)", errno);
        return -1;
    }
}

extern "C" EXPORT_SYMBOL int select(int __nfds, fd_set *__readfds, fd_set *__writefds,
                                    fd_set *__exceptfds, struct timeval *__timeout)
{
    PROFILE_FUNC

    if (!g_p_fd_collection) {
        BULLSEYE_EXCLUDE_BLOCK_START
        if (!orig_os_api.select) {
            get_orig_funcs();
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        return orig_os_api.select(__nfds, __readfds, __writefds, __exceptfds, __timeout);
    }

    if (__timeout) {
        srdr_logfunc_entry("nfds=%d, timeout=(%d sec, %d usec)", __nfds, __timeout->tv_sec,
                           __timeout->tv_usec);
    } else {
        srdr_logfunc_entry("nfds=%d, timeout=(infinite)", __nfds);
    }

    return select_helper(__nfds, __readfds, __writefds, __exceptfds, __timeout);
}

extern "C" EXPORT_SYMBOL int pselect(int __nfds, fd_set *__readfds, fd_set *__writefds,
                                     fd_set *__errorfds, const struct timespec *__timeout,
                                     const sigset_t *__sigmask)
{
    PROFILE_FUNC

    if (!g_p_fd_collection) {
        BULLSEYE_EXCLUDE_BLOCK_START
        if (!orig_os_api.pselect) {
            get_orig_funcs();
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        return orig_os_api.pselect(__nfds, __readfds, __writefds, __errorfds, __timeout, __sigmask);
    }

    struct timeval select_time;
    if (__timeout) {
        srdr_logfunc_entry("nfds=%d, timeout=(%d sec, %d nsec)", __nfds, __timeout->tv_sec,
                           __timeout->tv_nsec);
        select_time.tv_sec = __timeout->tv_sec;
        select_time.tv_usec = __timeout->tv_nsec / 1000;
    } else {
        srdr_logfunc_entry("nfds=%d, timeout=(infinite)", __nfds);
    }

    return select_helper(__nfds, __readfds, __writefds, __errorfds, __timeout ? &select_time : NULL,
                         __sigmask);
}

/* Poll the file descriptors described by the NFDS structures starting at
   FDS.  If TIMis nonzero and not -1, allow TIMmilliseconds for
   an event to occur; if TIMis -1, block until an event occurs.
   Returns the number of file descriptors with events, zero if timed out,
   or -1 for errors.  */
static int poll_helper(struct pollfd *__fds, nfds_t __nfds, int __timeout,
                       const sigset_t *__sigmask = NULL)
{
    int off_rfd_buffer[__nfds];
    io_mux_call::offloaded_mode_t off_modes_buffer[__nfds];
    int lookup_buffer[__nfds];
    pollfd working_fds_arr[__nfds + 1];

    try {
        poll_call pcall(off_rfd_buffer, off_modes_buffer, lookup_buffer, working_fds_arr, __fds,
                        __nfds, __timeout, __sigmask);

        int rc = pcall.call();
        srdr_logfunc_exit("rc = %d", rc);
        return rc;
    } catch (io_mux_call::io_error &) {
        srdr_logfunc_exit("io_mux_call::io_error (errno=%d %m)", errno);
        return -1;
    }
}

extern "C" EXPORT_SYMBOL int poll(struct pollfd *__fds, nfds_t __nfds, int __timeout)
{
    PROFILE_FUNC

    if (!g_p_fd_collection) {
        BULLSEYE_EXCLUDE_BLOCK_START
        if (!orig_os_api.poll) {
            get_orig_funcs();
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        return orig_os_api.poll(__fds, __nfds, __timeout);
    }

    srdr_logfunc_entry("nfds=%d, timeout=(%d milli-sec)", __nfds, __timeout);

    return poll_helper(__fds, __nfds, __timeout);
}

#if defined HAVE___POLL_CHK
extern "C" EXPORT_SYMBOL int __poll_chk(struct pollfd *__fds, nfds_t __nfds, int __timeout,
                                        size_t __fdslen)
{
    PROFILE_FUNC

    if (!g_p_fd_collection) {
        BULLSEYE_EXCLUDE_BLOCK_START
        if (!orig_os_api.__poll_chk) {
            get_orig_funcs();
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        return orig_os_api.__poll_chk(__fds, __nfds, __timeout, __fdslen);
    }

    BULLSEYE_EXCLUDE_BLOCK_START
    if (__fdslen / sizeof(*__fds) < __nfds) {
        srdr_logpanic("buffer overflow detected");
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    srdr_logfunc_entry("nfds=%d, timeout=(%d milli-sec)", __nfds, __timeout);

    return poll_helper(__fds, __nfds, __timeout);
}
#endif

extern "C" EXPORT_SYMBOL int ppoll(struct pollfd *__fds, nfds_t __nfds,
                                   const struct timespec *__timeout, const sigset_t *__sigmask)
{
    PROFILE_FUNC

    if (!g_p_fd_collection) {
        BULLSEYE_EXCLUDE_BLOCK_START
        if (!orig_os_api.ppoll) {
            get_orig_funcs();
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        return orig_os_api.ppoll(__fds, __nfds, __timeout, __sigmask);
    }

    int timeout =
        (__timeout == NULL) ? -1 : (__timeout->tv_sec * 1000 + __timeout->tv_nsec / 1000000);

    srdr_logfunc_entry("nfds=%d, timeout=(%d milli-sec)", __nfds, timeout);

    return poll_helper(__fds, __nfds, timeout, __sigmask);
}

#if defined HAVE___PPOLL_CHK
extern "C" EXPORT_SYMBOL int __ppoll_chk(struct pollfd *__fds, nfds_t __nfds,
                                         const struct timespec *__timeout,
                                         const sigset_t *__sigmask, size_t __fdslen)
{
    PROFILE_FUNC

    if (!g_p_fd_collection) {
        BULLSEYE_EXCLUDE_BLOCK_START
        if (!orig_os_api.__ppoll_chk) {
            get_orig_funcs();
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        return orig_os_api.__ppoll_chk(__fds, __nfds, __timeout, __sigmask, __fdslen);
    }

    BULLSEYE_EXCLUDE_BLOCK_START
    if (__fdslen / sizeof(*__fds) < __nfds) {
        srdr_logpanic("buffer overflow detected");
    }

    BULLSEYE_EXCLUDE_BLOCK_END

    int timeout =
        (__timeout == NULL) ? -1 : (__timeout->tv_sec * 1000 + __timeout->tv_nsec / 1000000);

    srdr_logfunc_entry("nfds=%d, timeout=(%d milli-sec)", __nfds, timeout);

    return poll_helper(__fds, __nfds, timeout, __sigmask);
}
#endif

static void xlio_epoll_create(int epfd, int size)
{
    if (g_p_fd_collection) {
        // Sanity check to remove any old sockinfo object using the same fd!!
        handle_close(epfd, true);

        // insert epfd to fd_collection as epfd_info
        g_p_fd_collection->addepfd(epfd, size);
    }
}

/* Creates an epoll instance.  Returns fd for the new instance.
   The "size" parameter is a hint specifying the number of file
   descriptors to be associated with the new instance.  The fd
   returned by epoll_create() should be closed with close().  */
extern "C" EXPORT_SYMBOL int epoll_create(int __size)
{
    DO_GLOBAL_CTORS();

    PROFILE_FUNC

    if (__size <= 0) {
        srdr_logdbg("invalid size (size=%d) - must be a positive integer", __size);
        errno = EINVAL;
        return -1;
    }

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.epoll_create) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    int epfd = orig_os_api.epoll_create(__size + 1); // +1 for the cq epfd
    srdr_logdbg("ENTER: (size=%d) = %d", __size, epfd);

    if (epfd <= 0) {
        return epfd;
    }

    xlio_epoll_create(epfd, 8);

    return epfd;
}

extern "C" EXPORT_SYMBOL int epoll_create1(int __flags)
{
    DO_GLOBAL_CTORS();

    PROFILE_FUNC

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.epoll_create1) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    int epfd = orig_os_api.epoll_create1(__flags);
    srdr_logdbg("ENTER: (flags=%d) = %d", __flags, epfd);

    if (epfd <= 0) {
        return epfd;
    }

    xlio_epoll_create(epfd, 8);

    return epfd;
}

/* Manipulate an epoll instance "epfd". Returns 0 in case of success,
   -1 in case of error ("errno" variable will contain the specific
   error code). The "op" parameter is one of the EPOLL_CTL_*
   constants defined above. The "fd" parameter is the target of the
   operation. The "event" parameter describes which events the caller
   is interested in and any associated user data.  */
extern "C" EXPORT_SYMBOL int epoll_ctl(int __epfd, int __op, int __fd, struct epoll_event *__event)
{
    PROFILE_FUNC

    const static char *op_names[] = {"<null>", "ADD", "DEL", "MOD"};
    NOT_IN_USE(op_names); /* to suppress warning in case MAX_DEFINED_LOG_LEVEL */
    if (__event) {
        srdr_logfunc_entry("epfd=%d, op=%s, fd=%d, events=%#x, data=%x", __epfd, op_names[__op],
                           __fd, __event->events, __event->data.u64);
    } else {
        srdr_logfunc_entry("epfd=%d, op=%s, fd=%d, event=NULL", __epfd, op_names[__op], __fd);
    }

    int rc = -1;
    epfd_info *epfd_info = fd_collection_get_epfd(__epfd);
    if (!epfd_info) {
        errno = EBADF;
    } else {
#if defined(DEFINED_ENVOY)
        if (g_p_app && g_p_app->type == APP_ENVOY) {
            auto iter = g_p_app->map_listen_fd.find(__fd);
            if (iter != g_p_app->map_listen_fd.end()) {
                socket_fd_api *p_socket_object = NULL;
                p_socket_object = fd_collection_get_sockfd(__fd);
                if (iter->second == gettid()) {
                    /* process listen sockets from main thread */
                    if (p_socket_object) {
                        rc = p_socket_object->listen(p_socket_object->m_back_log);
                        if (rc < 0) {
                            return rc;
                        }
                    }
                    std::lock_guard<decltype(g_p_app->m_lock)> lock(g_p_app->m_lock);
                    g_p_app->map_listen_fd.erase(iter);
                } else if (__op == EPOLL_CTL_ADD) {
                    static int worker_id = 0;

                    /* original listen socket should be on*/
                    int sleep_count = 1000;
                    while (!p_socket_object && !worker_id) {
                        if (!sleep_count--) {
                            return -1;
                        }
                        const struct timespec short_sleep = {0, 1000};
                        nanosleep(&short_sleep, NULL);
                    }
                    std::lock_guard<decltype(g_p_app->m_lock)> lock(g_p_app->m_lock);
                    g_p_app->map_listen_fd[__fd] = gettid();
                    g_p_app->map_thread_id[gettid()] = worker_id;
                    rc = init_worker(worker_id, __fd);
                    if (rc != 0) {
                        srdr_logerr("Failed to initialize worker %d, (errno=%d %m)", worker_id,
                                    errno);
                        g_p_app->map_listen_fd.erase(__fd);
                        g_p_app->map_thread_id.erase(gettid());
                        return rc;
                    }
                    worker_id++;
                } else if (__op == EPOLL_CTL_DEL) {
                    std::lock_guard<decltype(g_p_app->m_lock)> lock(g_p_app->m_lock);
                    g_p_app->map_listen_fd.erase(__fd);
                    g_p_app->map_thread_id.erase(gettid());
                }
            }
        }
#endif /* DEFINED_ENVOY */

        // TODO handle race - if close() gets here..
        rc = epfd_info->ctl(__op, __fd, __event);
    }

    srdr_logfunc_exit("rc = %d", rc);
    return rc;
}

/* Wait for events on an epoll instance "epfd". Returns the number of
   triggered events returned in "events" buffer. Or -1 in case of
   error with the "errno" variable set to the specific error code. The
   "events" parameter is a buffer that will contain triggered
   events. The "maxevents" is the maximum number of events to be
   returned ( usually size of "events" ). The "timeout" parameter
   specifies the maximum wait time in milliseconds (-1 == infinite).  */
inline int epoll_wait_helper(int __epfd, struct epoll_event *__events, int __maxevents,
                             int __timeout, const sigset_t *__sigmask = NULL)
{
    if (__maxevents <= 0 || __maxevents > EP_MAX_EVENTS) {
        srdr_logdbg("invalid value for maxevents: %d", __maxevents);
        errno = EINVAL;
        return -1;
    }

    if (safe_mce_sys().tcp_ctl_thread == option_tcp_ctl_thread::CTL_THREAD_DELEGATE_TCP_TIMERS) {
        g_thread_local_event_handler.do_tasks();
    }

    epoll_event extra_events_buffer[__maxevents];

    try {
        epoll_wait_call epcall(extra_events_buffer, NULL, __epfd, __events, __maxevents, __timeout,
                               __sigmask);

        int rc = epcall.get_current_events(); // returns ready nfds
        if (rc <= 0) {
            // if no ready nfds available then check all lower level queues (XLIO ring's and OS
            // queues)
            epcall.init_offloaded_fds();
            rc = epcall.call();
        }

        srdr_logfunc_exit("rc = %d", rc);
        return rc;
    } catch (io_mux_call::io_error &) {
        srdr_logfunc_exit("io_mux_call::io_error (errno=%d %m)", errno);
        return -1;
    }
}

extern "C" EXPORT_SYMBOL int epoll_wait(int __epfd, struct epoll_event *__events, int __maxevents,
                                        int __timeout)
{
    PROFILE_FUNC

    srdr_logfunc_entry("epfd=%d, maxevents=%d, timeout=(%d milli-sec)", __epfd, __maxevents,
                       __timeout);

    return epoll_wait_helper(__epfd, __events, __maxevents, __timeout);
}

extern "C" EXPORT_SYMBOL int epoll_pwait(int __epfd, struct epoll_event *__events, int __maxevents,
                                         int __timeout, const sigset_t *__sigmask)
{
    PROFILE_FUNC

    srdr_logfunc_entry("epfd=%d, maxevents=%d, timeout=(%d milli-sec)", __epfd, __maxevents,
                       __timeout);

    return epoll_wait_helper(__epfd, __events, __maxevents, __timeout, __sigmask);
}

/* Create two new sockets, of type TYPE in domain DOMand using
   protocol PROTOCOL, which are connected to each other, and put file
   descriptors for them in FDS[0] and FDS[1].  If PROTOCOL is zero,
   one will be chosen automatically.  Returns 0 on success, -1 for errors.  */
extern "C" EXPORT_SYMBOL int socketpair(int __domain, int __type, int __protocol, int __sv[2])
{
    PROFILE_FUNC

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.socketpair) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    int ret = orig_os_api.socketpair(__domain, __type, __protocol, __sv);

    srdr_logdbg("(domain=%s(%d) type=%s(%d) protocol=%d, fd[%d,%d]) = %d",
                socket_get_domain_str(__domain), __domain, socket_get_type_str(__type), __type,
                __protocol, __sv[0], __sv[1], ret);

    // Sanity check to remove any old sockinfo object using the same fd!!
    if (ret == 0 && g_p_fd_collection) {
        handle_close(__sv[0], true);
        handle_close(__sv[1], true);
    }

    return ret;
}

/* Create a one-way communication channel (pipe).
   If successful, two file descriptors are stored in PIPEDES;
   bytes written on PIPEDES[1] can be read from PIPEDES[0].
   Returns 0 if successful, -1 if not.  */
extern "C" EXPORT_SYMBOL int pipe(int __filedes[2])
{
    PROFILE_FUNC

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.pipe) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    int ret = orig_os_api.pipe(__filedes);
    srdr_logdbg("(fd[%d,%d]) = %d", __filedes[0], __filedes[1], ret);

    if (ret == 0 && g_p_fd_collection) {
        // Sanity check to remove any old sockinfo object using the same fd!!
        int fdrd = __filedes[0];
        handle_close(fdrd, true);
        int fdwr = __filedes[1];
        handle_close(fdwr, true);
    }

    return ret;
}

extern "C" EXPORT_SYMBOL int open(__const char *__file, int __oflag, ...)
{
    va_list va;
    va_start(va, __oflag);
    mode_t mode = va_arg(va, mode_t);

    PROFILE_FUNC

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.open) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    int fd = orig_os_api.open(__file, __oflag, mode);
    va_end(va);

    srdr_logdbg("(file=%s, flags=%#x, mode=%#x) = %d", __file, __oflag, mode, fd);

    // Sanity check to remove any old sockinfo object using the same fd!!
    handle_close(fd, true);

    return fd;
}

extern "C" EXPORT_SYMBOL int creat(const char *__pathname, mode_t __mode)
{
    PROFILE_FUNC

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.creat) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    int fd = orig_os_api.creat(__pathname, __mode);

    srdr_logdbg("(pathname=%s, mode=%#x) = %d", __pathname, __mode, fd);

    // Sanity check to remove any old sockinfo object using the same fd!!
    handle_close(fd, true);

    return fd;
}

/* Duplicate FD, returning a new file descriptor on the same file.  */
extern "C" EXPORT_SYMBOL int dup(int __fd)
{
    PROFILE_FUNC

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.dup) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    int fid = orig_os_api.dup(__fd);

    srdr_logdbg("(fd=%d) = %d", __fd, fid);

    // Sanity check to remove any old sockinfo object using the same fd!!
    handle_close(fid, true);
#if defined(DEFINED_ENVOY)
    if (g_p_app && g_p_app->type == APP_ENVOY) {
        std::lock_guard<decltype(g_p_app->m_lock)> lock(g_p_app->m_lock);
        g_p_app->map_dup_fd[fid] = __fd;
        g_p_app->map_dup_fd[__fd] = __fd;
    }
#endif /* DEFINED_ENVOY */
    return fid;
}

/* Duplicate FD to FD2, closing FD2 and making it open on the same file.  */
extern "C" EXPORT_SYMBOL int dup2(int __fd, int __fd2)
{
    PROFILE_FUNC

    if (safe_mce_sys().close_on_dup2 && __fd != __fd2) {
        srdr_logdbg("oldfd=%d, newfd=%d. Closing %d in XLIO.", __fd, __fd2, __fd2);
        handle_close(__fd2);
    }

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.dup2) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    int fid = orig_os_api.dup2(__fd, __fd2);

    srdr_logdbg("(fd=%d, fd2=%d) = %d", __fd, __fd2, fid);

    // Sanity check to remove any old sockinfo object using the same fd!!
    handle_close(fid, true);

    return fid;
}

#ifdef _CHANGE_CLONE_PROTO_IN_SLES_10_
extern "C" EXPORT_SYMBOL int clone(int (*__fn)(void *), void *__child_stack, int __flags,
                                   void *__arg)
{
    PROFILE_FUNC

    srdr_logfunc_entry("flags=%#x", __flags);

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.clone)
        get_orig_funcs();
    BULLSEYE_EXCLUDE_BLOCK_END

    return orig_os_api.clone(__fn, __child_stack, __flags, __arg);
}
#endif

/* Clone the calling process, creating an exact copy.
   Return -1 for errors, 0 to the new process,
   and the process ID of the new process to the old process.  */

extern "C" EXPORT_SYMBOL pid_t fork(void)
{
    PROFILE_FUNC

    srdr_logdbg("ENTER: **********");

    if (!g_init_global_ctors_done) {
        set_env_params();
        prepare_fork();
    }

    if (!g_init_ibv_fork_done) {
        srdr_logdbg("ERROR: ibv_fork_init failed, the effect of an application calling fork() is "
                    "undefined!!");
    }

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.fork) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

#if defined(DEFINED_NGINX)
    static int worker_index = -1;
    if (g_p_app && g_p_app->type == APP_NGINX && (g_p_app->get_worker_id() == -1)) {
        /* This section is actual for parent process only */
        std::lock_guard<decltype(g_p_app->m_lock)> lock(g_p_app->m_lock);
        if (!g_p_app->unused_worker_id.empty()) {
            auto itr = g_p_app->unused_worker_id.begin();
            worker_index = *itr;
            g_p_app->unused_worker_id.erase(itr);
        } else {
            if (worker_index < g_p_app->workers_num) {
                worker_index++;
            } else {
                srdr_logerr("Cannot fork: number of running worker processes are at configured "
                            "maximum (%d)",
                            g_p_app->workers_num);
                errno = ENOMEM;
                return -1;
            }
        }
    }
#endif

    pid_t pid = orig_os_api.fork();
    if (pid == 0) {
#if defined(DEFINED_NGINX)
        void *p_fd_collection_temp = g_p_fd_collection;
#endif // DEFINED_NGINX
        g_is_forked_child = true;
        srdr_logdbg_exit("Child Process: returned with %d", pid);

        // Child's process - restart module
        vlog_stop();

        // In case of child process, we want all global objects to re-construct
        reset_globals();

        g_init_global_ctors_done = false;
        sock_redirect_exit();

        safe_mce_sys().get_env_params();
        vlog_start(PRODUCT_NAME, safe_mce_sys().log_level, safe_mce_sys().log_filename,
                   safe_mce_sys().log_details, safe_mce_sys().log_colors);
        if (xlio_rdma_lib_reset()) {
            srdr_logerr("Child Process: rdma_lib_reset failed %d %s", errno, strerror(errno));
        }
        srdr_logdbg_exit("Child Process: starting with %d", getpid());
        g_is_forked_child = false;
        sock_redirect_main();

#if defined(DEFINED_NGINX)
        if (g_p_app && g_p_app->type == APP_NGINX) {
            g_p_app->map_thread_id[gettid()] = worker_index;
            /* Child process needs information about
             * listen socket_fd_api objects, so pass this using parent`s g_p_fd_collection.
             * It is possible as far as parent`s g_p_fd_collection is not deleted
             * by reset_globals()
             */
            g_p_app->context = (void *)p_fd_collection_temp;

            /* Do this only for regular user, not allowed for root user.
             * Root user will be handled in setuid call.
             */
            if (geteuid() != 0) {
                DO_GLOBAL_CTORS();
                std::lock_guard<decltype(g_p_app->m_lock)> lock(g_p_app->m_lock);

                auto itr = g_p_app->map_listen_fd.begin();
                while (itr != g_p_app->map_listen_fd.end()) {
                    int listen_fd = itr->first;
                    itr++;
                    int rc = init_worker(g_p_app->get_worker_id(), listen_fd);
                    if (rc != 0) {
                        srdr_logerr("Failed to initialize worker %d, (errno=%d %m)",
                                    g_p_app->get_worker_id(), errno);
                        break;
                    }
                }
            }
        }
#endif // DEFINED_NGINX
    } else if (pid > 0) {
        srdr_logdbg_exit("Parent Process: returned with %d", pid);
#if defined(DEFINED_NGINX)
        if (g_p_app && g_p_app->type == APP_NGINX) {
            g_p_app->map_thread_id[pid] = worker_index;
        }
#endif
    } else {
        srdr_logdbg_exit("failed (errno=%d %m)", errno);
    }

    return pid;
}

/* Redirect vfork to fork  */
extern "C" EXPORT_SYMBOL pid_t vfork(void)
{
    PROFILE_FUNC

    return fork();
}

/* Put the program in the background, and dissociate from the controlling
   terminal.  If NOCHDIR is zero, do `chdir ("/")'.  If NOCLOSE is zero,
   redirects stdin, stdout, and stderr to /dev/null.  */
extern "C" EXPORT_SYMBOL int daemon(int __nochdir, int __noclose)
{
    PROFILE_FUNC

    srdr_logdbg("ENTER: ***** (%d, %d) *****", __nochdir, __noclose);

    if (!g_init_global_ctors_done) {
        set_env_params();
        prepare_fork();
    }

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.daemon) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    int ret = orig_os_api.daemon(__nochdir, __noclose);
    if (ret == 0) {
        g_is_forked_child = true;
        srdr_logdbg_exit("returned with %d", ret);

        // Child's process - restart module
        vlog_stop();

        // In case of child process, we want all global objects to re-construct
        reset_globals();

        g_init_global_ctors_done = false;
        sock_redirect_exit();

        safe_mce_sys().get_env_params();
        vlog_start(PRODUCT_NAME, safe_mce_sys().log_level, safe_mce_sys().log_filename,
                   safe_mce_sys().log_details, safe_mce_sys().log_colors);
        if (xlio_rdma_lib_reset()) {
            srdr_logerr("Child Process: rdma_lib_reset failed %d %s", errno, strerror(errno));
        }
        srdr_logdbg_exit("Child Process: starting with %d", getpid());
        g_is_forked_child = false;
        sock_redirect_main();
    } else {
        srdr_logdbg_exit("failed (errno=%d %m)", errno);
    }
    return ret;
}

static void handler_intr(int sig)
{
    switch (sig) {
    case SIGINT:
        g_b_exit = true;
        srdr_logdbg("Catch Signal: SIGINT (%d)", sig);
        break;
    default:
        srdr_logdbg("Catch Signal: %d", sig);
        break;
    }

    if (g_act_prev.sa_handler) {
        g_act_prev.sa_handler(sig);
    }
}

extern "C" EXPORT_SYMBOL int sigaction(int signum, const struct sigaction *act,
                                       struct sigaction *oldact)
{
    int ret = 0;

    PROFILE_FUNC

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.sigaction) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    if (safe_mce_sys().handle_sigintr) {
        srdr_logdbg_entry("signum=%d, act=%p, oldact=%p", signum, act, oldact);

        switch (signum) {
        case SIGINT:
            if (oldact && g_act_prev.sa_handler) {
                *oldact = g_act_prev;
            }
            if (act) {
                struct sigaction xlio_action;
                xlio_action.sa_handler = handler_intr;
                xlio_action.sa_flags = 0;
                sigemptyset(&xlio_action.sa_mask);

                ret = orig_os_api.sigaction(SIGINT, &xlio_action, NULL);

                if (ret < 0) {
                    srdr_logdbg("Failed to register SIGINT handler, calling to original sigaction "
                                "handler");
                    break;
                }
                srdr_logdbg("Registered SIGINT handler");
                g_act_prev = *act;
            }
            if (ret >= 0) {
                srdr_logdbg_exit("returned with %d", ret);
            } else {
                srdr_logdbg_exit("failed (errno=%d %m)", errno);
            }

            return ret;
            break;
        default:
            break;
        }
    }
    ret = orig_os_api.sigaction(signum, act, oldact);

    if (safe_mce_sys().handle_sigintr) {
        if (ret >= 0) {
            srdr_logdbg_exit("returned with %d", ret);
        } else {
            srdr_logdbg_exit("failed (errno=%d %m)", errno);
        }
    }
    return ret;
}

static void handle_signal(int signum)
{
    srdr_logdbg_entry("Caught signal! signum=%d", signum);

    if (signum == SIGINT) {
        g_b_exit = true;
    }

    if (g_sighandler) {
        g_sighandler(signum);
    }
}

extern "C" EXPORT_SYMBOL sighandler_t signal(int signum, sighandler_t handler)
{
    PROFILE_FUNC

    if (!orig_os_api.signal) {
        get_orig_funcs();
    }

    if (safe_mce_sys().handle_sigintr) {
        srdr_logdbg_entry("signum=%d, handler=%p", signum, handler);

        if (handler && handler != SIG_ERR && handler != SIG_DFL && handler != SIG_IGN) {
            // Only SIGINT is supported for now
            if (signum == SIGINT) {
                g_sighandler = handler;
                return orig_os_api.signal(SIGINT, &handle_signal);
            }
        }
    }

    return orig_os_api.signal(signum, handler);
}

#if defined(DEFINED_NGINX)

extern "C" EXPORT_SYMBOL int setuid(uid_t uid)
{
    PROFILE_FUNC

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!orig_os_api.setuid) {
        get_orig_funcs();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    uid_t previous_uid = geteuid();
    int orig_rc = orig_os_api.setuid(uid);
    if (orig_rc < 0) {
        srdr_logdbg_exit("failed (errno=%d %m)", errno);
    }

    // Do this only for root user, regular user will be handled in fork call.
    if (g_p_app && g_p_app->type == APP_NGINX && previous_uid == 0) {
        DO_GLOBAL_CTORS();
        std::lock_guard<decltype(g_p_app->m_lock)> lock(g_p_app->m_lock);

        auto itr = g_p_app->map_listen_fd.begin();
        while (itr != g_p_app->map_listen_fd.end()) {
            int listen_fd = itr->first;
            itr++;
            int rc = init_worker(g_p_app->get_worker_id(), listen_fd);
            if (rc != 0) {
                srdr_logerr("Failed to initialize worker %d, (errno=%d %m)",
                            g_p_app->get_worker_id(), errno);
                orig_rc = -1;
                break;
            }
        }
    }

    return orig_rc;
}

extern "C" EXPORT_SYMBOL pid_t waitpid(pid_t pid, int *wstatus, int options)
{
    PROFILE_FUNC

    pid_t child_pid = orig_os_api.waitpid(pid, wstatus, options);
    /* This segment is used as part of NGINX worker termination recovery mechanism. The mechanism
     * marks the worker PID slot as vacant with -1 later to reuse it in the fork system call.The
     * implicit assumptions here are that:
     *     * NGINX monitors the worker process termination with waitpid system call.
     *     * NGINX internally updates that it currently has less than the worker number it needs.
     *     * NGINX at some future point forks a new worker process(es) to replenish the worker
     * process tally.
     */
    if (g_p_app && g_p_app->type == APP_NGINX && child_pid > 0 && !WIFCONTINUED(*wstatus)) {
        std::lock_guard<decltype(g_p_app->m_lock)> lock(g_p_app->m_lock);
        g_p_app->unused_worker_id.insert(g_p_app->get_worker_id());
        g_p_app->map_thread_id.erase(getpid());
    }
    return child_pid;
}

#endif // DEFINED_NGINX
