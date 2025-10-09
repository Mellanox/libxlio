/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

// sock-redirect-internal.h must be first
#include "sock-redirect-internal.h"
#include "sock-redirect.h"
#include "sock-extra.h"
#include "sock-app.h"
#include "xlio.h"

#include <sys/sendfile.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <iostream>
#include <fcntl.h>

#include "utils/compiler.h"
#include "utils/lock_wrapper.h"
#include <proto/ip_frag.h>
#include <dev/buffer_pool.h>
#include <event/event_handler_manager_local.h>
#include <event/vlogger_timer_handler.h>
#include <iomux/poll_call.h>
#include <iomux/select_call.h>
#include <iomux/epfd_info.h>
#include <iomux/epoll_wait_call.h>
#include <util/sys_vars.h>
#include <proto/mapping.h>
#include <proto/xlio_lwip.h>
#include <main.h>

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
struct sigaction g_act_prev;
sighandler_t g_sighandler = nullptr;
class ring_simple;

template <typename T> void assign_dlsym(T &ptr, const char *name)
{
    ptr = reinterpret_cast<T>(dlsym(RTLD_NEXT, name));
}

#define FD_MAP_SIZE (g_p_fd_collection ? g_p_fd_collection->get_fd_map_size() : 1024)

#ifndef XLIO_STATIC_BUILD
struct os_api orig_os_api;
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
#endif /* XLIO_STATIC_BUILD */

#define VERIFY_PASSTROUGH_CHANGED(__ret, __func_and_params__)                                      \
    do {                                                                                           \
        bool passthrough = p_socket_object->isPassthrough();                                       \
        __ret = __func_and_params__;                                                               \
        if (!passthrough && p_socket_object->isPassthrough()) {                                    \
            handle_close(__fd, false, true);                                                       \
        }                                                                                          \
    } while (0);

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

    srdr_logfunc("Cleanup fd=%d cleanup=%d", fd, !!cleanup);

    if (g_zc_cache) {
        g_zc_cache->handle_close(fd);
    }

    if (g_p_fd_collection) {
        // Remove fd from all existing epoll sets
        g_p_fd_collection->remove_from_all_epfds(fd, passthrough);

        sockinfo *sockfd = fd_collection_get_sockfd(fd);
        if (sockfd) {
            // Don't call close(2) for objects without a shadow socket (TCP incoming sockets).
            to_close_now = !passthrough && sockfd->is_shadow_socket_present();
#if defined(DEFINED_NGINX)
            // Save this value before pointer is destructed
            is_for_udp_pool = sockfd->m_is_for_socket_pool;
#endif
            g_p_fd_collection->del_sockfd(fd, is_for_udp_pool);
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

//-----------------------------------------------------------------------------
//  replacement functions
//-----------------------------------------------------------------------------
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
#if defined(DEFINED_NGINX)
    bool add_to_udp_pool = false;
    if (g_p_app && g_p_app->type == APP_NGINX && g_p_fd_collection && offload_sockets &&
        g_p_fd_collection->pop_socket_pool(fd, add_to_udp_pool, __type & 0xf)) {
        return fd;
    }
#endif

    fd = SOCKET_FAKE_FD;
    if (shadow || !offload_sockets || !g_p_fd_collection) {
        fd = SYSCALL(socket, __domain, __type, __protocol);
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

int bind_internal(void *sock, const struct sockaddr *addr, socklen_t addrlen)
{
    auto p_socket_object = reinterpret_cast<sockinfo *>(sock);
    int ret = p_socket_object->bind(addr, addrlen);
    if (p_socket_object->isPassthrough()) {
        int fd = p_socket_object->get_fd();
        handle_close(fd, false, true);
        if (ret) {
            ret = SYSCALL(bind, fd, addr, addrlen);
        }
    }
    return ret;
}

ssize_t sendmsg_internal(void *sock, __const struct msghdr *__msg, int __flags)
{
    auto p_socket_object = reinterpret_cast<sockinfo *>(sock);
    xlio_tx_call_attr_t tx_arg;

    tx_arg.opcode = TX_SENDMSG;
    tx_arg.attr.iov = __msg->msg_iov;
    tx_arg.attr.sz_iov = (ssize_t)__msg->msg_iovlen;
    tx_arg.attr.flags = __flags;
    tx_arg.attr.addr = (struct sockaddr *)(__CONST_SOCKADDR_ARG)__msg->msg_name;
    tx_arg.attr.len = (socklen_t)__msg->msg_namelen;
    tx_arg.attr.hdr = __msg;
    tx_arg.priv.attr = PBUF_DESC_NONE;

    return p_socket_object->tx(tx_arg);
}

static ssize_t sendfile_helper(sockinfo *p_socket_object, int in_fd, __off64_t *offset,
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

    if (!offset) {
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
        if (!mapping) {
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
                if (s->get_sock_stats()) {
                    s->get_sock_stats()->counters.n_tx_sendfile_overflows++;
                }
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
        tx_arg.priv.attr = PBUF_DESC_MDESC;
        tx_arg.priv.mdesc = (void *)mapping;
        totSent = p_socket_object->tx(tx_arg);

        mapping->put();
    fallback:
        /* Fallback to readv() implementation */
        if (totSent == 0) {
            if (s->get_sock_stats()) {
                s->get_sock_stats()->counters.n_tx_sendfile_fallbacks++;
            }
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
        if (-1 != (XLIO_CALL(fcntl, in_fd, F_SETLK, &lock))) {
            void *addr = nullptr;
            addr =
                mmap64(nullptr, pa_count, PROT_READ, MAP_SHARED | MAP_NORESERVE, in_fd, pa_offset);
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
            (void)XLIO_CALL(fcntl, in_fd, F_SETLK, &lock);
        }

        /* fallback on read() approach */
        if (totSent == 0) {
            char buf[sysconf(_SC_PAGE_SIZE)];
            ssize_t toRead, numRead, numSent = 0;

            if (s->get_sock_stats()) {
                s->get_sock_stats()->counters.n_tx_sendfile_fallbacks++;
            }

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
        if (offset) {
            *offset = *offset + totSent;
        } else {
            (void)lseek64(in_fd, (orig_offset + totSent), SEEK_SET);
        }
    }

    return totSent;
}

// Format a fd_set into a string for logging
// Check nfd to know how many 32 bits hexs do we want to sprintf into user buffer
const char *dbg_sprintf_fdset(char *buf, int buflen, int __nfds, fd_set *__fds)
{
    if (buflen < 1) {
        return "(null)";
    }
    buf[0] = '\0';

    if ((__nfds <= 0) || (!__fds)) {
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

/* Poll the file descriptors described by the NFDS structures starting at
   FDS.  If TIMis nonzero and not -1, allow TIMmilliseconds for
   an event to occur; if TIMis -1, block until an event occurs.
   Returns the number of file descriptors with events, zero if timed out,
   or -1 for errors.  */
static int poll_helper(struct pollfd *__fds, nfds_t __nfds, int __timeout,
                       const sigset_t *__sigmask = nullptr)
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

/* Check the first NFDS descriptors each in READFDS (if not NULL) for read
   readiness, in WRITEFDS (if not NULL) for write readiness, and in EXCEPTFDS
   (if not NULL) for exceptional conditions.  If TIMis not NULL, time out
   after waiting the interval specified therein.  Returns the number of ready
   descriptors, or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
static int select_helper(int __nfds, fd_set *__readfds, fd_set *__writefds, fd_set *__exceptfds,
                         struct timeval *__timeout, const sigset_t *__sigmask = nullptr)
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

static void xlio_epoll_create(int epfd, int size)
{
    if (g_p_fd_collection) {
        // Sanity check to remove any old sockinfo object using the same fd!!
        handle_close(epfd, true);

        // insert epfd to fd_collection as epfd_info
        g_p_fd_collection->addepfd(epfd, size);
    }
}

/* Wait for events on an epoll instance "epfd". Returns the number of
   triggered events returned in "events" buffer. Or -1 in case of
   error with the "errno" variable set to the specific error code. The
   "events" parameter is a buffer that will contain triggered
   events. The "maxevents" is the maximum number of events to be
   returned ( usually size of "events" ). The "timeout" parameter
   specifies the maximum wait time in milliseconds (-1 == infinite).  */
inline int epoll_wait_helper(int __epfd, struct epoll_event *__events, int __maxevents,
                             int __timeout, const sigset_t *__sigmask = nullptr)
{
    if (__maxevents <= 0 || __maxevents > EP_MAX_EVENTS) {
        srdr_logdbg("invalid value for maxevents: %d", __maxevents);
        errno = EINVAL;
        return -1;
    }

    if (safe_mce_sys().tcp_ctl_thread == option_tcp_ctl_thread::CTL_THREAD_DELEGATE_TCP_TIMERS) {
        g_event_handler_manager_local.do_tasks();
    }

    epoll_event extra_events_buffer[__maxevents];

    try {
        epoll_wait_call epcall(extra_events_buffer, nullptr, __epfd, __events, __maxevents,
                               __timeout, __sigmask);

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

int sigaction_internal(int signum, const struct sigaction *act, struct sigaction *oldact)
{
    int ret = 0;

    PROFILE_FUNC

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

                ret = SYSCALL(sigaction, SIGINT, &xlio_action, nullptr);

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
    ret = SYSCALL(sigaction, signum, act, oldact);

    if (safe_mce_sys().handle_sigintr) {
        if (ret >= 0) {
            srdr_logdbg_exit("returned with %d", ret);
        } else {
            srdr_logdbg_exit("failed (errno=%d %m)", errno);
        }
    }
    return ret;
}

extern "C" {
/* Create a new socket of type TYPE in domain DOMAIN, using
   protocol PROTOCOL.  If PROTOCOL is zero, one is chosen automatically.
   Returns a file descriptor for the new socket, or -1 for errors.  */
EXPORT_SYMBOL int XLIO_SYMBOL(socket)(int __domain, int __type, int __protocol)
{
    return socket_internal(__domain, __type, __protocol, true, true);
}

EXPORT_SYMBOL int XLIO_SYMBOL(close)(int __fd)
{
    PROFILE_FUNC

    srdr_logdbg_entry("fd=%d", __fd);

    bool toclose = handle_close(__fd);
    int rc = toclose ? SYSCALL(close, __fd) : 0;

    return rc;
}

#ifdef XLIO_STATIC_BUILD
extern void __res_iclose(res_state statp, bool free_addr);
#endif

EXPORT_SYMBOL void XLIO_SYMBOL(__res_iclose)(res_state statp, bool free_addr)
{
    PROFILE_FUNC

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
    SYSCALL(__res_iclose, statp, free_addr);
}

/* Shut down all or part of the connection open on socket FD.
   HOW determines what to shut down:
     SHUT_RD   = No more receptions;
     SHUT_WR   = No more transmissions;
     SHUT_RDWR = No more receptions or transmissions.
   Returns 0 on success, -1 for errors.  */
EXPORT_SYMBOL int XLIO_SYMBOL(shutdown)(int __fd, int __how)
{
    PROFILE_FUNC

    srdr_logdbg_entry("fd=%d, how=%d", __fd, __how);

    sockinfo *p_socket_object = nullptr;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        return p_socket_object->shutdown(__how);
    }

    return SYSCALL(shutdown, __fd, __how);
}

/**
 * @brief Listens for incoming connections on a socket
 *
 * @param[in] __fd      The file descriptor of the socket
 * @param[in] __backlog The maximum number of pending connections
 * @return               0 on success, -1 on error
 *
 * @note coverity[UNCAUGHT_EXCEPT] was added as it's a False Positive
 */
// coverity[UNCAUGHT_EXCEPT]
EXPORT_SYMBOL int XLIO_SYMBOL(listen)(int __fd, int backlog)
{
    PROFILE_FUNC

    srdr_logdbg_entry("fd=%d, backlog=%d", __fd, backlog);

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    if (g_p_app && g_p_app->type != APP_NONE) {
        /* Envoy:
         * Socket handling
         * Envoy uses the following procedure for creating sockets and assigning them to workers.
         *
         * When a listener is created, a socket is pre-created for every worker on the main thread.
         * This allows most errors to be caught early on in the listener creation process (e.g., bad
         * socket option, unable to bind, etc.).
         * - If using reuse_port, a unique socket is created for every worker.
         * - If not using reuse_port, a unique socket is created for worker 0, and then that socket
         * is duplicated for all other workers.
         * a listener can close() its sockets when removed without concern for other listeners.
         *
         * Implementation:
         * - reuse_port(false) :
         * Envoy uses dup() call for listen socket on workers_N (N > 0)
         * dup() call does not create socket object and does not store fd
         * in fd_collection in current implementation
         * so as a result duplicated fd is not returned by fd_collection_get_sockfd(__fd) and
         * listen() call for duplicated fds are ignored.
         * Original listen socket is not ignored by listen() function.
         * - reuse_port(true) :
         * dup() is not used. Unique socket is created for every worker.
         *
         * Store all duplicated fd in map_dup_fd with reference to original fd
         * Store all listen fd in map_listen_fd with tid
         * Identify correct listen fd during epoll_ctl(ADD) call by tid. It should be different.
         * Set worker id in map_thread_id basing on tid
         *
         * Nginx:
         * Nginx store all listen fd in map_listen_fd to proceed later in children processes
         * after fork() call.
         * Set worker id in map_thread_id basing on tid(pid). Nginx has single thread per process so
         * tid and pid should be equal.
         */
        std::lock_guard<decltype(g_p_app->m_lock)> lock(g_p_app->m_lock);
        g_p_app->map_listen_fd[__fd] = gettid();
    }
#endif /* DEFINED_ENVOY */

    sockinfo *p_socket_object = nullptr;
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
            if (g_p_app && g_p_app->type != APP_NONE) {
                p_socket_object->m_back_log = backlog;
            } else
#endif
            {
                return p_socket_object->listen(backlog);
            }
        }
    }

    srdr_logdbg("OS listen fd=%d, backlog=%d", __fd, backlog);
    return SYSCALL(listen, __fd, backlog);
}

EXPORT_SYMBOL int XLIO_SYMBOL(accept)(int __fd, struct sockaddr *__addr, socklen_t *__addrlen)
{
    PROFILE_FUNC

    sockinfo *p_socket_object = nullptr;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        return p_socket_object->accept(__addr, __addrlen);
    }

    return SYSCALL(accept, __fd, __addr, __addrlen);
}

EXPORT_SYMBOL int XLIO_SYMBOL(accept4)(int __fd, struct sockaddr *__addr, socklen_t *__addrlen,
                                       int __flags)
{
    PROFILE_FUNC

    sockinfo *p_socket_object = nullptr;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        return p_socket_object->accept4(__addr, __addrlen, __flags);
    }

    return SYSCALL(accept4, __fd, __addr, __addrlen, __flags);
}

/**
 * @brief Binds a socket to a local address
 *
 * @param[in] __fd      The file descriptor of the socket
 * @param[in] __addr    The local address to bind the socket to
 * @param[in] __addrlen The length of the local address
 * @return               0 on success, -1 on error
 *
 * @note coverity[UNCAUGHT_EXCEPT] was added as it's a False Positive
 */
// coverity[UNCAUGHT_EXCEPT]
EXPORT_SYMBOL int XLIO_SYMBOL(bind)(int __fd, const struct sockaddr *__addr, socklen_t __addrlen)
{
    int errno_tmp = errno;

    PROFILE_FUNC

    char buf[256];
    NOT_IN_USE(buf); /* to suppress warning in case MAX_DEFINED_LOG_LEVEL */
    srdr_logdbg_entry("fd=%d, %s", __fd, sprintf_sockaddr(buf, 256, __addr, __addrlen));

    int ret = 0;
    sockinfo *p_socket_object = nullptr;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        ret = bind_internal(p_socket_object, __addr, __addrlen);
    } else {
        ret = SYSCALL(bind, __fd, __addr, __addrlen);
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
EXPORT_SYMBOL int XLIO_SYMBOL(connect)(int __fd, const struct sockaddr *__to, socklen_t __tolen)
{
    int errno_tmp = errno;

    PROFILE_FUNC

    char buf[256];
    NOT_IN_USE(buf); /* to suppress warning in case MAX_DEFINED_LOG_LEVEL */
    srdr_logdbg_entry("fd=%d, %s", __fd, sprintf_sockaddr(buf, 256, __to, __tolen));

    int ret = 0;
    sockinfo *p_socket_object = fd_collection_get_sockfd(__fd);
    if (!p_socket_object) {
        srdr_logdbg_exit("Unable to get sock_fd_api");
        ret = SYSCALL(connect, __fd, __to, __tolen);
    } else if (!__to || (get_sa_family(__to) != AF_INET && (get_sa_family(__to) != AF_INET6))) {
        p_socket_object->setPassthrough();
        ret = SYSCALL(connect, __fd, __to, __tolen);
    } else {
        ret = p_socket_object->connect(__to, __tolen);
        if (p_socket_object->isPassthrough()) {
            handle_close(__fd, false, true);
            if (ret) {
                ret = SYSCALL(connect, __fd, __to, __tolen);
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

/**
 * @brief Sets the socket option for a given file descriptor
 *
 * @param[in] __fd      The file descriptor of the socket
 * @param[in] __level   The protocol level of the option
 * @param[in] __optname The name of the option to set
 * @param[in] __optval  The value of the option
 * @param[in] __optlen  The length of the option value
 * @return               0 on success, -1 on error
 *
 * @note coverity[UNCAUGHT_EXCEPT] was added as it's a False Positive
 */
// coverity[UNCAUGHT_EXCEPT]
EXPORT_SYMBOL int XLIO_SYMBOL(setsockopt)(int __fd, int __level, int __optname,
                                          __const void *__optval, socklen_t __optlen)
{
    srdr_logdbg_entry("fd=%d, level=%d, optname=%d", __fd, __level, __optname);

    if (!__optval) {
        errno = EFAULT;
        return -1;
    }

    PROFILE_FUNC

    int ret = 0;
    sockinfo *p_socket_object = nullptr;

    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        VERIFY_PASSTROUGH_CHANGED(
            ret, p_socket_object->setsockopt(__level, __optname, __optval, __optlen));
    } else {
        ret = SYSCALL(setsockopt, __fd, __level, __optname, __optval, __optlen);
    }

    if (ret >= 0) {
        srdr_logdbg_exit("returned with %d", ret);
    } else {
        srdr_logdbg_exit("failed (errno=%d %m)", errno);
    }
    return ret;
}

/**
 * @brief Gets the socket option for a given file descriptor
 *
 * @param[in] __fd      The file descriptor to get the option for
 * @param[in] __level   The protocol level of the option
 * @param[in] __optname The name of the option to get
 * @param[out] __optval  The value of the option
 * @param[in] __optlen   The length of the option value
 * @return               0 on success, -1 on error
 *
 * @note coverity[UNCAUGHT_EXCEPT] was added as it's a False Positive
 */
// coverity[UNCAUGHT_EXCEPT]
EXPORT_SYMBOL int XLIO_SYMBOL(getsockopt)(int __fd, int __level, int __optname, void *__optval,
                                          socklen_t *__optlen)
{
    PROFILE_FUNC

    srdr_logdbg_entry("fd=%d, level=%d, optname=%d", __fd, __level, __optname);

#ifndef XLIO_STATIC_BUILD
    if (__fd == -2 && __level == SOL_SOCKET && __optname == SO_XLIO_GET_API && __optlen &&
        *__optlen >= sizeof(struct xlio_api_t *)) {
        *((xlio_api_t **)__optval) = extra_api();
        *__optlen = sizeof(struct xlio_api_t *);
        return 0;
    }
#endif /* XLIO_STATIC_BUILD */

    int ret = 0;
    sockinfo *p_socket_object = nullptr;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        VERIFY_PASSTROUGH_CHANGED(
            ret, p_socket_object->getsockopt(__level, __optname, __optval, __optlen));
    } else {
        ret = SYSCALL(getsockopt, __fd, __level, __optname, __optval, __optlen);
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
EXPORT_SYMBOL int XLIO_SYMBOL(fcntl)(int __fd, int __cmd, ...)
{
    PROFILE_FUNC

    srdr_logfunc_entry("fd=%d, cmd=%d", __fd, __cmd);

    int res = -1;
    va_list va;
    va_start(va, __cmd);
    unsigned long int arg = va_arg(va, unsigned long int);
    va_end(va);

    int ret = 0;
    sockinfo *p_socket_object = nullptr;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        VERIFY_PASSTROUGH_CHANGED(res, p_socket_object->fcntl(__cmd, arg));
    } else {
        res = SYSCALL(fcntl, __fd, __cmd, arg);
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

EXPORT_SYMBOL int XLIO_SYMBOL(fcntl64)(int __fd, int __cmd, ...)
{
    PROFILE_FUNC

    srdr_logfunc_entry("fd=%d, cmd=%d", __fd, __cmd);

    int res = -1;
    va_list va;
    va_start(va, __cmd);
    unsigned long int arg = va_arg(va, unsigned long int);
    va_end(va);

    int ret = 0;
    sockinfo *p_socket_object = nullptr;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object && VALID_SYSCALL(fcntl64)) {
        VERIFY_PASSTROUGH_CHANGED(res, p_socket_object->fcntl64(__cmd, arg));
    } else {
        res = SYSCALL_ERRNO_UNSUPPORTED(fcntl64, __fd, __cmd, arg);
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

/**
 * @brief Performs the I/O control operation specified by REQUEST on FD
 *
 * @param[in] __fd      The file descriptor of the socket
 * @param[in] __request The I/O control operation to perform
 * @param[in] ...       Additional arguments depending on the request
 * @return               0 on success, -1 on error
 *
 * @note coverity[UNCAUGHT_EXCEPT] was added as it's a False Positive
 */
// coverity[UNCAUGHT_EXCEPT]
EXPORT_SYMBOL int XLIO_SYMBOL(ioctl)(int __fd, unsigned long int __request, ...)
{
    PROFILE_FUNC

    srdr_logfunc_entry("fd=%d, request=%d", __fd, __request);

    int res = -1;
    va_list va;
    va_start(va, __request);
    unsigned long int arg = va_arg(va, unsigned long int);
    va_end(va);

    int ret = 0;

    sockinfo *p_socket_object = nullptr;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object && arg) {
        VERIFY_PASSTROUGH_CHANGED(res, p_socket_object->ioctl(__request, arg));
    } else {
        res = SYSCALL(ioctl, __fd, __request, arg);
    }

    if (ret >= 0) {
        srdr_logfunc_exit("returned with %d", ret);
    } else {
        srdr_logfunc_exit("failed (errno=%d %m)", errno);
    }
    return res;
}

/**
 * @brief Gets the socket name for a given file descriptor
 *
 * @param[in] __fd      The file descriptor to get the socket name for
 * @param[out] __name   The socket address structure to store the result
 * @param[in] __namelen The length of the socket address structure
 * @return               0 on success, -1 on error
 *
 * @note coverity[UNCAUGHT_EXCEPT] was added as it's a False Positive
 */
// coverity[UNCAUGHT_EXCEPT]
EXPORT_SYMBOL int XLIO_SYMBOL(getsockname)(int __fd, struct sockaddr *__name, socklen_t *__namelen)
{
    PROFILE_FUNC

    srdr_logdbg_entry("fd=%d", __fd);

    sockinfo *p_socket_object = fd_collection_get_sockfd(__fd);
    int ret = p_socket_object ? p_socket_object->getsockname(__name, __namelen)
                              : SYSCALL(getsockname, __fd, __name, __namelen);

    srdr_logdbg_exit("returned with %d (errno=%d %m)", ret, errno);
    return ret;
}

EXPORT_SYMBOL int XLIO_SYMBOL(getpeername)(int __fd, struct sockaddr *__name, socklen_t *__namelen)
{
    PROFILE_FUNC

    srdr_logdbg_entry("fd=%d", __fd);

    int ret = 0;
    sockinfo *p_socket_object = nullptr;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        ret = p_socket_object->getpeername(__name, __namelen);
    } else {
        ret = SYSCALL(getpeername, __fd, __name, __namelen);
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
EXPORT_SYMBOL ssize_t XLIO_SYMBOL(read)(int __fd, void *__buf, size_t __nbytes)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d", __fd);

    sockinfo *p_socket_object = nullptr;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        struct iovec piov[1];
        piov[0].iov_base = __buf;
        piov[0].iov_len = __nbytes;
        int dummy_flags = 0;
        return p_socket_object->rx(RX_READ, piov, 1, &dummy_flags);
    }

    return SYSCALL(read, __fd, __buf, __nbytes);
}

#if defined HAVE___READ_CHK && !defined(XLIO_STATIC_BUILD)
/* Checks that the buffer is big enough to contain the number of bytes
 * the user requests to read. If the buffer is too small, aborts,
 * else read NBYTES into BUF from FD.  Return the
   number read, -1 for errors or 0 for EOF.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
EXPORT_SYMBOL ssize_t XLIO_SYMBOL(__read_chk)(int __fd, void *__buf, size_t __nbytes,
                                              size_t __buflen)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d", __fd);

    sockinfo *p_socket_object = nullptr;
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

    return SYSCALL(__read_chk, __fd, __buf, __nbytes, __buflen);
}
#endif

/* Read COUNT blocks into VECTOR from FD.  Return the
   number of bytes read, -1 for errors or 0 for EOF.

   This function is a cancellation point and therefore not marked with
   __THROW.  */

EXPORT_SYMBOL ssize_t XLIO_SYMBOL(readv)(int __fd, const struct iovec *iov, int iovcnt)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d", __fd);

    sockinfo *p_socket_object = nullptr;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        struct iovec *piov = (struct iovec *)iov;
        int dummy_flags = 0;
        return p_socket_object->rx(RX_READV, piov, iovcnt, &dummy_flags);
    }

    return SYSCALL(readv, __fd, iov, iovcnt);
}

/* Read N bytes into BUF from socket FD.
   Returns the number read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
EXPORT_SYMBOL ssize_t XLIO_SYMBOL(recv)(int __fd, void *__buf, size_t __nbytes, int __flags)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d", __fd);

    sockinfo *p_socket_object = nullptr;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        struct iovec piov[1];
        piov[0].iov_base = __buf;
        piov[0].iov_len = __nbytes;
        return p_socket_object->rx(RX_RECV, piov, 1, &__flags);
    }

    return SYSCALL(recv, __fd, __buf, __nbytes, __flags);
}

#if defined HAVE___RECV_CHK && !defined(XLIO_STATIC_BUILD)
/* Checks that the buffer is big enough to contain the number of bytes
   the user requests to read. If the buffer is too small, aborts,
   else read N bytes into BUF from socket FD.
   Returns the number read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
EXPORT_SYMBOL ssize_t XLIO_SYMBOL(__recv_chk)(int __fd, void *__buf, size_t __nbytes,
                                              size_t __buflen, int __flags)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d", __fd);

    sockinfo *p_socket_object = nullptr;
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

    return SYSCALL(__recv_chk, __fd, __buf, __nbytes, __buflen, __flags);
}
#endif

/* Receive a message as described by MESSAGE from socket FD.
   Returns the number of bytes read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
EXPORT_SYMBOL ssize_t XLIO_SYMBOL(recvmsg)(int __fd, struct msghdr *__msg, int __flags)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d", __fd);

    if (!__msg) {
        srdr_logdbg("NULL msghdr");
        errno = EINVAL;
        return -1;
    }

    sockinfo *p_socket_object = nullptr;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        __msg->msg_flags = 0;
        return p_socket_object->rx(RX_RECVMSG, __msg->msg_iov, __msg->msg_iovlen, &__flags,
                                   (__SOCKADDR_ARG)__msg->msg_name,
                                   (socklen_t *)&__msg->msg_namelen, __msg);
    }

    return SYSCALL(recvmsg, __fd, __msg, __flags);
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

#if defined(RECVMMSG_WITH_CONST_TIMESPEC) || defined(XLIO_STATIC_BUILD)
EXPORT_SYMBOL int XLIO_SYMBOL(recvmmsg)(int __fd, struct mmsghdr *__mmsghdr, unsigned int __vlen,
                                        int __flags, const struct timespec *__timeout)
#else
EXPORT_SYMBOL int XLIO_SYMBOL(recvmmsg)(int __fd, struct mmsghdr *__mmsghdr, unsigned int __vlen,
                                        int __flags, struct timespec *__timeout)
#endif
{
    PROFILE_FUNC

    int num_of_msg = 0;
    struct timespec start_time = TIMESPEC_INITIALIZER, current_time = TIMESPEC_INITIALIZER,
                    delta_time = TIMESPEC_INITIALIZER;

    srdr_logfuncall_entry("fd=%d, mmsghdr length=%d flags=%x", __fd, __vlen, __flags);

    if (!__mmsghdr) {
        srdr_logdbg("NULL mmsghdr");
        errno = EINVAL;
        return -1;
    }

    if (__timeout) {
        gettime(&start_time);
    }
    sockinfo *p_socket_object = nullptr;
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

    struct timespec timeout = TIMESPEC_INITIALIZER;
    if (__timeout) {
        memcpy(&timeout, __timeout, sizeof(timeout));
    }
    return SYSCALL(recvmmsg, __fd, __mmsghdr, __vlen, __flags, &timeout);
}

/* Read N bytes into BUF through socket FD.
   If ADDR is not NULL, fill in *ADDR_LEN bytes of it with tha address of
   the sender, and store the actual size of the address in *ADDR_LEN.
   Returns the number of bytes read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
EXPORT_SYMBOL ssize_t XLIO_SYMBOL(recvfrom)(int __fd, void *__buf, size_t __nbytes, int __flags,
                                            struct sockaddr *__from, socklen_t *__fromlen)
{
    ssize_t ret_val = 0;

    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d", __fd);

    sockinfo *p_socket_object = nullptr;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        struct iovec piov[1];
        piov[0].iov_base = __buf;
        piov[0].iov_len = __nbytes;
        ret_val = p_socket_object->rx(RX_RECVFROM, piov, 1, &__flags, __from, __fromlen);
    } else {
        ret_val = SYSCALL(recvfrom, __fd, __buf, __nbytes, __flags, __from, __fromlen);
    }
    return ret_val;
}

#if defined HAVE___RECVFROM_CHK && !defined(XLIO_STATIC_BUILD)
/* Checks that the buffer is big enough to contain the number of bytes
   the user requests to read. If the buffer is too small, aborts,
   else read N bytes into BUF through socket FD.
   If ADDR is not NULL, fill in *ADDR_LEN bytes of it with tha address of
   the sender, and store the actual size of the address in *ADDR_LEN.
   Returns the number of bytes read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
EXPORT_SYMBOL ssize_t XLIO_SYMBOL(__recvfrom_chk)(int __fd, void *__buf, size_t __nbytes,
                                                  size_t __buflen, int __flags,
                                                  struct sockaddr *__from, socklen_t *__fromlen)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d", __fd);

    sockinfo *p_socket_object = nullptr;
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

    return SYSCALL(__recvfrom_chk, __fd, __buf, __nbytes, __buflen, __flags, __from, __fromlen);
}
#endif

/* Write N bytes of BUF to FD.  Return the number written, or -1.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
EXPORT_SYMBOL ssize_t XLIO_SYMBOL(write)(int __fd, __const void *__buf, size_t __nbytes)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d, nbytes=%d", __fd, __nbytes);

    sockinfo *p_socket_object = nullptr;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        struct iovec piov[1] = {{(void *)__buf, __nbytes}};
        xlio_tx_call_attr_t tx_arg;

        tx_arg.opcode = TX_WRITE;
        tx_arg.attr.iov = piov;
        tx_arg.attr.sz_iov = 1;

        return p_socket_object->tx(tx_arg);
    }

    return SYSCALL(write, __fd, __buf, __nbytes);
}

/* Write IOCNT blocks from IOVEC to FD.  Return the number written, or -1.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
EXPORT_SYMBOL ssize_t XLIO_SYMBOL(writev)(int __fd, const struct iovec *iov, int iovcnt)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d, %d iov blocks", __fd, iovcnt);

    sockinfo *p_socket_object = nullptr;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        xlio_tx_call_attr_t tx_arg;

        tx_arg.opcode = TX_WRITEV;
        tx_arg.attr.iov = (struct iovec *)iov;
        tx_arg.attr.sz_iov = iovcnt;

        return p_socket_object->tx(tx_arg);
    }

    return SYSCALL(writev, __fd, iov, iovcnt);
}

/* Send N bytes of BUF to socket FD.  Returns the number sent or -1.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
EXPORT_SYMBOL ssize_t XLIO_SYMBOL(send)(int __fd, __const void *__buf, size_t __nbytes, int __flags)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d, nbytes=%d", __fd, __nbytes);

    sockinfo *p_socket_object = nullptr;
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

    return SYSCALL(send, __fd, __buf, __nbytes, __flags);
}

/* Sends a message as described by MESSAGE to socket FD.
   Returns the number of bytes read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
EXPORT_SYMBOL ssize_t XLIO_SYMBOL(sendmsg)(int __fd, __const struct msghdr *__msg, int __flags)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d", __fd);

    sockinfo *p_socket_object = nullptr;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object) {
        return sendmsg_internal(p_socket_object, __msg, __flags);
    }

    return SYSCALL(sendmsg, __fd, __msg, __flags);
}

/* Send multiple messages as described by MESSAGE from socket FD.
   Returns the number of messages sent or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
EXPORT_SYMBOL int XLIO_SYMBOL(sendmmsg)(int __fd, struct mmsghdr *__mmsghdr, unsigned int __vlen,
                                        int __flags)
{
    int num_of_msg = 0;

    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d, mmsghdr length=%d flags=%x", __fd, __vlen, __flags);

    if (!__mmsghdr) {
        srdr_logdbg("NULL mmsghdr");
        errno = EINVAL;
        return -1;
    }

    sockinfo *p_socket_object = nullptr;
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

    return SYSCALL(sendmmsg, __fd, __mmsghdr, __vlen, __flags);
}

/* Send N bytes of BUF on socket FD to peer at address ADDR (which is
   ADDR_LEN bytes long).  Returns the number sent, or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
EXPORT_SYMBOL ssize_t XLIO_SYMBOL(sendto)(int __fd, __const void *__buf, size_t __nbytes,
                                          int __flags, const struct sockaddr *__to,
                                          socklen_t __tolen)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("fd=%d, nbytes=%d", __fd, __nbytes);

    sockinfo *p_socket_object = nullptr;
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

    return SYSCALL(sendto, __fd, __buf, __nbytes, __flags, __to, __tolen);
}

EXPORT_SYMBOL ssize_t XLIO_SYMBOL(sendfile)(int out_fd, int in_fd, off_t *offset, size_t count)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("out_fd=%d, in_fd=%d, offset=%p, *offset=%zu, count=%d", out_fd, in_fd,
                          offset, offset ? *offset : 0, count);

    sockinfo *p_socket_object = fd_collection_get_sockfd(out_fd);
    if (!p_socket_object) {
        return SYSCALL(sendfile, out_fd, in_fd, offset, count);
    }

    return sendfile_helper(p_socket_object, in_fd, offset, count);
}

EXPORT_SYMBOL ssize_t XLIO_SYMBOL(sendfile64)(int out_fd, int in_fd, __off64_t *offset,
                                              size_t count)
{
    PROFILE_FUNC

    srdr_logfuncall_entry("out_fd=%d, in_fd=%d, offset=%p, *offset=%zu, count=%d", out_fd, in_fd,
                          offset, offset ? *offset : 0, count);

    sockinfo *p_socket_object = fd_collection_get_sockfd(out_fd);
    if (!p_socket_object) {
        return SYSCALL(sendfile64, out_fd, in_fd, offset, count);
    }

    return sendfile_helper(p_socket_object, in_fd, offset, count);
}

EXPORT_SYMBOL int XLIO_SYMBOL(select)(int __nfds, fd_set *__readfds, fd_set *__writefds,
                                      fd_set *__exceptfds, struct timeval *__timeout)
{
    PROFILE_FUNC

    if (!g_p_fd_collection) {
        return SYSCALL(select, __nfds, __readfds, __writefds, __exceptfds, __timeout);
    }

    if (__timeout) {
        srdr_logfunc_entry("nfds=%d, timeout=(%d sec, %d usec)", __nfds, __timeout->tv_sec,
                           __timeout->tv_usec);
    } else {
        srdr_logfunc_entry("nfds=%d, timeout=(infinite)", __nfds);
    }

    return select_helper(__nfds, __readfds, __writefds, __exceptfds, __timeout);
}

EXPORT_SYMBOL int XLIO_SYMBOL(pselect)(int __nfds, fd_set *__readfds, fd_set *__writefds,
                                       fd_set *__errorfds, const struct timespec *__timeout,
                                       const sigset_t *__sigmask)
{
    PROFILE_FUNC

    if (!g_p_fd_collection) {
        return SYSCALL(pselect, __nfds, __readfds, __writefds, __errorfds, __timeout, __sigmask);
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

    return select_helper(__nfds, __readfds, __writefds, __errorfds,
                         __timeout ? &select_time : nullptr, __sigmask);
}

EXPORT_SYMBOL int XLIO_SYMBOL(poll)(struct pollfd *__fds, nfds_t __nfds, int __timeout)
{
    PROFILE_FUNC

    if (!g_p_fd_collection) {
        return SYSCALL(poll, __fds, __nfds, __timeout);
    }

    srdr_logfunc_entry("nfds=%d, timeout=(%d milli-sec)", __nfds, __timeout);

    return poll_helper(__fds, __nfds, __timeout);
}

#if defined HAVE___POLL_CHK && !defined(XLIO_STATIC_BUILD)
EXPORT_SYMBOL int XLIO_SYMBOL(__poll_chk)(struct pollfd *__fds, nfds_t __nfds, int __timeout,
                                          size_t __fdslen)
{
    PROFILE_FUNC

    if (!g_p_fd_collection) {
        return SYSCALL(__poll_chk, __fds, __nfds, __timeout, __fdslen);
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

EXPORT_SYMBOL int XLIO_SYMBOL(ppoll)(struct pollfd *__fds, nfds_t __nfds,
                                     const struct timespec *__timeout, const sigset_t *__sigmask)
{
    PROFILE_FUNC

    if (!g_p_fd_collection) {
        return SYSCALL(ppoll, __fds, __nfds, __timeout, __sigmask);
    }

    int timeout = (!__timeout) ? -1 : (__timeout->tv_sec * 1000 + __timeout->tv_nsec / 1000000);

    srdr_logfunc_entry("nfds=%d, timeout=(%d milli-sec)", __nfds, timeout);

    return poll_helper(__fds, __nfds, timeout, __sigmask);
}

#if defined HAVE___PPOLL_CHK && !defined(XLIO_STATIC_BUILD)
EXPORT_SYMBOL int XLIO_SYMBOL(__ppoll_chk)(struct pollfd *__fds, nfds_t __nfds,
                                           const struct timespec *__timeout,
                                           const sigset_t *__sigmask, size_t __fdslen)
{
    PROFILE_FUNC

    if (!g_p_fd_collection) {
        return SYSCALL(__ppoll_chk, __fds, __nfds, __timeout, __sigmask, __fdslen);
    }

    BULLSEYE_EXCLUDE_BLOCK_START
    if (__fdslen / sizeof(*__fds) < __nfds) {
        srdr_logpanic("buffer overflow detected");
    }

    BULLSEYE_EXCLUDE_BLOCK_END

    int timeout = (!__timeout) ? -1 : (__timeout->tv_sec * 1000 + __timeout->tv_nsec / 1000000);

    srdr_logfunc_entry("nfds=%d, timeout=(%d milli-sec)", __nfds, timeout);

    return poll_helper(__fds, __nfds, timeout, __sigmask);
}
#endif

/**
 * @brief Creates an epoll instance
 *
 * @param[in] __size  A hint specifying the number of file descriptors to be associated with the new
 * instance
 * @return            File descriptor for the new instance, or -1 on error
 *
 * @note The fd returned by epoll_create() should be closed with close()
 * @note coverity[UNCAUGHT_EXCEPT] was added as it's a False Positive
 */
// coverity[UNCAUGHT_EXCEPT]
EXPORT_SYMBOL int XLIO_SYMBOL(epoll_create)(int __size)
{
    DO_GLOBAL_CTORS();

    PROFILE_FUNC

    if (__size <= 0) {
        srdr_logdbg("invalid size (size=%d) - must be a positive integer", __size);
        errno = EINVAL;
        return -1;
    }

    int epfd = SYSCALL(epoll_create, __size + 1); // +1 for the cq epfd
    srdr_logdbg("ENTER: (size=%d) = %d", __size, epfd);

    if (epfd <= 0) {
        return epfd;
    }

    xlio_epoll_create(epfd, 8);

    return epfd;
}

/**
 * @brief Creates an epoll instance with additional options
 *
 * @param[in] __flags  Option flags for the new instance
 * @return             File descriptor for the new instance, or -1 on error
 *
 * @note The fd returned by epoll_create1() should be closed with close()
 * @note coverity[UNCAUGHT_EXCEPT] was added as it's a False Positive
 */
// coverity[UNCAUGHT_EXCEPT]
EXPORT_SYMBOL int XLIO_SYMBOL(epoll_create1)(int __flags)
{
    DO_GLOBAL_CTORS();

    PROFILE_FUNC

    int epfd = SYSCALL(epoll_create1, __flags);
    srdr_logdbg("ENTER: (flags=%d) = %d", __flags, epfd);

    if (epfd <= 0) {
        return epfd;
    }

    xlio_epoll_create(epfd, 8);

    return epfd;
}

/**
 * @brief Manipulates an epoll instance
 *
 * @param[in] __epfd  The file descriptor of the epoll instance
 * @param[in] __op    The operation to perform
 * @param[in] __fd    The target of the operation
 * @param[in] __event The event to be monitored
 * @return             0 on success, -1 on error
 *
 * @note coverity[UNCAUGHT_EXCEPT] was added as it's a False Positive
 */
// coverity[UNCAUGHT_EXCEPT]
EXPORT_SYMBOL int XLIO_SYMBOL(epoll_ctl)(int __epfd, int __op, int __fd,
                                         struct epoll_event *__event)
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
            rc = g_p_app->proc_envoy(__op, __fd);
            if (rc != 0) {
                errno = EINVAL;
                return -1;
            }
        }
#endif /* DEFINED_ENVOY */

        // TODO handle race - if close() gets here..
        rc = epfd_info->ctl(__op, __fd, __event);
    }

    srdr_logfunc_exit("rc = %d", rc);
    return rc;
}

EXPORT_SYMBOL int XLIO_SYMBOL(epoll_wait)(int __epfd, struct epoll_event *__events, int __maxevents,
                                          int __timeout)
{
    PROFILE_FUNC

    srdr_logfunc_entry("epfd=%d, maxevents=%d, timeout=(%d milli-sec)", __epfd, __maxevents,
                       __timeout);

    return epoll_wait_helper(__epfd, __events, __maxevents, __timeout);
}

EXPORT_SYMBOL int XLIO_SYMBOL(epoll_pwait)(int __epfd, struct epoll_event *__events,
                                           int __maxevents, int __timeout,
                                           const sigset_t *__sigmask)
{
    PROFILE_FUNC

    srdr_logfunc_entry("epfd=%d, maxevents=%d, timeout=(%d milli-sec)", __epfd, __maxevents,
                       __timeout);

    return epoll_wait_helper(__epfd, __events, __maxevents, __timeout, __sigmask);
}

/**
 * @brief Creates a pair of connected sockets
 *
 * @param[in] __domain  The domain of the sockets
 * @param[in] __type    The type of the sockets
 * @param[in] __protocol The protocol of the sockets
 * @param[out] __sv      Array to store the file descriptors
 * @return               0 on success, -1 on error
 *
 * @note coverity[UNCAUGHT_EXCEPT] was added as it's a False Positive
 */
// coverity[UNCAUGHT_EXCEPT]
EXPORT_SYMBOL int XLIO_SYMBOL(socketpair)(int __domain, int __type, int __protocol, int __sv[2])
{
    PROFILE_FUNC

    int ret = SYSCALL(socketpair, __domain, __type, __protocol, __sv);

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

/**
 * @brief Creates a one-way communication channel (pipe)
 *
 * @param[out] __filedes  Array to store the file descriptors
 * @return                0 if successful, -1 if not
 *
 * @note coverity[UNCAUGHT_EXCEPT] was added as it's a False Positive
 */
// coverity[UNCAUGHT_EXCEPT]
EXPORT_SYMBOL int XLIO_SYMBOL(pipe)(int __filedes[2])
{
    PROFILE_FUNC

    int ret = SYSCALL(pipe, __filedes);
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

EXPORT_SYMBOL int XLIO_SYMBOL(open)(__const char *__file, int __oflag, ...)
{
    va_list va;
    va_start(va, __oflag);
    mode_t mode = va_arg(va, mode_t);

    PROFILE_FUNC

    int fd = SYSCALL(open, __file, __oflag, mode);
    va_end(va);

    srdr_logdbg("(file=%s, flags=%#x, mode=%#x) = %d", __file, __oflag, mode, fd);

    // Sanity check to remove any old sockinfo object using the same fd!!
    handle_close(fd, true);

    return fd;
}

EXPORT_SYMBOL int XLIO_SYMBOL(creat)(const char *__pathname, mode_t __mode)
{
    PROFILE_FUNC

    int fd = SYSCALL(creat, __pathname, __mode);

    srdr_logdbg("(pathname=%s, mode=%#x) = %d", __pathname, __mode, fd);

    // Sanity check to remove any old sockinfo object using the same fd!!
    handle_close(fd, true);

    return fd;
}

/**
 * @brief Duplicates a file descriptor
 *
 * @param[in] __fd  The file descriptor to duplicate
 * @return            The new file descriptor, or -1 on error
 *
 * @note coverity[UNCAUGHT_EXCEPT] was added as it's a False Positive
 */
// coverity[UNCAUGHT_EXCEPT]
EXPORT_SYMBOL int XLIO_SYMBOL(dup)(int __fd)
{
    PROFILE_FUNC

    int fid = SYSCALL(dup, __fd);

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

/**
 * @brief Duplicates a file descriptor
 *
 * @param[in] __fd  The file descriptor to duplicate
 * @param[in] __fd2 The file descriptor to duplicate to
 * @return            The new file descriptor, or -1 on error
 *
 * @note coverity[UNCAUGHT_EXCEPT] was added as it's a False Positive
 */
// coverity[UNCAUGHT_EXCEPT]
EXPORT_SYMBOL int XLIO_SYMBOL(dup2)(int __fd, int __fd2)
{
    PROFILE_FUNC

    if (safe_mce_sys().close_on_dup2 && __fd != __fd2) {
        srdr_logdbg("oldfd=%d, newfd=%d. Closing %d in XLIO.", __fd, __fd2, __fd2);
        handle_close(__fd2);
    }

    int fid = SYSCALL(dup2, __fd, __fd2);

    srdr_logdbg("(fd=%d, fd2=%d) = %d", __fd, __fd2, fid);

    // Sanity check to remove any old sockinfo object using the same fd!!
    handle_close(fid, true);

    return fid;
}

/**
 * @brief Clones the calling process
 *
 * @return Process ID of the new process, or -1 on error
 *
 * @note coverity[UNCAUGHT_EXCEPT] was added as it's a False Positive
 */
// coverity[UNCAUGHT_EXCEPT]
EXPORT_SYMBOL pid_t XLIO_SYMBOL(fork)(void)
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

    pid_t pid = SYSCALL(fork);
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

        safe_mce_sys().get_params();
        vlog_start(PRODUCT_NAME, safe_mce_sys().log_level, safe_mce_sys().log_filename,
                   safe_mce_sys().log_details, safe_mce_sys().log_colors);
        if (xlio_rdma_lib_reset()) {
            srdr_logerr("Child Process: rdma_lib_reset failed %d %s", errno, strerror(errno));
        }
        srdr_logdbg_exit("Child Process: starting with %d", getpid());
        g_is_forked_child = false;

        // In delegate mode, reset thread-local timer state after fork.
        // Child inherits parent's m_last_run_time which causes timers to be
        // rate-limited for up to 100ms, breaking TCP retransmit logic.
        if (safe_mce_sys().tcp_ctl_thread == option_tcp_ctl_thread::CTL_THREAD_DELEGATE_TCP_TIMERS) {
            g_event_handler_manager_local.reset_after_fork();
            srdr_logdbg("Child Process: reset delegate mode timers after fork");
        }

        const char *stats_filename = getenv(SYS_VAR_STATS_FILENAME);
        if (stats_filename && strstr(stats_filename, "%d")) {
            // Re-open the stats file in case of per-process filename.
            if (g_stats_file) {
                fclose(g_stats_file);
                g_stats_file = nullptr;
            }
            open_stats_file();
        }
        sock_redirect_main();

#if defined(DEFINED_NGINX)
        if (g_p_app && g_p_app->type == APP_NGINX) {
            g_p_app->map_thread_id[gettid()] = worker_index;
            /* Child process needs information about
             * listen sockinfo objects, so pass this using parent`s g_p_fd_collection.
             * It is possible as far as parent`s g_p_fd_collection is not deleted
             * by reset_globals()
             */
            g_p_app->context = (void *)p_fd_collection_temp;

            /* Do this only for regular user, not allowed for root user.
             * Root user will be handled in setuid call.
             */
            if (geteuid() != 0) {
                int rc = g_p_app->proc_nginx();
                if (rc != 0) {
                    errno = ENOMEM;
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
EXPORT_SYMBOL pid_t XLIO_SYMBOL(vfork)(void)
{
    PROFILE_FUNC

    return XLIO_CALL(fork);
}

/**
 * @brief Puts the program in the background
 *
 * @param[in] __nochdir  If zero, do `chdir ("/")'
 * @param[in] __noclose  If zero, redirect stdin, stdout, and stderr to /dev/null
 * @return               Process ID of the new process, or -1 on error
 *
 * @note coverity[UNCAUGHT_EXCEPT] was added as it's a False Positive
 */
// coverity[UNCAUGHT_EXCEPT]
EXPORT_SYMBOL int XLIO_SYMBOL(daemon)(int __nochdir, int __noclose)
{
    PROFILE_FUNC

    srdr_logdbg("ENTER: ***** (%d, %d) *****", __nochdir, __noclose);

    if (!g_init_global_ctors_done) {
        set_env_params();
        prepare_fork();
    }

    int ret = SYSCALL(daemon, __nochdir, __noclose);
    if (ret == 0) {
        g_is_forked_child = true;
        srdr_logdbg_exit("returned with %d", ret);

        // Child's process - restart module
        vlog_stop();

        // In case of child process, we want all global objects to re-construct
        reset_globals();

        g_init_global_ctors_done = false;
        sock_redirect_exit();

        safe_mce_sys().get_params();
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

/**
 * @brief Sets up a signal handler
 *
 * @param[in] signum  Signal number to set the handler for
 * @param[in] act     Pointer to the signal action structure
 * @param[out] oldact Pointer to store the previous signal action
 * @return            Previous signal action, or SIG_ERR on error
 *
 * @note coverity[UNCAUGHT_EXCEPT] was added as it's a False Positive
 */
// coverity[UNCAUGHT_EXCEPT]
EXPORT_SYMBOL int XLIO_SYMBOL(sigaction)(int signum, const struct sigaction *act,
                                         struct sigaction *oldact)
{
    return sigaction_internal(signum, act, oldact);
}

/**
 * @brief Sets up a signal handler
 *
 * @param[in] signum  Signal number to set the handler for
 * @param[in] handler Signal handler function
 * @return            Previous signal handler, or SIG_ERR on error
 *
 * @note coverity[UNCAUGHT_EXCEPT] was added as it's a False Positive
 */
// coverity[UNCAUGHT_EXCEPT]
EXPORT_SYMBOL sighandler_t XLIO_SYMBOL(signal)(int signum, sighandler_t handler)
{
    PROFILE_FUNC

    if (safe_mce_sys().handle_sigintr) {
        srdr_logdbg_entry("signum=%d, handler=%p", signum, handler);

        if (handler && handler != SIG_ERR && handler != SIG_DFL && handler != SIG_IGN) {
            // Only SIGINT is supported for now
            if (signum == SIGINT) {
                g_sighandler = handler;
                return SYSCALL(signal, SIGINT, &handle_signal);
            }
        }
    }

    return SYSCALL(signal, signum, handler);
}

#if defined(DEFINED_NGINX)

/**
 * @brief Sets the user ID of the calling process
 *
 * @param[in] uid  The user ID to set
 * @return          The previous user ID, or -1 on error
 *
 * @note coverity[UNCAUGHT_EXCEPT] was added as it's a False Positive
 */
// coverity[UNCAUGHT_EXCEPT]
EXPORT_SYMBOL int XLIO_SYMBOL(setuid)(uid_t uid)
{
    PROFILE_FUNC

    uid_t previous_uid = geteuid();
    int orig_rc = SYSCALL(setuid, uid);
    if (orig_rc < 0) {
        srdr_logdbg_exit("failed (errno=%d %m)", errno);
    }

    // Do this only for root user, regular user will be handled in fork call.
    if (g_p_app && g_p_app->type == APP_NGINX && previous_uid == 0) {
        orig_rc = g_p_app->proc_nginx();
    }

    return orig_rc;
}

EXPORT_SYMBOL pid_t XLIO_SYMBOL(waitpid)(pid_t pid, int *wstatus, int options)
{
    PROFILE_FUNC

    pid_t child_pid = SYSCALL(waitpid, pid, wstatus, options);
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
}
