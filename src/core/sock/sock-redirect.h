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

#ifndef SOCK_REDIRECT_H
#define SOCK_REDIRECT_H

// if you need select with more than 1024 sockets - enable this
#ifndef SELECT_BIG_SETSIZE
#define SELECT_BIG_SETSIZE 0
#endif

#if SELECT_BIG_SETSIZE
#include <features.h>
#if (__GLIBC__ > 2) || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 2)
#include <bits/types.h>
#undef __FD_SETSIZE
#define __FD_SETSIZE 32768
#endif
#endif // SELECT_BIG_SETSIZE

#include <stdint.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <features.h>
#include <signal.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <time.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <resolv.h>

#include <core/util/vtypes.h>
#include <core/util/xlio_stats.h>
#include <core/util/sys_vars.h>
#include <core/util/utils.h>
#include <utils/lock_wrapper.h>

#include <vlogger/vlogger.h>
#include <unordered_map>
#include <vector>
#include <mutex>

#if defined(DEFINED_NGINX)
typedef std::unordered_map<uint16_t, bool> map_udp_bounded_port_t;

extern std::vector<pid_t> *g_p_nginx_worker_pids;
extern int g_worker_index;
extern bool g_b_add_second_4t_rule;
extern map_udp_bounded_port_t g_map_udp_bounded_port;
#endif
#if defined(DEFINED_ENVOY)
struct app_conf {
    enum { APP_NONE, APP_NGINX, APP_ENVOY } type;
    lock_spin_recursive m_lock;
    int workers_num;
    int workers_pow2;
    int src_port_stride;
    bool add_second_4t_rule;
    struct attr {
        struct envoy {
            std::unordered_map<int, pid_t> map_listen_fd;
            std::unordered_map<pid_t, int> map_thread_id;
            std::unordered_map<int, int> map_dup_fd;
        } envoy;
    } attr;

    app_conf()
    {
        this->type = APP_NONE;
        m_lock = lock_spin_recursive("app_conf");
        this->workers_num = 0;
        this->workers_pow2 = 0;
        this->src_port_stride = 2;
        this->add_second_4t_rule = false;
        this->attr.envoy.map_listen_fd.clear();
        this->attr.envoy.map_thread_id.clear();
        this->attr.envoy.map_dup_fd.clear();
    }

    ~app_conf() {}

    inline int get_worker_id()
    {
        std::lock_guard<decltype(this->m_lock)> lock(this->m_lock);
        auto itr = this->attr.envoy.map_thread_id.find(gettid());
        if (itr != this->attr.envoy.map_thread_id.end()) {
            return itr->second;
        }
        return -1;
    }
};
extern struct app_conf *g_p_app;
#endif /* DEFINED_ENVOY */

struct mmsghdr;

/**
 *-----------------------------------------------------------------------------
 *  variables to hold the function-pointers to original functions
 *-----------------------------------------------------------------------------
 */

struct os_api {
    int (*creat)(const char *__pathname, mode_t __mode);
    int (*open)(__const char *__file, int __oflag, ...);
    int (*dup)(int fildes);
    int (*dup2)(int fildes, int fildes2);
    int (*pipe)(int __filedes[2]);
    int (*socket)(int __domain, int __type, int __protocol);
    int (*socketpair)(int __domain, int __type, int __protocol, int __sv[2]);

    int (*close)(int __fd);
    int (*__res_iclose)(res_state statp, bool free_addr);
    int (*shutdown)(int __fd, int __how);

    int (*accept)(int __fd, struct sockaddr *__addr, socklen_t *__addrlen);
    int (*accept4)(int __fd, struct sockaddr *__addr, socklen_t *__addrlen, int __flags);
    int (*bind)(int __fd, const struct sockaddr *__addr, socklen_t __addrlen);
    int (*connect)(int __fd, const struct sockaddr *__to, socklen_t __tolen);
    int (*listen)(int __fd, int __backlog);

    int (*setsockopt)(int __fd, int __level, int __optname, __const void *__optval,
                      socklen_t __optlen);
    int (*getsockopt)(int __fd, int __level, int __optname, void *__optval, socklen_t *__optlen);
    int (*fcntl)(int __fd, int __cmd, ...);
    int (*fcntl64)(int __fd, int __cmd, ...);
    int (*ioctl)(int __fd, unsigned long int __request, ...);
    int (*getsockname)(int __fd, struct sockaddr *__name, socklen_t *__namelen);
    int (*getpeername)(int __fd, struct sockaddr *__name, socklen_t *__namelen);

    ssize_t (*read)(int __fd, void *__buf, size_t __nbytes);
#if defined HAVE___READ_CHK
    ssize_t (*__read_chk)(int __fd, void *__buf, size_t __nbytes, size_t __buflen);
#endif
    ssize_t (*readv)(int __fd, const struct iovec *iov, int iovcnt);
    ssize_t (*recv)(int __fd, void *__buf, size_t __n, int __flags);
#if defined HAVE___RECV_CHK
    ssize_t (*__recv_chk)(int __fd, void *__buf, size_t __n, size_t __buflen, int __flags);
#endif
    ssize_t (*recvmsg)(int __fd, struct msghdr *__message, int __flags);
    int (*recvmmsg)(int __fd, struct mmsghdr *__mmsghdr, unsigned int __vlen, int __flags,
                    const struct timespec *__timeout);

    ssize_t (*recvfrom)(int __fd, void *__restrict __buf, size_t __n, int __flags,
                        struct sockaddr *__from, socklen_t *__fromlen);
#if defined HAVE___RECVFROM_CHK
    ssize_t (*__recvfrom_chk)(int __fd, void *__restrict __buf, size_t __n, size_t __buflen,
                              int __flags, struct sockaddr *__from, socklen_t *__fromlen);
#endif

    ssize_t (*write)(int __fd, __const void *__buf, size_t __n);
    ssize_t (*writev)(int __fd, const struct iovec *iov, int iovcnt);
    ssize_t (*send)(int __fd, __const void *__buf, size_t __n, int __flags);
    ssize_t (*sendmsg)(int __fd, __const struct msghdr *__message, int __flags);
    ssize_t (*sendmmsg)(int __fd, struct mmsghdr *__mmsghdr, unsigned int __vlen, int __flags);
    ssize_t (*sendto)(int __fd, __const void *__buf, size_t __n, int __flags,
                      const struct sockaddr *__to, socklen_t __tolen);
    ssize_t (*sendfile)(int out_fd, int in_fd, off_t *offset, size_t count);
    ssize_t (*sendfile64)(int out_fd, int in_fd, __off64_t *offset, size_t count);

    int (*select)(int __nfds, fd_set *__readfds, fd_set *__writefds, fd_set *__exceptfds,
                  struct timeval *__timeout);
    int (*pselect)(int __nfds, fd_set *__readfds, fd_set *__writefds, fd_set *__errorfds,
                   const struct timespec *__timeout, const sigset_t *__sigmask);

    int (*poll)(struct pollfd *__fds, nfds_t __nfds, int __timeout);
#if defined HAVE___POLL_CHK
    int (*__poll_chk)(struct pollfd *__fds, nfds_t __nfds, int __timeout, size_t __fdslen);
#endif
    int (*ppoll)(struct pollfd *__fds, nfds_t __nfds, const struct timespec *__timeout,
                 const sigset_t *__sigmask);
#if defined HAVE___PPOLL_CHK
    int (*__ppoll_chk)(struct pollfd *__fds, nfds_t __nfds, const struct timespec *__timeout,
                       const sigset_t *__sigmask, size_t __fdslen);
#endif
    int (*epoll_create)(int __size);
    int (*epoll_create1)(int __flags);
    int (*epoll_ctl)(int __epfd, int __op, int __fd, struct epoll_event *__event);
    int (*epoll_wait)(int __epfd, struct epoll_event *__events, int __maxevents, int __timeout);
    int (*epoll_pwait)(int __epfd, struct epoll_event *__events, int __maxevents, int __timeout,
                       const sigset_t *sigmask);

    int (*clone)(int (*__fn)(void *), void *__child_stack, int __flags, void *__arg);
    pid_t (*fork)(void);
    pid_t (*vfork)(void);
    int (*daemon)(int __nochdir, int __noclose);

    int (*sigaction)(int signum, const struct sigaction *act, struct sigaction *oldact);
    sighandler_t (*signal)(int signum, sighandler_t handler);
#if defined(DEFINED_NGINX)
    int (*setuid)(uid_t uid);
    pid_t (*waitpid)(pid_t pid, int *wstatus, int options);
#endif // DEFINED_NGINX
};

/**
 *-----------------------------------------------------------------------------
 *  variables to hold the function-pointers to original functions
 *-----------------------------------------------------------------------------
 */
extern os_api orig_os_api;

extern void get_orig_funcs();

extern iomux_stats_t *g_p_select_stats;
extern iomux_stats_t *g_p_poll_stats;
extern iomux_stats_t *g_p_epoll_stats;

int do_global_ctors();
void reset_globals();
bool handle_close(int fd, bool cleanup = false, bool passthrough = false);

// allow calling our socket(...) implementation safely from within libxlio.so
// this is critical in case XLIO was loaded using dlopen and not using LD_PRELOAD
// TODO: look for additional such functions/calls
int socket_internal(int __domain, int __type, int __protocol, bool shadow, bool check_offload);

#endif // SOCK_REDIRECT_H
