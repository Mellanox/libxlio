/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
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

#ifndef XLIO_H
#define XLIO_H

#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "xlio_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int xlio_socket(int __domain, int __type, int __protocol);

int xlio_close(int __fd);

int xlio_shutdown(int __fd, int __how);

int xlio_listen(int __fd, int backlog);

int xlio_accept(int __fd, struct sockaddr *__addr, socklen_t *__addrlen);

int xlio_accept4(int __fd, struct sockaddr *__addr, socklen_t *__addrlen, int __flags);

int xlio_bind(int __fd, const struct sockaddr *__addr, socklen_t __addrlen);

int xlio_connect(int __fd, const struct sockaddr *__to, socklen_t __tolen);

int xlio_setsockopt(int __fd, int __level, int __optname, __const void *__optval,
                    socklen_t __optlen);

int xlio_getsockopt(int __fd, int __level, int __optname, void *__optval, socklen_t *__optlen);

int xlio_fcntl(int __fd, int __cmd, ...);

int xlio_fcntl64(int __fd, int __cmd, ...);

int xlio_ioctl(int __fd, unsigned long int __request, ...);

int xlio_getsockname(int __fd, struct sockaddr *__name, socklen_t *__namelen);

int xlio_getpeername(int __fd, struct sockaddr *__name, socklen_t *__namelen);

ssize_t xlio_read(int __fd, void *__buf, size_t __nbytes);

ssize_t xlio_readv(int __fd, const struct iovec *iov, int iovcnt);

ssize_t xlio_recv(int __fd, void *__buf, size_t __nbytes, int __flags);

ssize_t xlio_recvmsg(int __fd, struct msghdr *__msg, int __flags);

struct mmsghdr;

int xlio_recvmmsg(int __fd, struct mmsghdr *__mmsghdr, unsigned int __vlen, int __flags,
                  const struct timespec *__timeout);

ssize_t xlio_recvfrom(int __fd, void *__buf, size_t __nbytes, int __flags, struct sockaddr *__from,
                      socklen_t *__fromlen);

ssize_t xlio_write(int __fd, __const void *__buf, size_t __nbytes);

ssize_t xlio_writev(int __fd, const struct iovec *iov, int iovcnt);

ssize_t xlio_send(int __fd, __const void *__buf, size_t __nbytes, int __flags);

ssize_t xlio_sendmsg(int __fd, __const struct msghdr *__msg, int __flags);

int xlio_sendmmsg(int __fd, struct mmsghdr *__mmsghdr, unsigned int __vlen, int __flags);

ssize_t xlio_sendto(int __fd, __const void *__buf, size_t __nbytes, int __flags,
                    const struct sockaddr *__to, socklen_t __tolen);

ssize_t xlio_sendfile(int out_fd, int in_fd, off_t *offset, size_t count);

ssize_t xlio_sendfile64(int out_fd, int in_fd, __off64_t *offset, size_t count);

int xlio_select(int __nfds, fd_set *__readfds, fd_set *__writefds, fd_set *__exceptfds,
                struct timeval *__timeout);

int xlio_pselect(int __nfds, fd_set *__readfds, fd_set *__writefds, fd_set *__errorfds,
                 const struct timespec *__timeout, const sigset_t *__sigmask);
int xlio_poll(struct pollfd *__fds, nfds_t __nfds, int __timeout);

int xlio_ppoll(struct pollfd *__fds, nfds_t __nfds, const struct timespec *__timeout,
               const sigset_t *__sigmask);

int xlio_epoll_create(int __size);

int xlio_epoll_create1(int __flags);

int xlio_epoll_ctl(int __epfd, int __op, int __fd, struct epoll_event *__event);

int xlio_epoll_wait(int __epfd, struct epoll_event *__events, int __maxevents, int __timeout);

int xlio_epoll_pwait(int __epfd, struct epoll_event *__events, int __maxevents, int __timeout,
                     const sigset_t *__sigmask);
int xlio_socketpair(int __domain, int __type, int __protocol, int __sv[2]);

int xlio_pipe(int __filedes[2]);

int xlio_open(__const char *__file, int __oflag, ...);

int xlio_creat(const char *__pathname, mode_t __mode);

int xlio_dup(int __fd);

int xlio_dup2(int __fd, int __fd2);

/* Before using XLIO static interface call xlio_init; */
int xlio_init(void);

/* After finishing workling with XLIO interface call xlio_exit */
int xlio_exit(void);

/*
 * Add a libxlio.conf rule to the top of the list.
 * This rule will not apply to existing sockets which already considered the conf rules.
 * (around connect/listen/send/recv ..)
 * @param config_line A char buffer with the exact format as defined in libxlio.conf, and should
 * end with '\0'.
 * @return 0 on success, or error code on failure.
 */
int xlio_add_conf_rule(const char *config_line);

/*
 * Create sockets on pthread tid as offloaded/not-offloaded.
 * This does not affect existing sockets.
 * Offloaded sockets are still subject to libxlio.conf rules.
 * @param offload 1 for offloaded, 0 for not-offloaded.
 * @return 0 on success, or error code on failure.
 */
int xlio_thread_offload(int offload, pthread_t tid);

/*
 * Dump fd statistics using the library logger.
 * @param fd to dump, 0 for all open fds.
 * @param log_level dumping level corresponding vlog_levels_t enum (vlogger.h).
 * @return 0 on success, or error code on failure.
 */
int xlio_dump_fd_stats(int fd, int log_level);

/**
 * This function allows to communicate with library using extendable protocol
 * based on struct cmshdr.
 *
 * Ancillary data is a sequence of cmsghdr structures with appended data.
 * The sequence of cmsghdr structures should never be accessed directly.
 * Instead, use only the following macros: CMSG_ALIGN, CMSG_SPACE, CMSG_DATA,
 * CMSG_LEN.
 *
 * @param cmsg_hdr - point to control message
 * @param cmsg_len - the byte count of the ancillary data,
 *                   which contains the size of the structure header.
 *
 * @return -1 on failure and 0 on success
 */
int xlio_extra_ioctl(void *cmsg_hdr, size_t cmsg_len);

/*
 * XLIO Socket API
 *
 * This is performance-oriented event based API.
 */

/*
 * XLIO initialization.
 *
 * xlio_init_ex() must be called before using any XLIO Socket API. This is heavy operation.
 * xlio_init_ex() is not thread-safe operation, however, subsequent serialized calls exit
 * successfully without any action.
 *
 * If set, xlio_init_attr::memory_cb() notifies about memory blocks which are allocated to
 * buffers. Each zerocopy RX buffer resides within one such memory block.
 * If set, XLIO uses external allocator xlio_init_attr::memory_alloc() instead of the internal.
 * Current implementation allocates a single memory block and does it in xlio_init_ex() context.
 */
int xlio_init_ex(const struct xlio_init_attr *attr);

/*
 * XLIO polling groups.
 *
 * Event callbacks are registered per group. This allows to move control flow connections to
 * a separate group and implement RX / completion logic differently.
 *
 * xlio_poll_group_poll() polls HW for events and executes TCP timers. Most of the callbacks are
 * expected from the context of this call.
 *
 * Recommendations:
 *  - Groups are expected to be long lived objects. Frequent creation/destruction has a penalty.
 *  - Reduce the number of different network interfaces within a group to minimum. This will
 *    optimize the HW objects utilization. However, maintaining extra groups can have an overhead.
 */

int xlio_poll_group_create(const struct xlio_poll_group_attr *attr, xlio_poll_group_t *group_out);
int xlio_poll_group_destroy(xlio_poll_group_t group);
void xlio_poll_group_poll(xlio_poll_group_t group);

/*
 * XLIO socket.
 *
 * XLIO socket is represented by xlio_socket_t instead of file descriptor. This is a TCP
 * non-blocking socket abstraction.
 *
 * xlio_socket_destroy() triggers socket closing procedure. The process can be asynchronous
 * and socket events may be expected until XLIO_SOCKET_EVENT_TERMINATED event arrives.
 * Example of the possible events is zerocopy completions which can arrive from the
 * xlio_socket_destroy() context or xlio_poll_group_poll() context.
 *
 * Limitations:
 *  - Only outgoing connections are supported
 *  - Bonding is not supported
 */

/* Forward declaration. */
struct ibv_pd;

int xlio_socket_create(const struct xlio_socket_attr *attr, xlio_socket_t *sock_out);
int xlio_socket_destroy(xlio_socket_t sock);
int xlio_socket_setsockopt(xlio_socket_t sock, int level, int optname, const void *optval,
                           socklen_t optlen);
int xlio_socket_bind(xlio_socket_t sock, const struct sockaddr *addr, socklen_t addrlen);
int xlio_socket_connect(xlio_socket_t sock, const struct sockaddr *to, socklen_t tolen);
struct ibv_pd *xlio_socket_get_pd(xlio_socket_t sock);

/*
 * TX flow.
 *
 * Properties of the TX flow:
 *  - Non-blocking
 *  - No partial write support - accepts all data unless memory allocation error happens
 *  - Each send call expects a complete or part of a single PDU or message. This is a requirement
 *    in case of either crypto or CRC offload is enabled.
 *  - User requests zerocopy completion callback with non-zero userdata_op value and controls
 *    the logic of completions. For example, each completion can complete entire PDU object.
 *  - Inline send operations don't trigger the completion callback.
 *  - XLIO aggregates data on socket and pushes it to wire with the flush-like API or
 *    XLIO_SOCKET_SEND_FLAG_FLUSH flag.
 *
 * **Current limitations**:
 *  - Currently, data can be pushes to wire in the RX flow regardless of the flush logic.
 *  - Avoid using xlio_socket_flush() for a XLIO_GROUP_FLAG_DIRTY group.
 *  - For a XLIO_GROUP_FLAG_DIRTY group, usage of XLIO_SOCKET_SEND_FLAG_FLUSH is limited,
 *    it's better to avoid using them both.
 */

/* Returns either 0 or -1. The errors, except of ENOMEM, are not recoverable. */
int xlio_socket_send(xlio_socket_t sock, const void *data, size_t len,
                     const struct xlio_socket_send_attr *attr);
int xlio_socket_sendv(xlio_socket_t sock, const struct iovec *iov, unsigned iovcnt,
                      const struct xlio_socket_send_attr *attr);
void xlio_poll_group_flush(xlio_poll_group_t group);
void xlio_socket_flush(xlio_socket_t sock);

/*
 * RX flow.
 */

void xlio_socket_buf_free(xlio_socket_t sock, struct xlio_buf *buf);
void xlio_poll_group_buf_free(xlio_poll_group_t group, struct xlio_buf *buf);

#ifdef __cplusplus
}
#endif
#endif /* XLIO_H */
