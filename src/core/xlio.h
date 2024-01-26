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

#ifndef XLIO_H
#define XLIO_H

#include <signal.h>
#include <sys/poll.h>

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

#ifdef __cplusplus
}
#endif
#endif /* XLIO_EXTRA_H */
