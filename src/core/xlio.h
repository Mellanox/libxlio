/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2024-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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

/**
 * Returns the amount of rings that are associated with socket.
 *
 * @param fd File Descriptor number of the socket.
 * @return On success, return the amount of rings.
 *         On error, -1 is returned.
 *
 * errno is set to: EINVAL - not a offloaded fd
 */
int xlio_get_socket_rings_num(int fd);

/**
 * Returns FDs of the RX rings that are associated with the socket.
 *
 * This function gets socket FD + int array + array size and populates
 * the array with FD numbers of the rings that are associated
 * with the socket.
 *
 * @param fd File Descriptor number.
 * @param ring_fds Array of ring fds
 * @param ring_fds_sz Size of the array
 * @return On success, return the number populated array entries.
 *         On error, -1 is returned.
 *
 * errno is set to: EINVAL - not a offloaded fd + TBD
 */
int xlio_get_socket_rings_fds(int fd, int *ring_fds, int ring_fds_sz);

/*
 * Dump fd statistics using the library logger.
 * @param fd to dump, 0 for all open fds.
 * @param log_level dumping level corresponding vlog_levels_t enum (vlogger.h).
 * @return 0 on success, or error code on failure.
 *
 * errno is set to: EOPNOTSUPP - Function is not supported when socketXtreme is enabled.
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

/**
 * Register a received packet notification callback.
 *
 * @param s Socket file descriptor.
 * @param callback Callback function.
 * @param context user contex for callback function.
 * @return 0 - success, -1 - error
 *
 * errno is set to: EINVAL - not offloaded socket
 */
int xlio_register_recv_callback(int s, xlio_recv_callback_t callback, void *context);

/**
 * socketxtreme_poll() polls for completions
 *
 * @param fd File descriptor.
 * @param completions Array of completions.
 * @param ncompletions Maximum number of completion to return.
 * @param flags Flags.
 *              SOCKETXTREME_POLL_TX - poll tx completions
 * @return On success, return the number of ready completions.
 * 	   On error, -1 is returned, and TBD:errno is set?.
 *
 * This function polls the `fd` for completions and returns maximum `ncompletions` ready
 * completions via `completions` array.
 * The `fd` can represent a ring, socket or epoll file descriptor.
 *
 * Completions are indicated for incoming packets and/or for other events.
 * If XLIO_SOCKETXTREME_PACKET flag is enabled in xlio_socketxtreme_completion_t.events field
 * the completion points to incoming packet descriptor that can be accesses
 * via xlio_socketxtreme_completion_t.packet field.
 * Packet descriptor points to library specific buffers that contain data scattered
 * by HW, so the data is deliver to application with zero copy.
 * Notice: after application finished using the returned packets
 * and their buffers it must free them using socketxtreme_free_packets(),
 * socketxtreme_free_buff() functions.
 *
 * If XLIO_SOCKETXTREME_PACKET flag is disabled xlio_socketxtreme_completion_t.packet field is
 * reserved.
 *
 * In addition to packet arrival event (indicated by XLIO_SOCKETXTREME_PACKET flag)
 * The library also reports XLIO_SOCKETXTREME_NEW_CONNECTION_ACCEPTED event and standard
 * epoll events via xlio_socketxtreme_completion_t.events field.
 * XLIO_SOCKETXTREME_NEW_CONNECTION_ACCEPTED event is reported when new connection is
 * accepted by the server.
 * When working with socketxtreme_poll() new connections are accepted
 * automatically and accept(listen_socket) must not be called.
 * XLIO_SOCKETXTREME_NEW_CONNECTION_ACCEPTED event is reported for the new
 * connected/child socket (xlio_socketxtreme_completion_t.user_data refers to child socket)
 * and EPOLLIN event is not generated for the listen socket.
 * For events other than packet arrival and new connection acceptance
 * xlio_socketxtreme_completion_t.events bitmask composed using standard epoll API
 * events types.
 * Notice: the same completion can report multiple events, for example
 * XLIO_SOCKETXTREME_PACKET flag can be enabled together with EPOLLOUT event,
 * etc...
 *
 * * errno is set to: EOPNOTSUPP - socketXtreme was not enabled during configuration time.
 */
int xlio_socketxtreme_poll(int fd, struct xlio_socketxtreme_completion_t *completions,
                           unsigned int ncompletions, int flags);

/**
 * Frees packets received by socketxtreme_poll().
 *
 * @param packets Packets to free.
 * @param num Number of packets in `packets` array
 * @return 0 on success, -1 on failure
 *
 * For each packet in `packet` array this function:
 * - Updates receive queue size and the advertised TCP
 *   window size, if needed, for the socket that received
 *   the packet.
 * - Frees the library specific buffer list that is associated with the packet.
 *   Notice: for each buffer in buffer list the library decreases buffer's
 *   reference count and only buffers with reference count zero are deallocated.
 *   Notice:
 *   - Application can increase buffer reference count,
 *     in order to hold the buffer even after socketxtreme_free_packets()
 *     was called for the buffer, using socketxtreme_ref_buff().
 *   - Application is responsible to free buffers, that
 *     couldn't be deallocated during socketxtreme_free_packets() due to
 *     non zero reference count, using socketxtreme_free_buff() function.
 *
 * errno is set to: EINVAL - NULL pointer is provided.
 *                  EOPNOTSUPP - socketXtreme was not enabled during configuration time.
 */
int xlio_socketxtreme_free_packets(struct xlio_socketxtreme_packet_desc_t *packets, int num);

/* This function increments the reference count of the buffer.
 * This function should be used in order to hold the buffer
 * even after socketxtreme_free_packets() call.
 * When buffer is not needed any more it should be freed via
 * socketxtreme_free_buff().
 *
 * @param buff Buffer to update.
 * @return On success, return buffer's reference count after the change
 * 	   On errors -1 is returned
 *
 * errno is set to: EINVAL - NULL pointer is provided.
 *                  EOPNOTSUPP - socketXtreme was not enabled during configuration time.
 */
int xlio_socketxtreme_ref_buff(struct xlio_buff_t *buff);

/* This function decrements the buff reference count.
 * When buff's reference count reaches zero, the buff is
 * deallocated.
 *
 * @param buff Buffer to free.
 * @return On success, return buffer's reference count after the change
 * 	   On error -1 is returned
 *
 * Notice: return value zero means that buffer was deallocated.
 *
 * errno is set to: EINVAL - NULL pointer is provided.
 *                  EOPNOTSUPP - socketXtreme was not enabled during configuration time.
 */
int xlio_socketxtreme_free_buff(struct xlio_buff_t *buff);

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
int xlio_poll_group_update(xlio_poll_group_t group, const struct xlio_poll_group_attr *attr);
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
