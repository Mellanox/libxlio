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

#ifndef XLIO_EXTRA_H
#define XLIO_EXTRA_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "xlio_types.h"

/** Magic value for xlio_get_api (NVDAXLIO) */
#define XLIO_MAGIC_NUMBER (0x4f494c584144564eULL)

/* Forward declaration. */
struct ibv_pd;

/**
 * XLIO Extended Socket API
 */

enum {
    XLIO_EXTRA_API_REGISTER_RECV_CALLBACK = (1 << 0),
    XLIO_EXTRA_API_RECVFROM_ZCOPY = (1 << 1),
    XLIO_EXTRA_API_RECVFROM_ZCOPY_FREE_PACKETS = (1 << 2),
    XLIO_EXTRA_API_ADD_CONF_RULE = (1 << 3),
    XLIO_EXTRA_API_THREAD_OFFLOAD = (1 << 4),
    XLIO_EXTRA_API_GET_SOCKET_RINGS_NUM = (1 << 5),
    XLIO_EXTRA_API_GET_SOCKET_RINGS_FDS = (1 << 6),
    XLIO_EXTRA_API_SOCKETXTREME_POLL = (1 << 7),
    XLIO_EXTRA_API_SOCKETXTREME_FREE_PACKETS = (1 << 8),
    XLIO_EXTRA_API_SOCKETXTREME_REF_XLIO_BUFF = (1 << 9),
    XLIO_EXTRA_API_SOCKETXTREME_FREE_XLIO_BUFF = (1 << 10),
    XLIO_EXTRA_API_DUMP_FD_STATS = (1 << 11),
    XLIO_EXTRA_API_IOCTL = (1 << 12),
    XLIO_EXTRA_API_XLIO_SOCKET = (1 << 13),
};

struct __attribute__((packed)) xlio_api_t {

    /**
     * Used to verify that API structure returned from xlio_get_api call is
     * compatible with current XLIO library version.
     */
    uint64_t magic;

    /**
     * Used to identify which methods were initialized by XLIO as part of xlio_get_api().
     * The value content is based on cap_mask bit field.
     * Order of fields in this structure should not be changed to keep abi compatibility.
     */
    uint64_t cap_mask;

    /**
     * Zero-copy revcfrom implementation.
     *
     * @param s Socket file descriptor.
     * @param buf Buffer to fill with received data or pointers to data (see below).
     * @param flags Pointer to flags (see below).
     * @param from If not NULL, will be filled with source address (same as recvfrom).
     * @param fromlen If not NULL, will be filled with source address size (same as recvfrom).
     *
     * This function attempts to receive a packet without doing data copy.
     * The flags argument can contain the usual flags of recvmsg(), and also the
     * MSG_XLIO_ZCOPY_FORCE flag. If the latter is set, the function will not
     * fall back to data copy. Otherwise, the function falls back to data copy
     * if zero-copy cannot be performed. If zero-copy is done then MSG_XLIO_ZCOPY
     * flag is set upon exit.
     *
     * If zero copy is performed (MSG_XLIO_ZCOPY flag is returned), the buffer
     * is filled with a xlio_recvfrom_zcopy_packets_t structure, holding as much fragments
     * as `len' allows. The total size of all fragments is returned.
     * Otherwise the MSG_XLIO_ZCOPY flag is not set and the buffer is filled
     * with actual data and it's size is returned (same as recvfrom())
     * If no data was received the return value is zero.
     *
     * NOTE: The returned packet must be freed with free_packet() after
     * the application finished using it.
     */
    int (*recvfrom_zcopy)(int s, void *buf, size_t len, int *flags, struct sockaddr *from,
                          socklen_t *fromlen);

    /**
     * Frees a packet received by recvfrom_zcopy() or held by receive callback.
     *
     * @param s Socket from which the packet was received.
     * @param pkts Array of packet.
     * @param count Number of packets in the array.
     * @return 0 on success, -1 on failure
     *
     * errno is set to: EINVAL - not a offloaded socket
     *                  ENOENT - the packet was not received from `s'.
     */
    int (*recvfrom_zcopy_free_packets)(int s, struct xlio_recvfrom_zcopy_packet_t *pkts,
                                       size_t count);

    /*
     * Add a libxlio.conf rule to the top of the list.
     * This rule will not apply to existing sockets which already considered the conf rules.
     * (around connect/listen/send/recv ..)
     * @param config_line A char buffer with the exact format as defined in libxlio.conf, and should
     * end with '\0'.
     * @return 0 on success, or error code on failure.
     */
    int (*add_conf_rule)(const char *config_line);

    /*
     * Create sockets on pthread tid as offloaded/not-offloaded.
     * This does not affect existing sockets.
     * Offloaded sockets are still subject to libxlio.conf rules.
     * @param offload 1 for offloaded, 0 for not-offloaded.
     * @return 0 on success, or error code on failure.
     */
    int (*thread_offload)(int offload, pthread_t tid);

    /**
     * Returns the amount of rings that are associated with socket.
     *
     * @param fd File Descriptor number of the socket.
     * @return On success, return the amount of rings.
     *         On error, -1 is returned.
     *
     * errno is set to: EINVAL - not a offloaded fd
     */
    int (*get_socket_rings_num)(int fd);

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
    int (*get_socket_rings_fds)(int fd, int *ring_fds, int ring_fds_sz);

    /*
     * Dump fd statistics using the library logger.
     * @param fd to dump, 0 for all open fds.
     * @param log_level dumping level corresponding vlog_levels_t enum (vlogger.h).
     * @return 0 on success, or error code on failure.
     *
     * errno is set to: EOPNOTSUPP - Function is not supported when socketXtreme is enabled.
     */
    int (*dump_fd_stats)(int fd, int log_level);

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
    int (*ioctl)(void *cmsg_hdr, size_t cmsg_len);

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
    int (*register_recv_callback)(int s, xlio_recv_callback_t callback, void *context);

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
    int (*socketxtreme_poll)(int fd, struct xlio_socketxtreme_completion_t *completions,
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
    int (*socketxtreme_free_packets)(struct xlio_socketxtreme_packet_desc_t *packets, int num);

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
    int (*socketxtreme_ref_buff)(struct xlio_buff_t *buff);

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
    int (*socketxtreme_free_buff)(struct xlio_buff_t *buff);

    /**
     * XLIO Socket API.
     */
    int (*xlio_init_ex)(const struct xlio_init_attr *attr);
    int (*xlio_poll_group_create)(const struct xlio_poll_group_attr *attr,
                                  xlio_poll_group_t *group_out);
    int (*xlio_poll_group_destroy)(xlio_poll_group_t group);
    void (*xlio_poll_group_poll)(xlio_poll_group_t group);
    int (*xlio_socket_create)(const struct xlio_socket_attr *attr, xlio_socket_t *sock_out);
    int (*xlio_socket_destroy)(xlio_socket_t sock);
    int (*xlio_socket_update)(xlio_socket_t sock, unsigned flags, uintptr_t userdata_sq);
    int (*xlio_socket_setsockopt)(xlio_socket_t sock, int level, int optname, const void *optval,
                                  socklen_t optlen);
    int (*xlio_socket_getpeername)(xlio_socket_t sock, struct sockaddr *addr, socklen_t *addrlen);
    int (*xlio_socket_bind)(xlio_socket_t sock, const struct sockaddr *addr, socklen_t addrlen);
    int (*xlio_socket_connect)(xlio_socket_t sock, const struct sockaddr *to, socklen_t tolen);
    int (*xlio_socket_listen)(xlio_socket_t sock);
    struct ibv_pd *(*xlio_socket_get_pd)(xlio_socket_t sock);
    int (*xlio_socket_detach_group)(xlio_socket_t sock);
    int (*xlio_socket_attach_group)(xlio_socket_t sock, xlio_poll_group_t group);
    int (*xlio_socket_send)(xlio_socket_t sock, const void *data, size_t len,
                            const struct xlio_socket_send_attr *attr);
    int (*xlio_socket_sendv)(xlio_socket_t sock, const struct iovec *iov, unsigned iovcnt,
                             const struct xlio_socket_send_attr *attr);
    void (*xlio_poll_group_flush)(xlio_poll_group_t group);
    void (*xlio_socket_flush)(xlio_socket_t sock);
    void (*xlio_socket_buf_free)(xlio_socket_t sock, struct xlio_buf *buf);
    void (*xlio_poll_group_buf_free)(xlio_poll_group_t group, struct xlio_buf *buf);
};

/**
 * Retrieve XLIO extended API.
 * This function can be called as an alternative to getsockopt() call
 * when library is preloaded using LD_PRELOAD
 * getsockopt() call should be used in case application loads library
 * using dlopen()/dlsym().
 *
 * @return Pointer to the XLIO Extended Socket API, of NULL if XLIO not found.
 */
static inline struct xlio_api_t *xlio_get_api()
{
    struct xlio_api_t *api_ptr = NULL;
    socklen_t len = sizeof(api_ptr);

    /* coverity[negative_returns] */
    int err = getsockopt(-2, SOL_SOCKET, SO_XLIO_GET_API, &api_ptr, &len);
    if (err < 0) {
        return NULL;
    }
    if (len < sizeof(struct xlio_api_t *) || api_ptr == NULL ||
        api_ptr->magic != XLIO_MAGIC_NUMBER) {
        return NULL;
    }
    return api_ptr;
}

#endif /* XLIO_EXTRA_H */
