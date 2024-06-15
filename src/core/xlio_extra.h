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
    XLIO_EXTRA_API_ADD_CONF_RULE = (1 << 3),
    XLIO_EXTRA_API_THREAD_OFFLOAD = (1 << 4),
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

    /*
     * Dump fd statistics using the library logger.
     * @param fd to dump, 0 for all open fds.
     * @param log_level dumping level corresponding vlog_levels_t enum (vlogger.h).
     * @return 0 on success, or error code on failure.
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
     * XLIO Socket API.
     */
    int (*xlio_init_ex)(const struct xlio_init_attr *attr);
    int (*xlio_poll_group_create)(const struct xlio_poll_group_attr *attr,
                                  xlio_poll_group_t *group_out);
    int (*xlio_poll_group_destroy)(xlio_poll_group_t group);
    void (*xlio_poll_group_poll)(xlio_poll_group_t group);
    int (*xlio_socket_create)(const struct xlio_socket_attr *attr, xlio_socket_t *sock_out);
    int (*xlio_socket_destroy)(xlio_socket_t sock);
    int (*xlio_socket_setsockopt)(xlio_socket_t sock, int level, int optname, const void *optval,
                                  socklen_t optlen);
    int (*xlio_socket_bind)(xlio_socket_t sock, const struct sockaddr *addr, socklen_t addrlen);
    int (*xlio_socket_connect)(xlio_socket_t sock, const struct sockaddr *to, socklen_t tolen);
    struct ibv_pd *(*xlio_socket_get_pd)(xlio_socket_t sock);
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
