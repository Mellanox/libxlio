/*
 * Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <util/sys_vars.h>
#include <util/libxlio.h>
#include <vlogger/vlogger.h>
#include <dev/buffer_pool.h>
#include <event/thread_local_event_handler.h>
#include <sock/socket_fd_api.h>
#include <sock/sockinfo_tcp.h>
#include <sock/sockinfo_udp.h>
#include <sock/fd_collection.h>

#include "sock/sock-extra.h"

#define MODULE_NAME "extra:"

#define SET_EXTRA_API(__dst, __func, __mask)                                                       \
    do {                                                                                           \
        xlio_api->__dst = __func;                                                                  \
        xlio_api->cap_mask |= __mask;                                                              \
    } while (0);

//-----------------------------------------------------------------------------
// extended API functions
//-----------------------------------------------------------------------------

extern "C" int xlio_register_recv_callback(int __fd, xlio_recv_callback_t __callback,
                                           void *__context)
{
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

struct xlio_api_t *extra_api(void)
{
    static struct xlio_api_t *xlio_api = NULL;

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
        SET_EXTRA_API(socketxtreme_poll,
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
        SET_EXTRA_API(
            socketxtreme_free_buff,
            enable_socketxtreme ? xlio_socketxtreme_free_buff : dummy_xlio_socketxtreme_free_buff,
            XLIO_EXTRA_API_SOCKETXTREME_FREE_XLIO_BUFF);
        SET_EXTRA_API(dump_fd_stats, xlio_dump_fd_stats, XLIO_EXTRA_API_DUMP_FD_STATS);
        SET_EXTRA_API(ioctl, xlio_ioctl, XLIO_EXTRA_API_IOCTL);
    }

    return xlio_api;
}