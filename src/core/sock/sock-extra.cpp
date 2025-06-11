/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2023-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <util/sys_vars.h>
#include <util/libxlio.h>
#include <vlogger/vlogger.h>
#include <dev/buffer_pool.h>
#include <event/event_handler_manager_local.h>
#include <event/poll_group.h>
#include <sock/sockinfo.h>
#include <sock/sockinfo_tcp.h>
#include <sock/sockinfo_udp.h>
#include <sock/fd_collection.h>

#include "sock/sock-extra.h"
#include "xlio.h"

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
    sockinfo *p_socket_object = nullptr;
    p_socket_object = fd_collection_get_sockfd(__fd);
    if (p_socket_object && p_socket_object->get_protocol() == PROTO_UDP) {
        reinterpret_cast<sockinfo_udp *>(p_socket_object)->register_callback(__callback, __context);
        return 0;
    }
    errno = EINVAL;
    return -1;
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

struct xlio_api_t *extra_api()
{
    static struct xlio_api_t *xlio_api = nullptr;

    if (!xlio_api) {
        xlio_api = new struct xlio_api_t();

        memset(xlio_api, 0, sizeof(struct xlio_api_t));
        xlio_api->magic = XLIO_MAGIC_NUMBER;
        xlio_api->cap_mask = 0;
        SET_EXTRA_API(register_recv_callback, xlio_register_recv_callback,
                      XLIO_EXTRA_API_REGISTER_RECV_CALLBACK);
        SET_EXTRA_API(add_conf_rule, xlio_add_conf_rule, XLIO_EXTRA_API_ADD_CONF_RULE);
        SET_EXTRA_API(thread_offload, xlio_thread_offload, XLIO_EXTRA_API_THREAD_OFFLOAD);
        SET_EXTRA_API(dump_fd_stats, xlio_dump_fd_stats, XLIO_EXTRA_API_DUMP_FD_STATS);

        // XLIO Socket API.
        SET_EXTRA_API(xlio_init_ex, xlio_init_ex, XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_exit, xlio_exit, XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_poll_group_create, xlio_poll_group_create, XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_poll_group_destroy, xlio_poll_group_destroy, XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_poll_group_poll, xlio_poll_group_poll, XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_socket_create, xlio_socket_create, XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_socket_destroy, xlio_socket_destroy, XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_socket_update, xlio_socket_update, XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_socket_setsockopt, xlio_socket_setsockopt, XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_socket_getsockname, xlio_socket_getsockname, XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_socket_getpeername, xlio_socket_getpeername, XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_socket_bind, xlio_socket_bind, XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_socket_connect, xlio_socket_connect, XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_socket_listen, xlio_socket_listen, XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_socket_get_pd, xlio_socket_get_pd, XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_socket_detach_group, xlio_socket_detach_group,
                      XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_socket_attach_group, xlio_socket_attach_group,
                      XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_socket_send, xlio_socket_send, XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_socket_sendv, xlio_socket_sendv, XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_poll_group_flush, xlio_poll_group_flush, XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_socket_flush, xlio_socket_flush, XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_socket_buf_free, xlio_socket_buf_free, XLIO_EXTRA_API_XLIO_SOCKET);
        SET_EXTRA_API(xlio_poll_group_buf_free, xlio_poll_group_buf_free,
                      XLIO_EXTRA_API_XLIO_SOCKET);
    }

    return xlio_api;
}

/*
 * Storage API
 */

extern "C" int xlio_init_ex(const struct xlio_init_attr *attr)
{
    // Set XLIO Socket API specific parameters unless user sets them explicitly
    if (!getenv(SYS_VAR_PROGRESS_ENGINE_INTERVAL)) {
        setenv(SYS_VAR_PROGRESS_ENGINE_INTERVAL, "0", 1);
    }

    // Read the updated parameters. A global object could trigger the reading earlier.
    safe_mce_sys().get_params();

    xlio_init();

    extern xlio_memory_cb_t g_user_memory_cb;
    g_user_memory_cb = attr->memory_cb;

    if (attr->memory_alloc) {
        safe_mce_sys().user_alloc.memalloc = attr->memory_alloc;
        safe_mce_sys().user_alloc.memfree = attr->memory_free;
        safe_mce_sys().memory_limit_user =
            std::max(safe_mce_sys().memory_limit_user, safe_mce_sys().memory_limit);
    }

    DO_GLOBAL_CTORS();

    return 0;
}

extern "C" int xlio_poll_group_create(const struct xlio_poll_group_attr *attr,
                                      xlio_poll_group_t *group_out)
{
    // Validate input arguments
    if (!group_out || !attr || !attr->socket_event_cb) {
        errno = EINVAL;
        return -1;
    }

    poll_group *grp = new poll_group(attr);
    if (!grp) {
        errno = ENOMEM;
        return -1;
    }

    *group_out = reinterpret_cast<xlio_poll_group_t>(grp);
    return 0;
}

extern "C" int xlio_poll_group_destroy(xlio_poll_group_t group)
{
    poll_group *grp = reinterpret_cast<poll_group *>(group);

    delete grp;
    return 0;
}

extern "C" int xlio_poll_group_update(xlio_poll_group_t group,
                                      const struct xlio_poll_group_attr *attr)
{
    poll_group *grp = reinterpret_cast<poll_group *>(group);

    if (!attr || !attr->socket_event_cb) {
        errno = EINVAL;
        return -1;
    }
    return grp->update(attr);
}

extern "C" void xlio_poll_group_poll(xlio_poll_group_t group)
{
    poll_group *grp = reinterpret_cast<poll_group *>(group);

    grp->poll();
}

extern "C" int xlio_socket_create(const struct xlio_socket_attr *attr, xlio_socket_t *sock_out)
{
    // Validate input arguments
    if (!sock_out || !attr || !attr->group ||
        !(attr->domain == AF_INET || attr->domain == AF_INET6)) {
        errno = EINVAL;
        return -1;
    }

    int fd = SYSCALL(socket, attr->domain, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    sockinfo_tcp *si = new sockinfo_tcp(fd, attr->domain);
    if (!si) {
        errno = ENOMEM;
        return -1;
    }
    si->set_xlio_socket(attr);

    poll_group *grp = reinterpret_cast<poll_group *>(attr->group);
    grp->add_socket(si);

    *sock_out = reinterpret_cast<xlio_socket_t>(si);
    return 0;
}

extern "C" int xlio_socket_destroy(xlio_socket_t sock)
{
    sockinfo_tcp *si = reinterpret_cast<sockinfo_tcp *>(sock);
    poll_group *grp = si->get_poll_group();

    if (unlikely(!si->is_xlio_socket())) {
        errno = EINVAL;
        return -1;
    }

    if (likely(grp)) {
        grp->mark_socket_to_close(si);
    } else {
        // Detached socket flow.
        g_p_fd_collection->clear_socket(si->get_fd());
        si->prepare_to_close(true);
        si->clean_socket_obj();
    }
    return 0;
}

extern "C" int xlio_socket_update(xlio_socket_t sock, unsigned flags, uintptr_t userdata_sq)
{
    sockinfo_tcp *si = reinterpret_cast<sockinfo_tcp *>(sock);
    return si->update_xlio_socket(flags, userdata_sq);
}

extern "C" int xlio_socket_setsockopt(xlio_socket_t sock, int level, int optname,
                                      const void *optval, socklen_t optlen)
{
    sockinfo_tcp *si = reinterpret_cast<sockinfo_tcp *>(sock);
    int errno_save = errno;

    int rc = si->setsockopt(level, optname, optval, optlen);
    if (rc == 0) {
        errno = errno_save;
    }
    return rc;
}

extern "C" int xlio_socket_getsockname(xlio_socket_t sock, struct sockaddr *addr,
                                       socklen_t *addrlen)
{
    sockinfo_tcp *si = reinterpret_cast<sockinfo_tcp *>(sock);
    return si->getsockname(addr, addrlen);
}

extern "C" int xlio_socket_getpeername(xlio_socket_t sock, struct sockaddr *addr,
                                       socklen_t *addrlen)
{
    sockinfo_tcp *si = reinterpret_cast<sockinfo_tcp *>(sock);
    return si->getpeername(addr, addrlen);
}

extern "C" int xlio_socket_bind(xlio_socket_t sock, const struct sockaddr *addr, socklen_t addrlen)
{
    sockinfo_tcp *si = reinterpret_cast<sockinfo_tcp *>(sock);
    int errno_save = errno;

    int rc = si->bind(addr, addrlen);
    if (rc == 0) {
        errno = errno_save;
    }
    return rc;
}

extern "C" int xlio_socket_connect(xlio_socket_t sock, const struct sockaddr *to, socklen_t tolen)
{
    sockinfo_tcp *si = reinterpret_cast<sockinfo_tcp *>(sock);
    int errno_save = errno;

    int rc = si->connect(to, tolen);
    rc = (rc == -1 && (errno == EINPROGRESS || errno == EAGAIN)) ? 0 : rc;
    if (rc == 0) {
        errno = errno_save;
    }
    return rc;
}

extern "C" int xlio_socket_listen(xlio_socket_t sock)
{
    sockinfo_tcp *si = reinterpret_cast<sockinfo_tcp *>(sock);
    poll_group *group = si->get_poll_group();

    if (!group->m_socket_accept_cb) {
        errno = ENOTCONN;
        return -1;
    }
    // TODO handle positive return code from prepareListen() and convert it to errno
    return si->prepareListen() ?: si->listen(-1);
}

extern "C" struct ibv_pd *xlio_socket_get_pd(xlio_socket_t sock)
{
    sockinfo_tcp *si = reinterpret_cast<sockinfo_tcp *>(sock);
    ib_ctx_handler *ctx = si->get_ctx();

    return ctx ? ctx->get_ibv_pd() : nullptr;
}

int xlio_socket_detach_group(xlio_socket_t sock)
{
    sockinfo_tcp *si = reinterpret_cast<sockinfo_tcp *>(sock);

    return si->detach_xlio_group();
}

int xlio_socket_attach_group(xlio_socket_t sock, xlio_poll_group_t group)
{
    sockinfo_tcp *si = reinterpret_cast<sockinfo_tcp *>(sock);
    poll_group *grp = reinterpret_cast<poll_group *>(group);

    return si->attach_xlio_group(grp);
}

static void xlio_buf_free(struct xlio_buf *buf)
{
    mem_buf_desc_t *desc = mem_buf_desc_t::from_xlio_buf(buf);
    ring_slave *rng = desc->p_desc_owner;

    desc->p_next_desc = nullptr;
    bool ret = rng->reclaim_recv_buffers(desc);
    if (unlikely(!ret)) {
        g_buffer_pool_rx_ptr->put_buffer_after_deref_thread_safe(desc);
    }
}

extern "C" void xlio_socket_buf_free(xlio_socket_t sock, struct xlio_buf *buf)
{
    NOT_IN_USE(sock);
    xlio_buf_free(buf);
}

extern "C" void xlio_poll_group_buf_free(xlio_poll_group_t group, struct xlio_buf *buf)
{
    NOT_IN_USE(group);
    xlio_buf_free(buf);
}

extern "C" int xlio_socket_send(xlio_socket_t sock, const void *data, size_t len,
                                const struct xlio_socket_send_attr *attr)
{
    const struct iovec iov = {.iov_base = const_cast<void *>(data), .iov_len = len};

    return xlio_socket_sendv(sock, &iov, 1, attr);
}

extern "C" int xlio_socket_sendv(xlio_socket_t sock, const struct iovec *iov, unsigned iovcnt,
                                 const struct xlio_socket_send_attr *attr)
{
    sockinfo_tcp *si = reinterpret_cast<sockinfo_tcp *>(sock);

    unsigned flags = XLIO_EXPRESS_OP_TYPE_DESC;
    flags |= !(attr->flags & XLIO_SOCKET_SEND_FLAG_FLUSH) * XLIO_EXPRESS_MSG_MORE;

    int rc = (attr->flags & XLIO_SOCKET_SEND_FLAG_INLINE)
        ? si->tcp_tx_express_inline(iov, iovcnt, flags)
        : si->tcp_tx_express(iov, iovcnt, attr->mkey, flags,
                             reinterpret_cast<void *>(attr->userdata_op));
    return rc < 0 ? rc : 0;
}

extern "C" void xlio_poll_group_flush(xlio_poll_group_t group)
{
    poll_group *grp = reinterpret_cast<poll_group *>(group);
    grp->flush();
}

extern "C" void xlio_socket_flush(xlio_socket_t sock)
{
    sockinfo_tcp *si = reinterpret_cast<sockinfo_tcp *>(sock);
    si->flush();
}
