/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2023-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sock/sockinfo.h>
#include <sock/sock-redirect.h>
#include <sock/sockinfo_tcp.h>
#include <sock/sockinfo_udp.h>
#include <sock/fd_collection.h>

#include <vlogger/vlogger.h>

#include "sock/sock-app.h"
#include "tuning_report_printer.h"

using namespace std;

#define MODULE_NAME "app:"

#define app_logpanic __log_panic
#define app_logerr   __log_err
#define app_logwarn  __log_warn
#define app_loginfo  __log_info
#define app_logdbg   __log_dbg

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)

#if defined(DEFINED_NGINX)
map_udp_reuse_port_t g_map_udp_resue_port;
#endif

static int init_worker(int worker_id, int listen_fd);
static void app_degrade_listen_to_kernel(int listen_fd, const char *reason);
static void count_listen_passthrough(void);

struct app_conf *g_p_app = nullptr;

pid_t app_conf::listen_fd_owner(int fd)
{
    std::lock_guard<decltype(m_map_lock)> lock(m_map_lock);
    auto iter = map_listen_fd.find(fd);
    return iter != map_listen_fd.end() ? iter->second : -1;
}

int app_conf::publish_worker(int fd)
{
    std::lock_guard<decltype(m_map_lock)> lock(m_map_lock);

    /* m_total_worker_id is unique for all threads */
    int worker_id = get_worker_id();
    if (worker_id < 0) {
        worker_id = m_total_worker_id;
        m_total_worker_id++;
    }

    map_listen_fd[fd] = gettid();
    map_thread_id[gettid()] = worker_id;
    return worker_id;
}

int app_conf::count_original_listeners()
{
    std::lock_guard<decltype(m_map_lock)> lock(m_map_lock);
    int originals = 0;
    for (const auto &itr : map_dup_fd) {
        if (itr.first == itr.second) {
            originals++;
        }
    }
    return originals;
}

int app_conf::assign_worker_and_publish(int fd, sockinfo *si)
{
    int worker_id = publish_worker(fd);

    /* This check is `enable_reuse_port = false` specific
     *
     * This part should guarantee initialization of all listeners for worker 0.
     * m_original_listen_count is initialized to number of them first. The
     * counter itself is serialized by m_init_lock (this path's caller) and
     * read unlocked by the ordering wait; only the map scan needs m_map_lock.
     */
    if (si && !si->get_reuseport() && worker_id == 0) {
        if (m_original_listen_count == INT_MAX) {
            m_original_listen_count = count_original_listeners();
        }
        m_original_listen_count--;
    }

    return worker_id;
}

bool app_conf::is_dup_of_reuseport(int fd)
{
    std::lock_guard<decltype(m_map_lock)> lock(m_map_lock);
    return set_dup_reuseport.count(fd) != 0;
}

int app_conf::lookup_dup_parent(int fd)
{
    std::lock_guard<decltype(m_map_lock)> lock(m_map_lock);
    const auto itr = map_dup_fd.find(fd);
    return itr != map_dup_fd.end() ? itr->second : -1;
}

void app_conf::register_dup(int fd, int parent_fd, bool reuseport_parent)
{
    std::lock_guard<decltype(m_map_lock)> lock(m_map_lock);
    map_dup_fd[fd] = parent_fd;
    /* The parent maps to itself */
    map_dup_fd[parent_fd] = parent_fd;
    if (reuseport_parent) {
        set_dup_reuseport.insert(fd);
    }
}

void app_conf::forget_fd(int fd)
{
    std::lock_guard<decltype(m_map_lock)> lock(m_map_lock);
    map_dup_fd.erase(fd);
    set_dup_reuseport.erase(fd);
}

#if defined(DEFINED_NGINX)
int app_conf::proc_nginx()
{
    int rc = 0;

    DO_GLOBAL_CTORS();
    std::lock_guard<decltype(g_p_app->m_map_lock)> lock(g_p_app->m_map_lock);

    /* This place processes a configuration including listen sockets are UDP sockets
     * in common way.
     * For UDP case order of fd processing is important so one or multipile fds
     * related worker 0 should be first.
     * TCP listen sockets can be taken from map_listen_fd in any order.
     * Enumerate all elements in fd_collection filtering by sockinfo objects.
     */
    fd_collection *p_fd_collection = (fd_collection *)g_p_app->context;
    for (int fd = 0; fd < p_fd_collection->get_fd_map_size(); fd++) {
        sockinfo *sock_fd_api = p_fd_collection->get_sockfd(fd);
        if (!sock_fd_api || !dynamic_cast<sockinfo *>(sock_fd_api)) {
            continue;
        }
        g_p_app->map_listen_fd[fd] = gettid();
        rc = init_worker(g_p_app->get_worker_id(), fd);
        if (rc != 0) {
            app_logerr("Failed to initialize worker %d, (errno=%d %m)", g_p_app->get_worker_id(),
                       errno);
            break;
        }
    }

    return rc;
}
#endif /* DEFINED_NGINX */

#if defined(DEFINED_ENVOY)
int app_conf::proc_envoy(int __op, int __fd)
{
    int rc = 0;

    /* Process only sockets from map_listen_fd */
    pid_t owner_tid = listen_fd_owner(__fd);
    if (owner_tid != -1) {
        sockinfo *p_socket_object = fd_collection_get_sockfd(__fd);
        if (owner_tid == gettid()) {
            /* process listen sockets from main thread and remove
             * them from map_listen_fd
             */
            if (p_socket_object) {
                rc = p_socket_object->listen(p_socket_object->m_back_log);
                if (rc < 0) {
                    /* The fd stays OS-listening (the listen() interposer always
                     * issues the kernel listen()); a retained sockinfo would make
                     * epoll_ctl() register the fd as offloaded while accept()
                     * keeps failing. Drop it so the fd serves on the kernel epoll. */
                    app_degrade_listen_to_kernel(__fd, "listen failed");
                    rc = 0;
                }
            }
            std::lock_guard<decltype(g_p_app->m_map_lock)> lock(g_p_app->m_map_lock);
            g_p_app->map_listen_fd.erase(__fd);
        } else if (__op == EPOLL_CTL_ADD) {
            int worker_id = -1;

            /* A dup of a live TCP reuse_port listener is the successor of an
             * Envoy same-address listener update (a full listener
             * replacement). The successor is not offloaded: degrade it to the
             * kernel path loudly, now. The ordering wait below only ever
             * opens on the enable_reuse_port=false path, so waiting would
             * starve the ADD into an EINVAL black-hole. The fd is already
             * OS-listening; with no sockinfo on it the interposer registers
             * it on the kernel epoll and it keeps serving unaccelerated. */
            if (!p_socket_object && g_p_app->is_dup_of_reuseport(__fd)) {
                app_account_listen_passthrough(__fd, "reuse_port listener update successor");
                /* The fd is no longer an XLIO-tracked listener (it serves on
                 * the kernel epoll). Drop its map_listen_fd entry so a later
                 * EPOLL_CTL_ADD on the same fd is not re-processed and
                 * re-counted - symmetric with the worker-init failure exit. */
                std::lock_guard<decltype(g_p_app->m_map_lock)> lock(g_p_app->m_map_lock);
                g_p_app->map_listen_fd.erase(__fd);
                return 0;
            }

            /* This check is `enable_reuse_port = false` specific
             *
             * original listen sockets should be created first
             * original_listen_count count sockets that should be
             * processed until openning a door for others.
             * timer should be enough to complete initialization of
             * all sockets related worker 0.
             */
            int sleep_count = 1000;
            while (!p_socket_object && (g_p_app->m_original_listen_count > 0)) {
                if (!sleep_count--) {
                    return -1;
                }
                const struct timespec short_sleep = {0, 1000};
                nanosleep(&short_sleep, NULL);
            }

            /* Serialize the whole worker initialization path. m_init_lock
             * cannot participate in the m_map_lock/device-layer lock
             * inversion: it is acquired only here, where the calling thread
             * holds no other XLIO locks (see the contract in sock-app.h).
             */
            std::lock_guard<decltype(g_p_app->m_init_lock)> init_guard(g_p_app->m_init_lock);
            worker_id =
                g_p_app->assign_worker_and_publish(__fd, dynamic_cast<sockinfo *>(p_socket_object));

            /* init_worker() creates rings/CQs and can take device-layer
             * locks, so it must run without m_map_lock.
             */
            rc = init_worker(worker_id, __fd);
            if (rc != 0) {
                app_logerr("Failed to initialize worker %d, (errno=%d %m)", worker_id, errno);
                std::lock_guard<decltype(g_p_app->m_map_lock)> lock(g_p_app->m_map_lock);
                g_p_app->map_listen_fd.erase(__fd);
                g_p_app->map_thread_id.erase(gettid());
                g_p_app->set_dup_reuseport.erase(__fd);
                return rc;
            }
        } else if (__op == EPOLL_CTL_DEL) {
            std::lock_guard<decltype(g_p_app->m_map_lock)> lock(g_p_app->m_map_lock);
            g_p_app->map_listen_fd.erase(__fd);
            /* Drop the reuse_port-dup mark for this child fd so it does not
             * persist across listener updates that recycle the same fd number. */
            g_p_app->set_dup_reuseport.erase(__fd);
        }
    }

    return rc;
}
#endif /* DEFINED_ENVOY */

/* The one counting point for a listener that lost acceleration and serves on
 * the kernel path (surfaced by the tuning report) */
static void count_listen_passthrough(void)
{
    g_tuning_report_counters.n_listen_passthrough.fetch_add(1, std::memory_order_relaxed);
}

void app_account_listen_passthrough(int listen_fd, const char *reason)
{
    count_listen_passthrough();
    vlog_printf(VLOG_WARNING,
                "could not offload listen fd=%d (%s); serving on the kernel path, "
                "acceleration lost\n",
                listen_fd, reason);
}

/* A listen fd that XLIO cannot offload must degrade to the kernel path, never
 * black-hole: a retained half-built sockinfo makes epoll_ctl() register the fd
 * as offloaded while accept() keeps failing. Dropping it (passthrough=true)
 * leaves the fd OS-listening, so the kernel epoll serves it. */
static void app_degrade_listen_to_kernel(int listen_fd, const char *reason)
{
    handle_close(listen_fd, false /*cleanup*/, true /*passthrough*/);
    app_account_listen_passthrough(listen_fd, reason);
}

static int init_worker(int worker_id, int listen_fd)
{
    NOT_IN_USE(worker_id);
    app_logdbg("worker: %d fd: %d", worker_id, listen_fd);

    int ret = 0;
    sockinfo *child_sock_fd_api = nullptr;
    int parent_fd = listen_fd;
    fd_collection *p_fd_collection = (fd_collection *)g_p_app->context;

    /* Find information about parent socket
     * Envoy (enable_reuse_port = false):
     * - g_p_fd_collection has all actual fds
     * - worker 0 has socket object in g_p_fd_collection (parent fd)
     * - Other workers should find parent fd to create child socket objects
     *   basing on parent socket objects.
     * Envoy (enable_reuse_port = true):
     * - g_p_fd_collection has all actual fds
     * - all workers have socket object in g_p_fd_collection (parent fd)
     * Nginx:
     * - should use fd_collection from parent process stored at g_p_app->context
     */
    if (g_p_app->type == APP_ENVOY) {
        p_fd_collection = g_p_fd_collection;
        if (!p_fd_collection->get_sockfd(listen_fd)) {
            parent_fd = g_p_app->lookup_dup_parent(listen_fd);
            if (parent_fd < 0) {
                return -1;
            }
        } else {
            ret = -1;
            child_sock_fd_api = p_fd_collection->get_sockfd(listen_fd);
            if (child_sock_fd_api) {
                ret = child_sock_fd_api->listen(child_sock_fd_api->m_back_log);
                if (ret < 0) {
                    /* The fd stays OS-listening; a retained sockinfo would make
                     * epoll_ctl() register the fd as offloaded while accept()
                     * keeps failing. Drop it so the fd serves on the kernel epoll. */
                    app_degrade_listen_to_kernel(listen_fd, "listen failed");
                    ret = 0;
                }
            }
            return ret;
        }
    }

    /* This part should be ignored by Envoy worker 0
     * Envoy: parent_fd is fd of parent socket
     * Nginx: parent_fd is equal to listen_fd
     */
    sockinfo *si;
    sockinfo *parent_sock_fd_api = p_fd_collection->get_sockfd(parent_fd);
    if (!parent_sock_fd_api || !(si = dynamic_cast<sockinfo *>(parent_sock_fd_api))) {
        app_logerr("parent sockinfo is not found");
        return -1;
    }

    int block_type = si->is_blocking() ? 0 : SOCK_NONBLOCK;
    sock_addr sa;
    socklen_t sa_len = sa.get_socklen();

    parent_sock_fd_api->getsockname(sa.get_p_sa(), &sa_len);
    if (PROTO_TCP == si->get_protocol()) {
        app_logdbg("found listen socket %d", parent_sock_fd_api->get_fd());
        g_p_fd_collection->addsocket(listen_fd, si->get_family(), SOCK_STREAM | block_type);
        child_sock_fd_api = g_p_fd_collection->get_sockfd(listen_fd);
        if (child_sock_fd_api) {
            /* Error-exit contract for this clone leg (shared by Envoy and nginx
             * workers): no exit may leave a half-built sockinfo behind, or the
             * epoll ADD registers the fd as offloaded while accept() keeps
             * failing, black-holing the listener. Every non-offload exit must
             * drop the sockinfo (handle_close with passthrough; the fd stays
             * OS-bound and listening) so the fd serves on the kernel path - for
             * Envoy through app_degrade_listen_to_kernel(), which also
             * accounts the lost acceleration. */
            child_sock_fd_api->copy_sockopt_fork(parent_sock_fd_api);

            ret = bind_internal(child_sock_fd_api, sa.get_p_sa(), sa_len);
            if (ret < 0) {
                /* Do not listen() on a mis-bound socket; drop it and let the fd
                 * serve on the kernel path (it is already OS-bound/listening). */
                if (g_p_app->type == APP_ENVOY) {
                    app_degrade_listen_to_kernel(listen_fd, "bind failed");
                    return 0;
                }
                app_logerr("bind() error on listen fd %d; serving on the kernel path", listen_fd);
                handle_close(child_sock_fd_api->get_fd(), false, true);
                count_listen_passthrough();
                child_sock_fd_api = nullptr;
            }

            // is the socket really offloaded
            if (child_sock_fd_api) {
                ret = child_sock_fd_api->prepareListen();
                if (ret < 0) {
                    if (g_p_app->type == APP_ENVOY) {
                        app_degrade_listen_to_kernel(listen_fd, "prepareListen failed");
                        return 0;
                    }
                    app_logerr("prepareListen error on listen fd %d; serving on the kernel path",
                               listen_fd);
                    handle_close(child_sock_fd_api->get_fd(), false, true);
                    count_listen_passthrough();
                    child_sock_fd_api = nullptr;
                } else if (ret > 0) { // Pass-through
                    handle_close(child_sock_fd_api->get_fd(), false, true);
                    /* Routine pass-through: not an error, so no warning - but
                     * still count the lost acceleration */
                    count_listen_passthrough();
                    child_sock_fd_api = nullptr;
                } else {
                    app_logdbg("Prepare listen successfully offloaded");
                }
            }

            if (child_sock_fd_api) {
                ret = child_sock_fd_api->listen(child_sock_fd_api->m_back_log);
                if (ret < 0) {
                    if (g_p_app->type == APP_ENVOY) {
                        app_degrade_listen_to_kernel(listen_fd, "listen failed");
                        return 0;
                    }
                    app_logerr("listen() error on listen fd %d; serving on the kernel path",
                               listen_fd);
                    handle_close(child_sock_fd_api->get_fd(), false, true);
                    count_listen_passthrough();
                    child_sock_fd_api = nullptr;
                } else {
                    app_logdbg("Listen success");
                }
            }
        } else if (g_p_app->type == APP_ENVOY) {
            /* No sockinfo was created; the fd is still OS-listening. */
            app_degrade_listen_to_kernel(listen_fd, "addsocket failed");
        } else {
            app_logerr("addsocket() error on listen fd %d; serving on the kernel path", listen_fd);
            count_listen_passthrough();
        }
    }
    if (PROTO_UDP == si->get_protocol()) {
        sockinfo_udp *udp_sock = dynamic_cast<sockinfo_udp *>(parent_sock_fd_api);
        if (udp_sock) {
            static std::unordered_map<uint32_t, uint16_t> udp_sockets_per_port;
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
            sa_family_t family = udp_sock->get_family();
            uint32_t family_port = ((uint32_t)family << 16) | port;

            if ((reuse_port == 0) ||
                (udp_sockets_per_port[family_port] == g_p_app->get_worker_id())) {
                app_logdbg("worker %d is using fd=%d. family=%d bound to port=%d",
                           g_p_app->get_worker_id(), listen_fd, family, port);
                g_p_fd_collection->addsocket(listen_fd, si->get_family(), SOCK_DGRAM | block_type);
                sockinfo_udp *new_udp_sock =
                    dynamic_cast<sockinfo_udp *>(g_p_fd_collection->get_sockfd(listen_fd));
                if (new_udp_sock) {
                    new_udp_sock->copy_sockopt_fork(udp_sock);
#if defined(DEFINED_NGINX)
                    g_map_udp_resue_port[family_port] = true;
#endif
                    // in order to create new steering rules we call bind()
                    // we skip os.bind since it always fails
                    new_udp_sock->bind_no_os();
                }
            }
            /* This processes a case with multiple listen sockets with different ports */
            udp_sockets_per_port[family_port]++;
        }
    }

    return 0;
}

#endif
