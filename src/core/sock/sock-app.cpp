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
#include <cassert>

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

int app_conf::assign_worker_and_publish(int fd, sockinfo *si)
{
    int worker_id;
    {
        std::lock_guard<decltype(m_map_lock)> lock(m_map_lock);

        /* m_total_worker_id is unique for all threads */
        worker_id = get_worker_id();
        if (worker_id < 0) {
            worker_id = m_total_worker_id;
            m_total_worker_id++;
        }

        map_listen_fd[fd] = gettid();
        map_thread_id[gettid()] = worker_id;
    }

    /* This check is `enable_reuse_port = false` specific
     *
     * This part should guarantee initialization of all listeners for worker 0.
     * m_original_listen_count is initialized to number of them first. The
     * counter itself is serialized by m_init_lock (this path's caller) and
     * read unlocked by the ordering wait; only the map scan needs m_map_lock.
     */
    if (si && !si->get_reuseport() && worker_id == 0) {
        if (m_original_listen_count == INT_MAX) {
            int originals = 0;
            {
                std::lock_guard<decltype(m_map_lock)> lock(m_map_lock);
                for (const auto &itr : map_dup_fd) {
                    if (itr.first == itr.second) {
                        originals++;
                    }
                }
            }
            m_original_listen_count = originals;
        }
        m_original_listen_count--;
    }

    return worker_id;
}

bool app_conf::has_dup_snapshot(int fd)
{
    std::lock_guard<decltype(m_map_lock)> lock(m_map_lock);
    return map_dup_listen.count(fd) != 0;
}

int app_conf::lookup_dup(int fd, dup_listen_snapshot &snap, bool &has_snap)
{
    int parent_fd = -1;
    has_snap = false;
    std::lock_guard<decltype(m_map_lock)> lock(m_map_lock);
    const auto itr = map_dup_fd.find(fd);
    if (itr != map_dup_fd.end()) {
        parent_fd = itr->second;
    }
    const auto snap_itr = map_dup_listen.find(fd);
    if (snap_itr != map_dup_listen.end()) {
        snap = snap_itr->second;
        has_snap = true;
    }
    return parent_fd;
}

void app_conf::register_dup(int fd, int parent_fd, const dup_listen_snapshot *snap)
{
    std::lock_guard<decltype(m_map_lock)> lock(m_map_lock);
    map_dup_fd[fd] = parent_fd;
    /* The parent maps to itself */
    map_dup_fd[parent_fd] = parent_fd;
    if (snap) {
        map_dup_listen[fd] = *snap;
    }
}

void app_conf::forget_fd(int fd)
{
    std::lock_guard<decltype(m_map_lock)> lock(m_map_lock);
    map_dup_fd.erase(fd);
    map_dup_listen.erase(fd);
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

            /* A snapshot marks a dup of an already offloaded reuse_port
             * listener (the Envoy same-address update): the ordering wait
             * below must be skipped for it, or it starves - the gate only
             * ever opens on the enable_reuse_port=false path - and the
             * updated listener black-holes. The snapshot was captured while
             * the parent was alive; nothing on this path dereferences the
             * draining parent sockinfo, which may already be freed. */
            bool dup_parent_offloaded = g_p_app->has_dup_snapshot(__fd);

            /* This check is `enable_reuse_port = false` specific
             *
             * original listen sockets should be created first
             * original_listen_count count sockets that should be
             * processed until openning a door for others.
             * timer should be enough to complete initialization of
             * all sockets related worker 0.
             */
            int sleep_count = 1000;
            while (!p_socket_object && !dup_parent_offloaded &&
                   (g_p_app->m_original_listen_count > 0)) {
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
                g_p_app->map_dup_listen.erase(__fd);
                return rc;
            }
        } else if (__op == EPOLL_CTL_DEL) {
            std::lock_guard<decltype(g_p_app->m_map_lock)> lock(g_p_app->m_map_lock);
            g_p_app->map_listen_fd.erase(__fd);
            /* Drop the dup snapshot for this child fd so it does not persist
             * across listener updates that recycle the same fd number. */
            g_p_app->map_dup_listen.erase(__fd);
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

/* Where the clone's source state was materialized. Selects leg-specific DEBUG
 * texts only; dispositions never depend on it (that is the point). */
enum class clone_source {
    DUP_SNAPSHOT, /* captured at dup() time on the Envoy main thread */
    LIVE_PARENT, /* read from the live parent sockinfo at worker time (Envoy) */
    FORK_INHERITED, /* read from the fork-inherited parent collection (nginx) */
};

enum class clone_exit {
    ADDSOCKET, /* addsocket() left no sockinfo on the fd */
    BIND, /* bind_internal() < 0 */
    PREPARE, /* prepareListen() < 0 */
    PASSTHROUGH, /* prepareListen() > 0 - routine, counted, never warns */
    LISTEN, /* listen() < 0 */
};

/* The ONLY place app identity influences clone exit handling (two branches,
 * keyed on g_p_app->type, never per leg). Every exit counts the kernel-path
 * listener; Envoy error exits degrade with a warning, nginx error exits keep
 * their exit-specific error log; PASSTHROUGH is routine on both (no warning).
 * Every disposition leaves NO sockinfo on the fd; the fd stays OS-listening,
 * so the kernel path serves. Callers return 0 (a clone failure is never an ADD
 * failure; a nonzero return would make the epoll_ctl interposer degrade and
 * count a second time). */
static void clone_listen_exit(clone_exit kind, int listen_fd, sockinfo *child)
{
    if (g_p_app->type == APP_ENVOY) {
        switch (kind) {
        case clone_exit::ADDSOCKET:
            app_degrade_listen_to_kernel(listen_fd, "addsocket failed");
            break;
        case clone_exit::BIND:
            app_degrade_listen_to_kernel(listen_fd, "bind failed");
            break;
        case clone_exit::PREPARE:
            app_degrade_listen_to_kernel(listen_fd, "prepareListen failed");
            break;
        case clone_exit::PASSTHROUGH:
            handle_close(child->get_fd(), false, true);
            count_listen_passthrough();
            break;
        case clone_exit::LISTEN:
            app_degrade_listen_to_kernel(listen_fd, "listen failed");
            break;
        }
        assert(!g_p_fd_collection->get_sockfd(listen_fd) &&
               "clone exit must leave no sockinfo on the fd");
        return;
    }

    count_listen_passthrough();
    switch (kind) {
    case clone_exit::ADDSOCKET:
        app_logerr("addsocket() error on listen fd %d; serving on the kernel path", listen_fd);
        break;
    case clone_exit::BIND:
        app_logerr("bind() error on listen fd %d; serving on the kernel path", listen_fd);
        handle_close(child->get_fd(), false, true);
        break;
    case clone_exit::PREPARE:
        app_logerr("prepareListen error on listen fd %d; serving on the kernel path", listen_fd);
        handle_close(child->get_fd(), false, true);
        break;
    case clone_exit::PASSTHROUGH:
        handle_close(child->get_fd(), false, true);
        break;
    case clone_exit::LISTEN:
        app_logerr("listen() error on listen fd %d; serving on the kernel path", listen_fd);
        handle_close(child->get_fd(), false, true);
        break;
    }
    assert(!g_p_fd_collection->get_sockfd(listen_fd) &&
           "clone exit must leave no sockinfo on the fd");
}

/* Clone-and-offload core, shared by every TCP listener clone (Envoy snapshot
 * leg, Envoy parent-lookup leg, nginx fork-inherited leg): addsocket -> copy
 * opts -> bind -> prepareListen -> listen, with exactly one disposition per
 * non-offload exit (clone_listen_exit), so the per-exit policy cannot diverge
 * between legs again. Always returns 0: every outcome leaves the fd serving -
 * offloaded on success, kernel path otherwise (no sockinfo remains).
 * Lock context: Envoy callers hold m_init_lock only; nginx callers hold the
 * recursive m_map_lock (single-threaded exemption); NEVER call this under
 * m_map_lock on the Envoy path (device-layer calls inside). */
static int clone_offloaded_listener(int listen_fd, const dup_listen_snapshot &src,
                                    clone_source prov)
{
    int block_type = src.is_blocking ? 0 : SOCK_NONBLOCK;

    g_p_fd_collection->addsocket(listen_fd, src.family, SOCK_STREAM | block_type);
    sockinfo *child_sock_fd_api = g_p_fd_collection->get_sockfd(listen_fd);
    if (!child_sock_fd_api) {
        /* No sockinfo was created; the fd is still OS-listening. */
        clone_listen_exit(clone_exit::ADDSOCKET, listen_fd, nullptr);
        return 0;
    }

    child_sock_fd_api->copy_sockopt_fork_values(src.is_ipv6only, src.back_log);

    int ret = bind_internal(child_sock_fd_api, src.sa.get_p_sa(), src.sa_len);
    if (ret < 0) {
        /* Do not listen() on a mis-bound socket. */
        clone_listen_exit(clone_exit::BIND, listen_fd, child_sock_fd_api);
        return 0;
    }

    ret = child_sock_fd_api->prepareListen();
    if (ret < 0) {
        clone_listen_exit(clone_exit::PREPARE, listen_fd, child_sock_fd_api);
        return 0;
    }
    if (ret > 0) {
        clone_listen_exit(clone_exit::PASSTHROUGH, listen_fd, child_sock_fd_api);
        return 0;
    }
    if (prov != clone_source::DUP_SNAPSHOT) {
        app_logdbg("Prepare listen successfully offloaded");
    }

    ret = child_sock_fd_api->listen(child_sock_fd_api->get_back_log());
    if (ret < 0) {
        clone_listen_exit(clone_exit::LISTEN, listen_fd, child_sock_fd_api);
        return 0;
    }
    if (prov == clone_source::DUP_SNAPSHOT) {
        app_logdbg("Envoy listen fd %d offloaded from dup snapshot", listen_fd);
    } else {
        app_logdbg("Listen success");
    }
    return 0;
}

static int init_worker_tcp(sockinfo *parent_sock_fd_api, sockinfo *si, int listen_fd,
                           const sock_addr &sa, socklen_t sa_len)
{
    NOT_IN_USE(parent_sock_fd_api);
    app_logdbg("found listen socket %d", parent_sock_fd_api->get_fd());
    /* Materialize the clone's source state from the live parent (Envoy reuse_port=false
     * fresh adds and same-address updates) or the fork-inherited parent (nginx). */
    dup_listen_snapshot src;
    src.sa = sa;
    src.sa_len = sa_len;
    src.family = si->get_family();
    src.is_ipv6only = si->is_ipv6only();
    src.is_blocking = si->is_blocking();
    src.back_log = si->get_back_log();
    return clone_offloaded_listener(
        listen_fd, src,
        g_p_app->type == APP_ENVOY ? clone_source::LIVE_PARENT : clone_source::FORK_INHERITED);
}

static int init_worker_udp(sockinfo *parent_sock_fd_api, sockinfo *si, int listen_fd,
                           const sock_addr &sa)
{
    int block_type = si->is_blocking() ? 0 : SOCK_NONBLOCK;
    sockinfo_udp *udp_sock = dynamic_cast<sockinfo_udp *>(parent_sock_fd_api);
    if (udp_sock) {
        /* Unsynchronized by design: callers serialize - proc_envoy() holds
         * m_init_lock across init_worker(), and proc_nginx() workers are
         * single-threaded processes (holding m_map_lock). Not safe for any
         * other caller. */
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

        if ((reuse_port == 0) || (udp_sockets_per_port[family_port] == g_p_app->get_worker_id())) {
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

    return 0;
}

/* worker_id is log-only context here: worker identity is already published via
 * map_thread_id before init_worker() runs, and the clone core does not take it. */
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
            dup_listen_snapshot snap;
            bool has_snap = false;
            parent_fd = g_p_app->lookup_dup(listen_fd, snap, has_snap);
            if (parent_fd < 0) {
                return -1;
            }
            /* Clone from the snapshot captured at dup() time - never from the
             * parent sockinfo, which may already be freed (the draining old
             * listener). A snapshot exists only for a TCP reuse_port parent;
             * the parent-lookup path below is the fallback without one. */
            if (has_snap) {
                app_logdbg("cloning listen fd %d from dup snapshot", listen_fd);
                return clone_offloaded_listener(listen_fd, snap, clone_source::DUP_SNAPSHOT);
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

    sock_addr sa;
    socklen_t sa_len = sa.get_socklen();

    parent_sock_fd_api->getsockname(sa.get_p_sa(), &sa_len);
    if (PROTO_TCP == si->get_protocol()) {
        return init_worker_tcp(parent_sock_fd_api, si, listen_fd, sa, sa_len);
    }
    if (PROTO_UDP == si->get_protocol()) {
        return init_worker_udp(parent_sock_fd_api, si, listen_fd, sa);
    }

    return 0;
}

#endif
