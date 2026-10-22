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
static void envoy_degrade_listen_to_kernel(int listen_fd, const char *reason);

struct app_conf *g_p_app = nullptr;

#if defined(DEFINED_NGINX)
int app_conf::proc_nginx()
{
    int rc = 0;

    DO_GLOBAL_CTORS();
    std::lock_guard<decltype(g_p_app->m_lock)> lock(g_p_app->m_lock);

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

    /* Prcess only sockets from map_listen_fd */
    bool found = false;
    pid_t owner_tid = -1;
    {
        std::lock_guard<decltype(g_p_app->m_lock)> lock(g_p_app->m_lock);
        auto iter = g_p_app->map_listen_fd.find(__fd);
        if (iter != g_p_app->map_listen_fd.end()) {
            found = true;
            owner_tid = iter->second;
        }
    }
    if (found) {
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
                    envoy_degrade_listen_to_kernel(__fd, "listen failed");
                    rc = 0;
                }
            }
            std::lock_guard<decltype(g_p_app->m_lock)> lock(g_p_app->m_lock);
            g_p_app->map_listen_fd.erase(__fd);
        } else if (__op == EPOLL_CTL_ADD) {
            static int original_listen_count = INT_MAX;
            static int total_worker_id = 0;
            int worker_id = -1;

            /* A duplicated listen fd has no sockinfo of its own; init_worker()
             * clones it from the parent-field snapshot captured by the dup()
             * intercept (map_dup_listen). When Envoy performs a same-address
             * listener update under enable_reuse_port=true it dup()s the old
             * listener's fds, whose parent is an already offloaded reuse_port
             * listen socket - there is nothing to wait for. A valid snapshot for
             * this fd marks exactly that case, so use it to skip the
             * enable_reuse_port=false ordering wait below: that wait never opens
             * for a dup'd fd under reuse_port=true (p_socket_object stays null and
             * original_listen_count stays INT_MAX), so it would starve and return
             * -1 (EINVAL), blackholing the new listener.
             *
             * The snapshot is captured while the parent is alive on Envoy's main
             * thread, so both the skip decision here and the clone in init_worker()
             * are race-free: neither dereferences the draining old listener, which
             * may already be freed by the time this worker thread runs. */
            bool dup_parent_offloaded = false;
            {
                std::lock_guard<decltype(g_p_app->m_lock)> lock(g_p_app->m_lock);
                auto snap_itr = g_p_app->map_dup_listen.find(__fd);
                dup_parent_offloaded =
                    (snap_itr != g_p_app->map_dup_listen.end()) && snap_itr->second.valid;
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
            while (!p_socket_object && !dup_parent_offloaded && (original_listen_count > 0)) {
                if (!sleep_count--) {
                    return -1;
                }
                const struct timespec short_sleep = {0, 1000};
                nanosleep(&short_sleep, NULL);
            }

            /* Serialize the whole worker initialization path. m_init_lock
             * cannot participate in the m_lock/device-layer lock inversion:
             * it is acquired only here, where the calling thread holds no
             * other XLIO locks (see the lock-order contract in sock-app.h).
             */
            std::lock_guard<decltype(g_p_app->m_init_lock)> init_guard(g_p_app->m_init_lock);
            {
                std::lock_guard<decltype(g_p_app->m_lock)> lock(g_p_app->m_lock);

                /* Logic that assigns worker id for processed listener
                 * total_worker_id is unique for all threads
                 */
                worker_id = g_p_app->get_worker_id();
                if (worker_id < 0) {
                    worker_id = total_worker_id;
                    total_worker_id++;
                }

                /* This check is `enable_reuse_port = false` specific
                 *
                 * This part should guarantee initialization of all listeners for worker 0.
                 * original_listen_count is initialized to number of them first.
                 */
                sockinfo *si = dynamic_cast<sockinfo *>(p_socket_object);
                if (si && !si->get_reuseport() && worker_id == 0) {
                    if (original_listen_count == INT_MAX) {
                        original_listen_count = 0;
                        for (const auto &itr : g_p_app->map_dup_fd) {
                            if (itr.first == itr.second) {
                                original_listen_count++;
                            }
                        }
                    }
                    original_listen_count--;
                }

                g_p_app->map_listen_fd[__fd] = gettid();
                g_p_app->map_thread_id[gettid()] = worker_id;
            }

            /* init_worker() creates rings/CQs and can take device-layer
             * locks, so it must run without m_lock.
             */
            rc = init_worker(worker_id, __fd);
            if (rc != 0) {
                app_logerr("Failed to initialize worker %d, (errno=%d %m)", worker_id, errno);
                std::lock_guard<decltype(g_p_app->m_lock)> lock(g_p_app->m_lock);
                g_p_app->map_listen_fd.erase(__fd);
                g_p_app->map_thread_id.erase(gettid());
                g_p_app->map_dup_listen.erase(__fd);
                return rc;
            }
        } else if (__op == EPOLL_CTL_DEL) {
            std::lock_guard<decltype(g_p_app->m_lock)> lock(g_p_app->m_lock);
            g_p_app->map_listen_fd.erase(__fd);
            /* Drop the dup snapshot for this child fd so it does not persist
             * across listener updates that recycle the same fd number. */
            g_p_app->map_dup_listen.erase(__fd);
        }
    }

    return rc;
}
#endif /* DEFINED_ENVOY */

/* An Envoy listen fd that XLIO cannot offload must degrade to the kernel path,
 * never black-hole. Drop the half-built XLIO sockinfo - passthrough=true leaves
 * the fd OS-listening (the socket()/listen() interposers already issued the
 * kernel listen()), so epoll_ctl()'s normal path then registers it on the kernel
 * epoll and accept() falls through to the kernel. Account the lost acceleration
 * loudly (counter + warning) so it surfaces in the tuning report instead of
 * failing silently. */
static void envoy_degrade_listen_to_kernel(int listen_fd, const char *reason)
{
    handle_close(listen_fd, false /*cleanup*/, true /*passthrough*/);
    g_tuning_report_counters.n_envoy_listen_passthrough.fetch_add(1, std::memory_order_relaxed);
    vlog_printf(VLOG_WARNING,
                "could not offload Envoy listen fd=%d (%s); serving on the kernel path, "
                "acceleration lost\n",
                listen_fd, reason);
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
    PASSTHROUGH, /* prepareListen() > 0 - routine, counted for Envoy, never WARNs */
    LISTEN, /* listen() < 0 */
};

/* The ONLY place app identity influences clone exit handling (two branches,
 * keyed on g_p_app->type, never per leg):
 * - APP_ENVOY: envoy_degrade_listen_to_kernel() (handle_close + counter + WARN);
 *   PASSTHROUGH counts without warning (routine).
 * - otherwise (nginx): app_logerr (exit-specific text below) + handle_close when
 *   a sockinfo exists; PASSTHROUGH closes silently.
 * Every disposition leaves NO sockinfo on the fd; the fd stays OS-listening, so
 * the kernel path serves. Callers return 0 (a clone failure is never an ADD
 * failure; a nonzero return would make the epoll_ctl interposer degrade and
 * count a second time). */
static void clone_listen_exit(clone_exit kind, int listen_fd, sockinfo *child)
{
    if (g_p_app->type == APP_ENVOY) {
        switch (kind) {
        case clone_exit::ADDSOCKET:
            envoy_degrade_listen_to_kernel(listen_fd, "addsocket failed");
            break;
        case clone_exit::BIND:
            envoy_degrade_listen_to_kernel(listen_fd, "bind failed");
            break;
        case clone_exit::PREPARE:
            envoy_degrade_listen_to_kernel(listen_fd, "prepareListen failed");
            break;
        case clone_exit::PASSTHROUGH:
            /* Routine pass-through: XLIO chose not to offload this listener.
             * Not an error, so no warning - but still count the lost
             * acceleration so the tuning report reflects every listener that
             * ended up on the kernel path. */
            handle_close(child->get_fd(), false, true);
            g_tuning_report_counters.n_envoy_listen_passthrough.fetch_add(
                1, std::memory_order_relaxed);
            break;
        case clone_exit::LISTEN:
            envoy_degrade_listen_to_kernel(listen_fd, "listen failed");
            break;
        }
        return;
    }

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
}

/* Clone-and-offload core, shared by every TCP listener clone:
 *  - Envoy snapshot leg (src captured at dup() time)       [DUP_SNAPSHOT]
 *  - Envoy parent-lookup leg (src read from live parent)   [LIVE_PARENT]
 *  - nginx fork-inherited leg (src read from inherited fd) [FORK_INHERITED]
 * addsocket -> copy opts -> bind -> prepareListen -> listen, with exactly one
 * disposition per non-offload exit (clone_listen_exit), so the per-exit policy
 * cannot diverge between legs again.
 * Always returns 0: every outcome leaves the fd serving - offloaded on success,
 * kernel path otherwise (no sockinfo remains; the fd is OS-listening).
 * Lock context (sock-app.h contract): Envoy callers hold m_init_lock only;
 * nginx callers hold recursive m_lock under the single-threaded exemption;
 * NEVER call this under m_lock on the Envoy path (device-layer calls inside). */
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

static int init_worker_udp(sockinfo *parent_sock_fd_api, sockinfo *si, int listen_fd,
                           const sock_addr &sa)
{
    int block_type = si->is_blocking() ? 0 : SOCK_NONBLOCK;
    sockinfo_udp *udp_sock = dynamic_cast<sockinfo_udp *>(parent_sock_fd_api);
    if (udp_sock) {
        /* Unsynchronized by design: callers serialize - proc_envoy() holds
         * m_init_lock across init_worker(), and proc_nginx() workers are
         * single-threaded processes (holding m_lock). Not safe for any other
         * caller. */
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
            parent_fd = -1;
            /* map_dup_fd and map_dup_listen are written by the dup() intercept
             * under m_lock. init_worker() runs without m_lock held (it is a leaf
             * lock, see sock-app.h), so take it for the lookup and copy the
             * snapshot out while holding it.
             */
            dup_listen_snapshot snap;
            {
                std::lock_guard<decltype(g_p_app->m_lock)> lock(g_p_app->m_lock);
                const auto itr = g_p_app->map_dup_fd.find(listen_fd);
                if (itr != g_p_app->map_dup_fd.end()) {
                    parent_fd = itr->second;
                }
                const auto snap_itr = g_p_app->map_dup_listen.find(listen_fd);
                if (snap_itr != g_p_app->map_dup_listen.end()) {
                    snap = snap_itr->second;
                }
            }
            if (parent_fd < 0) {
                return -1;
            }
            /* Clone the child listener from the snapshot captured at dup() time.
             * This never dereferences the parent sockinfo (the draining old
             * listener), so the clone is race-free even if the parent has already
             * been freed by the time this worker thread runs. The snapshot is only
             * populated for a TCP reuse_port listener (the Envoy same-address
             * update path); the parent-lookup path below serves as a safety
             * fallback if the snapshot is somehow absent. */
            if (snap.valid) {
                /* Clone the updated listener's per-worker socket from the snapshot
                 * and offload it. Every non-offload outcome degrades to the kernel
                 * path via envoy_degrade_listen_to_kernel() and returns success, so
                 * a failed clone never black-holes the listener and never leaves a
                 * half-built sockinfo that epoll_ctl() would treat as offloaded. */
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
                    envoy_degrade_listen_to_kernel(listen_fd, "listen failed");
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
        src.valid = true;
        return clone_offloaded_listener(
            listen_fd, src,
            g_p_app->type == APP_ENVOY ? clone_source::LIVE_PARENT : clone_source::FORK_INHERITED);
    }
    if (PROTO_UDP == si->get_protocol()) {
        return init_worker_udp(parent_sock_fd_api, si, listen_fd, sa);
    }

    return 0;
}

#endif
