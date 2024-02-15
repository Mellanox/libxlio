/*
 * Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include <sock/sockinfo.h>
#include <sock/sock-redirect.h>
#include <sock/sockinfo_tcp.h>
#include <sock/sockinfo_udp.h>
#include <sock/fd_collection.h>

#include <vlogger/vlogger.h>

#include "sock/sock-app.h"

using namespace std;

#define MODULE_NAME "app:"

#define app_logpanic __log_panic
#define app_logerr   __log_err
#define app_logwarn  __log_warn
#define app_loginfo  __log_info
#define app_logdbg   __log_dbg

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)

#if defined(DEFINED_NGINX)
map_udp_bounded_port_t g_map_udp_bounded_port;
#endif

static int init_worker(int worker_id, int listen_fd);

struct app_conf *g_p_app = NULL;

#if defined(DEFINED_NGINX)
int app_conf::proc_nginx(void)
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
    auto iter = g_p_app->map_listen_fd.find(__fd);
    if (iter != g_p_app->map_listen_fd.end()) {
        sockinfo *p_socket_object = fd_collection_get_sockfd(__fd);
        if (iter->second == gettid()) {
            /* process listen sockets from main thread and remove
             * them from map_listen_fd
             */
            if (p_socket_object) {
                rc = p_socket_object->listen(p_socket_object->m_back_log);
                if (rc < 0) {
                    return rc;
                }
            }
            std::lock_guard<decltype(g_p_app->m_lock)> lock(g_p_app->m_lock);
            g_p_app->map_listen_fd.erase(iter);
        } else if (__op == EPOLL_CTL_ADD) {
            static int original_listen_count = INT_MAX;
            static int total_worker_id = 0;
            int worker_id = -1;

            /* This check is `enable_reuse_port = false` specific
             *
             * original listen sockets should be created first
             * original_listen_count count sockets that should be
             * processed until openning a door for others.
             * timer should be enough to complete initialization of
             * all sockets related worker 0.
             */
            int sleep_count = 1000;
            while (!p_socket_object && (original_listen_count > 0)) {
                if (!sleep_count--) {
                    return -1;
                }
                const struct timespec short_sleep = {0, 1000};
                nanosleep(&short_sleep, NULL);
            }
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
            rc = init_worker(worker_id, __fd);
            if (rc != 0) {
                app_logerr("Failed to initialize worker %d, (errno=%d %m)", worker_id, errno);
                g_p_app->map_listen_fd.erase(__fd);
                g_p_app->map_thread_id.erase(gettid());
                return rc;
            }
        } else if (__op == EPOLL_CTL_DEL) {
            std::lock_guard<decltype(g_p_app->m_lock)> lock(g_p_app->m_lock);
            g_p_app->map_listen_fd.erase(__fd);
        }
    }

    return rc;
}
#endif /* DEFINED_ENVOY */

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
            const auto itr = g_p_app->map_dup_fd.find(listen_fd);
            if (itr != g_p_app->map_dup_fd.end()) {
                parent_fd = itr->second;
            }
            if (parent_fd < 0) {
                return -1;
            }
        } else {
            ret = -1;
            child_sock_fd_api = p_fd_collection->get_sockfd(listen_fd);
            if (child_sock_fd_api) {
                ret = child_sock_fd_api->listen(child_sock_fd_api->m_back_log);
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
            child_sock_fd_api->copy_sockopt_fork(parent_sock_fd_api);

            ret = bind_internal(child_sock_fd_api, sa.get_p_sa(), sa_len);
            if (ret < 0) {
                app_logerr("bind() error");
            }

            // is the socket really offloaded
            ret = child_sock_fd_api->prepareListen();
            if (ret < 0) {
                app_logerr("prepareListen error");
                child_sock_fd_api = nullptr;
            } else if (ret > 0) { // Pass-through
                handle_close(child_sock_fd_api->get_fd(), false, true);
                child_sock_fd_api = nullptr;
            } else {
                app_logdbg("Prepare listen successfully offloaded");
            }

            if (child_sock_fd_api) {
                ret = child_sock_fd_api->listen(child_sock_fd_api->m_back_log);
                if (ret < 0) {
                    app_logerr("Listen error");
                } else {
                    app_logdbg("Listen success");
                }
            }
        }
    }
    if (PROTO_UDP == si->get_protocol()) {
        sockinfo_udp *udp_sock = dynamic_cast<sockinfo_udp *>(parent_sock_fd_api);
        if (udp_sock) {
            static std::unordered_map<uint16_t, uint16_t> udp_sockets_per_port;
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
            if ((reuse_port == 0) || (udp_sockets_per_port[port] == g_p_app->get_worker_id())) {
                app_logdbg("worker %d is using fd=%d. bound to port=%d", g_p_app->get_worker_id(),
                           listen_fd, port);
                g_p_fd_collection->addsocket(listen_fd, si->get_family(), SOCK_DGRAM | block_type);
                sockinfo_udp *new_udp_sock =
                    dynamic_cast<sockinfo_udp *>(g_p_fd_collection->get_sockfd(listen_fd));
                if (new_udp_sock) {
                    new_udp_sock->copy_sockopt_fork(udp_sock);
#if defined(DEFINED_NGINX)
                    g_map_udp_bounded_port[port] = true;
#endif
                    // in order to create new steering rules we call bind()
                    // we skip os.bind since it always fails
                    new_udp_sock->bind_no_os();
                }
            }
            /* This processes a case with multiple listen sockets with different ports */
            udp_sockets_per_port[port]++;
        }
    }

    return 0;
}

#endif
