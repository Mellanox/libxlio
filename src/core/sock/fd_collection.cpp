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

#include <sys/resource.h>

#include "utils/bullseye.h"
#include "util/libxlio.h"
#include "fd_collection.h"
#include "sock-redirect.h"
#include "sockinfo.h"
#include "sockinfo_udp.h"
#include "sockinfo_tcp.h"
#include "iomux/epfd_info.h"

#undef MODULE_NAME
#define MODULE_NAME "fdc:"
#undef MODULE_HDR
#define MODULE_HDR MODULE_NAME "%d:%s() "

#define fdcoll_logpanic   __log_panic
#define fdcoll_logerr     __log_err
#define fdcoll_logwarn    __log_warn
#define fdcoll_loginfo    __log_info
#define fdcoll_logdetails __log_details
#define fdcoll_logdbg     __log_dbg
#define fdcoll_logfunc    __log_func

fd_collection *g_p_fd_collection = nullptr;

fd_collection::fd_collection()
    : lock_mutex_recursive("fd_collection")
    , m_b_sysvar_offloaded_sockets(safe_mce_sys().offloaded_sockets)
#if defined(DEFINED_NGINX)
    // Avoid using socket pool for the master process (which doesn't have parent fd_collection)
    , m_use_socket_pool(safe_mce_sys().nginx_udp_socket_pool_size && g_p_app->get_worker_id() >= 0)
    , m_socket_pool_size(safe_mce_sys().nginx_udp_socket_pool_size)
    , m_socket_pool_counter(0)
#endif
{
    fdcoll_logfunc("");

    m_n_fd_map_size = 1024;
    struct rlimit rlim;
    if ((getrlimit(RLIMIT_NOFILE, &rlim) == 0) && ((int)rlim.rlim_max > m_n_fd_map_size)) {
        m_n_fd_map_size = rlim.rlim_max;
    }
    fdcoll_logdbg("using open files max limit of %d file descriptors", m_n_fd_map_size);

    m_p_sockfd_map = new sockinfo *[m_n_fd_map_size];
    memset(m_p_sockfd_map, 0, m_n_fd_map_size * sizeof(sockinfo *));

    m_p_epfd_map = new epfd_info *[m_n_fd_map_size];
    memset(m_p_epfd_map, 0, m_n_fd_map_size * sizeof(epfd_info *));

    m_p_cq_channel_map = new cq_channel_info *[m_n_fd_map_size];
    memset(m_p_cq_channel_map, 0, m_n_fd_map_size * sizeof(cq_channel_info *));

    m_p_tap_map = new ring_tap *[m_n_fd_map_size];
    memset(m_p_tap_map, 0, m_n_fd_map_size * sizeof(ring_tap *));
}

fd_collection::~fd_collection()
{
    fdcoll_logfunc("");

    clear();
    m_n_fd_map_size = -1;

    delete[] m_p_sockfd_map;
    m_p_sockfd_map = nullptr;

    delete[] m_p_epfd_map;
    m_p_epfd_map = nullptr;

    delete[] m_p_cq_channel_map;
    m_p_cq_channel_map = nullptr;

    delete[] m_p_tap_map;
    m_p_tap_map = nullptr;

    m_epfd_lst.clear_without_cleanup();
    m_pending_to_remove_lst.clear_without_cleanup();
}

// Triggers connection close of all handled fds.
// This is important for TCP connection which needs some time to terminate the connection,
// before the connection can be finally and properly closed.
void fd_collection::prepare_to_close()
{
    lock();
    for (int fd = 0; fd < m_n_fd_map_size; ++fd) {
        if (m_p_sockfd_map[fd]) {
            if (!g_is_forked_child) {
                sockinfo *p_sfd_api = get_sockfd(fd);
                if (p_sfd_api) {
                    p_sfd_api->prepare_to_close(true);
                }
            }
        }
    }
    unlock();
}

// Called in destructor after Internal-Thread destroyed
void fd_collection::clear()
{
    int fd;

    fdcoll_logfunc("");

    if (!m_p_sockfd_map) {
        return;
    }

    lock();

    /* internal thread should be already dead and
     * these sockets can not be deleted through the it.
     */
    while (!m_pending_to_remove_lst.empty()) {
        sockinfo *p_sfd_api = m_pending_to_remove_lst.get_and_pop_back();
        p_sfd_api->clean_socket_obj();
    }

    g_global_stat_static.n_pending_sockets = 0;

    /* Clean up all left overs sockinfo
     */
    for (fd = 0; fd < m_n_fd_map_size; ++fd) {
        if (m_p_sockfd_map[fd]) {
            if (!g_is_forked_child) {
                sockinfo *p_sfd_api = get_sockfd(fd);
                if (p_sfd_api) {
                    p_sfd_api->statistics_print();
                    p_sfd_api->clean_socket_obj();
                }
            }

            m_p_sockfd_map[fd] = nullptr;
            fdcoll_logdbg("destroyed fd=%d", fd);
        }

        if (m_p_epfd_map[fd]) {
            epfd_info *p_epfd = get_epfd(fd);
            if (p_epfd) {
                delete p_epfd;
            }
            m_p_epfd_map[fd] = nullptr;
            fdcoll_logdbg("destroyed epfd=%d", fd);
        }

        if (m_p_cq_channel_map[fd]) {
            cq_channel_info *p_cq_ch_info = get_cq_channel_fd(fd);
            if (p_cq_ch_info) {
                delete p_cq_ch_info;
            }
            m_p_cq_channel_map[fd] = nullptr;
            fdcoll_logdbg("destroyed cq_channel_fd=%d", fd);
        }

        if (m_p_tap_map[fd]) {
            m_p_tap_map[fd] = nullptr;
            fdcoll_logdbg("destroyed tapfd=%d", fd);
        }
    }

    unlock();
    fdcoll_logfunc("done");
}

int fd_collection::addsocket(int fd, int domain, int type, bool check_offload /*= false*/)
{
    transport_t transport;
    const int SOCK_TYPE_MASK = 0xf;
    int sock_type = type & SOCK_TYPE_MASK;
    int sock_flags = type & ~SOCK_TYPE_MASK;
    sockinfo *p_sfd_api_obj;

    fdcoll_logfunc("fd=%d domain=%d type=%d", fd, domain, type);

    if (check_offload && !create_offloaded_sockets()) {
        fdcoll_logdbg(
            "socket [fd=%d, domain=%d, type=%d] is not offloaded by thread rules or by %s", fd,
            domain, type, SYS_VAR_OFFLOADED_SOCKETS);
        return -1;
    }

    if (domain != AF_INET && domain != AF_INET6) {
        return -1;
    }
    if (fd != SOCKET_FAKE_FD && !is_valid_fd(fd)) {
        return -1;
    }

    try {
        switch (sock_type) {
        case SOCK_DGRAM: {
            transport = __xlio_match_by_program(PROTO_UDP, safe_mce_sys().app_id);
            if (transport == TRANS_OS) {
                fdcoll_logdbg("All UDP rules are consistent and instructing to use OS.");
                return -1;
            }
            fdcoll_logdbg("UDP rules are either not consistent or instructing to use XLIO.");
            p_sfd_api_obj = new sockinfo_udp(fd, domain);
            break;
        }
        case SOCK_STREAM: {
            transport = __xlio_match_by_program(PROTO_TCP, safe_mce_sys().app_id);
            if (transport == TRANS_OS) {
                fdcoll_logdbg("All TCP rules are consistent and instructing to use OS.");
                return -1;
            }
            fdcoll_logdbg("TCP rules are either not consistent or instructing to use XLIO.");
            p_sfd_api_obj = new sockinfo_tcp(fd, domain);
            fd = p_sfd_api_obj->get_fd();
            break;
        }
        default:
            fdcoll_logdbg("unsupported socket type=%d", sock_type);
            return -1;
        }
    } catch (xlio_exception &e) {
        fdcoll_logdbg("recovering from %s", e.what());
        return -1;
    }
    lock();

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!p_sfd_api_obj) {
        fdcoll_logpanic("[fd=%d] Failed creating new sockinfo (%m)", fd);
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    if (sock_flags) {
        if (sock_flags & SOCK_NONBLOCK) {
            p_sfd_api_obj->fcntl(F_SETFL, O_NONBLOCK);
        }
        if (sock_flags & SOCK_CLOEXEC) {
            p_sfd_api_obj->fcntl(F_SETFD, FD_CLOEXEC);
        }
    }

    assert(!get_sockfd(fd));
    assert(!get_epfd(fd));
    m_p_sockfd_map[fd] = p_sfd_api_obj;

    unlock();

    return fd;
}

bool fd_collection::create_offloaded_sockets()
{
    bool ret = m_b_sysvar_offloaded_sockets;

    lock();
    if (m_offload_thread_rule.find(pthread_self()) == m_offload_thread_rule.end()) {
        unlock();
        return ret;
    }
    unlock();

    return !ret;
}

/*
 * Create sockets on the given thread as offloaded/not-offloaded.
 * pass true for offloaded, false for not-offloaded.
 */
void fd_collection::offloading_rule_change_thread(bool offloaded, pthread_t tid)
{
    fdcoll_logdbg("tid=%lu, offloaded=%d", tid, offloaded);

    lock();
    if (offloaded == m_b_sysvar_offloaded_sockets) {
        m_offload_thread_rule.erase(tid);
    } else {
        m_offload_thread_rule[tid] = 1;
    }
    unlock();
}

void fd_collection::statistics_print_helper(int fd, vlog_levels_t log_level)
{
    sockinfo *socket_fd;
    epfd_info *epoll_fd;

    if ((socket_fd = get_sockfd(fd))) {
        vlog_printf(log_level, "==================== SOCKET FD ===================\n");
        socket_fd->statistics_print(log_level);
        goto found_fd;
    }
    if ((epoll_fd = get_epfd(fd))) {
        vlog_printf(log_level, "==================== EPOLL FD ====================\n");
        epoll_fd->statistics_print(log_level);
        goto found_fd;
    }

    return;

found_fd:

    vlog_printf(log_level, "==================================================\n");
}

void fd_collection::statistics_print(int fd, vlog_levels_t log_level)
{
    vlog_printf(log_level, "==================================================\n");
    if (fd) {
        vlog_printf(log_level, "============ DUMPING FD %d STATISTICS ============\n", fd);
        g_p_fd_collection->statistics_print_helper(fd, log_level);
    } else {
        vlog_printf(log_level, "======= DUMPING STATISTICS FOR ALL OPEN FDS ======\n");
        int fd_map_size = g_p_fd_collection->get_fd_map_size();
        for (int i = 0; i < fd_map_size; i++) {
            g_p_fd_collection->statistics_print_helper(i, log_level);
        }
    }
    vlog_printf(log_level, "==================================================\n");
}

int fd_collection::addepfd(int epfd, int size)
{
    fdcoll_logfunc("epfd=%d", epfd);

    if (!is_valid_fd(epfd)) {
        return -1;
    }

    lock();

    // Sanity check to remove any old sockinfo object using the same fd!!
    epfd_info *p_fd_info = get_epfd(epfd);
    if (p_fd_info) {
        fdcoll_logwarn("[fd=%d] Deleting old duplicate sockinfo object (%p)", epfd, p_fd_info);
        unlock();
        handle_close(epfd, true);
        lock();
    }

    unlock();
    p_fd_info = new epfd_info(epfd, size);
    lock();

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!p_fd_info) {
        fdcoll_logpanic("[fd=%d] Failed creating new sockinfo (%m)", epfd);
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    m_p_epfd_map[epfd] = p_fd_info;
    m_epfd_lst.push_back(p_fd_info);

    unlock();

    return 0;
}

int fd_collection::addtapfd(int tapfd, ring_tap *p_ring)
{
    fdcoll_logfunc("tapfd=%d, p_ring=%p", tapfd, p_ring);

    if (!is_valid_fd(tapfd)) {
        return -1;
    }

    lock();

    if (get_tapfd(tapfd)) {
        fdcoll_logwarn("[tapfd=%d] already exist in the collection (ring %p)", tapfd,
                       get_tapfd(tapfd));
        return -1;
    }

    m_p_tap_map[tapfd] = p_ring;

    unlock();

    return 0;
}

int fd_collection::add_cq_channel_fd(int cq_ch_fd, ring *p_ring)
{
    fdcoll_logfunc("cq_ch_fd=%d", cq_ch_fd);

    if (!is_valid_fd(cq_ch_fd)) {
        return -1;
    }

    lock();

    epfd_info *p_fd_info = get_epfd(cq_ch_fd);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (p_fd_info) {
        fdcoll_logwarn("[fd=%d] Deleting old duplicate sockinfo object (%p)", cq_ch_fd, p_fd_info);
        unlock();
        handle_close(cq_ch_fd, true);
        lock();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    // Sanity check to remove any old objects using the same fd!!
    sockinfo *p_cq_ch_fd_api_obj = get_sockfd(cq_ch_fd);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (p_cq_ch_fd_api_obj) {
        fdcoll_logwarn("[fd=%d] Deleting old duplicate object (%p)", cq_ch_fd, p_cq_ch_fd_api_obj);
        unlock();
        handle_close(cq_ch_fd, true);
        lock();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    // Check if cq_channel_info was already created
    cq_channel_info *p_cq_ch_info = get_cq_channel_fd(cq_ch_fd);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (p_cq_ch_info) {
        fdcoll_logwarn("cq channel fd already exists in fd_collection");
        m_p_cq_channel_map[cq_ch_fd] = nullptr;
        delete p_cq_ch_info;
        p_cq_ch_info = nullptr;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    unlock();
    p_cq_ch_info = new cq_channel_info(p_ring);
    lock();

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!p_cq_ch_info) {
        fdcoll_logpanic("[fd=%d] Failed creating new cq_channel_info (%m)", cq_ch_fd);
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    m_p_cq_channel_map[cq_ch_fd] = p_cq_ch_info;

    unlock();

    return 0;
}

int fd_collection::del_sockfd(int fd, bool is_for_udp_pool /*=false*/)
{
    int ret_val = -1;
    sockinfo *p_sfd_api;

    p_sfd_api = get_sockfd(fd);

    if (p_sfd_api) {
        // TCP socket need some timer to before it can be deleted,
        // in order to gracefuly terminate TCP connection
        // so we have to stages:
        // 1. Prepare to close: kikstarts TCP connection termination
        // 2. Socket deletion when TCP connection == CLOSED
        if (p_sfd_api->prepare_to_close()) {
            // the socket is already closable
            // This may register the socket to be erased by internal thread,
            // However, a timer may tick on this socket before it is deleted.
            ret_val = del_socket(fd, m_p_sockfd_map);
        } else {
            lock();
            // The socket is not ready for close.
            // Delete it from fd_col and add it to pending_to_remove list.
            // This socket will be handled and destroyed now by fd_col.
            // This will be done from fd_col timer handler.
            // Used for UDP socket pool as well
            // so closed UDP sockets will be deleted at the end of the world
            if (m_p_sockfd_map[fd] == p_sfd_api) {
                if (!is_for_udp_pool) {
                    ++g_global_stat_static.n_pending_sockets;
                }
                m_p_sockfd_map[fd] = nullptr;
                m_pending_to_remove_lst.push_front(p_sfd_api);
            }

            unlock();
            ret_val = 0;
        }
    }

    return ret_val;
}

int fd_collection::del_epfd(int fd, bool b_cleanup /*=false*/)
{
    return del(fd, b_cleanup, m_p_epfd_map);
}

void fd_collection::remove_epfd_from_list(epfd_info *epfd)
{
    lock();
    m_epfd_lst.erase(epfd);
    unlock();
}

int fd_collection::del_cq_channel_fd(int fd, bool b_cleanup /*=false*/)
{
    return del(fd, b_cleanup, m_p_cq_channel_map);
}

void fd_collection::del_tapfd(int fd)
{
    if (!is_valid_fd(fd)) {
        return;
    }

    lock();
    m_p_tap_map[fd] = nullptr;
    unlock();
}

template <typename cls> int fd_collection::del(int fd, bool b_cleanup, cls **map_type)
{
    fdcoll_logfunc("fd=%d%s", fd,
                   b_cleanup ? ", cleanup case: trying to remove old socket handler" : "");

    if (!is_valid_fd(fd)) {
        return -1;
    }

    lock();
    cls *p_obj = map_type[fd];
    if (p_obj) {
        map_type[fd] = NULL;
        unlock();
        p_obj->clean_obj();
        return 0;
    }
    if (!b_cleanup) {
        fdcoll_logdbg("[fd=%d] Could not find related object", fd);
    }
    unlock();
    return -1;
}

int fd_collection::del_socket(int fd, sockinfo **map_type)
{
    fdcoll_logfunc("fd=%d", fd);

    if (!is_valid_fd(fd)) {
        return -1;
    }

    lock();
    sockinfo *p_obj = map_type[fd];
    if (p_obj) {
        map_type[fd] = nullptr;
        unlock();
        p_obj->clean_socket_obj();
        return 0;
    }

    fdcoll_logdbg("[fd=%d] Could not find related object", fd);
    unlock();
    return -1;
}

void fd_collection::remove_from_all_epfds(int fd, bool passthrough)
{
    lock();
    for (epfd_info *ep = m_epfd_lst.front(); ep; ep = m_epfd_lst.next(ep)) {
        ep->fd_closed(fd, passthrough);
    }
    unlock();

    return;
}

#if defined(DEFINED_NGINX)
void fd_collection::push_socket_pool(sockinfo *sockfd)
{
    lock();
    sockfd->prepare_to_close_socket_pool(true);
    m_socket_pool.push(sockfd);
    unlock();
}

bool fd_collection::pop_socket_pool(int &fd, bool &add_to_udp_pool, int type)
{
    bool ret = false;
    add_to_udp_pool = false;
    fd = -1;

    // socket pool is used only for udp sockets
    // here we verify it, while in all other places we use general case for socket fd
    if ((type != SOCK_DGRAM) || (safe_mce_sys().nginx_udp_socket_pool_size == 0)) {
        return ret;
    }

    lock();
    if (!m_socket_pool.empty()) {
        // use fd from pool - will skip creation of new fd by os
        sockinfo *sockfd = m_socket_pool.top();
        fd = sockfd->get_fd();
        if (!m_p_sockfd_map[fd]) {
            m_p_sockfd_map[fd] = sockfd;
            m_pending_to_remove_lst.erase(sockfd);
        }
        sockfd->prepare_to_close_socket_pool(false);
        m_socket_pool.pop();
        ret = true;
    } else {
        // pool is empty - will create of new fd by os, and will mark it as fd for the pool
        add_to_udp_pool = true;
    }
    unlock();

    return ret;
}

void fd_collection::handle_socket_pool(int fd)
{
    if (!m_use_socket_pool) {
        return;
    }

    if (m_socket_pool_counter >= m_socket_pool_size) {
        fdcoll_logdbg("Worker %d reached max UDP socket pool size (%d).", g_p_app->get_worker_id(),
                      m_socket_pool_size);
        m_use_socket_pool = false;
        return;
    }

    sockinfo *sockfd = get_sockfd(fd);
    if (sockfd) {
        ++m_socket_pool_counter;
        sockfd->set_params_for_socket_pool();
    }
}
#endif
