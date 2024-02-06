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

#include <mutex>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/route.h>

#include "vlogger/vlogger.h"
#include "utils/bullseye.h"
#include "netlink_wrapper.h"
#include <netlink/types.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/utils.h>

#define MODULE_NAME "nl_wrapper:"

#define nl_logpanic __log_panic
#define nl_logerr   __log_err
#define nl_logwarn  __log_warn
#define nl_loginfo  __log_info
#define nl_logdbg   __log_dbg
#define nl_logfine  __log_fine

netlink_wrapper *g_p_netlink_handler = nullptr;

// structure to pass arguments on internal netlink callbacks handling
typedef struct rcv_msg_arg {
    netlink_wrapper *netlink;
    nl_sock *socket_handle;
    std::map<e_netlink_event_type, subject *> *subjects_map;
    nlmsghdr *msghdr;
} rcv_msg_arg_t;

static rcv_msg_arg_t g_nl_rcv_arg;

static int nl_msg_rcv_cb(struct nl_msg *msg, void *arg)
{
    nl_logfine("---> nl_msg_rcv_cb");
    NOT_IN_USE(arg);
    g_nl_rcv_arg.msghdr = nlmsg_hdr(msg);
    // NETLINK MESAGE DEBUG
    // nl_msg_dump(msg, stdout);
    nl_logfine("<--- nl_msg_rcv_cb");
    return 0;
}

static nl_cache_mngr *nl_cache_mngr_alloc_aligned(nl_sock *handle, int protocol, int flags)
{
    nl_cache_mngr *cache_mngr;

    /* allocate temporary 10 nl_sockets for marking the first 10 bits of user_port_map[0]
     * (@[libnl/lib/socket.c]) as workaround to avoid conflict between the cache manager's internal
     * sync socket and other netlink sockets on same process
     */
    struct nl_sock *tmp_socket_arr[10];
    for (int i = 0; i < 10; i++) {
        tmp_socket_arr[i] = nl_socket_alloc();
    }

    int err = nl_cache_mngr_alloc(handle, protocol, flags, &cache_mngr);

    // free the temporary sockets after cache manager was allocated and bounded the sync socket
    for (int i = 0; i < 10; i++) {
        nl_socket_free(tmp_socket_arr[i]);
    }

    BULLSEYE_EXCLUDE_BLOCK_START
    if (err) {
        nl_logerr("Fail to allocate cache manager, error=%s", nl_geterror(err));
        return NULL;
    }
    int nl_socket_fd = nl_socket_get_fd(handle);
    if (fcntl(nl_socket_fd, F_SETFD, FD_CLOEXEC) != 0) {
        nl_logwarn("Fail in fctl, error = %d", errno);
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return cache_mngr;
}

static int nl_cache_mngr_add_ext(struct nl_cache_mngr *mngr, const char *name, change_func_t cb,
                                 void *data, struct nl_cache **result)
{
    int err = nl_cache_mngr_add(mngr, name, cb, data, result);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (err) {
        errno = ELIBEXEC;
        nl_logerr("Fail to add to cache manager, error=%s", nl_geterror(err));
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    return err;
}

static void neigh_callback(nl_cache *, nl_object *obj, int, void *)
{
    netlink_wrapper::neigh_cache_callback(obj);
}

static void link_callback(nl_cache *, nl_object *obj, int, void *)
{
    netlink_wrapper::link_cache_callback(obj);
}

static void route_callback(nl_cache *, nl_object *obj, int, void *)
{
    netlink_wrapper::route_cache_callback(obj);
}

/* This function is called from internal thread only as neigh_timer_expired()
 * so it is protected by m_cache_lock call
 */
void netlink_wrapper::notify_observers(netlink_event *p_new_event, e_netlink_event_type type)
{
    g_nl_rcv_arg.netlink->m_cache_lock.unlock();
    g_nl_rcv_arg.netlink->m_subj_map_lock.lock();

    auto iter = g_nl_rcv_arg.subjects_map->find(type);
    if (iter != g_nl_rcv_arg.subjects_map->end()) {
        iter->second->notify_observers(p_new_event);
    }

    g_nl_rcv_arg.netlink->m_subj_map_lock.unlock();
    /* coverity[missing_unlock] */
    g_nl_rcv_arg.netlink->m_cache_lock.lock();
}

void netlink_wrapper::neigh_cache_callback(nl_object *obj)
{
    nl_logfine("---> neigh_cache_callback");
    struct rtnl_neigh *neigh = (struct rtnl_neigh *)obj;
    neigh_nl_event new_event(g_nl_rcv_arg.msghdr, neigh, g_nl_rcv_arg.netlink);

    nl_logdbg("notify on neigh event: %s", new_event.to_str().c_str());
    netlink_wrapper::notify_observers(&new_event, nlgrpNEIGH);

    g_nl_rcv_arg.msghdr = nullptr;
    nl_logfine("<--- neigh_cache_callback");
}

void netlink_wrapper::link_cache_callback(nl_object *obj)
{
    nl_logfine("---> link_cache_callback");
    struct rtnl_link *link = (struct rtnl_link *)obj;
    link_nl_event new_event(g_nl_rcv_arg.msghdr, link, g_nl_rcv_arg.netlink);

    nl_logdbg("notify on link event: %s", new_event.to_str().c_str());
    netlink_wrapper::notify_observers(&new_event, nlgrpLINK);

    g_nl_rcv_arg.msghdr = nullptr;
    nl_logfine("<--- link_cache_callback");
}

void netlink_wrapper::route_cache_callback(nl_object *obj)
{
    nl_logfine("---> route_cache_callback");
    struct rtnl_route *route = (struct rtnl_route *)obj;
    if (route) {
        int table_id = rtnl_route_get_table(route);
        int family = rtnl_route_get_family(route);
        if ((table_id > (int)RT_TABLE_UNSPEC) && (family == AF_INET || family == AF_INET6)) {
            route_nl_event new_event(g_nl_rcv_arg.msghdr, route, g_nl_rcv_arg.netlink);
            nl_logdbg("notify on route event: %s", new_event.to_str().c_str());
            netlink_wrapper::notify_observers(&new_event, nlgrpROUTE);
        } else {
            nl_logdbg("Received event for not handled route entry: family=%d, table_id=%d", family,
                      table_id);
        }
    } else {
        nl_logdbg("Received invalid route event");
    }
    g_nl_rcv_arg.msghdr = nullptr;
    nl_logfine("<--- route_cache_callback");
}

netlink_wrapper::netlink_wrapper()
    : m_socket_handle(nullptr)
    , m_mngr(nullptr)
    , m_cache_link(nullptr)
    , m_cache_neigh(nullptr)
    , m_cache_route(nullptr)
{
    nl_logfine("---> netlink_route_listener CTOR");
    g_nl_rcv_arg.subjects_map = &m_subjects_map;
    g_nl_rcv_arg.netlink = this;
    g_nl_rcv_arg.msghdr = nullptr;
    nl_logfine("<--- netlink_route_listener CTOR");
}

netlink_wrapper::~netlink_wrapper()
{
    nl_logfine("---> netlink_route_listener DTOR");
    /* should not call nl_cache_free() for link, neigh, route as nl_cach_mngr_free() does the
     * freeing */
    // nl_cache_free(m_cache_link);
    // nl_cache_free(m_cache_neigh);
    // nl_cache_free(m_cache_route);
    nl_cache_mngr_free(m_mngr);
    nl_socket_free(m_socket_handle);

    auto iter = m_subjects_map.begin();
    while (iter != m_subjects_map.end()) {
        delete iter->second;
        iter++;
    }
    nl_logfine("<--- netlink_route_listener DTOR");
}

int netlink_wrapper::open_channel()
{
    std::lock_guard<decltype(m_cache_lock)> lock(m_cache_lock);
    nl_logdbg("opening netlink channel");

    /*
     // build to subscriptions groups mask for indicating what type of events the kernel will send
     on channel unsigned subscriptions = ~RTMGRP_TC; if (netlink_route_group_mask & nlgrpLINK) {
     subscriptions |= (1 << (RTNLGRP_LINK - 1));
     }
     if (netlink_route_group_mask & nlgrpADDRESS) {
     if (!m_preferred_family || m_preferred_family == AF_INET)
     subscriptions |= (1 << (RTNLGRP_IPV4_IFADDR - 1));
     if (!m_preferred_family || m_preferred_family == AF_INET6)
     subscriptions |= (1 << (RTNLGRP_IPV6_IFADDR - 1));
     }
     if (netlink_route_group_mask & nlgrpROUTE) {
     if (!m_preferred_family || m_preferred_family == AF_INET)
     subscriptions |= (1 << (RTNLGRP_IPV4_ROUTE - 1));
     if (!m_preferred_family || m_preferred_family == AF_INET6)
     subscriptions |= (1 << (RTNLGRP_IPV4_ROUTE - 1));
     }
     if (netlink_route_group_mask & nlgrpPREFIX) {
     if (!m_preferred_family || m_preferred_family == AF_INET6)
     subscriptions |= (1 << (RTNLGRP_IPV6_PREFIX - 1));
     }
     if (netlink_route_group_mask & nlgrpNEIGH) {
     subscriptions |= (1 << (RTNLGRP_NEIGH - 1));
     }
     */

    // Allocate a new netlink socket/handle
    m_socket_handle = nl_socket_alloc();

    BULLSEYE_EXCLUDE_BLOCK_START
    if (m_socket_handle == NULL) {
        nl_logerr("failed to allocate netlink handle");
        return -1;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    // set internal structure to pass the handle with callbacks from netlink
    g_nl_rcv_arg.socket_handle = m_socket_handle;

    // if multiple handles being allocated then a unique netlink PID need to be provided
    // If port is 0, a unique port identifier will be generated automatically as a unique PID
    nl_socket_set_local_port(m_socket_handle, 0);

    // Disables checking of sequence numbers on the netlink handle.
    // This is required to allow messages to be processed which were not requested by a preceding
    // request message, e.g. netlink events.
    nl_socket_disable_seq_check(m_socket_handle);

    // joining group
    // nl_join_groups(m_handle, 0);

    // Allocate a new cache manager for RTNETLINK
    // NL_AUTO_PROVIDE = automatically provide the caches added to the manager.
    m_mngr = nl_cache_mngr_alloc_aligned(m_socket_handle, NETLINK_ROUTE, NL_AUTO_PROVIDE);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!m_mngr) {
        nl_logerr("Fail to allocate cache manager");
        return -1;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    nl_logdbg("netlink socket is open");

    if (nl_cache_mngr_add_ext(m_mngr, "route/link", link_callback, nullptr, &m_cache_link)) {
        return -1;
    }
    if (nl_cache_mngr_add_ext(m_mngr, "route/route", route_callback, nullptr, &m_cache_route)) {
        return -1;
    }
    if (nl_cache_mngr_add_ext(m_mngr, "route/neigh", neigh_callback, nullptr, &m_cache_neigh)) {
        return -1;
    }

    // set custom callback for every message to update message
    nl_socket_modify_cb(m_socket_handle, NL_CB_MSG_IN, NL_CB_CUSTOM, nl_msg_rcv_cb, nullptr);

    // set the socket non-blocking
    BULLSEYE_EXCLUDE_BLOCK_START
    if (nl_socket_set_nonblocking(m_socket_handle)) {
        nl_logerr("Failed to set the socket non-blocking");
        return -1;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return 0;
}

int netlink_wrapper::get_channel()
{
    std::lock_guard<decltype(m_cache_lock)> lock(m_cache_lock);
    if (m_socket_handle) {
        return nl_socket_get_fd(m_socket_handle);
    } else {
        return -1;
    }
}

int netlink_wrapper::handle_events()
{
    std::lock_guard<decltype(m_cache_lock)> lock(m_cache_lock);

    nl_logfine("--->handle_events");

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!m_socket_handle) {
        nl_logerr(
            "Cannot handle events before opening the channel. please call first open_channel()");
        return -1;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    int n = nl_cache_mngr_data_ready(m_mngr);

    // int n = nl_recvmsgs_default(m_handle);
    nl_logfine("nl_recvmsgs=%d", n);
    if (n < 0) {
        nl_logdbg("recvmsgs returned with error = %d", n);
    }

    nl_logfine("<---handle_events");

    return n;
}

bool netlink_wrapper::register_event(e_netlink_event_type type, const observer *new_obs)
{
    std::lock_guard<decltype(m_subj_map_lock)> lock(m_subj_map_lock);
    subject *sub;
    auto iter = m_subjects_map.find(type);
    if (iter == m_subjects_map.end()) {
        sub = new subject();
        m_subjects_map[type] = sub;
    } else {
        sub = m_subjects_map[type];
    }

    return sub->register_observer(new_obs);
}

bool netlink_wrapper::unregister(e_netlink_event_type type, const observer *obs)
{
    std::lock_guard<decltype(m_subj_map_lock)> lock(m_subj_map_lock);
    if (!obs) {
        return false;
    }

    auto iter = m_subjects_map.find(type);
    if (iter != m_subjects_map.end()) {
        return m_subjects_map[type]->unregister_observer(obs);
    }

    return true;
}

int netlink_wrapper::get_neigh(const char *ipaddr, int ifindex, netlink_neigh_info *new_neigh_info)
{
    std::lock_guard<decltype(m_cache_lock)> lock(m_cache_lock);
    nl_logfine("--->netlink_listener::get_neigh");
    nl_object *obj;
    rtnl_neigh *neigh;
    char addr_str[256];

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!new_neigh_info) {
        nl_logerr("Illegal argument. user pass NULL neigh_info to fill");
        return -1;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    obj = nl_cache_get_first(m_cache_neigh);
    while (obj) {
        nl_object_get(obj); // Acquire a reference on a cache object. cache won't use/free it until
                            // calling to nl_object_put(obj)
        neigh = (rtnl_neigh *)obj;
        nl_addr *addr = rtnl_neigh_get_dst(neigh);
        int index = rtnl_neigh_get_ifindex(neigh);
        if ((addr) && (index > 0)) {
            nl_addr2str(addr, addr_str, 255);
            if (!strcmp(addr_str, ipaddr) && (ifindex == index)) {
                new_neigh_info->fill(neigh);
                nl_object_put(obj);
                nl_logdbg("neigh - DST_IP:%s IF_INDEX:%d LLADDR:%s", addr_str, index,
                          new_neigh_info->lladdr_str.c_str());
                nl_logfine("<---netlink_listener::get_neigh");
                return 1;
            }
        }
        nl_object_put(obj);
        obj = nl_cache_get_next(obj);
    }

    nl_logfine("<---netlink_listener::get_neigh");
    return 0;
}

void netlink_wrapper::neigh_timer_expired()
{
    std::lock_guard<decltype(m_cache_lock)> lock(m_cache_lock);

    nl_logfine("--->netlink_wrapper::neigh_timer_expired");
    nl_cache_refill(m_socket_handle, m_cache_neigh);
    notify_neigh_cache_entries();
    nl_logfine("<---netlink_wrapper::neigh_timer_expired");
}

void netlink_wrapper::notify_neigh_cache_entries()
{
    nl_logfine("--->netlink_wrapper::notify_cache_entries");
    g_nl_rcv_arg.msghdr = nullptr;
    nl_object *obj = nl_cache_get_first(m_cache_neigh);
    while (obj) {
        nl_object_get(obj);
        neigh_cache_callback(obj);
        nl_object_put(obj);
        obj = nl_cache_get_next(obj);
    }
    nl_logfine("<---netlink_wrapper::notify_cache_entries");
}
