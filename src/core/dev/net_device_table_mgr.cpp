/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <list>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <sys/epoll.h>
#include <algorithm>

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "event/netlink_event.h"
#include "event/event_handler_manager.h"
#include "util/vtypes.h"
#include "util/utils.h"
#include "util/valgrind.h"
#include "sock/sock-redirect.h"
#include "sock/fd_collection.h"
#include "dev/ring.h"
#include "net_device_table_mgr.h"

#include "ib_ctx_handler_collection.h"

#define MODULE_NAME "ndtm"

#define ndtm_logpanic   __log_panic
#define ndtm_logerr     __log_err
#define ndtm_logwarn    __log_warn
#define ndtm_loginfo    __log_info
#define ndtm_logdbg     __log_info_dbg
#define ndtm_logfunc    __log_info_func
#define ndtm_logfuncall __log_info_funcall

net_device_table_mgr *g_p_net_device_table_mgr = nullptr;

enum net_device_table_mgr_timers { RING_PROGRESS_ENGINE_TIMER, RING_ADAPT_CQ_MODERATION_TIMER };

net_device_table_mgr::net_device_table_mgr()
    : cache_table_mgr<int, net_device_val *>("net_device_table_mgr")
    , m_lock("net_device_table_mgr")
    , m_time_conversion_mode(TS_CONVERSION_MODE_DISABLE)
{
    m_num_devices = 0;
    m_global_ring_epfd = 0;
    m_max_mtu = 0;

    ndtm_logdbg("");

    m_global_ring_epfd = SYSCALL(epoll_create, 48);

    BULLSEYE_EXCLUDE_BLOCK_START
    if (m_global_ring_epfd == -1) {
        ndtm_logerr("epoll_create failed. (errno=%d %m)", errno);
        free_ndtm_resources();
        throw_xlio_exception("epoll_create failed");
    }

    if (SYSCALL(pipe, m_global_ring_pipe_fds)) {
        ndtm_logerr("pipe create failed. (errno=%d %m)", errno);
        free_ndtm_resources();
        throw_xlio_exception("pipe create failed");
    }
    if (SYSCALL(write, m_global_ring_pipe_fds[1], "#", 1) != 1) {
        ndtm_logerr("pipe write failed. (errno=%d %m)", errno);
        free_ndtm_resources();
        throw_xlio_exception("pipe write failed");
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    /* Read Link table from kernel and save it in local variable. */
    update_tbl();

    /* throw exception if there are no supported devices. */
    if (m_net_device_map_index.empty()) {
        int num_devices = 0;
        struct ibv_device **dev_list = nullptr;
        dev_list = xlio_ibv_get_device_list(&num_devices);
        if (dev_list && num_devices == 0) {
            ibv_free_device_list(dev_list);
            ndtm_logdbg("net_device_map is empty %d", num_devices);
            free_ndtm_resources();
            throw_xlio_exception("net_device_map is empty");
        }
    }

    // Print table
    print_val_tbl();

    // Calculate and update time conversion mode
    m_time_conversion_mode =
        time_converter::update_device_converters_status(m_net_device_map_index);

    // register to netlink event
    g_p_netlink_handler->register_event(nlgrpLINK, this);
    ndtm_logdbg("Registered to g_p_netlink_handler");

#ifndef DEFINED_NO_THREAD_LOCK
    if (safe_mce_sys().progress_engine_interval_msec != MCE_CQ_DRAIN_INTERVAL_DISABLED &&
        safe_mce_sys().progress_engine_wce_max != 0) {
        ndtm_logdbg("registering timer for ring draining with %d msec intervales",
                    safe_mce_sys().progress_engine_interval_msec);
        g_p_event_handler_manager->register_timer_event(
            safe_mce_sys().progress_engine_interval_msec, this, PERIODIC_TIMER,
            (void *)RING_PROGRESS_ENGINE_TIMER);
    }

    if (safe_mce_sys().cq_aim_interval_msec != MCE_CQ_ADAPTIVE_MODERATION_DISABLED) {
        ndtm_logdbg("registering timer for cq adaptive moderation with %d msec intervales",
                    safe_mce_sys().cq_aim_interval_msec);
        g_p_event_handler_manager->register_timer_event(safe_mce_sys().cq_aim_interval_msec, this,
                                                        PERIODIC_TIMER,
                                                        (void *)RING_ADAPT_CQ_MODERATION_TIMER);
    }
#endif // DEFINED_NO_THREAD_LOCK

    ndtm_logdbg("Done");
}

void net_device_table_mgr::free_ndtm_resources()
{
    m_lock.lock();

    if (m_global_ring_epfd > 0) {
        SYSCALL(close, m_global_ring_epfd);
        m_global_ring_epfd = 0;
    }

    SYSCALL(close, m_global_ring_pipe_fds[1]);
    SYSCALL(close, m_global_ring_pipe_fds[0]);

    net_device_map_index_t::iterator itr;
    while ((itr = m_net_device_map_index.begin()) != m_net_device_map_index.end()) {
        delete itr->second;
        m_net_device_map_index.erase(itr);
    }
    m_net_device_map_addr_v4.clear();
    m_net_device_map_addr_v6.clear();

    m_lock.unlock();
}

net_device_table_mgr::~net_device_table_mgr()
{
    ndtm_logdbg("");
    free_ndtm_resources();
    ndtm_logdbg("Done");
}

void net_device_table_mgr::update_tbl()
{
    int rc = 0;
    int fd = -1;
    struct {
        struct nlmsghdr hdr;
        struct ifinfomsg infomsg;
    } nl_req;
    struct nlmsghdr *nl_msg;
    int nl_msglen = 0;
    char nl_res[8096];
    static int _seq = 0;
    net_device_val *p_net_device_val;

    /* Track ips assigned to multiple-interfaces */
    std::set<std::string> duplicate_ips;

    /* Set up the netlink socket */
    fd = SYSCALL(socket, AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        ndtm_logerr("netlink socket() creation");
        return;
    }

    ndtm_logdbg("Checking for offload capable network interfaces...");

    /* Prepare RTM_GETLINK request */
    memset(&nl_req, 0, sizeof(nl_req));
    nl_req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    nl_req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nl_req.hdr.nlmsg_type = RTM_GETLINK;
    nl_req.hdr.nlmsg_seq = _seq++;
    nl_req.hdr.nlmsg_pid = getpid();
    nl_req.infomsg.ifi_family = AF_UNSPEC;
    nl_req.infomsg.ifi_change = 0xffffffff;

    /* Send the netlink request */
    rc = SYSCALL(send, fd, &nl_req, nl_req.hdr.nlmsg_len, 0);
    if (rc < 0) {
        ndtm_logerr("netlink send() operation");
        goto ret;
    }

    m_lock.lock();

    do {
        /* Receive the netlink reply */
        rc = SYSCALL(recv, fd, nl_res, sizeof(nl_res), 0);
        if (rc < 0) {
            ndtm_logerr("netlink recv() operation");
            goto ret;
        }

        nl_msg = (struct nlmsghdr *)nl_res;
        nl_msglen = rc;
        while (NLMSG_OK(nl_msg, (size_t)nl_msglen) && (nl_msg->nlmsg_type != NLMSG_ERROR)) {
            struct ifinfomsg *nl_msgdata;

            nl_msgdata = (struct ifinfomsg *)NLMSG_DATA(nl_msg);

            /* Skip existing interfaces */
            if (m_net_device_map_index.find(nl_msgdata->ifi_index) !=
                m_net_device_map_index.end()) {
                goto next;
            }

            /* Skip some types */
            if (!(nl_msgdata->ifi_flags & IFF_SLAVE)) {
                struct net_device_val::net_device_val_desc desc = {nl_msg};
                /* Add new interfaces */
                switch (nl_msgdata->ifi_type) {
                case ARPHRD_ETHER:
                    p_net_device_val = new net_device_val_eth(&desc);
                    break;
                default:
                    goto next;
                }
                BULLSEYE_EXCLUDE_BLOCK_START
                if (!p_net_device_val) {
                    ndtm_logerr("failed allocating new net_device (errno=%d %m)", errno);
                    goto next;
                }
                if (p_net_device_val->get_state() == net_device_val::INVALID) {
                    delete p_net_device_val;
                    goto next;
                }

                BULLSEYE_EXCLUDE_BLOCK_END
                if ((int)get_max_mtu() < p_net_device_val->get_mtu()) {
                    set_max_mtu(p_net_device_val->get_mtu());
                }
                auto handle_ip_insertion = [&p_net_device_val, &duplicate_ips](
                                               const std::unique_ptr<ip_data> &ip,
                                               net_device_map_addr &net_device_map,
                                               sa_family_t family) {
                    auto it = net_device_map.find(ip->local_addr);
                    if (it != net_device_map.end()) {
                        duplicate_ips.insert(ip->local_addr.to_str(family));
                    }
                    if (it == net_device_map.end() ||
                        p_net_device_val->get_state() != net_device_val::DOWN) {
                        net_device_map[ip->local_addr] = p_net_device_val;
                    }
                };

                const ip_data_vector_t &ipvec_v4 = p_net_device_val->get_ip_array(AF_INET);
                std::for_each(ipvec_v4.begin(), ipvec_v4.end(),
                              [this, &handle_ip_insertion](const std::unique_ptr<ip_data> &ip) {
                                  handle_ip_insertion(ip, m_net_device_map_addr_v4, AF_INET);
                              });

                const ip_data_vector_t &ipvec_v6 = p_net_device_val->get_ip_array(AF_INET6);
                std::for_each(ipvec_v6.begin(), ipvec_v6.end(),
                              [this, &handle_ip_insertion](const std::unique_ptr<ip_data> &ip) {
                                  handle_ip_insertion(ip, m_net_device_map_addr_v6, AF_INET6);
                              });
                m_net_device_map_index[p_net_device_val->get_if_idx()] = p_net_device_val;
            }

        next:

            /* Check if it is the last message */
            if (nl_msg->nlmsg_type == NLMSG_DONE) {
                goto ret;
            }
            nl_msg = NLMSG_NEXT(nl_msg, nl_msglen);
        }
    } while (1);

ret:

    m_lock.unlock();

    ndtm_logdbg("Check completed. Found %ld offload capable network interfaces",
                m_net_device_map_index.size());
    for (const auto &ip : duplicate_ips) {
        vlog_printf(VLOG_WARNING,
                    "Duplicate IP address %s detected on multiple interfaces. XLIO will work with "
                    "a single interface.\n",
                    ip.c_str());
    }
    SYSCALL(close, fd);
}

void net_device_table_mgr::print_val_tbl()
{
    net_device_map_index_t::iterator itr;
    for (itr = m_net_device_map_index.begin(); itr != m_net_device_map_index.end(); itr++) {
        net_device_val *p_ndev = dynamic_cast<net_device_val *>(itr->second);
        if (p_ndev) {
            p_ndev->print_val();
        }
    }
}

net_device_val *net_device_table_mgr::get_net_device_val(const ip_addr &if_addr)
{
    std::lock_guard<decltype(m_lock)> lock(m_lock);

    net_device_map_addr &net_device_map =
        (if_addr.get_family() == AF_INET ? m_net_device_map_addr_v4 : m_net_device_map_addr_v6);

    net_device_map_addr::iterator iter = net_device_map.find(if_addr);
    if (iter != net_device_map.end()) {
        net_device_val *net_dev = iter->second;
        ndtm_logdbg("Found %s for addr: %s", net_dev->to_str().c_str(), if_addr.to_str().c_str());
        if (net_dev->get_state() == net_device_val::INVALID) {
            ndtm_logdbg("invalid net_device %s", net_dev->to_str().c_str());
            return nullptr;
        }
        return iter->second;
    }
    ndtm_logdbg("Can't find net_device for addr: %s", if_addr.to_str().c_str());
    return nullptr;
}

net_device_val *net_device_table_mgr::get_net_device_val(int if_index)
{
    net_device_map_index_t::iterator iter;
    net_device_val *net_dev = nullptr;

    std::lock_guard<decltype(m_lock)> lock(m_lock);

    /* Find master interface */
    for (iter = m_net_device_map_index.begin(); iter != m_net_device_map_index.end(); iter++) {
        net_dev = iter->second;
        /* Check if interface is master */
        if (if_index == net_dev->get_if_idx()) {
            goto out;
        }
        /* Check if interface is slave */
        const slave_data_vector_t &slaves = net_dev->get_slave_array();
        for (size_t i = 0; i < slaves.size(); i++) {
            if (if_index == slaves[i]->if_index) {
                goto out;
            }
        }
        /* Check if interface is new netvsc slave */
        if (net_dev->get_is_bond() == net_device_val::NETVSC) {
            char if_name[IFNAMSIZ] = {0};
            char sys_path[256] = {0};
            int ret = 0;
            if (if_indextoname(if_index, if_name)) {
                ret = snprintf(sys_path, sizeof(sys_path), NETVSC_DEVICE_UPPER_FILE, if_name,
                               net_dev->get_ifname());
                if (ret > 0 && (size_t)ret < sizeof(sys_path)) {
                    ret = errno; /* to suppress errno */
                    int fd = SYSCALL(open, sys_path, O_RDONLY);
                    if (fd >= 0) {
                        SYSCALL(close, fd);
                        goto out;
                    }
                    errno = ret;
                }
            }
        }
    }

    ndtm_logdbg("Can't find net_device for index: %d", if_index);
    return nullptr;

out:

    ndtm_logdbg("Found %s for index: %d", net_dev->to_str().c_str(), if_index);
    if (net_dev->get_state() == net_device_val::INVALID) {
        ndtm_logdbg("invalid net_device %s", net_dev->to_str().c_str());
        return nullptr;
    }
    return net_dev;
}

net_device_entry *net_device_table_mgr::create_new_entry(int if_index, const observer *obs)
{
    ndtm_logdbg("");
    NOT_IN_USE(obs);

    net_device_val *p_ndv = get_net_device_val(if_index);

    if (p_ndv) {
        return new net_device_entry(if_index, p_ndv);
    }
    return nullptr;
}

void net_device_table_mgr::get_ip_list(local_ip_list_t &ip_list, sa_family_t family, int if_index)
{
    m_lock.lock();

    net_device_map_index_t::iterator iter =
        (if_index > 0 ? m_net_device_map_index.find(if_index) : m_net_device_map_index.begin());

    for (; iter != m_net_device_map_index.end(); iter++) {
        net_device_val *p_ndev = iter->second;
        const ip_data_vector_t &ip = p_ndev->get_ip_array(family);
        for (size_t i = 0; i < ip.size(); i++) {
            ip_list.emplace_back(*ip[i].get());
        }
        if (if_index > 0) {
            break;
        }
    }

    m_lock.unlock();
}

bool net_device_table_mgr::global_ring_poll_and_process_element(uint64_t *p_poll_sn_rx,
                                                                uint64_t *p_poll_sn_tx,
                                                                void *pv_fd_ready_array /*= NULL*/)
{
    ndtm_logfunc("");
    bool all_drained = true;

    net_device_map_index_t::iterator net_dev_iter;
    for (net_dev_iter = m_net_device_map_index.begin();
         net_dev_iter != m_net_device_map_index.end(); net_dev_iter++) {
        all_drained &= net_dev_iter->second->global_ring_poll_and_process_element(
            p_poll_sn_rx, p_poll_sn_tx, pv_fd_ready_array);
    }

    return all_drained;
}

int net_device_table_mgr::global_ring_request_notification(uint64_t poll_sn_rx, uint64_t poll_sn_tx)
{
    ndtm_logfunc("");
    int ret_total = 0;
    net_device_map_index_t::iterator net_dev_iter;
    for (net_dev_iter = m_net_device_map_index.begin();
         m_net_device_map_index.end() != net_dev_iter; net_dev_iter++) {
        int ret = net_dev_iter->second->global_ring_request_notification(poll_sn_rx, poll_sn_tx);
        BULLSEYE_EXCLUDE_BLOCK_START
        if (ret < 0) {
            ndtm_logerr("Error in net_device_val[%p]->request_notification() (errno=%d %m)",
                        net_dev_iter->second, errno);
            return ret;
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        ret_total += ret;
    }
    return ret_total;
}

int net_device_table_mgr::global_ring_epfd_get()
{
    return m_global_ring_epfd;
}

void net_device_table_mgr::global_ring_wait_for_notification_and_process_element(
    uint64_t *p_poll_sn, void *pv_fd_ready_array /*=NULL*/)
{
    ndtm_logfunc("");
    int max_fd = 16;
    struct epoll_event events[max_fd];

    int res = SYSCALL(epoll_wait, global_ring_epfd_get(), events, max_fd, 0);
    if (res > 0) {
        for (int event_idx = 0; event_idx < res; ++event_idx) {
            int fd = events[event_idx].data.fd; // This is the Rx cq channel fd
            assert(g_p_fd_collection);
            cq_channel_info *p_cq_ch_info = g_p_fd_collection->get_cq_channel_fd(fd);
            if (p_cq_ch_info) {
                ring *p_ready_ring = p_cq_ch_info->get_ring();
                // Handle the CQ notification channel
                p_ready_ring->wait_for_notification_and_process_element(p_poll_sn,
                                                                        pv_fd_ready_array);
            } else {
                ndtm_logdbg("removing wakeup fd from epfd");
                BULLSEYE_EXCLUDE_BLOCK_START
                if ((SYSCALL(epoll_ctl, m_global_ring_epfd, EPOLL_CTL_DEL,
                             m_global_ring_pipe_fds[0], nullptr)) &&
                    (!(errno == ENOENT || errno == EBADF))) {
                    ndtm_logerr("failed to del pipe channel fd from internal epfd (errno=%d %m)",
                                errno);
                }
                BULLSEYE_EXCLUDE_BLOCK_END
            }
        }
    }
}

int net_device_table_mgr::global_ring_drain_and_procces()
{
    ndtm_logfuncall("");
    int ret_total = 0;

    net_device_map_index_t::iterator net_dev_iter;
    for (net_dev_iter = m_net_device_map_index.begin();
         m_net_device_map_index.end() != net_dev_iter; net_dev_iter++) {
        int ret = net_dev_iter->second->ring_drain_and_proccess();
        if (ret < 0 && errno != EAGAIN) {
            ndtm_logerr("Error in ring[%p]->drain() (errno=%d %m)", net_dev_iter->second, errno);
            return ret;
        }
        ret_total += ret;
    }
    if (ret_total) {
        ndtm_logfunc("ret_total=%d", ret_total);
    } else {
        ndtm_logfuncall("ret_total=%d", ret_total);
    }
    return ret_total;
}

void net_device_table_mgr::global_ring_adapt_cq_moderation()
{
    ndtm_logfuncall("");

    net_device_map_index_t::iterator net_dev_iter;
    for (net_dev_iter = m_net_device_map_index.begin();
         m_net_device_map_index.end() != net_dev_iter; net_dev_iter++) {
        net_dev_iter->second->ring_adapt_cq_moderation();
    }
}

void net_device_table_mgr::handle_timer_expired(void *user_data)
{
    int timer_type = (uint64_t)user_data;
    switch (timer_type) {
    case RING_PROGRESS_ENGINE_TIMER:
        global_ring_drain_and_procces();
        break;
    case RING_ADAPT_CQ_MODERATION_TIMER:
        global_ring_adapt_cq_moderation();
        break;
    default:
        ndtm_logerr("unrecognized timer %d", timer_type);
    }
}

void net_device_table_mgr::global_ring_wakeup()
{
    ndtm_logdbg("");
    epoll_event ev = {0, {nullptr}};

    ev.events = EPOLLIN;
    ev.data.ptr = nullptr;
    int errno_tmp = errno; // don't let wakeup affect errno, as this can fail with EEXIST
    BULLSEYE_EXCLUDE_BLOCK_START
    if ((SYSCALL(epoll_ctl, m_global_ring_epfd, EPOLL_CTL_ADD, m_global_ring_pipe_fds[0], &ev)) &&
        (errno != EEXIST)) {
        ndtm_logerr("failed to add pipe channel fd to internal epfd (errno=%d %m)", errno);
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    errno = errno_tmp;
}

void net_device_table_mgr::get_net_devices(local_dev_vector &vec)
{
    std::lock_guard<decltype(m_lock)> lock(m_lock);
    vec.reserve(vec.size() + m_net_device_map_index.size());
    for (auto iter : m_net_device_map_index) {
        vec.emplace_back(*iter.second);
    }
}

void net_device_table_mgr::del_link_event(const netlink_link_info *info)
{
    ndtm_logdbg("netlink event: RTM_DELLINK if_index: %d", info->ifindex);

    /* This flow is actual when interface is removed quickly
     * w/o moving it in DOWN state.
     * Usually interface is removed during sequence of RTM_NEWLINK events
     * that puts it in DOWN state. In this case XLIO has more time to release
     * resources correctly.
     */
    if (info->flags & IFF_SLAVE) {
        net_device_val *net_dev = nullptr;
        int if_index = info->ifindex;

        ndtm_logdbg("netlink event: if_index: %d state: %s", info->ifindex,
                    (info->flags & IFF_RUNNING ? "Up" : "Down"));

        net_dev = get_net_device_val(if_index);
        if (net_dev && (if_index != net_dev->get_if_idx()) &&
            (net_dev->get_is_bond() == net_device_val::NETVSC) && (net_dev->get_slave(if_index))) {
            ndtm_logdbg("found entry [%p]: if_index: %d : %s", net_dev, net_dev->get_if_idx(),
                        net_dev->get_ifname());
            net_dev->update_netvsc_slaves(info->ifindex, info->flags);
        }
    }
}

void net_device_table_mgr::new_link_event(const netlink_link_info *info)
{
    ndtm_logdbg("netlink event: RTM_NEWLINK if_index: %d", info->ifindex);

    /* This flow is used to process interface UP and DOWN scenarios.
     * It is important that interface can be removed w/o putting it into
     * DOWN state (see RTM_DELLINK).
     */
    if (info->flags & IFF_SLAVE) {
        net_device_val *net_dev = nullptr;
        int if_index = info->ifindex;

        ndtm_logdbg("netlink event: if_index: %d state: %s", info->ifindex,
                    (info->flags & IFF_RUNNING ? "Up" : "Down"));

        net_dev = get_net_device_val(if_index);
        if (net_dev && (if_index != net_dev->get_if_idx()) &&
            (net_dev->get_is_bond() == net_device_val::NETVSC) &&
            ((net_dev->get_slave(if_index) && !(info->flags & IFF_RUNNING)) ||
             (!net_dev->get_slave(if_index) && (info->flags & IFF_RUNNING)))) {
            ndtm_logdbg("found entry [%p]: if_index: %d : %s", net_dev, net_dev->get_if_idx(),
                        net_dev->get_ifname());
            net_dev->update_netvsc_slaves(info->ifindex, info->flags);
        }
    }
}

void net_device_table_mgr::notify_cb(event *ev)
{
    ndtm_logdbg("netlink event: LINK");

    link_nl_event *link_netlink_ev = dynamic_cast<link_nl_event *>(ev);
    if (!link_netlink_ev) {
        ndtm_logwarn("netlink event: invalid!!!");
        return;
    }

    const netlink_link_info *p_netlink_link_info = link_netlink_ev->get_link_info();
    if (!p_netlink_link_info) {
        ndtm_logwarn("netlink event: invalid!!!");
        return;
    }

    switch (link_netlink_ev->nl_type) {
    case RTM_NEWLINK:
        new_link_event(p_netlink_link_info);
        break;
    case RTM_DELLINK:
        del_link_event(p_netlink_link_info);
        break;
    default:
        ndtm_logdbg("netlink event: (%u) is not handled", link_netlink_ev->nl_type);
        break;
    }
}
