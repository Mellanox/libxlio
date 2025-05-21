/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2024-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "config.h"
#include "poll_group.h"

#include "dev/net_device_table_mgr.h"
#include "dev/net_device_val.h"
#include "dev/ring.h"
#include "event/event_handler_manager_local.h"
#include "sock/sockinfo_tcp.h"

#define MODULE_NAME "group:"

#define grp_logpanic __log_panic
#define grp_logerr   __log_err
#define grp_logwarn  __log_warn
#define grp_loginfo  __log_info
#define grp_logdbg   __log_dbg

/*
 * Collection of the groups to destroy leftovers in the library destructor.
 * Groups are likely pre-initialized in a small number (up to the number of CPU cores)
 * and destroyed at exit. Therefore, a simple collection data structure is enough.
 */
static std::vector<poll_group *> s_poll_groups;
static lock_spin s_poll_groups_lock;

poll_group::poll_group(const struct xlio_poll_group_attr *attr)
    : m_socket_event_cb(attr->socket_event_cb)
    , m_socket_comp_cb(attr->socket_comp_cb)
    , m_socket_rx_cb(attr->socket_rx_cb)
    , m_socket_accept_cb(attr->socket_accept_cb)
    , m_group_flags(attr->flags)
{
    /*
     * In the best case, we expect a single ring per group. Reserve two elements for a scenario
     * with two network interfaces and when the both interfaces are used by the sockets.
     * More complex scenarios will be covered with re-allocation.
     */
    m_rings.reserve(2);

    m_event_handler = std::make_unique<event_handler_manager_local>();
    m_tcp_timers = std::make_unique<tcp_timers_collection>(1U);
    m_tcp_timers->set_group(this);

    s_poll_groups_lock.lock();
    s_poll_groups.push_back(this);
    s_poll_groups_lock.unlock();

    grp_logdbg("Polling group %p created", this);
}

poll_group::~poll_group()
{
    s_poll_groups_lock.lock();
    auto iter = std::find(s_poll_groups.begin(), s_poll_groups.end(), this);
    if (iter != std::end(s_poll_groups)) {
        s_poll_groups.erase(iter);
    }
    s_poll_groups_lock.unlock();

    while (!m_sockets_list.empty()) {
        sockinfo_tcp *si = dynamic_cast<sockinfo_tcp *>(m_sockets_list.front());
        if (likely(si)) {
            close_socket(si, true);
        }
    }

    // Release references to the rings that we take in add_ring()
    for (auto &item : m_rings_ref) {
        item.second->release_ring(item.first.get());
    }
    m_rings_ref.clear();

    grp_logdbg("Polling group %p destroyed", this);
}

/*static*/
void poll_group::destroy_all_groups()
{
    s_poll_groups_lock.lock();
    std::vector<poll_group *> groups(std::move(s_poll_groups));
    s_poll_groups_lock.unlock();
    for (poll_group *grp : groups) {
        delete grp;
    }
}

int poll_group::update(const struct xlio_poll_group_attr *attr)
{
    if (m_group_flags != attr->flags) {
        // Runtime flags change is not supported for now.
        errno = EINVAL;
        return -1;
    }

    m_socket_event_cb = attr->socket_event_cb;
    m_socket_comp_cb = attr->socket_comp_cb;
    m_socket_rx_cb = attr->socket_rx_cb;

    return 0;
}

void poll_group::poll()
{
    for (ring *rng : m_rings) {
        uint64_t sn = 0;
        rng->poll_and_process_element_tx(&sn);
        sn = 0;
        rng->poll_and_process_element_rx(&sn);
    }
    m_event_handler->do_tasks();
}

void poll_group::add_dirty_socket(sockinfo_tcp *si)
{
    if (m_group_flags & XLIO_GROUP_FLAG_DIRTY) {
        m_dirty_sockets.push_back(si);
    }
}

void poll_group::flush()
{
    for (auto si : m_dirty_sockets) {
        si->flush();
    }
    m_dirty_sockets.clear();
    // TODO Ring doorbell and request TX completion.
}

void poll_group::add_ring(ring *rng, ring_alloc_logic_attr *attr)
{
    if (std::find(m_rings.begin(), m_rings.end(), rng) == std::end(m_rings)) {
        grp_logdbg("New ring %p in group %p", rng, this);
        m_rings.push_back(rng);
        rng->set_poll_group(this);

        /*
         * Take reference to the ring. This avoids a race between socket destruction and buffer
         * return to the group. Socket destruction can lead to the ring destruction. But user
         * may return a buffer outside of the socket lifecycle.
         * This also avoids extra ring destruction in a scenario when application closes all
         * the sockets multiple times in runtime.
         */
        net_device_val *nd = g_p_net_device_table_mgr->get_net_device_val(rng->get_if_index());
        if (nd) {
            ring *reserved = nd->reserve_ring(attr);
            if (reserved != rng) {
                grp_logerr("Cannot reserve ring %p (reserved=%p)", rng, reserved);
                if (reserved) {
                    nd->release_ring(attr);
                }
            } else {
                m_rings_ref.push_back(
                    std::make_pair(std::make_unique<ring_alloc_logic_attr>(*attr), nd));
            }
        }
    }
}

void poll_group::add_socket(sockinfo_tcp *si)
{
    m_sockets_list.push_back(si);
    // For the flow_tag fast path support.
    g_p_fd_collection->set_socket(si->get_fd(), si);
}

void poll_group::remove_socket(sockinfo_tcp *si)
{
    g_p_fd_collection->clear_socket(si->get_fd());
    m_sockets_list.erase(si);

    auto iter = std::find(m_dirty_sockets.begin(), m_dirty_sockets.end(), si);
    if (iter != std::end(m_dirty_sockets)) {
        m_dirty_sockets.erase(iter);
    }
}

void poll_group::close_socket(sockinfo_tcp *si, bool force /*=false*/)
{
    remove_socket(si);

    bool closed = si->prepare_to_close(force);
    if (closed) {
        /*
         * Current implementation forces TCP reset, so the socket is expected to be closable.
         * Do a polling iteration to increase the chance that all the relevant WQEs are completed
         * and XLIO emitted all the TX completion before the XLIO_SOCKET_EVENT_TERMINATED event.
         *
         * TODO Implement more reliable mechanism of deferred socket destruction if there are
         * not completed TX operations.
         */
        poll();
        si->clean_socket_obj();
    }
}
