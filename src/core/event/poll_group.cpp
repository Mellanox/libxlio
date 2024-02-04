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

#include "config.h"
#include "poll_group.h"

#include "dev/ring.h"
#include "event/event_handler_manager_local.h"
#include "sock/sockinfo_tcp.h"

#define MODULE_NAME "group:"

#define grp_logpanic __log_panic
#define grp_logerr   __log_err
#define grp_logwarn  __log_warn
#define grp_loginfo  __log_info
#define grp_logdbg   __log_dbg

poll_group::poll_group(const struct xlio_poll_group_attr *attr)
    : m_socket_event_cb(attr->socket_event_cb)
    , m_socket_comp_cb(attr->socket_comp_cb)
    , m_socket_rx_cb(attr->socket_rx_cb)
    , m_group_flags(attr->flags)
{
    /*
     * In the best case, we expect a single ring per group. Reserve two elements for a scenario
     * with two network interfaces and when the both interfaces are used by the sockets.
     * More complex scenarios will be covered with re-allocation.
     */
    m_rings.reserve(2);

    m_event_handler = std::make_unique<event_handler_manager_local>();
    m_tcp_timers = std::make_unique<tcp_timers_collection>(
        safe_mce_sys().tcp_timer_resolution_msec, safe_mce_sys().tcp_timer_resolution_msec);
    m_tcp_timers->set_group(this);
}

poll_group::~poll_group()
{
}

void poll_group::poll()
{
    for (ring *rng : m_rings) {
        uint64_t sn;
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

void poll_group::add_ring(ring *rng)
{
    if (std::find(m_rings.begin(), m_rings.end(), rng) == std::end(m_rings)) {
        grp_logdbg("New ring %p in group %p", rng, this);
        if (rng->get_group()) {
            grp_logwarn("Ring belongs to a group %p (current group %p)", rng->get_group(), this);
        }
        rng->set_group(this);
        m_rings.push_back(rng);
        // TODO Increase ref count for the ring and keep it until the group is destroyed.
        // In this way we don't have to implement del_ring() and there won't be a race between
        // socket destruction and xlio_group_buf_free().
    }
}

void poll_group::del_ring(ring *rng)
{
    auto iter = std::find(m_rings.begin(), m_rings.end(), rng);
    if (iter != std::end(m_rings)) {
        grp_logdbg("Removed ring %p from group %p", rng, this);
        m_rings.erase(iter);
    }
}
