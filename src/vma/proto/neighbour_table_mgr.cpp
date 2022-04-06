/*
 * Copyright (c) 2001-2022 Mellanox Technologies, Ltd. All rights reserved.
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

#include <arpa/inet.h>
#include <linux/rtnetlink.h>

#include "utils/bullseye.h"
#include "vma/netlink/netlink_wrapper.h"
#include "vma/event/netlink_event.h"
#include "vma/proto/neighbour_table_mgr.h"

#include "vma/proto/neighbour_observer.h"
#include "vma/dev/net_device_table_mgr.h"

#define MODULE_NAME "ntm:"

#define neigh_mgr_logpanic   __log_panic
#define neigh_mgr_logerr     __log_err
#define neigh_mgr_logwarn    __log_warn
#define neigh_mgr_loginfo    __log_info
#define neigh_mgr_logdbg     __log_dbg
#define neigh_mgr_logfunc    __log_func
#define neigh_mgr_logfuncall __log_funcall

neigh_table_mgr *g_p_neigh_table_mgr = NULL;

#define DEFAULT_GARBAGE_COLLECTOR_TIME 100000

neigh_table_mgr::neigh_table_mgr()
{
    // Creating cma_event_channel

    create_rdma_channel();
    start_garbage_collector(DEFAULT_GARBAGE_COLLECTOR_TIME);
}

void neigh_table_mgr::create_rdma_channel()
{
    m_neigh_cma_event_channel = rdma_create_event_channel();
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!m_neigh_cma_event_channel) {
        neigh_mgr_logdbg("Failed to create neigh_cma_event_channel (errno=%d %m)", errno);
    } else {
        neigh_mgr_logdbg("Creation of neigh_cma_event_channel on fd=%d",
                         m_neigh_cma_event_channel->fd);
    }
    BULLSEYE_EXCLUDE_BLOCK_END
}

neigh_table_mgr::~neigh_table_mgr()
{
    stop_garbage_collector();
    if (m_neigh_cma_event_channel) {
        rdma_destroy_event_channel(m_neigh_cma_event_channel);
    }
    if (m_neigh_cma_event_channel_prev) {
        rdma_destroy_event_channel(m_neigh_cma_event_channel_prev);
    }
}

bool neigh_table_mgr::register_observer(
    neigh_key key, const cache_observer *new_observer,
    cache_entry_subject<neigh_key, class neigh_val *> **cache_entry)
{
    // Register to netlink event handler only if this is the first entry
    if (get_cache_tbl_size() == 0) {
        g_p_netlink_handler->register_event(nlgrpNEIGH, this);
        neigh_mgr_logdbg("Registered to g_p_netlink_handler");
    }
    return cache_table_mgr<neigh_key, class neigh_val *>::register_observer(key, new_observer,
                                                                            cache_entry);
}

neigh_entry *neigh_table_mgr::create_new_entry(neigh_key neigh_key, const observer *new_observer)
{
    observer *tmp = const_cast<observer *>(new_observer);
    const neigh_observer *dst = dynamic_cast<const neigh_observer *>(tmp);

    BULLSEYE_EXCLUDE_BLOCK_START
    if (dst == NULL) {
        // TODO: Need to add handling of this case
        neigh_mgr_logpanic("dynamic_casr failed, new_observer type is not neigh_observer");
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    transport_type_t transport = dst->get_obs_transport_type();

    if (transport == VMA_TRANSPORT_ETH) {
        neigh_mgr_logdbg("Creating new neigh_eth");
        return (new neigh_eth(neigh_key));
    } else {
        neigh_mgr_logdbg("Cannot create new entry, transport type is UNKNOWN");
        return NULL;
    }
}

void neigh_table_mgr::notify_cb(event *ev)
{
    neigh_mgr_logdbg("");
    // Got event from netlink

    neigh_nl_event *nl_ev = dynamic_cast<neigh_nl_event *>(ev);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (nl_ev == NULL) {
        neigh_mgr_logdbg("Non neigh_nl_event type");
        return;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    const netlink_neigh_info *nl_info = nl_ev->get_neigh_info();
    struct in6_addr in;
    if (1 != inet_pton(nl_info->addr_family, nl_info->dst_addr_str.c_str(), &in)) {
        neigh_mgr_logdbg("Ignoring netlink neigh event neigh for IP = %s, not a valid IP",
                         nl_info->dst_addr_str.c_str());
        return;
    }

    ip_addr addr(ip_address(reinterpret_cast<void *>(&in), nl_info->addr_family),
                 nl_info->addr_family);

    // Search for this neigh ip in cache_table
    m_lock.lock();
    net_device_val *p_ndev = g_p_net_device_table_mgr->get_net_device_val(nl_info->ifindex);

    // find all neigh entries with an appropriate peer_ip and net_device
    if (p_ndev) {
        neigh_entry *p_ne = dynamic_cast<neigh_entry *>(get_entry(neigh_key(addr, p_ndev)));
        if (p_ne) {
            // Call the relevant neigh_entry to handle the event
            p_ne->handle_neigh_event(nl_ev);
        } else {
            neigh_mgr_logdbg("Ignoring netlink neigh event for IP = %s if:%s, index=%d, p_ndev=%p",
                             nl_info->dst_addr_str.c_str(), p_ndev->to_str().c_str(),
                             nl_info->ifindex, p_ndev);
        }
    } else {
        neigh_mgr_logdbg("could not find ndv_val for ifindex=%d", nl_info->ifindex);
    }
    m_lock.unlock();

    return;
}

int neigh_table_mgr::create_rdma_id_and_register(rdma_cm_id *&cma_id,
                                                 enum rdma_port_space port_space,
                                                 event_handler_rdma_cm *context)
{
#define CHANNEL_LOCK(func)                                                                         \
    do {                                                                                           \
        if (0 != m_channel_lock.func()) {                                                          \
            neigh_mgr_logerr("Unable to " #func " m_channel_lock, errno=%d", errno);               \
            return -1;                                                                             \
        }                                                                                          \
    } while (0)

    int ch_fd = -1;

    if (!g_p_neigh_table_mgr->m_neigh_cma_event_channel) {
        return 0;
    }

    CHANNEL_LOCK(lock_rd);

    neigh_mgr_logdbg("Calling rdma_create_id. tid: %d", gettid());
    do {
        IF_RDMACM_FAILURE(rdma_create_id(m_neigh_cma_event_channel, &cma_id, context, port_space))
        {
            cma_id = nullptr;
            if (!m_neigh_cma_event_channel_prev) {
                CHANNEL_LOCK(unlock);
                CHANNEL_LOCK(lock_wr);
                // The rdma_create_id() can fail in a forked process due to permission issue.
                // Recreate the channel only once to overcome this issue.
                // Keep previous channel not to invalidate previously created rdma-ids.
                // If previous already exists that means the channel was already recreated once.
                // Threads waiting for the first recreation should continue to rdma_create_id.
                if (!m_neigh_cma_event_channel_prev) {
                    m_neigh_cma_event_channel_prev = m_neigh_cma_event_channel;
                    create_rdma_channel();
                }

                CHANNEL_LOCK(unlock);
                CHANNEL_LOCK(lock_rd);

                neigh_mgr_logdbg("Calling rdma_create_id second time. tid: %d", gettid());
            } else {
                break; // Quit on post channel-recreation rdma_create_id failure.
            }
        }
        ENDIF_RDMACM_FAILURE;
    } while (!cma_id);

    if (cma_id) {
        ch_fd = m_neigh_cma_event_channel->fd;
        g_p_event_handler_manager->register_rdma_cm_event(ch_fd, cma_id, m_neigh_cma_event_channel,
                                                          context);
    } else {
        neigh_mgr_logerr("Failed in rdma_create_id (errno=%d %m). tid: %d", errno, gettid());
    }

    CHANNEL_LOCK(unlock);
    return ch_fd;
}
