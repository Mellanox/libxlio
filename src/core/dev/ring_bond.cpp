/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "ring_bond.h"

#include "sock/sockinfo.h"
#include "dev/ring_simple.h"

#undef MODULE_NAME
#define MODULE_NAME "ring_bond"
DOCA_LOG_REGISTER(ring_bond);
#undef MODULE_HDR
#define MODULE_HDR MODULE_NAME "%d:%s() "

/* Set limitation for number of rings for bonding device */
#define MAX_NUM_RING_RESOURCES 10

ring_bond::ring_bond(int if_index)
    : ring()
    , m_lock_ring_rx("ring_bond:lock_rx")
    , m_lock_ring_tx("ring_bond:lock_tx")
{
    net_device_val *p_ndev = nullptr;

    /* Configure ring() fields */
    set_parent(this);
    set_if_index(if_index);

    /* Sanity check */
    p_ndev = g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());
    if (!p_ndev) {
        ring_logpanic("Invalid if_index = %d", if_index);
    }

    /* Configure ring_bond() fields */
    m_bond_rings.clear();
    m_xmit_rings.clear();
    m_recv_rings.clear();
    m_type = p_ndev->get_is_bond();
    m_xmit_hash_policy = p_ndev->get_bond_xmit_hash_policy();
#ifdef DEFINED_DPCP_PATH_TX
    m_max_inline_data = 0;
    m_max_send_sge = 0;
    update_cap();
#endif // DEFINED_DPCP_PATH_TX

    print_val();
    const slave_data_vector_t &slaves = p_ndev->get_slave_array();
    for (size_t i = 0; i < slaves.size(); i++) {
        slave_create(slaves[i]->if_index);
    }
}

ring_bond::~ring_bond()
{
    print_val();

    m_rx_flows.clear();

    ring_slave_vector_t::iterator iter = m_bond_rings.begin();
    for (; iter != m_bond_rings.end(); iter++) {
        delete *iter;
    }
    m_bond_rings.clear();
    m_xmit_rings.clear();
    m_recv_rings.clear();

    if (m_p_n_rx_channel_fds) {
        delete[] m_p_n_rx_channel_fds;
        m_p_n_rx_channel_fds = nullptr;
    }
}

void ring_bond::print_val()
{
    ring_logdbg("%d: %p: parent %p type %s", m_if_index, this,
                ((uintptr_t)this == (uintptr_t)m_parent ? nullptr : m_parent), "bond");
}

size_t ring_bond::get_rx_channels_num() const
{
    return m_recv_rings.size();
}

int ring_bond::get_rx_channel_fd(size_t ch_idx) const
{
    return m_p_n_rx_channel_fds[ch_idx];
}

int ring_bond::get_tx_channel_fd() const
{
    return -1;
}

bool ring_bond::attach_flow(flow_tuple &flow_spec_5t, sockinfo *sink, bool force_5t)
{
    bool ret = true;
    struct flow_sink_t value = {flow_spec_5t, sink};

    std::lock_guard<decltype(m_lock_ring_rx)> lock(m_lock_ring_rx);

    /* Map flow in local map */
    m_rx_flows.push_back(value);

    for (uint32_t i = 0; i < m_recv_rings.size(); i++) {
        bool step_ret = m_recv_rings[i]->attach_flow(flow_spec_5t, sink, force_5t);
        ret = ret && step_ret;
    }

    return ret;
}

bool ring_bond::detach_flow(flow_tuple &flow_spec_5t, sockinfo *sink)
{
    bool ret = true;
    struct flow_sink_t value = {flow_spec_5t, sink};

    std::lock_guard<decltype(m_lock_ring_rx)> lock(m_lock_ring_rx);

    std::vector<struct flow_sink_t>::iterator iter;
    for (iter = m_rx_flows.begin(); iter != m_rx_flows.end(); iter++) {
        struct flow_sink_t cur = *iter;
        if ((cur.flow == value.flow) && (cur.sink == value.sink)) {
            m_rx_flows.erase(iter);
            break;
        }
    }

    for (uint32_t i = 0; i < m_recv_rings.size(); i++) {
        bool step_ret = m_recv_rings[i]->detach_flow(flow_spec_5t, sink);
        ret = ret && step_ret;
    }

    return ret;
}

void ring_bond::restart()
{
    net_device_val *p_ndev = g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());

    if (!p_ndev) {
        return;
    }
    const slave_data_vector_t &slaves = p_ndev->get_slave_array();

    ring_logdbg("*** ring restart! ***");

    m_lock_ring_rx.lock();
    m_lock_ring_tx.lock();

    /* for active-backup mode
     * It is guaranteed that the first slave is active by popup_active_rings()
     */
    ring_simple *previously_active = dynamic_cast<ring_simple *>(m_xmit_rings[0]);

    for (uint32_t i = 0; i < m_bond_rings.size(); i++) {
        ring_simple *tmp_ring = dynamic_cast<ring_simple *>(m_bond_rings[i]);

        if (!tmp_ring) {
            continue;
        }

        for (uint32_t j = 0; j < slaves.size(); j++) {

            if (slaves[j]->if_index != m_bond_rings[i]->get_if_index()) {
                continue;
            }

            /* For RoCE LAG device income data is processed by single ring only
             * Consider using ring related slave with lag_tx_port_affinity = 1
             * even if slave is not active.
             * Always keep this ring active for RX
             * but keep common logic for TX
             */
            if (slaves[j]->active) {
                ring_logdbg("ring %d active", i);
                if (slaves[j]->lag_tx_port_affinity != 1) {
                    tmp_ring->start_active_queue_tx();
                    /* coverity[sleep] */
                    tmp_ring->start_active_queue_rx();
                }
                m_bond_rings[i]->m_active = true;
            } else {
                ring_logdbg("ring %d not active", i);
                if (slaves[j]->lag_tx_port_affinity != 1) {
                    /* coverity[sleep] */
                    tmp_ring->stop_active_queue_tx();
                    /* coverity[sleep] */
                    tmp_ring->stop_active_queue_rx();
                }
                m_bond_rings[i]->m_active = false;
            }
            break;
        }
    }
    popup_xmit_rings();

    if (!request_notification_rx()) {
        ring_logdbg("Failed arming RX notification");
    }
    if (!request_notification_tx()) {
        ring_logdbg("Failed arming TX notification");
    }

    if (m_type == net_device_val::ACTIVE_BACKUP) {
        ring_simple *currently_active = dynamic_cast<ring_simple *>(m_xmit_rings[0]);
        if (currently_active && safe_mce_sys().cq_moderation_enable) {
            if (likely(previously_active)) {
                currently_active->m_cq_moderation_info.period =
                    previously_active->m_cq_moderation_info.period;
                currently_active->m_cq_moderation_info.count =
                    previously_active->m_cq_moderation_info.count;
            } else {
                currently_active->m_cq_moderation_info.period =
                    safe_mce_sys().cq_moderation_period_usec;
                currently_active->m_cq_moderation_info.count = safe_mce_sys().cq_moderation_count;
            }

            currently_active->modify_cq_moderation(safe_mce_sys().cq_moderation_period_usec,
                                                   safe_mce_sys().cq_moderation_count);
        }
    }

    m_lock_ring_tx.unlock();
    m_lock_ring_rx.unlock();

    ring_logdbg("*** ring restart done! ***");
}

void ring_bond::adapt_cq_moderation()
{
    if (m_lock_ring_rx.trylock()) {
        return;
    }

    for (uint32_t i = 0; i < m_bond_rings.size(); i++) {
        if (m_bond_rings[i]->is_up()) {
            m_bond_rings[i]->adapt_cq_moderation();
        }
    }

    m_lock_ring_rx.unlock();
}

void ring_bond::flow_del_all_rfs_safe()
{
    std::lock_guard<decltype(m_lock_ring_rx)> lock(m_lock_ring_rx);
    for (auto &itr : m_bond_rings) {
        itr->flow_del_all_rfs_safe();
    }
}

mem_buf_desc_t *ring_bond::mem_buf_tx_get(ring_user_id_t id, pbuf_type type,
                                          uint32_t n_num_mem_bufs /* default = 1 */)
{
    mem_buf_desc_t *ret = nullptr;

    std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
    ret = m_xmit_rings[id]->mem_buf_tx_get(id, type, n_num_mem_bufs);

    return ret;
}

int ring_bond::mem_buf_tx_release(mem_buf_desc_t *p_mem_buf_desc_list, bool trylock /*=false*/)
{
    mem_buf_desc_t *buffer_per_ring[MAX_NUM_RING_RESOURCES];
    int ret = 0;
    uint32_t i = 0;

    std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);

    memset(buffer_per_ring, 0, sizeof(buffer_per_ring));
    ret = devide_buffers_helper(p_mem_buf_desc_list, buffer_per_ring);

    for (i = 0; i < m_bond_rings.size(); i++) {
        if (buffer_per_ring[i]) {
            ret += m_bond_rings[i]->mem_buf_tx_release(buffer_per_ring[i], trylock);
        }
    }
    return ret;
}

void ring_bond::mem_buf_rx_release(mem_buf_desc_t *p_mem_buf_desc)
{
    uint32_t i;

    for (i = 0; i < m_bond_rings.size(); i++) {
        if (m_bond_rings[i] == p_mem_buf_desc->p_desc_owner) {
            m_bond_rings[i]->mem_buf_rx_release(p_mem_buf_desc);
            break;
        }
    }
    if (i == m_bond_rings.size()) {
        buffer_pool::free_rx_lwip_pbuf_custom(&p_mem_buf_desc->lwip_pbuf);
    }
}

void ring_bond::mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t *p_mem_buf_desc)
{
    p_mem_buf_desc->p_desc_owner->mem_buf_desc_return_single_to_owner_tx(p_mem_buf_desc);
}

void ring_bond::mem_buf_desc_return_single_multi_ref(mem_buf_desc_t *p_mem_buf_desc, unsigned ref)
{
    p_mem_buf_desc->p_desc_owner->mem_buf_desc_return_single_multi_ref(p_mem_buf_desc, ref);
}

bool ring_bond::poll_and_process_element_rx(void *pv_fd_ready_array /*NULL*/)
{
    if (m_lock_ring_rx.trylock()) {
        return false;
    }

    bool all_drained = true;

    for (uint32_t i = 0; i < m_recv_rings.size(); i++) {
        if (m_recv_rings[i]->is_up()) {
            // TODO consider returning immediately after finding something, continue next time from
            // next ring
            all_drained &= m_recv_rings[i]->poll_and_process_element_rx(pv_fd_ready_array);
        }
    }
    m_lock_ring_rx.unlock();

    return all_drained;
}

void ring_bond::poll_and_process_element_tx()
{
    if (m_lock_ring_tx.trylock()) {
        errno = EAGAIN;
        return;
    }

    for (uint32_t i = 0; i < m_bond_rings.size(); i++) {
        if (m_bond_rings[i]->is_up()) {
            m_bond_rings[i]->poll_and_process_element_tx();
        }
    }
    m_lock_ring_tx.unlock();
}

int ring_bond::drain_and_proccess()
{
    if (m_lock_ring_rx.trylock()) {
        errno = EAGAIN;
        return 0;
    }

    int temp = 0;
    int ret = 0;

    for (uint32_t i = 0; i < m_recv_rings.size(); i++) {
        if (m_recv_rings[i]->is_up()) {
            temp = m_recv_rings[i]->drain_and_proccess();
            if (temp > 0) {
                ret += temp;
            }
        }
    }

    m_lock_ring_rx.unlock();

    if (ret > 0) {
        return ret;
    } else {
        return temp;
    }
}

void ring_bond::clear_rx_notification()
{
    std::lock_guard<decltype(m_lock_ring_rx)> lock(m_lock_ring_rx);

    for (size_t i = 0; i < m_recv_rings.size(); i++) {
        if (m_recv_rings[i]->is_up()) {
            m_recv_rings[i]->clear_rx_notification();
        }
    }
}

bool ring_bond::request_notification_rx()
{
    m_lock_ring_rx.lock();

    for (uint32_t i = 0; i < m_recv_rings.size(); i++) {
        if (m_recv_rings[i]->is_up()) {
            if (!m_recv_rings[i]->request_notification_rx()) {
                return false;
            }
        }
    }

    m_lock_ring_rx.unlock();

    return true;
}

bool ring_bond::request_notification_tx()
{
    m_lock_ring_tx.lock();

    for (uint32_t i = 0; i < m_xmit_rings.size(); i++) {
        if (m_xmit_rings[i]->is_up()) {
            if (!m_xmit_rings[i]->request_notification_tx()) {
                return false;
            }
        }
    }

    m_lock_ring_tx.unlock();

    return true;
}

void ring_bond::inc_tx_retransmissions_stats(ring_user_id_t id)
{
    std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);
    m_xmit_rings[id]->inc_tx_retransmissions_stats(id);
}

bool ring_bond::reclaim_recv_buffers(descq_t *rx_reuse)
{
    /* use this local array to avoid locking mechanizm
     * for threads synchronization. So every thread should use
     * own array. Set hardcoded number to meet C++11
     * VLA is not an official part of C++11.
     */
    descq_t buffer_per_ring[MAX_NUM_RING_RESOURCES];
    uint32_t i = 0;

    if (m_lock_ring_rx.trylock()) {
        errno = EAGAIN;
        return false;
    }

    devide_buffers_helper(rx_reuse, buffer_per_ring);

    for (i = 0; i < m_bond_rings.size(); i++) {
        if (buffer_per_ring[i].size() > 0) {
            if (!m_bond_rings[i]->reclaim_recv_buffers(&buffer_per_ring[i])) {
                g_buffer_pool_rx_ptr->put_buffers_after_deref_thread_safe(&buffer_per_ring[i]);
            }
        }
    }

    if (buffer_per_ring[m_bond_rings.size()].size() > 0) {
        g_buffer_pool_rx_ptr->put_buffers_after_deref_thread_safe(
            &buffer_per_ring[m_bond_rings.size()]);
    }

    m_lock_ring_rx.unlock();

    return true;
}

bool ring_bond::reclaim_recv_buffers(mem_buf_desc_t *)
{
    /* TODO: not supported */
    return false;
}

bool ring_bond::reclaim_recv_buffers_no_lock(mem_buf_desc_t *)
{
    return false;
}

void ring_bond::devide_buffers_helper(descq_t *rx_reuse, descq_t *buffer_per_ring)
{
    int last_found_index = 0;
    while (!rx_reuse->empty()) {
        mem_buf_desc_t *buff = rx_reuse->get_and_pop_front();
        uint32_t checked = 0;
        int index = last_found_index;
        while (checked < m_bond_rings.size()) {
            if (m_bond_rings[index] == buff->p_desc_owner) {
                buffer_per_ring[index].push_back(buff);
                last_found_index = index;
                break;
            }
            checked++;
            index++;
            index = index % m_bond_rings.size();
        }
        // no owner
        if (checked == m_bond_rings.size()) {
            ring_logfunc("No matching ring %p to return buffer", buff->p_desc_owner);
            buffer_per_ring[m_bond_rings.size()].push_back(buff);
        }
    }
}

int ring_bond::devide_buffers_helper(mem_buf_desc_t *p_mem_buf_desc_list,
                                     mem_buf_desc_t **buffer_per_ring)
{
    mem_buf_desc_t *buffers_last[MAX_NUM_RING_RESOURCES];
    mem_buf_desc_t *head, *current, *temp;
    ring_slave *last_owner;
    int count = 0;
    int ret = 0;

    memset(buffers_last, 0, sizeof(buffers_last));
    head = p_mem_buf_desc_list;
    while (head) {
        last_owner = head->p_desc_owner;
        current = head;
        count = 1;
        while (head && head->p_next_desc && head->p_next_desc->p_desc_owner == last_owner) {
            head = head->p_next_desc;
            count++;
        }
        uint32_t i = 0;
        for (i = 0; i < m_bond_rings.size(); i++) {
            if (m_bond_rings[i] == last_owner) {
                if (buffers_last[i]) {
                    buffers_last[i]->p_next_desc = current;
                    buffers_last[i] = head;
                } else {
                    buffer_per_ring[i] = current;
                    buffers_last[i] = head;
                }
                break;
            }
        }
        temp = head->p_next_desc;
        head->p_next_desc = nullptr;
        if (i == m_bond_rings.size()) {
            // handle no owner
            ring_logdbg("No matching ring %p to return buffer", current->p_desc_owner);
            g_buffer_pool_tx->put_buffers_thread_safe(current);
            ret += count;
        }

        head = temp;
    }

    return ret;
}

void ring_bond::popup_xmit_rings()
{
    ring_slave *cur_slave = nullptr;
    size_t i, j;

    m_xmit_rings.clear();

    /* Clone m_bond_rings to m_xmit_rings */
    j = 0;
    for (i = 0; i < m_bond_rings.size(); i++) {
        if (!cur_slave && m_bond_rings[i]->m_active) {
            cur_slave = m_bond_rings[i];
            j = i;
        }
        m_xmit_rings.push_back(m_bond_rings[i]);
    }

    if (cur_slave) {
        /* Assign xmit ring for non active rings in clockwise order */
        for (i = 1; i < m_xmit_rings.size(); i++) {
            j = (j ? j : m_xmit_rings.size()) - 1;
            if (m_xmit_rings[j]->m_active) {
                cur_slave = m_xmit_rings[j];
            } else {
                m_xmit_rings[j] = cur_slave;
            }
        }
    }
}

void ring_bond::popup_recv_rings()
{
    net_device_val *p_ndev = g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());

    m_recv_rings.clear();
    if (!p_ndev) {
        return;
    }
    const slave_data_vector_t &slaves = p_ndev->get_slave_array();

    /* Copy rings from m_bond_rings to m_recv_rings
     * that is active to process RX flow.
     * - For RoCE LAG device (lag_tx_port_affinity > 0) income data is processed by single ring only
     * Consider using ring related slave with lag_tx_port_affinity = 1
     * even if slave is not active.
     */
    for (uint32_t i = 0; i < m_bond_rings.size(); i++) {
        for (uint32_t j = 0; j < slaves.size(); j++) {
            if (slaves[j]->if_index != m_bond_rings[i]->get_if_index()) {
                continue;
            }
            if (slaves[j]->lag_tx_port_affinity < 2) {
                m_recv_rings.push_back(m_bond_rings[i]);
            }
            break;
        }
    }
}

void ring_bond::update_rx_channel_fds()
{
    if (m_p_n_rx_channel_fds) {
        delete[] m_p_n_rx_channel_fds;
        m_p_n_rx_channel_fds = nullptr;
    }

    if (m_recv_rings.size() == 0) {
        return;
    }

    m_p_n_rx_channel_fds = new int[m_recv_rings.size()];
    for (uint32_t i = 0; i < m_recv_rings.size(); i++) {
        // Assume that a slave ring contains exactly 1 channel fd.
        m_p_n_rx_channel_fds[i] = m_bond_rings[i]->get_rx_channel_fd(0U);
    }
}

bool ring_bond::is_active_member(ring_slave *rng, ring_user_id_t id)
{
    return (m_xmit_rings[id] == rng);
}

bool ring_bond::is_member(ring_slave *rng)
{
    for (uint32_t i = 0; i < m_bond_rings.size(); i++) {
        if (m_bond_rings[i]->is_member(rng)) {
            return true;
        }
    }
    return false;
}

ring_user_id_t ring_bond::generate_id(const address_t src_mac, const address_t dst_mac,
                                      uint16_t eth_proto, uint16_t encap_proto,
                                      const ip_address &src_ip, const ip_address &dst_ip,
                                      uint16_t src_port, uint16_t dst_port)
{

    if (m_type != net_device_val::LAG_8023ad) {
        return 0;
    }

    ring_logdbg("generate_id for policy %d from src_mac=" ETH_HW_ADDR_PRINT_FMT
                ", dst_mac=" ETH_HW_ADDR_PRINT_FMT
                ", eth_proto=%#x, encap_proto=%#x, src_ip=%s, dst_ip=%s, "
                "src_port=%d, dst_port=%d",
                m_xmit_hash_policy, ETH_HW_ADDR_PRINT_ADDR(src_mac),
                ETH_HW_ADDR_PRINT_ADDR(dst_mac), ntohs(eth_proto), ntohs(encap_proto),
                src_ip.to_str(AF_INET6).c_str(), dst_ip.to_str(AF_INET6).c_str(), ntohs(src_port),
                ntohs(dst_port));

    uint64_t user_id = 0;
    // uint64_t ips_hash[2] = {0U};
    if (m_xmit_hash_policy > net_device_val::XHP_LAYER_2_3 && eth_proto == htons(ETH_P_8021Q)) {
        eth_proto = encap_proto;
    }

    if (eth_proto != htons(ETH_P_IP) && eth_proto != htons(ETH_P_IPV6)) {
        user_id = dst_mac[5] ^ src_mac[5] ^ eth_proto;
        return user_id % m_bond_rings.size();
    }

    switch (m_xmit_hash_policy) {
    case (net_device_val::XHP_LAYER_2):
        user_id = dst_mac[5] ^ src_mac[5] ^ eth_proto;
        break;
    case (net_device_val::XHP_LAYER_2_3):
    case (net_device_val::XHP_ENCAP_2_3):
        //*reinterpret_cast<uint64_t*>(ips_hash) = dst_ip.hash() ^ src_ip.hash();
        user_id = dst_mac[5] ^ src_mac[5] ^ eth_proto;
        user_id ^= dst_ip.hash() ^ src_ip.hash();
        user_id ^= (user_id >> 16);
        user_id ^= (user_id >> 8);
        break;
    case (net_device_val::XHP_LAYER_3_4):
    case (net_device_val::XHP_ENCAP_3_4):
        //*reinterpret_cast<uint64_t*>(ips_hash) = dst_ip.hash() ^ src_ip.hash();
        user_id = static_cast<size_t>(src_port) | (static_cast<size_t>(dst_port) << 16);
        user_id ^= dst_ip.hash() ^ src_ip.hash();
        user_id ^= (user_id >> 16);
        user_id ^= (user_id >> 8);
        break;
    default:
        return ring::generate_id();
    }

    return user_id % m_bond_rings.size();
}

int ring_bond::modify_ratelimit(struct xlio_rate_limit_t &rate_limit)
{
    for (uint32_t i = 0; i < m_bond_rings.size(); i++) {
        if (m_bond_rings[i]) {
            m_bond_rings[i]->modify_ratelimit(rate_limit);
        }
    }
    return 0;
}

ib_ctx_handler *ring_bond::get_ctx(ring_user_id_t id)
{
    return m_xmit_rings[id]->get_ctx(0);
}

uint32_t ring_bond::get_max_payload_sz()
{
    return 0;
}

uint16_t ring_bond::get_max_header_sz()
{
    return 0;
}

bool ring_bond::is_tso()
{
    return false;
}

void ring_bond::slave_create(int if_index)
{
    ring_slave *cur_slave;

    cur_slave = new ring_eth(if_index, this);
    if (!cur_slave) {
        ring_logpanic("Error creating bond ring: memory allocation error");
    }
#ifdef DEFINED_DPCP_PATH_TX
    update_cap(cur_slave);
#endif // DEFINED_DPCP_PATH_TX
    m_bond_rings.push_back(cur_slave);

    if (m_bond_rings.size() > MAX_NUM_RING_RESOURCES) {
        ring_logpanic("Error creating bond ring with more than %d resource",
                      MAX_NUM_RING_RESOURCES);
    }

    popup_xmit_rings();
    popup_recv_rings();
    update_rx_channel_fds();
}

bool ring_bond::tls_tx_supported()
{
    return false;
}

bool ring_bond::tls_rx_supported()
{
    return false;
}

#ifdef DEFINED_DPCP_PATH_TX

std::unique_ptr<xlio_tis> ring_bond::create_tis(uint32_t flag) const
{
    NOT_IN_USE(flag);
    return nullptr;
}

void ring_bond::send_ring_buffer(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe,
                                 xlio_wr_tx_packet_attr attr)
{
    mem_buf_desc_t *p_mem_buf_desc = (mem_buf_desc_t *)(p_send_wqe->wr_id);

    std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);

    if (is_active_member(p_mem_buf_desc->p_desc_owner, id)) {
        m_xmit_rings[id]->send_ring_buffer(id, p_send_wqe, attr);
    } else {
        ring_logfunc("active ring=%p, silent packet drop (%p), (HA event?)", m_xmit_rings[id],
                     p_mem_buf_desc);
        p_mem_buf_desc->p_next_desc = nullptr;
        if (likely(p_mem_buf_desc->p_desc_owner == m_bond_rings[id])) {
            m_bond_rings[id]->mem_buf_tx_release(p_mem_buf_desc);
        } else {
            mem_buf_tx_release(p_mem_buf_desc);
        }
    }
}

int ring_bond::send_lwip_buffer(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe,
                                xlio_wr_tx_packet_attr attr, xlio_tis *tis)
{
    mem_buf_desc_t *p_mem_buf_desc = (mem_buf_desc_t *)(p_send_wqe->wr_id);

    std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);

    if (is_active_member(p_mem_buf_desc->p_desc_owner, id)) {
        return m_xmit_rings[id]->send_lwip_buffer(id, p_send_wqe, attr, tis);
    }

    ring_logfunc("active ring=%p, silent packet drop (%p), (HA event?)", m_xmit_rings[id],
                 p_mem_buf_desc);
    p_mem_buf_desc->p_next_desc = nullptr;
    /* no need to free the buffer here, as for lwip buffers we have 2 ref counts, */
    /* one for caller, and one for completion. for completion, we ref count in    */
    /* send_lwip_buffer(). Since we are not going in, the caller will free the    */
    /* buffer. */
    return -1;
}

bool ring_bond::get_hw_dummy_send_support(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe)
{
    mem_buf_desc_t *p_mem_buf_desc = (mem_buf_desc_t *)(p_send_wqe->wr_id);

    std::lock_guard<decltype(m_lock_ring_tx)> lock(m_lock_ring_tx);

    if (is_active_member(p_mem_buf_desc->p_desc_owner, id)) {
        return m_xmit_rings[id]->get_hw_dummy_send_support(id, p_send_wqe);
    } else {
        if (likely(p_mem_buf_desc->p_desc_owner == m_bond_rings[id])) {
            return m_bond_rings[id]->get_hw_dummy_send_support(id, p_send_wqe);
        }
    }

    return false;
}

uint32_t ring_bond::get_max_inline_data()
{
    return m_max_inline_data;
}

uint32_t ring_bond::get_max_send_sge()
{
    return m_max_send_sge;
}

void ring_bond::update_cap(ring_slave *slave)
{
    if (!slave) {
        m_max_inline_data = (uint32_t)(-1);
        m_max_send_sge = (uint32_t)(-1);
        return;
    }

    m_max_inline_data = (m_max_inline_data == (uint32_t)(-1)
                             ? slave->get_max_inline_data()
                             : std::min(m_max_inline_data, slave->get_max_inline_data()));

    m_max_send_sge =
        (m_max_send_sge == (uint32_t)(-1) ? slave->get_max_send_sge()
                                          : std::min(m_max_send_sge, slave->get_max_send_sge()));
}

void ring_bond::reset_inflight_zc_buffers_ctx(ring_user_id_t id, void *ctx)
{
    m_xmit_rings[id]->reset_inflight_zc_buffers_ctx(id, ctx);
}

void ring_bond::post_nop_fence()
{
}

void ring_bond::post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey, bool first)
{
    NOT_IN_USE(tis);
    NOT_IN_USE(addr);
    NOT_IN_USE(len);
    NOT_IN_USE(lkey);
    NOT_IN_USE(first);
}

bool ring_bond::credits_get(unsigned credits)
{
    NOT_IN_USE(credits);
    return false;
}

void ring_bond::credits_return(unsigned credits)
{
    NOT_IN_USE(credits);
}

uint32_t ring_bond::get_tx_user_lkey(void *addr, size_t length)
{
    NOT_IN_USE(addr);
    NOT_IN_USE(length);
    return LKEY_ERROR;
}

uint32_t ring_bond::get_tx_lkey(ring_user_id_t id)
{
    return m_xmit_rings[id]->get_tx_lkey(id);
}

#ifdef DEFINED_UTLS
xlio_tis *ring_bond::tls_context_setup_tx(const xlio_tls_info *info)
{
    NOT_IN_USE(info);
    return nullptr;
}

void ring_bond::tls_context_resync_tx(const xlio_tls_info *info, xlio_tis *tis, bool skip_static)
{
    NOT_IN_USE(info);
    NOT_IN_USE(tis);
    NOT_IN_USE(skip_static);
}

void ring_bond::tls_release_tis(xlio_tis *tis)
{
    NOT_IN_USE(tis);
}

void ring_bond::tls_tx_post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey,
                                     bool first)
{
    NOT_IN_USE(tis);
    NOT_IN_USE(addr);
    NOT_IN_USE(len);
    NOT_IN_USE(lkey);
    NOT_IN_USE(first);
}
#endif // DEFINED_UTLS
#else // DEFINED_DPCP_PATH_TX
uint32_t ring_bond::send_doca_single(void *ptr, uint32_t len, mem_buf_desc_t *buff)
{
    NOT_IN_USE(ptr);
    NOT_IN_USE(len);
    NOT_IN_USE(buff);
    return -1;
}
uint32_t ring_bond::send_doca_lso(struct iovec &h, struct pbuf *p, uint16_t mss, bool is_zerocopy)
{
    NOT_IN_USE(h);
    NOT_IN_USE(p);
    NOT_IN_USE(mss);
    NOT_IN_USE(is_zerocopy);
    return -1;
}
#endif // DEFINED_DPCP_PATH_TX

#if defined(DEFINED_DPCP_PATH_ONLY) && defined(DEFINED_UTLS)
xlio_tir *ring_bond::tls_create_tir(bool cached)
{
    NOT_IN_USE(cached);
    return nullptr;
}

int ring_bond::tls_context_setup_rx(xlio_tir *tir, const xlio_tls_info *info,
                                    uint32_t next_record_tcp_sn, xlio_comp_cb_t callback,
                                    void *callback_arg)
{
    NOT_IN_USE(tir);
    NOT_IN_USE(info);
    NOT_IN_USE(next_record_tcp_sn);
    NOT_IN_USE(callback);
    NOT_IN_USE(callback_arg);
    return -1;
}

rfs_rule *ring_bond::tls_rx_create_rule(const flow_tuple &flow_spec_5t, xlio_tir *tir)
{
    NOT_IN_USE(flow_spec_5t);
    NOT_IN_USE(tir);
    return nullptr;
}

void ring_bond::tls_resync_rx(xlio_tir *tir, const xlio_tls_info *info, uint32_t hw_resync_tcp_sn)
{
    NOT_IN_USE(tir);
    NOT_IN_USE(info);
    NOT_IN_USE(hw_resync_tcp_sn);
}

void ring_bond::tls_get_progress_params_rx(xlio_tir *tir, void *buf, uint32_t lkey)
{
    NOT_IN_USE(tir);
    NOT_IN_USE(buf);
    NOT_IN_USE(lkey);
}

void ring_bond::tls_release_tir(xlio_tir *tir)
{
    NOT_IN_USE(tir);
}
#endif // DEFINED_DPCP_PATH_ONLY && DEFINED_UTLS
