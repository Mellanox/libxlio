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

#include "ring.h"
#include "proto/route_table_mgr.h"
#include "sock/tcp_seg_pool.h"
#include "sock/sockinfo.h"

#undef MODULE_NAME
#define MODULE_NAME "ring"
#undef MODULE_HDR
#define MODULE_HDR MODULE_NAME "%d:%s() "

ring::ring()
{
    print_val();
}

ring::~ring()
{
    if (m_tcp_seg_list) {
        g_tcp_seg_pool->put_tcp_segs(m_tcp_seg_list);
    }

     if (m_ec_list) {
        g_ec_pool->put_ecs(m_ec_list);
    }
}

// Assumed num > 0.
tcp_seg *ring::get_tcp_segs(uint32_t num)
{
    std::lock_guard<decltype(m_tcp_seg_lock)> lock(m_tcp_seg_lock);

    if (unlikely(num > m_tcp_seg_count)) {
        uint32_t getsize = std::max(safe_mce_sys().tx_segs_ring_batch_tcp, num - m_tcp_seg_count);
        auto seg_list = g_tcp_seg_pool->get_tcp_seg_list(getsize);
        if (!seg_list.first) {
            return nullptr;
        }
        seg_list.second->next = m_tcp_seg_list;
        m_tcp_seg_list = seg_list.first;
        m_tcp_seg_count += getsize;
    }

    tcp_seg *head = m_tcp_seg_list;
    tcp_seg *last = head;
    m_tcp_seg_count -= num;

    // For non-batching, improves branch prediction. For batching, we do not get here often.
    if (unlikely(num > 1U)) {
        while (likely(num-- > 1U)) { // Find the last returned element.
            last = last->next;
        }
    }

    m_tcp_seg_list = last->next;
    last->next = nullptr;

    return head;
}

// Assumed seg is not nullptr
void ring::put_tcp_segs(tcp_seg *seg)
{
    static const uint32_t return_treshold = safe_mce_sys().tx_segs_ring_batch_tcp * 2U;

    std::lock_guard<decltype(m_tcp_seg_lock)> lock(m_tcp_seg_lock);

    tcp_seg *seg_temp = m_tcp_seg_list;
    m_tcp_seg_list = seg;

    // For non-batching, improves branch prediction. For batching, we do not get here often.
    if (unlikely(seg->next)) {
        while (likely(seg->next)) {
            seg = seg->next;
            ++m_tcp_seg_count; // Count all except the first.
        }
    }

    seg->next = seg_temp;
    if (unlikely(++m_tcp_seg_count > return_treshold)) {
        g_tcp_seg_pool->put_tcp_segs(
            tcp_seg_pool::split_tcp_segs(m_tcp_seg_count / 2, m_tcp_seg_list, m_tcp_seg_count));
    }
}

// Assumed num > 0.
ring_ec *ring::get_ecs(uint32_t num)
{
    std::lock_guard<decltype(m_ec_lock)> lock(m_ec_lock);

    if (unlikely(num > m_ec_count)) {
        uint32_t getsize = std::max(256U, num - m_ec_count);
        auto seg_list = g_ec_pool->get_ec_list(getsize);
        if (!seg_list.first) {
            return nullptr;
        }
        seg_list.second->next_ec = m_ec_list;
        m_ec_list = seg_list.first;
        m_ec_count += getsize;
    }

    ring_ec *head = m_ec_list;
    ring_ec *last = head;
    m_ec_count -= num;

    // For non-batching, improves branch prediction. For batching, we do not get here often.
    if (unlikely(num > 1U)) {
        while (likely(num-- > 1U)) { // Find the last returned element.
            last = last->next_ec;
        }
    }

    m_ec_list = last->next_ec;
    last->next_ec = nullptr;

    return head;
}

// Assumed seg is not nullptr
void ring::put_ecs(ring_ec *ec)
{
    static const uint32_t return_treshold = 256 * 2U;

    std::lock_guard<decltype(m_ec_lock)> lock(m_ec_lock);

    ring_ec *seg_temp = m_ec_list;
    m_ec_list = ec;

    // For non-batching, improves branch prediction. For batching, we do not get here often.
    if (unlikely(ec->next_ec)) {
        while (likely(ec->next_ec)) {
            ec = ec->next_ec;
            ++m_ec_count; // Count all except the first.
        }
    }

    ec->next_ec = seg_temp;
    if (unlikely(++m_ec_count > return_treshold)) {
        g_ec_pool->put_ecs(
            ec_sockxtreme_pool::split_ecs(m_ec_count / 2, m_ec_list, m_ec_count));
    }
}

void ring::ec_sock_list_add(sockinfo *sock)
{
    sock->set_next_in_ring_list(nullptr);
    if (likely(m_socketxtreme.ec_sock_list_end)) {
        m_socketxtreme.ec_sock_list_end->set_next_in_ring_list(sock);
        m_socketxtreme.ec_sock_list_end = sock;
    } else {
        m_socketxtreme.ec_sock_list_end = m_socketxtreme.ec_sock_list_start = sock;
    }
}

xlio_socketxtreme_completion_t &ring::ec_start_transaction(sockinfo *sock, bool always_new)
{
    m_socketxtreme.lock_ec_list.lock();
    if (likely(!sock->get_last_ec())) {
        ec_sock_list_add(sock);
        always_new = true;
    }

    if (always_new) {
        sock->add_ec(get_ecs(1U));
    }

    return sock->get_last_ec()->completion;
}

void ring::ec_end_transaction()
{
    m_socketxtreme.lock_ec_list.unlock();
}

bool ring::ec_pop_completion(xlio_socketxtreme_completion_t *completion)
{
    struct ring_ec *ec = nullptr;

    m_socketxtreme.lock_ec_list.lock();
    if (m_socketxtreme.ec_sock_list_start) {
        ec = m_socketxtreme.ec_sock_list_start->pop_next_ec();

        ring_logdbg("tid: %d completion %p: events:%lu, ud:%lu, b:%p, %p\n",
            gettid(), ec, ec->completion.events, ec->completion.user_data,
            ec->completion.packet.buff_lst,
            ec->completion.packet.buff_lst ? ec->completion.packet.buff_lst->next : nullptr);

        memcpy(completion, &ec->completion, sizeof(ec->completion));
        ec->next_ec = nullptr;
        put_ecs(ec);
        if (!m_socketxtreme.ec_sock_list_start->has_next_ec()) { // Last ec of the socket was popped.
            // Remove socket from ready list.
            sockinfo *temp = m_socketxtreme.ec_sock_list_start;
            m_socketxtreme.ec_sock_list_start = temp->get_next_in_ring_list();
            if (! m_socketxtreme.ec_sock_list_start) {
                m_socketxtreme.ec_sock_list_end = nullptr;
            }
            temp->set_next_in_ring_list(nullptr);
        }
    }
    m_socketxtreme.lock_ec_list.unlock();
    return (ec != nullptr);
}

void ring::ec_clear_sock(sockinfo *sock)
{
    m_socketxtreme.lock_ec_list.lock();

    ring_ec *ecs = sock->clear_ecs();
    if (ecs) {
        put_ecs(ecs);
        sockinfo *temp = m_socketxtreme.ec_sock_list_start;
        sockinfo *prev = nullptr;
        while (temp && temp != sock) {
            prev = temp;
            temp = temp->get_next_in_ring_list();
        }

        if (prev) {
            prev->set_next_in_ring_list(sock->get_next_in_ring_list());
        }

        if (sock == m_socketxtreme.ec_sock_list_start) {
            m_socketxtreme.ec_sock_list_start = sock->get_next_in_ring_list();
        }

        if (sock == m_socketxtreme.ec_sock_list_end) {
            m_socketxtreme.ec_sock_list_end = prev;
        }

        sock->set_next_in_ring_list(nullptr);
    }

    m_socketxtreme.lock_ec_list.unlock();
}

void ring::print_val()
{
    ring_logdbg("%d: %p: parent %p", m_if_index, this,
                ((uintptr_t)this == (uintptr_t)m_parent ? 0 : m_parent));
}
