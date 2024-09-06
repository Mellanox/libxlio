/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
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
#include "event/poll_group.h"
#include "proto/route_table_mgr.h"
#include "sock/sockinfo.h"

#undef MODULE_NAME
#define MODULE_NAME "ring"
#undef MODULE_HDR
#define MODULE_HDR MODULE_NAME "%d:%s() "

tcp_seg_pool *g_tcp_seg_pool = nullptr;
socketxtreme_ec_pool *g_socketxtreme_ec_pool = nullptr;

ring::ring()
{
    print_val();
}

ring::~ring()
{
    if (m_tcp_seg_list) {
        g_tcp_seg_pool->put_objs(m_tcp_seg_list);
    }

    if (m_socketxtreme_ec_list) {
        g_socketxtreme_ec_pool->put_objs(m_socketxtreme_ec_list);
    }
}

template <typename T>
static inline T *get_obj_list(cached_obj_pool<T> *obj_pool, uint32_t num, T *&obj_list_from,
                              uint32_t &obj_count, uint32_t batch_size)
{
    if (unlikely(num > obj_count)) {
        uint32_t getsize = std::max(batch_size, num - obj_count);
        auto obj_list = obj_pool->get_obj_list(getsize);
        if (!obj_list.first) {
            return nullptr;
        }
        obj_list.second->next = obj_list_from;
        obj_list_from = obj_list.first;
        obj_count += getsize;
    }

    T *head = obj_list_from;
    T *last = head;
    obj_count -= num;

    // For non-batching, improves branch prediction. For batching, we do not get here often.
    if (unlikely(num > 1U)) {
        while (likely(num-- > 1U)) { // Find the last returned element.
            last = last->next;
        }
    }

    obj_list_from = last->next;
    last->next = nullptr;

    return head;
}

// Assumed num > 0.
tcp_seg *ring::get_tcp_segs(uint32_t num)
{
    std::lock_guard<decltype(m_tcp_seg_lock)> lock(m_tcp_seg_lock);

    return get_obj_list(g_tcp_seg_pool, num, m_tcp_seg_list, m_tcp_seg_count,
                        safe_mce_sys().tx_segs_ring_batch_tcp);
}

// Assumed num > 0.
ring_ec *ring::socketxtreme_get_ecs(uint32_t num)
{
    std::lock_guard<decltype(m_ec_lock)> lock(m_ec_lock);

    return get_obj_list(g_socketxtreme_ec_pool, num, m_socketxtreme_ec_list,
                        m_socketxtreme_ec_count, 256U);
}

template <typename T>
static inline void put_obj_list(cached_obj_pool<T> *obj_pool, T *&obj_list_to, T *&obj_list_from,
                                uint32_t &obj_count, uint32_t return_treshold)
{
    T *obj_temp = obj_list_to;
    obj_list_to = obj_list_from;

    // For non-batching, improves branch prediction. For batching, we do not get here often.
    if (unlikely(obj_list_from->next)) {
        while (likely(obj_list_from->next)) {
            obj_list_from = obj_list_from->next;
            ++obj_count; // Count all except the first.
        }
    }

    obj_list_from->next = obj_temp;
    if (unlikely(++obj_count > return_treshold)) {
        obj_pool->put_objs(obj_pool->split_obj_list(obj_count / 2, obj_list_to, obj_count));
    }
}

// Assumed seg is not nullptr
void ring::put_tcp_segs(tcp_seg *seg)
{
    static const uint32_t return_treshold = safe_mce_sys().tx_segs_ring_batch_tcp * 2U;

    std::lock_guard<decltype(m_tcp_seg_lock)> lock(m_tcp_seg_lock);

    put_obj_list(g_tcp_seg_pool, m_tcp_seg_list, seg, m_tcp_seg_count, return_treshold);
}

// Assumed ec is not nullptr
void ring::socketxtreme_put_ecs(ring_ec *ec)
{
    static const uint32_t return_treshold = 256 * 2U;

    std::lock_guard<decltype(m_ec_lock)> lock(m_ec_lock);

    put_obj_list(g_socketxtreme_ec_pool, m_socketxtreme_ec_list, ec, m_socketxtreme_ec_count,
                 return_treshold);
}

void ring::socketxtreme_ec_sock_list_add(sockinfo *sock)
{
    sock->set_ec_ring_list_next(nullptr);
    if (likely(m_socketxtreme.ec_sock_list_end)) {
        m_socketxtreme.ec_sock_list_end->set_ec_ring_list_next(sock);
        m_socketxtreme.ec_sock_list_end = sock;
    } else {
        m_socketxtreme.ec_sock_list_end = m_socketxtreme.ec_sock_list_start = sock;
    }
}

xlio_socketxtreme_completion_t &ring::socketxtreme_start_ec_operation(sockinfo *sock,
                                                                      bool always_new)
{
    m_socketxtreme.lock_ec_list.lock();
    if (likely(!sock->get_last_ec())) {
        socketxtreme_ec_sock_list_add(sock);
        always_new = true;
    }

    if (always_new) {
        sock->add_ec(socketxtreme_get_ecs(1U));
    }

    return sock->get_last_ec()->completion;
}

void ring::socketxtreme_end_ec_operation()
{
    m_socketxtreme.lock_ec_list.unlock();
}

bool ring::socketxtreme_ec_pop_completion(xlio_socketxtreme_completion_t *completion)
{
    struct ring_ec *ec = nullptr;

    m_socketxtreme.lock_ec_list.lock();
    if (m_socketxtreme.ec_sock_list_start) {
        ec = m_socketxtreme.ec_sock_list_start->pop_next_ec();

        ring_logfunc(
            "tid: %d completion %p: events:%lu, ud:%lu, b:%p, %p\n", gettid(), ec,
            ec->completion.events, ec->completion.user_data, ec->completion.packet.buff_lst,
            ec->completion.packet.buff_lst ? ec->completion.packet.buff_lst->next : nullptr);

        memcpy(completion, &ec->completion, sizeof(ec->completion));
        ec->next = nullptr;
        socketxtreme_put_ecs(ec);
        if (!m_socketxtreme.ec_sock_list_start
                 ->has_next_ec()) { // Last ec of the socket was popped.
            // Remove socket from ready list.
            sockinfo *temp = m_socketxtreme.ec_sock_list_start;
            m_socketxtreme.ec_sock_list_start = temp->get_ec_ring_list_next();
            if (!m_socketxtreme.ec_sock_list_start) {
                m_socketxtreme.ec_sock_list_end = nullptr;
            }
            temp->set_ec_ring_list_next(nullptr);
        }
    }
    m_socketxtreme.lock_ec_list.unlock();
    return (ec != nullptr);
}

void ring::socketxtreme_ec_clear_sock(sockinfo *sock)
{
    m_socketxtreme.lock_ec_list.lock();

    ring_ec *ecs = sock->clear_ecs();
    if (ecs) {
        socketxtreme_put_ecs(ecs);
        sockinfo *temp = m_socketxtreme.ec_sock_list_start;
        sockinfo *prev = nullptr;
        while (temp && temp != sock) {
            prev = temp;
            temp = temp->get_ec_ring_list_next();
        }

        if (prev) {
            prev->set_ec_ring_list_next(sock->get_ec_ring_list_next());
        }

        if (sock == m_socketxtreme.ec_sock_list_start) {
            m_socketxtreme.ec_sock_list_start = sock->get_ec_ring_list_next();
        }

        if (sock == m_socketxtreme.ec_sock_list_end) {
            m_socketxtreme.ec_sock_list_end = prev;
        }

        sock->set_ec_ring_list_next(nullptr);
    }

    m_socketxtreme.lock_ec_list.unlock();
}

void ring::print_val()
{
    ring_logdbg("%d: %p: parent %p", m_if_index, this,
                ((uintptr_t)this == (uintptr_t)m_parent ? nullptr : m_parent));
}
