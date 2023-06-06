/*
 * Copyright (c) 2001-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#undef MODULE_NAME
#define MODULE_NAME "ring"
#undef MODULE_HDR
#define MODULE_HDR MODULE_NAME "%d:%s() "

ring::ring()
    : m_p_n_rx_channel_fds(NULL)
    , m_parent(NULL)
    , m_tcp_seg_count(0U)
{
    m_if_index = 0;
    print_val();
}

ring::~ring()
{
    if (m_tcp_seg_list) {
        g_tcp_seg_pool->put_tcp_segs(m_tcp_seg_list);
    }
}

struct tcp_seg *ring::get_tcp_segs(uint32_t num)
{
    std::lock_guard<decltype(m_tcp_seg_lock)> lock(m_tcp_seg_lock);

    if (num > m_tcp_seg_count) {
        uint32_t getsize = std::max(1024U, num - m_tcp_seg_count);
        auto seg_list = g_tcp_seg_pool->get_tcp_seg_list(static_cast<int>(getsize));
        if (!seg_list.first) {
            return nullptr;
        }
        seg_list.second->next = m_tcp_seg_list;
        m_tcp_seg_list = seg_list.first;
        m_tcp_seg_count += getsize;
    }

    struct tcp_seg *head = m_tcp_seg_list;
    m_tcp_seg_count -= num;
    if (likely(num == 1)) { // If we use batch > 1 we should not get here often.
        m_tcp_seg_list = head->next;
        head->next = nullptr;
    } else if (num--) { // Check if num > 0 and decrement for inner while.
        struct tcp_seg *last = head;
        while (num--) {
            last = last->next;
        }
        m_tcp_seg_list = last->next;
        last->next = nullptr;
    }

    return head;
}

void ring::put_tcp_segs(struct tcp_seg *seg)
{
    static const uint32_t RETURN_TO_GLOBAL_TRESHOLD =
        2048;
    if (likely(seg)) {
        std::lock_guard<decltype(m_tcp_seg_lock)> lock(m_tcp_seg_lock);

        seg->next = m_tcp_seg_list;
        m_tcp_seg_list = seg;
        ++m_tcp_seg_count;
        if (m_tcp_seg_count > RETURN_TO_GLOBAL_TRESHOLD) {
            int count = m_tcp_seg_count / 2;
            struct tcp_seg *next = m_tcp_seg_list;
            for (int i = 0; i < count - 1; i++) {
                next = next->next;
            }
            struct tcp_seg *head = m_tcp_seg_list;
            m_tcp_seg_list = next->next;
            next->next = nullptr;
            g_tcp_seg_pool->put_tcp_segs(head);
            m_tcp_seg_count -= count;
        }
    }
}

void ring::print_val()
{
    ring_logdbg("%d: %p: parent %p", m_if_index, this,
                ((uintptr_t)this == (uintptr_t)m_parent ? 0 : m_parent));
}
