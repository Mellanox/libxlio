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
    , m_tcp_seg_list(nullptr)
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

// Assumed num > 0.
tcp_seg *ring::get_tcp_segs(uint32_t num)
{
    std::lock_guard<decltype(m_tcp_seg_lock)> lock(m_tcp_seg_lock);

    if (unlikely(num > m_tcp_seg_count)) {
        uint32_t getsize = std::max(safe_mce_sys().tx_segs_ring_batch_tcp, num - m_tcp_seg_count);
        auto seg_list = g_tcp_seg_pool->get_tcp_seg_list(static_cast<int>(getsize));
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

void ring::print_val()
{
    ring_logdbg("%d: %p: parent %p", m_if_index, this,
                ((uintptr_t)this == (uintptr_t)m_parent ? 0 : m_parent));
}
