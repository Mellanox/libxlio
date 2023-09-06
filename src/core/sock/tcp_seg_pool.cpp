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

#include "tcp_seg_pool.h"
#include "core/util/utils.h"
#include "vlogger/vlogger.h"

#define MODULE_NAME "tcp_seg_pool"

extern global_stats_t g_global_stat_static;

tcp_seg_pool *g_tcp_seg_pool = NULL;

tcp_seg_pool::tcp_seg_pool(uint32_t size)
    : m_allocator(ALLOC_TYPE_PREFER_HUGE)
{
    tcp_seg *tcp_segs_array = (tcp_seg *)m_allocator.alloc(sizeof(tcp_seg) * size);
    if (!tcp_segs_array) {
        __log_dbg("TCP segments allocation failed");
        throw_xlio_exception("TCP segments allocation failed");
    }

    // Allocator can allocate more memory than requested - utilize it.
    size = m_allocator.size() / sizeof(tcp_seg);

    memset(tcp_segs_array, 0, sizeof(tcp_seg) * size);
    for (uint32_t i = 0; i < size - 1; i++) {
        tcp_segs_array[i].next = &tcp_segs_array[i + 1];
    }
    m_p_head = &tcp_segs_array[0];
    g_global_stat_static.n_tcp_seg_pool_size = size;
}

tcp_seg_pool::~tcp_seg_pool()
{
}

tcp_seg *tcp_seg_pool::get_tcp_segs(uint32_t amount)
{
    return get_tcp_seg_list(amount).first;
}

std::pair<tcp_seg *, tcp_seg *> tcp_seg_pool::get_tcp_seg_list(uint32_t amount)
{
    uint32_t orig_amount = amount;
    tcp_seg *head, *next, *prev;
    if (unlikely(amount <= 0)) {
        return std::make_pair(nullptr, nullptr);
    }
    lock();
    head = next = m_p_head;
    prev = NULL;
    while (amount > 0 && next) {
        prev = next;
        next = next->next;
        amount--;
    }
    if (amount) {
        // run out of segments
        g_global_stat_static.n_tcp_seg_pool_no_segs++;
        unlock();
        return std::make_pair(nullptr, nullptr);
    }
    prev->next = NULL;
    m_p_head = next;
    g_global_stat_static.n_tcp_seg_pool_size -= orig_amount;
    unlock();

    return std::make_pair(head, prev);
}

void tcp_seg_pool::put_tcp_segs(tcp_seg *seg_list)
{
    tcp_seg *next = seg_list;
    if (unlikely(!seg_list)) {
        return;
    }

    int i;
    for (i = 1; next->next; i++) {
        next = next->next;
    }

    lock();
    next->next = m_p_head;
    m_p_head = seg_list;
    g_global_stat_static.n_tcp_seg_pool_size += i;
    unlock();
}

// Splitting seg list such that first 'count' segs are returned and 'tcp_seg_list'
// is updated to point to the remaining segs.
// The length of tcp_seg_list is assumed to be at least 'count' long.
tcp_seg *tcp_seg_pool::split_tcp_segs(uint32_t count, tcp_seg *&tcp_seg_list, uint32_t &total_count)
{
    struct tcp_seg *head = tcp_seg_list;
    struct tcp_seg *last = head;
    total_count -= count;
    while (count-- > 1U) {
        last = last->next;
    }

    tcp_seg_list = last->next;
    last->next = nullptr;
    return head;
}
