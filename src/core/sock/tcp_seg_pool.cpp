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

enum {
    TCP_SEG_POOL_COMPENSATION_LEVEL = 16384U,
};

extern global_stats_t g_global_stat_static;

tcp_seg_pool *g_tcp_seg_pool = NULL;

tcp_seg_pool::tcp_seg_pool()
    : m_p_head(nullptr)
    , m_allocator(false)
{
    memset(&m_stats, 0, sizeof(m_stats));
    expand();
}

tcp_seg_pool::~tcp_seg_pool()
{
    print_report();
}

tcp_seg *tcp_seg_pool::get_tcp_segs(uint32_t amount)
{
    return get_tcp_seg_list(amount).first;
}

std::pair<tcp_seg *, tcp_seg *> tcp_seg_pool::get_tcp_seg_list(uint32_t amount)
{
    uint32_t count;
    tcp_seg *head, *next, *prev;
    if (unlikely(amount <= 0)) {
        return std::make_pair(nullptr, nullptr);
    }
    lock();
repeat:
    count = amount;
    head = next = m_p_head;
    prev = NULL;
    while (count > 0 && next) {
        prev = next;
        next = next->next;
        count--;
    }
    if (count) {
        // run out of segments
        if (expand()) {
            goto repeat;
        }
        g_global_stat_static.n_tcp_seg_pool_no_segs++;
        unlock();
        return std::make_pair(nullptr, nullptr);
    }
    prev->next = NULL;
    m_p_head = next;
    m_stats.allocations++;
    g_global_stat_static.n_tcp_seg_pool_size -= amount;
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

bool tcp_seg_pool::expand()
{
    size_t size = sizeof(tcp_seg) * TCP_SEG_POOL_COMPENSATION_LEVEL;
    tcp_seg *tcp_segs_array = (tcp_seg *)m_allocator.alloc(size);

    if (!tcp_segs_array) {
        __log_dbg("TCP segments allocation failed");
        return false;
    }

    // Allocator can allocate more memory than requested - utilize it.
    size_t segs_nr = size / sizeof(tcp_seg);

    if (segs_nr > 0) {
        memset(tcp_segs_array, 0, size);
        for (size_t i = 0; i < segs_nr - 1; i++) {
            tcp_segs_array[i].next = &tcp_segs_array[i + 1];
        }
        tcp_segs_array[segs_nr - 1].next = m_p_head;
        m_p_head = &tcp_segs_array[0];
        m_stats.total_segs += segs_nr;
        m_stats.expands++;
        g_global_stat_static.n_tcp_seg_pool_size += segs_nr;
    }
    return true;
}

void tcp_seg_pool::print_report(vlog_levels_t log_level /*= VLOG_DEBUG*/)
{
    vlog_printf(log_level, "TCP segments pool statistics:\n");
    vlog_printf(log_level, "  allocations=%u expands=%u total_segs=%u\n", m_stats.allocations,
                m_stats.expands, m_stats.total_segs);
}
