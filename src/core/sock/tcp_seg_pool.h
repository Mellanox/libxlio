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

#ifndef TCP_SEG_POOL_H
#define TCP_SEG_POOL_H

#include <utility>
#include "dev/allocator.h"
#include "utils/lock_wrapper.h"
#include "lwip/tcp_impl.h"

class tcp_seg_pool : lock_spin {
public:
    tcp_seg_pool();
    virtual ~tcp_seg_pool();

    std::pair<tcp_seg *, tcp_seg *> get_tcp_seg_list(uint32_t amount);
    tcp_seg *get_tcp_segs(uint32_t amount);
    void put_tcp_segs(tcp_seg *seg_list);

    static tcp_seg *split_tcp_segs(uint32_t count, tcp_seg *&tcp_seg_list, uint32_t &total_count);

private:
    bool expand();
    void print_report(vlog_levels_t log_level = VLOG_DEBUG);

    tcp_seg *m_p_head;
    xlio_allocator_heap m_allocator;

    struct {
        unsigned total_segs;
        unsigned allocations;
        unsigned expands;
    } m_stats;
};

/* Ring event completion */
struct ring_ec {
    //struct list_head list;
    struct xlio_socketxtreme_completion_t completion;
    ring_ec* next_ec;

    //inline void clear()
    //{
    //    INIT_LIST_HEAD(&list);
    //    memset(&completion, 0, sizeof(completion));
    //    last_buff_lst = NULL;
    //}
};

class ec_sockxtreme_pool : lock_spin {
public:
    ec_sockxtreme_pool();
    virtual ~ec_sockxtreme_pool();

    // Return first and last
    std::pair<ring_ec *, ring_ec *> get_ec_list(uint32_t amount);
    ring_ec *get_ecs(uint32_t amount);
    void put_ecs(ring_ec *ec_list);

    static ring_ec *split_ecs(uint32_t count, ring_ec *&ec_list, uint32_t &total_count);

private:
    bool expand();
    void print_report(vlog_levels_t log_level = VLOG_DEBUG);

    ring_ec *m_p_head;
    xlio_allocator_heap m_allocator;

    struct {
        unsigned total_ecs;
        unsigned allocations;
        unsigned expands;
    } m_stats;
};
extern ec_sockxtreme_pool *g_ec_pool;

extern tcp_seg_pool *g_tcp_seg_pool;

#endif
