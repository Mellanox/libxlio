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

#ifndef TCP_SEG_POOL_H
#define TCP_SEG_POOL_H

#include <utility>
#include "utils/lock_wrapper.h"
#include "lwip/tcp_impl.h"

class tcp_seg_pool : lock_spin {
public:
    tcp_seg_pool(uint32_t size);
    virtual ~tcp_seg_pool();

    std::pair<tcp_seg *, tcp_seg *> get_tcp_seg_list(uint32_t amount);
    tcp_seg *get_tcp_segs(uint32_t amount);
    void put_tcp_segs(tcp_seg *seg_list);

    static tcp_seg *split_tcp_segs(uint32_t count, tcp_seg *&tcp_seg_list, uint32_t &total_count);

private:
    tcp_seg *m_tcp_segs_array;
    tcp_seg *m_p_head;
};

extern tcp_seg_pool *g_tcp_seg_pool;

#endif
