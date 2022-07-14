/*
 * Copyright (c) 2001-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef BUFFER_POOL_H
#define BUFFER_POOL_H

#include "utils/lock_wrapper.h"
#include "vma/util/vma_stats.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/dev/allocator.h"
#include "vma/util/vma_list.h"
#include "vma/proto/mapping.h"
#include "vma/proto/mem_desc.h"

inline static void free_lwip_pbuf(struct pbuf_custom *pbuf_custom)
{
    mem_buf_desc_t *p_desc = (mem_buf_desc_t *)pbuf_custom;

    if (pbuf_custom->pbuf.desc.attr == PBUF_DESC_MDESC) {
        mem_desc *mdesc = (mem_desc *)pbuf_custom->pbuf.desc.mdesc;
        mdesc->put();
    } else if ((pbuf_custom->pbuf.type == PBUF_ZEROCOPY) &&
               (pbuf_custom->pbuf.desc.attr == PBUF_DESC_MAP)) {
        mapping_t *mapping = (mapping_t *)pbuf_custom->pbuf.desc.map;
        mapping->put();
    }

    if (p_desc->m_flags & mem_buf_desc_t::ZCOPY) {
        p_desc->tx.zc.callback(p_desc);
    }
    pbuf_custom->pbuf.flags = 0;
    pbuf_custom->pbuf.ref = 0;
    pbuf_custom->pbuf.desc.attr = PBUF_DESC_NONE;
}

class buffer_pool_area {
public:
    buffer_pool_area(size_t buffer_nr);
    ~buffer_pool_area();

    static inline size_t node_offset(void) { return NODE_OFFSET(buffer_pool_area, m_node); }

    /* Pointer to aligned area */
    void *m_area;
    size_t m_n_buffers;

private:
    /* Pointer to unaligned allocated block */
    void *m_ptr;

    list_node<buffer_pool_area, buffer_pool_area::node_offset> m_node;
};

typedef vma_list_t<buffer_pool_area, buffer_pool_area::node_offset> buffer_pool_area_list_t;

/**
 * A buffer pool which internally sorts the buffers.
 */
class buffer_pool {
public:
    buffer_pool(size_t buffer_count, size_t size, pbuf_free_custom_fn custom_free_function,
                alloc_t alloc_func = NULL, free_t free_func = NULL);
    ~buffer_pool();

    void register_memory(ib_ctx_handler *p_ib_ctx_h);
    void print_val_tbl();

    uint32_t find_lkey_by_ib_ctx_thread_safe(ib_ctx_handler *p_ib_ctx_h);

    /**
     * Get buffers from the pool - thread safe
     * @parma pDeque List to put the buffers.
     * @param desc_owner The new owner of the buffers.
     * @param count Number of buffers required.
     * @param lkey The registered memory lkey.
     * @return False if no buffers are available, else True.
     */
    bool get_buffers_thread_safe(descq_t &pDeque, ring_slave *desc_owner, size_t count,
                                 uint32_t lkey);

    /**
     * Return buffers to the pool.
     */
    void put_buffers_thread_safe(descq_t *buffers, size_t count);

    void put_buffers_thread_safe(mem_buf_desc_t *buff_list);
    void put_buffers_thread_safe(mem_buf_desc_t **buff_vec, size_t count);
    static void free_rx_lwip_pbuf_custom(struct pbuf *p_buff);
    static void free_tx_lwip_pbuf_custom(struct pbuf *p_buff);

    /**
     * Assume locked owner!!! Return buffers to the pool with ref_count check.
     */
    void put_buffers_after_deref_thread_safe(descq_t *pDeque);

    /**
     * @return Number of free buffers in the pool.
     */
    size_t get_free_count();

    void set_RX_TX_for_stats(bool rx);

private:
    lock_spin m_lock_spin;
    // XXX-dummy buffer list head and count
    // to be replaced with a bucket-sorted array

    size_t m_size; /* pool size in bytes */
    size_t m_n_buffers;
    size_t m_n_buffers_created;
    mem_buf_desc_t *m_p_head;

    bpool_stats_t *m_p_bpool_stat;
    bpool_stats_t m_bpool_stat_static;
    vma_allocator m_allocator;
    buffer_pool_area_list_t m_areas;
    pbuf_free_custom_fn m_custom_free_function;

    /**
     * Add a buffer to the pool
     */
    inline void put_buffer_helper(mem_buf_desc_t *buff);
    void expand(size_t count, void *data, size_t buf_size,
                pbuf_free_custom_fn custom_free_function);

    void buffersPanic();
    void put_buffers(descq_t *buffers, size_t count);
    inline void put_buffers(mem_buf_desc_t *buff_list);
    inline void put_buffers(mem_buf_desc_t **buff_vec, size_t count);

    /**
     * dtor
     */
    inline void free_bpool_resources();
};

extern buffer_pool *g_buffer_pool_rx_ptr;
extern buffer_pool *g_buffer_pool_rx_stride;
extern buffer_pool *g_buffer_pool_rx_rwqe;
extern buffer_pool *g_buffer_pool_tx;
extern buffer_pool *g_buffer_pool_zc;

#endif
