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

#include <mutex>
#include "buffer_pool.h"

#include <stdlib.h>
#include <sys/param.h> // for MIN

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "util/sys_vars.h"
#include "proto/mem_buf_desc.h"
#include "ib_ctx_handler_collection.h"

#define MODULE_NAME "bpool"

// A pointer to differentiate between g_buffer_pool_rx_stride and g_buffer_pool_rx_rwqe
// and create an abstraction to the layers above device layer for cases when Striding RQ is on/off.
// When Striding RQ is on, it points to g_buffer_pool_rx_stride since the upper layers work with
// strides. When Striding RQ is off, it points to g_buffer_pool_rx_rwqe since the upper layers work
// with RWQEs buffers themselves.
buffer_pool *g_buffer_pool_rx_ptr = NULL;

// This buffer-pool holds buffer descriptors which represent strides in strided RWQEs.
// These buffers descriptos do not actually own a buffer.
// Each such descriptor points into a portion of a buffer of a g_buffer_pool_rx_rwqe descriptor.
buffer_pool *g_buffer_pool_rx_stride = NULL;

// This buffer-pool holds the actual buffers for receive WQEs.
buffer_pool *g_buffer_pool_rx_rwqe = NULL;

// This buffer-pool holds the actual buffers for send WQEs.
buffer_pool *g_buffer_pool_tx = NULL;

// This buffer-pool holds buffer descriptors for zero copy TX.
// These buffer descriptors do not actually own a buffer.
buffer_pool *g_buffer_pool_zc = NULL;

buffer_pool_area::buffer_pool_area(size_t buffer_nr)
{
    m_ptr = malloc(sizeof(mem_buf_desc_t) * buffer_nr + MCE_ALIGNMENT);
    m_area = (void *)((unsigned long)((char *)m_ptr + MCE_ALIGNMENT) & (~MCE_ALIGNMENT));
    m_n_buffers = buffer_nr;
}

buffer_pool_area::~buffer_pool_area()
{
    free(m_ptr);
}

// inlining a function only help in case it come before using it...
inline void buffer_pool::put_buffer_helper(mem_buf_desc_t *buff)
{
#if VLIST_DEBUG
    if (buff->buffer_node.is_list_member()) {
        __log_info_warn("Buffer is already a member in a list! id=[%s]",
                        buff->buffer_node.list_id());
    }
#endif

    if (buff->lwip_pbuf.pbuf.desc.attr == PBUF_DESC_STRIDE) {
        mem_buf_desc_t *rwqe = reinterpret_cast<mem_buf_desc_t *>(buff->lwip_pbuf.pbuf.desc.mdesc);
        if (buff->rx.strides_num == rwqe->add_ref_count(-buff->rx.strides_num)) { // Is last stride.
            g_buffer_pool_rx_rwqe->put_buffers_thread_safe(rwqe);
        }
    }

    buff->p_next_desc = m_p_head;
    assert(buff->lwip_pbuf.pbuf.type != PBUF_ZEROCOPY || this == g_buffer_pool_zc ||
           g_buffer_pool_zc == NULL);
    free_lwip_pbuf(&buff->lwip_pbuf);
    m_p_head = buff;
    m_n_buffers++;
    m_p_bpool_stat->n_buffer_pool_size++;
}

void buffer_pool::expand(size_t count, void *data, size_t buf_size,
                         pbuf_free_custom_fn custom_free_function)
{
    buffer_pool_area *area;
    mem_buf_desc_t *desc;
    uint8_t *ptr_data;
    uint8_t *ptr_desc;

    area = new buffer_pool_area(count);
    assert(area != NULL);
    assert(area->m_area != NULL);
    m_areas.push_back(area);

    ptr_data = (uint8_t *)data;
    ptr_desc = (uint8_t *)area->m_area;

    for (size_t i = 0; i < count; ++i) {
        pbuf_type type = (ptr_data == NULL && custom_free_function == free_tx_lwip_pbuf_custom)
            ? PBUF_ZEROCOPY
            : PBUF_RAM;
        desc = new (ptr_desc) mem_buf_desc_t(ptr_data, buf_size, type, custom_free_function);
        put_buffer_helper(desc);
        ptr_desc += sizeof(mem_buf_desc_t);
        if (ptr_data != NULL) {
            ptr_data += buf_size;
        }
    }

    m_n_buffers_created += count;
}

/** Free-callback function to free a 'struct pbuf_custom_ref', called by
 * pbuf_free. */
void buffer_pool::free_rx_lwip_pbuf_custom(struct pbuf *p_buff)
{
    buffer_pool *pool = (p_buff->type == PBUF_ZEROCOPY) ? g_buffer_pool_zc : g_buffer_pool_rx_ptr;
    pool->put_buffers_thread_safe((mem_buf_desc_t *)p_buff);
}

void buffer_pool::free_tx_lwip_pbuf_custom(struct pbuf *p_buff)
{
    buffer_pool *pool = (p_buff->type == PBUF_ZEROCOPY) ? g_buffer_pool_zc : g_buffer_pool_tx;
    pool->put_buffers_thread_safe((mem_buf_desc_t *)p_buff);
}

buffer_pool::buffer_pool(size_t buffer_count, size_t buf_size,
                         pbuf_free_custom_fn custom_free_function, alloc_t alloc_func,
                         free_t free_func)
    : m_lock("buffer_pool")
    , m_n_buffers(0)
    , m_n_buffers_created(0)
    , m_p_head(NULL)
    , m_allocator(alloc_func, free_func)
{
    size_t sz_aligned_element = 0;
    void *ptr_data = NULL;
    void *data_block;

    __log_info_func("count = %d", buffer_count);

    m_custom_free_function = custom_free_function;
    m_p_bpool_stat = &m_bpool_stat_static;
    memset(m_p_bpool_stat, 0, sizeof(*m_p_bpool_stat));
    xlio_stats_instance_create_bpool_block(m_p_bpool_stat);

    if (buf_size == 0) {
        m_size = 0;
    } else if (buffer_count) {
        sz_aligned_element = (buf_size + MCE_ALIGNMENT) & (~MCE_ALIGNMENT);
        m_size = sz_aligned_element * buffer_count + MCE_ALIGNMENT;
    } else {
        m_size = buf_size;
    }

    data_block = m_size ? m_allocator.alloc_and_reg_mr(m_size, NULL) : NULL;
    assert(m_size == 0 || data_block != NULL);

    if (!buffer_count) {
        return;
    }

    if (m_size) {
        // Align pointers
        ptr_data = (void *)((unsigned long)((char *)data_block + MCE_ALIGNMENT) & (~MCE_ALIGNMENT));
    }

    expand(buffer_count, ptr_data, sz_aligned_element, custom_free_function);

    print_val_tbl();

    __log_info_func("done");
}

buffer_pool::~buffer_pool()
{
    free_bpool_resources();
}

void buffer_pool::free_bpool_resources()
{
    if (m_n_buffers == m_n_buffers_created) {
        __log_info_func("count %lu, missing %lu", m_n_buffers, m_n_buffers_created - m_n_buffers);
    } else {
        __log_info_dbg("count %lu, missing %lu", m_n_buffers, m_n_buffers_created - m_n_buffers);
    }

    xlio_stats_instance_remove_bpool_block(m_p_bpool_stat);

    while (!m_areas.empty()) {
        buffer_pool_area *area;
        area = m_areas.get_and_pop_front();
        delete area;
    }

    __log_info_func("done");
}

void buffer_pool::register_memory(ib_ctx_handler *p_ib_ctx_h)
{
    m_allocator.register_memory(m_size, p_ib_ctx_h, XLIO_IBV_ACCESS_LOCAL_WRITE);
}

void buffer_pool::print_val_tbl()
{
    __log_info_dbg("pool %p size: %ld buffers: %lu", this, m_size, m_n_buffers);
}

bool buffer_pool::get_buffers_thread_safe(descq_t &pDeque, ring_slave *desc_owner, size_t count,
                                          uint32_t lkey)
{
    std::lock_guard<decltype(m_lock)> lock(m_lock);

    mem_buf_desc_t *head;

    __log_info_funcall("requested %lu, present %lu, created %lu", count, m_n_buffers,
                       m_n_buffers_created);

    if (unlikely(m_n_buffers < count)) {
        if (m_size == 0) {
            __log_info_dbg("Expanding buffer_pool %p", this);
            m_p_bpool_stat->n_buffer_pool_expands++;
            expand(m_areas.front()->m_n_buffers, NULL, 0, m_custom_free_function);
            if (m_n_buffers >= count) {
                goto return_buffers;
            }
        }
        VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(VLOG_DEBUG, VLOG_FUNC,
                                          "ERROR! not enough buffers in the pool (requested: %lu, "
                                          "have: %lu, created: %lu, Buffer pool type: %s)",
                                          count, m_n_buffers, m_n_buffers_created,
                                          m_p_bpool_stat->is_rx ? "Rx" : "Tx");

        m_p_bpool_stat->n_buffer_pool_no_bufs++;
        return false;
    }

return_buffers:
    // pop buffers from the list
    m_n_buffers -= count;
    m_p_bpool_stat->n_buffer_pool_size -= count;
    while (count-- > 0) {
        // Remove from list
        head = m_p_head;
        m_p_head = m_p_head->p_next_desc;
        head->p_next_desc = NULL;

        // Init
        head->lkey = lkey;
        head->p_desc_owner = desc_owner;

        // Push to queue
        pDeque.push_back(head);
    }

    return true;
}

uint32_t buffer_pool::find_lkey_by_ib_ctx_thread_safe(ib_ctx_handler *p_ib_ctx_h)
{
    std::lock_guard<decltype(m_lock)> lock(m_lock);
    return m_allocator.find_lkey_by_ib_ctx(p_ib_ctx_h);
}

#if _BullseyeCoverage
#pragma BullseyeCoverage off
#endif

/*
 * this function is minimal C version of Floyd's cycle-finding algorithm
 * just for determining whether a circle exists or not.
 * Complexity is O(n)
 * see: http://en.wikipedia.org/wiki/Cycle_detection#Tortoise_and_hare
 */
bool isCircle(mem_buf_desc_t *pNode)
{
    if (!pNode) {
        return false;
    }

    mem_buf_desc_t *p1 = pNode;
    mem_buf_desc_t *p2 = pNode;

    while (p2->p_next_desc && p2->p_next_desc->p_next_desc) {
        p1 = p1->p_next_desc;
        p2 = p2->p_next_desc->p_next_desc;
        if (p1 == p2) {
            return true;
        }
    }
    return false;
}

typedef mem_buf_desc_t *Node;

static inline Node f(Node x)
{
    // NOTE: after we determined we have a circle, no need to check for nullity
    return x->p_next_desc;
}

// full version of Floyd's cycle-finding algorithm
// see: http://en.wikipedia.org/wiki/Cycle_detection#Tortoise_and_hare
void Floyd_LogCircleInfo(Node x0)
{

    // The main phase of the algorithm, finding a repetition x_mu = x_2mu
    // The hare moves twice as quickly as the tortoise
    Node tortoise = f(x0); // f(x0) is the element/node next to x0.
    Node hare = f(f(x0));
    while (tortoise != hare) {
        tortoise = f(tortoise);
        hare = f(f(hare));
    }

    // at this point tortoise position is equvi-distant from x0
    // and current hare position (which is the same as tortoise position).  This is
    // true because tortoise moved exactly half of the hare way.
    // so hare (set to tortoise-current position and move at tortoise speed) moving in
    // circle and tortoise (set to x0 ) moving towards circle, must meet at
    // current hare position (== current turtle position).  Realize that they move
    // in same speed, the first intersection will be the beginning of the circle.
    //

    // Find the position of the first repetition of length mu
    // The hare and tortoise move at the same speeds
    int mu = 0; // first index that starts the circle
    hare = tortoise;
    tortoise = x0;
    const int MAX_STEPS = 1 << 24; // = 16M
    while (tortoise != hare) {
        tortoise = f(tortoise);
        hare = f(hare);
        mu++;
        if (mu > MAX_STEPS) {
            break; // extra safety; not really needed
        }
    }

    // Find the length of the shortest cycle starting from x_mu
    // The hare moves while the tortoise stays still
    int lambda = 1; // circle length
    hare = f(tortoise);
    while (tortoise != hare) {
        hare = f(hare);
        lambda++;
        if (lambda > MAX_STEPS) {
            break; // extra safety; not really needed
        }
    }
    vlog_printf(VLOG_ERROR, "circle first index (mu) = %d, circle length (lambda) = %d\n", mu,
                lambda);
}

void buffer_pool::buffersPanic()
{
    if (isCircle(m_p_head)) {
        __log_info_err("Circle was found in buffer_pool");

        // print mu & lambda of circle
        Floyd_LogCircleInfo(m_p_head);
    } else {
        __log_info_info("no circle was found in buffer_pool");
    }

    // log backtrace
    const int MAX_BACKTRACE = 25;
    char **symbols;
    void *addresses[MAX_BACKTRACE];
    int count = backtrace(addresses, MAX_BACKTRACE);
    symbols = backtrace_symbols(addresses, count);
    for (int i = 0; i < count; ++i) {
        vlog_printf(VLOG_ERROR, "   %2d  %s\n", i, symbols[i]);
    }

    __log_info_panic("m_n_buffers(%lu) > m_n_buffers_created(%lu)", m_n_buffers,
                     m_n_buffers_created);
}

#if _BullseyeCoverage
#pragma BullseyeCoverage on
#endif

inline void buffer_pool::put_buffers(mem_buf_desc_t *buff_list)
{
    mem_buf_desc_t *next;
    __log_info_funcall("returning list, present %lu, created %lu", m_n_buffers,
                       m_n_buffers_created);
    while (buff_list) {
        next = buff_list->p_next_desc;
        put_buffer_helper(buff_list);
        buff_list = next;
    }

    if (unlikely(m_n_buffers > m_n_buffers_created)) {
        buffersPanic();
    }
}

inline void buffer_pool::put_buffers(mem_buf_desc_t **buff_vec, size_t count)
{
    __log_info_funcall("returning vector, present %zu, created %zu, returned %zu", m_n_buffers,
                       m_n_buffers_created, count);
    while (count-- > 0U) {
        put_buffer_helper(buff_vec[count]);
    }

    if (unlikely(m_n_buffers > m_n_buffers_created)) {
        buffersPanic();
    }
}

void buffer_pool::put_buffers_thread_safe(mem_buf_desc_t *buff_list)
{
    std::lock_guard<decltype(m_lock)> lock(m_lock);
    put_buffers(buff_list);
}

void buffer_pool::put_buffers_thread_safe(mem_buf_desc_t **buff_vec, size_t count)
{
    std::lock_guard<decltype(m_lock)> lock(m_lock);
    put_buffers(buff_vec, count);
}

void buffer_pool::put_buffers(descq_t *buffers, size_t count)
{
    mem_buf_desc_t *buff_list, *next;
    __log_info_funcall("returning %lu, present %lu, created %lu", count, m_n_buffers,
                       m_n_buffers_created);
    for (size_t amount = std::min(count, buffers->size()); amount > 0; amount--) {
        buff_list = buffers->get_and_pop_back();
        while (buff_list) {
            next = buff_list->p_next_desc;
            put_buffer_helper(buff_list);
            buff_list = next;
        }
    }

    if (unlikely(m_n_buffers > m_n_buffers_created)) {
        buffersPanic();
    }
}

void buffer_pool::put_buffers_thread_safe(descq_t *buffers, size_t count)
{
    std::lock_guard<decltype(m_lock)> lock(m_lock);
    put_buffers(buffers, count);
}

void buffer_pool::put_buffers_after_deref_thread_safe(descq_t *pDeque)
{
    std::lock_guard<decltype(m_lock)> lock(m_lock);
    while (!pDeque->empty()) {
        mem_buf_desc_t *list = pDeque->get_and_pop_front();
        if (list->dec_ref_count() <= 1 && (list->lwip_pbuf.pbuf.ref-- <= 1)) {
            put_buffers(list);
        }
    }
}

size_t buffer_pool::get_free_count()
{
    return m_n_buffers;
}

void buffer_pool::set_RX_TX_for_stats(bool rx)
{
    if (rx) {
        m_p_bpool_stat->is_rx = true;
    } else {
        m_p_bpool_stat->is_tx = true;
    }
}
