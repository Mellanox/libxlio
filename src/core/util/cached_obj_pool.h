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

#ifndef CACHED_OBJ_POOL_H
#define CACHED_OBJ_POOL_H

#include <utility>
#include "dev/allocator.h"
#include "utils/lock_wrapper.h"

template <typename T> class cached_obj_pool : lock_spin {
public:
    cached_obj_pool(const char *pool_name, size_t alloc_batch, uint32_t &global_obj_pool_size_ref,
                    uint32_t &global_obj_pool_no_objs_ref);
    ~cached_obj_pool() override;

    std::pair<T *, T *> get_obj_list(uint32_t amount);
    T *get_objs(uint32_t amount);
    void put_objs(T *obj_list);

    static T *split_obj_list(uint32_t count, T *&obj_list, uint32_t &total_count);

protected:
    bool expand();

    T *m_p_head = nullptr;
    xlio_allocator_heap m_allocator;

    struct {
        unsigned total_objs;
        unsigned allocations;
        unsigned expands;
        uint32_t &global_obj_pool_size;
        uint32_t &global_obj_pool_no_objs;
    } m_stats;

    const size_t m_alloc_batch;
    const char *m_pool_name;
};

template <typename T>
cached_obj_pool<T>::cached_obj_pool(const char *pool_name, size_t alloc_batch,
                                    uint32_t &global_obj_pool_size_ref,
                                    uint32_t &global_obj_pool_no_objs_ref)
    : m_allocator(false)
    , m_stats {0U, 0U, 0U, global_obj_pool_size_ref, global_obj_pool_no_objs_ref}
    , m_alloc_batch(alloc_batch)
    , m_pool_name(pool_name)
{
    expand();
}

template <typename T> cached_obj_pool<T>::~cached_obj_pool()
{
    __log_header_dbg("%s pool statistics:\n", m_pool_name);
    __log_header_dbg("  allocations=%u expands=%u total_objs=%u\n", m_stats.allocations,
                     m_stats.expands, m_stats.total_objs);
}

template <typename T> T *cached_obj_pool<T>::get_objs(uint32_t amount)
{
    return get_obj_list(amount).first;
}

template <typename T> std::pair<T *, T *> cached_obj_pool<T>::get_obj_list(uint32_t amount)
{
    uint32_t count;
    T *head, *next, *prev;
    if (unlikely(amount <= 0)) {
        return std::make_pair(nullptr, nullptr);
    }
    lock();
repeat:
    count = amount;
    head = next = m_p_head;
    prev = nullptr;
    while (count > 0 && next) {
        prev = next;
        next = next->next;
        count--;
    }
    if (count) {
        // Ran out of objects
        if (expand()) {
            goto repeat;
        }
        m_stats.global_obj_pool_no_objs++;
        unlock();
        return std::make_pair(nullptr, nullptr);
    }
    prev->next = nullptr;
    m_p_head = next;
    m_stats.allocations++;
    m_stats.global_obj_pool_size -= amount;
    unlock();

    return std::make_pair(head, prev);
}

template <typename T> void cached_obj_pool<T>::put_objs(T *obj_list)
{
    if (unlikely(!obj_list)) {
        return;
    }

    T *next = obj_list;
    int i;
    for (i = 1; next->next; i++) {
        next = next->next;
    }

    lock();
    next->next = m_p_head;
    m_p_head = obj_list;
    m_stats.global_obj_pool_size += i;
    unlock();
}

// Splitting obj list such that first 'count' objs are returned and 'obj_list'
// is updated to point to the remaining objs.
// The length of obj_list is assumed to be at least 'count' long.
template <typename T>
T *cached_obj_pool<T>::split_obj_list(uint32_t count, T *&obj_list, uint32_t &total_count)
{
    T *head = obj_list;
    T *last = head;
    total_count -= count;
    while (count-- > 1U) {
        last = last->next;
    }

    obj_list = last->next;
    last->next = nullptr;
    return head;
}

template <typename T> bool cached_obj_pool<T>::expand()
{
    size_t size = sizeof(T) * m_alloc_batch;
    T *objs_array = (T *)m_allocator.alloc(size);
    if (!objs_array) {
        __log_header_dbg("Cached pool failed to allocate objects (%s)\n", m_pool_name);
        return false;
    }

    // Allocator can allocate more memory than requested - utilize it.
    size_t objs_nr = size / sizeof(T);

    if (objs_nr > 0) {
        memset(objs_array, 0, size);
        for (size_t i = 0; i < objs_nr - 1; i++) {
            objs_array[i].next = &objs_array[i + 1];
        }
        objs_array[objs_nr - 1].next = m_p_head;
        m_p_head = &objs_array[0];
        m_stats.total_objs += objs_nr;
        m_stats.expands++;
        m_stats.global_obj_pool_size += objs_nr;
    }
    return true;
}

#endif
