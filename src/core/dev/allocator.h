/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef _XLIO_DEV_ALLOCATOR_H_
#define _XLIO_DEV_ALLOCATOR_H_

#include <stddef.h>
#include <stdint.h>

#include <vector>
#include <unordered_map>

#include "utils/lock_wrapper.h"
#include "util/sys_vars.h" // alloc_mode_t, alloc_t, free_t

#include <doca_mmap.h>

// Forward declarations
class ib_ctx_handler;

class xlio_allocator {
public:
    xlio_allocator();
    xlio_allocator(alloc_mode_t preferable_type);
    xlio_allocator(alloc_t alloc_func, free_t free_func);
    virtual ~xlio_allocator();

    void *alloc(size_t size);
    void *alloc_aligned(size_t size, size_t align);

    void *alloc_huge(size_t size);
    void *alloc_posix_memalign(size_t size, size_t align);
    void *alloc_malloc(size_t size);

    void dealloc();

    size_t size() { return m_size; }
    size_t page_size() { return m_page_size; }
    void *data() { return m_data; }

private:
    void print_hugepages_warning(size_t requested_size);

protected:
    alloc_mode_t m_type;
    void *m_data;
    size_t m_size;
    size_t m_page_size;

private:
    alloc_t m_memalloc;
    free_t m_memfree;
};

class xlio_registrator {
public:
    xlio_registrator();
    virtual ~xlio_registrator();

    bool register_memory(void *data, size_t size);
    void deregister_memory();

#ifdef DEFINED_DPCP_PATH_RX_OR_TX
public:
    bool register_memory_dpcp(void *data, size_t size);
    void deregister_memory_dpcp();
    uint32_t find_lkey_by_ib_ctx(ib_ctx_handler *p_ib_ctx_h) const;

private:
    std::unordered_map<ib_ctx_handler *, uint32_t> m_lkey_map_ib_ctx;
#endif // DEFINED_DPCP_PATH_RX_OR_TX

#ifndef DEFINED_DPCP_PATH_RX_AND_TX
public:
    bool register_memory_doca(void *data, size_t size);
    void deregister_memory_doca();
    doca_mmap *get_doca_mmap() const { return m_p_doca_mmap; };

private:
    doca_mmap *m_p_doca_mmap = nullptr;
#endif // !DEFINED_DPCP_PATH_RX_AND_TX
};

class xlio_allocator_hw : public xlio_allocator, public xlio_registrator {
public:
    xlio_allocator_hw();
    xlio_allocator_hw(alloc_mode_t preferable_type);
    xlio_allocator_hw(alloc_t alloc_func, free_t free_func);
    virtual ~xlio_allocator_hw();

    bool register_memory();
};

class xlio_heap {
public:
    static xlio_heap *get(alloc_t alloc_func, free_t free_func, bool hw);
    static void initialize();
    static void finalize();

    void *alloc(size_t &size);
    bool register_memory();
#ifdef DEFINED_DPCP_PATH_RX_OR_TX
    uint32_t find_lkey_by_ib_ctx(ib_ctx_handler *p_ib_ctx_h) const;
#endif // DEFINED_DPCP_PATH_RX_OR_TX
#ifndef DEFINED_DPCP_PATH_RX_AND_TX
    doca_mmap *get_doca_mmap() const;
#endif // !DEFINED_DPCP_PATH_RX_AND_TX

    bool is_hw() const { return m_b_hw; }

private:
    xlio_heap(alloc_t alloc_func, free_t free_func, bool hw);
    ~xlio_heap();
    bool expand(size_t size = 0);

    lock_mutex m_lock;
    std::vector<xlio_allocator_hw *> m_blocks;
    unsigned long m_latest_offset;

    bool m_b_hw;
    alloc_t m_p_alloc_func;
    free_t m_p_free_func;
};

class xlio_allocator_heap {
public:
    xlio_allocator_heap(alloc_t alloc_func, free_t free_func, bool hw = false);
    xlio_allocator_heap(bool hw = false);
    ~xlio_allocator_heap();

    void *alloc(size_t &size);
    bool register_memory();
#ifdef DEFINED_DPCP_PATH_RX_OR_TX
    uint32_t find_lkey_by_ib_ctx(ib_ctx_handler *p_ib_ctx_h) const;
#endif // DEFINED_DPCP_PATH_RX_OR_TX
#ifndef DEFINED_DPCP_PATH_RX_AND_TX
    doca_mmap *get_doca_mmap() const { return m_p_heap->get_doca_mmap(); }
#endif // !DEFINED_DPCP_PATH_RX_AND_TX

private:
    xlio_heap *m_p_heap;
    /* Currently we don't support free, so no need to track allocated blocks */
};

#endif /* _XLIO_DEV_ALLOCATOR_H_ */
