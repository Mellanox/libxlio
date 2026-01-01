/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef _XLIO_DEV_ALLOCATOR_H_
#define _XLIO_DEV_ALLOCATOR_H_

#include <stddef.h>
#include <stdint.h>

#include <vector>
#include <unordered_map>

#include "utils/lock_wrapper.h"
#include "util/sys_vars.h" // alloc_mode_t, alloc_t, free_t

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

    bool register_memory(void *data, size_t size, ib_ctx_handler *p_ib_ctx_h, uint64_t access);
    bool register_memory(void *data, size_t size, ib_ctx_handler *p_ib_ctx_h);
    void deregister_memory();

    uint32_t find_lkey_by_ib_ctx(ib_ctx_handler *p_ib_ctx_h) const;

private:
    uint32_t register_memory_single(void *data, size_t size, ib_ctx_handler *p_ib_ctx_h,
                                    uint64_t access);

    std::unordered_map<ib_ctx_handler *, uint32_t> m_lkey_map_ib_ctx;
};

class xlio_allocator_hw : public xlio_allocator, public xlio_registrator {
public:
    xlio_allocator_hw();
    xlio_allocator_hw(alloc_mode_t preferable_type);
    xlio_allocator_hw(alloc_t alloc_func, free_t free_func);
    virtual ~xlio_allocator_hw();

    void *alloc_and_reg_mr(size_t size, ib_ctx_handler *p_ib_ctx_h, uint64_t access);
    void *alloc_and_reg_mr(size_t size, ib_ctx_handler *p_ib_ctx_h);
    bool register_memory(ib_ctx_handler *p_ib_ctx_h);
};

class xlio_heap {
public:
    static xlio_heap *get(alloc_t alloc_func, free_t free_func, bool hw);
    static void initialize();
    static void finalize();

    void *alloc(size_t &size);
    bool register_memory(ib_ctx_handler *p_ib_ctx_h);
    uint32_t find_lkey_by_ib_ctx(ib_ctx_handler *p_ib_ctx_h) const;

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
    void *alloc_and_reg_mr(size_t &size, ib_ctx_handler *p_ib_ctx_h);
    bool register_memory(ib_ctx_handler *p_ib_ctx_h);
    uint32_t find_lkey_by_ib_ctx(ib_ctx_handler *p_ib_ctx_h) const;

private:
    xlio_heap *m_p_heap;
    /* Currently we don't support free, so no need to track allocated blocks */
};

#endif /* _XLIO_DEV_ALLOCATOR_H_ */
