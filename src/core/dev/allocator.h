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

#ifndef _XLIO_DEV_ALLOCATOR_H_
#define _XLIO_DEV_ALLOCATOR_H_

#include <stddef.h>
#include <stdint.h>

#include <unordered_map>

#include "util/sys_vars.h" // alloc_mode_t, alloc_t, free_t

// Forward declarations
class ib_ctx_handler;

class xlio_allocator {
public:
    xlio_allocator();
    xlio_allocator(alloc_mode_t preferable_type);
    xlio_allocator(alloc_t alloc_func, free_t free_func);
    virtual ~xlio_allocator();

    static void initialize();

    void *alloc(size_t size);
    void *alloc_aligned(size_t size, size_t align);

    void *alloc_huge(size_t size);
    void *alloc_posix_memalign(size_t size, size_t align);
    void *alloc_malloc(size_t size);

    void dealloc();

private:
    void print_hugepages_warning();

protected:
    alloc_mode_t m_type;
    void *m_data;
    size_t m_size;

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
    xlio_allocator_hw(alloc_t alloc_func, free_t free_func);
    virtual ~xlio_allocator_hw();

    void *alloc_and_reg_mr(size_t size, ib_ctx_handler *p_ib_ctx_h, uint64_t access);
    void *alloc_and_reg_mr(size_t size, ib_ctx_handler *p_ib_ctx_h);
    bool register_memory(ib_ctx_handler *p_ib_ctx_h);
};

#endif /* _XLIO_DEV_ALLOCATOR_H_ */
