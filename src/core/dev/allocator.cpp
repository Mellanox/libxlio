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

#include "allocator.h"

#include <stdlib.h>

#include "vlogger/vlogger.h"
#include "ib_ctx_handler_collection.h"
#include "util/hugepage_mgr.h"
#include "util/vtypes.h"

#define MODULE_NAME "allocator"

xlio_allocator::xlio_allocator()
    : xlio_allocator(nullptr, nullptr)
{
}

xlio_allocator::xlio_allocator(alloc_mode_t preferable_type)
    : xlio_allocator()
{
    if (m_type != ALLOC_TYPE_ANON) {
        // Don't override ANON type since it can disable hugepages intentionally.
        m_type = preferable_type;
    }
}

xlio_allocator::xlio_allocator(alloc_t alloc_func, free_t free_func)
{
    m_type = static_cast<alloc_mode_t>(safe_mce_sys().mem_alloc_type);
    m_data = nullptr;
    m_size = 0;
    m_memalloc = alloc_func;
    m_memfree = free_func;
    if (m_memalloc && m_memfree) {
        m_type = ALLOC_TYPE_EXTERNAL;
        __log_info_dbg("allocator uses external functions to allocate and free memory");
    }
}

/*virtual*/
xlio_allocator::~xlio_allocator()
{
    dealloc();
}

void *xlio_allocator::alloc(size_t size)
{
    __log_info_dbg("Allocating %zu bytes", size);

    switch (m_type) {
    case ALLOC_TYPE_PREFER_HUGE:
        // Fallthrough
    case ALLOC_TYPE_HUGEPAGES:
        m_data = alloc_huge(size);
        if (m_data) {
            break;
        }
        // Fallthrough
    case ALLOC_TYPE_ANON:
        long page_size;
        page_size = sysconf(_SC_PAGESIZE);
        if (page_size > 0) {
            m_data = alloc_posix_memalign(size, (size_t)page_size);
        }
        if (!m_data) {
            m_data = alloc_malloc(size);
        }
        break;
    case ALLOC_TYPE_EXTERNAL:
        if (m_memalloc) {
            m_data = m_memalloc(size);
            m_size = size;
        }
        if (!m_data) {
            // We don't try other allocation methods, because this can affect application.
            __log_info_warn("Failed allocating memory using external functions");
        }
        break;
    default:
        __log_info_err("Cannot allocate memory: unexpected type (%d)", m_type);
    }

    if (m_data) {
        __log_info_dbg("Allocated successfully: type=%d ptr=%p size=%zu", m_type, m_data, m_size);
    }
    return m_data;
}

void *xlio_allocator::alloc_aligned(size_t size, size_t align)
{
    __log_info_dbg("Allocating %zu bytes aligned to %zu", size, align);

    if (m_type == ALLOC_TYPE_HUGEPAGES || m_type == ALLOC_TYPE_PREFER_HUGE) {
        // We should check that hugepage provides requested alignment, however,
        // it is unlikely to have alignment bigger than a hugepage (at least 2MB).
        m_data = alloc_huge(size);
    }
    if (!m_data) {
        m_data = alloc_posix_memalign(size, align);
    }
    if (m_data) {
        __log_info_dbg("Allocated successfully: type=%d ptr=%p size=%zu alignment=%zu", m_type,
                       m_data, m_size, align);
    }
    return m_data;
}

void *xlio_allocator::alloc_huge(size_t size)
{
    __log_info_dbg("Allocating %zu bytes in huge tlb using mmap", size);

    size_t actual_size = size;
    m_data = g_hugepage_mgr.alloc_hugepages(actual_size);
    if (!m_data && g_hugepage_mgr.get_default_hugepage() && m_type == ALLOC_TYPE_HUGEPAGES) {
        // Print a warning message on allocation error if hugepages are supported
        // and this is not a fallback from a different allocation method.
        print_hugepages_warning(size);
    }
    if (m_data) {
        m_type = ALLOC_TYPE_HUGEPAGES;
        m_size = actual_size;
    }
    return m_data;
}

void *xlio_allocator::alloc_posix_memalign(size_t size, size_t align)
{
    int rc = posix_memalign(&m_data, align, size);
    if (rc == 0 && m_data) {
        m_type = ALLOC_TYPE_ANON;
        m_size = size;
    } else {
        m_data = nullptr;
        __log_info_dbg("posix_memalign failed: error=%d size=%zu align=%zu", rc, size, align);
    }
    return m_data;
}

void *xlio_allocator::alloc_malloc(size_t size)
{
    m_data = malloc(size);
    if (m_data) {
        m_type = ALLOC_TYPE_ANON;
        m_size = size;
    } else {
        __log_info_dbg("malloc failed: errno=%d size=%zu", errno, size);
    }
    return m_data;
}

void xlio_allocator::dealloc()
{
    if (!m_data) {
        return;
    }
    __log_info_dbg("Freeing memory: type=%d ptr=%p size=%zu", m_type, m_data, m_size);

    switch (m_type) {
    case ALLOC_TYPE_HUGEPAGES:
        g_hugepage_mgr.dealloc_hugepages(m_data, m_size);
        break;
    case ALLOC_TYPE_ANON:
        free(m_data);
        break;
    case ALLOC_TYPE_EXTERNAL:
        if (m_memfree) {
            m_memfree(m_data);
        }
        break;
    default:
        __log_info_err("Cannot free memory: unknown allocator type (%d)", m_type);
    }
    m_data = nullptr;
}

void xlio_allocator::print_hugepages_warning(size_t requested_size)
{
    static bool s_printed_once = false;

    if (!s_printed_once) {
        s_printed_once = true;
        vlog_printf(VLOG_WARNING, "************************************************************\n");
        vlog_printf(VLOG_WARNING, "NO IMMEDIATE ACTION NEEDED!\n");
        vlog_printf(VLOG_WARNING, "Not enough suitable hugepages to allocate %zu kB.\n",
                    requested_size / 1024U);
        vlog_printf(VLOG_WARNING, "Allocation will be done with regular pages.\n");
        vlog_printf(VLOG_WARNING, "To avoid this message, either increase number of hugepages\n");
        vlog_printf(VLOG_WARNING, "or switch to a different memory allocation type:\n");
        vlog_printf(VLOG_WARNING, "  %s=ANON\n", SYS_VAR_MEM_ALLOC_TYPE);

        g_hugepage_mgr.print_report(true);

        vlog_printf(VLOG_WARNING, "************************************************************\n");
    } else {
        __log_info_dbg("Failed to allocated %zu kB with hugepages.", requested_size / 1024U);
    }
}

xlio_registrator::xlio_registrator()
{
}

/*virtual*/
xlio_registrator::~xlio_registrator()
{
    deregister_memory();
}

uint32_t xlio_registrator::register_memory_single(void *data, size_t size,
                                                  ib_ctx_handler *p_ib_ctx_h, uint64_t access)
{
    uint32_t lkey;

    assert(p_ib_ctx_h);

    if (unlikely(!data)) {
        return LKEY_ERROR;
    }

    lkey = p_ib_ctx_h->mem_reg(data, size, access);
    if (lkey == LKEY_ERROR) {
        __log_info_warn("Failure during memory registration on dev %s addr=%p size=%zu",
                        p_ib_ctx_h->get_ibname(), data, size);
        __log_info_warn("This might happen due to low MTT entries. "
                        "Please refer to README for more info");
        return LKEY_ERROR;
    }

    m_lkey_map_ib_ctx[p_ib_ctx_h] = lkey;
    errno = 0; // ibv_reg_mr() set errno=12 despite successful returning
    __log_info_dbg("Registered memory on dev %s addr=%p size=%zu", p_ib_ctx_h->get_ibname(), data,
                   size);

    return lkey;
}

bool xlio_registrator::register_memory(void *data, size_t size, ib_ctx_handler *p_ib_ctx_h,
                                       uint64_t access)
{
    uint32_t lkey;

    if (p_ib_ctx_h) {
        // Specific ib context path
        lkey = register_memory_single(data, size, p_ib_ctx_h, access);
        return lkey != LKEY_ERROR;
    }

    // Path for all ib contextes
    ib_context_map_t *ib_ctx_map = g_p_ib_ctx_handler_collection->get_ib_cxt_list();
    if (likely(ib_ctx_map)) {
        for (const auto &ib_ctx_key_val : *ib_ctx_map) {
            p_ib_ctx_h = ib_ctx_key_val.second;
            lkey = register_memory_single(data, size, p_ib_ctx_h, access);

            if (lkey == LKEY_ERROR) {
                deregister_memory();
                return false;
            }
        }
    }
    return true;
}

bool xlio_registrator::register_memory(void *data, size_t size, ib_ctx_handler *p_ib_ctx_h)
{
    return register_memory(data, size, p_ib_ctx_h, XLIO_IBV_ACCESS_LOCAL_WRITE);
}

void xlio_registrator::deregister_memory()
{
    ib_ctx_handler *p_ib_ctx_h;
    ib_context_map_t *ib_ctx_map;
    uint32_t lkey;

    ib_ctx_map = g_p_ib_ctx_handler_collection->get_ib_cxt_list();
    if (ib_ctx_map) {
        for (const auto &ib_ctx_key_val : *ib_ctx_map) {
            p_ib_ctx_h = ib_ctx_key_val.second;
            lkey = find_lkey_by_ib_ctx(p_ib_ctx_h);
            if (lkey != LKEY_ERROR) {
                p_ib_ctx_h->mem_dereg(lkey);
                m_lkey_map_ib_ctx.erase(p_ib_ctx_h);
            }
        }
    }
    m_lkey_map_ib_ctx.clear();
}

uint32_t xlio_registrator::find_lkey_by_ib_ctx(ib_ctx_handler *p_ib_ctx_h) const
{
    auto iter = m_lkey_map_ib_ctx.find(p_ib_ctx_h);

    return (iter != m_lkey_map_ib_ctx.end()) ? iter->second : LKEY_ERROR;
}

xlio_allocator_hw::xlio_allocator_hw()
    : xlio_allocator()
    , xlio_registrator()
{
}

xlio_allocator_hw::xlio_allocator_hw(alloc_t alloc_func, free_t free_func)
    : xlio_allocator(alloc_func, free_func)
    , xlio_registrator()
{
}

/*virtual*/
xlio_allocator_hw::~xlio_allocator_hw()
{
}

void *xlio_allocator_hw::alloc_and_reg_mr(size_t size, ib_ctx_handler *p_ib_ctx_h, uint64_t access)
{
    m_data = alloc(size);
    if (!m_data) {
        return nullptr;
    }

    if (!xlio_registrator::register_memory(m_data, m_size, p_ib_ctx_h, access)) {
        dealloc();
    }
    return m_data;
}

void *xlio_allocator_hw::alloc_and_reg_mr(size_t size, ib_ctx_handler *p_ib_ctx_h)
{
    return alloc_and_reg_mr(size, p_ib_ctx_h, XLIO_IBV_ACCESS_LOCAL_WRITE);
}

bool xlio_allocator_hw::register_memory(ib_ctx_handler *p_ib_ctx_h)
{
    return m_data && xlio_registrator::register_memory(m_data, m_size, p_ib_ctx_h);
}
