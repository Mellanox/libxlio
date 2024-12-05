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

#include "allocator.h"

#include <stdlib.h>

#include <mutex>

#include "vlogger/vlogger.h"
#include "ib_ctx_handler_collection.h"
#include "util/hugepage_mgr.h"
#include "util/vtypes.h"
#include "xlio.h"
#include <doca_mmap.h>

#define MODULE_NAME "allocator"
DOCA_LOG_REGISTER(allocator);

// See description at the xlio_memory_cb_t definition.
xlio_memory_cb_t g_user_memory_cb = nullptr;

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
    m_page_size = 0;
    m_memalloc = alloc_func;
    m_memfree = free_func;
    if (m_memalloc) {
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

    if (m_data) {
        return nullptr;
    }

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

    if (m_data) {
        return nullptr;
    }

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
    m_data = g_hugepage_mgr.alloc_hugepages(actual_size, m_page_size);
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
        __log_warn("************************************************************\n");
        __log_warn("NO IMMEDIATE ACTION NEEDED!\n");
        __log_warn("Not enough suitable hugepages to allocate %zu kB.\n", requested_size / 1024U);
        __log_warn("Allocation will be done with regular pages.\n");
        __log_warn("To avoid this message, either increase number of hugepages\n");
        __log_warn("or switch to a different memory allocation type:\n");
        __log_warn("  %s=ANON\n", SYS_VAR_MEM_ALLOC_TYPE);

        g_hugepage_mgr.print_report(true);

        __log_warn("************************************************************\n");
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

bool xlio_registrator::register_memory(void *data, size_t size)
{
    if (m_p_doca_mmap) {
        __log_info_err("Memory already registered, doca_mmap already exists=%p",
                       (void *)m_p_doca_mmap);
        return false;
    }

    struct doca_dev *new_dev {nullptr};

    doca_error_t rc = doca_mmap_create(&m_p_doca_mmap);
    if (DOCA_IS_ERROR(rc)) {
        PRINT_DOCA_ERR(__log_info_err, rc, "doca_mmap_create");
        return false;
    }

    ib_context_map_t *ib_ctx_map = g_p_ib_ctx_handler_collection->get_ib_cxt_list();
    uint32_t num_of_devices = ib_ctx_map->size();
    rc = doca_mmap_set_max_num_devices(m_p_doca_mmap, num_of_devices);
    if (DOCA_IS_ERROR(rc)) {
        PRINT_DOCA_ERR(__log_info_err, rc, "doca_mmap_set_max_num_devices");
        return false;
    }

    for (const auto &ib_ctx_key_val : *ib_ctx_map) {
        ib_ctx_handler *p_ib_ctx_h = ib_ctx_key_val.second;
        // keep ibv mem_reg to allow doca integration with working traffic
        uint32_t lkey = p_ib_ctx_h->mem_reg(data, size, XLIO_IBV_ACCESS_LOCAL_WRITE);
        m_lkey_map_ib_ctx[p_ib_ctx_h] = lkey;

        if ((new_dev = p_ib_ctx_h->get_doca_device())) {
            rc = doca_mmap_add_dev(m_p_doca_mmap, new_dev);
            if (DOCA_IS_ERROR(rc)) {
                PRINT_DOCA_ERR(__log_info_err, rc, "doca_mmap_add_dev");
                return false;
            }
        }
    }

    rc = doca_mmap_set_memrange(m_p_doca_mmap, data, size);
    if (DOCA_IS_ERROR(rc)) {
        PRINT_DOCA_ERR(__log_info_err, rc, "doca_mmap_set_memrange");
        return false;
    }

    rc = doca_mmap_enable_thread_safety(m_p_doca_mmap);
    if (DOCA_IS_ERROR(rc)) {
        PRINT_DOCA_ERR(__log_info_err, rc, "doca_mmap_enable_thread_safety");
        return false;
    }

    rc = doca_mmap_start(m_p_doca_mmap);
    if (DOCA_IS_ERROR(rc)) {
        PRINT_DOCA_ERR(__log_info_err, rc, "doca_mmap_start");
        return false;
    }

    return true;
}

void xlio_registrator::deregister_memory()
{
    uint32_t lkey;
    ib_ctx_handler *p_ib_ctx_h;

    for (const auto &ib_ctx_key_val : m_lkey_map_ib_ctx) {
        p_ib_ctx_h = ib_ctx_key_val.first;
        lkey = find_lkey_by_ib_ctx(p_ib_ctx_h);
        if (lkey != LKEY_ERROR) {
            p_ib_ctx_h->mem_dereg(lkey);
        }
    }

    m_lkey_map_ib_ctx.clear();

    if (!m_p_doca_mmap) {
        return;
    }

    doca_error_t rc = doca_mmap_stop(m_p_doca_mmap);
    if (DOCA_IS_ERROR(rc)) {
        PRINT_DOCA_ERR(__log_info_err, rc, "doca_mmap_stop");
    }

    rc = doca_mmap_destroy(m_p_doca_mmap);
    if (DOCA_IS_ERROR(rc)) {
        PRINT_DOCA_ERR(__log_info_warn, rc, "doca_mmap_destroy");
    }
    m_p_doca_mmap = nullptr;
}

uint32_t xlio_registrator::find_lkey_by_ib_ctx(ib_ctx_handler *p_ib_ctx_h) const
{
    auto iter = m_lkey_map_ib_ctx.find(p_ib_ctx_h);
    uint32_t ret = (iter != m_lkey_map_ib_ctx.end()) ? iter->second : LKEY_ERROR;
    return ret;
}

xlio_allocator_hw::xlio_allocator_hw()
    : xlio_allocator()
    , xlio_registrator()
{
}

xlio_allocator_hw::xlio_allocator_hw(alloc_mode_t preferable_type)
    : xlio_allocator(preferable_type)
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

bool xlio_allocator_hw::register_memory()
{
    return m_data && xlio_registrator::register_memory(m_data, m_size);
}

/*
 * xlio_allocator_heap implementation
 */

struct heap_key {
    alloc_t alloc_func;
    free_t free_func;
    bool hw;

    bool operator==(const heap_key &key) const
    {
        return key.alloc_func == alloc_func && key.free_func == free_func && key.hw == hw;
    }
};

namespace std {
template <> class hash<heap_key> {
public:
    size_t operator()(const heap_key &key) const
    {
        return ((size_t)key.alloc_func ^ (size_t)key.free_func ^ key.hw);
    }
};
} // namespace std

static std::unordered_map<heap_key, xlio_heap *> s_heap_map;
static lock_mutex s_heap_lock;
static size_t s_pagesize;

/*static*/
xlio_heap *xlio_heap::get(alloc_t alloc_func, free_t free_func, bool hw)
{
    std::lock_guard<decltype(s_heap_lock)> lock(s_heap_lock);

    if (!alloc_func) {
        // Free is pointless without allocation function. Reset it for the key.
        free_func = nullptr;
    }

    heap_key key = {.alloc_func = alloc_func, .free_func = free_func, .hw = hw};
    auto item = s_heap_map.find(key);
    xlio_heap *heap = (item == s_heap_map.end()) ? nullptr : item->second;

    if (!heap) {
        heap = new xlio_heap(alloc_func, free_func, hw);
        s_heap_map[key] = heap;
    }
    return heap;
}

/*static*/
void xlio_heap::initialize()
{
    // Cache pagesize to align allocation requests.
    s_pagesize = (size_t)sysconf(_SC_PAGESIZE) ?: 4096U;
    // Support re-initialization after fork().
    s_heap_map.clear();
}

/*static*/
void xlio_heap::finalize()
{
    std::lock_guard<decltype(s_heap_lock)> lock(s_heap_lock);

    for (auto &item : s_heap_map) {
        delete item.second;
    }
    s_heap_map.clear();
}

xlio_heap::xlio_heap(alloc_t alloc_func, free_t free_func, bool hw)
    : m_latest_offset(0)
    , m_b_hw(hw)
    , m_p_alloc_func(alloc_func)
    , m_p_free_func(free_func)
{
    if (!expand()) {
        throw_xlio_exception("Couldn't allocate or register memory for XLIO heap.");
    }
}

xlio_heap::~xlio_heap()
{
    for (auto &block : m_blocks) {
        delete block;
    }
    m_blocks.clear();
}

bool xlio_heap::expand(size_t size /*=0*/)
{
    void *data;
    xlio_allocator_hw *block;

    if (!size && m_b_hw) {
        size = (m_p_alloc_func && safe_mce_sys().memory_limit_user)
            ? safe_mce_sys().memory_limit_user
            : safe_mce_sys().memory_limit;
    }
    size = size ?: safe_mce_sys().heap_metadata_block;

    if (!m_p_alloc_func && !m_b_hw) {
        block = new xlio_allocator_hw(ALLOC_TYPE_PREFER_HUGE);
    } else {
        block = new xlio_allocator_hw(m_p_alloc_func, m_p_free_func);
    }

    data = block ? block->alloc(size) : nullptr;
    if (m_b_hw && data) {
        if (!block->register_memory()) {
            data = nullptr;
        }
    }
    if (!data) {
        goto error;
    }

    m_blocks.push_back(block);
    m_latest_offset = 0;

    if (m_b_hw && g_user_memory_cb) {
        g_user_memory_cb(data, size, block->page_size());
    }

    return true;

error:
    if (block) {
        delete block;
    }
    return false;
}

void *xlio_heap::alloc(size_t &size)
{
    std::lock_guard<decltype(m_lock)> lock(m_lock);

    size_t actual_size = (size + s_pagesize - 1) & ~(s_pagesize - 1U);
    void *data = nullptr;

repeat:
    if (actual_size + m_latest_offset <= m_blocks.back()->size()) {
        data = (void *)((uintptr_t)m_blocks.back()->data() + m_latest_offset);
        m_latest_offset += actual_size;
    } else if (!m_b_hw) {
        if (expand(std::max(safe_mce_sys().heap_metadata_block, actual_size))) {
            goto repeat;
        }
    }

    if (data) {
        size = actual_size;
    }
    return data;
}

bool xlio_heap::register_memory()
{
    std::lock_guard<decltype(m_lock)> lock(m_lock);

    return m_b_hw && m_blocks.size() ? m_blocks.back()->register_memory() : false;
}

uint32_t xlio_heap::find_lkey_by_ib_ctx(ib_ctx_handler *p_ib_ctx_h) const
{
    // Current implementation doesn't support runtime registrations, lock is not necessary.
    return m_b_hw && m_blocks.size() ? m_blocks.back()->find_lkey_by_ib_ctx(p_ib_ctx_h)
                                     : LKEY_ERROR;
}

doca_mmap *xlio_heap::get_doca_mmap() const
{
    return (m_b_hw && m_blocks.size()) ? m_blocks.back()->get_doca_mmap() : nullptr;
}

xlio_allocator_heap::xlio_allocator_heap(alloc_t alloc_func, free_t free_func, bool hw)
{
    m_p_heap = xlio_heap::get(alloc_func, free_func, hw);

    if (!m_p_heap) {
        throw_xlio_exception("Couldn't create XLIO heap.");
    }
}

xlio_allocator_heap::xlio_allocator_heap(bool hw)
    : xlio_allocator_heap(nullptr, nullptr, hw)
{
}

xlio_allocator_heap::~xlio_allocator_heap()
{
}

void *xlio_allocator_heap::alloc(size_t &size)
{
    return m_p_heap->alloc(size);
}

bool xlio_allocator_heap::register_memory()
{
    return m_p_heap->register_memory();
}

uint32_t xlio_allocator_heap::find_lkey_by_ib_ctx(ib_ctx_handler *p_ib_ctx_h) const
{
    return m_p_heap->find_lkey_by_ib_ctx(p_ib_ctx_h);
}
