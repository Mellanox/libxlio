/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef _MEM_DESC_H
#define _MEM_DESC_H

#include <stdint.h>

#include <unordered_map>

#include "utils/lock_wrapper.h"

/*
 * Note, the following mem_desc implementations must be allocated with new()
 * (not by new[], nor by placement new, nor a local object on the stack,
 * nor a namespace-scope / global, nor a member of another object; but by
 * plain ordinary new):
 *  - mem_desc_compose
 *  - zcopy_user_memory
 *  - zcopy_external
 * This is because they call "delete this" in put() method.
 */

enum {
    DATA_SOURCE_NR_MAX = 3,
};

/* forward declarations */
class ib_ctx_handler;
class mem_buf_desc_t;

class mem_desc {
public:
    virtual ~mem_desc() {}

    /* get() is always called under socket lock */
    virtual void get(void) = 0;
    /*
     * There is no guarantee that put() is protected by either
     * socket or ring lock
     */
    virtual void put(void) = 0;

    /* get_lkey() is always called under socket lock */
    virtual uint32_t get_lkey(mem_buf_desc_t *desc, ib_ctx_handler *ib_ctx, const void *addr,
                              size_t len)
    {
        NOT_IN_USE(desc);
        NOT_IN_USE(ib_ctx);
        NOT_IN_USE(addr);
        NOT_IN_USE(len);
        return LKEY_ERROR;
    }
};

class mem_desc_compose : public mem_desc {
public:
    mem_desc_compose()
        : m_array_size(0)
    {
        atomic_set(&m_ref, 0);
    }

    void get(void)
    {
        int ref = atomic_fetch_and_inc(&m_ref);

        if (ref == 0) {
            for (int i = 0; i < m_array_size; ++i) {
                m_array[i]->get();
            }
        }
    }

    void put(void)
    {
        int ref = atomic_fetch_and_dec(&m_ref);

        if (ref == 1) {
            for (int i = 0; i < m_array_size; ++i) {
                m_array[i]->put();
            }
            delete this;
        }
    }

    uint32_t get_lkey(mem_buf_desc_t *desc, ib_ctx_handler *ib_ctx, const void *addr, size_t len)
    {
        if (likely(m_array_size != 0)) {
            return m_array[0]->get_lkey(desc, ib_ctx, addr, len);
        } else {
            return LKEY_ERROR;
        }
    }

    void add_child(mem_desc *child)
    {
        if (likely(m_array_size < DATA_SOURCE_NR_MAX)) {
            m_array[m_array_size++] = child;
        }
    }

private:
    mem_desc *m_array[DATA_SOURCE_NR_MAX];
    int m_array_size;
    atomic_t m_ref;
};

class zcopy_hugepage : public mem_desc, lock_spin {
public:
    zcopy_hugepage(void *addr, size_t size)
    {
        m_is_pinned = false;
        m_addr = addr;
        m_size = size;
    }

    ~zcopy_hugepage()
    { /* TODO Unregister hugepage */
    }

    void get(void)
    { /* Reference counting is not required, we never destroy hugepages. */
    }

    void put(void)
    { /* Reference counting is not required, we never destroy hugepages. */
    }

    uint32_t get_lkey(mem_buf_desc_t *desc, ib_ctx_handler *ib_ctx, const void *addr, size_t len);

public:
    void *m_addr;
    size_t m_size;

private:
    bool m_is_pinned;
    uint32_t m_lkey;
    /*
     * TODO Add bonding support:
     * - Collection of <ib_ctx, lkey> pairs
     * - Cache ib_ctx
     * - Remove m_is_pinned
     * - ib_ctx change is unlikely, we may find new lkey in O(N) time:
     *	if (unlikely(ib_ctx != m_ib_ctx_cached)) {
     *		m_lkey = find_or_register_new_lkey(ib_ctx);
     *		m_ib_ctx_cached = ib_ctx;
     *	}
     */
};

class zcopy_hugepage_mgr : public lock_spin {
public:
    zcopy_hugepage_mgr();

    zcopy_hugepage *get_hugepage(void *addr)
    {
        void *page_addr = (void *)((uintptr_t)addr & m_hugepage_mask);
        zcopy_hugepage *page;

        lock();

        auto iter = m_hugepage_map.find(page_addr);
        if (likely(iter != m_hugepage_map.end())) {
            page = iter->second;
        } else {
            page = new zcopy_hugepage(page_addr, m_hugepage_size);
            if (likely(page)) {
                m_hugepage_map[page_addr] = page;
            }
        }

        unlock();
        return page;
    }

public:
    size_t m_hugepage_size;
    uintptr_t m_hugepage_mask;

private:
    std::unordered_map<void *, zcopy_hugepage *> m_hugepage_map;
};

#endif /* _MEM_DESC_H */
