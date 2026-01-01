/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "core/proto/mapping.h"
#include "core/sock/sock-redirect.h"
#include "core/util/instrumentation.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

#define MODULE_NAME "map:"

#define map_logpanic   __log_panic
#define map_logerr     __log_err
#define map_logwarn    __log_warn
#define map_loginfo    __log_info
#define map_logdbg     __log_dbg
#define map_logfunc    __log_func
#define map_logfuncall __log_funcall

#define map_logdbg_entry     __log_entry_dbg
#define map_logfunc_entry    __log_entry_func
#define map_logfuncall_entry __log_entry_funcall

#define map_logdbg_exit  __log_exit_dbg
#define map_logfunc_exit __log_exit_func

mapping_cache *g_zc_cache = nullptr;

mapping_t::mapping_t(file_uid_t &uid, mapping_cache *cache, ib_ctx_handler *p_ib_ctx)
    : m_registrator()
{
    m_state = MAPPING_STATE_UNMAPPED;
    m_fd = -1;
    m_uid = uid;
    m_addr = nullptr;
    m_size = 0;
    m_ref = 0;
    m_owners = 0;
    m_ib_ctx = p_ib_ctx;
    p_cache = cache;

    map_logdbg("Created mapping %p", this);
}

mapping_t::~mapping_t()
{
    map_logdbg("Destroying mapping %p", this);
    assert(is_free());

    if (m_state == MAPPING_STATE_MAPPED) {
        unmap();
    }
}

int mapping_t::map(int fd)
{
    struct stat st;
    bool result;
    bool rw;
    int flags;
    int rc;

    assert(m_state == MAPPING_STATE_UNMAPPED);

    rc = fstat(fd, &st);
    if (rc != 0) {
        map_logerr("fstat() errno=%d (%s)", errno, strerror(errno));
        goto failed;
    }

    result = p_cache->memory_reserve_unlocked(st.st_size);
    if (!result) {
        map_logdbg("Not enough space in the mapping cache %p", p_cache);
        errno = ENOMEM;
        goto failed;
    }

    /* On success, rw flag indicates whether new fd is opened for writing. */
    m_fd = duplicate_fd(fd, rw);
    if (m_fd < 0) {
        goto failed;
    }

    /*
     * Create mapping. User may open fd as read-only. If we can't re-open
     * it as read-write, shared mapping with PROT_WRITE fails. On the other
     * hand, ibv_reg_mr() requires PROT_WRITE, registration fails otherwise.
     * Therefore, for read-only fd we have to create a private mapping.
     */
    m_size = st.st_size;
    /*
     * XXX For some reason, with MAP_SHARED NGINX benchmark shows worse
     * performance results. For now, use only MAP_PRIVATE mappings.
     */
    flags = /* rw ? MAP_SHARED :*/ MAP_PRIVATE;
    m_addr = mmap64(nullptr, m_size, PROT_WRITE | PROT_READ, flags | MAP_NORESERVE | MAP_POPULATE,
                    m_fd, 0);
    if (MAP_FAILED == m_addr) {
        map_logerr("mmap64() errno=%d (%s)", errno, strerror(errno));
        goto failed_close_fd;
    }

    result = m_registrator.register_memory(m_addr, m_size, m_ib_ctx);
    if (!result) {
        map_logerr("Failed to register mmapped memory");
        goto failed_unmap;
    }
    m_state = MAPPING_STATE_MAPPED;

    map_logdbg("Mapped: pid=%u fd=%d addr=%p size=%zu rw=%d.", (unsigned)getpid(), m_fd, m_addr,
               m_size, !!rw);
    return 0;

failed_unmap:
    (void)munmap(m_addr, m_size);
failed_close_fd:
    SYSCALL(close, m_fd);
    m_addr = nullptr;
    m_size = 0;
    m_fd = -1;
failed:
    m_state = MAPPING_STATE_FAILED;
    return -1;
}

int mapping_t::unmap(void)
{
    int rc;

    assert(m_state == MAPPING_STATE_MAPPED);
    assert(is_free());

    map_logdbg("Unmapped: pid=%u fd=%d addr=%p size=%zu.", (unsigned)getpid(), m_fd, m_addr,
               m_size);

    m_registrator.deregister_memory();
    rc = munmap(m_addr, m_size);
    if (rc < 0) {
        map_logerr("munmap() errno=%d (%s)", errno, strerror(errno));
    }
    p_cache->memory_free(m_size);
    SYSCALL(close, m_fd);
    m_fd = -1;
    m_addr = nullptr;
    m_size = 0;
    m_state = MAPPING_STATE_UNMAPPED;

    return rc;
}

uint32_t mapping_t::get_lkey(mem_buf_desc_t *desc, ib_ctx_handler *p_ib_ctx, const void *addr,
                             size_t len)
{
    NOT_IN_USE(desc);
    NOT_IN_USE(addr);
    NOT_IN_USE(len);

    return m_registrator.find_lkey_by_ib_ctx(p_ib_ctx);
}

bool mapping_t::memory_belongs(uintptr_t addr, size_t size)
{
    uintptr_t map_addr = (uintptr_t)m_addr;

    return (map_addr != 0) && (addr >= map_addr) && (addr + size <= map_addr + m_size);
}

void mapping_t::get(void)
{
    lock();
    ++m_ref;
    unlock();
}

void mapping_t::put(void)
{
    p_cache->lock();
    lock();

    --m_ref;
    if (m_ref == 0) {
        p_cache->release_mapping(this);
    }

    unlock();
    p_cache->unlock();
}

int mapping_t::duplicate_fd(int fd, bool &rw)
{
    int result;
    ssize_t len;
    char link[PATH_MAX];
    char filename[PATH_MAX];

    result = snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    if (result > 0 && result < (int)sizeof(link)) {
        len = readlink(link, filename, sizeof(filename) - 1);
        if (len > 0) {
            filename[len] = '\0';
            result = SYSCALL(open, filename, O_RDWR);
            if (result < 0) {
                map_logdbg("open() errno=%d (%s)", errno, strerror(errno));
            } else {
                rw = true;
            }
        } else {
            /* Error in readlink(2). */
            result = -1;
        }
    } else {
        /* String is incomplete. */
        errno = ERANGE;
        result = -1;
    }

    if (result < 0) {
        /* Fallback to dup(2). */
        result = SYSCALL(dup, fd);
        if (result < 0) {
            map_logerr("dup() errno=%d (%s)", errno, strerror(errno));
        } else {
            int flags = SYSCALL(fcntl, result, F_GETFL);
            rw = (flags > 0) && ((flags & O_RDWR) == O_RDWR);
        }
    }
    return result;
}

mapping_cache::mapping_cache(size_t threshold)
    : lock_spin("mapping_cache_lock")
    , m_cache_uid()
    , m_cache_fd()
    , m_lru_list()
{
    memset(&m_stats, 0, sizeof(m_stats));
    m_used = 0;
    m_threshold = threshold;
}

mapping_cache::~mapping_cache()
{
    mapping_t *mapping;

    mapping_fd_map_iter_t fd_map_iter;
    while ((fd_map_iter = m_cache_fd.begin()) != m_cache_fd.end()) {
        /* do m_cache_fd.erase() */
        handle_close(fd_map_iter->first);
    }

    while (!m_lru_list.empty()) {
        mapping = m_lru_list.get_and_pop_front();
        evict_mapping_unlocked(mapping);
    }

    mapping_uid_map_iter_t uid_map_iter;
    for (uid_map_iter = m_cache_uid.begin(); uid_map_iter != m_cache_uid.end(); ++uid_map_iter) {
        mapping = uid_map_iter->second;
        map_loginfo("Cache not empty: fd=%d ref=%u owners=%u", mapping->m_fd,
                    (unsigned)mapping->m_ref, (unsigned)mapping->m_owners);
    }
}

mapping_t *mapping_cache::get_mapping(int local_fd, void *p_ctx)
{
    mapping_t *mapping = nullptr;
    mapping_fd_map_iter_t iter;
    file_uid_t uid;
    struct stat st;
    ib_ctx_handler *p_ib_ctx = (ib_ctx_handler *)p_ctx;

    lock();

    iter = m_cache_fd.find(local_fd);
    if (iter != m_cache_fd.end()) {
        mapping = iter->second;
        if (mapping->is_free() && mapping->m_state == MAPPING_STATE_MAPPED) {
            m_lru_list.erase(mapping);
        }
    }

    if (!mapping) {
        if (fstat(local_fd, &st) != 0) {
            map_logerr("fstat() errno=%d (%s)", errno, strerror(errno));
            goto quit;
        }
        uid.dev = st.st_dev;
        uid.ino = st.st_ino;
        mapping = get_mapping_by_uid_unlocked(uid, p_ib_ctx);
        if (!mapping) {
            map_logwarn("Failed to create mapping for uid (dev=%lu, ino=%lu)", uid.dev, uid.ino);
            goto quit;
        }
        m_cache_fd[local_fd] = mapping;
        ++mapping->m_owners;
    }

quit:
    if (mapping) {
        mapping->get();

        /* Mapping object may be unmapped, call mmap() in this case */
        if (mapping->m_state == MAPPING_STATE_UNMAPPED) {
            mapping->map(local_fd);
        }
    }

    unlock();

    if (mapping && mapping->m_state == MAPPING_STATE_FAILED) {
        mapping->put();
        mapping = nullptr;
    }
    return mapping;
}

void mapping_cache::release_mapping(mapping_t *mapping)
{
    assert(mapping->is_free());

    /* TODO Rework */
    if (mapping->m_state == MAPPING_STATE_FAILED) {
        return;
    }

    m_lru_list.push_back(mapping);
}

void mapping_cache::handle_close(int local_fd)
{
    mapping_t *mapping;
    mapping_fd_map_iter_t iter;

    lock();
    iter = m_cache_fd.find(local_fd);
    if (iter != m_cache_fd.end()) {
        mapping = iter->second;
        assert(mapping->m_owners > 0);
        --mapping->m_owners;
        if (mapping->m_owners == 0 &&
            (mapping->m_state != MAPPING_STATE_MAPPED &&
             mapping->m_state != MAPPING_STATE_UNKNOWN)) {
            m_cache_uid.erase(mapping->m_uid);
            mapping->m_state = MAPPING_STATE_UNKNOWN;
            delete mapping;
        }
        m_cache_fd.erase(iter);
    }
    unlock();
}

bool mapping_cache::memory_reserve_unlocked(size_t size)
{
    bool result = true;

    if (m_used + size > m_threshold) {
        result = cache_evict_unlocked(m_used + size - m_threshold);
    }
    if (result) {
        m_used += size;
    }

    return result;
}

void mapping_cache::memory_free(size_t size)
{
    /*
     * This method is called during mapping->unmap() which is called
     * under the cache lock or in cache destructor.
     */
    assert(m_used >= size);
    m_used -= size;
}

mapping_t *mapping_cache::get_mapping_by_uid_unlocked(file_uid_t &uid, ib_ctx_handler *p_ib_ctx)
{
    mapping_t *mapping = nullptr;
    mapping_uid_map_iter_t iter;

    iter = m_cache_uid.find(uid);
    if (iter != m_cache_uid.end()) {
        mapping = iter->second;
        if (mapping->is_free() && mapping->m_state == MAPPING_STATE_MAPPED) {
            m_lru_list.erase(mapping);
        }
    }

    if (!mapping) {
        mapping = new (std::nothrow) mapping_t(uid, this, p_ib_ctx);
        if (mapping) {
            m_cache_uid[uid] = mapping;
        }
    }

    return mapping;
}

void mapping_cache::evict_mapping_unlocked(mapping_t *mapping)
{
    assert(mapping->is_free());

    if (mapping->m_state == MAPPING_STATE_MAPPED) {
        mapping->unmap();
    }
    if (mapping->m_owners == 0 && (mapping->m_state != MAPPING_STATE_UNKNOWN)) {
        m_cache_uid.erase(mapping->m_uid);
        mapping->m_state = MAPPING_STATE_UNKNOWN;
        delete mapping;
    }
}

bool mapping_cache::cache_evict_unlocked(size_t toFree)
{
    size_t freed = 0;
    mapping_t *mapping;

    map_logdbg("Evicting cache, LRU list size=%zu", m_lru_list.size());

    while (freed < toFree) {
        if (m_lru_list.empty()) {
            return false;
        }
        mapping = m_lru_list.get_and_pop_front();
        freed += mapping->m_size;
        evict_mapping_unlocked(mapping);
        ++m_stats.n_evicts;
    }
    return true;
}
