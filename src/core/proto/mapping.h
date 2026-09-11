/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef _MAPPING_H
#define _MAPPING_H

#include "dev/allocator.h"
#include "proto/mem_desc.h"
#include "util/xlio_list.h"
#include "utils/lock_wrapper.h"

#include <stddef.h>
#include <stdint.h>

#include <assert.h>

#include <atomic>
#include <unordered_map>

/* Forward declaration */
class mapping_cache;

class mapping_ref_count {
public:
    /* Initialize a mapping with no active or retained references. */
    mapping_ref_count()
        : m_value(0)
    {
    }

    /* Acquire a reference when the caller already protects the mapping lifetime. */
    void get() { m_value.fetch_add(1, std::memory_order_relaxed); }

    /* Acquire a reference only if already referenced; return true if acquired, false at zero. */
    bool try_get()
    {
        uint32_t value = m_value.load(std::memory_order_relaxed);

        while (value != 0) {
            if (m_value.compare_exchange_weak(value, value + 1, std::memory_order_acquire,
                                              std::memory_order_relaxed)) {
                return true;
            }
        }
        return false;
    }

    /* Drop a non-final reference; return true if dropped, false if locked final-put is required. */
    bool put_fast()
    {
        uint32_t value = m_value.load(std::memory_order_relaxed);

        while (value > 1) {
            if (m_value.compare_exchange_weak(value, value - 1, std::memory_order_release,
                                              std::memory_order_relaxed)) {
                return true;
            }
        }
        return false;
    }

    /* Drop a reference under the cache write lock; return true if the count reached zero. */
    bool put_locked()
    {
        uint32_t value = m_value.fetch_sub(1, std::memory_order_acq_rel);

        assert(value > 0);
        return value == 1;
    }

    /* Return a relaxed snapshot of the total current reference count. */
    uint32_t value() const { return m_value.load(std::memory_order_relaxed); }

private:
    /* Total transient references plus the optional cache-owned hot reference. */
    std::atomic<uint32_t> m_value;
};

class mapping_hot_ref {
public:
    /* Initialize a mapping without a retained hot reference or recent access. */
    mapping_hot_ref()
        : m_retained(false)
        , m_recent(false)
    {
    }

    /* Add the single cache-owned hot reference and mark the mapping as recently used. */
    void retain(mapping_ref_count &refs)
    {
        assert(!m_retained);
        refs.get();
        m_retained = true;
        m_recent.store(true, std::memory_order_relaxed);
    }

    /* Remove the hot reference; return true if it was the final reference. */
    bool release(mapping_ref_count &refs)
    {
        assert(m_retained);
        m_retained = false;
        m_recent.store(false, std::memory_order_relaxed);
        return refs.put_locked();
    }

    /* Mark the hot mapping as recently accessed without taking the cache write lock. */
    void touch() { m_recent.store(true, std::memory_order_relaxed); }

    /* Atomically clear recency; return true if the mapping had been touched since the last scan. */
    bool consume_recent() { return m_recent.exchange(false, std::memory_order_relaxed); }

    /* Return true while the cache owns a retained hot reference, otherwise false. */
    bool is_retained() const { return m_retained; }

private:
    /* Cache-lock-protected ownership flag; cache readers only inspect it. */
    bool m_retained;

    /* Lock-free second-chance marker updated by concurrent cache readers. */
    std::atomic<bool> m_recent;
};

/* Identifier which must uniquely identify a file within the system. */
struct file_uid_t {
    /* Device containing the file. */
    dev_t dev;

    /* Inode identifying the file within its device. */
    ino_t ino;

    /* Return true when both identities have the same device and inode. */
    bool operator==(const file_uid_t &other) const { return dev == other.dev && ino == other.ino; }
};

namespace std {
template <> struct hash<file_uid_t> {
    /* Return the combined device/inode hash used by std::unordered_map. */
    std::size_t operator()(file_uid_t const &uid) const
    {
        std::size_t h1 = std::hash<unsigned long>()((unsigned long)uid.dev);
        std::size_t h2 = std::hash<unsigned long>()((unsigned long)uid.ino);
        return h1 ^ (h2 << 1);
    }
};
} /* namespace std */

typedef enum {
    MAPPING_STATE_UNKNOWN,
    MAPPING_STATE_UNMAPPED,
    MAPPING_STATE_MAPPED,
    MAPPING_STATE_FAILED
} mapping_state_t;

/*
 * Mapping cache lifetime and bounded hot-retention model
 * ======================================================
 *
 * A mapping_t is the single canonical mmap/NIC-registration object for one
 * (device, inode). Two indexes point to that same object:
 *
 * - m_cache_fd maps each application FD to its mapping and m_owners counts
 *   those entries. FD ownership keeps the object discoverable, but does not
 *   contribute to m_ref and therefore does not prevent memory eviction.
 * - m_cache_uid deduplicates different FDs for the same file.
 *
 * m_ref contains transient sendfile/pbuf references plus at most one retained
 * hot reference. Frequently reused mappings stay on m_hot_list with that extra
 * reference, so sendfile and TX-completion puts remain atomic fast-path
 * decrements and never perform the 1 -> 0 transition.
 *
 * Hot retention is bounded by the existing mapping-cache byte threshold:
 * m_used never exceeds m_threshold. When a new mapping needs space, eviction
 * first consumes zero-reference mappings from m_lru_list. If the cold LRU is
 * empty, the cache uses a second-chance policy on m_hot_list: a mapping touched
 * since the previous scan has its atomic recent bit cleared and moves to the
 * back. Older mappings lose their hot references until one becomes immediately
 * evictable. If none of them does, the second-chance mappings are similarly
 * considered oldest-first. Each eviction attempt scans a bounded snapshot.
 *
 * Demotion has two outcomes:
 *
 * - No transient users: the hot reference was the last reference, so the
 *   mapping reaches zero and moves to m_lru_list for immediate eviction.
 * - Active send/pbuf users: the mapping is removed from m_hot_list but remains
 *   alive. The final transient put later moves it to m_lru_list.
 *
 * The same intrusive m_node is used by the hot list and cold LRU, so a mapping
 * may be in at most one of them. A mapped object with m_ref == 0 is cold and
 * must be on m_lru_list. A retained hot object has m_ref >= 1 and is on
 * m_hot_list. An active, demoted object is temporarily on neither list.
 *
 * The mapping-cache RW lock protects both indexes, both lists, m_owners,
 * m_retained, mapping state, and byte accounting. Fast FD hits hold a read lock
 * and use try_get(), which never resurrects a zero-reference LRU entry. Cache
 * misses, promotion/demotion, close, remap, and eviction hold the write lock.
 * TX completion uses atomic refcount operations; only a final 1 -> 0 put takes
 * the cache write lock before changing list membership or object lifetime.
 */
class mapping_t : public mem_desc {
public:
    /* Create an unmapped cache object for a canonical file identity. */
    mapping_t(file_uid_t &uid, mapping_cache *cache, ib_ctx_handler *p_ib_ctx);

    /* Release registration, mapping, and internal FD resources during destruction. */
    ~mapping_t();

    /* Map and register the file; return 0 on success or -1 with errno set on failure. */
    int map(int fd);

    /* Deregister and unmap the file; return the munmap result (0 or -1). */
    int unmap(void);

    /* mem_desc interface */
    /* Return the registered NIC lkey, or LKEY_ERROR when the context is not registered. */
    uint32_t get_lkey(mem_buf_desc_t *desc, ib_ctx_handler *ib_ctx, const void *addr, size_t len);

    /* Acquire an unconditional transient mapping reference. */
    void get(void);

    /* Release a reference, taking the cache write lock only for the final put. */
    void put(void);

    /* Return true when the entire address range lies inside the mapped file region. */
    bool memory_belongs(uintptr_t addr, size_t size);

    /* Return true when no transient or retained hot references remain. */
    bool is_free(void) { return m_ref.value() == 0; }

    /* Return the byte offset of the intrusive node within mapping_t. */
    static inline size_t mapping_node_offset(void) { return NODE_OFFSET(mapping_t, m_node); }

private:
    /* Return an internal FD on success or -1 on failure; rw reports whether it is writable. */
    int duplicate_fd(int fd, bool &rw);

    /* Drop a reference under the cache write lock; return true if the count reached zero. */
    bool put_locked(void);

    friend class mapping_cache;

public:
    /* Current mapping lifecycle state. */
    mapping_state_t m_state;

    /* Internal reopened or duplicated FD backing the mmap, not the application FD. */
    int m_fd;

    /* Canonical device/inode identity used by the UID cache. */
    file_uid_t m_uid;

    /* Base address of the current mmap, or nullptr while unmapped. */
    void *m_addr;

    /* Length of the current mmap in bytes. */
    size_t m_size;

    /* Atomic transient-reference count including an optional retained hot reference. */
    mapping_ref_count m_ref;

    /* Cache-owned hot-reference and second-chance recency state. */
    mapping_hot_ref m_hot_ref;

    /* Number of application FD-cache entries that point to this mapping. */
    uint32_t m_owners;

private:
    /* Parent cache that owns indexes, list membership, and mapping lifetime. */
    mapping_cache *p_cache;

    /* Optional device context used to scope memory registration. */
    ib_ctx_handler *m_ib_ctx;

    /* Owns the NIC memory registrations associated with the mapped range. */
    xlio_registrator m_registrator;

    /* Intrusive node used exclusively by either m_hot_list or m_lru_list. */
    list_node<mapping_t, mapping_t::mapping_node_offset> m_node;
};

struct mapping_cache_stats {
    /* Number of mappings removed from the cold LRU to free cache capacity. */
    uint32_t n_evicts;
};

typedef std::unordered_map<int, mapping_t *> mapping_fd_map_t;
typedef std::unordered_map<int, mapping_t *>::iterator mapping_fd_map_iter_t;
typedef std::unordered_map<file_uid_t, mapping_t *> mapping_uid_map_t;
typedef std::unordered_map<file_uid_t, mapping_t *>::iterator mapping_uid_map_iter_t;
typedef xlio_list_t<mapping_t, mapping_t::mapping_node_offset> mapping_list_t;

class mapping_cache : public lock_rw {
public:
    /* Create an empty cache with the supplied mapped-byte limit. */
    mapping_cache(size_t threshold);

    /* Drain FD ownership, hot retention, and evictable mappings during shutdown. */
    ~mapping_cache();

    /* Return a referenced mapping for the FD, or nullptr when mapping cannot be prepared. */
    mapping_t *get_mapping(int local_fd, void *p_ctx = nullptr);

    /* Process a zero-reference mapping while the cache write lock is held. */
    void release_mapping_unlocked(mapping_t *mapping);

    /* Remove an application FD from the cache and update mapping ownership. */
    void handle_close(int local_fd);

    /* Reserve mapped bytes; return true on success or false if enough space cannot be evicted. */
    bool memory_reserve_unlocked(size_t size);

    /* Return mapped-byte capacity after a mapping is unmapped. */
    void memory_free(size_t size);

    /* Public counters describing mapping-cache activity. */
    struct mapping_cache_stats m_stats;

private:
    /* Return the canonical mapping for the UID, or nullptr if object allocation fails. */
    mapping_t *get_mapping_by_uid_unlocked(file_uid_t &uid, ib_ctx_handler *p_ib_ctx = nullptr);

    /* Retain a mapped object in the hot list, removing it from the cold LRU if needed. */
    void promote_mapping_unlocked(mapping_t *mapping);

    /* Remove the hot reference; return true if the mapping became immediately evictable. */
    bool demote_mapping_unlocked(mapping_t *mapping);

    /* Demote bounded hot candidates until one becomes immediately evictable. */
    bool demote_hot_mappings_unlocked();

    /* Remove an ownerless mapping from the UID index and delete its object. */
    void destroy_mapping_unlocked(mapping_t *mapping);

    /* Unmap one zero-reference mapping and delete it when no FD owners remain. */
    void evict_mapping_unlocked(mapping_t *mapping);

    /* Evict requested bytes; return true if enough was freed, otherwise false. */
    bool cache_evict_unlocked(size_t toFree);

    /* Canonical device/inode index that deduplicates mappings across FDs. */
    mapping_uid_map_t m_cache_uid;

    /* Fast application-FD index into canonical mapping objects. */
    mapping_fd_map_t m_cache_fd;

    /* Recently used mappings that retain one cache-owned reference. */
    mapping_list_t m_hot_list;

    /* Zero-reference mapped objects ordered from oldest to newest. */
    mapping_list_t m_lru_list;

    /* Total bytes currently mapped and charged to the cache. */
    size_t m_used;

    /* Maximum mapped bytes allowed before eviction is required. */
    size_t m_threshold;
};

/* Process-global sendfile mapping cache. */
extern mapping_cache *g_zc_cache;

#endif /* _MAPPING_H */
