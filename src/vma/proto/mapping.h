/*
 * Copyright (c) 2001-2022 Mellanox Technologies, Ltd. All rights reserved.
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

#ifndef VMA_MAPPING_H
#define VMA_MAPPING_H

#include "vma/dev/allocator.h"
#include "vma/proto/mem_desc.h"
#include "vma/util/vma_list.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include <unordered_map>

/* Forward declaration */
class mapping_cache;

/* Identifier which must uniquely identify a file within the system. */
struct file_uid_t {
    dev_t dev;
    ino_t ino;

    bool operator==(const file_uid_t &other) const { return dev == other.dev && ino == other.ino; }
};

namespace std {
template <> struct hash<file_uid_t> {
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

/* TODO replace with rwlock */
class mapping_t : public mem_desc, lock_spin {
public:
    mapping_t(file_uid_t &uid, mapping_cache *cache, ib_ctx_handler *p_ib_ctx);
    ~mapping_t();

    int map(int fd);
    int unmap(void);

    /* mem_desc interface */
    uint32_t get_lkey(mem_buf_desc_t *desc, ib_ctx_handler *ib_ctx, void *addr, size_t len);
    void get(void);
    void put(void);

    /* For debug */
    bool memory_belongs(uintptr_t addr, size_t size);

    bool is_free(void) { return m_ref == 0; }

    static inline size_t mapping_node_offset(void) { return NODE_OFFSET(mapping_t, m_node); }

public:
    mapping_state_t m_state;
    int m_fd;
    file_uid_t m_uid;
    void *m_addr;
    size_t m_size;
    uint32_t m_ref;
    uint32_t m_owners;
    ib_ctx_handler *m_ib_ctx;
    vma_allocator m_allocator;

private:
    int duplicate_fd(int fd, bool &rw);

    mapping_cache *p_cache;
    list_node<mapping_t, mapping_t::mapping_node_offset> m_node;
};

struct mapping_cache_stats {
    uint32_t n_evicts;
};

typedef std::unordered_map<int, mapping_t *> mapping_fd_map_t;
typedef std::unordered_map<int, mapping_t *>::iterator mapping_fd_map_iter_t;
typedef std::unordered_map<file_uid_t, mapping_t *> mapping_uid_map_t;
typedef std::unordered_map<file_uid_t, mapping_t *>::iterator mapping_uid_map_iter_t;
typedef vma_list_t<mapping_t, mapping_t::mapping_node_offset> mapping_list_t;

class mapping_cache : public lock_spin {
public:
    mapping_cache(size_t threshold);
    ~mapping_cache();

    mapping_t *get_mapping(int local_fd, void *p_ctx = NULL);
    void release_mapping(mapping_t *mapping);
    void handle_close(int local_fd);

    bool memory_reserve_unlocked(size_t size);
    void memory_free(size_t size);

    struct mapping_cache_stats m_stats;

private:
    mapping_t *get_mapping_by_uid_unlocked(file_uid_t &uid, ib_ctx_handler *p_ib_ctx = NULL);
    void evict_mapping_unlocked(mapping_t *mapping);
    bool cache_evict_unlocked(size_t toFree);

    mapping_uid_map_t m_cache_uid;
    mapping_fd_map_t m_cache_fd;
    mapping_list_t m_lru_list;
    size_t m_used;
    size_t m_threshold;
};

extern mapping_cache *g_zc_cache;

#endif /* VMA_MAPPING_H */
