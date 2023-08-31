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

#ifndef _XLIO_UTIL_HUGEPAGE_MGR_H_
#define _XLIO_UTIL_HUGEPAGE_MGR_H_

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>
#include <unordered_map>

#include "utils/lock_wrapper.h"

struct hugepage_metadata {
    uint32_t nr_hugepages_total;
    uint32_t nr_hugepages_free;
    unsigned nr_hugepages_allocated;
    unsigned nr_allocations;
};

class hugepage_mgr {
public:
    hugepage_mgr();

    void update();

    size_t get_default_hugepage() { return m_default_hugepage; }
    bool is_hugepage_supported(size_t hugepage);

    void *alloc_hugepages(size_t &size);
    void dealloc_hugepages(void *ptr, size_t size);

    void print_report(bool short_report = false);

private:
    enum {
        HUGEPAGE_METRIC_OPTIMAL = 10U,
        HUGEPAGE_METRIC_ACCEPTABLE = 50U,
        HUGEPAGE_UNUSED_OPTIMAL = (2U * 1024U * 1024U),
        HUGEPAGE_UNUSED_ACCEPTABLE = (256U * 1024U * 1024U),
        HUGEPAGE_UNUSED_WARNING_THRESHOLD = (100U * 1024U * 1024U),
    };

    void read_sysfs();
    size_t read_meminfo(const char *tag);
    uint32_t read_file_uint(std::string path);

    bool is_hugepage_optimal(size_t hugepage, size_t size);
    bool is_hugepage_acceptable(size_t hugepage, size_t size);
    size_t find_optimal_hugepage(size_t size);

    // Returns unused bytes in the tail hugepage because of alignment.
    size_t hugepage_unused_space(size_t hugepage, size_t size)
    {
        const size_t hugepage_mask = hugepage - 1;
        return ((size + hugepage_mask) & ~hugepage_mask) - size;
    }

    size_t hugepage_metric(size_t hugepage, size_t size)
    {
        // Percentage of the unused hugepage tail.
        return hugepage_unused_space(hugepage, size) / (hugepage / 100U);
    }

    uint32_t get_total_hugepages(size_t hugepage)
    {
        auto iter = m_hugepages.find(hugepage);
        return iter == m_hugepages.end() ? 0 : iter->second.nr_hugepages_total;
    }

    uint32_t get_free_hugepages(size_t hugepage)
    {
        auto iter = m_hugepages.find(hugepage);
        return iter == m_hugepages.end() ? 0 : iter->second.nr_hugepages_free;
    }

    void get_supported_hugepages(std::vector<size_t> &hugepages)
    {
        hugepages.reserve(m_hugepages.size());
        for (const auto &p : m_hugepages) {
            hugepages.push_back(p.first);
        }
    }

    size_t m_default_hugepage;
    lock_mutex m_lock;
    std::unordered_map<size_t, hugepage_metadata> m_hugepages;

    struct {
        unsigned allocations;
        unsigned fails;
        size_t total_allocated;
        size_t total_requested;
        size_t total_unused;
    } m_stats;
};

extern hugepage_mgr g_hugepage_mgr;

#endif /* _XLIO_UTIL_HUGEPAGE_MGR_H_ */
