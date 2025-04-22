/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2023-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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

    hugepage_metadata()
    {
        nr_hugepages_total = 0;
        nr_hugepages_free = 0;
        nr_hugepages_allocated = 0;
        nr_allocations = 0;
    }
};

class hugepage_mgr {
public:
    hugepage_mgr();

    void update();

    size_t get_default_hugepage() { return m_default_hugepage; }
    bool is_hugepage_supported(size_t hugepage);

    void *alloc_hugepages(size_t &size, size_t &hugepage_size);
    void dealloc_hugepages(void *ptr, size_t size);

    void print_report(bool short_report = false, option_3::mode_t mode_type = option_3::OFF);

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
    bool check_resident_pages(void *ptr, size_t size, size_t page_size);
    void *alloc_hugepages_helper(size_t &size, size_t hugepage);

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
