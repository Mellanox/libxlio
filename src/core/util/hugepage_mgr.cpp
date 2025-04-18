/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2023-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "hugepage_mgr.h"

#include <sys/types.h>
#include <dirent.h>
#include <sys/mman.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <mutex>
#include <fstream>
#include <sstream>

#include "vlogger/vlogger.h"
#include "util/sys_vars.h"

#define MODULE_NAME "hugepage_mgr"

hugepage_mgr g_hugepage_mgr;

hugepage_mgr::hugepage_mgr()
{
    memset(&m_stats, 0, sizeof(m_stats));
    m_default_hugepage = read_meminfo("Hugepagesize:");
    update();

    /* Check hugepage size if requested by user explicitly. */
    if (safe_mce_sys().hugepage_size != 0 && !is_hugepage_supported(safe_mce_sys().hugepage_size)) {
        vlog_printf(VLOG_WARNING,
                    "Requested hugepage %s is not supported by the system. "
                    "XLIO will autodetect optimal hugepage.\n",
                    option_size::to_str(safe_mce_sys().hugepage_size));
        /* Value 0 means default autodetection behavior. Don't set MCE_DEFAULT_HUGEPAGE_SIZE
         * here, because it can be defined to an unsupported specific value.
         */
        safe_mce_sys().hugepage_size = 0;
    }
}

void hugepage_mgr::update()
{
    std::lock_guard<decltype(m_lock)> lock(m_lock);

    read_sysfs();
}

bool hugepage_mgr::is_hugepage_supported(size_t hugepage)
{
    std::lock_guard<decltype(m_lock)> lock(m_lock);
    return m_hugepages.find(hugepage) != m_hugepages.end();
}

bool hugepage_mgr::is_hugepage_optimal(size_t hugepage, size_t size)
{
    return (size / hugepage) || hugepage_unused_space(hugepage, size) <= HUGEPAGE_UNUSED_OPTIMAL ||
        hugepage_metric(hugepage, size) <= HUGEPAGE_METRIC_OPTIMAL;
}

bool hugepage_mgr::is_hugepage_acceptable(size_t hugepage, size_t size)
{
    return hugepage_unused_space(hugepage, size) <= HUGEPAGE_UNUSED_ACCEPTABLE ||
        hugepage_metric(hugepage, size) <= HUGEPAGE_METRIC_ACCEPTABLE;
}

bool hugepage_mgr::check_resident_pages(void *ptr, size_t size, size_t page_size)
{
    const size_t pages_nr = size / page_size;
    size_t resident_nr = 0;
    char *page_ptr = reinterpret_cast<char *>(ptr);

    /* Checking a single page per hugepage in a loop is more efficient than a single mincore()
     * syscall for the entire range. A single syscall would also require an array allocation
     * which can grow to tens of MB for the preallocated memory region.
     */
    for (size_t i = 0; i < pages_nr; ++i) {
        unsigned char vec;
        int rc = mincore(page_ptr, 1, &vec);
        if (rc < 0) {
            __log_info_dbg("mincore() failed to verify hugepages (errno=%d)", errno);
            return false;
        }
        resident_nr += (vec & 1U);
        page_ptr += page_size;
    }
    if (resident_nr != pages_nr) {
        __log_info_dbg("Not all hugepages are resident (allocated=%zu resident=%zu)", pages_nr,
                       resident_nr);
    }
    return resident_nr == pages_nr;
}

void *hugepage_mgr::alloc_hugepages_helper(size_t &size, size_t hugepage)
{
    size_t hugepage_mask = hugepage - 1;
    size_t actual_size = (size + hugepage_mask) & ~hugepage_mask;
    void *ptr = nullptr;
    int map_flags = 0;

    __log_info_dbg("Allocating %zu bytes with hugepages %zu kB", actual_size, hugepage / 1024U);

    if (hugepage != m_default_hugepage) {
        map_flags = (int)log2(hugepage) << MAP_HUGE_SHIFT;
    }

    ptr = mmap(nullptr, actual_size, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_HUGETLB | map_flags, -1, 0);
    if (ptr == MAP_FAILED) {
        ptr = nullptr;
        __log_info_dbg("mmap failed (errno=%d)", errno);
    } else if (!safe_mce_sys().quick_start) {
        /* Check whether all the pages are resident. Allocation beyond the cgroup limit can be
         * successful and lead to a SIGBUS on an access. For example, the limit can be configured
         * for a container.
         */
        if (!check_resident_pages(ptr, actual_size, hugepage)) {
            int rc = munmap(ptr, actual_size);
            if (rc < 0) {
                __log_info_dbg("munmap failed (errno=%d)", errno);
            }
            ptr = nullptr;
        }
    }
    if (ptr) {
        // Success.
        size = actual_size;
    } else {
        // Failure.
        __log_info_dbg("Skipping hugepage %zu kB", hugepage / 1024U);
    }
    return ptr;
}

void *hugepage_mgr::alloc_hugepages(size_t &size, size_t &hugepage_size)
{
    std::lock_guard<decltype(m_lock)> lock(m_lock);

    size_t hugepage = 0;
    size_t actual_size = size;
    void *ptr = nullptr;
    std::vector<size_t> hugepages;

    if (safe_mce_sys().hugepage_size == 0) {
        get_supported_hugepages(hugepages);
        std::sort(hugepages.begin(), hugepages.end(), std::greater<size_t>());
    } else {
        // User requested specific hugepage size - don't check other types.
        hugepages.push_back(safe_mce_sys().hugepage_size);
    }

    for (auto iter = hugepages.begin(); !ptr && iter != hugepages.end(); ++iter) {
        hugepage = *iter;
        if (get_total_hugepages(hugepage) && is_hugepage_optimal(hugepage, size)) {
            ptr = alloc_hugepages_helper(actual_size, hugepage);
        }
    }
    for (auto iter = hugepages.begin(); !ptr && iter != hugepages.end(); ++iter) {
        hugepage = *iter;
        if (get_total_hugepages(hugepage) && is_hugepage_acceptable(hugepage, size)) {
            ptr = alloc_hugepages_helper(actual_size, hugepage);
        }
    }
    if (ptr) {
        size = actual_size;
        hugepage_size = hugepage;
    }

    // Statistics
    m_stats.total_requested += actual_size;
    if (ptr) {
        ++m_stats.allocations;
        m_stats.total_allocated += actual_size;
        m_stats.total_unused += actual_size - size;
        m_hugepages[hugepage].nr_hugepages_allocated += actual_size / hugepage;
        ++m_hugepages[hugepage].nr_allocations;
    } else {
        ++m_stats.fails;
    }
    return ptr;
}

void hugepage_mgr::dealloc_hugepages(void *ptr, size_t size)
{
    int rc = munmap(ptr, size);
    if (rc != 0) {
        __log_info_dbg("munmap failed (errno=%d)", errno);
    }
}

void hugepage_mgr::print_report(bool short_report /*=false*/)
{
    std::lock_guard<decltype(m_lock)> lock(m_lock);

    const size_t ONE_MB = 1024U * 1024U;
    std::vector<size_t> hugepages;

    // Update hugepage information to mitigate potential race with other processes.
    read_sysfs();

    get_supported_hugepages(hugepages);
    vlog_printf(VLOG_INFO, "Hugepages info:\n");
    if (safe_mce_sys().hugepage_size) {
        vlog_printf(VLOG_INFO, "  User forced to use %lu kB hugepages.\n",
                    (safe_mce_sys().hugepage_size) / 1024U);
    }
    for (size_t hugepage : hugepages) {
        vlog_printf(VLOG_INFO, "  %zu kB : total=%u free=%u\n", hugepage / 1024U,
                    get_total_hugepages(hugepage), get_free_hugepages(hugepage));
    }

    if (short_report) {
        return;
    }

    vlog_printf(VLOG_INFO, "Hugepages statistics:\n");
    for (size_t hugepage : hugepages) {
        vlog_printf(VLOG_INFO, "  %zu kB : allocated_pages=%u allocations=%u\n", hugepage / 1024U,
                    m_hugepages[hugepage].nr_hugepages_allocated,
                    m_hugepages[hugepage].nr_allocations);
    }
    vlog_printf(VLOG_INFO, "  Total: allocations=%u unsatisfied=%u\n", m_stats.allocations,
                m_stats.fails);
    vlog_printf(VLOG_INFO, "  Total: allocated=%zuMB requested=%zuMB unused_space=%zuMB\n",
                m_stats.total_allocated / ONE_MB, m_stats.total_requested / ONE_MB,
                m_stats.total_unused / ONE_MB);
}

void hugepage_mgr::read_sysfs()
{
    DIR *dir = opendir("/sys/kernel/mm/hugepages/");
    struct dirent *entry;

    if (dir) {
        while ((entry = readdir(dir))) {
            if (strncmp(entry->d_name, "hugepages-", 10) == 0) {
                std::string path = std::string("/sys/kernel/mm/hugepages/") + entry->d_name;
                size_t key = atol(entry->d_name + 10) * 1024U;

                m_hugepages[key].nr_hugepages_total = read_file_uint(path + "/nr_hugepages");
                m_hugepages[key].nr_hugepages_free = read_file_uint(path + "/free_hugepages");
            }
        }
        closedir(dir);
    }
}

size_t hugepage_mgr::read_meminfo(const char *tag)
{
    std::ifstream infile("/proc/meminfo");
    std::string prefix(tag);
    std::string line;
    size_t val = 0;

    if (infile.is_open()) {
        while (std::getline(infile, line)) {
            if (line.compare(0, prefix.length(), prefix) == 0) {
                std::string sval = line.substr(prefix.length());
                std::istringstream iss(sval);
                iss >> val;
                if (sval.find("kB") != std::string::npos) {
                    val *= 1024U;
                }
            }
        }
        infile.close();
    }
    // coverity[return_overflow:FALSE] /*Turn off coverity check for overflow*/
    return val;
}

uint32_t hugepage_mgr::read_file_uint(std::string path)
{
    uint32_t val = 0;
    std::ifstream infile(path);

    if (infile.is_open()) {
        infile >> val;
    }
    return val;
}
