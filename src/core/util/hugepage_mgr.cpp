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

#include "hugepage_mgr.h"

#include <sys/types.h>
#include <dirent.h>
#include <sys/mman.h>

#include <algorithm>
#include <cmath>
#include <cstring>
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
}

void hugepage_mgr::update()
{
    read_sysfs();
}

bool hugepage_mgr::is_hugepage_supported(size_t hugepage)
{
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

size_t hugepage_mgr::find_optimal_hugepage(size_t size)
{
    std::vector<size_t> hugepages;
    size_t best_hugepage = 0;

    if (safe_mce_sys().hugepage_log2 == 0) {
        get_supported_hugepages(hugepages);
        std::sort(hugepages.begin(), hugepages.end(), std::greater<size_t>());
    } else {
        // User requested specific hugepage size - don't check other types.
        hugepages.push_back(1LU << safe_mce_sys().hugepage_log2);
    }

    // This is naive algorithm and may work inefficiently in complex scenarios.
    for (size_t hugepage : hugepages) {
        if (get_free_hugepages(hugepage) * hugepage >= size) {
            if (is_hugepage_optimal(hugepage, size)) {
                return hugepage;
            }
            if (is_hugepage_acceptable(hugepage, size) && best_hugepage == 0) {
                best_hugepage = hugepage;
            }
        }
    }

    if (best_hugepage &&
        hugepage_unused_space(best_hugepage, size) > HUGEPAGE_UNUSED_WARNING_THRESHOLD) {
        __log_info_dbg("Allocating %zu bytes with hugepages %zu kB.", size, best_hugepage / 1024U);
        __log_info_dbg("%zu bytes of the last hugepage may be unused.",
                       best_hugepage - size % best_hugepage);
    }
    return best_hugepage;
}

void *hugepage_mgr::alloc_hugepages(size_t &size)
{
    size_t hugepage = find_optimal_hugepage(size);
    size_t hugepage_mask = hugepage - 1;
    size_t actual_size = size;
    void *ptr = nullptr;

    if (hugepage) {
        int map_flags = 0;

        if (hugepage != m_default_hugepage) {
            map_flags = (int)log2(hugepage) << MAP_HUGE_SHIFT;
        }
        actual_size = (size + hugepage_mask) & ~hugepage_mask;

        __log_info_dbg("Allocating %zu bytes with hugepages %zu kB", actual_size, hugepage / 1024U);

        ptr = mmap(NULL, actual_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_HUGETLB | map_flags, -1, 0);
        if (ptr == MAP_FAILED) {
            ptr = nullptr;
            __log_info_dbg("mmap failed (errno=%d)", errno);
        } else {
            m_hugepages[hugepage].nr_hugepages_free -= actual_size / hugepage;
        }
    }

    // Statistics
    m_stats.total_requested += actual_size;
    if (ptr) {
        m_hugepages[hugepage].nr_hugepages_allocated += actual_size / hugepage;
        ++m_hugepages[hugepage].nr_allocations;
        ++m_stats.allocations;
        m_stats.total_allocated += actual_size;
        m_stats.total_unused += actual_size - size;

        size = actual_size;
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
    // We don't track released hugepages. Usually they're used for preallocation
    // and not freed in runtime.
}

void hugepage_mgr::print_report(bool short_report /*=false*/)
{
    const size_t ONE_MB = 1024U * 1024U;
    std::vector<size_t> hugepages;

    get_supported_hugepages(hugepages);
    vlog_printf(VLOG_INFO, "Hugepages info:\n");
    if (safe_mce_sys().hugepage_log2) {
        vlog_printf(VLOG_INFO, "  User forced to use %lu kB hugepages (%s=%u).\n",
                    (1LU << safe_mce_sys().hugepage_log2) / 1024U, SYS_VAR_HUGEPAGE_LOG2,
                    safe_mce_sys().hugepage_log2);
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
    vlog_printf(VLOG_INFO, "  Total: allocations=%u fails=%u\n", m_stats.allocations,
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
                m_hugepages[key].nr_hugepages_allocated = 0U;
                m_hugepages[key].nr_allocations = 0U;
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
