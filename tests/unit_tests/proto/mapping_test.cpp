/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "core/proto/mapping.h"
#include "vlogger/vlogger.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <stdio.h>
#include <thread>
#include <unistd.h>
#include <vector>

/*
 * mapping.cpp is linked into this hardware-free unit-test target. Stub only
 * memory registration and logging, which are outside the cache policy under
 * test.
 */
vlog_levels_t g_vlogger_level = VLOG_NONE;

void vlog_output(vlog_levels_t, const char *, ...)
{
}

xlio_registrator::xlio_registrator()
{
}

xlio_registrator::~xlio_registrator()
{
}

bool xlio_registrator::register_memory(void *, size_t, ib_ctx_handler *)
{
    return true;
}

void xlio_registrator::deregister_memory()
{
}

uint32_t xlio_registrator::find_lkey_by_ib_ctx(ib_ctx_handler *) const
{
    return 0;
}

static FILE *create_mapping_file(size_t size)
{
    FILE *file = tmpfile();

    if (file && ftruncate(fileno(file), size) != 0) {
        fclose(file);
        file = nullptr;
    }
    return file;
}

struct file_closer {
    void operator()(FILE *file) const { fclose(file); }
};

using file_ptr = std::unique_ptr<FILE, file_closer>;

TEST(mapping_ref_count_test, keeps_last_reference_until_cache_is_locked)
{
    mapping_ref_count refs;

    refs.get();
    refs.get();

    EXPECT_TRUE(refs.put_fast());
    EXPECT_EQ(1U, refs.value());
    EXPECT_FALSE(refs.put_fast());
    EXPECT_EQ(1U, refs.value());
    EXPECT_TRUE(refs.put_locked());
    EXPECT_EQ(0U, refs.value());
}

TEST(mapping_ref_count_test, retained_reference_keeps_send_references_on_fast_path)
{
    mapping_ref_count refs;

    refs.get(); // Retained hot reference.
    refs.get(); // sendfile() reference.
    refs.get(); // queued pbuf reference.

    EXPECT_TRUE(refs.put_fast());
    EXPECT_TRUE(refs.put_fast());
    EXPECT_EQ(1U, refs.value());

    EXPECT_FALSE(refs.put_fast());
    EXPECT_TRUE(refs.put_locked());
    EXPECT_EQ(0U, refs.value());
}

TEST(mapping_ref_count_test, try_get_does_not_resurrect_zero)
{
    mapping_ref_count refs;

    EXPECT_FALSE(refs.try_get());

    refs.get();
    EXPECT_TRUE(refs.try_get());
    EXPECT_EQ(2U, refs.value());

    EXPECT_TRUE(refs.put_fast());
    EXPECT_TRUE(refs.put_locked());
    EXPECT_EQ(0U, refs.value());
}

TEST(mapping_hot_ref_test, retains_one_reference_until_demoted)
{
    mapping_ref_count refs;
    mapping_hot_ref hot;

    hot.retain(refs);
    EXPECT_TRUE(hot.is_retained());
    EXPECT_EQ(1U, refs.value());
    EXPECT_TRUE(hot.consume_recent());
    EXPECT_FALSE(hot.consume_recent());

    hot.touch();
    EXPECT_TRUE(hot.consume_recent());

    refs.get(); // Active send reference.
    EXPECT_TRUE(refs.put_fast());
    EXPECT_TRUE(hot.release(refs));
    EXPECT_FALSE(hot.is_retained());
    EXPECT_EQ(0U, refs.value());
}

TEST(mapping_hot_ref_test, demotion_waits_for_active_reference)
{
    mapping_ref_count refs;
    mapping_hot_ref hot;

    hot.retain(refs);
    refs.get(); // Active send reference.

    EXPECT_FALSE(hot.release(refs));
    EXPECT_EQ(1U, refs.value());
    EXPECT_FALSE(refs.put_fast());
    EXPECT_TRUE(refs.put_locked());
    EXPECT_EQ(0U, refs.value());
}

TEST(mapping_cache_test, eviction_scans_past_active_hot_candidate)
{
    const size_t mapping_size = 4096;
    file_ptr active_file(create_mapping_file(mapping_size));
    file_ptr idle_file(create_mapping_file(mapping_size));
    file_ptr replacement_file(create_mapping_file(mapping_size));

    ASSERT_NE(nullptr, active_file.get());
    ASSERT_NE(nullptr, idle_file.get());
    ASSERT_NE(nullptr, replacement_file.get());

    mapping_cache cache(2 * mapping_size);
    mapping_t *active = cache.get_mapping(fileno(active_file.get()));
    mapping_t *idle = cache.get_mapping(fileno(idle_file.get()));

    ASSERT_NE(nullptr, active);
    ASSERT_NE(nullptr, idle);
    idle->put();

    mapping_t *replacement = cache.get_mapping(fileno(replacement_file.get()));

    EXPECT_NE(nullptr, replacement);
    EXPECT_EQ(1U, cache.m_stats.n_evicts);

    if (replacement) {
        replacement->put();
    }
    active->put();
}

TEST(mapping_cache_test, concurrent_shared_mapping_survives_eviction)
{
    constexpr size_t mapping_size = 4096;
    constexpr size_t thread_count = 4;
    constexpr size_t file_count = 8;
    constexpr uint64_t required_shared_acquisitions = 10000;
    constexpr uint32_t required_evictions = 1000;
    std::vector<file_ptr> files;

    files.reserve(file_count);
    for (size_t i = 0; i < file_count; ++i) {
        files.emplace_back(create_mapping_file(mapping_size));
        ASSERT_NE(nullptr, files.back().get());
    }

    mapping_cache cache(2 * mapping_size);

    /* Seed the shared mapping and one idle candidate so eviction can always make progress. */
    mapping_t *mapping = cache.get_mapping(fileno(files[0].get()));
    ASSERT_NE(nullptr, mapping);
    mapping->put();
    mapping = cache.get_mapping(fileno(files[1].get()));
    ASSERT_NE(nullptr, mapping);
    mapping->put();

    std::atomic<size_t> ready_threads {0};
    std::atomic<bool> start {false};
    std::atomic<bool> stop {false};
    std::atomic<unsigned> failure {0};
    std::atomic<uint64_t> shared_acquisitions {0};
    std::atomic<uint64_t> eviction_acquisitions {0};
    uint64_t per_thread_acquisitions[thread_count] = {};
    std::chrono::steady_clock::time_point maximum_deadline;
    std::vector<std::thread> threads;

    threads.reserve(thread_count);
    for (size_t thread_index = 0; thread_index < thread_count; ++thread_index) {
        threads.emplace_back([&, thread_index]() {
            size_t replacement_index = 1;

            ready_threads.fetch_add(1, std::memory_order_release);
            while (!start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }

            while (!stop.load(std::memory_order_relaxed) &&
                   failure.load(std::memory_order_relaxed) == 0 &&
                   std::chrono::steady_clock::now() < maximum_deadline) {
                mapping_t *shared = cache.get_mapping(fileno(files[0].get()));
                if (!shared) {
                    failure.fetch_or(1U, std::memory_order_relaxed);
                    break;
                }
                if (!shared->memory_belongs(reinterpret_cast<uintptr_t>(shared->m_addr),
                                            mapping_size)) {
                    failure.fetch_or(2U, std::memory_order_relaxed);
                }
                shared->put();
                shared_acquisitions.fetch_add(1, std::memory_order_relaxed);
                ++per_thread_acquisitions[thread_index];

                /* One of the four threads continuously forces cache eviction. */
                if (thread_index == 0) {
                    mapping_t *replacement =
                        cache.get_mapping(fileno(files[replacement_index].get()));
                    if (!replacement) {
                        failure.fetch_or(4U, std::memory_order_relaxed);
                        break;
                    }
                    if (!replacement->memory_belongs(
                            reinterpret_cast<uintptr_t>(replacement->m_addr), mapping_size)) {
                        failure.fetch_or(8U, std::memory_order_relaxed);
                    }
                    replacement->put();
                    eviction_acquisitions.fetch_add(1, std::memory_order_relaxed);
                    replacement_index = 1 + replacement_index % (file_count - 1);
                }
            }
        });
    }

    while (ready_threads.load(std::memory_order_acquire) != thread_count) {
        std::this_thread::yield();
    }
    const auto start_time = std::chrono::steady_clock::now();
    const auto minimum_deadline = start_time + std::chrono::seconds(1);
    maximum_deadline = start_time + std::chrono::seconds(10);
    start.store(true, std::memory_order_release);

    auto get_eviction_count = [&cache]() {
        cache.lock_rd();
        uint32_t count = cache.m_stats.n_evicts;
        cache.unlock();
        return count;
    };

    while (failure.load(std::memory_order_relaxed) == 0) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= minimum_deadline &&
            shared_acquisitions.load(std::memory_order_relaxed) >=
                required_shared_acquisitions &&
            get_eviction_count() >= required_evictions) {
            break;
        }
        if (now >= maximum_deadline) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    stop.store(true, std::memory_order_relaxed);

    for (auto &thread : threads) {
        thread.join();
    }

    const auto elapsed = std::chrono::steady_clock::now() - start_time;
    EXPECT_EQ(0U, failure.load(std::memory_order_relaxed));
    EXPECT_GE(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 1000);
    EXPECT_GE(shared_acquisitions.load(std::memory_order_relaxed),
              required_shared_acquisitions);
    EXPECT_GT(eviction_acquisitions.load(std::memory_order_relaxed), 0U);
    EXPECT_GE(get_eviction_count(), required_evictions);
    for (size_t thread_index = 0; thread_index < thread_count; ++thread_index) {
        EXPECT_GT(per_thread_acquisitions[thread_index], 0U);
    }
}
