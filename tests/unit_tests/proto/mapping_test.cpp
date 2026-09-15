/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "core/proto/mapping.h"
#include "vlogger/vlogger.h"

#include <gtest/gtest.h>

#include <memory>
#include <stdio.h>
#include <unistd.h>

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
