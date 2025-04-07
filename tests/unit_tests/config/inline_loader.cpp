/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <gtest/gtest.h>
#include "loaders/inline_loader.h"
#include "xlio_exception.h"
#include "utils.h"

TEST(config, inline_loader_sanity)
{
    env_setter setter(
        "XLIO_INLINE_CONFIG",
        "core.log.level=10, core.log.file_path=/var/log/xlio.log, core.exit_report=true");
    inline_loader loader("XLIO_INLINE_CONFIG");

    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(10, std::experimental::any_cast<int64_t>(data["core.log.level"]));
    ASSERT_EQ("/var/log/xlio.log",
              std::experimental::any_cast<std::string>(data["core.log.file_path"]));
    ASSERT_EQ(true, std::experimental::any_cast<bool>(data["core.exit_report"]));
}

TEST(config, inline_loader_single_key_value_pair_works)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.log.level=10");
    inline_loader loader("XLIO_INLINE_CONFIG");

    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(10, std::experimental::any_cast<int64_t>(data["core.log.level"]));
}

TEST(config, inline_loader_no_spaces_after_commas)
{
    env_setter setter(
        "XLIO_INLINE_CONFIG",
        "core.log.level=10,core.log.file_path=/var/log/xlio.log,core.exit_report=true");
    inline_loader loader("XLIO_INLINE_CONFIG");

    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(10, std::experimental::any_cast<int64_t>(data["core.log.level"]));
    ASSERT_EQ("/var/log/xlio.log",
              std::experimental::any_cast<std::string>(data["core.log.file_path"]));
    ASSERT_EQ(true, std::experimental::any_cast<bool>(data["core.exit_report"]));
}

TEST(config, inline_loader_empty)
{
    env_setter setter("XLIO_INLINE_CONFIG", "");
    inline_loader loader("XLIO_INLINE_CONFIG");

    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_double_commas_works)
{
    env_setter setter(
        "XLIO_INLINE_CONFIG",
        "core.log.level=10,,core.log.file_path=/var/log/xlio.log,core.exit_report=true");
    inline_loader loader("XLIO_INLINE_CONFIG");

    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(10, std::experimental::any_cast<int64_t>(data["core.log.level"]));
    ASSERT_EQ("/var/log/xlio.log",
              std::experimental::any_cast<std::string>(data["core.log.file_path"]));
    ASSERT_EQ(true, std::experimental::any_cast<bool>(data["core.exit_report"]));
}

TEST(config, inline_loader_double_get_non_existent_key_throws)
{
    // Only one key is provided.
    env_setter setter("XLIO_INLINE_CONFIG", "core.log.level=10");
    inline_loader loader("XLIO_INLINE_CONFIG");

    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(data.find("non.existent.key"), data.end());
}

TEST(config, inline_loader_pair_format_throws)
{
    // The pair "core.log.level10" is invalid because it lacks an '='.
    env_setter setter("XLIO_INLINE_CONFIG",
                      "core.log.level10, core.log.file_path=/var/log/xlio.log");
    inline_loader loader("XLIO_INLINE_CONFIG");

    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_env_not_set)
{
    // Ensure the environment variable is unset.
    unsetenv("XLIO_INLINE_CONFIG");
    ASSERT_THROW(inline_loader("XLIO_INLINE_CONFIG"), xlio_exception);
}

TEST(config, inline_loader_load_huge_int_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.memory.limit=100000000000");
    inline_loader loader("XLIO_INLINE_CONFIG");

    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(100000000000, std::experimental::any_cast<int64_t>(data["core.memory.limit"]));
}
