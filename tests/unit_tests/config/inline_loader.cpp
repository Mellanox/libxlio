/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

TEST(config, inline_loader_double_commas_throws)
{
    env_setter setter(
        "XLIO_INLINE_CONFIG",
        "core.log.level=10,,core.log.file_path=/var/log/xlio.log,core.exit_report=true");
    inline_loader loader("XLIO_INLINE_CONFIG");

    ASSERT_THROW(loader.load_all(), xlio_exception);
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

// ===== STRICT VALIDATION TESTS =====

TEST(config, inline_loader_rejects_spaces_in_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "network.protocols.ip.mtu=9 0 0 0");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_accepts_spaces_after_comma)
{
    env_setter setter(
        "XLIO_INLINE_CONFIG",
        "core.log.level=10, core.log.file_path=/var/log/xlio.log, core.exit_report=true");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_NO_THROW(loader.load_all());

    std::map<std::string, std::experimental::any> data = loader.load_all();
    ASSERT_EQ(data.size(), 3UL);
    ASSERT_TRUE(data.find("core.log.level") != data.end());
    ASSERT_TRUE(data.find("core.log.file_path") != data.end());
    ASSERT_TRUE(data.find("core.exit_report") != data.end());
}

TEST(config, inline_loader_rejects_trailing_comma)
{
    env_setter setter("XLIO_INLINE_CONFIG", "network.protocols.ip.mtu=9000,");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_leading_comma)
{
    env_setter setter("XLIO_INLINE_CONFIG", ",network.protocols.ip.mtu=9000");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_quotes_in_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "network.protocols.ip.mtu=\"9000");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_multiple_quotes_in_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "network.protocols.ip.mtu=90\"\"\"\"00");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_consecutive_commas)
{
    env_setter setter("XLIO_INLINE_CONFIG",
                      "network.protocols.ip.mtu=9000,,network.protocols.ip.mtu=9000");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_multiple_equals)
{
    env_setter setter("XLIO_INLINE_CONFIG",
                      "network.protocols.ip.mtu==9000,network.protocols.ip.mtu=9000");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_empty_value)
{
    env_setter setter("XLIO_INLINE_CONFIG",
                      "network.protocols.ip.mtu=,network.protocols.ip.mtu=9000");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_spaces_in_boolean_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.resources.hugepages.enable=t r u e");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_quotes_in_boolean_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.resources.hugepages.enable=tr\"\"\"\"ue");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_single_quote_in_boolean_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.resources.hugepages.enable=\"true");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_multiple_equals_in_boolean)
{
    env_setter setter("XLIO_INLINE_CONFIG",
                      "core.resources.hugepages.enable==true,core.resources.hugepages.enable=true");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_empty_boolean_value)
{
    env_setter setter("XLIO_INLINE_CONFIG",
                      "core.resources.hugepages.enable=,core.resources.hugepages.enable=true");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_multiple_equals_in_string)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.daemon.dir==Checking_Syntax");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_empty_string_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.daemon.dir=");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_single_quote_in_string_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.daemon.dir='Checking_Syntax");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_quotes_in_string_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.daemon.dir=Checkin\"\"\"\"g_Syntax");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_spaces_in_string_value)
{
    env_setter setter("XLIO_INLINE_CONFIG",
                      "core.daemon.dir=Checking_Syntax core.daemon.dir=Checking_Syntax");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_invalid_delimiter)
{
    env_setter setter("XLIO_INLINE_CONFIG",
                      "core.daemon.dir=Checking_Syntax;core.daemon.dir=Checking_Syntax");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_spaces_in_boolean_value_2)
{
    env_setter setter("XLIO_INLINE_CONFIG",
                      "hardware_features.tcp.tso.enable=e t h t o o l _ a u t o");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_invalid_characters_in_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.resources.external_memory_limit=6$$");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

// Valid configuration test
TEST(config, inline_loader_accepts_valid_configuration)
{
    env_setter setter("XLIO_INLINE_CONFIG",
                      "network.protocols.ip.mtu=1500,core.quick_init=true,core.daemon.dir=/tmp");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_NO_THROW(loader.load_all());

    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(data.size(), 3UL);
    ASSERT_TRUE(data.find("network.protocols.ip.mtu") != data.end());
    ASSERT_TRUE(data.find("core.quick_init") != data.end());
    ASSERT_TRUE(data.find("core.daemon.dir") != data.end());
}

TEST(config, inline_loader_rejects_tab_in_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "network.protocols.ip.mtu=90\t00");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_newline_in_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "network.protocols.ip.mtu=90\n00");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_carriage_return_in_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "network.protocols.ip.mtu=90\r00");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_vertical_tab_in_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "network.protocols.ip.mtu=90\v00");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}
TEST(config, inline_loader_rejects_form_feed_in_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "network.protocols.ip.mtu=90\f00");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}
TEST(config, inline_loader_rejects_trailing_dot_in_key)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.log.=5");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_consecutive_dots_in_key)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core..log.level=5");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, inline_loader_rejects_multiple_consecutive_dots_in_key)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core...log=5");
    inline_loader loader("XLIO_INLINE_CONFIG");
    ASSERT_THROW(loader.load_all(), xlio_exception);
}
