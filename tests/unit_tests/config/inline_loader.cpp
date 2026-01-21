/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <gtest/gtest.h>
#include "loaders/inline_loader.h"
#include "descriptor_providers/json_descriptor_provider.h"
#include "xlio_exception.h"
#include "utils.h"

// Minimal test schema with:
// - "enable" is ambiguous (exists in core.daemon.enable and hardware.offloads.enable)
// - "memory_limit" is unique (only in core.memory_limit)
// - "daemon.enable" is unique (disambiguates core.daemon.enable)
// - "offloads.enable" is unique (disambiguates hardware.offloads.enable)
static const char *test_schema = R"({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "properties": {
        "core": {
            "type": "object",
            "properties": {
                "memory_limit": {
                    "type": "integer",
                    "default": 0,
                    "title": "Memory Limit",
                    "description": "Maximum memory usage"
                },
                "log": {
                    "type": "object",
                    "properties": {
                        "level": {
                            "type": "integer",
                            "default": 3,
                            "title": "Log Level",
                            "description": "Logging verbosity level"
                        },
                        "file_path": {
                            "type": "string",
                            "default": "/var/log/xlio.log",
                            "title": "Log File Path",
                            "description": "Path to log file"
                        }
                    }
                },
                "exit_report": {
                    "type": "boolean",
                    "default": false,
                    "title": "Exit Report",
                    "description": "Generate report on exit"
                },
                "quick_init": {
                    "type": "boolean",
                    "default": false,
                    "title": "Quick Init",
                    "description": "Enable quick initialization"
                },
                "daemon": {
                    "type": "object",
                    "properties": {
                        "enable": {
                            "type": "boolean",
                            "default": false,
                            "title": "Daemon Enable",
                            "description": "Enable daemon mode"
                        },
                        "dir": {
                            "type": "string",
                            "default": "/tmp",
                            "title": "Daemon Directory",
                            "description": "Daemon working directory"
                        }
                    }
                },
                "resources": {
                    "type": "object",
                    "properties": {
                        "hugepages": {
                            "type": "object",
                            "properties": {
                                "enable": {
                                    "type": "boolean",
                                    "default": false,
                                    "title": "Hugepages Enable",
                                    "description": "Enable hugepages"
                                }
                            }
                        },
                        "external_memory_limit": {
                            "type": "integer",
                            "default": 0,
                            "title": "External Memory Limit",
                            "description": "External memory limit"
                        }
                    }
                }
            }
        },
        "hardware": {
            "type": "object",
            "properties": {
                "offloads": {
                    "type": "object",
                    "properties": {
                        "enable": {
                            "type": "boolean",
                            "default": false,
                            "title": "Offloads Enable",
                            "description": "Enable hardware offloads"
                        }
                    }
                }
            }
        },
        "hardware_features": {
            "type": "object",
            "properties": {
                "tcp": {
                    "type": "object",
                    "properties": {
                        "tso": {
                            "type": "object",
                            "properties": {
                                "enable": {
                                    "type": "string",
                                    "default": "auto",
                                    "title": "TSO Enable",
                                    "description": "TSO mode"
                                }
                            }
                        }
                    }
                }
            }
        },
        "network": {
            "type": "object",
            "properties": {
                "protocols": {
                    "type": "object",
                    "properties": {
                        "ip": {
                            "type": "object",
                            "properties": {
                                "mtu": {
                                    "type": "integer",
                                    "default": 1500,
                                    "title": "IP MTU",
                                    "description": "Maximum transmission unit"
                                }
                            }
                        }
                    }
                }
            }
        },
        "performance": {
            "type": "object",
            "properties": {
                "threading": {
                    "type": "object",
                    "properties": {
                        "cpu_affinity": {
                            "type": "string",
                            "default": "",
                            "title": "CPU Affinity",
                            "description": "CPU affinity mask"
                        }
                    }
                }
            }
        }
    }
})";

class InlineLoaderTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        json_descriptor_provider provider(test_schema);
        m_descriptor = provider.load_descriptors();
    }

    config_descriptor m_descriptor;
};

// ===== KEY RESOLUTION TESTS =====

TEST_F(InlineLoaderTest, resolves_unique_leaf_name)
{
    env_setter setter("XLIO_INLINE_CONFIG", "memory_limit=100");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    auto data = loader.load_all();

    EXPECT_TRUE(data.count("core.memory_limit"));
    EXPECT_EQ(100, std::experimental::any_cast<int64_t>(data["core.memory_limit"]));
}

TEST_F(InlineLoaderTest, rejects_ambiguous_leaf_name)
{
    // "enable" exists in multiple paths: core.daemon.enable, hardware.offloads.enable,
    // core.resources.hugepages.enable, hardware_features.tcp.tso.enable
    env_setter setter("XLIO_INLINE_CONFIG", "enable=true");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    EXPECT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, resolves_partial_path_to_disambiguate)
{
    env_setter setter("XLIO_INLINE_CONFIG", "daemon.enable=true");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    auto data = loader.load_all();

    EXPECT_TRUE(data.count("core.daemon.enable"));
    EXPECT_EQ(true, std::experimental::any_cast<bool>(data["core.daemon.enable"]));
}

TEST_F(InlineLoaderTest, resolves_full_path)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.daemon.enable=true");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    auto data = loader.load_all();

    EXPECT_TRUE(data.count("core.daemon.enable"));
    EXPECT_EQ(true, std::experimental::any_cast<bool>(data["core.daemon.enable"]));
}

TEST_F(InlineLoaderTest, detects_duplicate_after_resolution)
{
    // Both "daemon.enable" and "core.daemon.enable" resolve to the same full path
    env_setter setter("XLIO_INLINE_CONFIG", "daemon.enable=true; core.daemon.enable=false");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    EXPECT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_unknown_key)
{
    env_setter setter("XLIO_INLINE_CONFIG", "nonexistent_key=123");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    EXPECT_THROW(loader.load_all(), xlio_exception);
}

// ===== BASIC FUNCTIONALITY TESTS =====

TEST_F(InlineLoaderTest, sanity_test_multiple_values)
{
    env_setter setter(
        "XLIO_INLINE_CONFIG",
        "core.log.level=10; core.log.file_path=/var/log/xlio.log; core.exit_report=true");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(10, std::experimental::any_cast<int64_t>(data["core.log.level"]));
    ASSERT_EQ("/var/log/xlio.log",
              std::experimental::any_cast<std::string>(data["core.log.file_path"]));
    ASSERT_EQ(true, std::experimental::any_cast<bool>(data["core.exit_report"]));
}

TEST_F(InlineLoaderTest, single_key_value_pair_works)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.log.level=10");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(10, std::experimental::any_cast<int64_t>(data["core.log.level"]));
}

TEST_F(InlineLoaderTest, no_spaces_after_semicolons)
{
    env_setter setter(
        "XLIO_INLINE_CONFIG",
        "core.log.level=10;core.log.file_path=/var/log/xlio.log;core.exit_report=true");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(10, std::experimental::any_cast<int64_t>(data["core.log.level"]));
    ASSERT_EQ("/var/log/xlio.log",
              std::experimental::any_cast<std::string>(data["core.log.file_path"]));
    ASSERT_EQ(true, std::experimental::any_cast<bool>(data["core.exit_report"]));
}

TEST_F(InlineLoaderTest, empty_config_throws)
{
    env_setter setter("XLIO_INLINE_CONFIG", "");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, whitespace_only_config_throws)
{
    env_setter setter("XLIO_INLINE_CONFIG", "   ");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, tabs_only_config_throws)
{
    env_setter setter("XLIO_INLINE_CONFIG", "\t\t\t");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, mixed_whitespace_only_config_throws)
{
    env_setter setter("XLIO_INLINE_CONFIG", "  \t  \t  ");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, double_semicolons_throws)
{
    env_setter setter(
        "XLIO_INLINE_CONFIG",
        "core.log.level=10;;core.log.file_path=/var/log/xlio.log;core.exit_report=true");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, whitespace_only_key_value_pair_throws)
{
    // Tests "; ;" pattern where whitespace-only pair exists between semicolons
    env_setter setter("XLIO_INLINE_CONFIG", "core.log.level=10; ;core.exit_report=true");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, get_non_existent_key_returns_end_iterator)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.log.level=10");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(data.find("non.existent.key"), data.end());
}

TEST_F(InlineLoaderTest, pair_format_without_equals_throws)
{
    env_setter setter("XLIO_INLINE_CONFIG",
                      "core.log.level10; core.log.file_path=/var/log/xlio.log");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(InlineLoaderNoFixture, env_not_set_throws)
{
    // Ensure the environment variable is unset.
    unsetenv("XLIO_INLINE_CONFIG");
    json_descriptor_provider provider(test_schema);
    config_descriptor descriptor = provider.load_descriptors();
    ASSERT_THROW(inline_loader("XLIO_INLINE_CONFIG", descriptor), xlio_exception);
}

TEST_F(InlineLoaderTest, load_huge_int_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "memory_limit=100000000000");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(100000000000, std::experimental::any_cast<int64_t>(data["core.memory_limit"]));
}

// ===== WHITESPACE HANDLING TESTS =====

TEST_F(InlineLoaderTest, trims_whitespace_around_key)
{
    env_setter setter("XLIO_INLINE_CONFIG", "  memory_limit  =100");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    auto data = loader.load_all();
    EXPECT_TRUE(data.count("core.memory_limit"));
    EXPECT_EQ(100, std::experimental::any_cast<int64_t>(data["core.memory_limit"]));
}

TEST_F(InlineLoaderTest, trims_whitespace_around_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "memory_limit=  100  ");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    auto data = loader.load_all();
    EXPECT_TRUE(data.count("core.memory_limit"));
    EXPECT_EQ(100, std::experimental::any_cast<int64_t>(data["core.memory_limit"]));
}

TEST_F(InlineLoaderTest, trims_whitespace_around_key_and_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "  memory_limit  =  100  ");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    auto data = loader.load_all();
    EXPECT_TRUE(data.count("core.memory_limit"));
    EXPECT_EQ(100, std::experimental::any_cast<int64_t>(data["core.memory_limit"]));
}

TEST_F(InlineLoaderTest, accepts_spaces_after_semicolon)
{
    env_setter setter(
        "XLIO_INLINE_CONFIG",
        "core.log.level=10; core.log.file_path=/var/log/xlio.log; core.exit_report=true");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_NO_THROW(loader.load_all());

    std::map<std::string, std::experimental::any> data = loader.load_all();
    ASSERT_EQ(data.size(), 3UL);
    ASSERT_TRUE(data.find("core.log.level") != data.end());
    ASSERT_TRUE(data.find("core.log.file_path") != data.end());
    ASSERT_TRUE(data.find("core.exit_report") != data.end());
}

TEST_F(InlineLoaderTest, rejects_spaces_in_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "network.protocols.ip.mtu=9 0 0 0");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

// ===== STRICT VALIDATION TESTS =====

TEST_F(InlineLoaderTest, rejects_trailing_semicolon)
{
    env_setter setter("XLIO_INLINE_CONFIG", "network.protocols.ip.mtu=9000;");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_leading_semicolon)
{
    env_setter setter("XLIO_INLINE_CONFIG", ";network.protocols.ip.mtu=9000");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_quotes_in_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "network.protocols.ip.mtu=\"9000");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_multiple_quotes_in_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "network.protocols.ip.mtu=90\"\"\"\"00");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_consecutive_semicolons)
{
    env_setter setter("XLIO_INLINE_CONFIG",
                      "network.protocols.ip.mtu=9000;;network.protocols.ip.mtu=9000");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_multiple_equals)
{
    env_setter setter("XLIO_INLINE_CONFIG",
                      "network.protocols.ip.mtu==9000;network.protocols.ip.mtu=9000");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_empty_value)
{
    env_setter setter("XLIO_INLINE_CONFIG",
                      "network.protocols.ip.mtu=;network.protocols.ip.mtu=9000");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_spaces_in_boolean_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.resources.hugepages.enable=t r u e");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_quotes_in_boolean_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.resources.hugepages.enable=tr\"\"\"\"ue");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_single_quote_in_boolean_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.resources.hugepages.enable=\"true");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_multiple_equals_in_boolean)
{
    env_setter setter("XLIO_INLINE_CONFIG",
                      "core.resources.hugepages.enable==true;core.resources.hugepages.enable=true");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_empty_boolean_value)
{
    env_setter setter("XLIO_INLINE_CONFIG",
                      "core.resources.hugepages.enable=;core.resources.hugepages.enable=true");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_multiple_equals_in_string)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.daemon.dir==Checking_Syntax");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_empty_string_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.daemon.dir=");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_single_quote_in_string_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.daemon.dir='Checking_Syntax");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_quotes_in_string_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.daemon.dir=Checkin\"\"\"\"g_Syntax");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_spaces_in_string_value)
{
    env_setter setter("XLIO_INLINE_CONFIG",
                      "core.daemon.dir=Checking_Syntax core.daemon.dir=Checking_Syntax");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_comma_as_delimiter)
{
    // Comma is no longer accepted as delimiter - semicolon is the new delimiter
    env_setter setter("XLIO_INLINE_CONFIG",
                      "core.daemon.dir=Checking_Syntax,core.daemon.dir=Checking_Syntax");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_spaces_in_tso_enable_value)
{
    env_setter setter("XLIO_INLINE_CONFIG",
                      "hardware_features.tcp.tso.enable=e t h t o o l _ a u t o");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_invalid_characters_in_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.resources.external_memory_limit=6$$");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, accepts_comma_delimited_value)
{
    // cpu_affinity supports comma-delimited values like "0,4,8"
    env_setter setter("XLIO_INLINE_CONFIG", "cpu_affinity=0,4,8");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    auto data = loader.load_all();
    EXPECT_TRUE(data.count("performance.threading.cpu_affinity"));
    EXPECT_EQ("0,4,8",
              std::experimental::any_cast<std::string>(data["performance.threading.cpu_affinity"]));
}

TEST_F(InlineLoaderTest, accepts_comma_and_range_in_value)
{
    // cpu_affinity supports ranges like "0,1,7-10"
    env_setter setter("XLIO_INLINE_CONFIG", "cpu_affinity=0,1,7-10");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    auto data = loader.load_all();
    EXPECT_TRUE(data.count("performance.threading.cpu_affinity"));
    EXPECT_EQ("0,1,7-10",
              std::experimental::any_cast<std::string>(data["performance.threading.cpu_affinity"]));
}

// Valid configuration test
TEST_F(InlineLoaderTest, accepts_valid_configuration_with_semicolons)
{
    env_setter setter("XLIO_INLINE_CONFIG",
                      "network.protocols.ip.mtu=1500;core.quick_init=true;core.daemon.dir=/tmp");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_NO_THROW(loader.load_all());

    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(data.size(), 3UL);
    ASSERT_TRUE(data.find("network.protocols.ip.mtu") != data.end());
    ASSERT_TRUE(data.find("core.quick_init") != data.end());
    ASSERT_TRUE(data.find("core.daemon.dir") != data.end());
}

TEST_F(InlineLoaderTest, rejects_tab_in_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "network.protocols.ip.mtu=90\t00");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_newline_in_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "network.protocols.ip.mtu=90\n00");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_carriage_return_in_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "network.protocols.ip.mtu=90\r00");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_vertical_tab_in_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "network.protocols.ip.mtu=90\v00");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_form_feed_in_value)
{
    env_setter setter("XLIO_INLINE_CONFIG", "network.protocols.ip.mtu=90\f00");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_trailing_dot_in_key)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core.log.=5");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_consecutive_dots_in_key)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core..log.level=5");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, rejects_multiple_consecutive_dots_in_key)
{
    env_setter setter("XLIO_INLINE_CONFIG", "core...log=5");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST_F(InlineLoaderTest, multiple_short_names_in_single_config)
{
    env_setter setter("XLIO_INLINE_CONFIG", "memory_limit=500; level=7");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    auto data = loader.load_all();

    EXPECT_EQ(500, std::experimental::any_cast<int64_t>(data["core.memory_limit"]));
    EXPECT_EQ(7, std::experimental::any_cast<int64_t>(data["core.log.level"]));
}

TEST_F(InlineLoaderTest, mix_of_short_and_full_paths)
{
    env_setter setter("XLIO_INLINE_CONFIG", "memory_limit=500; core.log.level=7");
    inline_loader loader("XLIO_INLINE_CONFIG", m_descriptor);

    auto data = loader.load_all();

    EXPECT_EQ(500, std::experimental::any_cast<int64_t>(data["core.memory_limit"]));
    EXPECT_EQ(7, std::experimental::any_cast<int64_t>(data["core.log.level"]));
}
