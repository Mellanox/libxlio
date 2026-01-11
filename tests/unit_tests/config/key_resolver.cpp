/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <gtest/gtest.h>
#include "loaders/key_resolver.h"
#include "descriptor_providers/json_descriptor_provider.h"
#include "xlio_exception.h"

// Test schema with various levels of nesting and some ambiguous leaf names
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
                        }
                    }
                },
                "daemon": {
                    "type": "object",
                    "properties": {
                        "enable": {
                            "type": "boolean",
                            "default": false,
                            "title": "Daemon Enable",
                            "description": "Enable daemon mode"
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
        "network": {
            "type": "object",
            "properties": {
                "protocols": {
                    "type": "object",
                    "properties": {
                        "tcp": {
                            "type": "object",
                            "properties": {
                                "nodelay": {
                                    "type": "object",
                                    "properties": {
                                        "enable": {
                                            "type": "boolean",
                                            "default": false,
                                            "title": "TCP Nodelay Enable",
                                            "description": "Enable TCP_NODELAY"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
})";

class KeyResolverTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        json_descriptor_provider provider(test_schema);
        m_descriptor = provider.load_descriptors();
    }

    config_descriptor m_descriptor;
};

// ===== EXACT MATCH TESTS =====

TEST_F(KeyResolverTest, exact_match_returns_same_path)
{
    key_resolver resolver(m_descriptor, "TEST_SOURCE");

    EXPECT_EQ("core.memory_limit", resolver.resolve("core.memory_limit"));
}

TEST_F(KeyResolverTest, exact_match_nested_path)
{
    key_resolver resolver(m_descriptor, "TEST_SOURCE");

    EXPECT_EQ("core.log.level", resolver.resolve("core.log.level"));
}

TEST_F(KeyResolverTest, exact_match_deep_path)
{
    key_resolver resolver(m_descriptor, "TEST_SOURCE");

    EXPECT_EQ("network.protocols.tcp.nodelay.enable",
              resolver.resolve("network.protocols.tcp.nodelay.enable"));
}

// ===== UNIQUE LEAF NAME TESTS =====

TEST_F(KeyResolverTest, unique_leaf_name_resolves_correctly)
{
    key_resolver resolver(m_descriptor, "TEST_SOURCE");

    // memory_limit is unique
    EXPECT_EQ("core.memory_limit", resolver.resolve("memory_limit"));
}

TEST_F(KeyResolverTest, unique_leaf_name_level_resolves_correctly)
{
    key_resolver resolver(m_descriptor, "TEST_SOURCE");

    // level is unique (only in core.log.level)
    EXPECT_EQ("core.log.level", resolver.resolve("level"));
}

// ===== PARTIAL PATH TESTS =====

TEST_F(KeyResolverTest, partial_path_two_segments_resolves)
{
    key_resolver resolver(m_descriptor, "TEST_SOURCE");

    // log.level should resolve to core.log.level
    EXPECT_EQ("core.log.level", resolver.resolve("log.level"));
}

TEST_F(KeyResolverTest, partial_path_disambiguates_enable)
{
    key_resolver resolver(m_descriptor, "TEST_SOURCE");

    // daemon.enable should resolve to core.daemon.enable
    EXPECT_EQ("core.daemon.enable", resolver.resolve("daemon.enable"));
}

TEST_F(KeyResolverTest, partial_path_offloads_enable)
{
    key_resolver resolver(m_descriptor, "TEST_SOURCE");

    // offloads.enable should resolve to hardware.offloads.enable
    EXPECT_EQ("hardware.offloads.enable", resolver.resolve("offloads.enable"));
}

TEST_F(KeyResolverTest, partial_path_hugepages_enable)
{
    key_resolver resolver(m_descriptor, "TEST_SOURCE");

    // hugepages.enable should resolve to core.resources.hugepages.enable
    EXPECT_EQ("core.resources.hugepages.enable", resolver.resolve("hugepages.enable"));
}

TEST_F(KeyResolverTest, partial_path_nodelay_enable)
{
    key_resolver resolver(m_descriptor, "TEST_SOURCE");

    // nodelay.enable should resolve to network.protocols.tcp.nodelay.enable
    EXPECT_EQ("network.protocols.tcp.nodelay.enable", resolver.resolve("nodelay.enable"));
}

// ===== AMBIGUOUS KEY TESTS =====

TEST_F(KeyResolverTest, ambiguous_leaf_throws_exception)
{
    key_resolver resolver(m_descriptor, "TEST_SOURCE");

    // "enable" exists in multiple paths
    EXPECT_THROW(resolver.resolve("enable"), xlio_exception);
}

TEST_F(KeyResolverTest, ambiguous_key_error_contains_source_name)
{
    key_resolver resolver(m_descriptor, "TEST_SOURCE");

    try {
        resolver.resolve("enable");
        FAIL() << "Expected xlio_exception to be thrown";
    } catch (const xlio_exception &e) {
        std::string msg = e.what();
        EXPECT_NE(msg.find("TEST_SOURCE"), std::string::npos)
            << "Error message should contain source name: " << msg;
    }
}

TEST_F(KeyResolverTest, ambiguous_key_error_contains_suggestions)
{
    key_resolver resolver(m_descriptor, "TEST_SOURCE");

    try {
        resolver.resolve("enable");
        FAIL() << "Expected xlio_exception to be thrown";
    } catch (const xlio_exception &e) {
        std::string msg = e.what();
        // Should suggest at least one of the valid options
        bool has_suggestion = msg.find("daemon.enable") != std::string::npos ||
            msg.find("offloads.enable") != std::string::npos ||
            msg.find("hugepages.enable") != std::string::npos ||
            msg.find("nodelay.enable") != std::string::npos;
        EXPECT_TRUE(has_suggestion) << "Error message should contain suggestions: " << msg;
    }
}

// ===== UNKNOWN KEY TESTS =====

TEST_F(KeyResolverTest, unknown_key_throws_exception)
{
    key_resolver resolver(m_descriptor, "TEST_SOURCE");

    EXPECT_THROW(resolver.resolve("nonexistent_key"), xlio_exception);
}

TEST_F(KeyResolverTest, unknown_key_error_contains_source_name)
{
    key_resolver resolver(m_descriptor, "TEST_SOURCE");

    try {
        resolver.resolve("nonexistent_key");
        FAIL() << "Expected xlio_exception to be thrown";
    } catch (const xlio_exception &e) {
        std::string msg = e.what();
        EXPECT_NE(msg.find("TEST_SOURCE"), std::string::npos)
            << "Error message should contain source name: " << msg;
    }
}

TEST_F(KeyResolverTest, unknown_key_close_to_valid_suggests_alternative)
{
    key_resolver resolver(m_descriptor, "TEST_SOURCE");

    try {
        // "leve" is close to "level"
        resolver.resolve("leve");
        FAIL() << "Expected xlio_exception to be thrown";
    } catch (const xlio_exception &e) {
        std::string msg = e.what();
        // Should suggest "level" via Levenshtein distance
        EXPECT_NE(msg.find("Did you mean"), std::string::npos)
            << "Error message should contain 'Did you mean' suggestion: " << msg;
    }
}

// ===== EDGE CASE TESTS =====

TEST_F(KeyResolverTest, empty_key_throws)
{
    key_resolver resolver(m_descriptor, "TEST_SOURCE");

    EXPECT_THROW(resolver.resolve(""), xlio_exception);
}

TEST_F(KeyResolverTest, key_with_leading_dot_throws)
{
    key_resolver resolver(m_descriptor, "TEST_SOURCE");

    // ".memory_limit" is not a valid key format
    EXPECT_THROW(resolver.resolve(".memory_limit"), xlio_exception);
}

TEST_F(KeyResolverTest, key_with_trailing_dot_throws)
{
    key_resolver resolver(m_descriptor, "TEST_SOURCE");

    // "memory_limit." is not a valid key format
    EXPECT_THROW(resolver.resolve("memory_limit."), xlio_exception);
}
