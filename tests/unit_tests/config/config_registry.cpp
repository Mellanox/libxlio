/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <gtest/gtest.h>
#include "loaders/json_loader.h"
#include "loaders/inline_loader.h"
#include "descriptor_providers/json_descriptor_provider.h"
#include "xlio_exception.h"
#include "config_registry.h"
#include "utils.h"

static const char *sample_descriptor = R"({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "XLIO Configuration Schema",
    "description": "Schema for XLIO configuration",
    "type": "object",
    "properties": {
        "core": {
            "description": "controls the core functionality of libxlio.",
            "type": "object",
            "properties": {
                "append_pid_to_path": {
                    "type": "boolean",
                    "default": false,
                    "title": "Append PID to xlio.daemon.dir, core.stats.shmem_dir, core.stats.file_path, core.log.file_path.",
                    "description": "Append PID to xlio.daemon.dir, core.stats.shmem_dir, core.stats.file_path, core.log.file_path."
                },
                "log": {
                    "description": "controls logging behavior.",
                    "type": "object",
                    "properties": {
                        "level": {
                            "oneOf": [
                                {
                                    "type": "integer",
                                    "enum": [-2, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8],
                                    "default": 3
                                },
                                {
                                    "type": "string",
                                    "enum": [
                                        "init",
                                        "none",
                                        "panic",
                                        "error",
                                        "warn",
                                        "info",
                                        "details",
                                        "debug",
                                        "fine",
                                        "finer",
                                        "all"
                                    ],
                                    "default": "info"
                                }
                            ],
                            "description": "Sets level according to desired logging verbosity.",
                            "title": "Sets level according to desired logging verbosity."
                        }
                    }
                }
            }
        }
    }
})";

static const char *sample_json_config = R"({ "core": { "log": { "level": "debug" } } })";

TEST(config, config_registry_sanity)
{
    conf_file_writer json_config = conf_file_writer(sample_json_config);

    std::queue<std::unique_ptr<loader>> loaders;
    loaders.push(std::make_unique<json_loader>(json_config.get()));
    config_registry registry(std::move(loaders),
                             std::make_unique<json_descriptor_provider>(sample_descriptor));

    ASSERT_EQ(5, registry.get_value<int64_t>("core.log.level"));
}

TEST(config, config_registry_value_not_respecting_constraints_throws)
{
    conf_file_writer json_config = conf_file_writer(R"({ "core": { "log": { "level": 5000 } } })");

    std::queue<std::unique_ptr<loader>> loaders;
    loaders.push(std::make_unique<json_loader>(json_config.get()));
    ASSERT_THROW(config_registry(std::move(loaders),
                                 std::make_unique<json_descriptor_provider>(sample_descriptor)),
                 xlio_exception);
}

TEST(config, config_registry_value_last_loader_prioritized)
{
    conf_file_writer json_config = conf_file_writer(R"({ "core": { "log": { "level": -2 } } })");
    conf_file_writer json_config2 = conf_file_writer(R"({ "core": { "log": { "level": 0 } } })");
    conf_file_writer json_config3 = conf_file_writer(R"({ "core": { "log": { "level": 1 } } })");

    std::queue<std::unique_ptr<loader>> loaders;
    loaders.push(std::make_unique<json_loader>(json_config.get()));
    loaders.push(std::make_unique<json_loader>(json_config2.get()));
    loaders.push(std::make_unique<json_loader>(json_config3.get()));

    config_registry registry(std::move(loaders),
                             std::make_unique<json_descriptor_provider>(sample_descriptor));

    ASSERT_EQ(1, registry.get_value<int64_t>("core.log.level"));
}

TEST(config, config_registry_missing_gets_defaults)
{
    conf_file_writer json_config(sample_json_config);

    const char *descriptor_with_missing_property = R"({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "XLIO Configuration Schema",
    "description": "Schema for XLIO configuration",
    "type": "object",
    "properties": {
        "core": {
            "description": "controls the core functionality of libxlio.",
            "type": "object",
            "properties": {
                "missing": {
                    "type": "string",
                    "default": "hello",
                    "title": "A missing property",
                    "description": "A missing property"
                },
                "log": {
                    "description": "controls logging behavior.",
                    "type": "object",
                    "properties": {
                        "level": {
                            "oneOf": [
                                {
                                    "type": "integer",
                                    "enum": [-2, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8],
                                    "default": 3
                                },
                                {
                                    "type": "string",
                                    "enum": [
                                        "init",
                                        "none",
                                        "panic",
                                        "error",
                                        "warn",
                                        "info",
                                        "details",
                                        "debug",
                                        "fine",
                                        "finer",
                                        "all"
                                    ],
                                    "default": "info"
                                }
                            ],
                            "title": "Sets level according to desired logging verbosity.",
                            "description": "Sets level according to desired logging verbosity."
                        }
                    }
                }
            }
        }
    }
})";

    std::queue<std::unique_ptr<loader>> loaders;
    loaders.push(std::make_unique<json_loader>(json_config.get()));

    config_registry registry(
        std::move(loaders),
        std::make_unique<json_descriptor_provider>(descriptor_with_missing_property));

    ASSERT_EQ("hello", registry.get_value<std::string>("core.missing"));
}

TEST(config, config_registry_get_value_wrong_type_throws)
{
    conf_file_writer json_config(sample_json_config);

    std::queue<std::unique_ptr<loader>> loaders;
    loaders.push(std::make_unique<json_loader>(json_config.get()));

    config_registry registry(std::move(loaders),
                             std::make_unique<json_descriptor_provider>(sample_descriptor));

    ASSERT_THROW(registry.get_value<std::string>("core.log.level"), xlio_exception);
}

TEST(config, config_registry_missing_descriptor_for_key_throws)
{
    conf_file_writer json_config(sample_json_config);

    std::queue<std::unique_ptr<loader>> loaders;
    loaders.push(std::make_unique<json_loader>(json_config.get()));

    config_registry registry(std::move(loaders),
                             std::make_unique<json_descriptor_provider>(sample_descriptor));

    // Attempting to get a key that neither exists in the loaded data nor in the descriptor
    // should result in an exception.
    ASSERT_THROW(registry.get_value<bool>("nonexistent.key"), xlio_exception);
}

TEST(config, config_registry_empty_loaders_throw)
{
    std::queue<std::unique_ptr<loader>> empty_loaders;

    ASSERT_THROW(
        config_registry registry(std::move(empty_loaders),
                                 std::make_unique<json_descriptor_provider>(sample_descriptor)),
        xlio_exception);
}

TEST(config, config_registry_boundary_constraint)
{
    conf_file_writer json_config1(R"({ "core": { "log": { "level": -2 } } })");

    std::queue<std::unique_ptr<loader>> loaders;
    loaders.push(std::make_unique<json_loader>(json_config1.get()));

    config_registry registry(std::move(loaders),
                             std::make_unique<json_descriptor_provider>(sample_descriptor));

    ASSERT_EQ(-2, registry.get_value<int64_t>("core.log.level"));

    // Now test with a value equal to the maximum.
    conf_file_writer json_config2(R"({ "core": { "log": { "level": 8 } } })");

    std::queue<std::unique_ptr<loader>> loaders2;
    loaders2.push(std::make_unique<json_loader>(json_config2.get()));

    config_registry registry2(std::move(loaders2),
                              std::make_unique<json_descriptor_provider>(sample_descriptor));

    ASSERT_EQ(8, registry2.get_value<int64_t>("core.log.level"));
}

TEST(config, config_registry_mixed_loaders_merge)
{
    conf_file_writer json_config(R"({
        "core": {
            "json_only": "from_json"
        }
    })");

    env_setter inline_setter("XLIO_INLINE_CONFIG", "core.inline_only=from_inline");

    std::queue<std::unique_ptr<loader>> loaders;
    loaders.push(std::make_unique<json_loader>(json_config.get()));
    loaders.push(std::make_unique<inline_loader>("XLIO_INLINE_CONFIG"));

    const char *descriptor = R"({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "XLIO Configuration Schema",
    "description": "Schema for XLIO configuration",
    "type": "object",
    "properties": {
        "core": {
            "description": "controls the core functionality of libxlio.",
            "type": "object",
            "properties": {
                "json_only": {
                    "type": "string",
                    "default": "from_json",
                    "title": "Json only",
                    "description": "dummy description"
                },
                "inline_only": {
                    "type": "string",
                    "default": "from_inline",
                    "title": "Inline only",
                    "description": "dummy description"
                },
            }
        }
    }
})";

    config_registry registry(std::move(loaders),
                             std::make_unique<json_descriptor_provider>(descriptor));

    ASSERT_EQ("from_json", registry.get_value<std::string>("core.json_only"));
    ASSERT_EQ("from_inline", registry.get_value<std::string>("core.inline_only"));
}

TEST(config, config_registry_default_ctr_inline_has_precedence)
{
    conf_file_writer json_config(R"({ "monitor": { "log": { "level": 2 } } })");
    env_setter inline_setter("XLIO_INLINE_CONFIG", "monitor.log.level=5");
    env_setter config_file_setter("XLIO_CONFIG_FILE", json_config.get());

    config_registry registry;

    ASSERT_EQ(5, registry.get_value<int64_t>("monitor.log.level"));
}

TEST(config, config_registry_pattern_transformer_applied)
{
    conf_file_writer json_config(
        R"({ "core": { "syscall": { "sendfile_cache_limit": "10GB" } } })");

    env_setter config_file_setter("XLIO_CONFIG_FILE", json_config.get());

    config_registry registry;

    ASSERT_EQ(10737418240LL, registry.get_value<int64_t>("core.syscall.sendfile_cache_limit"));
}

TEST(config, config_registry_default_ctr_inline_corrupted_json_ok_throws)
{
    conf_file_writer json_config(R"({ "core": { "log": { "level": 2 } } })");
    env_setter inline_setter("XLIO_INLINE_CONFIG", "core.log.level5");
    env_setter config_file_setter("XLIO_CONFIG_FILE", json_config.get());

    ASSERT_THROW(config_registry(), xlio_exception);
}

TEST(config, config_registry_memory_size_transformer_gb_suffix)
{
    const char *memory_schema = R"({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "XLIO Configuration Schema",
    "description": "Schema for XLIO configuration",
    "type": "object",
    "properties": {
        "core": {
            "description": "controls the core functionality of libxlio.",
            "type": "object",
            "properties": {
                "memory_limit": {
                    "oneOf": [
                        {
                            "type": "integer",
                            "minimum": 0,
                            "default": 2147483648
                        },
                        {
                            "type": "string",
                            "default": "2GB",
                            "pattern": "^[0-9]+[KMGkmg]?[B]?$"
                        }
                    ],
                    "title": "Memory limit",
               "description" : "Memory limit in bytes. Supports suffixes: B, KB, MB, GB.",
               "x-memory-size" : true
}
}
}
}
})";

    conf_file_writer json_config(R"({ "core": { "memory_limit": "4GB" } })");

    std::queue<std::unique_ptr<loader>> loaders;
    loaders.push(std::make_unique<json_loader>(json_config.get()));

    config_registry registry(std::move(loaders),
                             std::make_unique<json_descriptor_provider>(memory_schema));

    // 4GB = 4 * 1024 * 1024 * 1024 = 4294967296 bytes
    ASSERT_EQ(4294967296LL, registry.get_value<int64_t>("core.memory_limit"));
}

TEST(config, config_registry_memory_size_transformer_mb_suffix)
{
    const char *memory_schema = R"({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "XLIO Configuration Schema",
    "description": "Schema for XLIO configuration",
    "type": "object",
    "properties": {
        "core": {
            "description": "controls the core functionality of libxlio.",
            "type": "object",
            "properties": {
                "memory_limit": {
                    "oneOf": [
                        {
                            "type": "integer",
                            "minimum": 0,
                            "default": 2147483648
                        },
                        {
                            "type": "string",
                            "default": "2GB",
                            "pattern": "^[0-9]+[KMGkmg]?[B]?$"
                        }
                    ],
                    "title": "Memory limit",
               "description" : "Memory limit in bytes. Supports suffixes: B, KB, MB, GB.",
               "x-memory-size" : true
}
}
}
}
})";

    conf_file_writer json_config(R"({ "core": { "memory_limit": "512MB" } })");

    std::queue<std::unique_ptr<loader>> loaders;
    loaders.push(std::make_unique<json_loader>(json_config.get()));

    config_registry registry(std::move(loaders),
                             std::make_unique<json_descriptor_provider>(memory_schema));

    // 512MB = 512 * 1024 * 1024 = 536870912 bytes
    ASSERT_EQ(536870912LL, registry.get_value<int64_t>("core.memory_limit"));
}

TEST(config, config_registry_memory_size_transformer_plain_number_backwards_compatibility)
{
    const char *memory_schema = R"({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "XLIO Configuration Schema",
    "description": "Schema for XLIO configuration",
    "type": "object",
    "properties": {
        "core": {
            "description": "controls the core functionality of libxlio.",
            "type": "object",
            "properties": {
                "memory_limit": {
                    "oneOf": [
                        {
                            "type": "integer",
                            "minimum": 0,
                            "default": 2147483648
                        },
                        {
                            "type": "string",
                            "default": "2GB",
                            "pattern": "^[0-9]+[KMGkmg]?[B]?$"
                        }
                    ],
                    "title": "Memory limit",
               "description" : "Memory limit in bytes. Supports suffixes: B, KB, MB, GB.",
               "x-memory-size" : true
}
}
}
}
})";

    conf_file_writer json_config(R"({ "core": { "memory_limit": 1073741824 } })");

    std::queue<std::unique_ptr<loader>> loaders;
    loaders.push(std::make_unique<json_loader>(json_config.get()));

    config_registry registry(std::move(loaders),
                             std::make_unique<json_descriptor_provider>(memory_schema));

    // Plain number should work as before (1GB in bytes)
    ASSERT_EQ(1073741824LL, registry.get_value<int64_t>("core.memory_limit"));
}

TEST(config, config_registry_memory_size_transformer_inline_config)
{
    // Test with the inline config loader to ensure memory size suffixes work there too
    env_setter inline_setter("XLIO_INLINE_CONFIG", "core.memory_limit=2GB");

    const char *memory_schema = R"({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "XLIO Configuration Schema",
    "description": "Schema for XLIO configuration",
    "type": "object",
    "properties": {
        "core": {
            "description": "controls the core functionality of libxlio.",
            "type": "object",
            "properties": {
                "memory_limit": {
                    "oneOf": [
                        {
                            "type": "integer",
                            "minimum": 0,
                            "default": 2147483648
                        },
                        {
                            "type": "string",
                            "default": "2GB",
                            "pattern": "^[0-9]+[KMGkmg]?[B]?$"
                        }
                    ],
                    "title": "Memory limit",
               "description" : "Memory limit in bytes. Supports suffixes: B, KB, MB, GB.",
               "x-memory-size" : true
}
}
}
}
})";

    std::queue<std::unique_ptr<loader>> loaders;
    loaders.push(std::make_unique<inline_loader>("XLIO_INLINE_CONFIG"));

    config_registry registry(std::move(loaders),
                             std::make_unique<json_descriptor_provider>(memory_schema));

    // 2GB = 2 * 1024 * 1024 * 1024 = 2147483648 bytes
    ASSERT_EQ(2147483648LL, registry.get_value<int64_t>("core.memory_limit"));
}

// Helper descriptor for type validation tests
static const char *sample_type_validation_descriptor = R"({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "XLIO Configuration Schema",
    "description": "Schema for XLIO configuration",
    "type": "object",
    "properties": {
        "performance": {
            "type": "object",
            "description": "Performance-related settings",
            "properties": {
                "rings": {
                    "type": "object",
                    "description": "Ring configuration",
                    "properties": {
                        "tx": {
                            "type": "object",
                            "description": "Transmission ring settings",
                            "properties": {
                                "udp_buffer_batch": {
                                    "type": "integer",
                                    "default": 16,
                                    "minimum": 1,
                                    "title": "TX buffer batch size",
                                    "description": "Number of TX buffers fetched by a UDP socket at once"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
})";

TEST(config, config_registry_boolean_type_mismatch_throws)
{
    // Test that boolean values are rejected for integer parameters during loading
    // This test specifically catches the bug where boolean values were accepted for integer
    // parameters

    conf_file_writer json_config(R"({
        "performance": {
            "rings": {
                "tx": {
                    "udp_buffer_batch": true
                }
            }
        }
    })");

    std::queue<std::unique_ptr<loader>> loaders;
    loaders.push(std::make_unique<json_loader>(json_config.get()));

    ASSERT_THROW(config_registry(
                     std::move(loaders),
                     std::make_unique<json_descriptor_provider>(sample_type_validation_descriptor)),
                 xlio_exception);
}

TEST(config, config_registry_string_type_mismatch_throws)
{
    // Test that string values are rejected for integer parameters during loading

    conf_file_writer json_config(R"({
        "performance": {
            "rings": {
                "tx": {
                    "udp_buffer_batch": "invalid"
                }
            }
        }
    })");

    std::queue<std::unique_ptr<loader>> loaders;
    loaders.push(std::make_unique<json_loader>(json_config.get()));

    ASSERT_THROW(config_registry(
                     std::move(loaders),
                     std::make_unique<json_descriptor_provider>(sample_type_validation_descriptor)),
                 xlio_exception);
}

TEST(config, config_registry_valid_integer_works)
{
    // Test that valid integer values work correctly
    conf_file_writer json_config(R"({
        "performance": {
            "rings": {
                "tx": {
                    "udp_buffer_batch": 32
                }
            }
        }
    })");

    std::queue<std::unique_ptr<loader>> loaders;
    loaders.push(std::make_unique<json_loader>(json_config.get()));

    config_registry registry(
        std::move(loaders),
        std::make_unique<json_descriptor_provider>(sample_type_validation_descriptor));

    ASSERT_EQ(32LL, registry.get_value<int64_t>("performance.rings.tx.udp_buffer_batch"));
}

TEST(config, config_registry_missing_uses_default)
{
    // Test that missing parameters use their default values

    conf_file_writer json_config(R"({
        "performance": {
            "rings": {
                "tx": {}
            }
        }
    })");

    std::queue<std::unique_ptr<loader>> loaders;
    loaders.push(std::make_unique<json_loader>(json_config.get()));

    config_registry registry(
        std::move(loaders),
        std::make_unique<json_descriptor_provider>(sample_type_validation_descriptor));

    ASSERT_EQ(16LL, registry.get_value<int64_t>("performance.rings.tx.udp_buffer_batch"));
}
