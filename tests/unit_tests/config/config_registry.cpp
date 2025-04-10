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

// our config provider represents ints by int64_t, for size_t we can lose information
// so instead of static_cast and risk bugs, we throw to inform the user on load time.
TEST(config, config_registry_get_value_size_t_throws)
{
    conf_file_writer json_config(sample_json_config);

    std::queue<std::unique_ptr<loader>> loaders;
    loaders.push(std::make_unique<json_loader>(json_config.get()));

    config_registry registry(std::move(loaders),
                             std::make_unique<json_descriptor_provider>(sample_descriptor));

    ASSERT_THROW(registry.get_value<size_t>("core.log.level"), xlio_exception);
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
    conf_file_writer json_config(R"({ "observability": { "log": { "level": 2 } } })");
    env_setter inline_setter("XLIO_INLINE_CONFIG", "observability.log.level=5");
    env_setter config_file_setter("XLIO_CUSTOM_CONFIG_FILE", json_config.get());

    config_registry registry;

    ASSERT_EQ(5, registry.get_value<int64_t>("observability.log.level"));
}

TEST(config, config_registry_default_ctr_inline_corrupted_json_ok_throws)
{
    conf_file_writer json_config(R"({ "core": { "log": { "level": 2 } } })");
    env_setter inline_setter("XLIO_INLINE_CONFIG", "core.log.level5");
    env_setter config_file_setter("XLIO_CUSTOM_CONFIG_FILE", json_config.get());

    ASSERT_THROW(config_registry(), xlio_exception);
}