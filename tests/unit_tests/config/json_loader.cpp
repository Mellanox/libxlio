/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <gtest/gtest.h>
#include "loaders/json_loader.h"
#include "xlio_exception.h"
#include "utils.h"

const char *valid_cfg_str = R"({
                    "core": {
                        "log": {
                            "level": 2,
                            "file_path": "/var/log/xlio.log"
                        },
                        "exit_report": true
                    },
                    "net": {
                        "mtu": 1500,
                        "offload": {
                            "enable": true
                        },
                        "tcp": {
                            "mss": 1000
                        }
                    }
                    })";

TEST(config, json_loader_sanity)
{
    conf_file_writer json_config = conf_file_writer(valid_cfg_str);

    json_loader loader(json_config.get());

    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(2, std::experimental::any_cast<int64_t>(data["core.log.level"]));
    ASSERT_EQ("/var/log/xlio.log",
              std::experimental::any_cast<std::string>(data["core.log.file_path"]));
    ASSERT_EQ(true, std::experimental::any_cast<bool>(data["core.exit_report"]));
    ASSERT_EQ(2, std::experimental::any_cast<int64_t>(data["core.log.level"]));
    ASSERT_EQ("/var/log/xlio.log",
              std::experimental::any_cast<std::string>(data["core.log.file_path"]));
    ASSERT_EQ(true, std::experimental::any_cast<bool>(data["core.exit_report"]));
    ASSERT_EQ(1500, std::experimental::any_cast<int64_t>(data["net.mtu"]));
    ASSERT_EQ(true, std::experimental::any_cast<bool>(data["net.offload.enable"]));
    ASSERT_EQ(1000, std::experimental::any_cast<int64_t>(data["net.tcp.mss"]));
}

// missing '}' in the end of the json string
TEST(config, json_loader_invalid_json)
{
    conf_file_writer json_config = conf_file_writer(R"({ "core": { "log": { "level": 2 } } )");

    json_loader loader(json_config.get());
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, json_loader_comments_work)
{
    conf_file_writer json_config = conf_file_writer(R"({ "core": { "log": { "level": 2
    // this is my comment
     } } })");

    json_loader loader(json_config.get());
    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(2, std::experimental::any_cast<int64_t>(data["core.log.level"]));
}

TEST(config, json_loader_load_all_same_data)
{
    conf_file_writer json_config(R"({
        "core": { "log": { "level": 2 } }
    })");

    json_loader loader(json_config.get());

    std::map<std::string, std::experimental::any> data = loader.load_all();
    std::map<std::string, std::experimental::any> data2 = loader.load_all();

    ASSERT_EQ(data.size(), data2.size());
    ASSERT_EQ(std::experimental::any_cast<int64_t>(data["core.log.level"]),
              std::experimental::any_cast<int64_t>(data2["core.log.level"]));
}

TEST(config, json_loader_unsupported_double)
{
    conf_file_writer json_config(R"({
       "core": { "log": { "level": 2.5 } }
    })");
    json_loader loader(json_config.get());
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, json_loader_flattens_nested_objects)
{
    conf_file_writer json_config(R"({
        "a": {
            "b": {
                "c": 42,
                "d": "hello"
            },
            "e": true
        }
    })");

    json_loader loader(json_config.get());

    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(42, std::experimental::any_cast<int64_t>(data["a.b.c"]));
    ASSERT_EQ("hello", std::experimental::any_cast<std::string>(data["a.b.d"]));
    ASSERT_EQ(true, std::experimental::any_cast<bool>(data["a.e"]));
}

TEST(config, json_loader_file_not_exists)
{
    ASSERT_THROW(json_loader("/tmp/this_file_should_not_exist_123456789.json"), xlio_exception);
}

TEST(config, json_loader_load_huge_int_value)
{
    conf_file_writer json_config(R"({ "core": { "memory": { "limit": 50000000000 } } })");

    json_loader loader(json_config.get());

    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(50000000000, std::experimental::any_cast<int64_t>(data["core.memory.limit"]));
}

TEST(config, json_loader_array_simple)
{
    conf_file_writer json_config(R"({
        "test": {
            "string_array": ["one", "two", "three"],
            "int_array": [1, 2, 3],
            "bool_array": [true, false, true]
        }
    })");

    json_loader loader(json_config.get());
    std::map<std::string, std::experimental::any> data = loader.load_all();

    // Check string array
    auto string_array =
        std::experimental::any_cast<std::vector<std::experimental::any>>(data["test.string_array"]);
    ASSERT_EQ(static_cast<size_t>(3), string_array.size());
    ASSERT_EQ("one", std::experimental::any_cast<std::string>(string_array[0]));
    ASSERT_EQ("two", std::experimental::any_cast<std::string>(string_array[1]));
    ASSERT_EQ("three", std::experimental::any_cast<std::string>(string_array[2]));

    // Check int array
    auto int_array =
        std::experimental::any_cast<std::vector<std::experimental::any>>(data["test.int_array"]);
    ASSERT_EQ(static_cast<size_t>(3), int_array.size());
    ASSERT_EQ(1, std::experimental::any_cast<int64_t>(int_array[0]));
    ASSERT_EQ(2, std::experimental::any_cast<int64_t>(int_array[1]));
    ASSERT_EQ(3, std::experimental::any_cast<int64_t>(int_array[2]));

    // Check bool array
    auto bool_array =
        std::experimental::any_cast<std::vector<std::experimental::any>>(data["test.bool_array"]);
    ASSERT_EQ(static_cast<size_t>(3), bool_array.size());
    ASSERT_EQ(true, std::experimental::any_cast<bool>(bool_array[0]));
    ASSERT_EQ(false, std::experimental::any_cast<bool>(bool_array[1]));
    ASSERT_EQ(true, std::experimental::any_cast<bool>(bool_array[2]));
}

// Test for dot validation - prevents keys with dots in JSON
TEST(config, json_loader_rejects_keys_with_dots)
{
    // Test Method A from the ticket - should be rejected
    conf_file_writer json_config(R"({
        "core": {
            "resources.memory_limit": "50GB"
        }
    })");

    json_loader loader(json_config.get());
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

// Test that proper nested structure (Method B) still works
TEST(config, json_loader_accepts_proper_nested_structure)
{
    // Test Method B from the ticket - should work correctly
    conf_file_writer json_config(R"({
        "core": {
            "resources": {
                "memory_limit": "50GB"
            }
        }
    })");

    json_loader loader(json_config.get());
    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ("50GB",
              std::experimental::any_cast<std::string>(data["core.resources.memory_limit"]));
}

// Test various edge cases for dot validation
TEST(config, json_loader_dot_validation_edge_cases)
{
    // Test key with multiple dots
    {
        conf_file_writer json_config(R"({
            "core": {
                "a.b.c": "value"
            }
        })");
        json_loader loader(json_config.get());
        ASSERT_THROW(loader.load_all(), xlio_exception);
    }

    // Test key starting with dot
    {
        conf_file_writer json_config(R"({
            "core": {
                ".hidden": "value"
            }
        })");
        json_loader loader(json_config.get());
        ASSERT_THROW(loader.load_all(), xlio_exception);
    }

    // Test key ending with dot
    {
        conf_file_writer json_config(R"({
            "core": {
                "suffix.": "value"
            }
        })");
        json_loader loader(json_config.get());
        ASSERT_THROW(loader.load_all(), xlio_exception);
    }

    // Test key with only dots
    {
        conf_file_writer json_config(R"({
            "core": {
                "...": "value"
            }
        })");
        json_loader loader(json_config.get());
        ASSERT_THROW(loader.load_all(), xlio_exception);
    }
}

// Test that valid keys without dots still work
TEST(config, json_loader_valid_keys_without_dots)
{
    conf_file_writer json_config(R"({
        "core": {
            "log_level": 2,
            "memory_limit": "1GB",
            "enable_feature": true,
            "nested": {
                "value": "test"
            }
        }
    })");

    json_loader loader(json_config.get());
    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(2, std::experimental::any_cast<int64_t>(data["core.log_level"]));
    ASSERT_EQ("1GB", std::experimental::any_cast<std::string>(data["core.memory_limit"]));
    ASSERT_EQ(true, std::experimental::any_cast<bool>(data["core.enable_feature"]));
    ASSERT_EQ("test", std::experimental::any_cast<std::string>(data["core.nested.value"]));
}

TEST(config, json_loader_array_of_objects)
{
    conf_file_writer json_config(R"({
        "users": [
            {
                "id": 1,
                "name": "John",
                "active": true
            },
            {
                "id": 2,
                "name": "Jane",
                "active": false
            }
        ]
    })");

    json_loader loader(json_config.get());
    std::map<std::string, std::experimental::any> data = loader.load_all();

    auto users = std::experimental::any_cast<std::vector<std::experimental::any>>(data["users"]);
    ASSERT_EQ(static_cast<size_t>(2), users.size());

    // Check first user
    auto user1 =
        std::experimental::any_cast<std::map<std::string, std::experimental::any>>(users[0]);
    ASSERT_EQ(1, std::experimental::any_cast<int64_t>(user1["id"]));
    ASSERT_EQ("John", std::experimental::any_cast<std::string>(user1["name"]));
    ASSERT_EQ(true, std::experimental::any_cast<bool>(user1["active"]));

    // Check second user
    auto user2 =
        std::experimental::any_cast<std::map<std::string, std::experimental::any>>(users[1]);
    ASSERT_EQ(2, std::experimental::any_cast<int64_t>(user2["id"]));
    ASSERT_EQ("Jane", std::experimental::any_cast<std::string>(user2["name"]));
    ASSERT_EQ(false, std::experimental::any_cast<bool>(user2["active"]));
}

TEST(config, json_loader_nested_arrays)
{
    conf_file_writer json_config(R"({
        "matrix": [
            [1, 2, 3],
            [4, 5, 6],
            [7, 8, 9]
        ]
    })");

    json_loader loader(json_config.get());
    std::map<std::string, std::experimental::any> data = loader.load_all();

    auto matrix = std::experimental::any_cast<std::vector<std::experimental::any>>(data["matrix"]);
    ASSERT_EQ(static_cast<size_t>(3), matrix.size());

    auto row1 = std::experimental::any_cast<std::vector<std::experimental::any>>(matrix[0]);
    ASSERT_EQ(static_cast<size_t>(3), row1.size());
    ASSERT_EQ(1, std::experimental::any_cast<int64_t>(row1[0]));
    ASSERT_EQ(2, std::experimental::any_cast<int64_t>(row1[1]));
    ASSERT_EQ(3, std::experimental::any_cast<int64_t>(row1[2]));

    auto row2 = std::experimental::any_cast<std::vector<std::experimental::any>>(matrix[1]);
    ASSERT_EQ(static_cast<size_t>(3), row2.size());
    ASSERT_EQ(4, std::experimental::any_cast<int64_t>(row2[0]));
    ASSERT_EQ(5, std::experimental::any_cast<int64_t>(row2[1]));
    ASSERT_EQ(6, std::experimental::any_cast<int64_t>(row2[2]));

    auto row3 = std::experimental::any_cast<std::vector<std::experimental::any>>(matrix[2]);
    ASSERT_EQ(static_cast<size_t>(3), row3.size());
    ASSERT_EQ(7, std::experimental::any_cast<int64_t>(row3[0]));
    ASSERT_EQ(8, std::experimental::any_cast<int64_t>(row3[1]));
    ASSERT_EQ(9, std::experimental::any_cast<int64_t>(row3[2]));
}

TEST(config, json_loader_acceleration_rules)
{
    conf_file_writer json_config(R"({
        "net": {
            "offload": {
                "rules": [
                    {
                        "id": "app1",
                        "name": "Application 1",
                        "actions": ["action1", "action2"]
                    },
                    {
                        "id": "app2",
                        "name": "Application 2",
                        "actions": ["action3"]
                    }
                ]
            }
        }
    })");

    json_loader loader(json_config.get());
    std::map<std::string, std::experimental::any> data = loader.load_all();

    auto acceleration_rules =
        std::experimental::any_cast<std::vector<std::experimental::any>>(data["net.offload.rules"]);
    ASSERT_EQ(static_cast<size_t>(2), acceleration_rules.size());

    // Check first app
    auto app1 = std::experimental::any_cast<std::map<std::string, std::experimental::any>>(
        acceleration_rules[0]);
    ASSERT_EQ("app1", std::experimental::any_cast<std::string>(app1["id"]));
    ASSERT_EQ("Application 1", std::experimental::any_cast<std::string>(app1["name"]));

    auto app1_actions =
        std::experimental::any_cast<std::vector<std::experimental::any>>(app1["actions"]);
    ASSERT_EQ(static_cast<size_t>(2), app1_actions.size());
    ASSERT_EQ("action1", std::experimental::any_cast<std::string>(app1_actions[0]));
    ASSERT_EQ("action2", std::experimental::any_cast<std::string>(app1_actions[1]));

    // Check second app
    auto app2 = std::experimental::any_cast<std::map<std::string, std::experimental::any>>(
        acceleration_rules[1]);
    ASSERT_EQ("app2", std::experimental::any_cast<std::string>(app2["id"]));
    ASSERT_EQ("Application 2", std::experimental::any_cast<std::string>(app2["name"]));

    auto app2_actions =
        std::experimental::any_cast<std::vector<std::experimental::any>>(app2["actions"]);
    ASSERT_EQ(static_cast<size_t>(1), app2_actions.size());
    ASSERT_EQ("action3", std::experimental::any_cast<std::string>(app2_actions[0]));
}

TEST(config, json_loader_empty_array)
{
    conf_file_writer json_config(R"({
        "test": {
            "empty_array": []
        }
    })");

    json_loader loader(json_config.get());
    std::map<std::string, std::experimental::any> data = loader.load_all();

    auto empty_array =
        std::experimental::any_cast<std::vector<std::experimental::any>>(data["test.empty_array"]);
    ASSERT_TRUE(empty_array.empty());
}
