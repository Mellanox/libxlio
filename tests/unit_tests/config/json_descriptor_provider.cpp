/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <gtest/gtest.h>
#include "descriptor_providers/json_descriptor_provider.h"
#include "xlio_exception.h"
#include "utils.h"

TEST(config, json_descriptor_provider_sanity)
{
    json_descriptor_provider provider(R"({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "XLIO Configuration Schema",
    "description": "Schema for XLIO configuration",
    "type": "object",
    "properties": {
        "core": {
            "type": "object",
            "title": "controls the core functionality of libxlio.",
            "description": "The core category includes fundamental system or application configurations, focusing on essential functionalities like logging, statistics collection, initialization processes, CPU usage, memory management, exception handling, and signal processing.",
            "properties": {
                "append_pid_to_path": {
                    "type": "boolean",
                    "default": false,
                    "title": "Append PID to dirs",
                    "description": "Append PID to xlio.daemon.dir, core.stats.shmem_dir, core.stats.file_path, core.log.file_path."
                },
                "log": {
                    "type": "object",
                    "description": "controls logging behavior.",
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
                            "title": "Sets log level.",
                            "description": "Sets level according to desired logging verbosity."
                        }
                    }
                }
            }
        }
    }
})");

    config_descriptor cd = provider.load_descriptors();
    ASSERT_EQ(
        3,
        std::experimental::any_cast<int64_t>(cd.get_parameter("core.log.level").default_value()));
    ASSERT_EQ(false,
              std::experimental::any_cast<bool>(
                  cd.get_parameter("core.append_pid_to_path").default_value()));
}

TEST(config, json_descriptor_provider_invalid_json_throws)
{
    json_descriptor_provider provider(R"({
            "$schema": "http://json-schema.org/draft-07/schema#","lolzzzzzzzzzzzzzzzz"
            "title": "XLIO Configuration Schema",
            "description": "Schema for XLIO configuration",
            "type": "object",
            "properties": {
                "core": {
                    "type": "object",
                    "description": "controls the core functionality of libxlio.",
                    "properties": {
                        "append_pid_to_path": {
                            "type": "boolean",
                            "default": false,
                            "title": "Append PID to dirs",
                            "description": "Append PID to xlio.daemon.dir, core.stats.shmem_dir, core.stats.file_path, core.log.file_path."
                        },
                        "log": {
                            "type": "object",
                            "description": "controls logging behavior.",
                            "properties": {
                                "level": {
                                    "oneOf": [
                                        {
                                            "type": "integer",
                                            "minimum": -2,
                                            "maximum": 8
                                        },
                                        {
                                            "type": "string",
                                            "enum": [
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
                                            ]
                                        }
                                    ],
                                    "default": 3,
                                    "title": "Sets log level.",
                                    "description": "Sets level according to desired logging verbosity."
                                }
                            }
                        }
                    }
                }
            }
        })");

    ASSERT_THROW(provider.load_descriptors(), xlio_exception);
}

TEST(config, json_descriptor_provider_no_description_throws)
{
    // core.log.level has no description - should throw
    json_descriptor_provider provider(R"({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "XLIO Configuration Schema",
    "description": "Schema for XLIO configuration",
    "type": "object",
    "properties": {
        "core": {
            "type": "object",
            "description": "controls the core functionality of libxlio.",
            "properties": {
                "append_pid_to_path": {
                    "type": "boolean",
                    "default": false,
                    "title": "Append PID to dirs",
                    "description": "Append PID to xlio.daemon.dir, core.stats.shmem_dir, core.stats.file_path, core.log.file_path."
                },
                "log": {
                    "type": "object",
                    "description": "controls logging behavior.",
                    "properties": {
                        "level": {
                            "oneOf": [
                                {
                                    "type": "integer",
                                    "minimum": -2,
                                    "maximum": 8
                                },
                                {
                                    "type": "string",
                                    "enum": [
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
                                    ]
                                }
                            ],
                            "default": 3,
                        }
                    }
                }
            }
        }
    }
})");

    ASSERT_THROW(provider.load_descriptors(), xlio_exception);
}

// finding duplications is not supported OOB in libjson-c
// introducing such logic will complicate the code and not worth it ROI
TEST(config, json_descriptor_provider_duplication_last_is_taken)
{
    json_descriptor_provider provider(R"({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "XLIO Configuration Schema",
    "description": "Schema for XLIO configuration",
    "type": "object",
    "properties": {
        "core": {
            "type": "object",
            "description": "controls the core functionality of libxlio.",
            "properties": {
                "append_pid_to_path": {
                    "type": "boolean",
                    "default": false,
                    "title": "Append PID to dirs",
                    "description": "Append PID to xlio.daemon.dir, core.stats.shmem_dir, core.stats.file_path, core.log.file_path."
                },
                "append_pid_to_path": {
                    "type": "boolean",
                    "default": true,
                    "title": "Append PID to dirs",
                    "description": "Append PID to xlio.daemon.dir, core.stats.shmem_dir, core.stats.file_path, core.log.file_path."
                }
            }
        }
    }
})");

    config_descriptor cd = provider.load_descriptors();
    ASSERT_EQ(true,
              std::experimental::any_cast<bool>(
                  cd.get_parameter("core.append_pid_to_path").default_value()));
}

TEST(config, json_descriptor_provider_unrecognized_type_throws)
{
    json_descriptor_provider provider(R"({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "XLIO Configuration Schema",
    "description": "Schema for XLIO configuration",
    "type": "object",
    "properties": {
        "core": {
            "type": "object",
            "description": "controls the core functionality of libxlio.",
            "properties": {
                "lolz": {
                    "type": "float",
                    "default": 3.5,
                    "title": "Sets log level.",
                    "description": "Append PID to xlio.daemon.dir, core.stats.shmem_dir, core.stats.file_path, core.log.file_path."
                },
            }
        }
    }
})");
    ASSERT_THROW(provider.load_descriptors(), xlio_exception);
}

TEST(config, json_descriptor_provider_array_support)
{
    json_descriptor_provider provider(R"({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "XLIO Configuration Schema",
    "description": "Schema for XLIO configuration",
    "type": "object",
    "properties": {
        "net": {
            "type": "object",
            "description": "network configuration",
            "properties": {
                "offload": {
                    "type": "object",
                    "description": "controls hardware offload capabilities.",
                    "properties": {
                        "rules": {
                            "type": "array",
                            "default": [],
                            "title": "Transport control per apps.",
                            "description": "Transport control per apps.",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "id": {
                                        "type": "string",
                                        "description": "Identifier for the transport control"
                                    },
                                    "name": {
                                        "type": "string",
                                        "description": "Name of the application"
                                    },
                                    "actions": {
                                        "type": "array",
                                        "description": "List of actions for the transport control",
                                        "items": {
                                            "type": "string"
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
})");

    config_descriptor cd = provider.load_descriptors();
    auto acceleration_rules = cd.get_parameter("net.offload.rules").default_value();

    // Default should be an empty array
    std::vector<std::experimental::any> tc_array =
        std::experimental::any_cast<std::vector<std::experimental::any>>(acceleration_rules);
    ASSERT_TRUE(tc_array.empty());
}

TEST(config, json_descriptor_provider_array_with_default_values)
{
    json_descriptor_provider provider(R"({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "XLIO Configuration Schema",
    "description": "Schema for XLIO configuration",
    "type": "object",
    "properties": {
        "test": {
            "type": "object",
            "description": "test object",
            "properties": {
                "string_array": {
                    "type": "array",
                    "default": ["value1", "value2", "value3"],
                    "description": "Array of strings",
                    "title": "String array",
                    "items": {
                        "type": "string"
                    }
                },
                "int_array": {
                    "type": "array",
                    "default": [1, 2, 3],
                    "description": "Array of integers",
                    "title": "Integer array",
                    "items": {
                        "type": "integer"
                    }
                }
            }
        }
    }
})");

    config_descriptor cd = provider.load_descriptors();

    // Check string array
    auto string_array = cd.get_parameter("test.string_array").default_value();
    std::vector<std::experimental::any> str_array =
        std::experimental::any_cast<std::vector<std::experimental::any>>(string_array);

    ASSERT_EQ(static_cast<size_t>(3), str_array.size());
    ASSERT_EQ("value1", std::experimental::any_cast<std::string>(str_array[0]));
    ASSERT_EQ("value2", std::experimental::any_cast<std::string>(str_array[1]));
    ASSERT_EQ("value3", std::experimental::any_cast<std::string>(str_array[2]));

    // Check integer array
    auto int_array = cd.get_parameter("test.int_array").default_value();
    std::vector<std::experimental::any> i_array =
        std::experimental::any_cast<std::vector<std::experimental::any>>(int_array);

    ASSERT_EQ(static_cast<size_t>(3), i_array.size());
    ASSERT_EQ(1, std::experimental::any_cast<int64_t>(i_array[0]));
    ASSERT_EQ(2, std::experimental::any_cast<int64_t>(i_array[1]));
    ASSERT_EQ(3, std::experimental::any_cast<int64_t>(i_array[2]));
}

TEST(config, json_descriptor_provider_array_of_objects)
{
    json_descriptor_provider provider(R"({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "XLIO Configuration Schema",
    "description": "Schema for XLIO configuration",
    "type": "object",
    "properties": {
        "net": {
            "type": "object",
            "description": "network configuration",
            "properties": {
                "offload": {
                    "type": "object",
                    "description": "controls hardware offload capabilities.",
                    "properties": {
                        "rules": {
                            "type": "array",
                            "default": [
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
                            ],
                            "description": "Transport control per apps.",
                            "title": "Transport control per apps.",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "id": {
                                        "type": "string",
                                        "description": "Identifier for the transport control"
                                    },
                                    "name": {
                                        "type": "string",
                                        "description": "Name of the application"
                                    },
                                    "actions": {
                                        "type": "array",
                                        "description": "List of actions for the transport control",
                                        "items": {
                                            "type": "string"
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
})");

    config_descriptor cd = provider.load_descriptors();
    auto acceleration_rules = cd.get_parameter("net.offload.rules").default_value();

    // Should be an array with two objects
    std::vector<std::experimental::any> tc_array =
        std::experimental::any_cast<std::vector<std::experimental::any>>(acceleration_rules);
    ASSERT_EQ(static_cast<size_t>(2), tc_array.size());

    // Check first object
    auto app1 =
        std::experimental::any_cast<std::map<std::string, std::experimental::any>>(tc_array[0]);
    ASSERT_EQ("app1", std::experimental::any_cast<std::string>(app1["id"]));
    ASSERT_EQ("Application 1", std::experimental::any_cast<std::string>(app1["name"]));

    auto app1_actions =
        std::experimental::any_cast<std::vector<std::experimental::any>>(app1["actions"]);
    ASSERT_EQ(static_cast<size_t>(2), app1_actions.size());
    ASSERT_EQ("action1", std::experimental::any_cast<std::string>(app1_actions[0]));
    ASSERT_EQ("action2", std::experimental::any_cast<std::string>(app1_actions[1]));

    // Check second object
    auto app2 =
        std::experimental::any_cast<std::map<std::string, std::experimental::any>>(tc_array[1]);
    ASSERT_EQ("app2", std::experimental::any_cast<std::string>(app2["id"]));
    ASSERT_EQ("Application 2", std::experimental::any_cast<std::string>(app2["name"]));

    auto app2_actions =
        std::experimental::any_cast<std::vector<std::experimental::any>>(app2["actions"]);
    ASSERT_EQ(static_cast<size_t>(1), app2_actions.size());
    ASSERT_EQ("action3", std::experimental::any_cast<std::string>(app2_actions[0]));
}

TEST(config, json_descriptor_provider_oneOf_memory_size_parsing)
{
    json_descriptor_provider provider(R"({
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
                    "description": "Memory limit in bytes. Supports suffixes: B, KB, MB, GB.",
                    "x-memory-size": true
                }
            }
        }
    }
})");

    config_descriptor cd = provider.load_descriptors();

    // Should parse oneOf schema correctly and return int64_t default value
    int64_t default_value =
        std::experimental::any_cast<int64_t>(cd.get_parameter("core.memory_limit").default_value());
    ASSERT_EQ(2147483648LL, default_value);
}

TEST(config, json_descriptor_provider_oneOf_without_memory_size_flag)
{
    // Test oneOf schema without x-memory-size flag should still work
    json_descriptor_provider provider(R"({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "XLIO Configuration Schema",
    "description": "Schema for XLIO configuration",
    "type": "object",
    "properties": {
        "core": {
            "description": "controls the core functionality of libxlio.",
            "type": "object",
            "properties": {
                "regular_param": {
                    "oneOf": [
                        {
                            "type": "integer",
                            "minimum": 0,
                            "default": 42,
                            "enum": [42, 43]
                        },
                        {
                            "type": "string",
                            "enum": ["42", "43"]
                        }
                    ],
                    "title": "Regular parameter",
                    "description": "A regular parameter using oneOf without memory size."
                }
            }
        }
    }
})");

    config_descriptor cd = provider.load_descriptors();

    // Should parse oneOf schema and detect integer type correctly
    int64_t default_value = std::experimental::any_cast<int64_t>(
        cd.get_parameter("core.regular_param").default_value());
    ASSERT_EQ(42LL, default_value);
}

TEST(config, json_descriptor_provider_memory_size_transformer_applied)
{
    json_descriptor_provider provider(R"({
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "XLIO Configuration Schema",
    "description": "Schema for XLIO configuration",
    "type": "object",
    "properties": {
        "core": {
            "description": "controls the core functionality of libxlio.",
            "type": "object",
            "properties": {
                "memory_with_transformer": {
                    "oneOf": [
                        {
                            "type": "integer",
                            "minimum": 0,
                            "default": 1073741824
                        },
                        {
                            "type": "string",
                            "default": "1GB",
                            "pattern": "^[0-9]+[KMGkmg]?[B]?$"
                        }
                    ],
                    "title": "Memory with transformer",
                    "description": "Memory param with transformer.",
                    "x-memory-size": true
                },
                "memory_without_transformer": {
                    "type": "integer",
                    "default": 1073741824,
                    "title": "Memory without transformer",
                    "description": "Memory param without transformer."
                }
            }
        }
    }
})");

    config_descriptor cd = provider.load_descriptors();

    // Get both parameters to verify transformer is only applied where x-memory-size is true
    parameter_descriptor with_transformer = cd.get_parameter("core.memory_with_transformer");
    parameter_descriptor without_transformer = cd.get_parameter("core.memory_without_transformer");

    // Test that the transformer transforms "1GB" to bytes for the parameter with x-memory-size
    std::experimental::any gb_string = std::string("1GB");
    std::experimental::any transformed = with_transformer.get_value(gb_string);
    int64_t transformed_value = std::experimental::any_cast<int64_t>(transformed);
    ASSERT_EQ(1073741824LL, transformed_value); // 1GB in bytes

    // Test that parameter without transformer throws an exception
    ASSERT_THROW(without_transformer.get_value(gb_string), std::experimental::bad_any_cast);
}
