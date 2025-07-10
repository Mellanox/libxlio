/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "gtest/gtest.h"
#include "core/config/descriptors/config_descriptor.h"
#include "core/config/descriptors/parameter_descriptor.h"
#include "core/util/xlio_exception.h"

#include <string>
#include <experimental/any>

// Test fixture for basic functionality tests
class config_descriptor_test : public ::testing::Test {
protected:
    config_descriptor desc;

    void SetUp() override
    {
        // Set up some test parameters
        std::experimental::any bool_default = true;
        std::experimental::any int_default = int64_t(42);
        std::experimental::any string_default = std::string("test");

        desc.set_parameter("test.bool_param", parameter_descriptor(bool_default));
        desc.set_parameter("test.int_param", parameter_descriptor(int_default));
        desc.set_parameter("test.string_param", parameter_descriptor(string_default));
    }
};

// Test fixture for error handling and suggestion tests
class config_descriptor_suggestion_test : public ::testing::Test {
protected:
    void SetUp() override
    {
        // Set up a config descriptor with some test parameters
        parameter_descriptor param1(std::experimental::any(std::string("default_val")));
        config_desc.set_parameter("network.tcp.buffer_size", std::move(param1));

        parameter_descriptor param2(std::experimental::any(42));
        config_desc.set_parameter("network.tcp.window_size", std::move(param2));

        parameter_descriptor param3(std::experimental::any(true));
        config_desc.set_parameter("network.udp.enable_checksum", std::move(param3));

        parameter_descriptor param4(std::experimental::any(std::string("info")));
        config_desc.set_parameter("core.log.level", std::move(param4));

        parameter_descriptor param5(std::experimental::any(1024));
        config_desc.set_parameter("memory.pool.max_size", std::move(param5));
    }

    config_descriptor config_desc;
};

// Basic functionality tests
TEST_F(config_descriptor_test, get_existing_parameter)
{
    auto param = desc.get_parameter("test.bool_param");
    ASSERT_EQ(param.default_value().type(), typeid(bool));
    ASSERT_EQ(std::experimental::any_cast<bool>(param.default_value()), true);

    param = desc.get_parameter("test.int_param");
    ASSERT_EQ(param.default_value().type(), typeid(int64_t));
    ASSERT_EQ(std::experimental::any_cast<int64_t>(param.default_value()), 42);

    param = desc.get_parameter("test.string_param");
    ASSERT_EQ(param.default_value().type(), typeid(std::string));
    ASSERT_EQ(std::experimental::any_cast<std::string>(param.default_value()), "test");
}

TEST_F(config_descriptor_test, get_nonexistent_parameter_throws)
{
    ASSERT_THROW(desc.get_parameter("nonexistent.param"), xlio_exception);
    ASSERT_THROW(desc.get_parameter("test.nonexistent"), xlio_exception);
    ASSERT_THROW(desc.get_parameter(""), xlio_exception);
}

TEST_F(config_descriptor_test, set_parameter_ignores_duplicates)
{
    // Verify initial value
    auto param = desc.get_parameter("test.int_param");
    ASSERT_EQ(std::experimental::any_cast<int64_t>(param.default_value()), 42);

    // Try to set the same parameter again - should be ignored (insert-only behavior)
    std::experimental::any new_default = int64_t(100);
    desc.set_parameter("test.int_param", parameter_descriptor(new_default));

    // Verify original value is preserved
    param = desc.get_parameter("test.int_param");
    ASSERT_EQ(std::experimental::any_cast<int64_t>(param.default_value()), 42);
}

TEST_F(config_descriptor_test, set_new_parameter)
{
    // Add a new parameter
    std::experimental::any new_default = 3.14;
    desc.set_parameter("test.double_param", parameter_descriptor(new_default));

    // Verify it can be retrieved
    auto param = desc.get_parameter("test.double_param");
    ASSERT_EQ(param.default_value().type(), typeid(double));
    ASSERT_EQ(std::experimental::any_cast<double>(param.default_value()), 3.14);
}

TEST_F(config_descriptor_test, parameter_with_constraints)
{
    // Create a parameter with constraints
    std::experimental::any int_default = int64_t(50);
    parameter_descriptor param_desc(int_default);

    // Add a constraint (value must be >= 0)
    param_desc.add_constraint([](const std::experimental::any &val) -> constraint_result {
        if (val.type() == typeid(int64_t)) {
            int64_t int_val = std::experimental::any_cast<int64_t>(val);
            if (int_val >= 0) {
                return constraint_result(true);
            }
            return constraint_result(false, "Value must be non-negative");
        }
        return constraint_result(false, "Value must be an integer");
    });

    desc.set_parameter("test.constrained_param", std::move(param_desc));

    // Verify the parameter was stored correctly
    auto retrieved_param = desc.get_parameter("test.constrained_param");
    ASSERT_EQ(retrieved_param.default_value().type(), typeid(int64_t));
    ASSERT_EQ(std::experimental::any_cast<int64_t>(retrieved_param.default_value()), 50);

    // Verify constraints work (this tests that the constraint function was preserved)
    // Note: validate_constraints throws on failure, so we test both success and failure cases
    ASSERT_NO_THROW(retrieved_param.validate_constraints(int64_t(10)));
    ASSERT_THROW(retrieved_param.validate_constraints(int64_t(-5)), xlio_exception);
}

TEST_F(config_descriptor_test, move_semantics)
{
    // Test that move semantics work correctly
    std::experimental::any move_default = std::string("movable");
    parameter_descriptor move_param(move_default);

    // Use move semantics
    desc.set_parameter("test.move_param", std::move(move_param));

    // Verify the parameter was moved correctly
    auto retrieved_param = desc.get_parameter("test.move_param");
    ASSERT_EQ(retrieved_param.default_value().type(), typeid(std::string));
    ASSERT_EQ(std::experimental::any_cast<std::string>(retrieved_param.default_value()), "movable");
}

// Error handling and suggestion tests
TEST_F(config_descriptor_suggestion_test, get_parameter_valid_key_returns_parameter)
{
    auto param = config_desc.get_parameter("network.tcp.buffer_size");
    EXPECT_EQ("default_val", std::experimental::any_cast<std::string>(param.default_value()));
}

TEST_F(config_descriptor_suggestion_test, get_parameter_invalid_key_throws_exception)
{
    EXPECT_THROW(config_desc.get_parameter("invalid.key"), xlio_exception);
}

TEST_F(config_descriptor_suggestion_test,
       get_parameter_suggests_full_path_for_single_character_typo)
{
    try {
        config_desc.get_parameter("network.tcp.buffer_siz"); // missing 'e'
        FAIL() << "Expected xlio_exception";
    } catch (const xlio_exception &e) {
        std::string error_msg = e.what();
        EXPECT_TRUE(error_msg.find("Unknown key 'network.tcp.buffer_siz'") != std::string::npos);
        EXPECT_TRUE(error_msg.find("Did you mean 'network.tcp.buffer_size'?") != std::string::npos);
    }
}

TEST_F(config_descriptor_suggestion_test, get_parameter_suggests_for_parent_path_typo)
{
    try {
        config_desc.get_parameter("network.tdp.buffer_size"); // tcp -> tdp
        FAIL() << "Expected xlio_exception";
    } catch (const xlio_exception &e) {
        std::string error_msg = e.what();
        EXPECT_TRUE(error_msg.find("Unknown key 'network.tdp.buffer_size'") != std::string::npos);
        EXPECT_TRUE(error_msg.find("Did you mean 'network.tcp.buffer_size'?") != std::string::npos);
    }
}

TEST_F(config_descriptor_suggestion_test, get_parameter_suggests_for_mixed_typos)
{
    try {
        config_desc.get_parameter("netwrk.tcp.buffer_siz"); // missing 'o' and 'e'
        FAIL() << "Expected xlio_exception";
    } catch (const xlio_exception &e) {
        std::string error_msg = e.what();
        EXPECT_TRUE(error_msg.find("Unknown key 'netwrk.tcp.buffer_siz'") != std::string::npos);
        EXPECT_TRUE(error_msg.find("Did you mean 'network.tcp.buffer_size'?") != std::string::npos);
    }
}

TEST_F(config_descriptor_suggestion_test,
       get_parameter_suggests_closest_match_among_multiple_candidates)
{
    try {
        config_desc.get_parameter("network.tcp.window_siz"); // missing 'e'
        FAIL() << "Expected xlio_exception";
    } catch (const xlio_exception &e) {
        std::string error_msg = e.what();
        EXPECT_TRUE(error_msg.find("Unknown key 'network.tcp.window_siz'") != std::string::npos);
        EXPECT_TRUE(error_msg.find("Did you mean 'network.tcp.window_size'?") != std::string::npos);
    }
}

TEST_F(config_descriptor_suggestion_test, get_parameter_no_suggestion_for_distant_typos)
{
    try {
        config_desc.get_parameter("completely.different.key"); // too many changes
        FAIL() << "Expected xlio_exception";
    } catch (const xlio_exception &e) {
        std::string error_msg = e.what();
        EXPECT_TRUE(error_msg.find("Unknown key 'completely.different.key'") != std::string::npos);
        EXPECT_TRUE(error_msg.find("Did you mean") == std::string::npos); // No suggestion
    }
}

TEST_F(config_descriptor_suggestion_test, get_parameter_suggestion_threshold_boundary)
{
    try {
        config_desc.get_parameter("network.tcp.buffer_sz"); // distance = 2 (remove 'i' and 'e')
        FAIL() << "Expected xlio_exception";
    } catch (const xlio_exception &e) {
        std::string error_msg = e.what();
        EXPECT_TRUE(error_msg.find("Unknown key 'network.tcp.buffer_sz'") != std::string::npos);
        EXPECT_TRUE(error_msg.find("Did you mean 'network.tcp.buffer_size'?") != std::string::npos);
    }
}

TEST_F(config_descriptor_suggestion_test, get_parameter_no_suggestion_beyond_threshold)
{
    try {
        config_desc.get_parameter(
            "network.tcp.buff"); // distance = 3 (remove 'e', 'r', '_', 's', 'i', 'z', 'e')
        FAIL() << "Expected xlio_exception";
    } catch (const xlio_exception &e) {
        std::string error_msg = e.what();
        EXPECT_TRUE(error_msg.find("Unknown key 'network.tcp.buff'") != std::string::npos);
        EXPECT_TRUE(error_msg.find("Did you mean") == std::string::npos); // No suggestion
    }
}

TEST_F(config_descriptor_suggestion_test, get_parameter_suggests_cross_section_if_close_enough)
{
    try {
        config_desc.get_parameter("core.log.lvel"); // distance = 1 (missing 'e')
        FAIL() << "Expected xlio_exception";
    } catch (const xlio_exception &e) {
        std::string error_msg = e.what();
        EXPECT_TRUE(error_msg.find("Unknown key 'core.log.lvel'") != std::string::npos);
        EXPECT_TRUE(error_msg.find("Did you mean 'core.log.level'?") != std::string::npos);
    }
}
