/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <gtest/gtest.h>
#include "descriptors/config_descriptor.h"
#include "descriptors/parameter_descriptor.h"
#include "xlio_exception.h"
#include <experimental/any>

class config_descriptor_test : public ::testing::Test {
protected:
    void SetUp() override {
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

TEST_F(config_descriptor_test, get_parameter_valid_key_returns_parameter)
{
    auto param = config_desc.get_parameter("network.tcp.buffer_size");
    EXPECT_EQ("default_val", std::experimental::any_cast<std::string>(param.default_value()));
}

TEST_F(config_descriptor_test, get_parameter_invalid_key_throws_exception)
{
    EXPECT_THROW(config_desc.get_parameter("invalid.key"), xlio_exception);
}

TEST_F(config_descriptor_test, get_parameter_suggests_full_path_for_single_character_typo)
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

TEST_F(config_descriptor_test, get_parameter_suggests_for_parent_path_typo)
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

TEST_F(config_descriptor_test, get_parameter_suggests_for_mixed_typos)
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

TEST_F(config_descriptor_test, get_parameter_suggests_closest_match_among_multiple_candidates)
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

TEST_F(config_descriptor_test, get_parameter_no_suggestion_for_distant_typos)
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

TEST_F(config_descriptor_test, get_parameter_suggestion_threshold_boundary)
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

TEST_F(config_descriptor_test, get_parameter_no_suggestion_beyond_threshold)
{
    try {
        config_desc.get_parameter("network.tcp.buff"); // distance = 3 (remove 'e', 'r', '_', 's', 'i', 'z', 'e')
        FAIL() << "Expected xlio_exception";
    } catch (const xlio_exception &e) {
        std::string error_msg = e.what();
        EXPECT_TRUE(error_msg.find("Unknown key 'network.tcp.buff'") != std::string::npos);
        EXPECT_TRUE(error_msg.find("Did you mean") == std::string::npos); // No suggestion
    }
}

TEST_F(config_descriptor_test, get_parameter_suggests_cross_section_if_close_enough)
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