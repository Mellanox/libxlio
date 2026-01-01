/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "gtest/gtest.h"
#include "core/config/descriptor_providers/schema_analyzer.h"
#include "core/util/xlio_exception.h"

#include <json-c/json.h>
#include <string>

class schema_analyzer_test : public ::testing::Test {
protected:
    void SetUp() override
    {
        // Create test JSON objects for different property types
        simple_property = json_object_new_object();
        json_object_object_add(simple_property, "type", json_object_new_string("integer"));
        json_object_object_add(simple_property, "title", json_object_new_string("Test Property"));
        json_object_object_add(simple_property, "description",
                               json_object_new_string("A test property"));
        json_object_object_add(simple_property, "default", json_object_new_int(42));

        extended_property = json_object_new_object();
        json_object_object_add(extended_property, "type", json_object_new_string("string"));
        json_object_object_add(extended_property, "title", json_object_new_string("Memory Size"));
        json_object_object_add(extended_property, "description",
                               json_object_new_string("A memory size property"));
        json_object_object_add(extended_property, "x-memory-size", json_object_new_boolean(true));
        json_object *extended_one_of_array = json_object_new_array();
        json_object *extended_string_option = json_object_new_object();
        json_object_object_add(extended_string_option, "type", json_object_new_string("string"));
        json_object_object_add(extended_string_option, "pattern",
                               json_object_new_string("^[0-9]+[KMGkmg]?[B]?$"));
        json_object_object_add(extended_string_option, "default", json_object_new_string("32MB"));
        json_object *extended_integer_option = json_object_new_object();
        json_object_object_add(extended_integer_option, "type", json_object_new_string("integer"));
        json_object_object_add(extended_integer_option, "default",
                               json_object_new_int(32 * 1024 * 1024));
        json_object_array_add(extended_one_of_array, extended_string_option);
        json_object_array_add(extended_one_of_array, extended_integer_option);
        json_object_object_add(extended_property, "oneOf", extended_one_of_array);

        one_of_property = json_object_new_object();
        json_object *one_of_array = json_object_new_array();
        json_object *int_option = json_object_new_object();
        json_object_object_add(int_option, "type", json_object_new_string("integer"));
        json_object_object_add(int_option, "default", json_object_new_int(1));
        json_object_array_add(one_of_array, int_option);
        json_object *string_option = json_object_new_object();
        json_object_object_add(string_option, "type", json_object_new_string("string"));
        json_object_object_add(string_option, "default", json_object_new_string("default_val"));
        json_object_array_add(one_of_array, string_option);
        json_object_object_add(one_of_property, "oneOf", one_of_array);
        json_object_object_add(one_of_property, "title", json_object_new_string("OneOf Property"));
        json_object_object_add(one_of_property, "description",
                               json_object_new_string("A oneOf property"));

        object_property = json_object_new_object();
        json_object_object_add(object_property, "type", json_object_new_string("object"));
        json_object *properties = json_object_new_object();
        // Create a separate nested property to avoid reference counting issues
        json_object *nested_property = json_object_new_object();
        json_object_object_add(nested_property, "type", json_object_new_string("string"));
        json_object_object_add(properties, "nested", nested_property);
        json_object_object_add(object_property, "properties", properties);

        array_property = json_object_new_object();
        json_object_object_add(array_property, "type", json_object_new_string("array"));
        json_object_object_add(array_property, "title", json_object_new_string("Array Property"));
        json_object_object_add(array_property, "description",
                               json_object_new_string("An array property"));
        json_object *items = json_object_new_object();
        json_object_object_add(items, "type", json_object_new_string("string"));
        json_object_object_add(array_property, "items", items);
        json_object_object_add(array_property, "default", json_object_new_array());

        simple_property_no_title = json_object_new_object();
        json_object_object_add(simple_property_no_title, "type", json_object_new_string("integer"));
        json_object_object_add(simple_property_no_title, "description",
                               json_object_new_string("A test property"));
        json_object_object_add(simple_property_no_title, "default", json_object_new_int(42));
    }

    void TearDown() override
    {
        json_object_put(simple_property);
        json_object_put(extended_property);
        json_object_put(one_of_property);
        json_object_put(object_property);
        json_object_put(array_property);
        json_object_put(simple_property_no_title);
    }

    json_object *simple_property;
    json_object *extended_property;
    json_object *one_of_property;
    json_object *object_property;
    json_object *array_property;
    json_object *simple_property_no_title;
};

TEST_F(schema_analyzer_test, analyze_simple_property)
{
    auto analysis = schema_analyzer::analyze(simple_property, "test.simple");

    ASSERT_EQ(analysis.json_property_type, property_type::SIMPLE);
    ASSERT_EQ(analysis.value_type, typeid(int64_t));
    ASSERT_FALSE(analysis.needs_value_transformation());
    ASSERT_FALSE(analysis.needs_constraint_validation());
    ASSERT_FALSE(analysis.needs_enum_mapping());

    // Test default value
    ASSERT_EQ(std::experimental::any_cast<int64_t>(*analysis.default_value), 42);
    ASSERT_EQ(*analysis.title, "Test Property");
}

TEST_F(schema_analyzer_test, analyze_simple_property_no_title_throws)
{
    // We want to verify the error message, so not using ASSERT_THROW
    //ASSERT_THROW(schema_analyzer::analyze(simple_property_no_title, "test.simple_no_title"),
    //xlio_exception);
    try {
        schema_analyzer::analyze(simple_property_no_title, "test.simple_no_title");
        FAIL() << "Expected xlio_exception";
    } catch (const xlio_exception &e) {
        EXPECT_NE(std::string(e.what()).find("Title must be a defined for"), std::string::npos);
    } catch (...) {
        FAIL() << "Expected xlio_exception";
    }
}

TEST_F(schema_analyzer_test, analyze_extended_property)
{
    auto analysis = schema_analyzer::analyze(extended_property, "test.extended");

    ASSERT_EQ(analysis.json_property_type, property_type::EXTENDED);
    ASSERT_EQ(analysis.value_type, typeid(int64_t));
    ASSERT_TRUE(analysis.needs_value_transformation());
    ASSERT_TRUE(analysis.memory_cfg);
    ASSERT_FALSE(analysis.needs_constraint_validation());
    ASSERT_FALSE(analysis.needs_enum_mapping());
    ASSERT_EQ(std::experimental::any_cast<int64_t>(*analysis.default_value), 32 * 1024 * 1024);
    ASSERT_EQ(analysis.memory_cfg, true);
}

TEST_F(schema_analyzer_test, analyze_one_of_property)
{
    // OneOf property is not valid because it does not have a string/int enum setup
    ASSERT_THROW(schema_analyzer::analyze(one_of_property, "test.oneof"), xlio_exception);
}

TEST_F(schema_analyzer_test, analyze_object_property)
{
    auto analysis = schema_analyzer::analyze(object_property, "test.object");

    ASSERT_EQ(analysis.json_property_type, property_type::OBJECT);
    ASSERT_EQ(analysis.value_type, typeid(json_object *));
    ASSERT_FALSE(analysis.needs_value_transformation());
    ASSERT_FALSE(analysis.needs_constraint_validation());
    ASSERT_FALSE(analysis.needs_enum_mapping());
}

TEST_F(schema_analyzer_test, analyze_array_property)
{
    auto analysis = schema_analyzer::analyze(array_property, "test.array");

    ASSERT_EQ(analysis.json_property_type, property_type::ARRAY);
    ASSERT_EQ(analysis.value_type, typeid(std::vector<std::experimental::any>));
    ASSERT_FALSE(analysis.needs_value_transformation());
    ASSERT_FALSE(analysis.needs_constraint_validation());
    ASSERT_FALSE(analysis.needs_enum_mapping());
}

TEST_F(schema_analyzer_test, analyze_null_property_throws)
{
    ASSERT_THROW(schema_analyzer::analyze(nullptr, "test.null"), xlio_exception);
}

TEST_F(schema_analyzer_test, analyze_non_object_throws)
{
    json_object *non_object = json_object_new_string("not an object");

    ASSERT_THROW(schema_analyzer::analyze(non_object, "test.invalid"), xlio_exception);

    json_object_put(non_object);
}

TEST_F(schema_analyzer_test, analyze_property_with_constraints)
{
    json_object *constrained_property = json_object_new_object();
    json_object_object_add(constrained_property, "type", json_object_new_string("integer"));
    json_object_object_add(constrained_property, "minimum", json_object_new_int(0));
    json_object_object_add(constrained_property, "maximum", json_object_new_int(100));
    json_object_object_add(constrained_property, "default", json_object_new_int(50));
    json_object_object_add(constrained_property, "title",
                           json_object_new_string("Constrained Property"));
    json_object_object_add(constrained_property, "description",
                           json_object_new_string("A constrained property"));

    auto analysis = schema_analyzer::analyze(constrained_property, "test.constrained");

    ASSERT_EQ(analysis.json_property_type, property_type::SIMPLE);
    ASSERT_TRUE(analysis.needs_constraint_validation());
    ASSERT_TRUE(analysis.constraint_cfg.has_minimum);
    ASSERT_TRUE(analysis.constraint_cfg.has_maximum);
    ASSERT_FALSE(analysis.constraint_cfg.has_enum);
    ASSERT_EQ(analysis.constraint_cfg.minimum_value, 0);
    ASSERT_EQ(analysis.constraint_cfg.maximum_value, 100);
    ASSERT_EQ(std::experimental::any_cast<int64_t>(*analysis.default_value), 50);
    json_object_put(constrained_property);
}
