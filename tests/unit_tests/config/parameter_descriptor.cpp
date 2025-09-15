/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "gtest/gtest.h"
#include "core/config/descriptors/parameter_descriptor.h"
#include "core/util/xlio_exception.h"

#include <string>
#include <experimental/any>
#include <climits>

// Test suite for memory_size_transformer
class memory_size_transformer_test : public ::testing::Test {
protected:
    value_transformer_t transformer = parameter_descriptor::create_memory_size_transformer();

    // Helper function to test valid parsing
    void test_valid_transform(const std::string &input, int64_t expected)
    {
        std::experimental::any val = transformer(input);
        ASSERT_EQ(val.type(), typeid(int64_t));
        ASSERT_EQ(std::experimental::any_cast<int64_t>(val), expected);
    }

    // Helper function to test invalid parsing with exception
    void test_invalid_transform(const std::string &input)
    {
        ASSERT_THROW(transformer(input), xlio_exception);
    }

    // Helper function to test invalid parsing with specific error message
    void test_invalid_transform_with_message(const std::string &input,
                                             const std::string &expected_message)
    {
        try {
            transformer(input);
            FAIL() << "Expected xlio_exception for input: " << input;
        } catch (const xlio_exception &e) {
            ASSERT_TRUE(std::string(e.what()).find(expected_message) != std::string::npos)
                << "Expected error message to contain: " << expected_message
                << ", but got: " << e.what();
        }
    }
};

// Test valid inputs with bytes
TEST_F(memory_size_transformer_test, valid_bytes)
{
    test_valid_transform("0", 0);
    test_valid_transform("1", 1);
    test_valid_transform("1024", 1024);
    test_valid_transform("123456789", 123456789);

    test_valid_transform("0B", 0);
    test_valid_transform("1B", 1);
    test_valid_transform("1024B", 1024);
    test_valid_transform("123456789B", 123456789);
}

// Test valid inputs with kilobytes
TEST_F(memory_size_transformer_test, valid_kilobytes)
{
    test_valid_transform("1K", 1024);
    test_valid_transform("2K", 2 * 1024);
    test_valid_transform("1024K", 1024 * 1024);

    test_valid_transform("1KB", 1024);
    test_valid_transform("2KB", 2 * 1024);
    test_valid_transform("1024KB", 1024 * 1024);
}

// Test valid inputs with megabytes
TEST_F(memory_size_transformer_test, valid_megabytes)
{
    test_valid_transform("1M", 1024 * 1024);
    test_valid_transform("4M", 4 * 1024 * 1024);
    test_valid_transform("512M", 512 * 1024 * 1024);

    test_valid_transform("1MB", 1024 * 1024);
    test_valid_transform("4MB", 4 * 1024 * 1024);
    test_valid_transform("512MB", 512 * 1024 * 1024);
}

// Test valid inputs with gigabytes
TEST_F(memory_size_transformer_test, valid_gigabytes)
{
    test_valid_transform("1G", 1024LL * 1024 * 1024);
    test_valid_transform("2G", 2LL * 1024 * 1024 * 1024);
    test_valid_transform("8G", 8LL * 1024 * 1024 * 1024);

    test_valid_transform("1GB", 1024LL * 1024 * 1024);
    test_valid_transform("2GB", 2LL * 1024 * 1024 * 1024);
    test_valid_transform("8GB", 8LL * 1024 * 1024 * 1024);
}

// Test valid inputs with lowercase letters
TEST_F(memory_size_transformer_test, valid_lowercase_units)
{
    // Test lowercase 'b' suffix
    test_valid_transform("0b", 0);
    test_valid_transform("1b", 1);
    test_valid_transform("1024b", 1024);

    // Test lowercase kilobytes
    test_valid_transform("1k", 1024);
    test_valid_transform("2k", 2 * 1024);
    test_valid_transform("1024k", 1024 * 1024);

    test_valid_transform("1kb", 1024);
    test_valid_transform("2kb", 2 * 1024);
    test_valid_transform("1024kb", 1024 * 1024);

    // Test lowercase megabytes
    test_valid_transform("1m", 1024 * 1024);
    test_valid_transform("4m", 4 * 1024 * 1024);
    test_valid_transform("512m", 512 * 1024 * 1024);

    test_valid_transform("1mb", 1024 * 1024);
    test_valid_transform("4mb", 4 * 1024 * 1024);
    test_valid_transform("512mb", 512 * 1024 * 1024);

    // Test lowercase gigabytes
    test_valid_transform("1g", 1024LL * 1024 * 1024);
    test_valid_transform("2g", 2LL * 1024 * 1024 * 1024);
    test_valid_transform("8g", 8LL * 1024 * 1024 * 1024);

    test_valid_transform("1gb", 1024LL * 1024 * 1024);
    test_valid_transform("2gb", 2LL * 1024 * 1024 * 1024);
    test_valid_transform("8gb", 8LL * 1024 * 1024 * 1024);
}

// Test valid inputs with mixed case
TEST_F(memory_size_transformer_test, valid_mixed_case)
{
    // Test mixed case kilobytes
    test_valid_transform("1Kb", 1024);
    test_valid_transform("2kB", 2 * 1024);
    test_valid_transform("1024Kb", 1024 * 1024);
    test_valid_transform("1024kB", 1024 * 1024);

    // Test mixed case megabytes
    test_valid_transform("1Mb", 1024 * 1024);
    test_valid_transform("4mB", 4 * 1024 * 1024);
    test_valid_transform("512Mb", 512 * 1024 * 1024);
    test_valid_transform("512mB", 512 * 1024 * 1024);

    // Test mixed case gigabytes
    test_valid_transform("1Gb", 1024LL * 1024 * 1024);
    test_valid_transform("2gB", 2LL * 1024 * 1024 * 1024);
    test_valid_transform("8Gb", 8LL * 1024 * 1024 * 1024);
    test_valid_transform("8gB", 8LL * 1024 * 1024 * 1024);
}

// Test empty inputs
TEST_F(memory_size_transformer_test, empty_inputs)
{
    test_invalid_transform_with_message("", "Memory value cannot be empty");
}

// Test invalid numeric inputs
TEST_F(memory_size_transformer_test, invalid_numeric_inputs)
{
    test_invalid_transform_with_message("abc", "must start with a number");
    test_invalid_transform_with_message("K", "must start with a number");
    test_invalid_transform_with_message("GB", "must start with a number");
    test_invalid_transform_with_message("-123", "must start with a number");
    test_invalid_transform_with_message("12.5MB", "has invalid format");
}

// Test invalid unit inputs
TEST_F(memory_size_transformer_test, invalid_unit_inputs)
{
    test_invalid_transform_with_message("123X", "has invalid unit 'X'");
    test_invalid_transform_with_message("123T", "has invalid unit 'T'");
    test_invalid_transform_with_message("123XB", "has invalid unit 'X'");
    test_invalid_transform_with_message("123TB", "has invalid unit 'T'");
}

// Test invalid format inputs
TEST_F(memory_size_transformer_test, invalid_format_inputs)
{
    test_invalid_transform_with_message("123GBX", "has invalid format");
    test_invalid_transform_with_message("123MBExtra", "has invalid format");
    test_invalid_transform_with_message("123 MB", "has invalid format");
    test_invalid_transform_with_message("123KBB", "has invalid format");
    test_invalid_transform_with_message("123MX", "has invalid suffix format");
    test_invalid_transform_with_message("123GX", "has invalid suffix format");
}

// Test overflow conditions
TEST_F(memory_size_transformer_test, overflow_conditions)
{
    // Test value that would overflow during multiplication
    test_invalid_transform_with_message("9223372036854775808G",
                                        "is too large and would cause an overflow");

    // Test value that fits in uint64_t but exceeds int64_t max
    test_invalid_transform_with_message("9223372036854775808", "exceeds maximum supported size");

    // Test large value that would overflow
    test_invalid_transform_with_message("18446744073709551615G",
                                        "is too large and would cause an overflow");
}

// Test edge cases near maximum values
TEST_F(memory_size_transformer_test, edge_cases_max_values)
{
    // Test maximum int64_t value
    test_valid_transform("9223372036854775807", LLONG_MAX);

    // Test maximum value for different units that still fit in int64_t
    test_valid_transform("8G", 8LL * 1024 * 1024 * 1024); // 8GB should be fine
    test_valid_transform("8192M", 8192LL * 1024 * 1024); // 8GB in MB
}

// Test cases for inputs with whitespace (should fail)
TEST_F(memory_size_transformer_test, test_inputs_with_whitespace)
{
    // Test with space between number and suffix
    test_invalid_transform("10 B");
    test_invalid_transform("2 KB");

    // Test with leading whitespace
    test_invalid_transform("  512MB");

    // Test with trailing whitespace
    test_invalid_transform("1GB  ");

    // Test with leading and trailing whitespace
    test_invalid_transform("  20 G  ");

    // Test with multiple spaces
    test_invalid_transform("100  K");

    // Test with zero and whitespace
    test_invalid_transform(" 0 KB ");
}

// Test cases for other invalid inputs
TEST_F(memory_size_transformer_test, test_other_invalid_inputs)
{
    test_invalid_transform("10XB"); // Invalid suffix
    test_invalid_transform("10MBextra"); // Characters after suffix
    test_invalid_transform("-10MB"); // Negative number
    test_invalid_transform("abc"); // Non-numeric
    test_invalid_transform("   "); // Only whitespace
    test_invalid_transform("GB"); // Suffix without a number
    test_invalid_transform("10 GB G"); // Multiple suffixes
}

// Test cases for non-string inputs
TEST_F(memory_size_transformer_test, test_non_string_inputs)
{
    // The transformer should not modify int64_t inputs.
    std::experimental::any val = transformer(static_cast<int64_t>(12345));
    ASSERT_EQ(val.type(), typeid(int64_t));
    ASSERT_EQ(std::experimental::any_cast<int64_t>(val), 12345);

    // Other types should throw
    ASSERT_THROW(transformer(true), xlio_exception);
    ASSERT_THROW(transformer(static_cast<int>(12345)), xlio_exception);
}

// Test cases for large numbers that still fit
TEST_F(memory_size_transformer_test, test_large_valid_numbers)
{
    // Test some large but valid numbers
    test_valid_transform("1000000", 1000000);
    test_valid_transform("2000000K", 2000000LL * 1024);
    test_valid_transform("2000M", 2000LL * 1024 * 1024);
}

// Legacy test name kept for compatibility
class memory_size_transformer : public memory_size_transformer_test {};

// Legacy tests for backward compatibility
TEST_F(memory_size_transformer, test_valid_inputs)
{
    // Test with "B" suffix
    std::experimental::any val = transformer(std::string("10B"));
    ASSERT_EQ(val.type(), typeid(int64_t));
    ASSERT_EQ(std::experimental::any_cast<int64_t>(val), 10);

    // Test with "KB" suffix
    val = transformer(std::string("2KB"));
    ASSERT_EQ(val.type(), typeid(int64_t));
    ASSERT_EQ(std::experimental::any_cast<int64_t>(val), 2 * 1024);

    // Test with "K" suffix (fixed: was incorrectly testing KB value)
    val = transformer(std::string("3K"));
    ASSERT_EQ(val.type(), typeid(int64_t));
    ASSERT_EQ(std::experimental::any_cast<int64_t>(val), 3 * 1024);

    // Test with "MB" suffix
    val = transformer(std::string("4MB"));
    ASSERT_EQ(val.type(), typeid(int64_t));
    ASSERT_EQ(std::experimental::any_cast<int64_t>(val), 4 * 1024 * 1024);

    // Test with "M" suffix (fixed: was incorrectly testing MB value)
    val = transformer(std::string("5M"));
    ASSERT_EQ(val.type(), typeid(int64_t));
    ASSERT_EQ(std::experimental::any_cast<int64_t>(val), 5 * 1024 * 1024);

    // Test with "GB" suffix
    val = transformer(std::string("6GB"));
    ASSERT_EQ(val.type(), typeid(int64_t));
    ASSERT_EQ(std::experimental::any_cast<int64_t>(val), 6LL * 1024 * 1024 * 1024);

    // Test with "G" suffix (fixed: was incorrectly testing GB value)
    val = transformer(std::string("7G"));
    ASSERT_EQ(val.type(), typeid(int64_t));
    ASSERT_EQ(std::experimental::any_cast<int64_t>(val), 7LL * 1024 * 1024 * 1024);

    // Test with no suffix (fixed: was incorrectly including B)
    val = transformer(std::string("12345"));
    ASSERT_EQ(val.type(), typeid(int64_t));
    ASSERT_EQ(std::experimental::any_cast<int64_t>(val), 12345);

    // Test with zero
    val = transformer(std::string("0B"));
    ASSERT_EQ(val.type(), typeid(int64_t));
    ASSERT_EQ(std::experimental::any_cast<int64_t>(val), 0);

    // Test with zero and suffix
    val = transformer(std::string("0KB"));
    ASSERT_EQ(val.type(), typeid(int64_t));
    ASSERT_EQ(std::experimental::any_cast<int64_t>(val), 0);
}

TEST_F(memory_size_transformer, test_inputs_with_whitespace)
{
    // Test with space between number and suffix
    ASSERT_THROW(transformer(std::string("10 B")), xlio_exception);

    ASSERT_THROW(transformer(std::string("2 KB")), xlio_exception);

    // Test with leading whitespace
    ASSERT_THROW(transformer(std::string("  512MB")), xlio_exception);

    // Test with trailing whitespace
    ASSERT_THROW(transformer(std::string("1GB  ")), xlio_exception);

    // Test with leading and trailing whitespace
    ASSERT_THROW(transformer(std::string("  20 G  ")), xlio_exception);

    // Test with multiple spaces
    ASSERT_THROW(transformer(std::string("100  K")), xlio_exception);

    // Test with zero and whitespace
    ASSERT_THROW(transformer(std::string(" 0 KB ")), xlio_exception);
}

TEST_F(memory_size_transformer, test_invalid_inputs)
{
    // For invalid string inputs, the transformer should throw exceptions.
    auto check_invalid = [&](const std::string &input_str) {
        ASSERT_THROW(transformer(input_str), xlio_exception);
    };

    check_invalid("10XB"); // Invalid suffix
    check_invalid("10MBextra"); // Characters after suffix
    check_invalid("-10MB"); // Negative number
    check_invalid("abc"); // Non-numeric
    check_invalid(""); // Empty string
    check_invalid("   "); // Only whitespace
    check_invalid("GB"); // Suffix without a number
    check_invalid("10 GB G"); // Multiple suffixes
}

TEST_F(memory_size_transformer, test_non_string_inputs)
{
    // The transformer should not modify non-string inputs.
    std::experimental::any val = transformer(static_cast<int64_t>(12345));
    ASSERT_EQ(val.type(), typeid(int64_t));
    ASSERT_EQ(std::experimental::any_cast<int64_t>(val), 12345);

    ASSERT_THROW(transformer(true), xlio_exception);
    ASSERT_THROW(transformer(static_cast<int>(12345)), xlio_exception);
}

TEST_F(memory_size_transformer, test_overflow)
{
    // A very large number without suffix that fits uint64_t but not int64_t
    ASSERT_THROW(transformer(std::string("10000000000000000000")), xlio_exception);
}

TEST(config, parameter_descriptor_valid_integer_passes)
{
    // Test that valid integer values pass through unchanged
    constexpr int64_t DEFAULT_INT_VALUE = 16;
    parameter_descriptor int_param_descriptor {std::experimental::any(int64_t(DEFAULT_INT_VALUE))};

    std::experimental::any valid_int = int64_t(32);
    std::experimental::any result = int_param_descriptor.get_value(valid_int);
    ASSERT_EQ(typeid(int64_t), result.type());
    ASSERT_EQ(32LL, std::experimental::any_cast<int64_t>(result));
}

TEST(config, parameter_descriptor_boolean_rejected)
{
    // Test that boolean values are rejected for integer parameters (this was the bug)
    constexpr int64_t DEFAULT_INT_VALUE = 16;
    parameter_descriptor int_param_descriptor {std::experimental::any(int64_t(DEFAULT_INT_VALUE))};

    std::experimental::any bool_value = true;
    ASSERT_THROW(int_param_descriptor.get_value(bool_value), std::experimental::bad_any_cast);
}

TEST(config, parameter_descriptor_string_rejected)
{
    // Test that string values are rejected for integer parameters
    constexpr int64_t DEFAULT_INT_VALUE = 16;
    parameter_descriptor int_param_descriptor {std::experimental::any(int64_t(DEFAULT_INT_VALUE))};

    std::experimental::any string_value = std::string("invalid");
    ASSERT_THROW(int_param_descriptor.get_value(string_value), std::experimental::bad_any_cast);
}

TEST(config, parameter_descriptor_double_rejected)
{
    // Test that double values are rejected for integer parameters
    constexpr int64_t DEFAULT_INT_VALUE = 16;
    parameter_descriptor int_param_descriptor {std::experimental::any(int64_t(DEFAULT_INT_VALUE))};

    std::experimental::any double_value = 3.14;
    ASSERT_THROW(int_param_descriptor.get_value(double_value), std::experimental::bad_any_cast);
}

TEST(config, parameter_descriptor_boolean_accepts_boolean)
{
    // Test that boolean parameters accept boolean values
    parameter_descriptor bool_param_descriptor(std::experimental::any(bool(false)));

    std::experimental::any bool_value = true;
    std::experimental::any result = bool_param_descriptor.get_value(bool_value);
    ASSERT_EQ(typeid(bool), result.type());
    ASSERT_EQ(true, std::experimental::any_cast<bool>(result));
}

TEST(config, parameter_descriptor_boolean_rejects_integer)
{
    // Test that boolean parameters reject integer values
    parameter_descriptor bool_param_descriptor(std::experimental::any(bool(false)));

    std::experimental::any int_value = int64_t(1);
    ASSERT_THROW(bool_param_descriptor.get_value(int_value), std::experimental::bad_any_cast);
}
// Test suite for power-of-2 constraint validation
class power_of_2_or_zero_constraint_test : public ::testing::Test {
protected:
    constraint_t constraint = parameter_descriptor::create_power_of_2_or_zero_constraint();

    // Helper function to test valid power-of-2 values
    void test_valid_power_of_2(const std::experimental::any &value)
    {
        constraint_result result = constraint(value);
        ASSERT_TRUE(result.result()) << "Expected power-of-2 validation to pass for value";
    }

    // Helper function to test invalid power-of-2 values
    void test_invalid_power_of_2(const std::experimental::any &value,
                                 const std::string &expected_error_substring = "")
    {
        constraint_result result = constraint(value);
        ASSERT_FALSE(result.result()) << "Expected power-of-2 validation to fail for value";
        if (!expected_error_substring.empty()) {
            ASSERT_TRUE(result.error_message().find(expected_error_substring) != std::string::npos)
                << "Expected error message to contain: " << expected_error_substring
                << ", but got: " << result.error_message();
        }
    }
};

// Test valid power-of-2 integer values
TEST_F(power_of_2_or_zero_constraint_test, valid_power_of_2_integers)
{
    // Test powers of 2 from 1 to 2^30
    for (int i = 0; i <= 30; ++i) {
        int64_t power_of_2 = 1LL << i;
        test_valid_power_of_2(static_cast<int64_t>(power_of_2));
    }

    // Test some specific common values
    test_valid_power_of_2(static_cast<int64_t>(1));
    test_valid_power_of_2(static_cast<int64_t>(2));
    test_valid_power_of_2(static_cast<int64_t>(4));
    test_valid_power_of_2(static_cast<int64_t>(8));
    test_valid_power_of_2(static_cast<int64_t>(16));
    test_valid_power_of_2(static_cast<int64_t>(32));
    test_valid_power_of_2(static_cast<int64_t>(64));
    test_valid_power_of_2(static_cast<int64_t>(128));
    test_valid_power_of_2(static_cast<int64_t>(256));
    test_valid_power_of_2(static_cast<int64_t>(512));
    test_valid_power_of_2(static_cast<int64_t>(1024));
    test_valid_power_of_2(static_cast<int64_t>(2048));
    test_valid_power_of_2(static_cast<int64_t>(4096));
    test_valid_power_of_2(static_cast<int64_t>(8192));
    test_valid_power_of_2(static_cast<int64_t>(16384));
    test_valid_power_of_2(static_cast<int64_t>(32768));
    test_valid_power_of_2(static_cast<int64_t>(65536));
}

// Test invalid power-of-2 integer values
TEST_F(power_of_2_or_zero_constraint_test, invalid_power_of_2_integers)
{
    // Test non-powers of 2
    test_invalid_power_of_2(static_cast<int64_t>(3), "is not a power of 2");
    test_invalid_power_of_2(static_cast<int64_t>(5), "is not a power of 2");
    test_invalid_power_of_2(static_cast<int64_t>(6), "is not a power of 2");
    test_invalid_power_of_2(static_cast<int64_t>(7), "is not a power of 2");
    test_invalid_power_of_2(static_cast<int64_t>(9), "is not a power of 2");
    test_invalid_power_of_2(static_cast<int64_t>(10), "is not a power of 2");
    test_invalid_power_of_2(static_cast<int64_t>(15), "is not a power of 2");
    test_invalid_power_of_2(static_cast<int64_t>(100), "is not a power of 2");
    test_invalid_power_of_2(static_cast<int64_t>(1000), "is not a power of 2");
    test_invalid_power_of_2(static_cast<int64_t>(3000), "is not a power of 2");
    test_invalid_power_of_2(static_cast<int64_t>(5000), "is not a power of 2");
    test_invalid_power_of_2(static_cast<int64_t>(10000), "is not a power of 2");
}

// Test zero and negative values
TEST_F(power_of_2_or_zero_constraint_test, zero_and_negative_values)
{
    // Zero should be valid (explicitly allowed)
    test_valid_power_of_2(static_cast<int64_t>(0));

    // Negative values should fail
    test_invalid_power_of_2(static_cast<int64_t>(-1), "must be non-negative");
    test_invalid_power_of_2(static_cast<int64_t>(-2), "must be non-negative");
    test_invalid_power_of_2(static_cast<int64_t>(-4), "must be non-negative");
    test_invalid_power_of_2(static_cast<int64_t>(-1024), "must be non-negative");
}

// Test unsupported value types
TEST_F(power_of_2_or_zero_constraint_test, unsupported_value_types)
{
    // Test unsupported types
    test_invalid_power_of_2(true, "only supports integer values");
    test_invalid_power_of_2(false, "only supports integer values");
    test_invalid_power_of_2(static_cast<int>(42), "only supports integer values");
    test_invalid_power_of_2(static_cast<double>(42.0), "only supports integer values");
    test_invalid_power_of_2(static_cast<float>(42.0f), "only supports integer values");
    test_invalid_power_of_2(std::string("42"), "only supports integer values");
    test_invalid_power_of_2(std::string("42MB"), "only supports integer values");
}

// Test edge cases and boundary values
TEST_F(power_of_2_or_zero_constraint_test, edge_cases_and_boundaries)
{
    // Test very large powers of 2
    test_valid_power_of_2(static_cast<int64_t>(1LL << 30)); // 2^30
    test_valid_power_of_2(static_cast<int64_t>(1LL << 40)); // 2^40
    test_valid_power_of_2(static_cast<int64_t>(1LL << 50)); // 2^50
    test_valid_power_of_2(static_cast<int64_t>(1LL << 60)); // 2^60
    // Test values just below and above powers of 2
    test_invalid_power_of_2(static_cast<int64_t>((1LL << 30) - 1), "is not a power of 2");
    test_invalid_power_of_2(static_cast<int64_t>((1LL << 30) + 1), "is not a power of 2");
    test_invalid_power_of_2(static_cast<int64_t>((1LL << 40) - 1), "is not a power of 2");
    test_invalid_power_of_2(static_cast<int64_t>((1LL << 40) + 1), "is not a power of 2");

    // Test maximum int64_t value (not a power of 2)
    test_invalid_power_of_2(static_cast<int64_t>(LLONG_MAX), "is not a power of 2");

    // Test maximum power of 2 that fits in int64_t
    test_valid_power_of_2(static_cast<int64_t>(1LL << 62)); // 2^62
}
