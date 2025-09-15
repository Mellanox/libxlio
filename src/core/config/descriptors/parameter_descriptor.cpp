/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "parameter_descriptor.h"
#include "core/config/config_strings.h"
#include "core/util/xlio_exception.h"
#include <cstdlib>
#include <cstring>
#include <climits>
#include <sstream>
#include <cctype>

/**
 * @brief Parse memory size string with suffixes (e.g., "4GB", "512MB", "1024KB", "1024B", "5G")
 * @param str The string to parse. Must match "^[0-9]+[KMGkmg]?[B]?$" (case insensitive)
 * @return The parsed size in bytes.
 * @throws xlio_exception on parsing errors.
 */
int64_t parameter_descriptor::parse_memory_size(const char *str)
{
    if (!str) {
        throw_xlio_exception("Memory value cannot be null.");
    }

    std::string input(str);
    size_t len = input.length();
    if (len == 0) {
        throw_xlio_exception("Memory value cannot be empty.");
    }

    // Find where the numeric part ends
    size_t num_len = 0;
    while (num_len < len && std::isdigit(static_cast<unsigned char>(input[num_len]))) {
        num_len++;
    }

    if (num_len == 0) {
        throw_xlio_exception("Memory value '" + input + "' must start with a number.");
    }

    // Use stringstream to parse the numeric part
    std::istringstream iss(input.substr(0, num_len));
    uint64_t value = 0;
    iss >> value;
    if (!iss || !iss.eof()) {
        throw_xlio_exception("Memory value '" + input + "' contains invalid numeric part.");
    }

    auto get_unit_multiplier = [](char unit) -> uint64_t {
        switch (unit) {
        case 'K':
        case 'k':
            return 1024ULL;
        case 'M':
        case 'm':
            return 1024ULL * 1024ULL;
        case 'G':
        case 'g':
            return 1024ULL * 1024ULL * 1024ULL;
        default:
            return 0; // Invalid unit
        }
    };

    // Parse the unit
    uint64_t multiplier = 1;

    if (num_len == len) {
        // No suffix, treat as bytes
        multiplier = 1;
    } else if (num_len == len - 1) {
        // One character suffix
        char suffix = input[num_len];
        if (suffix == 'B' || suffix == 'b') {
            // Just 'B' or 'b', so bytes
            multiplier = 1;
        } else {
            // Unit character without 'B'
            multiplier = get_unit_multiplier(suffix);
            if (multiplier == 0) {
                throw_xlio_exception("Memory value '" + input + "' has invalid unit '" + suffix +
                                     "'.");
            }
        }
    } else if (num_len == len - 2) {
        // Two character suffix, should be unit + 'B'/'b'
        char unit = input[num_len];
        char suffix = input[num_len + 1];
        if (suffix != 'B' && suffix != 'b') {
            throw_xlio_exception("Memory value '" + input + "' has invalid suffix format.");
        }
        multiplier = get_unit_multiplier(unit);
        if (multiplier == 0) {
            throw_xlio_exception("Memory value '" + input + "' has invalid unit '" + unit + "'.");
        }
    } else {
        throw_xlio_exception("Memory value '" + input + "' has invalid format.");
    }

    // Check for overflow
    if (value > 0 && multiplier > 1 && value > static_cast<uint64_t>(LLONG_MAX) / multiplier) {
        throw_xlio_exception("Memory value '" + input +
                             "' is too large and would cause an overflow.");
    }

    uint64_t result = value * multiplier;
    if (result > static_cast<uint64_t>(LLONG_MAX)) {
        throw_xlio_exception("Memory value '" + input + "' exceeds maximum supported size.");
    }

    return static_cast<int64_t>(result);
}

value_transformer_t parameter_descriptor::create_memory_size_transformer()
{
    return [](const std::experimental::any &val) -> std::experimental::any {
        // Only transform string values
        if (val.type() == typeid(int64_t)) {
            return val; // No transformation needed for int64_t values
        }

        std::string str_val;
        try {
            str_val = std::experimental::any_cast<std::string>(val);
        } catch (const std::experimental::bad_any_cast &) {
            throw_xlio_exception("Memory value type '" + std::string(val.type().name()) +
                                 "' is not a valid memory size type.");
        }

        return parameter_descriptor::parse_memory_size(str_val.c_str());
    };
}

parameter_descriptor::parameter_descriptor()
    : m_type(typeid(void))
{
}

parameter_descriptor::parameter_descriptor(const std::experimental::any &def)
    : m_default_value(def)
    , m_type(def.type())
{
}

parameter_descriptor::parameter_descriptor(const parameter_descriptor &pd)
    : m_default_value(pd.m_default_value)
    , m_constraints(pd.m_constraints)
    , m_string_mapping(pd.m_string_mapping)
    , m_value_transformer(pd.m_value_transformer)
    , m_type(pd.m_type)
{
}

void parameter_descriptor::add_string_mapping(const std::string &str,
                                              const std::experimental::any &val)
{
    if (m_string_mapping.find(str) != m_string_mapping.end()) {
        throw_xlio_exception("String mapping already exists for value: " + str);
    }

    m_string_mapping[str] = val;
}

void parameter_descriptor::set_value_transformer(value_transformer_t transformer)
{
    m_value_transformer = std::move(transformer);
}

std::experimental::any parameter_descriptor::default_value() const
{
    return m_default_value;
}

void parameter_descriptor::add_constraint(constraint_t constraint)
{
    m_constraints.push_back(std::move(constraint));
}

std::experimental::any parameter_descriptor::convert_string_to_int64(const std::string &val) const
{
    // Try value transformer first (e.g., "1GB" -> 1073741824)
    if (m_value_transformer) {
        std::experimental::any result = m_value_transformer(std::experimental::any(val));
        if (std::type_index(result.type()) != m_type) {
            throw std::experimental::bad_any_cast();
        }
        return result;
    }

    // Try string mapping (e.g., "enabled" -> 1)
    auto it = m_string_mapping.find(val);
    if (it != m_string_mapping.end()) {
        return it->second;
    }

    throw std::experimental::bad_any_cast();
}

std::experimental::any parameter_descriptor::get_value(bool val) const
{
    // For boolean values, no string mapping or transformation is typically needed
    // Just validate that the parameter type is boolean
    if (m_type != typeid(bool)) {
        throw std::experimental::bad_any_cast();
    }

    return std::experimental::any(val);
}

std::experimental::any parameter_descriptor::get_value(const std::string &val) const
{
    // Case 1: Parameter expects string - direct pass-through
    if (m_type == typeid(std::string)) {
        return std::experimental::any(val);
    }

    // Case 2: Parameter expects int64_t - convert string via transformer or mapping
    if (m_type == typeid(int64_t)) {
        return convert_string_to_int64(val);
    }

    // Case 3: Unsupported type conversion
    throw std::experimental::bad_any_cast();
}

std::experimental::any parameter_descriptor::get_value(int64_t val) const
{
    if (m_type != typeid(int64_t)) {
        throw std::experimental::bad_any_cast();
    }
    return std::experimental::any(val);
}

std::experimental::any parameter_descriptor::get_value(const std::experimental::any &val) const
{
    // Dispatch to type-specific convenience methods based on the input type
    if (val.type() == typeid(bool)) {
        return get_value(std::experimental::any_cast<bool>(val));
    } else if (val.type() == typeid(std::string)) {
        return get_value(std::experimental::any_cast<std::string>(val));
    } else if (val.type() == typeid(int64_t)) {
        return get_value(std::experimental::any_cast<int64_t>(val));
    } else {
        // For unsupported types, throw an exception
        throw std::experimental::bad_any_cast();
    }
}

void parameter_descriptor::validate_constraints(const std::experimental::any &value) const
{
    for (const auto &constraint : m_constraints) {
        auto result = constraint(value);
        if (!result.result()) {
            throw_xlio_exception(result.error_message());
        }
    }
}

std::type_index parameter_descriptor::type() const
{
    return m_type;
}

constraint_t parameter_descriptor::create_power_of_2_or_zero_constraint()
{
    return [](const std::experimental::any &value) -> constraint_result {
        // Handle integer values
        if (value.type() == typeid(int64_t)) {
            int64_t int_value = std::experimental::any_cast<int64_t>(value);
            if (int_value == 0) {
                return constraint_result(true); // Zero is explicitly allowed
            }
            if (int_value < 0) {
                return constraint_result(
                    false, "Value must be non-negative for power-of-2-or-zero validation");
            }
            // Check if it's a power of 2: (n & (n-1)) == 0
            if ((int_value & (int_value - 1)) == 0) {
                return constraint_result(true);
            } else {
                return constraint_result(
                    false, "Value " + std::to_string(int_value) + " is not a power of 2");
            }
        }

        return constraint_result(false,
                                 "Power-of-2-or-zero validation only supports integer values");
    };
}
