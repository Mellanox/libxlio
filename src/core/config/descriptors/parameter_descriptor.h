/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include <experimental/any>
#include <functional>
#include <map>
#include <stdexcept>
#include <string>
#include <typeindex>
#include <utility>
#include <vector>
#include <cstdint>

class constraint_result {
public:
    bool m_result = false;
    std::string m_error_message;

    constraint_result(bool result, std::string error_message = std::string())
        : m_result(result)
        , m_error_message(std::move(error_message))
    {
    }

    bool result() const { return m_result; }

    const std::string &error_message() const { return m_error_message; }
};
using constraint_t = std::function<constraint_result(const std::experimental::any &)>;
using value_transformer_t = std::function<std::experimental::any(const std::experimental::any &)>;

/**
 * @brief Describes a configuration parameter with type, default value, and constraints
 *
 * Holds metadata about a configuration parameter including its default value,
 * validation constraints, string-to-value mappings, and optional value transformations.
 */
class parameter_descriptor {
public:
    /**
     * @brief Default constructor
     */
    explicit parameter_descriptor();

    /**
     * @brief Copy assignment operator
     * @param pd Parameter descriptor to copy
     * @return Reference to this parameter descriptor
     */
    parameter_descriptor &operator=(const parameter_descriptor &) = default;

    /**
     * @brief Constructor with default value
     * @param def Default value for the parameter
     */
    explicit parameter_descriptor(const std::experimental::any &def);

    /**
     * @brief Move constructor
     */
    parameter_descriptor(parameter_descriptor &&pd) noexcept = default;

    /**
     * @brief Copy constructor
     * @param pd Parameter descriptor to copy
     */
    parameter_descriptor(const parameter_descriptor &pd);

    /**
     * @brief Sets string-to-value mappings
     * @param mappings Map of string-to-value mappings
     * @throws xlio_exception If double-mapping is detected
     */
    void set_string_mappings(const std::map<std::string, int64_t> &mappings);

    /**
     * @brief Sets a value transformer function
     * @param transformer Function to transform input values
     */
    void set_value_transformer(value_transformer_t transformer);

    /**
     * @brief Validates a value against all constraints
     * @param value Value to validate
     */
    void validate_constraints(const std::experimental::any &value) const;

    /**
     * @brief Gets the default value
     * @return Default value for the parameter
     */
    std::experimental::any default_value() const;

    /**
     * @brief Adds a validation constraint
     * @param constraint Function that validates a parameter value
     */
    void add_constraint(constraint_t constraint);

    /**
     * @brief Resolves string mappings and applies transformations to actual values
     * @param val Input value (may be a string reference to a mapped value)
     * @return Resolved value (mapped and transformed value if applicable, original otherwise)
     */
    std::experimental::any get_value(const std::experimental::any &val) const;

    /**
     * @brief Type-specific get_value for boolean values
     * @param val Boolean input value
     * @return Resolved boolean value as std::experimental::any
     */
    std::experimental::any get_value(bool val) const;

    /**
     * @brief Type-specific get_value for string values
     * @param val String input value
     * @return Resolved value (mapped and transformed value if applicable, original otherwise) as
     * std::experimental::any
     */
    std::experimental::any get_value(const std::string &val) const;

    /**
     * @brief Type-specific get_value for int64_t values
     * @param val int64_t input value
     * @return Resolved int64_t value as std::experimental::any
     */
    std::experimental::any get_value(int64_t val) const;

    /**
     * @brief Type-specific get_value for vector<std::experimental::any> values
     * @param val vector<std::experimental::any> input value
     * @return Resolved vector<std::experimental::any> value as std::experimental::any
     */
    std::experimental::any get_value(const std::vector<std::experimental::any> &val) const;

    /**
     * @brief Gets the type of the parameter
     * @return The type of the parameter
     */
    std::type_index type() const;

    /**
     * @brief Creates a memory size transformer that parses size suffixes (KB, MB, GB)
     * @return Value transformer function for memory sizes
     */
    static value_transformer_t create_memory_size_transformer();

    /**
     * @brief Creates a power-of-2-or-zero validation constraint
     * @return Constraint function that validates power-of-2 values or zero
     */
    static constraint_t create_power_of_2_or_zero_constraint();

private:
    std::experimental::any m_default_value; /**< Default parameter value */
    std::vector<constraint_t> m_constraints; /**< Validation constraints */
    std::map<std::string, std::experimental::any> m_string_mapping; /**< String-to-value mappings */
    value_transformer_t m_value_transformer; /**< Value transformation function */
    std::type_index m_type;

    /**
     * @brief Parses a memory size string with suffixes (KB, MB, GB)
     * @param str String to parse
     * @return Parsed value in bytes
     */
    static int64_t parse_memory_size(const char *str);
    /**
     * @brief Check if the given type matches the expected parameter type
     * @param type The type to check
     * @return True if the type matches the expected parameter type
     */
    bool is_expected_type(const std::type_index &type) const;

    /**
     * @brief Convert a string value to int64_t using transformer or string mapping
     * @param val The string value to convert
     * @return The converted int64_t value as std::experimental::any
     * @throws std::experimental::bad_any_cast if conversion fails
     */
    std::experimental::any convert_string_to_int64(const std::string &val) const;
};
