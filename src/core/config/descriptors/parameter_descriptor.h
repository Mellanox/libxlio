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

using constraint_t = std::function<std::pair<bool, std::string>(const std::experimental::any &)>;

/**
 * @brief Describes a configuration parameter with type, default value, and constraints
 *
 * Holds metadata about a configuration parameter including its default value,
 * validation constraints, and string-to-value mappings.
 */
class parameter_descriptor {
public:
    /**
     * @brief Default constructor
     */
    explicit parameter_descriptor();

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
     * @brief Adds a string-to-value mapping
     * @param str String representation
     * @param val Value to map to
     * @throws xlio_exception If mapping already exists
     */
    void add_string_mapping(const std::string &str, const std::experimental::any &val);

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
     * @brief Resolves string mappings to actual values
     * @param val Input value (may be a string reference to a mapped value)
     * @return Resolved value (mapped value if string mapping exists, original otherwise)
     */
    std::experimental::any get_value(const std::experimental::any &val) const;

    /**
     * @brief Gets the type of the parameter
     * @return The type of the parameter
     */
    std::type_index type() const;

private:
    std::experimental::any m_default_value; /**< Default parameter value */
    std::vector<constraint_t> m_constraints; /**< Validation constraints */
    std::map<std::string, std::experimental::any> m_string_mapping; /**< String-to-value mappings */
    std::type_index m_type;
};
