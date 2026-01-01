/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include <experimental/any>
#include <json-c/json.h>
#include <string>
#include <vector>

/**
 * @brief JSON utility functions for configuration subsystem
 *
 * Provides centralized, reusable functions for JSON manipulation and conversion
 * to avoid code duplication across the configuration subsystem.
 */
namespace json_utils {

/**
 * @brief Safely retrieves a field from a JSON object
 * @param obj The JSON object to search in
 * @param field_name The name of the field to retrieve
 * @return Pointer to the field object, or throws xlio_exception if not found or obj is null
 */
json_object *get_field(json_object *obj, const char *field_name);

/**
 * @brief Tries to retrieve a field from a JSON object
 * @param obj The JSON object to search in
 * @param field_name The name of the field to retrieve
 * @return Pointer to the field object, or nullptr if not found or obj is null
 */
json_object *try_get_field(json_object *obj, const char *field_name);

/**
 * @brief Converts a JSON object to std::experimental::any
 * @param obj The JSON object to convert
 * @return The converted value as std::experimental::any
 * @throws xlio_exception If obj is null or has unsupported type
 */
std::experimental::any to_any_value(json_object *obj);

/**
 * @brief Extracts enum values from a JSON array
 * @tparam T The type of values to extract (int64_t or std::string)
 * @param enum_field The JSON array containing enum values
 * @return Vector of extracted values, empty if enum_field is null
 */
template <typename T> std::vector<T> extract_enum_values(json_object *enum_field);

/**
 * @brief Gets a human-readable name for a JSON type
 * @param type The JSON type
 * @return String representation of the type
 */
std::string get_type_name(json_type type);

/**
 * @brief Validates that a JSON object has the expected type
 * @param obj The JSON object to validate
 * @param expected_type The expected JSON type
 * @param context String describing the context for error messages
 * @throws xlio_exception If obj is null or has wrong type
 */
void validate_type(json_object *obj, json_type expected_type, const std::string &context);

} // namespace json_utils

// Template specializations (must be in header for proper instantiation)
template <> std::vector<int64_t> json_utils::extract_enum_values<int64_t>(json_object *enum_field);

template <>
std::vector<std::string> json_utils::extract_enum_values<std::string>(json_object *enum_field);