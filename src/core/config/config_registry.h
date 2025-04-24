/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include "config_strings.h"
#include "core/util/xlio_exception.h"
#include "descriptor_providers/descriptor_provider.h"
#include "descriptors/config_descriptor.h"
#include "loaders/loader.h"
#include <experimental/any>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <queue>
#include <string>
#include <type_traits>
#include <vector>

/**
 * @brief Helper to check if a type is an integer (excluding bool)
 * @tparam T Type to check
 */
template <typename T>
struct is_integer
    : std::integral_constant<bool, std::is_integral<T>::value && !std::is_same<T, bool>::value> {};

/**
 * @brief Central registry for configuration values
 *
 * Manages configuration parameters, their loading from various sources,
 * and validation against defined constraints.
 */
class config_registry {
public:
    /**
     * @brief Default constructor using default loaders and descriptor provider
     */
    config_registry();

    /**
     * @brief Constructor with custom loaders and descriptor provider
     * @param value_loaders Queue of loaders to use (in priority order)
     * @param descriptor_provider Provider for parameter descriptors
     */
    config_registry(std::queue<std::unique_ptr<loader>> &&value_loaders,
                    std::unique_ptr<descriptor_provider> descriptor_provider);

    /**
     * @brief Virtual destructor
     */
    virtual ~config_registry() noexcept = default;

    /**
     * @brief Checks if a configuration value exists
     * @param key Configuration parameter key
     * @return True if value exists, false otherwise
     */
    bool value_exists(const std::string &key) const;

    /**
     * @brief Gets list of configuration sources
     * @return Vector of source identifiers
     */
    std::vector<std::string> get_sources() const;

    /**
     * @brief Gets default value for non-integer types
     * @tparam T Value type
     * @param key Configuration parameter key
     * @return Default value for the parameter
     */
    template <typename T>
    typename std::enable_if<!is_integer<T>::value, T>::type get_default_value(
        const std::string &key) const
    {
        return get_value_impl<T>(
            key, [this](const std::string &k) { return get_default_value_as_any(k); });
    }

    /**
     * @brief Gets default value for integer types with bounds checking
     * @tparam T Integer type
     * @param key Configuration parameter key
     * @return Default value for the parameter
     * @note For enums, use int instead since C++14 doesn't support bound checking for enums
     */
    template <typename T>
    typename std::enable_if<is_integer<T>::value, T>::type get_default_value(
        const std::string &key) const
    {
        return get_value_impl<T>(
            key, [this](const std::string &k) { return get_default_value_as_any(k); });
    }

    /**
     * @brief Gets configured value for non-integer types
     * @tparam T Value type
     * @param key Configuration parameter key
     * @return Current value for the parameter
     */
    template <typename T>
    typename std::enable_if<!is_integer<T>::value, T>::type get_value(const std::string &key) const
    {
        return get_value_impl<T>(key, [this](const std::string &k) { return get_value_as_any(k); });
    }

    /**
     * @brief Gets configured value for integer types with bounds checking
     * @tparam T Integer type
     * @param key Configuration parameter key
     * @return Current value for the parameter
     * @note For enums, use int instead since C++14 doesn't support bound checking for enums
     */
    template <typename T>
    typename std::enable_if<is_integer<T>::value, T>::type get_value(const std::string &key) const
    {
        return get_value_impl<T>(key, [this](const std::string &k) { return get_value_as_any(k); });
    }

private:
    std::map<std::string, std::experimental::any> m_config_data;
    config_descriptor m_config_descriptor;
    std::vector<std::string> m_sources;
    std::experimental::any get_value_as_any(const std::string &key) const;
    std::experimental::any get_default_value_as_any(const std::string &key) const;
    void validate_config() const;
    void initialize_registry(std::queue<std::unique_ptr<loader>> &&value_loaders,
                             std::unique_ptr<descriptor_provider> descriptor_provider);

    /**
     * @brief Helper implementation for retrieving non-integer values
     * @tparam T Value type
     * @param key Configuration parameter key
     * @param getter Function to retrieve the raw value
     * @return Value of type T
     */
    template <typename T>
    typename std::enable_if<!is_integer<T>::value, T>::type get_value_impl(
        const std::string &key,
        const std::function<std::experimental::any(const std::string &)> &getter) const
    {
        std::experimental::any raw_value = getter(key);

        try {
            return std::experimental::any_cast<T>(raw_value);
        } catch (const std::experimental::bad_any_cast &e) {
            throw_xlio_exception("Bad any_cast for key: " + key + " - " + e.what());
        }
    }

    /**
     * @brief Helper implementation for retrieving integer values with bounds checking
     * @tparam T Integer type
     * @param key Configuration parameter key
     * @param getter Function to retrieve the raw value
     * @return Value of type T with bounds validation
     */
    template <typename T>
    typename std::enable_if<is_integer<T>::value, T>::type get_value_impl(
        const std::string &key,
        const std::function<std::experimental::any(const std::string &)> &getter) const
    {
        static_assert(!std::is_enum<T>::value,
                      "T must not be an enum type as std::numeric_limits on enum returns 0. ");

        std::experimental::any raw_value = getter(key);

        try {
            int64_t int_value = std::experimental::any_cast<int64_t>(raw_value);
            // For int64_t, this check is redundant since int_value is already int64_t,
            // and the comparison will always be valid. However, for smaller integer types
            // (int, short, etc.), this check is necessary to ensure the value fits within
            // the target type's range. We keep this check for all integer types for consistency
            // and to avoid specialization.
            // coverity[result_independent_of_operands:FALSE]
            if (int_value < static_cast<int64_t>(std::numeric_limits<T>::min()) ||
                int_value > static_cast<int64_t>(std::numeric_limits<T>::max())) {
                throw_xlio_exception("Value out of range for key: " + key);
            }
            return static_cast<T>(int_value);
        } catch (const std::experimental::bad_any_cast &e) {
            throw_xlio_exception("Bad any_cast for key: " + key + " - " + e.what());
        }
    }
};
