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

// c++14 idiomatic way to check if the type is an integer
template <typename T>
struct is_integer
    : std::integral_constant<bool, std::is_integral<T>::value && !std::is_same<T, bool>::value> {};

class config_registry {
public:
    config_registry(std::queue<std::unique_ptr<loader>> &&value_loaders,
                    std::unique_ptr<descriptor_provider> descriptor_provider);

    config_registry();
    virtual ~config_registry() noexcept = default;

    bool value_exists(const std::string &key) const;

    // Generic implementation for non-integer types
    template <typename T>
    typename std::enable_if<!is_integer<T>::value, T>::type get_default_value(
        const std::string &key) const
    {
        return get_value_impl<T>(
            key, [this](const std::string &k) { return get_default_value_as_any(k); });
    }

    // Specialized implementation for integer types, check bounds before casting
    // In C++14 - bound checking isn't supportted for enum types.
    // It returns 0 for max and min.
    // Make sure to supply `int` to the template parameter
    template <typename T>
    typename std::enable_if<is_integer<T>::value, T>::type get_default_value(
        const std::string &key) const
    {
        return get_value_impl<T>(
            key, [this](const std::string &k) { return get_default_value_as_any(k); });
    }

    // Generic implementation for non-integer types
    template <typename T>
    typename std::enable_if<!is_integer<T>::value, T>::type get_value(const std::string &key) const
    {
        return get_value_impl<T>(key, [this](const std::string &k) { return get_value_as_any(k); });
    }

    // Specialized implementation for integer types, check bounds before casting
    // In C++14 - bound checking isn't supportted for enum types.
    // It returns 0 for max and min.
    // Make sure to supply `int` to the template parameter
    template <typename T>
    typename std::enable_if<is_integer<T>::value, T>::type get_value(const std::string &key) const
    {
        return get_value_impl<T>(key, [this](const std::string &k) { return get_value_as_any(k); });
    }

private:
    std::map<std::string, std::experimental::any> m_config_data;
    config_descriptor m_config_descriptor;

    std::experimental::any get_value_as_any(const std::string &key) const;
    std::experimental::any get_default_value_as_any(const std::string &key) const;
    void validate_config() const;
    void initialize_registry(std::queue<std::unique_ptr<loader>> &&value_loaders,
                             std::unique_ptr<descriptor_provider> descriptor_provider);

    // Helper method to consolidate the common logic
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

    // Specialized implementation for integer types
    template <typename T>
    typename std::enable_if<is_integer<T>::value, T>::type get_value_impl(
        const std::string &key,
        const std::function<std::experimental::any(const std::string &)> &getter) const
    {
        std::experimental::any raw_value = getter(key);

        try {
            int64_t int_value = std::experimental::any_cast<int64_t>(raw_value);
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
