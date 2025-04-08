/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once
#include "config_strings.h"
#include "core/util/xlio_exception.h"
#include <experimental/any>
#include <limits>
#include <string>
#include <type_traits>

// c++14 idiomatic way to check if the type is an integer
template <typename T>
struct is_integer
    : std::integral_constant<bool, std::is_integral<T>::value &&
                                       !std::is_same<T, bool>::value> {};

class config_provider {
public:
  virtual ~config_provider() noexcept = default;

  // Generic implementation for non-integer types
  template <typename T>
  typename std::enable_if<!is_integer<T>::value, T>::type
  get_value(const std::string &key) const {
    std::experimental::any raw_value = get_value_as_any(key);

    try {
      return std::experimental::any_cast<T>(raw_value);
    } catch (const std::experimental::bad_any_cast &e) {
      throw_xlio_exception(
          config_strings::errors::CONFIG_PROVIDER_BAD_ANY_CAST + key + " - " +
          e.what());
    }
  }

  // Specialized implementation for integer types, check bounds before casting
  // In C++14 - bound checking isn't supportted for enum types. 
  // It returns 0 for max and min.
  // Make sure to supply `int` to the template parameter
  template <typename T>
  typename std::enable_if<is_integer<T>::value, T>::type
  get_value(const std::string &key) const {
    std::experimental::any raw_value = get_value_as_any(key);

    try {
      int64_t int_value = std::experimental::any_cast<int64_t>(raw_value);
      if (int_value < static_cast<int64_t>(std::numeric_limits<T>::min()) ||
          int_value > static_cast<int64_t>(std::numeric_limits<T>::max())) {
        throw_xlio_exception(
            config_strings::errors::CONFIG_PROVIDER_BAD_ANY_CAST + key + " - " +
            "Value out of range for type " + typeid(T).name());
      }
      return static_cast<T>(int_value);
    } catch (const std::experimental::bad_any_cast &e) {
      throw_xlio_exception(
          config_strings::errors::CONFIG_PROVIDER_BAD_ANY_CAST + key + " - " +
          e.what());
    }
  }

protected:
  virtual std::experimental::any
  get_value_as_any(const std::string &key) const = 0;
};
