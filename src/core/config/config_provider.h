/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once
#include "config_strings.h"
#include <experimental/any>
#include <stdexcept>
#include <string>

class config_provider {
public:
  virtual ~config_provider() noexcept = default;
  template <typename T> T get_value(const std::string &key) const {
    std::experimental::any raw_value = get_value_as_any(key);

    try {
      return std::experimental::any_cast<T>(raw_value);
    } catch (const std::experimental::bad_any_cast &e) {
      throw std::runtime_error(
          config_strings::errors::CONFIG_PROVIDER_BAD_ANY_CAST + key + " - " +
          e.what());
    }
  }

protected:
  virtual std::experimental::any
  get_value_as_any(const std::string &key) const = 0;
};
