/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include "loader.h" // The loader base interface
#include <algorithm>
#include <cctype>
#include <experimental/any> // C++14 any
#include <map>
#include <stdexcept> // for std::runtime_error
#include <stdlib.h>  // for getenv
#include <string>
#include <vector>

class inline_loader : public loader {
public:
  inline_loader(const char *inline_config_key);
  std::map<std::string, std::experimental::any> load_all() & override;

private:
  void parse_inline_data();

private:
  const char *m_inline_config;
};