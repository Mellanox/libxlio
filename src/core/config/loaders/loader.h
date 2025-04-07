/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once
#include <experimental/any>
#include <map>
#include <string>

class loader {
public:
  virtual ~loader() noexcept = default;
  virtual std::map<std::string, std::experimental::any> load_all() & = 0;

protected:
  // Cache of key->value pairs read
  std::map<std::string, std::experimental::any> m_data;
};
