/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "config_descriptor.h"
#include "core/config/config_strings.h"
#include "core/util/xlio_exception.h"

using namespace config_strings;

parameter_descriptor
config_descriptor::get_parameter(const std::string &key) const {
  auto it = parameter_map.find(key);
  if (it == parameter_map.end()) {
    throw_xlio_exception(errors::CONFIG_DESCRIPTOR_PARAMETER_NOT_FOUND_PREFIX +
                         key +
                         errors::CONFIG_DESCRIPTOR_PARAMETER_NOT_FOUND_SUFFIX);
  }
  return it->second;
}

void config_descriptor::set_parameter(const std::string &key,
                                      parameter_descriptor &&descriptor) {
  parameter_map.insert({key, std::move(descriptor)});
}