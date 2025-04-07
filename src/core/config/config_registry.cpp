/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "config_registry.h"
#include "config_strings.h"
#include "core/util/xlio_exception.h"
#include "descriptor_providers/json_descriptor_provider.h"
#include "loaders/inline_loader.h"
#include "loaders/json_loader.h"

#include <fstream>

using namespace config_strings;

static const char *get_config_path() {
  const char *custom_path = std::getenv(env::XLIO_CUSTOM_CONFIG_FILE);
  return custom_path ? custom_path : paths::DEFAULT_CONFIG_FILE;
}

static std::queue<std::unique_ptr<loader>> create_default_loaders() {
  std::queue<std::unique_ptr<loader>> loaders;

  const char *inline_env = std::getenv(env::XLIO_INLINE_CONFIG);
  if (inline_env) {
    loaders.push(std::make_unique<inline_loader>(env::XLIO_INLINE_CONFIG));
  }

  loaders.push(std::make_unique<json_loader>(get_config_path()));

  return loaders;
}

config_registry::config_registry()
    : config_registry(create_default_loaders(),
                      std::make_unique<json_descriptor_provider>()) {}

config_registry::config_registry(
    std::queue<std::unique_ptr<loader>> &&value_loaders,
    std::unique_ptr<descriptor_provider> descriptor_provider) {
  initialize_registry(std::move(value_loaders), std::move(descriptor_provider));
}

void config_registry::initialize_registry(
    std::queue<std::unique_ptr<loader>> &&value_loaders,
    std::unique_ptr<descriptor_provider> descriptor_provider) {
  if (value_loaders.empty() || !descriptor_provider) {
    throw_xlio_exception(errors::CONFIG_MANAGER_NULL_LOADER);
  }

  // Load raw config data - first in queue means higher priority
  std::map<std::string, std::experimental::any> aggregated_config_data;
  while (!value_loaders.empty()) {
    std::map<std::string, std::experimental::any> loaded_data =
        value_loaders.front()->load_all();
    aggregated_config_data.insert(loaded_data.begin(), loaded_data.end());
    value_loaders.pop();
  }

  m_config_data = std::move(aggregated_config_data);

  m_config_descriptor = descriptor_provider->load_descriptors();

  validate_config();
}

static std::string format_value_for_error(const std::experimental::any &value) {
  if (value.type() == typeid(int64_t)) {
    return error_format::INTEGER_PREFIX +
           std::to_string(std::experimental::any_cast<int64_t>(value)) +
           errors::CLOSE_PAREN;
  } else if (value.type() == typeid(std::string)) {
    return error_format::STRING_PREFIX +
           std::experimental::any_cast<std::string>(value) +
           errors::CLOSE_PAREN;
  } else if (value.type() == typeid(bool)) {
    return error_format::BOOLEAN_PREFIX +
           std::string(std::experimental::any_cast<bool>(value)
                           ? error_format::TRUE_VALUE
                           : error_format::FALSE_VALUE) +
           errors::CLOSE_PAREN;
  }
  return misc::EMPTY_STRING;
}

void config_registry::validate_config() const {
  for (auto const &kv_pair : m_config_data) {
    const std::string &key = kv_pair.first;
    const std::experimental::any &value = kv_pair.second;

    const parameter_descriptor param_desc =
        m_config_descriptor.get_parameter(key);

    try {
      if (!param_desc.validate_constraints(value)) {
        const std::string error_msg = errors::CONFIG_MANAGER_VALIDATION_FAILED +
                                      key + format_value_for_error(value);
        throw_xlio_exception(error_msg);
      }
    } catch (const std::experimental::bad_any_cast &e) {
      throw_xlio_exception(errors::CONFIG_MANAGER_TYPE_MISMATCH + key +
                           errors::OPEN_PAREN + e.what() + errors::CLOSE_PAREN);
    }
  }
}

std::experimental::any
config_registry::get_value_as_any(const std::string &key) const {
  const auto it = m_config_data.find(key);

  const parameter_descriptor param = m_config_descriptor.get_parameter(key);

  if (it == m_config_data.end()) {
    return param.default_value();
  }

  return param.get_value(it->second);
}
