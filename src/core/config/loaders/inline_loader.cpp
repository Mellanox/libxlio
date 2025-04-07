/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "inline_loader.h"
#include "core/config/config_strings.h"
#include "core/util/xlio_exception.h"

#include <sstream>

using namespace config_strings;

static std::vector<std::string> split(const std::string &s, char delimiter);
static std::string remove_spaces(std::string str);
static bool compare_case_insensitive(const std::string &val,
                                     const std::string &token);

static std::experimental::any parse_value(const std::string &val);

inline_loader::inline_loader(const char *inline_config_key) {
  if (inline_config_key == nullptr) {
    throw_xlio_exception(errors::INLINE_LOADER_CONFIG_KEY_NULL);
  }

  const char *inline_config = std::getenv(inline_config_key);
  if (inline_config == nullptr) {
    throw_xlio_exception(errors::INLINE_LOADER_CONFIG_KEY_NOT_SET +
                         std::string(inline_config_key));
  }

  m_inline_config = inline_config;
}

std::map<std::string, std::experimental::any> inline_loader::load_all() & {
  if (m_data.empty()) {
    parse_inline_data();
  }
  return m_data;
}

void inline_loader::parse_inline_data() {
  std::vector<std::string> pairs = split(m_inline_config, ',');
  for (const std::string &kv : pairs) {
    const std::string trimmed_kv = remove_spaces(kv);

    if (trimmed_kv.empty()) {
      continue;
    }

    const std::string::size_type eq_pos = trimmed_kv.find('=');
    if (eq_pos == std::string::npos) {
      throw_xlio_exception(errors::INLINE_LOADER_INVALID_PAIR + trimmed_kv);
    }

    std::string key = trimmed_kv.substr(0, eq_pos);
    std::string val = trimmed_kv.substr(eq_pos + 1);

    // If either the key is empty, it's invalid
    if (trimmed_kv.empty()) {
      throw_xlio_exception(errors::INLINE_LOADER_EMPTY_KEY + kv);
    }

    // Attempt to parse the value as bool/int, otherwise store string
    m_data[key] = parse_value(val);
  }

  if (m_data.empty()) {
    throw_xlio_exception(errors::INLINE_LOADER_INVALID_CONFIG +
                         std::string(m_inline_config));
  }
}

static std::vector<std::string> split(const std::string &s, char delimiter) {
  std::vector<std::string> tokens;
  std::string token;
  std::istringstream token_stream(s);
  while (std::getline(token_stream, token, delimiter)) {
    tokens.push_back(token);
  }
  return tokens;
}

static std::string remove_spaces(std::string str) {
  str.erase(std::remove_if(str.begin(), str.end(), ::isspace), str.end());
  return str;
}

static std::experimental::any parse_value(const std::string &val) {
  // Check for bool
  if (compare_case_insensitive(val, error_format::TRUE_VALUE)) {
    return std::experimental::any(true);
  }
  if (compare_case_insensitive(val, error_format::FALSE_VALUE)) {
    return std::experimental::any(false);
  }

  try {
    const int64_t int_val = std::stoll(val);
    return std::experimental::any(int_val);
  } catch (...) {
    // not an int
  }

  // store as string
  return std::experimental::any(val);
}

static bool compare_case_insensitive(const std::string &val,
                                     const std::string &token) {
  if (val.size() != token.size()) {
    return false;
  }

  for (size_t i = 0; i < val.size(); ++i) {
    if (std::tolower(val[i]) != std::tolower(token[i])) {
      return false;
    }
  }
  return true;
}
