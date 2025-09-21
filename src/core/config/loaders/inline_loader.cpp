/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "inline_loader.h"
#include "core/config/config_strings.h"
#include "core/util/xlio_exception.h"
#include <algorithm>
#include <sstream>
#include <vector>

static std::vector<std::string> split(const std::string &s, char delimiter);
static std::string remove_spaces(std::string str);

static std::experimental::any parse_value(const std::string &val);

inline_loader::inline_loader(const char *inline_config_key)
    : loader(inline_config_key)
{
    if (m_source.empty()) {
        throw_xlio_exception("inline_config_key cannot be null.");
    }

    const char *inline_config = std::getenv(m_source.c_str());
    if (inline_config == nullptr) {
        throw_xlio_exception("inline config key not set: " + m_source);
    }

    m_inline_config = inline_config;
}

std::map<std::string, std::experimental::any> inline_loader::load_all() &
{
    if (m_data.empty()) {
        parse_inline_data();
    }
    return m_data;
}

bool inline_loader::check_unsupported_key_value_pair(const std::string &key,
                                                     const std::string &val) const
{
    // CPU affinity values may contain commas, which conflict with the inline format.
    // Hence - only hex values are supported for this parameter.
    if (key != "performance.threading.cpu_affinity") {
        return false;
    }

    // Only allow hexadecimal values (e.g., "0xCAFECAFE")
    if (val.size() >= 3 && val[0] == '0' && (val[1] == 'x' || val[1] == 'X')) {
        // Check that all remaining characters are valid hex digits
        for (size_t i = 2; i < val.size(); ++i) {
            if (!isxdigit(val[i])) {
                return true; // Not a valid hex number, so unsupported
            }
        }
        return false;
    }

    return true; // Not a hex value, so unsupported
}

void inline_loader::parse_inline_data()
{
    std::vector<std::string> pairs = split(m_inline_config, ',');
    for (const std::string &kv : pairs) {
        const std::string trimmed_kv = remove_spaces(kv);

        if (trimmed_kv.empty()) {
            continue;
        }

        const std::string::size_type eq_pos = trimmed_kv.find('=');
        if (eq_pos == std::string::npos) {
            throw_xlio_exception("Invalid key=value pair: " + trimmed_kv);
        }

        std::string key = trimmed_kv.substr(0, eq_pos);
        std::string val = trimmed_kv.substr(eq_pos + 1);

        // If either the key is empty, it's invalid
        if (trimmed_kv.empty()) {
            throw_xlio_exception("Empty key found in pair: " + kv);
        }

        // Check for unsupported parameters
        if (check_unsupported_key_value_pair(key, val)) {
            throw_xlio_exception("Value not supported in inline config: " + key +
                                 ".\nSee description for supported values.");
        }

        // Attempt to parse the value as bool/int, otherwise store string
        m_data[key] = parse_value(val);
    }

    if (m_data.empty()) {
        throw_xlio_exception("Invalid config: " + std::string(m_inline_config));
    }
}

static std::vector<std::string> split(const std::string &s, char delimiter)
{
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream token_stream(s);
    while (std::getline(token_stream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

static std::string remove_spaces(std::string str)
{
    str.erase(std::remove_if(str.begin(), str.end(), ::isspace), str.end());
    return str;
}

static std::experimental::any parse_value(const std::string &val)
{
    if (val == "true") {
        return true;
    }
    if (val == "false") {
        return false;
    }

    std::istringstream str_stream(val);
    int64_t int_val = 0;
    if (str_stream >> int_val && str_stream.eof()) {
        return int_val;
    }

    return val;
}
