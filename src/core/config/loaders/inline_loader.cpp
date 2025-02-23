/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-3-Clause
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "inline_loader.h"
#include "core/util/xlio_exception.h"

#include <sstream>

static std::vector<std::string> split(const std::string &s, char delimiter);
static std::string remove_spaces(std::string str);
static bool compare_case_insensitive(const std::string &val, const std::string &token);

static std::experimental::any parse_value(const std::string &val);

inline_loader::inline_loader(const char *inline_config_key)
{
    if (inline_config_key == nullptr) {
        throw_xlio_exception("inline_loader::inline_loader - inline_config_key cannot be null");
    }

    const char *inline_config = std::getenv(inline_config_key);
    if (inline_config == nullptr) {
        throw_xlio_exception("inline_loader::inline_loader - inline config key not set: " +
                             std::string(inline_config_key));
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

void inline_loader::parse_inline_data()
{
    std::vector<std::string> pairs = split(m_inline_config, ',');
    for (const std::string &kv : pairs) {
        const std::string trimmed_kv = remove_spaces(kv);

        if (trimmed_kv.empty()) {
            continue;
        }

        auto eq_pos = trimmed_kv.find('=');
        if (eq_pos == std::string::npos) {
            throw_xlio_exception("inline_loader::parse_inline_data - Invalid key=value pair: " +
                                 trimmed_kv);
        }

        std::string key = trimmed_kv.substr(0, eq_pos);
        std::string val = trimmed_kv.substr(eq_pos + 1);

        // If either the key is empty, it's invalid
        if (trimmed_kv.empty()) {
            throw_xlio_exception("inline_loader::parse_inline_data - Empty key found in pair: " +
                                 kv);
        }

        // Attempt to parse the value as bool/int, otherwise store string
        m_data[key] = parse_value(val);
    }

    if (m_data.empty()) {
        throw_xlio_exception("inline_loader::parse_inline_data - Invalid config: " +
                             std::string(m_inline_config));
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
    // Check for bool
    if (compare_case_insensitive(val, "true")) {
        return std::experimental::any(true);
    }
    if (compare_case_insensitive(val, "false")) {
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

static bool compare_case_insensitive(const std::string &val, const std::string &token)
{
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
