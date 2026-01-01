/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "inline_loader.h"
#include "core/config/config_strings.h"
#include "core/util/xlio_exception.h"
#include <algorithm>
#include <sstream>
#include <vector>
#include <set>
#include <cctype>
#include <charconv>
#include <experimental/optional>

// Static constants for magic characters
static const char DOUBLE_QUOTE = '"';
static const char SINGLE_QUOTE = '\'';
static const char EQUALS = '=';
static const char COMMA = ',';

static std::vector<std::string> split_strict(const std::string &s, char delimiter);
static std::string remove_spaces(std::string str);
static std::experimental::any parse_value_strict(const std::string &val, const std::string &key);
static std::experimental::optional<int64_t> try_parse_integer(const std::string &val);
static void validate_input_format(const std::string &config);
static void validate_key_value_pair(const std::string &kv);
static void validate_key_format(const std::string &key);
static void validate_value_characters(const std::string &val, const std::string &key,
                                      const std::string &config);
static void validate_key_characters(const std::string &key);
static bool contains_quotes(const std::string &str);
static bool contains_whitespace(const std::string &str);
static void validate_characters(const std::string &str, const std::string &allowed_chars,
                                const std::string &error_message, const std::string &config);
static void throw_parsing_error(const std::string &message, const std::string &config);

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

bool inline_loader::check_unsupported_key(const std::string &key) const
{
    // Do not support the cpu_affinity key in inline config
    if (key == "performance.threading.cpu_affinity") {
        return true;
    }
    return false;
}

void inline_loader::parse_inline_data()
{
    validate_input_format(m_inline_config);
    std::vector<std::string> pairs = split_strict(m_inline_config, COMMA);

    std::set<std::string> seen_keys;

    for (const std::string &kv : pairs) {
        validate_key_value_pair(kv);

        const std::string::size_type eq_pos = kv.find(EQUALS);
        if (eq_pos == std::string::npos) {
            throw_parsing_error("Missing equals sign in pair: " + kv, m_inline_config);
        }
        std::string key = kv.substr(0, eq_pos);
        std::string val = kv.substr(eq_pos + 1);

        if (contains_quotes(key)) {
            throw_parsing_error("Key contains quotes: " + key + "=" + val, m_inline_config);
        }
        if (contains_quotes(val)) {
            throw_parsing_error("Value contains quotes: " + key + "=" + val, m_inline_config);
        }

        if (contains_whitespace(val)) {
            throw_parsing_error("Value contains whitespace: " + key + "=" + val, m_inline_config);
        }

        validate_value_characters(val, key, m_inline_config);

        key = remove_spaces(key);

        if (key.empty()) {
            throw_parsing_error("Key cannot be empty", m_inline_config);
        }
        if (check_unsupported_key(key)) {
            throw_xlio_exception("Key not supported in inline config: " + key +
                                 ".\nSee description for unsupported keys.");
        }

        if (val.empty()) {
            throw_parsing_error("Value cannot be empty", m_inline_config);
        }

        if (seen_keys.find(key) != seen_keys.end()) {
            throw_parsing_error("Duplicate parameter: " + key, m_inline_config);
        }
        seen_keys.insert(key);

        validate_key_format(key);

        m_data[key] = parse_value_strict(val, key);
    }

    if (m_data.empty()) {
        throw_parsing_error("No valid configuration found", m_inline_config);
    }
}

static std::vector<std::string> split_strict(const std::string &s, char delimiter)
{
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream token_stream(s);

    while (std::getline(token_stream, token, delimiter)) {
        // Don't trim spaces here - we need to check for them later
        // Skip empty tokens
        if (token.empty()) {
            continue;
        }

        tokens.push_back(token);
    }

    return tokens;
}

static std::string remove_spaces(std::string str)
{
    str.erase(std::remove_if(str.begin(), str.end(), ::isspace), str.end());
    return str;
}

static std::experimental::any parse_value_strict(const std::string &val, const std::string &key)
{
    if (val.empty()) {
        throw_parsing_error("Empty value for key: " + key, "");
    }

    if (val == "true" || val == "false") {
        return val == "true";
    }

    if (std::experimental::optional<int64_t> int_val = try_parse_integer(val)) {
        return *int_val;
    }

    return val;
}

static std::experimental::optional<int64_t> try_parse_integer(const std::string &val)
{
    int64_t result = 0;
    const char *ptr = val.data();
    const char *end = val.data() + val.size();
    auto parse_result = std::from_chars(ptr, end, result);

    // Return the parsed value if successful, empty optional otherwise
    if (parse_result.ec == std::errc {} && parse_result.ptr == end) {
        return result;
    }
    return std::experimental::nullopt;
}

static void validate_input_format(const std::string &config)
{
    if (config.empty()) {
        throw_parsing_error("Empty configuration string", config);
    }

    // Check for leading/trailing commas
    if (config.front() == COMMA || config.back() == COMMA) {
        throw_parsing_error("Leading or trailing comma not allowed", config);
    }

    // Check for consecutive commas
    if (config.find(std::string(2, COMMA)) != std::string::npos) {
        throw_parsing_error("Consecutive commas not allowed", config);
    }
}

static void validate_key_value_pair(const std::string &kv)
{
    // Must contain exactly one equals sign
    size_t eq_count = std::count(kv.begin(), kv.end(), EQUALS);
    if (eq_count == 0) {
        throw_parsing_error("Missing equals sign in pair: " + kv, "");
    }
    if (eq_count > 1) {
        throw_parsing_error("Multiple equals signs in pair: " + kv, "");
    }

    // Must not start or end with equals
    if (kv.front() == EQUALS || kv.back() == EQUALS) {
        throw_parsing_error("Key or value cannot be empty in pair: " + kv, "");
    }
}

static void validate_key_format(const std::string &key)
{
    // Keys should match pattern: [a-zA-Z][a-zA-Z0-9._]*
    if (key.empty()) {
        throw_parsing_error("Empty key not allowed", "");
    }

    if (!std::isalpha(key[0])) {
        throw_parsing_error("Key must start with letter: " + key, "");
    }
    validate_key_characters(key);

    if (key[key.length() - 1] == '.') {
        throw_parsing_error("Key cannot end with dot: " + key, "");
    }
    if (key.find("..") != std::string::npos) {
        throw_parsing_error("Key cannot contain consecutive dots: " + key, "");
    }
}

static void validate_value_characters(const std::string &val, const std::string &key,
                                      const std::string &config)
{
    // values can only have underscores, dots, hyphens, and slashes
    // aside from alphanumeric characters
    // underscores - for enums
    // dots - for paths
    // hyphens - for negative numbers
    // slashes - for paths
    static const std::string ALLOWED_VALUE_CHARS = ".-_/";
    validate_characters(val, ALLOWED_VALUE_CHARS,
                        "Value contains invalid character: " + key + "=" + val, config);
}

static void validate_key_characters(const std::string &key)
{
    // keys can only have underscores and dots aside from alphanumeric characters
    static const std::string ALLOWED_KEY_CHARS = "._";
    validate_characters(key, ALLOWED_KEY_CHARS, "Invalid character in key: " + key, "");
}

static bool contains_quotes(const std::string &str)
{
    return str.find(DOUBLE_QUOTE) != std::string::npos ||
        str.find(SINGLE_QUOTE) != std::string::npos;
}

static bool contains_whitespace(const std::string &str)
{
    for (char c : str) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            return true;
        }
    }
    return false;
}

static void validate_characters(const std::string &str, const std::string &allowed_chars,
                                const std::string &error_message, const std::string &config)
{
    for (char c : str) {
        if (!std::isalnum(c) && allowed_chars.find(c) == std::string::npos) {
            throw_parsing_error(error_message, config);
        }
    }
}

static void throw_parsing_error(const std::string &message, const std::string &config)
{
    std::string full_message = "XLIO_INLINE_CONFIG parsing error: " + message;
    if (!config.empty()) {
        full_message += "\nConfiguration: " + config;
    }
    throw_xlio_exception(full_message);
}
