/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "inline_loader.h"
#include "core/config/config_strings.h"
#include "core/config/string_utils.h"
#include "core/util/xlio_exception.h"
#include <algorithm>
#include <sstream>
#include <vector>
#include <set>
#include <cctype>
#include <charconv>
#include <experimental/optional>
#include <utility>

// Static constants for magic characters
static const char DOUBLE_QUOTE = '"';
static const char SINGLE_QUOTE = '\'';
static const char EQUALS = '=';
static const char SEMICOLON = ';';
static std::string trim(const std::string &str);
static std::experimental::any parse_value_strict(const std::string &val, const std::string &key);
static std::experimental::optional<int64_t> try_parse_integer(const std::string &val);
static void validate_input_format(const std::string &config);
static void validate_key_value_pair(const std::string &kv);
static void validate_key_format(const std::string &key);
static void validate_value_characters(const std::string &val, const std::string &key,
                                      const std::string &config);
static void validate_key_characters(const std::string &key);
static bool contains_quotes(const std::string &str);
static bool contains_whitespace_internal(const std::string &str);
static void validate_characters(const std::string &str, const std::string &allowed_chars,
                                const std::string &error_message, const std::string &config);
static void throw_parsing_error(const std::string &message, const std::string &config = "");
static std::pair<std::string, std::string> extract_key_value(const std::string &kv,
                                                             const std::string &config);

inline_loader::inline_loader(const char *inline_config_key, const config_descriptor &descriptor)
    : loader(inline_config_key)
    , m_resolver(descriptor, inline_config_key)
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

void inline_loader::parse_inline_data()
{
    validate_input_format(m_inline_config);
    auto pairs = string_utils::split(m_inline_config, SEMICOLON);

    std::map<std::string, std::experimental::any> resolved_data;
    std::map<std::string, std::string> resolved_to_original;

    for (const auto &kv : pairs) {
        auto parsed = extract_key_value(kv, m_inline_config);

        std::string full_key = m_resolver.resolve(parsed.first);

        // check for duplicate parameters
        if (resolved_data.find(full_key) != resolved_data.end()) {
            throw_parsing_error("Duplicate parameter: '" + parsed.first + "' resolves to '" +
                                    full_key + "' which was already set by '" +
                                    resolved_to_original[full_key] + "'",
                                m_inline_config);
        }

        resolved_to_original[full_key] = parsed.first;
        resolved_data[full_key] = parse_value_strict(parsed.second, full_key);
    }

    if (resolved_data.empty()) {
        throw_parsing_error("No valid configuration found", m_inline_config);
    }

    m_data = std::move(resolved_data);
}

static std::string trim(const std::string &str)
{
    auto start = str.find_first_not_of(" \t");
    if (start == std::string::npos) {
        return "";
    }
    auto end = str.find_last_not_of(" \t");
    return str.substr(start, end - start + 1);
}

static std::experimental::any parse_value_strict(const std::string &val, const std::string &key)
{
    if (val.empty()) {
        throw_parsing_error("Empty value for key: " + key);
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

static std::pair<std::string, std::string> extract_key_value(const std::string &kv,
                                                             const std::string &config)
{
    validate_key_value_pair(kv);

    const auto eq_pos = kv.find(EQUALS);
    if (eq_pos == std::string::npos) {
        throw_parsing_error("Missing equals sign in pair: " + kv, config);
    }

    std::string raw_key = kv.substr(0, eq_pos);
    std::string raw_val = kv.substr(eq_pos + 1);

    if (contains_quotes(raw_key)) {
        throw_parsing_error("Key contains quotes: " + raw_key + "=" + raw_val, config);
    }
    if (contains_quotes(raw_val)) {
        throw_parsing_error("Value contains quotes: " + raw_key + "=" + raw_val, config);
    }

    std::string key = trim(raw_key);
    std::string val = trim(raw_val);

    if (contains_whitespace_internal(val)) {
        throw_parsing_error("Value contains whitespace: " + key + "=" + val, config);
    }

    validate_value_characters(val, key, config);

    if (key.empty()) {
        throw_parsing_error("Key cannot be empty", config);
    }

    if (val.empty()) {
        throw_parsing_error("Value cannot be empty", config);
    }

    validate_key_format(key);

    return {key, val};
}

static void validate_input_format(const std::string &config)
{
    if (config.empty()) {
        throw_parsing_error("Empty configuration string", config);
    }

    // Check for leading/trailing semicolons
    std::string trimmed = trim(config);
    if (trimmed.empty()) {
        throw_parsing_error("Empty configuration string");
    }
    if (trimmed.front() == SEMICOLON || trimmed.back() == SEMICOLON) {
        throw_parsing_error("Leading or trailing semicolon not allowed", config);
    }

    // Check for consecutive semicolons
    if (config.find(std::string(2, SEMICOLON)) != std::string::npos) {
        throw_parsing_error("Consecutive semicolons not allowed", config);
    }
}

static void validate_key_value_pair(const std::string &kv)
{
    std::string trimmed = trim(kv);

    if (trimmed.empty()) {
        throw_parsing_error("Empty key-value pair");
    }

    // Must contain exactly one equals sign
    size_t eq_count = std::count(trimmed.begin(), trimmed.end(), EQUALS);
    if (eq_count == 0) {
        throw_parsing_error("Missing equals sign in pair: " + kv);
    }
    if (eq_count > 1) {
        throw_parsing_error("Multiple equals signs in pair: " + kv);
    }

    // Must not start or end with equals
    if (trimmed.front() == EQUALS || trimmed.back() == EQUALS) {
        throw_parsing_error("Key or value cannot be empty in pair: " + kv);
    }
}

static void validate_key_format(const std::string &key)
{
    // Keys should match pattern: [a-zA-Z][a-zA-Z0-9._]*
    if (key.empty()) {
        throw_parsing_error("Empty key not allowed");
    }

    if (!std::isalpha(key[0])) {
        throw_parsing_error("Key must start with letter: " + key);
    }
    validate_key_characters(key);

    if (key[key.length() - 1] == '.') {
        throw_parsing_error("Key cannot end with dot: " + key);
    }
    if (key.find("..") != std::string::npos) {
        throw_parsing_error("Key cannot contain consecutive dots: " + key);
    }
}

static void validate_value_characters(const std::string &val, const std::string &key,
                                      const std::string &config)
{
    // values can only have underscores, dots, hyphens, slashes, and commas
    // aside from alphanumeric characters
    // underscores - for enums
    // dots - for paths
    // hyphens - for negative numbers and ranges (e.g., 7-10)
    // slashes - for paths
    // commas - for lists (e.g., cpu_affinity=0,4,8)
    static const std::string ALLOWED_VALUE_CHARS = ".-_/,";
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

static bool contains_whitespace_internal(const std::string &str)
{
    // Check for whitespace inside the string (after trimming)
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
