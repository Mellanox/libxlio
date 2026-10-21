/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "key_resolver.h"
#include "core/config/string_utils.h"
#include "core/util/xlio_exception.h"
#include <algorithm>
#include <experimental/optional>

key_resolver::key_resolver(const config_descriptor &descriptor, const std::string &source_name)
    : m_source_name(source_name)
{
    build_suffix_index(descriptor);
}

void key_resolver::build_suffix_index(const config_descriptor &descriptor)
{
    for (const auto &pair : descriptor.get_parameter_map()) {
        const std::string &full_path = pair.first;
        m_all_paths.insert(full_path);

        // Add all suffixes: for "a.b.c.d" add "d", "c.d", "b.c.d", "a.b.c.d"
        for (size_t pos = 0; pos < full_path.size();) {
            m_suffix_index[full_path.substr(pos)].emplace_back(full_path);
            pos = full_path.find('.', pos);
            if (pos == std::string::npos) {
                break;
            }
            ++pos; // Skip the dot
        }
    }
}

std::string key_resolver::resolve(const std::string &input_key) const
{
    // Exact match wins
    if (m_all_paths.count(input_key)) {
        return input_key;
    }

    // Suffix match
    auto it = m_suffix_index.find(input_key);
    if (it == m_suffix_index.end() || it->second.empty()) {
        // No matches - throw with Levenshtein suggestion
        std::string error_msg = "In '" + m_source_name + "': Unknown key '" + input_key + "'.";
        if (auto suggestion = find_suggestion(input_key)) {
            error_msg += "\nDid you mean '" + *suggestion + "'?";
        }
        throw_xlio_exception(error_msg);
    }

    if (it->second.size() == 1) {
        return it->second[0];
    }

    // Ambiguous
    throw_xlio_exception(format_ambiguity_error(input_key, it->second));
}

std::string key_resolver::format_ambiguity_error(const std::string &key,
                                                 const std::vector<std::string> &matches) const
{
    std::string error_msg =
        "In '" + m_source_name + "': Ambiguous key '" + key + "'. Did you mean:";

    for (const auto &full_path : matches) {
        auto shortest = find_shortest_unique_suffix(full_path);
        error_msg += "\n  - " + shortest;
        if (shortest != full_path) {
            error_msg += " (" + full_path + ")";
        }
    }

    return error_msg;
}

std::string key_resolver::find_shortest_unique_suffix(const std::string &full_path) const
{
    // Split "a.b.c.d" into ["a", "b", "c", "d"]
    auto segments = string_utils::split(full_path, '.');

    // Build suffixes right-to-left: "d", "c.d", "b.c.d", "a.b.c.d"
    std::string suffix;
    for (auto it = segments.rbegin(); it != segments.rend(); ++it) {
        suffix = suffix.empty() ? *it : *it + "." + suffix;

        auto found = m_suffix_index.find(suffix);
        if (found != m_suffix_index.end() && found->second.size() == 1) {
            return suffix;
        }
    }

    return full_path;
}

std::experimental::optional<std::string> key_resolver::find_suggestion(const std::string &key) const
{
    if (m_suffix_index.empty()) {
        return std::experimental::nullopt;
    }

    auto best = std::min_element(m_suffix_index.begin(), m_suffix_index.end(),
                                 [&key](const auto &a, const auto &b) {
                                     return string_utils::levenshtein_distance(key, a.first) <
                                         string_utils::levenshtein_distance(key, b.first);
                                 });

    if (string_utils::levenshtein_distance(key, best->first) <=
        string_utils::MAX_LEVENSHTEIN_DISTANCE) {
        return find_shortest_unique_suffix(best->second[0]);
    }

    return std::experimental::nullopt;
}
