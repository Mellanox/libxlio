/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "config_descriptor.h"
#include "core/config/config_strings.h"
#include "core/util/xlio_exception.h"
#include <limits>
#include <algorithm>
#include <experimental/any>

static const size_t MAX_LEVENSHTEIN_DISTANCE = 2;
static size_t calculate_levenshtein_distance(const std::string &s1, const std::string &s2);

parameter_descriptor config_descriptor::get_parameter(const std::string &key) const
{
    auto it = parameter_map.find(key);
    if (it == parameter_map.end()) {
        std::string suggestion;
        size_t min_distance = std::numeric_limits<size_t>::max();

        // Find the closest valid key using full path comparison
        for (const auto &pair : parameter_map) {
            const std::string &valid_key = pair.first;
            size_t distance = calculate_levenshtein_distance(key, valid_key);
            if (distance < min_distance) {
                min_distance = distance;
                suggestion = valid_key;
            }
        }

        std::string error_msg = " Unknown key '" + key + "'.";

        // Add suggestion if a close match is found
        if (!suggestion.empty() && min_distance <= MAX_LEVENSHTEIN_DISTANCE) {
            error_msg += "\n Did you mean '" + suggestion + "'?";
        }

        throw_xlio_exception(error_msg);
    }
    return it->second;
}

void config_descriptor::set_parameter(const std::string &key, parameter_descriptor &&descriptor)
{
    parameter_map.insert({key, std::move(descriptor)});
    update_parameter_keys(key);
}

bool config_descriptor::is_parent_of_parameter_keys(const std::string &key) const
{
    std::string parent_key = key + ".";

    // Use lower_bound to find the first key that is >= parent_key
    auto it = parameter_keys.lower_bound(parent_key);

    // Check if the found key starts with our parent_key prefix
    if (it != parameter_keys.end() && it->find(parent_key) == 0) {
        return true;
    }

    return false;
}

void config_descriptor::update_parameter_keys(const std::string &key)
{
    parameter_keys.insert(key);
}

std::type_index config_descriptor::get_parent_expected_type(const std::string &key) const
{
    if (!is_parent_of_parameter_keys(key)) {
        throw_xlio_exception("Key '" + key + "' is not a parent of parameter keys");
    }

    // Parent objects in JSON schema are always objects (they contain nested properties)
    // We return the type for a JSON object, which is typically represented as a map
    return typeid(std::map<std::string, std::experimental::any>);
}

const config_descriptor::parameter_map_t &config_descriptor::get_parameter_map() const
{
    return parameter_map;
}

/**
 * @brief Calculates the Levenshtein distance between two strings.
 *
 * The Levenshtein distance is the number of single-character edits
 * (insertions, deletions, or substitutions) required to change one
 * string into the other.
 *
 * @param s1 The first string.
 * @param s2 The second string.
 * @return The Levenshtein distance between the two strings.
 */
static size_t calculate_levenshtein_distance(const std::string &s1, const std::string &s2)
{
    const size_t len1 = s1.size();
    const size_t len2 = s2.size();

    // Create a distance matrix
    std::vector<size_t> col(len2 + 1);
    std::vector<size_t> prev_col(len2 + 1);

    // Initialize the first column
    for (size_t i = 0; i < prev_col.size(); i++) {
        prev_col[i] = i;
    }

    // Calculate distances
    for (size_t i = 0; i < len1; i++) {
        col[0] = i + 1;
        for (size_t j = 0; j < len2; j++) {
            col[j + 1] =
                std::min({prev_col[j + 1] + 1, col[j] + 1, prev_col[j] + (s1[i] == s2[j] ? 0 : 1)});
        }
        col.swap(prev_col);
    }

    return prev_col[len2];
}
