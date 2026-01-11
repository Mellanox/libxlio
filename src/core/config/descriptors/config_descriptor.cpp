/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "config_descriptor.h"
#include "core/config/config_strings.h"
#include "core/config/string_utils.h"
#include "core/util/xlio_exception.h"
#include <limits>
#include <algorithm>
#include <experimental/any>

parameter_descriptor config_descriptor::get_parameter(const std::string &key) const
{
    auto it = parameter_map.find(key);
    if (it == parameter_map.end()) {
        std::string suggestion;
        size_t min_distance = std::numeric_limits<size_t>::max();

        // Find the closest valid key using full path comparison
        for (const auto &pair : parameter_map) {
            const std::string &valid_key = pair.first;
            size_t distance = string_utils::levenshtein_distance(key, valid_key);
            if (distance < min_distance) {
                min_distance = distance;
                suggestion = valid_key;
            }
        }

        std::string error_msg = " Unknown key '" + key + "'.";

        // Add suggestion if a close match is found
        if (!suggestion.empty() && min_distance <= string_utils::MAX_LEVENSHTEIN_DISTANCE) {
            error_msg += "\nDid you mean '" + suggestion + "'?";
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
