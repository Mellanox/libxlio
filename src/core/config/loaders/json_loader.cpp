/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "json_loader.h"
#include "core/config/config_strings.h"
#include "core/config/json_object_handle.h"
#include "core/config/json_utils.h"
#include "core/util/xlio_exception.h"
#include <fstream>

json_loader::json_loader(const char *file_path)
    : loader(file_path)
{
    std::ifstream ifs(m_source.c_str());
    if (!ifs.good()) {
        throw_xlio_exception("Cannot open file: " + m_source);
    }
}

std::map<std::string, std::experimental::any> json_loader::load_all() &
{
    if (!m_data.empty()) {
        return m_data;
    }

    json_object *raw_obj = doca_third_party_json_object_from_file(m_source.c_str());
    if (!raw_obj) {
        throw_xlio_exception("Failed to parse JSON file: " + m_source);
    }

    json_object_handle root_obj(raw_obj);

    if (doca_third_party_json_object_get_type(root_obj.get()) != json_type_object) {
        throw_xlio_exception("Top-level JSON is not an object: " + m_source);
    }

    process_json_object(config_strings::misc::EMPTY_STRING, root_obj.get());
    return m_data;
}

void json_loader::process_json_object(const std::string &prefix, json_object *obj)
{
    doca_third_party_json_object_object_foreach(obj, key, value)
    {
        std::string key_str(key);
        if (key_str.find('.') != std::string::npos) {
            throw_xlio_exception("Key cannot contain dots: " + key_str);
        }

        std::string current_key =
            prefix.empty() ? std::move(key_str) : (prefix + config_strings::misc::DOT + key_str);

        json_type type = doca_third_party_json_object_get_type(value);
        if (type == json_type_object) {
            // Recursively process nested objects
            process_json_object(current_key, value);
        } else {
            // Store non-object values directly using centralized conversion
            m_data[current_key] = json_utils::to_any_value(value);
        }
    }
}
