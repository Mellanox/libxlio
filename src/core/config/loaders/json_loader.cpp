/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "json_loader.h"
#include "core/config/config_strings.h"
#include "core/config/json_object_handle.h"
#include "core/util/xlio_exception.h"
#include <fstream>
#include <functional>
#include <queue>
#include <tuple>
#include <typeindex>

static std::experimental::any to_any_value(json_object *obj);
static std::experimental::any convert_boolean(json_object *obj);
static std::experimental::any convert_integer(json_object *obj);
static std::experimental::any convert_string(json_object *obj);
static std::experimental::any convert_object(json_object *obj);
static std::experimental::any convert_array(json_object *obj);

static std::experimental::any convert_boolean(json_object *obj)
{
    return bool(json_object_get_boolean(obj));
}

static std::experimental::any convert_integer(json_object *obj)
{
    return json_object_get_int64(obj);
}

static std::experimental::any convert_string(json_object *obj)
{
    const char *s = json_object_get_string(obj);
    return std::string(s ? s : config_strings::misc::EMPTY_STRING);
}

static std::experimental::any convert_object(json_object *obj)
{
    std::map<std::string, std::experimental::any> obj_map;
    json_object_object_foreach(obj, key, val)
    {
        obj_map[key] = to_any_value(val);
    }
    return obj_map;
}

static std::experimental::any convert_array(json_object *obj)
{
    std::vector<std::experimental::any> array_values;
    const size_t array_length = json_object_array_length(obj);
    for (size_t i = 0; i < array_length; ++i) {
        json_object *item = json_object_array_get_idx(obj, i);
        array_values.push_back(to_any_value(item));
    }
    return array_values;
}

static std::experimental::any to_any_value(json_object *obj)
{
    if (obj == nullptr) {
        throw_xlio_exception("obj can't be nullptr.");
    }

    // Map JSON types to their conversion functions
    static const std::map<json_type, std::experimental::any (*)(json_object *)> type_converters = {
        {json_type_boolean, convert_boolean},
        {json_type_int, convert_integer},
        {json_type_string, convert_string},
        {json_type_object, convert_object},
        {json_type_array, convert_array}};

    const json_type type = json_object_get_type(obj);
    const auto converter = type_converters.find(type);

    if (converter == type_converters.end()) {
        // JSON doubles and other types are not supported in the config
        throw_xlio_exception("Unsupported JSON type: " + std::to_string(type));
    }

    return converter->second(obj);
}

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

    json_object *raw_obj = json_object_from_file(m_source.c_str());
    if (!raw_obj) {
        throw_xlio_exception("Failed to parse JSON file: " + m_source);
    }

    json_object_handle root_obj(raw_obj);

    if (json_object_get_type(root_obj.get()) != json_type_object) {
        throw_xlio_exception("Top-level JSON is not an object: " + m_source);
    }

    process_json_object(config_strings::misc::EMPTY_STRING, root_obj.get());
    return m_data;
}

void json_loader::process_json_object(const std::string &prefix, json_object *obj)
{
    json_object_object_foreach(obj, key, value)
    {
        std::string current_key = prefix.empty() ? key : (prefix + config_strings::misc::DOT + key);

        json_type type = json_object_get_type(value);
        if (type == json_type_object) {
            // Recursively process nested objects
            process_json_object(current_key, value);
        } else {
            // Store non-object values directly
            m_data[current_key] = to_any_value(value);
        }
    }
}
