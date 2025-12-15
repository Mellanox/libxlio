/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "json_utils.h"
#include "config_strings.h"
#include "core/util/xlio_exception.h"
#include <map>

namespace json_utils {

// Forward declarations for converter functions
static std::experimental::any convert_boolean(json_object *obj);
static std::experimental::any convert_integer(json_object *obj);
static std::experimental::any convert_string(json_object *obj);
static std::experimental::any convert_object(json_object *obj);
static std::experimental::any convert_array(json_object *obj);

json_object *get_field(json_object *obj, const char *field_name)
{
    json_object *field = try_get_field(obj, field_name);
    if (!field) {
        throw_xlio_exception("Field " + std::string(field_name) + " not found in JSON object");
    }
    return field;
}

json_object *try_get_field(json_object *obj, const char *field_name)
{
    if (!obj || !field_name) {
        throw_xlio_exception("JSON object or field name cannot be null");
    }

    json_object *field = nullptr;
    if (doca_third_party_json_object_object_get_ex(obj, field_name, &field)) {
        return field;
    }

    return nullptr;
}

std::experimental::any to_any_value(json_object *obj)
{
    if (obj == nullptr) {
        throw_xlio_exception("JSON object cannot be null");
    }

    // Use function pointer dispatch for better performance and maintainability
    static const std::map<json_type, std::experimental::any (*)(json_object *)> type_converters = {
        {json_type_boolean, convert_boolean},
        {json_type_int, convert_integer},
        {json_type_string, convert_string},
        {json_type_object, convert_object},
        {json_type_array, convert_array}};

    const json_type type = doca_third_party_json_object_get_type(obj);
    const auto converter = type_converters.find(type);

    if (converter == type_converters.end()) {
        throw_xlio_exception("Unsupported JSON type: " + get_type_name(type) +
                             ". Supported types are: boolean, integer, string, object, array");
    }

    return converter->second(obj);
}

std::string get_type_name(json_type type)
{
    switch (type) {
    case json_type_null:
        return "null";
    case json_type_boolean:
        return "boolean";
    case json_type_double:
        return "double";
    case json_type_int:
        return "integer";
    case json_type_object:
        return "object";
    case json_type_array:
        return "array";
    case json_type_string:
        return "string";
    default:
        return "unknown";
    }
}

void validate_type(json_object *obj, json_type expected_type, const std::string &context)
{
    if (!obj) {
        throw_xlio_exception("JSON object is null in context: " + context);
    }

    json_type actual_type = doca_third_party_json_object_get_type(obj);
    if (actual_type != expected_type) {
        throw_xlio_exception("Type mismatch in " + context + ": expected " +
                             get_type_name(expected_type) + ", got " + get_type_name(actual_type));
    }
}

// Converter function implementations
static std::experimental::any convert_boolean(json_object *obj)
{
    return bool(doca_third_party_json_object_get_boolean(obj));
}

static std::experimental::any convert_integer(json_object *obj)
{
    return doca_third_party_json_object_get_int64(obj);
}

static std::experimental::any convert_string(json_object *obj)
{
    const char *s = doca_third_party_json_object_get_string(obj);
    return std::string(s ? s : config_strings::misc::EMPTY_STRING);
}

static std::experimental::any convert_object(json_object *obj)
{
    std::map<std::string, std::experimental::any> obj_map;
    doca_third_party_json_object_object_foreach(obj, key, val)
    {
        obj_map[key] = to_any_value(val);
    }
    return obj_map;
}

static std::experimental::any convert_array(json_object *obj)
{
    std::vector<std::experimental::any> array_values;
    const int array_length = doca_third_party_json_object_array_length(obj);
    array_values.reserve(array_length); // Optimize memory allocation

    for (int i = 0; i < array_length; i++) {
        json_object *item = doca_third_party_json_object_array_get_idx(obj, i);
        array_values.push_back(to_any_value(item));
    }
    return array_values;
}

// Template specializations
template <> std::vector<int64_t> extract_enum_values<int64_t>(json_object *enum_field)
{
    std::vector<int64_t> values;
    if (!enum_field) {
        return values;
    }

    const int enum_length = doca_third_party_json_object_array_length(enum_field);
    values.reserve(enum_length); // Optimize memory allocation

    for (int i = 0; i < enum_length; i++) {
        json_object *enum_value = doca_third_party_json_object_array_get_idx(enum_field, i);
        if (enum_value && doca_third_party_json_object_get_type(enum_value) == json_type_int) {
            values.push_back(doca_third_party_json_object_get_int64(enum_value));
        }
    }
    return values;
}

template <> std::vector<std::string> extract_enum_values<std::string>(json_object *enum_field)
{
    std::vector<std::string> values;
    if (!enum_field) {
        return values;
    }

    const int enum_length = doca_third_party_json_object_array_length(enum_field);
    values.reserve(enum_length); // Optimize memory allocation

    for (int i = 0; i < enum_length; i++) {
        json_object *enum_value = doca_third_party_json_object_array_get_idx(enum_field, i);
        if (enum_value && doca_third_party_json_object_get_type(enum_value) == json_type_string) {
            const char *str_val = doca_third_party_json_object_get_string(enum_value);
            if (str_val) {
                values.emplace_back(str_val);
            }
        }
    }
    return values;
}

} // namespace json_utils
