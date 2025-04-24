/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "json_descriptor_provider.h"
#include "core/config/config_strings.h"
#include "core/config/json_object_handle.h"
#include "core/util/xlio_exception.h"
#include <algorithm>
#include <json-c/json.h>
#include <limits>
#include <string>
#include <vector>

#include "xlio_config_schema.h"

// Reference to the embedded JSON schema data that's compiled into the binary
extern unsigned char config_descriptor_providers_xlio_config_schema_json[];

// Forward declarations for all static functions
static std::type_index get_property_type(json_object *property_obj);
static std::experimental::any get_type_default(std::type_index type_index);
static std::experimental::any convert_json_to_any(json_object *field, std::type_index type_index);
static std::experimental::any get_property_default(json_object *property_obj,
                                                   std::type_index type_index);
static std::experimental::any to_any_value(json_object *obj);
static void add_numeric_constraint(json_object *property_obj, parameter_descriptor &param_desc,
                                   const char *field_name,
                                   std::function<bool(int64_t, int64_t)> comparator);

struct one_of_options {
    json_object *int_option;
    json_object *string_option;
    std::experimental::any default_val;
    bool valid;
};
static one_of_options find_one_of_options(json_object *one_of, const std::string &current_path);
static bool create_one_of_mappings(parameter_descriptor &param_desc, json_object *int_option,
                                   json_object *string_option, const std::string &current_path);
static bool is_one_of_property(json_object *property_obj);
static bool is_simple_property(json_object *property_obj);
static bool is_object_with_properties(json_object *property_obj);
static bool is_array_property(json_object *property_obj);

json_descriptor_provider::json_descriptor_provider()
    : json_descriptor_provider(
          reinterpret_cast<const char *>(config_descriptor_providers_xlio_config_schema_json))
{
}

json_descriptor_provider::json_descriptor_provider(const char *json_string)
    : m_json_string(json_string ? json_string
                                : throw_xlio_exception(config_strings::misc::JSON_STRING))
{
}

bool check_required_field(json_object *obj, const char *field_name, json_type expected_type)
{
    json_object *field = nullptr;
    return json_object_object_get_ex(obj, field_name, &field) &&
        json_object_get_type(field) == expected_type;
}

json_object *get_json_field(json_object *obj, const char *field_name)
{
    json_object *field = nullptr;
    if (!json_object_object_get_ex(obj, field_name, &field)) {
        return nullptr;
    }
    return field;
}

template <typename T> std::vector<T> extract_enum_values(json_object *enum_field);

template <> std::vector<int64_t> extract_enum_values<int64_t>(json_object *enum_field)
{
    std::vector<int64_t> values;
    if (!enum_field) {
        return values;
    }

    int enum_length = json_object_array_length(enum_field);
    for (int i = 0; i < enum_length; i++) {
        json_object *enum_value = json_object_array_get_idx(enum_field, i);
        if (json_object_get_type(enum_value) == json_type_int) {
            values.push_back(json_object_get_int64(enum_value));
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

    int enum_length = json_object_array_length(enum_field);
    for (int i = 0; i < enum_length; i++) {
        json_object *enum_value = json_object_array_get_idx(enum_field, i);
        const char *str_val = json_object_get_string(enum_value);
        if (str_val) {
            values.push_back(std::string(str_val));
        }
    }
    return values;
}

static std::experimental::any to_any_value(json_object *obj);

void json_descriptor_provider::validate_schema(json_object *schema)
{
    if (json_object_get_type(schema) != json_type_object) {
        throw_xlio_exception("Schema is not a JSON object.");
    }

    const std::map<std::string, json_type> required_fields = {
        {config_strings::schema::JSON_SCHEMA, json_type_string},
        {config_strings::schema::JSON_TITLE, json_type_string},
        {config_strings::schema::JSON_TYPE, json_type_string},
        {config_strings::schema::JSON_PROPERTIES, json_type_object}};

    for (const auto &field_kv : required_fields) {
        if (!check_required_field(schema, field_kv.first.c_str(), field_kv.second)) {
            throw_xlio_exception("Missing field: " + field_kv.first);
        }
    }

    json_object *type_field = get_json_field(schema, config_strings::schema::JSON_TYPE);
    if (std::string(json_object_get_string(type_field)) !=
        config_strings::schema_types::JSON_TYPE_OBJECT) {
        throw_xlio_exception("Schema root must have type 'object'.");
    }
}

static std::type_index get_property_type(json_object *property_obj)
{
    json_object *type_field = get_json_field(property_obj, config_strings::schema::JSON_TYPE);
    if (!type_field) {
        throw_xlio_exception("Missing 'type' field.");
    }

    std::string type_str = json_object_get_string(type_field);

    if (type_str == config_strings::schema_types::JSON_TYPE_BOOLEAN) {
        return typeid(bool);
    } else if (type_str == config_strings::schema_types::JSON_TYPE_INTEGER) {
        return typeid(int64_t);
    } else if (type_str == config_strings::schema_types::JSON_TYPE_STRING) {
        return typeid(std::string);
    } else if (type_str == config_strings::schema_types::JSON_TYPE_OBJECT) {
        return typeid(json_object *);
    } else if (type_str == config_strings::schema_types::JSON_TYPE_ARRAY) {
        return typeid(std::vector<std::experimental::any>);
    }

    throw_xlio_exception("Unsupported type: " + type_str);
}

static std::experimental::any get_type_default(std::type_index type_index)
{
    if (type_index == typeid(bool)) {
        return false;
    } else if (type_index == typeid(int64_t)) {
        return int64_t(0);
    } else if (type_index == typeid(std::string)) {
        return config_strings::misc::EMPTY_STRING;
    } else if (type_index == typeid(std::vector<std::experimental::any>)) {
        return std::vector<std::experimental::any>();
    }
    throw_xlio_exception("unsupported type for default value.");
}

static std::experimental::any convert_json_to_any(json_object *field, std::type_index type_index)
{
    if (type_index == typeid(bool)) {
        if (json_object_get_type(field) == json_type_boolean) {
            return static_cast<bool>(json_object_get_boolean(field));
        }
        throw_xlio_exception("Invalid boolean for default value.");
    } else if (type_index == typeid(int64_t)) {
        if (json_object_get_type(field) == json_type_int) {
            return json_object_get_int64(field);
        }
        throw_xlio_exception("Invalid integer for default value.");
    } else if (type_index == typeid(std::string)) {
        const char *str = json_object_get_string(field);
        if (str) {
            return std::string(str);
        }
        throw_xlio_exception("Invalid string for default value.");
    } else if (type_index == typeid(std::vector<std::experimental::any>)) {
        if (json_object_get_type(field) == json_type_array) {
            std::vector<std::experimental::any> array_values;
            int array_length = json_object_array_length(field);
            for (int i = 0; i < array_length; i++) {
                json_object *item = json_object_array_get_idx(field, i);
                array_values.push_back(to_any_value(item));
            }
            return array_values;
        }
        return std::vector<std::experimental::any>();
    }

    throw_xlio_exception("unsupported type for default value.");
}

static std::experimental::any get_property_default(json_object *property_obj,
                                                   std::type_index type_index)
{
    json_object *default_field = get_json_field(property_obj, config_strings::schema::JSON_DEFAULT);

    if (!default_field) {
        return get_type_default(type_index);
    }

    return convert_json_to_any(default_field, type_index);
}

static std::experimental::any to_any_value(json_object *obj)
{
    if (obj == nullptr) {
        throw_xlio_exception("obj can't be nullptr.");
    }

    json_type type = json_object_get_type(obj);
    switch (type) {
    case json_type_boolean:
        return bool(json_object_get_boolean(obj));
    case json_type_int:
        return json_object_get_int64(obj);
    case json_type_string: {
        const char *s = json_object_get_string(obj);
        return std::string(s ? s : config_strings::misc::EMPTY_STRING);
    }
    case json_type_object: {
        std::map<std::string, std::experimental::any> obj_map;
        json_object_object_foreach(obj, key, val)
        {
            obj_map[key] = to_any_value(val);
        }
        return obj_map;
    }
    case json_type_array: {
        std::vector<std::experimental::any> array_values;
        int array_length = json_object_array_length(obj);
        for (int i = 0; i < array_length; i++) {
            json_object *item = json_object_array_get_idx(obj, i);
            array_values.push_back(to_any_value(item));
        }
        return array_values;
    }
    default:
        throw_xlio_exception("unsupported type: " + std::to_string(type));
    }
}

static void add_numeric_constraint(json_object *property_obj, parameter_descriptor &param_desc,
                                   const char *field_name,
                                   std::function<bool(int64_t, int64_t)> comparator)
{
    json_object *field = get_json_field(property_obj, field_name);
    if (field && json_object_get_type(field) == json_type_int) {
        int64_t bound_val = json_object_get_int64(field);
        param_desc.add_constraint(
            [bound_val, comparator = std::move(comparator)](const std::experimental::any &val) {
                return comparator(std::experimental::any_cast<int64_t>(val), bound_val);
            });
    }
}

void json_descriptor_provider::add_property_constraints(json_object *property_obj,
                                                        parameter_descriptor &param_desc)
{
    add_numeric_constraint(property_obj, param_desc, config_strings::schema::JSON_MINIMUM,
                           [](int64_t value, int64_t min_val) { return value >= min_val; });

    add_numeric_constraint(property_obj, param_desc, config_strings::schema::JSON_MAXIMUM,
                           [](int64_t value, int64_t max_val) { return value <= max_val; });

    json_object *enum_field = get_json_field(property_obj, config_strings::schema::JSON_ENUM);
    if (enum_field && json_object_get_type(enum_field) == json_type_array) {
        std::vector<int64_t> allowed_values = extract_enum_values<int64_t>(enum_field);

        if (!allowed_values.empty()) {
            param_desc.add_constraint(
                [allowed_values = std::move(allowed_values)](const std::experimental::any &val) {
                    int64_t value = std::experimental::any_cast<int64_t>(val);
                    return std::find(allowed_values.begin(), allowed_values.end(), value) !=
                        allowed_values.end();
                });
        }
    }
}

static one_of_options find_one_of_options(json_object *one_of, const std::string &current_path)
{
    one_of_options result = {nullptr, nullptr, {}, false};

    int one_of_length = json_object_array_length(one_of);
    for (int i = 0; i < one_of_length; i++) {
        json_object *option = json_object_array_get_idx(one_of, i);
        json_object *type_field = get_json_field(option, config_strings::schema::JSON_TYPE);

        if (type_field && json_object_get_type(type_field) == json_type_string) {
            json_object *default_field =
                get_json_field(option, config_strings::schema::JSON_DEFAULT);
            if (!default_field) {
                throw_xlio_exception("no default value: " + current_path);
            }

            std::string type_str = json_object_get_string(type_field);
            if (type_str == config_strings::schema_types::JSON_TYPE_INTEGER) {
                result.int_option = option;
                if (result.default_val.type() == typeid(void)) {
                    result.default_val = json_object_get_int64(default_field);
                }
            } else if (type_str == config_strings::schema_types::JSON_TYPE_STRING) {
                result.string_option = option;
            }
        }
    }

    result.valid = (result.int_option != nullptr && result.string_option != nullptr &&
                    result.default_val.type() != typeid(void));

    return result;
}

static bool create_one_of_mappings(parameter_descriptor &param_desc, json_object *int_option,
                                   json_object *string_option, const std::string &current_path)
{
    std::vector<int64_t> allowed_int_values =
        extract_enum_values<int64_t>(get_json_field(int_option, config_strings::schema::JSON_ENUM));
    std::vector<std::string> allowed_string_values = extract_enum_values<std::string>(
        get_json_field(string_option, config_strings::schema::JSON_ENUM));

    if (allowed_int_values.size() != allowed_string_values.size()) {
        throw_xlio_exception("different option count: " + current_path);
    }

    for (size_t i = 0; i < allowed_string_values.size(); i++) {
        param_desc.add_string_mapping(allowed_string_values[i], allowed_int_values[i]);
    }

    param_desc.add_constraint([allowed_int_values = std::move(allowed_int_values),
                               allowed_string_values = std::move(allowed_string_values)](
                                  const std::experimental::any &val) {
        try {
            if (val.type() == typeid(int64_t)) {
                int64_t int_val = std::experimental::any_cast<int64_t>(val);

                if (!allowed_int_values.empty()) {
                    return std::find(allowed_int_values.begin(), allowed_int_values.end(),
                                     int_val) != allowed_int_values.end();
                }
                return true;
            } else if (val.type() == typeid(std::string)) {
                std::string str_val = std::experimental::any_cast<std::string>(val);

                if (!allowed_string_values.empty()) {
                    return std::find(allowed_string_values.begin(), allowed_string_values.end(),
                                     str_val) != allowed_string_values.end();
                }
                return true;
            }
        } catch (const std::exception &) {
            return false;
        }
        return false;
    });

    return true;
}

bool json_descriptor_provider::process_one_of_property(json_object *one_of,
                                                       const std::string &current_path,
                                                       config_descriptor &desc)
{
    json_object *one_of_field = get_json_field(one_of, config_strings::schema::JSON_ONE_OF);
    auto one_of_type = json_object_get_type(one_of_field);
    if (one_of_type != json_type_array) {
        throw_xlio_exception("one_of must be an array: " + current_path +
                             " - got: " + std::to_string(one_of_type));
    }

    one_of_options options = find_one_of_options(one_of_field, current_path);
    if (!options.valid) {
        return false;
    }

    parameter_descriptor param_desc(options.default_val);

    create_one_of_mappings(param_desc, options.int_option, options.string_option, current_path);

    desc.set_parameter(current_path, std::move(param_desc));
    return true;
}

bool json_descriptor_provider::process_array_property(json_object *property_obj,
                                                      const std::string &current_path,
                                                      config_descriptor &desc)
{
    std::experimental::any default_value =
        get_property_default(property_obj, typeid(std::vector<std::experimental::any>));

    parameter_descriptor param_desc(default_value);

    desc.set_parameter(current_path, std::move(param_desc));
    return true;
}

static bool is_one_of_property(json_object *property_obj)
{
    json_object *one_of = get_json_field(property_obj, config_strings::schema::JSON_ONE_OF);
    if (one_of) {
        return true;
    }

    return false;
}

static bool is_simple_property(json_object *property_obj)
{
    json_object *type_field = get_json_field(property_obj, config_strings::schema::JSON_TYPE);
    if (!type_field) {
        return false;
    }

    std::type_index type_index = get_property_type(property_obj);
    if (type_index == typeid(json_object *)) {
        return false;
    }

    return true;
}

static bool is_object_with_properties(json_object *property_obj)
{
    json_object *properties = get_json_field(property_obj, config_strings::schema::JSON_PROPERTIES);
    if (!properties || json_object_get_type(properties) != json_type_object) {
        return false;
    }

    return true;
}

static bool is_array_property(json_object *property_obj)
{
    json_object *type_field = get_json_field(property_obj, config_strings::schema::JSON_TYPE);
    if (type_field && json_object_get_type(type_field) == json_type_string &&
        json_object_get_string(type_field) == config_strings::schema_types::JSON_TYPE_ARRAY) {
        return true;
    }

    return false;
}

bool json_descriptor_provider::process_simple_property(json_object *property_obj,
                                                       const std::string &current_path,
                                                       config_descriptor &desc)
{

    // if you're a leaf property - you must have a title and description
    if (!check_required_field(property_obj, config_strings::schema::JSON_TITLE, json_type_string)) {
        throw_xlio_exception("no title: " + current_path);
    }

    if (!check_required_field(property_obj, config_strings::schema::JSON_DESCRIPTION,
                              json_type_string)) {
        throw_xlio_exception("no description: " + current_path);
    }

    std::experimental::any default_value =
        get_property_default(property_obj, get_property_type(property_obj));

    parameter_descriptor param_desc(default_value);

    add_property_constraints(property_obj, param_desc);

    desc.set_parameter(current_path, std::move(param_desc));
    return true;
}

bool json_descriptor_provider::process_object_property(json_object *property_obj,
                                                       const std::string &current_path,
                                                       config_descriptor &desc)
{
    json_object *properties = get_json_field(property_obj, config_strings::schema::JSON_PROPERTIES);
    if (!properties || json_object_get_type(properties) != json_type_object) {
        return false;
    }

    bool added_any = false;
    json_object_object_foreach(properties, nested_name, nested_obj)
    {
        added_any |= process_schema_property(nested_obj, nested_name, desc, current_path);
    }
    return added_any;
}

bool json_descriptor_provider::process_schema_property(json_object *property_obj,
                                                       const std::string &property_name,
                                                       config_descriptor &desc,
                                                       const std::string &path_prefix)
{
    if (json_object_get_type(property_obj) != json_type_object) {
        return false;
    }

    std::string current_path = path_prefix.empty()
        ? property_name
        : path_prefix + config_strings::misc::DOT + property_name;

    if (is_one_of_property(property_obj)) {
        return process_one_of_property(property_obj, current_path, desc);
    }

    if (is_simple_property(property_obj)) {
        return process_simple_property(property_obj, current_path, desc);
    }

    if (is_object_with_properties(property_obj)) {
        return process_object_property(property_obj, current_path, desc);
    }

    if (is_array_property(property_obj)) {
        return process_array_property(property_obj, current_path, desc);
    }

    return false;
}

config_descriptor json_descriptor_provider::load_descriptors()
{
    const char *schema_str = reinterpret_cast<const char *>(m_json_string);
    json_object *schema = json_tokener_parse(schema_str);
    if (!schema) {
        throw_xlio_exception("Failed to parse embedded JSON schema.");
    }

    json_object_handle schema_handle(schema);

    validate_schema(schema_handle.get());

    config_descriptor result_desc;

    json_object *properties =
        get_json_field(schema_handle.get(), config_strings::schema::JSON_PROPERTIES);
    if (!properties) {
        throw_xlio_exception("Schema missing 'properties' object.");
    }

    json_object_object_foreach(properties, section_name, section_obj)
    {
        process_schema_property(section_obj, section_name, result_desc);
    }

    return result_desc;
}
