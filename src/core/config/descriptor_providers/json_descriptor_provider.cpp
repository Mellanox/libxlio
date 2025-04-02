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

#include "json_descriptor_provider.h"
#include <json-c/json.h>
#include <algorithm>
#include <limits>
#include <string>
#include <vector>
#include "core/util/xlio_exception.h"

#ifndef JSON_DESCRIPTOR_H
#define JSON_DESCRIPTOR_H
#include "json_descriptor.h"
#endif

extern unsigned char config_descriptor_providers_json_descriptor_json[];

json_descriptor_provider::json_descriptor_provider()
    : json_descriptor_provider(
          reinterpret_cast<const char *>(config_descriptor_providers_json_descriptor_json))
{
}

json_descriptor_provider::json_descriptor_provider(const char *json_string)
    : m_json_string(json_string ? json_string : throw_xlio_exception("json_string"))
{
}

// Helper function to check if a JSON object has a required field of specific type
bool check_required_field(json_object *obj, const char *field_name, json_type expected_type)
{
    json_object *field = nullptr;
    return json_object_object_get_ex(obj, field_name, &field) &&
        json_object_get_type(field) == expected_type;
}

// Helper function to get a JSON field as a specific object
json_object *get_json_field(json_object *obj, const char *field_name)
{
    json_object *field = nullptr;
    if (!json_object_object_get_ex(obj, field_name, &field)) {
        return nullptr;
    }
    return field;
}

// Extract enum values from JSON into a vector
template <typename T> std::vector<T> extract_enum_values(json_object *enum_field);

// Specialization for int64_t
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

// Specialization for std::string
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

void json_descriptor_provider::validate_schema(json_object *schema)
{
    // Basic schema validation
    if (json_object_get_type(schema) != json_type_object) {
        throw_xlio_exception("json_descriptor_provider: Schema is not a JSON object.");
    }

    // Required fields with their expected types
    const struct {
        const char *name;
        json_type type;
    } fields[] = {{"$schema", json_type_string},
                  {"title", json_type_string},
                  {"type", json_type_string},
                  {"properties", json_type_object}};

    // Check each required field
    for (const auto &field : fields) {
        if (!check_required_field(schema, field.name, field.type)) {
            throw_xlio_exception("json_descriptor_provider: Missing or invalid '" +
                                 std::string(field.name) + "' field.");
        }
    }

    // Verify that root type is "object"
    json_object *type_field = get_json_field(schema, "type");
    if (std::string(json_object_get_string(type_field)) != "object") {
        throw_xlio_exception("json_descriptor_provider: Schema root must have type 'object'.");
    }
}

std::type_index json_descriptor_provider::get_property_type(json_object *property_obj)
{
    json_object *type_field = get_json_field(property_obj, "type");
    if (!type_field) {
        throw_xlio_exception("json_descriptor_provider: Missing 'type' field.");
    }

    std::string type_str = json_object_get_string(type_field);

    if (type_str == "boolean") {
        return typeid(bool);
    } else if (type_str == "integer") {
        return typeid(int64_t);
    } else if (type_str == "string") {
        return typeid(std::string);
    } else if (type_str == "object") {
        return typeid(json_object *);
    }

    throw_xlio_exception("json_descriptor_provider: Unsupported type: " + type_str);
}

std::experimental::any json_descriptor_provider::get_property_default(json_object *property_obj,
                                                                      std::type_index type_index)
{
    json_object *default_field = get_json_field(property_obj, "default");

    // If no default is specified, use type-appropriate defaults
    if (!default_field) {
        if (type_index == typeid(bool)) {
            return false;
        } else if (type_index == typeid(int64_t)) {
            return int64_t(0);
        } else if (type_index == typeid(std::string)) {
            return std::string("");
        }
        throw_xlio_exception("json_descriptor_provider: No default value for unsupported type.");
    }

    // Convert default value based on type
    if (type_index == typeid(bool)) {
        if (json_object_get_type(default_field) == json_type_boolean) {
            return static_cast<bool>(json_object_get_boolean(default_field));
        }
        throw_xlio_exception("json_descriptor_provider: Invalid boolean for default value.");
    } else if (type_index == typeid(int64_t)) {
        if (json_object_get_type(default_field) == json_type_int) {
            return json_object_get_int64(default_field);
        }
        throw_xlio_exception("json_descriptor_provider: Invalid integer for default value.");
    } else if (type_index == typeid(std::string)) {
        const char *str = json_object_get_string(default_field);
        if (str) {
            return std::string(str);
        }
        throw_xlio_exception("json_descriptor_provider: Invalid string for default value.");
    }

    throw_xlio_exception("json_descriptor_provider: Unsupported type for default value.");
}

void json_descriptor_provider::add_property_constraints(json_object *property_obj,
                                                        parameter_descriptor &param_desc)
{
    // Add minimum constraint if present
    json_object *minimum_field = get_json_field(property_obj, "minimum");
    if (minimum_field && json_object_get_type(minimum_field) == json_type_int) {
        int64_t min_val = json_object_get_int64(minimum_field);
        param_desc.add_constraint([min_val](const std::experimental::any &val) {
            return std::experimental::any_cast<int64_t>(val) >= min_val;
        });
    }

    // Add maximum constraint if present
    json_object *maximum_field = get_json_field(property_obj, "maximum");
    if (maximum_field && json_object_get_type(maximum_field) == json_type_int) {
        int64_t max_val = json_object_get_int64(maximum_field);
        param_desc.add_constraint([max_val](const std::experimental::any &val) {
            return std::experimental::any_cast<int64_t>(val) <= max_val;
        });
    }

    // Add enum constraints if present for integers
    json_object *enum_field = get_json_field(property_obj, "enum");
    if (enum_field && json_object_get_type(enum_field) == json_type_array) {
        std::vector<int64_t> allowed_values = extract_enum_values<int64_t>(enum_field);

        if (!allowed_values.empty()) {
            param_desc.add_constraint([allowed_values](const std::experimental::any &val) {
                int64_t value = std::experimental::any_cast<int64_t>(val);
                return std::find(allowed_values.begin(), allowed_values.end(), value) !=
                    allowed_values.end();
            });
        }
    }
}

// Process a oneOf property (typically for dual int/string types)
bool json_descriptor_provider::process_one_of_property(json_object *one_of,
                                                       const std::string &current_path,
                                                       config_descriptor &desc)
{
    json_object *int_option = nullptr;
    json_object *string_option = nullptr;
    std::experimental::any default_val;
    bool has_default = false;

    // Examine each oneOf option to find integer and string types
    int one_of_length = json_object_array_length(one_of);
    for (int i = 0; i < one_of_length; i++) {
        json_object *option = json_object_array_get_idx(one_of, i);
        json_object *type_field = get_json_field(option, "type");

        if (type_field && json_object_get_type(type_field) == json_type_string) {
            json_object *default_field = get_json_field(option, "default");
            if (!default_field) {
                throw_xlio_exception("json_descriptor_provider: Property " + current_path +
                                     " has no default value.");
            }

            std::string type_str = json_object_get_string(type_field);
            if (type_str == "integer") {
                int_option = option;
                if (!has_default) {
                    default_val = json_object_get_int64(default_field);
                    has_default = true;
                }
            } else if (type_str == "string") {
                string_option = option;
            }
        }
    }

    if (!int_option || !string_option || !has_default) {
        return false;
    }

    // Create parameter descriptor with the primary type
    parameter_descriptor param_desc(default_val, typeid(int64_t));

    // Extract integer and string enum values
    std::vector<int64_t> allowed_int_values =
        extract_enum_values<int64_t>(get_json_field(int_option, "enum"));
    std::vector<std::string> allowed_string_values =
        extract_enum_values<std::string>(get_json_field(string_option, "enum"));

    // Ensure we have matching pairs of integer and string values
    if (allowed_int_values.size() != allowed_string_values.size()) {
        throw_xlio_exception("json_descriptor_provider: Property " + current_path +
                             " has different number of integer and string options.");
    }

    // Create mapping from string values to integer values
    for (size_t i = 0; i < allowed_string_values.size(); i++) {
        param_desc.add_string_mapping(allowed_string_values[i], allowed_int_values[i]);
    }

    // Create the validator function that handles both integer and string types
    param_desc.add_constraint(
        [allowed_int_values, allowed_string_values](const std::experimental::any &val) {
            try {
                if (val.type() == typeid(int64_t)) {
                    // Integer validation
                    int64_t int_val = std::experimental::any_cast<int64_t>(val);

                    // Check enum constraints if present
                    if (!allowed_int_values.empty()) {
                        return std::find(allowed_int_values.begin(), allowed_int_values.end(),
                                         int_val) != allowed_int_values.end();
                    }
                    return true;
                } else if (val.type() == typeid(std::string)) {
                    // String validation
                    std::string str_val = std::experimental::any_cast<std::string>(val);

                    // Check enum constraints
                    if (!allowed_string_values.empty()) {
                        return std::find(allowed_string_values.begin(), allowed_string_values.end(),
                                         str_val) != allowed_string_values.end();
                    }
                    return true;
                }
            } catch (const std::exception &) {
                // Any cast failed
                return false;
            }
            // Unknown type
            return false;
        });

    // Add the parameter to the descriptor
    desc.set_parameter(current_path, std::move(param_desc));
    return true;
}

bool json_descriptor_provider::process_schema_property(json_object *property_obj,
                                                       const std::string &property_name,
                                                       config_descriptor &desc,
                                                       const std::string &path_prefix)
{
    if (json_object_get_type(property_obj) != json_type_object) {
        return false;
    }

    std::string current_path =
        path_prefix.empty() ? property_name : path_prefix + "." + property_name;

    // Make sure property has a description
    if (!check_required_field(property_obj, "description", json_type_string)) {
        throw_xlio_exception("json_descriptor_provider: Property " + current_path +
                             " has no description.");
    }

    // Handle oneOf case - create a dual-type parameter descriptor
    json_object *one_of = get_json_field(property_obj, "oneOf");
    if (one_of && json_object_get_type(one_of) == json_type_array) {
        return process_one_of_property(one_of, current_path, desc);
    }

    // Handle regular properties with a single type
    json_object *type_field = get_json_field(property_obj, "type");
    if (type_field) {
        // Simple property case (boolean, integer, string)
        std::type_index type_index = get_property_type(property_obj);
        if (type_index != typeid(json_object *)) {
            // Get default value
            std::experimental::any default_value = get_property_default(property_obj, type_index);

            // Create parameter descriptor
            parameter_descriptor param_desc(default_value, type_index);

            // Handle constraints for integer type
            add_property_constraints(property_obj, param_desc);

            // Add to config descriptor
            desc.set_parameter(current_path, std::move(param_desc));
            return true;
        }
    }

    // Object property case - has nested properties
    json_object *properties = get_json_field(property_obj, "properties");
    if (properties && json_object_get_type(properties) == json_type_object) {
        bool added_any = false;
        json_object_object_foreach(properties, nested_name, nested_obj)
        {
            added_any |= process_schema_property(nested_obj, nested_name, desc, current_path);
        }
        return added_any;
    }

    return false;
}

config_descriptor json_descriptor_provider::load_descriptors()
{
    // Parse embedded schema JSON
    const char *schema_str = reinterpret_cast<const char *>(m_json_string);
    json_object *schema = json_tokener_parse(schema_str);
    if (!schema) {
        throw_xlio_exception("json_descriptor_provider: Failed to parse embedded JSON schema.");
    }

    // Ensure it's a proper schema
    validate_schema(schema);

    try {
        config_descriptor result_desc;

        // Get the top-level properties object
        json_object *properties = get_json_field(schema, "properties");
        if (!properties) {
            throw_xlio_exception("json_descriptor_provider: Schema missing 'properties' object.");
        }

        // Process each top-level section (core, xlio, net)
        json_object_object_foreach(properties, section_name, section_obj)
        {
            process_schema_property(section_obj, section_name, result_desc);
        }

        json_object_put(schema);
        return result_desc;
    } catch (...) {
        json_object_put(schema);
        throw;
    }
}
