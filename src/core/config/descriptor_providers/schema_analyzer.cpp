/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "schema_analyzer.h"
#include "core/config/config_strings.h"
#include "core/config/json_utils.h"
#include "core/util/xlio_exception.h"
#include <stdexcept>
#include <functional>

static void for_each_oneof_option(json_object *one_of_field,
                                  std::function<void(json_object *)> func)
{
    int one_of_length = json_object_array_length(one_of_field);
    for (int i = 0; i < one_of_length; i++) {
        json_object *option = json_object_array_get_idx(one_of_field, i);
        func(option);
    }
}

schema_analyzer::analysis_result schema_analyzer::analyze(json_object *property_obj,
                                                          const std::string &path)
{
    if (!property_obj) {
        throw_xlio_exception("Property object cannot be null for: " + path);
    }

    if (!is_applicable(property_obj)) {
        throw_xlio_exception("Property is not applicable for analysis: " + path);
    }

    schema_analyzer analyzer(property_obj, path);

    analysis_result result;

    // Core analysis
    result.json_property_type = analyzer.determine_property_type();
    result.value_type = analyzer.determine_value_type();
    if (result.json_property_type != property_type::OBJECT) {
        result.default_value = analyzer.determine_default_value(result.value_type);
    }

    // Component configuration analysis
    result.memory_cfg = analyzer.analyze_memory_size_extension_config();
    result.constraint_cfg = analyzer.analyze_constraint_config();
    result.enum_cfg = analyzer.analyze_enum_mapping_config();

    // Set component applicability flags
    result.needs_value_transformation = result.memory_cfg.enabled;
    result.needs_constraint_validation = result.constraint_cfg.has_minimum ||
        result.constraint_cfg.has_maximum || result.constraint_cfg.has_enum;
    result.needs_enum_mapping = result.enum_cfg.enabled;
    // coverity[uninit_use_in_call]
    return result;
}

bool schema_analyzer::is_applicable(json_object *property_obj)
{
    if (!property_obj) {
        return false;
    }

    if (json_object_get_type(property_obj) != json_type_object) {
        return false;
    }

    // Can handle any property that has a type field or oneOf field
    json_object *type_field =
        json_utils::try_get_field(property_obj, config_strings::schema::JSON_TYPE);
    json_object *one_of_field =
        json_utils::try_get_field(property_obj, config_strings::schema::JSON_ONE_OF);

    return type_field != nullptr || one_of_field != nullptr;
}

schema_analyzer::schema_analyzer(json_object *property_obj, std::string path)
    : m_property_obj(property_obj)
    , m_path(std::move(path))
{
}

property_type schema_analyzer::determine_property_type()
{
    // Clear hierarchy of classification - order matters for priority
    // Extended properties have highest priority (memory size flag overrides oneOf)
    if (has_memory_size_flag()) {
        return property_type::EXTENDED;
    }

    // OneOf properties need special handling for string/integer enum mapping
    if (has_oneof_field()) {
        return property_type::ONE_OF;
    }

    // Get JSON type for further classification
    json_object *type_field =
        json_utils::get_field(m_property_obj, config_strings::schema::JSON_TYPE);
    std::string json_type_str;
    if (json_object_get_type(type_field) == json_type_string) {
        json_type_str = json_object_get_string(type_field);
    }

    // Object properties with nested properties
    if (json_type_str == config_strings::schema_types::JSON_TYPE_OBJECT) {
        json_object *properties_field =
            json_utils::get_field(m_property_obj, config_strings::schema::JSON_PROPERTIES);
        if (json_object_get_type(properties_field) == json_type_object) {
            return property_type::OBJECT;
        }
    }

    // Array properties
    if (json_type_str == config_strings::schema_types::JSON_TYPE_ARRAY) {
        return property_type::ARRAY;
    }

    // Simple primitive properties
    if (json_type_str == config_strings::schema_types::JSON_TYPE_BOOLEAN ||
        json_type_str == config_strings::schema_types::JSON_TYPE_INTEGER ||
        json_type_str == config_strings::schema_types::JSON_TYPE_STRING) {
        return property_type::SIMPLE;
    }

    // If we can't determine the type, return UNKNOWN
    return property_type::UNKNOWN;
}

std::type_index schema_analyzer::determine_value_type()
{
    // Check for oneOf first (as it can override basic type determination)
    if (has_oneof_field()) {
        // OneOf properties are integer-based (for enum mapping)
        return typeid(int64_t);
    }

    // Standard type determination
    json_object *type_field =
        json_utils::get_field(m_property_obj, config_strings::schema::JSON_TYPE);

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

    throw_xlio_exception("Unsupported type: " + type_str + " for key: " + m_path);
}

std::experimental::any schema_analyzer::determine_default_value(std::type_index type)
{
    // Check for oneOf first - default values are nested inside oneOf options
    json_object *one_of_field =
        json_utils::try_get_field(m_property_obj, config_strings::schema::JSON_ONE_OF);
    if (one_of_field && json_object_get_type(one_of_field) == json_type_array) {
        return extract_oneof_value(one_of_field, type, config_strings::schema::JSON_DEFAULT);
    }

    // Standard default value handling
    json_object *default_field =
        json_utils::get_field(m_property_obj, config_strings::schema::JSON_DEFAULT);

    return json_utils::to_any_value(default_field);
}

memory_size_extension_config schema_analyzer::analyze_memory_size_extension_config()
{
    memory_size_extension_config config;
    config.enabled = has_memory_size_flag();

    if (config.enabled) {
        json_object *one_of_field =
            json_utils::get_field(m_property_obj, config_strings::schema::JSON_ONE_OF);
        config.pattern = std::experimental::any_cast<std::string>(extract_oneof_value(
            one_of_field, typeid(std::string), config_strings::schema::JSON_PATTERN));

        if (config.pattern != "^[0-9]+[KMGkmg]?[B]?$") {
            throw_xlio_exception("Pattern is not supported for: " + m_path);
        }
    }

    return config;
}

static void extract_constraints_from_json(json_object *obj, constraint_config &config)
{
    if (!obj) {
        return;
    }
    json_object *min_field = json_utils::try_get_field(obj, config_strings::schema::JSON_MINIMUM);
    if (min_field && json_object_get_type(min_field) == json_type_int) {
        config.has_minimum = true;
        config.minimum_value = json_object_get_int64(min_field);
    }
    json_object *max_field = json_utils::try_get_field(obj, config_strings::schema::JSON_MAXIMUM);
    if (max_field && json_object_get_type(max_field) == json_type_int) {
        config.has_maximum = true;
        config.maximum_value = json_object_get_int64(max_field);
    }
    json_object *enum_field = json_utils::try_get_field(obj, config_strings::schema::JSON_ENUM);
    if (enum_field && json_object_get_type(enum_field) == json_type_array) {
        config.has_enum = true;
        config.enum_int_values = json_utils::extract_enum_values<int64_t>(enum_field);
    }
}

constraint_config schema_analyzer::analyze_constraint_config()
{
    constraint_config config;

    // Extract direct constraints
    extract_constraints_from_json(m_property_obj, config);

    // For oneOf, also check constraints in the integer option
    if (has_oneof_field()) {
        json_object *one_of_field =
            json_utils::get_field(m_property_obj, config_strings::schema::JSON_ONE_OF);
        for_each_oneof_option(one_of_field, [&](json_object *option) {
            json_object *type_field =
                json_utils::get_field(option, config_strings::schema::JSON_TYPE);
            std::string type_str = json_object_get_string(type_field);
            if (type_str == config_strings::schema_types::JSON_TYPE_INTEGER) {
                extract_constraints_from_json(option, config);
            }
        });
    }

    return config;
}

enum_mapping_config schema_analyzer::analyze_enum_mapping_config()
{
    enum_mapping_config config;

    if (!has_oneof_field()) {
        // coverity[uninit_use_in_call]
        return config;
    }

    // Exclude properties with memory size flag - those should be handled by value_transformer
    if (has_memory_size_flag()) {
        // coverity[uninit_use_in_call]
        return config;
    }

    json_object *one_of_field =
        json_utils::get_field(m_property_obj, config_strings::schema::JSON_ONE_OF);

    json_object *int_option = nullptr;
    json_object *string_option = nullptr;

    // Find integer and string options
    for_each_oneof_option(one_of_field, [&](json_object *option) {
        json_object *type_field = json_utils::get_field(option, config_strings::schema::JSON_TYPE);

        std::string type_str = json_object_get_string(type_field);
        if (type_str == config_strings::schema_types::JSON_TYPE_INTEGER) {
            int_option = option;
            json_object *default_field =
                json_utils::get_field(option, config_strings::schema::JSON_DEFAULT);
            config.default_from_int_option = json_object_get_int64(default_field);
        } else if (type_str == config_strings::schema_types::JSON_TYPE_STRING) {
            string_option = option;
        }
    });

    // Validate that we found both options
    if (!int_option || !string_option) {
        throw_xlio_exception("OneOf field must contain both integer and string options for: " +
                             m_path);
    }

    json_object *int_enum = json_utils::get_field(int_option, config_strings::schema::JSON_ENUM);
    json_object *string_enum =
        json_utils::get_field(string_option, config_strings::schema::JSON_ENUM);

    const std::vector<int64_t> int_values = json_utils::extract_enum_values<int64_t>(int_enum);
    const std::vector<std::string> string_values =
        json_utils::extract_enum_values<std::string>(string_enum);

    if (int_values.empty() || string_values.empty()) {
        throw_xlio_exception("OneOf field must have enum options for: " + m_path);
    }

    if (int_values.size() != string_values.size()) {
        throw_xlio_exception("OneOf field must have equal length of enum options for: " + m_path);
    }

    config.enabled = true;
    config.int_values = int_values;
    config.string_values = string_values;

    return config;
}

bool schema_analyzer::has_memory_size_flag()
{
    json_object *memory_size_flag = json_utils::try_get_field(
        m_property_obj, config_strings::schema_extensions::JSON_EXTENSION_MEMORY_SIZE);
    if (!memory_size_flag) {
        return false;
    }

    return json_object_get_type(memory_size_flag) == json_type_boolean &&
        json_object_get_boolean(memory_size_flag);
}

bool schema_analyzer::has_constraint_fields()
{
    // Check for direct constraints on the property
    bool has_direct_constraints =
        json_utils::try_get_field(m_property_obj, config_strings::schema::JSON_ENUM) != nullptr ||
        json_utils::try_get_field(m_property_obj, config_strings::schema::JSON_MINIMUM) !=
            nullptr ||
        json_utils::try_get_field(m_property_obj, config_strings::schema::JSON_MAXIMUM) != nullptr;

    if (has_direct_constraints) {
        return true;
    }

    // For oneOf properties, also check constraints in the integer option
    if (has_oneof_field()) {
        json_object *one_of_field =
            json_utils::get_field(m_property_obj, config_strings::schema::JSON_ONE_OF);
        int one_of_length = json_object_array_length(one_of_field);
        for (int i = 0; i < one_of_length; i++) {
            json_object *option = json_object_array_get_idx(one_of_field, i);
            json_object *type_field =
                json_utils::get_field(option, config_strings::schema::JSON_TYPE);

            std::string type_str = json_object_get_string(type_field);

            // For integer option, check if it has constraints
            if (type_str == config_strings::schema_types::JSON_TYPE_INTEGER) {
                if (json_utils::try_get_field(option, config_strings::schema::JSON_ENUM) !=
                        nullptr ||
                    json_utils::try_get_field(option, config_strings::schema::JSON_MINIMUM) !=
                        nullptr ||
                    json_utils::try_get_field(option, config_strings::schema::JSON_MAXIMUM) !=
                        nullptr) {
                    return true;
                }
            }
        }
    }

    return false;
}

bool schema_analyzer::has_oneof_field()
{
    json_object *one_of_field =
        json_utils::try_get_field(m_property_obj, config_strings::schema::JSON_ONE_OF);

    if (one_of_field && json_object_get_type(one_of_field) != json_type_array) {
        throw_xlio_exception("OneOf field must be an array for: " + m_path);
    }

    return one_of_field != nullptr;
}

std::experimental::any schema_analyzer::extract_oneof_value(json_object *one_of_field,
                                                            std::type_index type,
                                                            const std::string &key)
{
    int one_of_length = json_object_array_length(one_of_field);
    for (int i = 0; i < one_of_length; i++) {
        json_object *option = json_object_array_get_idx(one_of_field, i);
        json_object *key_field = json_utils::try_get_field(option, key.c_str());

        if (key_field && std::type_index(json_utils::to_any_value(key_field).type()) == type) {
            return json_utils::to_any_value(key_field);
        }
    }

    throw_xlio_exception("No " + key + " value found in oneOf field for: " + m_path);
}
