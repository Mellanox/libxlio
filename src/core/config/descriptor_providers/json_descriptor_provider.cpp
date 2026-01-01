/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "json_descriptor_provider.h"
#include "core/config/config_strings.h"
#include "core/config/json_object_handle.h"
#include "core/config/json_utils.h"
#include "core/util/xlio_exception.h"
#include "schema_analyzer.h"
#include <json-c/json.h>
#include <vector>
#include <fstream>
#include <iostream>
#include <map>
#include <experimental/any>
#include <sstream>

#include "xlio_config_schema.h"

// Reference to the embedded JSON schema data that's compiled into the binary
extern unsigned char config_descriptor_providers_xlio_config_schema_json[];

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

config_descriptor json_descriptor_provider::load_descriptors()
{
    json_object_handle schema_handle(json_tokener_parse(m_json_string));
    if (!schema_handle.get()) {
        throw_xlio_exception("Failed to parse JSON schema.");
    }

    validate_schema(schema_handle.get());

    config_descriptor result_desc;

    json_object *properties =
        json_utils::get_field(schema_handle.get(), config_strings::schema::JSON_PROPERTIES);

    json_object_object_foreach(properties, key, val)
    {
        process_schema_property(val, key, result_desc);
    }

    return result_desc;
}

void json_descriptor_provider::validate_schema(json_object *schema)
{
    if (json_object_get_type(schema) != json_type_object) {
        throw_xlio_exception("Schema root must be an object.");
    }

    json_object *properties =
        json_utils::get_field(schema, config_strings::schema::JSON_PROPERTIES);

    json_object_object_foreach(properties, key, val)
    {
        if (json_object_get_type(val) != json_type_object) {
            throw_xlio_exception("Property '" + std::string(key) + "' must be an object.");
        }
    }

    json_object *type_field = json_utils::get_field(schema, config_strings::schema::JSON_TYPE);
    if (type_field) {
        const char *type_str = json_object_get_string(type_field);
        if (type_str && std::string(type_str) != config_strings::schema_types::JSON_TYPE_OBJECT) {
            throw_xlio_exception("Schema root must have type 'object'.");
        }
    } else {
        throw_xlio_exception("Type field not found in schema");
    }
}

void json_descriptor_provider::validate_terminal_property(json_object *property_obj,
                                                          const std::string &current_path)
{
    // Basic validation for terminal properties
    if (!property_obj || json_object_get_type(property_obj) != json_type_object) {
        throw_xlio_exception("Invalid property object for: " + current_path);
    }

    // Check for required description field
    json_object *description_field =
        json_utils::get_field(property_obj, config_strings::schema::JSON_DESCRIPTION);

    if (json_object_get_type(description_field) != json_type_string) {
        throw_xlio_exception("Invalid 'description' field type for terminal property: " +
                             current_path);
    }
}

void json_descriptor_provider::process_schema_property(json_object *property_obj,
                                                       const std::string &property_name,
                                                       config_descriptor &desc,
                                                       const std::string &path_prefix)
{
    std::string current_path = path_prefix.empty()
        ? property_name
        : path_prefix + config_strings::misc::DOT + property_name;

    try {
        if (!schema_analyzer::is_applicable(property_obj)) {
            return;
        }

        schema_analyzer::analysis_result analysis =
            schema_analyzer::analyze(property_obj, current_path);

        // For object properties, recursively process nested properties
        if (analysis.json_property_type == property_type::OBJECT) {
            json_object *properties =
                json_utils::try_get_field(property_obj, config_strings::schema::JSON_PROPERTIES);
            if (properties && json_object_get_type(properties) == json_type_object) {
                json_object_object_foreach(properties, key, val)
                {
                    process_schema_property(val, key, desc, current_path);
                }
            }
        }

        // For terminal properties, create descriptor and add to config
        auto descriptor = create_descriptor(analysis);
        if (descriptor) {
            // Only validate terminal properties that will get descriptors
            validate_terminal_property(property_obj, current_path);
            desc.set_parameter(current_path, std::move(*descriptor));
        }
    } catch (const xlio_exception &e) {
        throw_xlio_exception("Failed to process schema property '" + current_path +
                             "': " + e.what());
    }
}

std::unique_ptr<parameter_descriptor> json_descriptor_provider::create_descriptor(
    const schema_analyzer::analysis_result &analysis)
{
    // Object types are containers, not direct configuration values
    // They should not have parameter descriptors - only their nested properties should
    if (analysis.json_property_type == property_type::OBJECT) {
        return nullptr;
    }

    // Create parameter descriptor with default value
    auto descriptor = std::make_unique<parameter_descriptor>(*analysis.default_value);

    descriptor->set_title(analysis.title);

    // Apply constraints if present
    if (analysis.needs_constraint_validation()) {
        apply_constraints(descriptor.get(), analysis.constraint_cfg);
    }

    // Apply value transformation if needed
    if (analysis.needs_value_transformation()) {
        apply_value_transformation(descriptor.get());
    }

    // Apply enum mapping if needed
    if (analysis.needs_enum_mapping()) {
        apply_enum_mapping(descriptor.get(), analysis.enum_cfg);
    }

    return descriptor;
}

void json_descriptor_provider::apply_constraints(parameter_descriptor *descriptor,
                                                 const constraint_config &config)
{
    if (config.has_minimum) {
        descriptor->add_constraint([min_val = config.minimum_value](
                                       const std::experimental::any &val) -> constraint_result {
            if (val.type() == typeid(int64_t)) {
                int64_t int_val = std::experimental::any_cast<int64_t>(val);
                if (int_val < min_val) {
                    return constraint_result(false,
                                             "Value " + std::to_string(int_val) +
                                                 " is less than minimum " +
                                                 std::to_string(min_val));
                }
            }
            return constraint_result(true);
        });
    }

    if (config.has_maximum) {
        descriptor->add_constraint([max_val = config.maximum_value](
                                       const std::experimental::any &val) -> constraint_result {
            if (val.type() == typeid(int64_t)) {
                int64_t int_val = std::experimental::any_cast<int64_t>(val);
                if (int_val > max_val) {
                    return constraint_result(false,
                                             "Value " + std::to_string(int_val) +
                                                 " is greater than maximum " +
                                                 std::to_string(max_val));
                }
            }
            return constraint_result(true);
        });
    }

    if (config.has_enum) {
        descriptor->add_constraint([enum_values = config.enum_int_values](
                                       const std::experimental::any &val) -> constraint_result {
            if (val.type() == typeid(int64_t)) {
                int64_t int_val = std::experimental::any_cast<int64_t>(val);
                for (int64_t enum_val : enum_values) {
                    if (int_val == enum_val) {
                        return constraint_result(true);
                    }
                }
                return constraint_result(
                    false, "Value " + std::to_string(int_val) + " is not in allowed enum values");
            }
            return constraint_result(true);
        });
    }

    // Apply power-of-2-or-zero constraint if enabled
    if (config.has_power_of_2_or_zero) {
        descriptor->add_constraint(parameter_descriptor::create_power_of_2_or_zero_constraint());
    }
}

void json_descriptor_provider::apply_value_transformation(parameter_descriptor *descriptor)
{
    descriptor->set_value_transformer(parameter_descriptor::create_memory_size_transformer());
}

void json_descriptor_provider::apply_enum_mapping(parameter_descriptor *descriptor,
                                                  const enum_mapping_config_t &config)
{
    if (static_cast<bool>(config) && config->size() > 0) {
        descriptor->set_string_mappings(*config);
    }
}
