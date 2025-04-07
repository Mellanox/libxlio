/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "config_strings.h"

namespace config_strings {

namespace env {
const char *XLIO_INLINE_CONFIG = "XLIO_INLINE_CONFIG";
const char *XLIO_CUSTOM_CONFIG_FILE = "XLIO_CUSTOM_CONFIG_FILE";
} // namespace env

namespace paths {
const char *DEFAULT_CONFIG_FILE = "/etc/libxlio_config.json";
}

namespace schema {
const char *JSON_SCHEMA = "$schema";
const char *JSON_TITLE = "title";
const char *JSON_TYPE = "type";
const char *JSON_PROPERTIES = "properties";
const char *JSON_DESCRIPTION = "description";
const char *JSON_DEFAULT = "default";
const char *JSON_ENUM = "enum";
const char *JSON_ONE_OF = "oneOf";
const char *JSON_MINIMUM = "minimum";
const char *JSON_MAXIMUM = "maximum";
} // namespace schema

namespace schema_types {
const char *JSON_TYPE_BOOLEAN = "boolean";
const char *JSON_TYPE_INTEGER = "integer";
const char *JSON_TYPE_STRING = "string";
const char *JSON_TYPE_OBJECT = "object";
const char *JSON_TYPE_ARRAY = "array";
} // namespace schema_types

// Error messages
namespace errors {
const char *JSON_DESCRIPTOR_PROVIDER_PREFIX = "json_descriptor_provider: ";
const char *JSON_DESCRIPTOR_PROVIDER_SCHEMA_NOT_OBJECT =
    "json_descriptor_provider::validate_schema: Schema is not a JSON object.";
const char *JSON_DESCRIPTOR_PROVIDER_MISSING_FIELD =
    "json_descriptor_provider::validate_schema: Missing or invalid '";
const char *JSON_DESCRIPTOR_PROVIDER_FIELD_SUFFIX = "' field.";
const char *JSON_DESCRIPTOR_PROVIDER_ROOT_TYPE_OBJECT =
    "json_descriptor_provider::validate_schema: Schema root must have type "
    "'object'.";
const char *JSON_DESCRIPTOR_PROVIDER_MISSING_TYPE =
    "json_descriptor_provider::validate_schema: Missing 'type' field.";
const char *JSON_DESCRIPTOR_PROVIDER_UNSUPPORTED_TYPE =
    "json_descriptor_provider::validate_schema: Unsupported type: ";
const char *JSON_DESCRIPTOR_PROVIDER_NO_DEFAULT =
    "json_descriptor_provider::process_default: No default value for "
    "unsupported type.";
const char *JSON_DESCRIPTOR_PROVIDER_INVALID_BOOLEAN =
    "json_descriptor_provider::process_default: Invalid boolean for default "
    "value.";
const char *JSON_DESCRIPTOR_PROVIDER_INVALID_INTEGER =
    "json_descriptor_provider::process_default: Invalid integer for default "
    "value.";
const char *JSON_DESCRIPTOR_PROVIDER_INVALID_STRING =
    "json_descriptor_provider::process_default: Invalid string for default "
    "value.";
const char *NULL_OBJECT = "obj can't be nullptr";
const char *JSON_DESCRIPTOR_PROVIDER_UNSUPPORTED_TYPE_DEFAULT =
    "json_descriptor_provider::process_default: Unsupported type for default "
    "value.";
const char *JSON_DESCRIPTOR_PROVIDER_UNSUPPORTED_TYPE_FORMAT =
    "unsupported/unexpected type ";
const char *JSON_DESCRIPTOR_PROVIDER_NO_PROPERTY_DESCRIPTION =
    "json_descriptor_provider::process_descriptor: Property ";
const char *JSON_DESCRIPTOR_PROVIDER_NO_DESCRIPTION_SUFFIX =
    " has no description.";
const char *JSON_DESCRIPTOR_PROVIDER_NO_DEFAULT_VALUE =
    "json_descriptor_provider::process_descriptor: Property ";
const char *JSON_DESCRIPTOR_PROVIDER_NO_DEFAULT_VALUE_SUFFIX =
    " has no default value.";
const char *JSON_DESCRIPTOR_PROVIDER_DIFFERENT_OPTION_COUNT =
    "json_descriptor_provider::process_descriptor: Property ";
const char *JSON_DESCRIPTOR_PROVIDER_DIFFERENT_OPTION_COUNT_SUFFIX =
    " has different number of integer and string options.";
const char *JSON_DESCRIPTOR_PROVIDER_SCHEMA_PARSE_FAILED =
    "json_descriptor_provider::load_descriptors: Failed to parse embedded JSON "
    "schema.";
const char *JSON_DESCRIPTOR_PROVIDER_MISSING_PROPERTIES =
    "json_descriptor_provider::process_schema: Schema missing 'properties' "
    "object.";
const char *CONFIG_MANAGER_NULL_LOADER =
    "config_manager::initialize_manager: loader/descriptor_provider cannot be "
    "null";
const char *CONFIG_MANAGER_VALIDATION_FAILED =
    "config_manager::validate_config: Validation failed for key: ";
const char *CONFIG_MANAGER_TYPE_MISMATCH =
    "config_manager::validate_config: Type mismatch for key: ";
const char *OPEN_PAREN = " (";
const char *CLOSE_PAREN = ")";

const char *CONFIG_PROVIDER_BAD_ANY_CAST =
    "config_provider::get_value - Bad any_cast for key: ";

const char *JSON_LOADER_CANNOT_OPEN =
    "json_loader::json_loader: Cannot open file: ";
const char *JSON_LOADER_PARSE_FAILED =
    "json_loader::load_all: Failed to parse JSON file: ";
const char *JSON_LOADER_NOT_OBJECT =
    "json_loader::load_all: Top-level JSON is not an object: ";

const char *CONFIG_DESCRIPTOR_PARAMETER_NOT_FOUND_PREFIX =
    "config_descriptor::get_parameter: Parameter descriptor for '";
const char *CONFIG_DESCRIPTOR_PARAMETER_NOT_FOUND_SUFFIX = "' not found";

const char *INLINE_LOADER_CONFIG_KEY_NULL =
    "inline_loader::inline_loader: inline_config_key cannot be null";
const char *INLINE_LOADER_CONFIG_KEY_NOT_SET =
    "inline_loader::inline_loader: inline config key not set: ";
const char *INLINE_LOADER_INVALID_PAIR =
    "inline_loader::parse_inline_data: Invalid key=value pair: ";
const char *INLINE_LOADER_EMPTY_KEY =
    "inline_loader::parse_inline_data: Empty key found in pair: ";
const char *INLINE_LOADER_INVALID_CONFIG =
    "inline_loader::parse_inline_data: Invalid config: ";
} // namespace errors

namespace error_format {
const char *INTEGER_PREFIX = " (integer value: ";
const char *STRING_PREFIX = " (string value: ";
const char *BOOLEAN_PREFIX = " (boolean value: ";
const char *TRUE_VALUE = "true";
const char *FALSE_VALUE = "false";
} // namespace error_format

namespace misc {
const char *JSON_STRING = "json_string";
const char *EMPTY_STRING = "";
const char *DOT = ".";
} // namespace misc

} // namespace config_strings