/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

namespace config_strings {

// Environment variables
namespace env {
extern const char *XLIO_INLINE_CONFIG;
extern const char *XLIO_CUSTOM_CONFIG_FILE;
} // namespace env

// File paths
namespace paths {
extern const char *DEFAULT_CONFIG_FILE;
}

// JSON schema keys/fields
namespace schema {
extern const char *JSON_SCHEMA;
extern const char *JSON_TITLE;
extern const char *JSON_TYPE;
extern const char *JSON_PROPERTIES;
extern const char *JSON_DESCRIPTION;
extern const char *JSON_DEFAULT;
extern const char *JSON_ENUM;
extern const char *JSON_ONE_OF;
extern const char *JSON_MINIMUM;
extern const char *JSON_MAXIMUM;
} // namespace schema

// JSON schema types
namespace schema_types {
extern const char *JSON_TYPE_BOOLEAN;
extern const char *JSON_TYPE_INTEGER;
extern const char *JSON_TYPE_STRING;
extern const char *JSON_TYPE_OBJECT;
extern const char *JSON_TYPE_ARRAY;
} // namespace schema_types

// Error messages
namespace errors {
extern const char *JSON_DESCRIPTOR_PROVIDER_PREFIX;
extern const char *JSON_DESCRIPTOR_PROVIDER_SCHEMA_NOT_OBJECT;
extern const char *JSON_DESCRIPTOR_PROVIDER_MISSING_FIELD;
extern const char *JSON_DESCRIPTOR_PROVIDER_FIELD_SUFFIX;
extern const char *JSON_DESCRIPTOR_PROVIDER_ROOT_TYPE_OBJECT;
extern const char *JSON_DESCRIPTOR_PROVIDER_MISSING_TYPE;
extern const char *JSON_DESCRIPTOR_PROVIDER_UNSUPPORTED_TYPE;
extern const char *JSON_DESCRIPTOR_PROVIDER_NO_DEFAULT;
extern const char *JSON_DESCRIPTOR_PROVIDER_INVALID_BOOLEAN;
extern const char *JSON_DESCRIPTOR_PROVIDER_INVALID_INTEGER;
extern const char *JSON_DESCRIPTOR_PROVIDER_INVALID_STRING;
extern const char *NULL_OBJECT;
extern const char *JSON_DESCRIPTOR_PROVIDER_UNSUPPORTED_TYPE_DEFAULT;
extern const char *JSON_DESCRIPTOR_PROVIDER_UNSUPPORTED_TYPE_FORMAT;
extern const char *JSON_DESCRIPTOR_PROVIDER_NO_PROPERTY_DESCRIPTION;
extern const char *JSON_DESCRIPTOR_PROVIDER_NO_DESCRIPTION_SUFFIX;
extern const char *JSON_DESCRIPTOR_PROVIDER_NO_DEFAULT_VALUE;
extern const char *JSON_DESCRIPTOR_PROVIDER_NO_DEFAULT_VALUE_SUFFIX;
extern const char *JSON_DESCRIPTOR_PROVIDER_DIFFERENT_OPTION_COUNT;
extern const char *JSON_DESCRIPTOR_PROVIDER_DIFFERENT_OPTION_COUNT_SUFFIX;
extern const char *JSON_DESCRIPTOR_PROVIDER_SCHEMA_PARSE_FAILED;
extern const char *JSON_DESCRIPTOR_PROVIDER_MISSING_PROPERTIES;
extern const char *CONFIG_MANAGER_NULL_LOADER;
extern const char *CONFIG_MANAGER_VALIDATION_FAILED;
extern const char *CONFIG_MANAGER_TYPE_MISMATCH;
extern const char *OPEN_PAREN;
extern const char *CLOSE_PAREN;

extern const char *CONFIG_PROVIDER_BAD_ANY_CAST;

// JSON Loader error messages
extern const char *JSON_LOADER_CANNOT_OPEN;
extern const char *JSON_LOADER_PARSE_FAILED;
extern const char *JSON_LOADER_NOT_OBJECT;

// Config descriptor error messages
extern const char *CONFIG_DESCRIPTOR_PARAMETER_NOT_FOUND_PREFIX;
extern const char *CONFIG_DESCRIPTOR_PARAMETER_NOT_FOUND_SUFFIX;

// Inline loader error messages
extern const char *INLINE_LOADER_CONFIG_KEY_NULL;
extern const char *INLINE_LOADER_CONFIG_KEY_NOT_SET;
extern const char *INLINE_LOADER_INVALID_PAIR;
extern const char *INLINE_LOADER_EMPTY_KEY;
extern const char *INLINE_LOADER_INVALID_CONFIG;
} // namespace errors

// Formatted error components
namespace error_format {
extern const char *INTEGER_PREFIX;
extern const char *STRING_PREFIX;
extern const char *BOOLEAN_PREFIX;
extern const char *TRUE_VALUE;
extern const char *FALSE_VALUE;
} // namespace error_format

// Miscellaneous
namespace misc {
extern const char *JSON_STRING;
extern const char *EMPTY_STRING;
extern const char *DOT;
} // namespace misc

} // namespace config_strings