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

// TODO - remove all refs to ERROR_STRING
// use throw_xlio_exception instead

extern const char *OPEN_PAREN;
extern const char *CLOSE_PAREN;

} // namespace errors

// Formatted error components
namespace type_format {
extern const char *INTEGER_PREFIX;
extern const char *STRING_PREFIX;
extern const char *BOOLEAN_PREFIX;
extern const char *TRUE_VALUE;
extern const char *FALSE_VALUE;
} // namespace type_format

// Miscellaneous
namespace misc {
extern const char *JSON_STRING;
extern const char *EMPTY_STRING;
extern const char *DOT;
} // namespace misc

} // namespace config_strings