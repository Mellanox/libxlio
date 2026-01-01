/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "config_strings.h"

namespace config_strings {

namespace env {
const char *XLIO_INLINE_CONFIG = "XLIO_INLINE_CONFIG";
const char *XLIO_CONFIG_FILE = "XLIO_CONFIG_FILE";
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
const char *JSON_PATTERN = "pattern";
} // namespace schema

namespace schema_types {
const char *JSON_TYPE_BOOLEAN = "boolean";
const char *JSON_TYPE_INTEGER = "integer";
const char *JSON_TYPE_STRING = "string";
const char *JSON_TYPE_OBJECT = "object";
const char *JSON_TYPE_ARRAY = "array";
} // namespace schema_types

namespace schema_extensions {
const char *JSON_EXTENSION_MEMORY_SIZE = "x-memory-size";
const char *JSON_EXTENSION_POWER_OF_2_OR_ZERO = "x-power-of-2-or-zero";
} // namespace schema_extensions

// Error messages
namespace errors {
const char *OPEN_PAREN = " (";
const char *CLOSE_PAREN = ")";

} // namespace errors

namespace type_format {
const char *INTEGER_PREFIX = " (integer value: ";
const char *STRING_PREFIX = " (string value: ";
const char *BOOLEAN_PREFIX = " (boolean value: ";
const char *TRUE_VALUE = "true";
const char *FALSE_VALUE = "false";
} // namespace type_format

namespace misc {
const char *JSON_STRING = "json_string";
const char *EMPTY_STRING = "";
const char *DOT = ".";
} // namespace misc

} // namespace config_strings