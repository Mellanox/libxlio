/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

/**
 * @brief Common string constants used throughout the configuration subsystem
 */
namespace config_strings {

/**
 * @brief Environment variable names
 */
namespace env {
extern const char *XLIO_INLINE_CONFIG; /**< Environment variable for inline configuration */
extern const char *XLIO_CONFIG_FILE; /**< Environment variable for custom config file path */
} // namespace env

/**
 * @brief File path constants
 */
namespace paths {
extern const char *DEFAULT_CONFIG_FILE; /**< Default configuration file path */
}

/**
 * @brief JSON schema key names
 */
namespace schema {
extern const char *JSON_SCHEMA; /**< Schema identifier key */
extern const char *JSON_TITLE; /**< Title key */
extern const char *JSON_TYPE; /**< Type key */
extern const char *JSON_PROPERTIES; /**< Properties key */
extern const char *JSON_DESCRIPTION; /**< Description key */
extern const char *JSON_DEFAULT; /**< Default value key */
extern const char *JSON_ENUM; /**< Enumeration values key */
extern const char *JSON_ONE_OF; /**< One of values key */
extern const char *JSON_MINIMUM; /**< Minimum value key */
extern const char *JSON_MAXIMUM; /**< Maximum value key */
} // namespace schema

/**
 * @brief JSON schema type names
 */
namespace schema_types {
extern const char *JSON_TYPE_BOOLEAN; /**< Boolean type identifier */
extern const char *JSON_TYPE_INTEGER; /**< Integer type identifier */
extern const char *JSON_TYPE_STRING; /**< String type identifier */
extern const char *JSON_TYPE_OBJECT; /**< Object type identifier */
extern const char *JSON_TYPE_ARRAY; /**< Array type identifier */
} // namespace schema_types

/**
 * @brief Error message components
 */
namespace errors {

// TODO - remove all refs to ERROR_STRING
// use throw_xlio_exception instead

extern const char *OPEN_PAREN; /**< Opening parenthesis for error messages */
extern const char *CLOSE_PAREN; /**< Closing parenthesis for error messages */

} // namespace errors

/**
 * @brief Type formatting components for error messages
 */
namespace type_format {
extern const char *INTEGER_PREFIX; /**< Prefix for integer values in errors */
extern const char *STRING_PREFIX; /**< Prefix for string values in errors */
extern const char *BOOLEAN_PREFIX; /**< Prefix for boolean values in errors */
extern const char *TRUE_VALUE; /**< String representation of true value */
extern const char *FALSE_VALUE; /**< String representation of false value */
} // namespace type_format

/**
 * @brief Miscellaneous string constants
 */
namespace misc {
extern const char *JSON_STRING; /**< JSON string identifier */
extern const char *EMPTY_STRING; /**< Empty string constant */
extern const char *DOT; /**< Dot character */
} // namespace misc

} // namespace config_strings