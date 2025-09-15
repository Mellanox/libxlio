/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include <experimental/any>
#include <experimental/optional>
#include <json-c/json.h>
#include <string>
#include <typeindex>
#include <vector>

/**
 * @brief Property type classification for JSON schema properties
 */
enum class property_type {
    SIMPLE, /**< Basic property (boolean, integer, string without special handling) */
    EXTENDED, /**< Simple property with memory size flag or other extensions */
    ONE_OF, /**< Property with oneOf field for string/integer enum mapping */
    OBJECT, /**< Nested object property with properties field */
    ARRAY, /**< Array property type */
    UNKNOWN /**< Property type could not be determined */
};

/**
 * @brief Configuration for memory size transformation
 */
struct memory_size_extension_config {
    bool enabled = false;
    std::string pattern;
};

/**
 * @brief Configuration for constraint validation
 */
struct constraint_config {
    bool has_minimum = false;
    bool has_maximum = false;
    bool has_enum = false;
    bool has_power_of_2_or_zero = false;
    int64_t minimum_value = 0;
    int64_t maximum_value = 0;
    std::vector<int64_t> enum_int_values;
};

/**
 * @brief Configuration for enum mapping (oneOf properties)
 */
struct enum_mapping_config {
    bool enabled = false;
    std::vector<int64_t> int_values;
    std::vector<std::string> string_values;
    std::experimental::any default_from_int_option;
};

/**
 * @brief Unified schema analyzer that provides comprehensive analysis of JSON schema properties
 *
 * This analyzer combines property classification, type determination, default value extraction,
 * and component configuration preparation into a single analysis phase, eliminating duplication
 * and providing a single source of truth for schema analysis.
 */
class schema_analyzer {
public:
    /**
     * @brief Comprehensive analysis result containing all information needed for descriptor
     * building
     */
    struct analysis_result {
        // Core property information
        property_type json_property_type =
            property_type::UNKNOWN; /**< Property type for routing decisions */
        std::type_index value_type = typeid(void); /**< C++ type for the parameter value */
        std::experimental::any default_value; /**< Default value ready for use */

        // Component applicability flags
        bool needs_value_transformation = false; /**< Whether value transformation is needed */
        bool needs_constraint_validation = false; /**< Whether constraint validation is needed */
        bool needs_enum_mapping = false; /**< Whether enum mapping is needed */

        // Pre-parsed component configurations
        memory_size_extension_config memory_cfg; /**< Memory size transformation configuration */
        constraint_config constraint_cfg; /**< Constraint validation configuration */
        enum_mapping_config enum_cfg; /**< Enum mapping configuration */
    };

    /**
     * @brief Performs comprehensive analysis of a JSON schema property
     * @param property_obj JSON schema property object to analyze
     * @param path Configuration path for error reporting
     * @return Complete analysis result with all information needed for descriptor building
     */
    static analysis_result analyze(json_object *property_obj, const std::string &path);

    /**
     * @brief Checks if a property can be analyzed by this analyzer
     * @param property_obj JSON schema property object
     * @return True if the property can be analyzed
     */
    static bool is_applicable(json_object *property_obj);

private:
    schema_analyzer(json_object *property_obj, std::string path);

    // Core analysis methods
    property_type determine_property_type();
    std::type_index determine_value_type();
    std::experimental::any determine_default_value(std::type_index type);

    // Component configuration methods
    memory_size_extension_config analyze_memory_size_extension_config();
    constraint_config analyze_constraint_config();
    enum_mapping_config analyze_enum_mapping_config();

    // Helper methods
    bool has_memory_size_flag();
    bool has_power_of_2_or_zero_flag();
    bool has_constraint_fields();
    bool has_oneof_field();
    std::experimental::any extract_oneof_value(json_object *one_of_field, std::type_index type,
                                               const std::string &key);

    json_object *m_property_obj;
    std::string m_path;
};