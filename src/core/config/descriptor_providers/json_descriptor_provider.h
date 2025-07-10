/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once
#include "descriptor_provider.h"
#include "schema_analyzer.h"
#include <memory>
#include <string>

struct json_object;

/**
 * @brief Provides parameter descriptors from JSON schema
 *
 * Loads and parses JSON schema to extract parameter descriptors,
 * including types, default values, and validation constraints.
 */
class json_descriptor_provider : public descriptor_provider {
public:
    /**
     * @brief Default constructor using embedded schema
     */
    explicit json_descriptor_provider();

    /**
     * @brief Constructor with custom JSON schema
     * @param json_string JSON schema as a string
     */
    explicit json_descriptor_provider(const char *json_string);

    /**
     * @brief Virtual destructor
     */
    ~json_descriptor_provider() override = default;

    /**
     * @brief Loads parameter descriptors from JSON schema
     * @return Configuration descriptor containing all parameter descriptors
     */
    config_descriptor load_descriptors() override;

    /**
     * @brief Creates a parameter descriptor from a JSON property
     * @param property_obj JSON property object
     * @param path Configuration path for the property
     * @return Parameter descriptor, or nullptr if not applicable
     */
    static std::unique_ptr<parameter_descriptor> create_descriptor(
        const schema_analyzer::analysis_result &analysis);

private:
    const char *m_json_string; /**< JSON schema string */

    /**
     * @brief Validates schema structure and format
     * @param schema Parsed JSON schema object
     * @throws xlio_exception If schema is invalid
     */
    void validate_schema(json_object *schema);

    /**
     * @brief Validates that terminal properties have required fields
     * @param property_obj JSON property object
     * @param current_path Current property path for error reporting
     * @throws xlio_exception If required fields are missing
     */
    void validate_terminal_property(json_object *property_obj, const std::string &current_path);

    /**
     * @brief Processes a schema property
     * @param property_obj JSON property object
     * @param property_name Property name
     * @param desc Configuration descriptor to populate
     * @param path_prefix Path prefix for nested properties
     */
    void process_schema_property(json_object *property_obj, const std::string &property_name,
                                 config_descriptor &desc, const std::string &path_prefix = "");

    // Helper methods for component application
    static void apply_constraints(parameter_descriptor *descriptor,
                                  const constraint_config &config);

    /**
     * @brief Applies value transformation to a parameter descriptor
     * @param descriptor Parameter descriptor to apply transformation to
     * @note This method is used to apply only x-memory-size transformation to a parameter
     * descriptor.
     */
    static void apply_value_transformation(parameter_descriptor *descriptor);

    static void apply_enum_mapping(parameter_descriptor *descriptor,
                                   const enum_mapping_config &config);

    /**
     * @brief Processes an object property (nested object)
     * @param property_obj JSON property object
     * @param current_path Current property path
     * @param desc Configuration descriptor to populate
     * @return True if processing succeeded
     */
    bool process_object_property(json_object *property_obj, const std::string &current_path,
                                 config_descriptor &desc);

    /**
     * @brief Processes an array property
     * @param property_obj JSON property object
     * @param current_path Current property path
     * @param desc Configuration descriptor to populate
     * @return True if processing succeeded
     */
    bool process_array_property(json_object *property_obj, const std::string &current_path,
                                config_descriptor &desc);

    /**
     * @brief Adds constraints to a parameter descriptor
     * @param property_obj JSON property object containing constraints
     * @param current_path Current property path
     * @param param_desc Parameter descriptor to add constraints to
     */
    void add_property_constraints(json_object *property_obj, const std::string &current_path,
                                  parameter_descriptor &param_desc);
};
