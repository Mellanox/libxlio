/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once
#include "descriptor_provider.h"
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

private:
    const char *m_json_string; /**< JSON schema string */

    /**
     * @brief Validates schema structure and format
     * @param schema Parsed JSON schema object
     * @throws xlio_exception If schema is invalid
     */
    void validate_schema(json_object *schema);

    /**
     * @brief Processes a schema property
     * @param property_obj JSON property object
     * @param property_name Property name
     * @param desc Configuration descriptor to populate
     * @param path_prefix Path prefix for nested properties
     * @return True if processing succeeded
     */
    bool process_schema_property(json_object *property_obj, const std::string &property_name,
                                 config_descriptor &desc, const std::string &path_prefix = "");

    /**
     * @brief Processes a oneOf property (alternative types)
     * @param one_of JSON oneOf array
     * @param current_path Current property path
     * @param desc Configuration descriptor to populate
     * @return True if processing succeeded
     */
    bool process_one_of_property(json_object *one_of, const std::string &current_path,
                                 config_descriptor &desc);

    /**
     * @brief Processes a simple property (boolean, integer, string)
     * @param property_obj JSON property object
     * @param current_path Current property path
     * @param desc Configuration descriptor to populate
     * @return True if processing succeeded
     */
    bool process_simple_property(json_object *property_obj, const std::string &current_path,
                                 config_descriptor &desc);

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
     * @param desc Parameter descriptor to add constraints to
     */
    void add_property_constraints(json_object *property_obj, parameter_descriptor &desc);
};
