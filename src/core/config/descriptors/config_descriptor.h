/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include "parameter_descriptor.h"
#include <map>
#include <set>
#include <string>
#include <typeindex>

/**
 * @brief Collection of parameter descriptors
 *
 * Contains a mapping of parameter names to their descriptors.
 * Used to store metadata about all configuration parameters.
 */
class config_descriptor {
public:
    /**
     * @brief Default constructor
     */
    explicit config_descriptor() = default;

    /**
     * @brief Gets a parameter descriptor by key
     * @param key Parameter name
     * @return Parameter descriptor
     * @throws xlio_exception If parameter not found
     */
    parameter_descriptor get_parameter(const std::string &key) const;

    /**
     * @brief Sets a parameter descriptor
     * @param key Parameter name
     * @param descriptor Descriptor for the parameter
     */
    void set_parameter(const std::string &key, parameter_descriptor &&descriptor);

    /**
     * @brief Checks if a key is a parent of any parameter keys
     * @param key Parameter name to check
     * @return True if key is a parent of parameter keys, false otherwise
     */
    bool is_parent_of_parameter_keys(const std::string &key) const;

    /**
     * @brief Gets the expected type for a parent object key
     * @param key Parent key to get expected type for
     * @return The expected type for the parent object
     * @throws xlio_exception If key is not a parent of parameter keys
     */
    std::type_index get_parent_expected_type(const std::string &key) const;

private:
    /**
     * @brief Map from parameter name to its descriptor
     */
    std::map<std::string, parameter_descriptor> parameter_map;

    /**
     * @brief Set of all parameter keys for efficient prefix-based lookups
     * This allows O(log n) parent-child relationship checks instead of O(n) linear search
     */
    std::set<std::string> parameter_keys;

    /**
     * @brief Updates the parameter keys set when parameters are added
     * @param key The parameter key to add
     */
    void update_parameter_keys(const std::string &key);
};
