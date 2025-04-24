/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include "parameter_descriptor.h"
#include <map>

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

private:
    /**
     * @brief Map from parameter name to its descriptor
     */
    std::map<std::string, parameter_descriptor> parameter_map;
};
