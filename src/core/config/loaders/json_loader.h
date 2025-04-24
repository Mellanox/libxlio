/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include "loader.h"
#include <json-c/json.h>
#include <map>
#include <string>

/**
 * @brief Loads configuration from JSON files
 *
 * Parses JSON configuration files and extracts parameter values,
 * handling nested objects with dot notation.
 */
class json_loader : public loader {
public:
    /**
     * @brief Constructor with JSON file path
     * @param file_path Path to the JSON configuration file
     */
    explicit json_loader(const char *file_path);

    /**
     * @brief Loads all configuration values from the JSON file
     * @return Map of configuration keys to their values
     */
    std::map<std::string, std::experimental::any> load_all() & override;

private:
    /**
     * @brief Recursively processes a JSON object
     * @param prefix Key prefix for nested values
     * @param obj JSON object to process
     */
    void process_json_object(const std::string &prefix, json_object *obj);
};