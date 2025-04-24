/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include "loader.h"
#include <experimental/any>
#include <map>
#include <string>

/**
 * @brief Loads configuration from environment variables
 *
 * Parses inline configuration data from environment variables,
 * formatted as key-value pairs.
 */
class inline_loader : public loader {
public:
    /**
     * @brief Constructor with environment variable name
     * @param inline_config_key Name of the environment variable containing inline config
     */
    explicit inline_loader(const char *inline_config_key);

    /**
     * @brief Loads all configuration values from the environment variable
     * @return Map of configuration keys to their values
     */
    std::map<std::string, std::experimental::any> load_all() & override;

private:
    /**
     * @brief Parses the inline configuration data
     * Extracts key-value pairs from the environment variable
     */
    void parse_inline_data();

private:
    const char *m_inline_config; /**< Environment variable name */
};