/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include "key_resolver.h"
#include "loader.h"
#include <experimental/any>
#include <map>
#include <string>

/**
 * @brief Loads configuration from environment variables
 *
 * Parses inline configuration data from environment variables,
 * formatted as semicolon-separated key-value pairs. Supports short
 * parameter names that are automatically resolved to full paths.
 *
 * Example: XLIO_INLINE_CONFIG="memory_limit=8GB; daemon.enable=true"
 */
class inline_loader : public loader {
public:
    /**
     * @brief Constructor with environment variable name and config descriptor
     * @param inline_config_key Name of the environment variable containing inline config
     * @param descriptor The config descriptor for key resolution
     */
    inline_loader(const char *inline_config_key, const config_descriptor &descriptor);

    /**
     * @brief Loads all configuration values from the environment variable
     * @return Map of configuration keys to their values
     */
    std::map<std::string, std::experimental::any> load_all() & override;

private:
    /**
     * @brief Parses the inline configuration data
     * Extracts key-value pairs from the environment variable and resolves
     * short names to full paths.
     */
    void parse_inline_data();

private:
    const char *m_inline_config; /**< Raw inline config string */
    key_resolver m_resolver; /**< Resolver for short key names */
};
