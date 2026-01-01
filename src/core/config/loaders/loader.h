/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include <experimental/any>
#include <map>
#include <string>

/**
 * @brief Abstract base class for configuration loaders
 *
 * Interface for loading configuration values from different sources
 * such as environment variables, JSON files, etc.
 */
class loader {
public:
    /**
     * @brief Constructor with source identifier
     * @param source String identifying the configuration source
     */
    loader(const std::string &source)
        : m_source(source)
    {
    }

    /**
     * @brief Virtual destructor
     */
    virtual ~loader() noexcept = default;

    /**
     * @brief Loads all configuration values from the source
     * @return Map of configuration keys to their values
     */
    virtual std::map<std::string, std::experimental::any> load_all() & = 0;

    /**
     * @brief Gets the loader's source identifier
     * @return Source identifier string
     */
    const std::string &source() const { return m_source; }

protected:
    std::map<std::string, std::experimental::any> m_data; /**< Cache of loaded key-value pairs */
    std::string m_source; /**< Source identifier */
};
