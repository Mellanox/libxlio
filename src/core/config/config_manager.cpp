/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-3-Clause
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "config_manager.h"
#include "loaders/inline_loader.h"
#include "loaders/json_loader.h"
#include "descriptor_providers/json_descriptor_provider.h"
#include "core/util/xlio_exception.h"

#include <fstream>

config_manager::config_manager()
{
    std::queue<std::unique_ptr<loader>> loaders;

    const char *inline_env = std::getenv("XLIO_INLINE_CONFIG");
    if (inline_env) {
        loaders.push(std::make_unique<inline_loader>("XLIO_INLINE_CONFIG"));
    }

    const char *custom_path = std::getenv("XLIO_CUSTOM_CONFIG_FILE");
    if (custom_path) {
        loaders.push(std::make_unique<json_loader>(custom_path));
    } else {
        loaders.push(std::make_unique<json_loader>("/etc/libxlio_config.json"));
    }

    initialize_manager(std::move(loaders), std::make_unique<json_descriptor_provider>());
}

config_manager::config_manager(std::queue<std::unique_ptr<loader>> &&value_loaders,
                               std::unique_ptr<descriptor_provider> descriptor_provider)
{
    initialize_manager(std::move(value_loaders), std::move(descriptor_provider));
}

void config_manager::initialize_manager(std::queue<std::unique_ptr<loader>> &&value_loaders,
                                        std::unique_ptr<descriptor_provider> descriptor_provider)
{
    if (value_loaders.empty() || !descriptor_provider) {
        throw_xlio_exception("loader/descriptor_provider cannot be null");
    }

    // 1) Load raw config data - first in queue means higher priority
    std::map<std::string, std::experimental::any> aggregated_config_data;
    while (!value_loaders.empty()) {
        auto loaded_data = value_loaders.front()->load_all();
        aggregated_config_data.insert(loaded_data.begin(), loaded_data.end());
        value_loaders.pop();
    }

    m_config_bundle.m_config_data = std::move(aggregated_config_data);

    // 2) Load or build the descriptor structure
    m_config_bundle.m_config_descriptor = descriptor_provider->load_descriptors();

    // 3) Validate all settings on construction (fail fast if invalid)
    validate_config();
}

// Formats a value for error messages based on its type
static std::string format_value_for_error(const std::experimental::any &value)
{
    if (value.type() == typeid(int64_t)) {
        return " (integer value: " + std::to_string(std::experimental::any_cast<int64_t>(value)) +
            ")";
    } else if (value.type() == typeid(std::string)) {
        return " (string value: " + std::experimental::any_cast<std::string>(value) + ")";
    } else if (value.type() == typeid(bool)) {
        return " (boolean value: " +
            std::string(std::experimental::any_cast<bool>(value) ? "true" : "false") + ")";
    }
    return "";
}

// Validate all config items against their descriptors & constraints.
void config_manager::validate_config() const
{
    // For each key-value in config_data, see if we have descriptor constraints
    for (auto const &kv : m_config_bundle.m_config_data) {
        const auto &key = kv.first;
        const auto &value = kv.second;

        // Retrieve the descriptor (could be empty if not found)
        auto param_desc = m_config_bundle.m_config_descriptor.get_parameter(key);

        try {
            // If there's a specific type required, check constraints
            if (!param_desc.validate(value)) {
                // Validation failed - build appropriate error message
                std::string error_msg =
                    "Validation failed for key: " + key + format_value_for_error(value);
                throw_xlio_exception(error_msg);
            }
        } catch (const std::experimental::bad_any_cast &e) {
            // Type mismatch error
            throw_xlio_exception("Type mismatch for key: " + key + " (" + e.what() + ")");
        }
    }
}
std::experimental::any config_manager::get_value_as_any(const std::string &key) const
{
    // Try to find the key in the loaded data
    const auto it = m_config_bundle.m_config_data.find(key);

    // Get the parameter descriptor once
    const parameter_descriptor param = m_config_bundle.m_config_descriptor.get_parameter(key);

    if (it == m_config_bundle.m_config_data.end()) {
        // Not found in data. Fallback to descriptor's default.
        return param.default_value();
    }

    return param.get_value(it->second);
}