/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "config_registry.h"
#include "config_strings.h"
#include "core/util/xlio_exception.h"
#include "descriptor_providers/json_descriptor_provider.h"
#include "loaders/inline_loader.h"
#include "loaders/json_loader.h"
#include <numeric>
#include <fstream>

static std::string get_user_friendly_type_name(const std::type_index &type)
{
    if (type == typeid(int64_t)) {
        return "integer";
    }
    if (type == typeid(bool)) {
        return "boolean";
    }
    if (type == typeid(std::string)) {
        return "string";
    }
    return "unknown type";
}

static const char *get_config_path()
{
    const char *custom_path = std::getenv(config_strings::env::XLIO_CONFIG_FILE);
    return custom_path ? custom_path : config_strings::paths::DEFAULT_CONFIG_FILE;
}

static std::queue<std::unique_ptr<loader>> create_default_loaders()
{
    std::queue<std::unique_ptr<loader>> loaders;

    const char *inline_env = std::getenv(config_strings::env::XLIO_INLINE_CONFIG);
    if (inline_env) {
        loaders.push(std::make_unique<inline_loader>(config_strings::env::XLIO_INLINE_CONFIG));
    }

    loaders.push(std::make_unique<json_loader>(get_config_path()));

    return loaders;
}

config_registry::config_registry()
    : config_registry(create_default_loaders(), std::make_unique<json_descriptor_provider>())
{
}

config_registry::config_registry(std::queue<std::unique_ptr<loader>> &&value_loaders,
                                 std::unique_ptr<descriptor_provider> descriptor_provider)
{
    initialize_registry(std::move(value_loaders), std::move(descriptor_provider));
}

std::vector<std::string> config_registry::get_sources() const
{
    return m_sources;
}

void config_registry::initialize_registry(std::queue<std::unique_ptr<loader>> &&value_loaders,
                                          std::unique_ptr<descriptor_provider> descriptor_provider)
{
    if (value_loaders.empty() || !descriptor_provider) {
        throw_xlio_exception("loader/descriptor_provider cannot be null");
    }

    m_config_descriptor = descriptor_provider->load_descriptors();

    // Load raw config data - first in queue means higher priority
    while (!value_loaders.empty()) {
        auto &loader = value_loaders.front();
        std::map<std::string, std::experimental::any> loaded_data = loader->load_all();

        // Validate before merging
        for (const auto &kv_pair : loaded_data) {
            const std::string &key = kv_pair.first;
            const std::experimental::any &value = kv_pair.second;
            try {
                const parameter_descriptor param_desc = m_config_descriptor.get_parameter(key);

                // First, get the canonical value. This will resolve string mappings
                // and throw bad_any_cast on a true type mismatch.
                std::experimental::any canonical_value = param_desc.get_value(value);

                // Now, validate constraints on the canonical value.
                param_desc.validate_constraints(canonical_value);

            } catch (const xlio_exception &e) {
                // Check if this is a type mismatch for a parent object
                if (m_config_descriptor.is_parent_of_parameter_keys(key)) {
                    std::type_index expected_type =
                        m_config_descriptor.get_parent_expected_type(key);
                    throw_xlio_exception("In '" + loader->source() + "': Type mismatch for key '" +
                                         key + "': expected " +
                                         get_user_friendly_type_name(expected_type) + ", got " +
                                         get_user_friendly_type_name(value.type()));
                }
                // Otherwise, use the original error message
                throw_xlio_exception("In '" + loader->source() + "': " + e.message);
            } catch (const std::experimental::bad_any_cast &) {
                const parameter_descriptor param_desc = m_config_descriptor.get_parameter(key);
                throw_xlio_exception("In '" + loader->source() + "': Type mismatch for key '" +
                                     key + "': expected " +
                                     get_user_friendly_type_name(param_desc.type()) + ", got " +
                                     get_user_friendly_type_name(value.type()));
            }
        }

        m_config_data.insert(loaded_data.begin(), loaded_data.end());
        m_sources.push_back(loader->source());
        value_loaders.pop();
    }
}

std::experimental::any config_registry::get_value_as_any(const std::string &key) const
{
    const auto it = m_config_data.find(key);

    const parameter_descriptor param = m_config_descriptor.get_parameter(key);

    if (it == m_config_data.end()) {
        return param.default_value();
    }

    return param.get_value(it->second);
}

bool config_registry::value_exists(const std::string &key) const
{
    return m_config_data.find(key) != m_config_data.end();
}

std::experimental::any config_registry::get_default_value_as_any(const std::string &key) const
{
    return m_config_descriptor.get_parameter(key).default_value();
}
