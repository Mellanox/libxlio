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

#include <fstream>

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

    // Load raw config data - first in queue means higher priority
    std::map<std::string, std::experimental::any> aggregated_config_data;
    while (!value_loaders.empty()) {
        std::map<std::string, std::experimental::any> loaded_data =
            value_loaders.front()->load_all();
        aggregated_config_data.insert(loaded_data.begin(), loaded_data.end());
        m_sources.push_back(value_loaders.front()->source());
        value_loaders.pop();
    }

    m_config_data = std::move(aggregated_config_data);

    m_config_descriptor = descriptor_provider->load_descriptors();

    validate_config();
}

static std::string format_value_for_error(const std::experimental::any &value)
{
    if (value.type() == typeid(int64_t)) {
        return config_strings::type_format::INTEGER_PREFIX +
            std::to_string(std::experimental::any_cast<int64_t>(value)) +
            config_strings::errors::CLOSE_PAREN;
    } else if (value.type() == typeid(std::string)) {
        return config_strings::type_format::STRING_PREFIX +
            std::experimental::any_cast<std::string>(value) + config_strings::errors::CLOSE_PAREN;
    } else if (value.type() == typeid(bool)) {
        return config_strings::type_format::BOOLEAN_PREFIX +
            std::string(std::experimental::any_cast<bool>(value)
                            ? config_strings::type_format::TRUE_VALUE
                            : config_strings::type_format::FALSE_VALUE) +
            config_strings::errors::CLOSE_PAREN;
    }
    return config_strings::misc::EMPTY_STRING;
}

void config_registry::validate_config() const
{
    for (auto const &kv_pair : m_config_data) {
        const std::string &key = kv_pair.first;
        const std::experimental::any &value = kv_pair.second;

        const parameter_descriptor param_desc = m_config_descriptor.get_parameter(key);

        try {
            if (!param_desc.validate_constraints(value)) {
                throw_xlio_exception("validation failed: " + key + " - " +
                                     format_value_for_error(value));
            }
        } catch (const std::experimental::bad_any_cast &e) {
            throw_xlio_exception("type mismatch: " + key + " - " + e.what());
        }
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
