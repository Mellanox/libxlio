/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "runtime_registry.h"

#include "vlogger/vlogger.h"

runtime_registry::runtime_registry()
{
}

void runtime_registry::register_char_array_and_set_default_value(
    char *char_p, size_t size, const config_var_info_t<std::string> &key)
{
    register_pointer_and_check_duplicates(key.name, char_p);
    memset(char_p, 0, size);
    m_runtime_values[key.name] = runtime_entry_t {
        std::make_unique<runtime_char_array_t>(char_p, size, false), change_reason::NotChanged};
    m_runtime_values[key.name].value_adapter->set_default_value_from_config_registry(
        m_config_registry, key.name);
}

void runtime_registry::register_char_array_and_set_explicit_value(
    char *char_p, size_t size, const config_var_info_t<std::string> &key, const std::string &value)
{
    register_pointer_and_check_duplicates(key.name, char_p);
    memset(char_p, 0, size);
    m_runtime_values[key.name] = runtime_entry_t {
        std::make_unique<runtime_char_array_t>(char_p, size, true), change_reason::NotChanged};
    strncpy(char_p, value.c_str(), size - 1);
}

void runtime_registry::set_value_if_exists(const std::string &key)
{
    auto it = m_runtime_values.find(key);
    if (it == m_runtime_values.end()) {
        throw_xlio_exception("Key " + key + " not registered into runtime registry");
    }
    auto &value_adapter = it->second.value_adapter;
    std::string old_value = value_adapter->get_value_as_string();
    if (value_adapter->set_value_from_config_registry_if_exists(m_config_registry, key)) {
        std::string new_value = value_adapter->get_value_as_string();
        if (old_value != new_value) {
            auto reason = change_reason::ConfigurationFile;
            vlog_printf(VLOG_INFO, "Config key %s changed from %s to %s: reason=%s\n", key.c_str(),
                        old_value.c_str(), new_value.c_str(), change_reason::to_string(reason));
            it->second.last_change_reason = reason;
        }
    }
}

void runtime_registry::set_all_configured_values()
{
    for (auto it = m_runtime_values.begin(); it != m_runtime_values.end(); ++it) {
        const std::string &key = it->first;
        auto &value_adapter = it->second.value_adapter;
        std::string old_value = value_adapter->get_value_as_string();
        if (value_adapter->set_value_from_config_registry_if_exists(m_config_registry, key)) {
            std::string new_value = value_adapter->get_value_as_string();
            if (old_value != new_value) {
                auto reason = change_reason::ConfigurationFile;
                vlog_printf(VLOG_INFO, "Config key %s changed from %s to %s: reason=%s\n",
                            key.c_str(), old_value.c_str(), new_value.c_str(),
                            change_reason::to_string(reason));
                it->second.last_change_reason = reason;
            }
        }
    }
}

std::experimental::any runtime_registry::get_value_as_any(const std::string &key) const
{
    auto it = m_runtime_values.find(key);
    if (it == m_runtime_values.end()) {
        throw_xlio_exception("Key " + key + " not registered into runtime registry");
    }
    return it->second.value_adapter->get_value_as_any();
}

void runtime_registry::set_value_from_any(const std::string &key,
                                          const std::experimental::any &value,
                                          change_reason::change_reason_t reason,
                                          const std::string &description)
{
    auto it = m_runtime_values.find(key);
    if (it == m_runtime_values.end()) {
        throw_xlio_exception("Key " + key + " not registered into runtime registry");
    }
    std::string old_value = it->second.value_adapter->get_value_as_string();
    it->second.value_adapter->set_value_from_any(value);
    std::string new_value = it->second.value_adapter->get_value_as_string();
    if (old_value != new_value) {
        vlog_printf(VLOG_INFO, "Config key %s changed from %s to %s: reason=%s; %s\n", key.c_str(),
                    old_value.c_str(), new_value.c_str(), change_reason::to_string(reason),
                    description.c_str());
        it->second.last_change_reason = reason;
    }
}

change_reason::change_reason_t runtime_registry::get_last_change_reason(
    const std::string &key) const
{
    auto it = m_runtime_values.find(key);
    if (it == m_runtime_values.end()) {
        throw_xlio_exception("Key " + key + " not registered into runtime registry");
    }
    return it->second.last_change_reason;
}

bool runtime_registry::is_registered(const std::string &key) const
{
    return m_runtime_values.find(key) != m_runtime_values.end();
}

void runtime_registry::register_pointer_and_check_duplicates(const std::string &key,
                                                             void *runtime_pointer)
{
    if (m_runtime_values.find(key) != m_runtime_values.end()) {
        throw_xlio_exception("Key already exists in runtime registry: " + key);
    }
    auto all_pointers_it = m_all_pointers.find(runtime_pointer);
    if (all_pointers_it != m_all_pointers.end()) {
        throw_xlio_exception("Pointer for " + key +
                             " already exists in runtime registry, registered under key: " +
                             all_pointers_it->second);
    }
    m_all_pointers[runtime_pointer] = key;
}

// runtime_char_array_t functions
//================================

void runtime_registry::runtime_char_array_t::set_default_value_from_config_registry(
    config_registry &config_registry, const std::string &key)
{
    set_value(config_registry.get_default_value<std::string>(key));
}

bool runtime_registry::runtime_char_array_t::set_value_from_config_registry_if_exists(
    config_registry &config_registry, const std::string &key)
{
    if (m_explicitly_set) {
        return false;
    }
    if (config_registry.value_exists(key)) {
        set_value(config_registry.get_value<std::string>(key));
        return true;
    }
    return false;
}

void runtime_registry::runtime_char_array_t::set_value_from_any(const std::experimental::any &value)
{
    set_value(std::experimental::any_cast<std::string>(value));
}

void runtime_registry::runtime_char_array_t::set_value(const std::string &value)
{
    strncpy(m_ptr, value.c_str(), m_size - 1);
}

std::experimental::any runtime_registry::runtime_char_array_t::get_value_as_any() const
{
    return std::experimental::any(std::string(m_ptr));
}

std::string runtime_registry::runtime_char_array_t::get_value_as_string() const
{
    return std::string(m_ptr);
}
