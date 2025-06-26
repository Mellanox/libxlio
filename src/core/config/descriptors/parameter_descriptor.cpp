/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "parameter_descriptor.h"
#include "core/config/config_strings.h"
#include "core/util/xlio_exception.h"

parameter_descriptor::parameter_descriptor()
    : m_type(typeid(void))
{
}

parameter_descriptor::parameter_descriptor(const std::experimental::any &def)
    : m_default_value(def)
    , m_type(def.type())
{
}

parameter_descriptor::parameter_descriptor(const parameter_descriptor &pd)
    : m_default_value(pd.m_default_value)
    , m_constraints(pd.m_constraints)
    , m_string_mapping(pd.m_string_mapping)
    , m_type(pd.m_type)
{
}

void parameter_descriptor::add_string_mapping(const std::string &str,
                                              const std::experimental::any &val)
{
    if (m_string_mapping.find(str) != m_string_mapping.end()) {
        throw_xlio_exception("String mapping already exists for value: " + str);
    }

    m_string_mapping[str] = val;
}

std::experimental::any parameter_descriptor::default_value() const
{
    return m_default_value;
}

void parameter_descriptor::add_constraint(constraint_t constraint)
{
    m_constraints.push_back(std::move(constraint));
}

std::experimental::any parameter_descriptor::get_value(const std::experimental::any &val) const
{
    if (val.type() == typeid(std::string)) {
        auto it = m_string_mapping.find(std::experimental::any_cast<std::string>(val));
        if (it != m_string_mapping.end()) {
            return it->second;
        }
    }

    if (!m_string_mapping.empty() && val.type() != typeid(int64_t) &&
        val.type() != typeid(std::string)) {
        // If there is a string mapping, then the value must be a string or an int as it represents
        // an enum
        throw std::experimental::bad_any_cast();
    }

    return val;
}

void parameter_descriptor::validate_constraints(const std::experimental::any &value) const
{
    for (const auto &constraint : m_constraints) {
        auto result = constraint(value);
        if (!result.first) {
            throw_xlio_exception(result.second);
        }
    }
}

std::type_index parameter_descriptor::type() const
{
    return m_type;
}
