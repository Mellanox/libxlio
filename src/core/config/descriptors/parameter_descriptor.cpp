/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "parameter_descriptor.h"
#include "core/util/xlio_exception.h"

parameter_descriptor::parameter_descriptor(const std::experimental::any &def)
    : m_default_value(def)
{
}

parameter_descriptor::parameter_descriptor(const parameter_descriptor &pd)
    : m_default_value(pd.m_default_value)
    , m_constraints(pd.m_constraints)
    , m_string_mapping(pd.m_string_mapping)
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

    return val;
}

bool parameter_descriptor::validate_constraints(const std::experimental::any &val) const
{
    for (const constraint_t &constraint : m_constraints) {
        if (!constraint(val)) {
            return false;
        }
    }
    return true;
}