/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include <experimental/any>
#include <functional>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <typeindex>
#include <vector>

class parameter_descriptor {
public:
    explicit parameter_descriptor() = default;
    explicit parameter_descriptor(const std::experimental::any &def);

    parameter_descriptor(parameter_descriptor &&pd) noexcept = default;

    // non-trivial copy constructor
    parameter_descriptor(const parameter_descriptor &pd);

    void add_string_mapping(const std::string &str, const std::experimental::any &val);

    bool validate_constraints(const std::experimental::any &val) const;

    std::experimental::any default_value() const;

    using constraint_t = std::function<bool(const std::experimental::any &)>;
    void add_constraint(constraint_t constraint);

    std::experimental::any get_value(const std::experimental::any &val) const;

private:
    std::experimental::any m_default_value;
    std::vector<constraint_t> m_constraints;
    std::map<std::string, std::experimental::any> m_string_mapping;
};