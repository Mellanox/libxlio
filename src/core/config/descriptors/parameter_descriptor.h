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

#pragma once

#include <string>
#include <map>
#include <typeindex>
#include <vector>
#include <stdexcept>
#include <experimental/any>
#include <functional>
#include <memory>

class parameter_descriptor {
public:
    explicit parameter_descriptor() = default;
    explicit parameter_descriptor(const std::experimental::any &def, std::type_index type);
    parameter_descriptor(parameter_descriptor &&pd) noexcept;
    parameter_descriptor(const parameter_descriptor &pd);

    void add_string_mapping(const std::string &str, const std::experimental::any &val);

    // Validates the given value against:
    //    1) type_index check
    //    2) all constraints
    bool validate(const std::experimental::any &val) const;

    std::experimental::any default_value() const;

    using constraint_t = std::function<bool(const std::experimental::any &)>;
    void add_constraint(constraint_t c);

    // Clear all constraints
    void clear_constraints();

    std::experimental::any get_value(const std::experimental::any &val) const;

private:
    std::experimental::any m_default_value;

    // The expected C++ type (e.g. typeid(int), typeid(bool), etc.).
    // a ptr so parameter_descriptor can be default-constructed to be in a container.
    std::unique_ptr<std::type_index> m_expected_type;

    // Example naive constraints container:
    // (In a real system, these could be pointers to constraint objects
    //  or std::function<bool(const std::experimental::any&)>, etc.)
    std::vector<constraint_t> m_constraints;

    // Map of string values to their corresponding values. useful for enums.
    std::map<std::string, std::experimental::any> m_string_mapping;
};