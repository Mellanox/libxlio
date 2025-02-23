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

#include "parameter_descriptor.h"
#include "core/util/xlio_exception.h"

parameter_descriptor::parameter_descriptor(const std::experimental::any &def, std::type_index type)
    : m_default_value(def)
    , m_expected_type(std::make_unique<std::type_index>(type))
{
    if (std::type_index(m_default_value.type()) != type) {
        throw_xlio_exception("Default value type does not match the expected type.");
    }
}

parameter_descriptor::parameter_descriptor(parameter_descriptor &&pd) noexcept
    : m_default_value(std::move(pd.m_default_value))
    , m_expected_type(std::move(pd.m_expected_type))
    , m_constraints(std::move(pd.m_constraints))
{
}

parameter_descriptor::parameter_descriptor(const parameter_descriptor &pd)
    : m_default_value(pd.m_default_value)
    , m_expected_type(std::make_unique<std::type_index>(*pd.m_expected_type))
    , m_constraints(pd.m_constraints)
{
}

std::experimental::any parameter_descriptor::default_value() const
{
    return m_default_value;
}

void parameter_descriptor::add_constraint(constraint_t c)
{
    m_constraints.push_back(std::move(c));
}

// Validates the given value against:
//    1) type_index check
//    2) all constraints
bool parameter_descriptor::validate(const std::experimental::any &val) const
{
    // 1) Check type
    if (*m_expected_type != std::type_index(val.type())) {
        // Type mismatch
        return false;
    }

    // 2) Check constraints
    for (const auto &constraint : m_constraints) {
        if (!constraint(val)) {
            // Constraint violated
            return false;
        }
    }
    return true;
}