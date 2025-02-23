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
#include "descriptor_provider.h"

struct json_object;

class json_descriptor_provider : public descriptor_provider {
public:
    explicit json_descriptor_provider();
    explicit json_descriptor_provider(const char *json_string);

    ~json_descriptor_provider() override = default;

    config_descriptor load_descriptors() override;

private:
    const char *m_json_string;
    // Attempt to parse the object at val as a parameter if it has "type"
    // Return true if we recognized this object as a parameter and added it to `desc`, else false.
    bool try_add_parameter(json_object *obj, const std::string &full_key, config_descriptor &desc);

    // Utility to determine the type (int, bool, string) from a JSON string
    std::type_index compute_type_index(const std::string &type_str) const;

    // Parse the "constraints" object, adding min, max, or other constraints to pd
    void parse_constraints(json_object *constraints_obj, parameter_descriptor &pd,
                           const std::type_index &ti);
};
