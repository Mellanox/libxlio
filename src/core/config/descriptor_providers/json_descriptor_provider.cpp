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

#include "json_descriptor_provider.h"
#include "../utils/json_parsing.h"
#include <json-c/json.h>
#include <queue>
#include <iostream>
#include "core/util/xlio_exception.h"

#ifndef JSON_DESCRIPTOR_H
#define JSON_DESCRIPTOR_H
#include "json_descriptor.h"
#endif

extern unsigned char config_descriptor_providers_json_descriptor_json[];

static std::experimental::any convert_json_value_to_any(json_object *val,
                                                        const std::type_index &ti);

json_descriptor_provider::json_descriptor_provider()
    : json_descriptor_provider(
          reinterpret_cast<const char *>(config_descriptor_providers_json_descriptor_json))
{
}

json_descriptor_provider::json_descriptor_provider(const char *json_string)
    : m_json_string(json_string ? json_string : throw_xlio_exception("json_string"))
{
}

config_descriptor json_descriptor_provider::load_descriptors()
{
    json_object *root = json_tokener_parse(m_json_string);
    if (!root) {
        throw_xlio_exception("json_descriptor_provider: failed to parse JSON string.");
    }
    if (json_object_get_type(root) != json_type_object) {
        json_object_put(root);
        throw_xlio_exception("json_descriptor_provider: top-level JSON not an object.");
    }

    try {
        config_descriptor result_desc;
        flatten_json(
            root,
            [&](json_object *obj, const std::string &new_prefix) {
                return !try_add_parameter(obj, new_prefix, result_desc);
            },
            [](json_object *, const std::string &) {
                throw_xlio_exception("json_descriptor_provider: Invalid descriptor.");
            });
        return result_desc;
    } catch (...) {
        json_object_put(root);
        throw;
    }

    json_object_put(root);
}

bool json_descriptor_provider::try_add_parameter(json_object *obj, const std::string &full_key,
                                                 config_descriptor &desc)
{
    // If there's no "type" property, this isn't a parameter descriptor. keep exploring
    json_object *type_field = nullptr;
    if (!json_object_object_get_ex(obj, "type", &type_field)) {
        return false;
    }

    // Must be a string to interpret
    if (json_object_get_type(type_field) != json_type_string) {
        throw_xlio_exception("json_descriptor_provider: type is not a string.");
    }

    // It's a parameter descriptor.
    std::string type_str = json_object_get_string(type_field);
    std::type_index ti = compute_type_index(type_str);

    // "default"
    json_object *default_field = nullptr;
    if (!json_object_object_get_ex(obj, "default", &default_field)) {
        throw_xlio_exception("json_descriptor_provider: parameter has no default.");
    }

    // "description"
    json_object *desc_field = nullptr;
    if (!json_object_object_get_ex(obj, "description", &desc_field)) {
        throw_xlio_exception("json_descriptor_provider: parameter has no description.");
    }

    if (json_object_get_type(desc_field) != json_type_string) {
        throw_xlio_exception("json_descriptor_provider: parameter has no description.");
    }

    parameter_descriptor pd(convert_json_value_to_any(default_field, ti), ti);

    // "constraints"
    json_object *constraints_obj = nullptr;
    if (json_object_object_get_ex(obj, "constraints", &constraints_obj)) {
        if (json_object_get_type(constraints_obj) == json_type_object) {
            parse_constraints(constraints_obj, pd, ti);
        }
    }

    desc.set_parameter(full_key, std::move(pd));
    return true;
}

std::type_index json_descriptor_provider::compute_type_index(const std::string &type_str) const
{
    if (type_str == "int") {
        return typeid(int64_t);
    } else if (type_str == "bool") {
        return typeid(bool);
    } else if (type_str == "string") {
        return typeid(std::string);
    }

    throw_xlio_exception("json_descriptor_provider: unexpected type.");
}

std::experimental::any convert_json_value_to_any(json_object *val, const std::type_index &ti)
{
    json_type t = json_object_get_type(val);
    if (ti == typeid(int64_t)) {
        // If actual JSON is int, read it
        if (t == json_type_int) {
            return json_object_get_int64(val);
        }
        throw_xlio_exception("json_descriptor_provider: type is int but value is not an int.");
    } else if (ti == typeid(bool)) {
        // If actual JSON is bool, read it
        if (t == json_type_boolean) {
            return static_cast<bool>(json_object_get_boolean(val));
        }
        throw_xlio_exception("json_descriptor_provider: type is bool but value is not a bool.");
    } else if (ti == typeid(std::string)) {
        // Convert anything to string by calling json_object_get_string if possible
        const char *str = json_object_get_string(val);
        if (str) {
            return std::string(str);
        }
        throw_xlio_exception("json_descriptor_provider: type is string but value is not a string.");
    }

    throw_xlio_exception("json_descriptor_provider: unexpected type.");
}

void json_descriptor_provider::parse_constraints(json_object *constraints_obj,
                                                 parameter_descriptor &pd,
                                                 const std::type_index &ti)
{
    // "min"
    json_object *min_constraint = nullptr;
    if (json_object_object_get_ex(constraints_obj, "min", &min_constraint)) {
        if (json_object_get_type(min_constraint) == json_type_int && ti == typeid(int64_t)) {
            int min_val = json_object_get_int64(min_constraint);
            pd.add_constraint([=](const std::experimental::any &val) {
                return std::experimental::any_cast<int64_t>(val) >= min_val;
            });
        }
    }

    // "max"
    json_object *max_constraint = nullptr;
    if (json_object_object_get_ex(constraints_obj, "max", &max_constraint)) {
        if (json_object_get_type(max_constraint) == json_type_int && ti == typeid(int64_t)) {
            int max_val = json_object_get_int64(max_constraint);
            pd.add_constraint([=](const std::experimental::any &val) {
                return std::experimental::any_cast<int64_t>(val) <= max_val;
            });
        }
    }
}
