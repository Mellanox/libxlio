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

#include "json_loader.h"
#include "../utils/json_parsing.h"
#include "core/util/xlio_exception.h"
#include <queue>
#include <tuple>
#include <fstream>
#include <typeindex>
#include <json-c/json.h>

static std::experimental::any to_any_value(json_object *obj);
static std::map<std::string, std::experimental::any> flatten_json_to_parameters(json_object *root);

json_loader::json_loader(const char *file_path)
    : m_file_path(file_path)
{
    std::ifstream ifs(m_file_path.c_str());
    if (!ifs.good()) {
        throw_xlio_exception("json_loader: Cannot open file: " + m_file_path);
    }
}

std::map<std::string, std::experimental::any> json_loader::load_all() &
{
    if (!m_data.empty()) {
        return m_data;
    }

    // Parse JSON from file
    json_object *root_obj = json_object_from_file(m_file_path.c_str());
    if (!root_obj) {
        printf("Error: %s\n", json_util_get_last_err());
        throw_xlio_exception("json_loader: Failed to parse JSON file: " + m_file_path);
    }

    // Ensure top-level is an object
    if (json_object_get_type(root_obj) != json_type_object) {
        json_object_put(root_obj); // free resource
        throw_xlio_exception("json_loader: Top-level JSON is not an object: " + m_file_path);
    }

    try {
        m_data = flatten_json_to_parameters(root_obj);
    } catch (...) {
        json_object_put(root_obj);
        throw;
    }

    // Release JSON object memory
    json_object_put(root_obj);
    return m_data;
}

static std::experimental::any to_any_value(json_object *obj)
{
    if (obj == nullptr) {
        throw_xlio_exception("obj can't be nullptr");
    }

    json_type type = json_object_get_type(obj);
    switch (type) {
    case json_type_boolean:
        return bool(json_object_get_boolean(obj));
    case json_type_int:
        return json_object_get_int64(obj);
    case json_type_string: {
        const char *s = json_object_get_string(obj);
        return std::string(s ? s : "");
    }
    // For object/array, we flatten them iteratively, so this is unexpected behavior.
    // For double - is simply not supported in the config.
    default:
        throw_xlio_exception("unsupported/unexpected type " + std::to_string(type));
    }
}

std::map<std::string, std::experimental::any> flatten_json_to_parameters(json_object *root)
{
    std::map<std::string, std::experimental::any> result;
    flatten_json(
        root, [](json_object *, const std::string &) { return true; },
        [&result](json_object *obj, const std::string &current_prefix) {
            result[current_prefix] = to_any_value(obj);
        });

    return result;
}
