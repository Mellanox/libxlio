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

#include "json_parsing.h"
#include <queue>
#include "core/util/xlio_exception.h"

void flatten_json(json_object *root,
                  std::function<bool(json_object *, const std::string &)> object_visitor,
                  std::function<void(json_object *, const std::string &)> primitive_object_visitor)
{
    // We’ll store (prefix, pointer to json_object) pairs in a queue.
    // Each iteration processes one pair, potentially adding new ones
    // for object/array elements.
    std::queue<std::pair<std::string, json_object *>> queue;
    queue.push({"", root});

    while (!queue.empty()) {
        auto front = queue.front();
        queue.pop();

        std::string current_prefix = front.first;
        json_object *current_obj = front.second;
        if (!current_obj) {
            continue;
        }

        // Check the type
        json_type type = json_object_get_type(current_obj);
        switch (type) {
        case json_type_object: {
            // For objects, iterate over each key and add to the queue
            json_object_object_foreach(current_obj, key, val)
            {
                // Build new prefix. If empty, just the key; else prefix + "." + key
                const std::string new_prefix =
                    (current_prefix.empty() ? key : (current_prefix + "." + key));
                if (object_visitor(val, new_prefix)) {
                    queue.push({new_prefix, val});
                }
            }
            break;
        }
        case json_type_array: {
            throw_xlio_exception("Arrays in config are not supported.");
            break;
        }
        default:
            primitive_object_visitor(current_obj, current_prefix);
            break;
        }
    }
}
