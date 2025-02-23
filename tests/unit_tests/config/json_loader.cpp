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

#include <gtest/gtest.h>
#include "loaders/json_loader.h"
#include "xlio_exception.h"
#include "utils.h"

const char *valid_cfg_str = R"({
                    "core": {
                        "log": {
                            "level": 2,
                            "file_path": "/var/log/xlio.log"
                        },
                        "exit_report": true
                    },
                    "net": {
                        "mtu": 1500,
                        "offload": {
                            "enable": true
                        },
                        "tcp": {
                            "mss": 1000
                        }
                    }
                    })";

TEST(config, json_loader_sanity)
{
    conf_file_writer json_config = conf_file_writer(valid_cfg_str);

    json_loader loader(json_config.get());

    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(2, std::experimental::any_cast<int64_t>(data["core.log.level"]));
    ASSERT_EQ("/var/log/xlio.log",
              std::experimental::any_cast<std::string>(data["core.log.file_path"]));
    ASSERT_EQ(true, std::experimental::any_cast<bool>(data["core.exit_report"]));
    ASSERT_EQ(2, std::experimental::any_cast<int64_t>(data["core.log.level"]));
    ASSERT_EQ("/var/log/xlio.log",
              std::experimental::any_cast<std::string>(data["core.log.file_path"]));
    ASSERT_EQ(true, std::experimental::any_cast<bool>(data["core.exit_report"]));
    ASSERT_EQ(1500, std::experimental::any_cast<int64_t>(data["net.mtu"]));
    ASSERT_EQ(true, std::experimental::any_cast<bool>(data["net.offload.enable"]));
    ASSERT_EQ(1000, std::experimental::any_cast<int64_t>(data["net.tcp.mss"]));
}

// missing '}' in the end of the json string
TEST(config, json_loader_invalid_json)
{
    conf_file_writer json_config = conf_file_writer(R"({ "core": { "log": { "level": 2 } } )");

    json_loader loader(json_config.get());
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, json_loader_comments_work)
{
    conf_file_writer json_config = conf_file_writer(R"({ "core": { "log": { "level": 2
    // this is my comment
     } } })");

    json_loader loader(json_config.get());
    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(2, std::experimental::any_cast<int64_t>(data["core.log.level"]));
}

TEST(config, json_loader_load_all_same_data)
{
    conf_file_writer json_config(R"({
        "core": { "log": { "level": 2 } }
    })");

    json_loader loader(json_config.get());

    std::map<std::string, std::experimental::any> data = loader.load_all();
    std::map<std::string, std::experimental::any> data2 = loader.load_all();

    ASSERT_EQ(data.size(), data2.size());
    ASSERT_EQ(std::experimental::any_cast<int64_t>(data["core.log.level"]),
              std::experimental::any_cast<int64_t>(data2["core.log.level"]));
}

TEST(config, json_loader_unsupported_double)
{
    conf_file_writer json_config(R"({
       "core": { "log": { "level": 2.5 } }
    })");
    json_loader loader(json_config.get());
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, json_loader_unsupported_array)
{
    conf_file_writer json_config(R"({
       "core": { "log": { "level": [2] } }
    })");
    json_loader loader(json_config.get());
    ASSERT_THROW(loader.load_all(), xlio_exception);
}

TEST(config, json_loader_flattens_nested_objects)
{
    conf_file_writer json_config(R"({
        "a": {
            "b": {
                "c": 42,
                "d": "hello"
            },
            "e": true
        }
    })");

    json_loader loader(json_config.get());

    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(42, std::experimental::any_cast<int64_t>(data["a.b.c"]));
    ASSERT_EQ("hello", std::experimental::any_cast<std::string>(data["a.b.d"]));
    ASSERT_EQ(true, std::experimental::any_cast<bool>(data["a.e"]));
}

TEST(config, json_loader_file_not_exists)
{
    ASSERT_THROW(json_loader("/tmp/this_file_should_not_exist_123456789.json"), xlio_exception);
}

TEST(config, json_loader_load_huge_int_value)
{
    conf_file_writer json_config(R"({ "core": { "memory": { "limit": 50000000000 } } })");

    json_loader loader(json_config.get());

    std::map<std::string, std::experimental::any> data = loader.load_all();

    ASSERT_EQ(50000000000, std::experimental::any_cast<int64_t>(data["core.memory.limit"]));
}
