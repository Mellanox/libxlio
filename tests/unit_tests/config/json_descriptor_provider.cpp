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
#include "descriptor_providers/json_descriptor_provider.h"
#include "xlio_exception.h"
#include "utils.h"

TEST(config, json_descriptor_provider_sanity)
{
    json_descriptor_provider provider(R"({
        "core": {
            "append_pid_to_path": {
                "type": "bool",
                "default": false,
                "description": "Append PID to xlio.daemon.dir, core.stats.shmem_dir, core.stats.file_path, core.log.file_path."
            },
            "log": {
                "level": {
                    "type": "int",
                    "default": 3,
                    "constraints": {
                        "min": -2,
                        "max": 8
                    },
                    "description": "Sets level according to desired logging verbosity.",
                }
            }
        }
    })");

    config_descriptor cd = provider.load_descriptors();
    ASSERT_EQ(
        3,
        std::experimental::any_cast<int64_t>(cd.get_parameter("core.log.level").default_value()));
    ASSERT_EQ(false,
              std::experimental::any_cast<bool>(
                  cd.get_parameter("core.append_pid_to_path").default_value()));
}

TEST(config, json_descriptor_provider_invalid_json_throws)
{
    // comma after no more element "max": 8,
    json_descriptor_provider provider(R"({
        "core": {
            "append_pid_to_path": {
                "type": "bool",
                "default": false,
                "description": "Append PID to xlio.daemon.dir, core.stats.shmem_dir, core.stats.file_path, core.log.file_path."
            },
            "log": {
                "level": {
                    "type": "int",
                    "default": 3,
                    "constraints": {
                        "min": -2,
                        "max": 8,
                    }
                }
            }
        }
    })");

    ASSERT_THROW(provider.load_descriptors(), xlio_exception);
}

TEST(config, json_descriptor_provider_no_description_throws)
{
    // core.log.level has no description - should throw
    json_descriptor_provider provider(R"({
        "core": {
            "append_pid_to_path": {
                "type": "bool",
                "default": false,
                "description": "Append PID to xlio.daemon.dir, core.stats.shmem_dir, core.stats.file_path, core.log.file_path."
            },
            "log": {
                "level": {
                    "type": "int",
                    "default": 3,
                    "constraints": {
                        "min": -2,
                        "max": 8
                    }
                }
            }
        }
    })");

    ASSERT_THROW(provider.load_descriptors(), xlio_exception);
}

// finding duplications is not supported OOB in libjson-c
// introducing such logic will complicate the code and not worth it ROI
TEST(config, json_descriptor_provider_duplication_last_is_taken)
{
    json_descriptor_provider provider(R"({
        "core": {
            "append_pid_to_path": {
                "type": "bool",
                "default": false,
                "description": "Append PID to xlio.daemon.dir, core.stats.shmem_dir, core.stats.file_path, core.log.file_path."
            },
            "append_pid_to_path": {
                "type": "bool",
                "default": true,
                "description": "Append PID to xlio.daemon.dir, core.stats.shmem_dir, core.stats.file_path, core.log.file_path."
            },
        }
    })");

    config_descriptor cd = provider.load_descriptors();
    ASSERT_EQ(true,
              std::experimental::any_cast<bool>(
                  cd.get_parameter("core.append_pid_to_path").default_value()));
}

TEST(config, json_descriptor_provider_unrecognized_type_throws)
{
    json_descriptor_provider provider(R"({
        "core": {
            "unknown": {
                "type": "float",
                "default": 1.5,
                "description": "A float value"
            }
        }
    })");
    ASSERT_THROW(provider.load_descriptors(), xlio_exception);
}
