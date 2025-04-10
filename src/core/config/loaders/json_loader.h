/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include "loader.h"
#include <json-c/json.h>
#include <map>
#include <string>

class json_loader : public loader {
public:
    explicit json_loader(const char *json_string);
    std::map<std::string, std::experimental::any> load_all() & override;

private:
    void process_json_object(const std::string &prefix, json_object *obj);

    std::string m_file_path;
};