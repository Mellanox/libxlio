/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once
#include "descriptor_provider.h"
#include <string>

struct json_object;

class json_descriptor_provider : public descriptor_provider {
public:
    explicit json_descriptor_provider();
    explicit json_descriptor_provider(const char *json_string);

    ~json_descriptor_provider() override = default;

    config_descriptor load_descriptors() override;

private:
    const char *m_json_string;

    void validate_schema(json_object *schema);
    bool process_schema_property(json_object *property_obj, const std::string &property_name,
                                 config_descriptor &desc, const std::string &path_prefix = "");
    bool process_one_of_property(json_object *one_of, const std::string &current_path,
                                 config_descriptor &desc);
    bool process_simple_property(json_object *property_obj, const std::string &current_path,
                                 config_descriptor &desc);
    bool process_object_property(json_object *property_obj, const std::string &current_path,
                                 config_descriptor &desc);
    bool process_array_property(json_object *property_obj, const std::string &current_path,
                                config_descriptor &desc);
    void add_property_constraints(json_object *property_obj, parameter_descriptor &desc);
};
