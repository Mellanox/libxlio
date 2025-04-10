/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include "parameter_descriptor.h"
#include <map>

class config_descriptor {
public:
    explicit config_descriptor() = default;
    // Retrieves descriptor by key, throws if not found
    parameter_descriptor get_parameter(const std::string &key) const;
    void set_parameter(const std::string &key, parameter_descriptor &&descriptor);

private:
    // A map from parameter name to its descriptor. available to providers to fill
    std::map<std::string, parameter_descriptor> parameter_map;
};
