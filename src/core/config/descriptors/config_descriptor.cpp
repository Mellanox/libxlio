/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "config_descriptor.h"
#include "core/config/config_strings.h"
#include "core/util/xlio_exception.h"

parameter_descriptor config_descriptor::get_parameter(const std::string &key) const
{
    auto it = parameter_map.find(key);
    if (it == parameter_map.end()) {
        throw_xlio_exception("Parameter descriptor for '" + key + "' not found");
    }
    return it->second;
}

void config_descriptor::set_parameter(const std::string &key, parameter_descriptor &&descriptor)
{
    parameter_map.insert({key, std::move(descriptor)});
}