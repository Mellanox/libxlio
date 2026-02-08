/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

/**
 * @brief This class holds information about a configuration variable.
 * @tparam RUNTIME_T Type of the runtime value
 * @tparam REGISTRY_T Type of the registry value
 * @param name Name of the configuration variable
 *
 * The fact that the runtime and registry types are a part of the parameter type
 * allows us to enforce proper typing, i.e runtime_registry::set_value() will only accept values
 * of the same type as the registry value.
 *
 * Note: name is a const char * instead of std::string because the entire config subsystem
 * is initialized by ctors of global variables, and if we make the config variables
 * themselves contain std::string, which needs to run a ctor to be initialized,
 * we would have code that depends on the order of initialization of global variables.
 */
template <typename RUNTIME_T, typename REGISTRY_T = RUNTIME_T> struct config_var_info_t {
    const char *name;
};
