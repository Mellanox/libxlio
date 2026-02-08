/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include "core/config/runtime_registry.h"

// Fwd declaration to allow cyclic dependency
struct mce_sys_var;

/**
 * @brief This class knows how to configure mce_sys_var from the configuration registry
 *
 * It does verifications and adaptations of the configuration registry values to the mce_sys_var.
 */
class sys_var_configurator {
public:
    /**
     * @brief Constructor
     * @param runtime_registry The runtime registry to use
     * @param sys_vars The mce_sys_var to configure
     * @note runtime_registry and sys_vars are not owned, just referenced
     */
    sys_var_configurator(runtime_registry &runtime_registry, mce_sys_var &sys_vars);

    virtual ~sys_var_configurator() noexcept = default;

    /**
     * @brief Configure the mce_sys_var from the runtime and configuration registries
     */
    void configure();

private:
    void initialize_base_variables();
    void configure_striding_rq();
    void configure_running_mode();
    void detect_application_profile();
    void apply_spec_profile_optimizations();
    void apply_ultra_latency_profile();
    void apply_latency_profile();
    void apply_nginx_profile();
    void apply_nvme_bf3_profile();

    void configure_before_user_settings();
    void configure_after_user_settings();

    // Not owned, just referenced
    runtime_registry &m_runtime_registry;
    // Not owned, just referenced
    config_registry &m_config_registry;
    // Not owned, just referenced
    mce_sys_var &m_sys_vars;
};
