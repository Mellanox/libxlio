/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include <string>
#include <experimental/any>

#include "config.h"

// fwd declarations
struct mce_sys_var;
class parameter_descriptor;

/**
 * This class shows configured values using log messages.
 * Normally, only non-default valules are shown.
 * When the debug level is set to DETAILS, all values are shown.
 */

class config_printer {
public:
    config_printer(const mce_sys_var &mce_sys_var);

    /**
     * @brief Shows configured values using log messages. Normally, only non-default values
     *       are shown. When the debug level is set to DETAILS, all values are shown.
     */
    void print_to_log();

private:
    /**
     * @brief Translates a number to a string, using K/M/G suffix as appropriate, without rounding.
     *      Example: 1024 -> "1K", 2048 -> "2K", 1024*1024 -> "1M", 7*1024*1024 -> "7M",
     *              1024*1024*1024 -> "1G"
     *      NOTE unlike option_size::to_str(): 10241 -> "10241" and not "10K"
     * @param size The number to translate
     * @return The translated string
     */
    std::string to_str_accurate(size_t size);

    /**
     * @brief Shows configured values using log messages
     * @param key Configuration parameter name
     * @param param_descriptor Configuration parameter descriptor. nullptr for sub-objects.
     * @param element Current value for the parameter, as any
     * @param def_value_any Default value for the parameter, as std::any.
             When there is no default value defined, it is empty
    */
    void print_config_element(const std::string &key, const parameter_descriptor *param_descriptor,
                              const std::experimental::any &element,
                              const std::experimental::any &def_value_any);

    // Helpers to print_config_element()
    // Each halper handles an element of a specific type
    void print_int64_config_element(const std::string &key, const std::string &title,
                                    const parameter_descriptor *param_descriptor,
                                    const std::experimental::any &element,
                                    const std::experimental::any &def_value_any);

    void print_bool_config_element(const std::string &key, const std::string &title,
                                   const std::experimental::any &element,
                                   const std::experimental::any &def_value_any);

    void print_string_config_element(const std::string &key, const std::string &title,
                                     const std::experimental::any &element,
                                     const std::experimental::any &def_value_any);

    void print_config_vector(const std::string &key, const std::string &title,
                             const std::experimental::any &element);

    void print_config_map(const std::string &key, const std::experimental::any &element);

    // Print functions for specific fields which we handle  in a non-standard way
    void print_log_level(const std::string &key, const std::string &title);

    void print_rx_num_wre(const std::string &key, const std::string &title);

    void print_rx_num_wre_to_post_recv(const std::string &key, const std::string &title);

    void print_progress_engine_interval(const std::string &key, const std::string &title);

    void print_nothing(const std::string & /*key*/, const std::string & /*title*/);

    void print_qp_compensation_level(const std::string &key, const std::string &title);

#if defined(DEFINED_NGINX)
    void print_nginx_workers_num(const std::string &key, const std::string &title);
#endif

#if defined(DEFINED_ENVOY)
    void print_envoy_workers_num(const std::string &key, const std::string &title);
#endif

    // Members
    const mce_sys_var &m_mce_sys_var;
};
