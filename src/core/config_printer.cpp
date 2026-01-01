/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "config_printer.h"

#include <cassert>
#include <functional>

#include "config/descriptors/config_descriptor.h"
#include "config/config_registry.h"
#include "util/sys_vars.h"
#include "vlogger/vlogger.h"

#define FORMAT_NUMBER "%-30s %-26d [%s]\n"
#define FORMAT_STRING "%-30s %-26s [%s]\n"
#define FORMAT_NUMSTR "%-30s %-2d%-24s [%s]\n"

#define VLOG_STR_PARAM_DETAILS(param_val, param_def_val, args...)                                  \
    do {                                                                                           \
        if (param_val && strcmp(param_val, param_def_val)) {                                       \
            vlog_printf(VLOG_INFO, ##args);                                                        \
        } else {                                                                                   \
            vlog_printf(VLOG_DETAILS, ##args);                                                     \
        }                                                                                          \
    } while (0);

#define VLOG_NUM_PARAM_DETAILS(param_val, param_def_val, args...)                                  \
    do {                                                                                           \
        if (param_val != param_def_val) {                                                          \
            vlog_printf(VLOG_INFO, ##args);                                                        \
        } else {                                                                                   \
            vlog_printf(VLOG_DETAILS, ##args);                                                     \
        }                                                                                          \
    } while (0);

#define LOG_STR_PARAM_AS(param_desc, param_val, param_def_val, param_name, val_desc_str)           \
    VLOG_STR_PARAM_DETAILS(param_val, param_def_val, FORMAT_STRING, param_desc, val_desc_str,      \
                           param_name)

#define LOG_NUM_PARAM(param_desc, param_val, param_def_val, param_name)                            \
    VLOG_NUM_PARAM_DETAILS(param_val, param_def_val, FORMAT_NUMBER, param_desc, param_val,         \
                           param_name)

#define LOG_NUM_PARAM_AS(param_desc, param_val, param_def_val, param_name, val_desc_str)           \
    VLOG_NUM_PARAM_DETAILS(param_val, param_def_val, FORMAT_STRING, param_desc, val_desc_str,      \
                           param_name)

#define LOG_BOOL_PARAM(param_desc, param_val, param_def_val, param_name)                           \
    VLOG_NUM_PARAM_DETAILS(param_val, param_def_val, FORMAT_STRING, param_desc,                    \
                           param_val ? "true" : "false", param_name)

#define LOG_NUM_PARAM_AS_NUMSTR(param_desc, param_val, param_def_val, param_name, val_desc_str)    \
    VLOG_NUM_PARAM_DETAILS(param_val, param_def_val, FORMAT_NUMSTR, param_desc, param_val,         \
                           val_desc_str, param_name)

/**
 * @brief Constructor
 * @param mce_sys_var Reference to the mce_sys_var object
 */
config_printer::config_printer(const mce_sys_var &mce_sys_var)
    : m_mce_sys_var(mce_sys_var)
{
}

void config_printer::print_to_log()
{
    // Scan all config parameters and print them.
    // The VLOG_PARAM_XXX macros show:
    // - When logging level is INFO: non-default parameters only
    // - When logging level is DETAILS: all parameters
    const config_registry &registry = m_mce_sys_var.get_registry().value();
    const config_descriptor &descriptor = registry.get_config_descriptor();
    const config_descriptor::parameter_map_t &parameter_map = descriptor.get_parameter_map();
    for (const auto &it : parameter_map) {
        const std::string &key = it.first;
        const parameter_descriptor &param_descriptor = it.second;

        const std::string &title = param_descriptor.get_title().value_or("");

        // Use function pointer dispatch for better performance and maintainability
        static const std::map<
            std::string,
            std::function<void(config_printer *, const std::string &, const std::string &)>>
            special_treatments = {
                {CONFIG_VAR_LOG_LEVEL, &config_printer::print_log_level},
                {CONFIG_VAR_RX_NUM_WRE, &config_printer::print_rx_num_wre},
                {CONFIG_VAR_RX_NUM_WRE_TO_POST_RECV,
                 &config_printer::print_rx_num_wre_to_post_recv},
                {CONFIG_VAR_PROGRESS_ENGINE_INTERVAL,
                 &config_printer::print_progress_engine_interval},
                // NOP - handled by prev case CONFIG_VAR_PROGRESS_ENGINE_INTERVAL
                {CONFIG_VAR_PROGRESS_ENGINE_WCE_MAX, &config_printer::print_nothing},
                {CONFIG_VAR_QP_COMPENSATION_LEVEL, &config_printer::print_qp_compensation_level}
#if defined(DEFINED_NGINX)
                ,
                {CONFIG_VAR_NGINX_WORKERS_NUM, &config_printer::print_nginx_workers_num}
#endif
#if defined(DEFINED_ENVOY)
                ,
                {CONFIG_VAR_ENVOY_WORKERS_NUM, &config_printer::print_envoy_workers_num}
#endif
            };

        const auto special_treatment = special_treatments.find(key);

        if (special_treatment != special_treatments.end()) {
            special_treatment->second(this, key, title);
        } else {
            // Generic handling by type of all other params
            const std::experimental::any element = registry.get_value_as_any(key);
            print_config_element(key, &param_descriptor, element, param_descriptor.default_value());
        }
    }
}

void config_printer::print_log_level(const std::string &key, const std::string &title)
{
    // Specific treatment to ensure log level is always shown
    LOG_NUM_PARAM_AS(title.c_str(), m_mce_sys_var.log_level,
                     // VLOG_INIT is never == m_mce_sys_var.log_level, so we always show log level
                     VLOG_INIT, key.c_str(), log_level::to_str(m_mce_sys_var.log_level));
}

void config_printer::print_rx_num_wre(const std::string &key, const std::string &title)
{
    LOG_NUM_PARAM(
        title.c_str(), m_mce_sys_var.rx_num_wr,
        (m_mce_sys_var.enable_striding_rq ? MCE_DEFAULT_STRQ_NUM_WRE : MCE_DEFAULT_RX_NUM_WRE),
        key.c_str());
}

void config_printer::print_rx_num_wre_to_post_recv(const std::string &key, const std::string &title)
{
    LOG_NUM_PARAM(title.c_str(), m_mce_sys_var.rx_num_wr_to_post_recv,
                  (m_mce_sys_var.enable_striding_rq ? MCE_DEFAULT_STRQ_NUM_WRE_TO_POST_RECV
                                                    : MCE_DEFAULT_RX_NUM_WRE_TO_POST_RECV),
                  key.c_str());
}

void config_printer::print_progress_engine_interval(const std::string &key,
                                                    const std::string &title)
{
    // Always show both parameters individually
    if (m_mce_sys_var.progress_engine_interval_msec == MCE_CQ_DRAIN_INTERVAL_DISABLED) {
        LOG_NUM_PARAM_AS_NUMSTR(title.c_str(), m_mce_sys_var.progress_engine_interval_msec, INT_MAX,
                                key.c_str(), "(Disabled)");
    } else {
        LOG_NUM_PARAM(title.c_str(), m_mce_sys_var.progress_engine_interval_msec,
                      MCE_DEFAULT_PROGRESS_ENGINE_INTERVAL_MSEC, key.c_str());
    }

    if (m_mce_sys_var.progress_engine_wce_max == 0) {
        LOG_NUM_PARAM_AS_NUMSTR("Periodic drain max CQEs", m_mce_sys_var.progress_engine_wce_max,
                                INT_MAX, CONFIG_VAR_PROGRESS_ENGINE_WCE_MAX, "(Disabled)");
    } else {
        LOG_NUM_PARAM("Periodic drain max CQEs", m_mce_sys_var.progress_engine_wce_max,
                      MCE_DEFAULT_PROGRESS_ENGINE_WCE_MAX, CONFIG_VAR_PROGRESS_ENGINE_WCE_MAX);
    }
}

void config_printer::print_nothing(const std::string & /*key*/, const std::string & /*title*/)
{
}

void config_printer::print_qp_compensation_level(const std::string &key, const std::string &title)
{
    LOG_NUM_PARAM(title.c_str(), m_mce_sys_var.qp_compensation_level, m_mce_sys_var.rx_num_wr / 2U,
                  key.c_str());
}

#if defined(DEFINED_NGINX)
void config_printer::print_nginx_workers_num(const std::string &key, const std::string &title)
{
    LOG_NUM_PARAM(title.c_str(),
                  (m_mce_sys_var.app.type == APP_NGINX ? m_mce_sys_var.app.workers_num
                                                       : MCE_DEFAULT_APP_WORKERS_NUM),
                  MCE_DEFAULT_APP_WORKERS_NUM, key.c_str());
}
#endif

#if defined(DEFINED_ENVOY)
void config_printer::print_envoy_workers_num(const std::string &key, const std::string &title)
{
    LOG_NUM_PARAM(title.c_str(),
                  (m_mce_sys_var.app.type == APP_ENVOY ? m_mce_sys_var.app.workers_num
                                                       : MCE_DEFAULT_APP_WORKERS_NUM),
                  MCE_DEFAULT_APP_WORKERS_NUM, key.c_str());
}
#endif

std::string config_printer::to_str_accurate(size_t size)
{
    static const char *suffixes[] = {"", "K", "M", "G", nullptr};
    int sfx_idx = 0;

    while ((size > 0 && size % 1024U == 0) && suffixes[sfx_idx + 1]) {
        ++sfx_idx;
        size /= 1024U;
    }

    return std::to_string(size) + suffixes[sfx_idx];
}

/**
  * @brief Shows a configured int64 value using log messages
  * @param key Configuration parameter name
  * @param title Configuration parameter title
  * @param param_descriptor Configuration parameter descriptor. nullptr for sub-objects.
  * @param element Current value for the parameter, as any
  * @param def_value_any Default value for the parameter, as std::any.
           When there is no default value defined, it is empty
  */
void config_printer::print_int64_config_element(const std::string &key, const std::string &title,
                                                const parameter_descriptor *param_descriptor,
                                                const std::experimental::any &element,
                                                const std::experimental::any &def_value_any)
{
    // def_value is of type void when not given

    int64_t def_value = (def_value_any.type() == typeid(int64_t))
        ? std::experimental::any_cast<int64_t>(def_value_any)
        : 0;
    int64_t cur_value = std::experimental::any_cast<int64_t>(element);
    // Check if this int has a string mapping
    std::string def_value_str;
    std::string cur_value_str;
    if (param_descriptor && param_descriptor->has_string_mappings()) {
        def_value_str = param_descriptor->convert_int64_to_mapped_string_or(
            def_value, std::to_string(def_value) + "(Invalid value)");
        cur_value_str = param_descriptor->convert_int64_to_mapped_string_or(
            cur_value, std::to_string(cur_value) + "(Invalid value)");
    }
    // No string ? Show the number as-is (But use K/M/G suffixes if it is a power of 1K, for
    // clarity)
    if (cur_value_str.empty()) {
        // Sentinel values (negative) should not be K/M/G formatted - they're not sizes
        std::string value_str =
            (cur_value < 0) ? std::to_string(cur_value) : to_str_accurate(cur_value);
        LOG_NUM_PARAM_AS(title.c_str(), cur_value, def_value, key.c_str(), value_str.c_str());
    } else {
        LOG_STR_PARAM_AS(title.c_str(), cur_value_str.c_str(), def_value_str.c_str(), key.c_str(),
                         cur_value_str.c_str());
    }
}

/**
  * @brief Shows a configured boolean value using log messages
  * @param key Configuration parameter name
  * @param title Configuration parameter title
  * @param param_descriptor Configuration parameter descriptor. nullptr for sub-objects.
  * @param element Current value for the parameter, as any
  * @param def_value_any Default value for the parameter, as std::any.
           When there is no default value defined, it is empty
  */
void config_printer::print_bool_config_element(const std::string &key, const std::string &title,
                                               const std::experimental::any &element,
                                               const std::experimental::any &def_value_any)
{
    // def_value is of type void when not given

    bool def_value = (def_value_any.type() == typeid(bool))
        ? std::experimental::any_cast<bool>(def_value_any)
        : false;
    bool cur_value = std::experimental::any_cast<bool>(element);
    LOG_BOOL_PARAM(title.c_str(), cur_value, def_value, key.c_str());
}

/**
  * @brief Shows a configured string value using log messages
  * @param key Configuration parameter name
  * @param title Configuration parameter title
  * @param param_descriptor Configuration parameter descriptor. nullptr for sub-objects.
  * @param element Current value for the parameter, as any
  * @param def_value_any Default value for the parameter, as std::any.
           When there is no default value defined, it is empty
  */
void config_printer::print_string_config_element(const std::string &key, const std::string &title,
                                                 const std::experimental::any &element,
                                                 const std::experimental::any &def_value_any)
{
    // def_value is of type void when not given
    std::string def_value = (def_value_any.type() == typeid(std::string))
        ? std::experimental::any_cast<std::string>(def_value_any)
        : std::string();
    std::string cur_value = std::experimental::any_cast<std::string>(element);
    LOG_NUM_PARAM_AS(title.c_str(), cur_value, def_value, key.c_str(), cur_value.c_str());
}

/*
 * This part of the code shows the value of all non-default config variables
 * using log messages.
 * Since configuration parameters may be nested, and not only in a simple hierarchy of scalars but
 * also as vectors or maps, we need to dig into vectors and maps and show them using the same method
 * as we use for scalars.
 * Here is how we show scalars:

   XLIO INFO   : TX ring allocation logic      per_socket [performance.rings.tx.allocation_logic]
   XLIO INFO   : RX poll duration (µsec)       2049 [performance.polling.blocking_rx_poll_usec]

 * And here is how we show a vector of maps:

   XLIO INFO   : Acceleration control rules [acceleration_control.rules] XLIO INFO   : Action 0 of
 rule 1         [acceleration_control.rules[0].actions[0]] XLIO INFO   : 1
 [acceleration_control.rules[0].id] XLIO INFO   :                                a
 [acceleration_control.rules[0].name] XLIO INFO   :                                Action 0 of rule
 2         [acceleration_control.rules[1].actions[0]] XLIO INFO   : xx
 [acceleration_control.rules[1].actions[1]]

 */

/*
 * Helper functions to print configured values using log messages
 */

/**
 * @brief Shows a configured vector of values using log messages
 * @param key Configuration parameter name
 * @param title Configuration parameter title
 * @param element Current value for the parameter, as any (It is actually std::vector<std::any>)
 */
void config_printer::print_config_vector(const std::string &key, const std::string &title,
                                         const std::experimental::any &element)
{
    auto cur_value_vector =
        std::experimental::any_cast<std::vector<std::experimental::any>>(element);
    // When a vector is not empty and has a title, show the title
    if (cur_value_vector.size() > 0 && !title.empty()) {
        // "Because "dummy" is not an empty string, this line will be shown the moment the vector is
        // not empty
        LOG_NUM_PARAM_AS(title.c_str(), std::string(), std::string("dummy"), key.c_str(), "");
    }

    for (auto it = cur_value_vector.cbegin(); it != cur_value_vector.cend(); ++it) {
        const auto &cur_value_any = *it;

        // If there are more than 4 elements, show only the first two and the last 2,
        // as we do not want to flood the output in case there are
        // many elements in the vector.

        /*
        Here is how it looks when there are 8 elements in the vector:

        XLIO INFO   :                                Action-0-0
        [acceleration_control.rules[0].actions[0]] XLIO INFO   :                                0
        [acceleration_control.rules[0].id] XLIO INFO   :                                Zero
        [acceleration_control.rules[0].name] XLIO INFO   :                                Action-1-0
        [acceleration_control.rules[1].actions[0]] XLIO INFO   :                                1
        [acceleration_control.rules[1].id] XLIO INFO   :                                One
        [acceleration_control.rules[1].name] XLIO INFO   : 4 element(s) not shown
        [acceleration_control.rules[2-5]] XLIO INFO   :                                Action-6-0
        [acceleration_control.rules[5].actions[0]] XLIO INFO   :                                6
        [acceleration_control.rules[6].id] XLIO INFO   :                                Six
        [acceleration_control.rules[6].name] XLIO INFO   :                                Action-7-0
        [acceleration_control.rules[7].actions[0]] XLIO INFO   :                                7
        [acceleration_control.rules[7].id] XLIO INFO   :                                Seven
        [acceleration_control.rules[7].name]

        */
        const int amount_to_show = 2;
        unsigned int index = it - cur_value_vector.begin();
        // show the first 2 and the last 2 elements
        if ((index < amount_to_show) || (index >= cur_value_vector.size() - amount_to_show)) {
            print_config_element(key + "[" + std::to_string(index) + "]", nullptr, cur_value_any,
                                 std::experimental::any());
        }
        // If we are here, there are elements which are not shown. Show which elements are not
        // shown.
        else if (index == amount_to_show) {
            std::string msg = key + "[" + std::to_string(amount_to_show);
            if (cur_value_vector.size() > amount_to_show * 2 + 1) {
                msg += "-" + std::to_string(cur_value_vector.size() - amount_to_show - 1);
            }
            msg += "]";
            std::string title1 = std::to_string(cur_value_vector.size() - amount_to_show * 2) +
                " element(s) not shown";
            LOG_NUM_PARAM_AS(title1.c_str(), std::string(), std::string("dummy"), msg.c_str(), "");
        }
    }
}

/**
 * @brief Shows a configured map of values using log messages
 * @param key Configuration parameter name
 * @param title Configuration parameter title
 * @param element Current value for the parameter, as any (It is actually std::map<std::string,
 * std::any>)
 */
void config_printer::print_config_map(const std::string &key, const std::experimental::any &element)
{
    auto cur_value_map =
        std::experimental::any_cast<std::map<std::string, std::experimental::any>>(element);
    for (const auto &it : cur_value_map) {
        const auto &cur_value_any = it.second;
        print_config_element(key + "." + it.first, nullptr, cur_value_any,
                             std::experimental::any());
    }
}

/**
  * @brief Shows configured values using log messages
  * @param key Configuration parameter name
  * @param param_descriptor Configuration parameter descriptor. nullptr for sub-objects.
  * @param element Current value for the parameter, as any
  * @param def_value_any Default value for the parameter, as std::any.
           When there is no default value defined, it is empty
  */
void config_printer::print_config_element(const std::string &key,
                                          const parameter_descriptor *param_descriptor,
                                          const std::experimental::any &element,
                                          const std::experimental::any &def_value_any)
{
    const std::string title = param_descriptor ? param_descriptor->get_title().value_or("") : "";
    const std::type_info &type = element.type();

    if (type == typeid(bool)) {
        print_bool_config_element(key, title, element, def_value_any);
    } else if (type == typeid(std::string)) {
        print_string_config_element(key, title, element, def_value_any);
    } else if (type == typeid(int64_t)) {
        print_int64_config_element(key, title, param_descriptor, element, def_value_any);
    } else if (type == typeid(std::vector<std::experimental::any>)) {
        print_config_vector(key, title, element);
    } else if (type == typeid(std::map<std::string, std::experimental::any>)) {
        print_config_map(key, element);
    } else {
        vlog_printf(VLOG_ERROR, "%s : Unsupported type: %s\n", key.c_str(), type.name());
        throw_xlio_exception("Unsupported type - See error output for details\n");
    }
}
