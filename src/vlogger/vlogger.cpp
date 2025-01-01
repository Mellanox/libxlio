/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "vlogger.h"

#include <mellanox/dpcp.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <execinfo.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <doca_log.h>
#include <errno.h>
#include <fcntl.h>
#include <unordered_map>

#include "utils/bullseye.h"
#include "core/util/sys_vars.h"

#define VLOG_DEFAULT_MODULE_NAME "XLIO"
#define XLIO_LOG_CB_ENV_VAR      "XLIO_LOG_CB_FUNC_PTR"

char g_vlogger_module_name[VLOG_MODULE_MAX_LEN] = VLOG_DEFAULT_MODULE_NAME;
int g_vlogger_fd = -1;
FILE *g_vlogger_file = NULL;
vlog_levels_t g_vlogger_level = VLOG_DEFAULT;
vlog_levels_t *g_p_vlogger_level = NULL;

DOCA_LOG_REGISTER(logger);

// similiarly to DOCA_DLOG_HDR
// all the headers calling `__log_raw_header`
// use the `logger` registered source
int get_header_source()
{
    // the source registered as part of `DOCA_LOG_REGISTER(logger)`
    return log_source;
}

namespace log_level {

// convert str to vlog_levels_t; upon error - returns the given 'def_value'
vlog_levels_t from_str(const char *str, vlog_levels_t def_value)
{
    static const std::unordered_map<const char *, vlog_levels_t> string_to_level = {
        {"none", VLOG_NONE},        {"panic", VLOG_PANIC},   {"0", VLOG_PANIC},
        {"error", VLOG_ERROR},      {"1", VLOG_ERROR},       {"warn", VLOG_WARNING},
        {"warning", VLOG_WARNING},  {"2", VLOG_WARNING},     {"info", VLOG_INFO},
        {"information", VLOG_INFO}, {"3", VLOG_INFO},        {"details", VLOG_DETAILS},
        {"debug", VLOG_DEBUG},      {"4", VLOG_DEBUG},       {"fine", VLOG_FINE},
        {"func", VLOG_FINE},        {"5", VLOG_FINE},        {"finer", VLOG_FINER},
        {"func+", VLOG_FINER},      {"funcall", VLOG_FINER}, {"func_all", VLOG_FINER},
        {"func-all", VLOG_FINER},   {"6", VLOG_FINER},       {"all", VLOG_ALL},
    };

    if (str == NULL) {
        return def_value;
    }

    const auto string_level_tuple = string_to_level.find(str);
    if (string_level_tuple == std::end(string_to_level)) {
        return def_value;
    }

    if (string_level_tuple->second <= MAX_DEFINED_LOG_LEVEL) {
        return string_level_tuple->second;
    }
    __log_warn("Trace level set to max level %s\n", to_str(def_value));

    return static_cast<vlog_levels_t>(MAX_DEFINED_LOG_LEVEL);
}

// convert int to vlog_levels_t; upon error - returns the given 'def_value'
vlog_levels_t from_int(const int int_log, vlog_levels_t def_value)
{
    if (int_log >= VLOG_NONE && int_log <= VLOG_ALL) {
        return static_cast<vlog_levels_t>(int_log);
    }
    return def_value; // not found. use given def_value
}

const char *to_str(vlog_levels_t level)
{
    static const std::unordered_map<vlog_levels_t, const char *> level_to_string = {
        {VLOG_NONE, "VLOG_NONE"},         {VLOG_PANIC, "VLOG_PANIC"},
        {VLOG_ERROR, "VLOG_ERROR"},       {VLOG_WARNING, "VLOG_WARNING"},
        {VLOG_INFO, "VLOG_INFO"},         {VLOG_DETAILS, "VLOG_DETAILS"},
        {VLOG_DEBUG, "VLOG_DEBUG"},       {VLOG_FINE, "VLOG_FINE"},
        {VLOG_FUNC, "VLOG_FUNC"},         {VLOG_FINER, "VLOG_FINER"},
        {VLOG_FUNC_ALL, "VLOG_FUNC_ALL"}, {VLOG_ALL, "VLOG_ALL"},
    };

    const auto level_string_tuple = level_to_string.find(level);
    if (level_string_tuple == std::end(level_to_string)) {
        return "VLOG_INVALID_LEVEL";
    }

    return level_string_tuple->second;
}
} // namespace log_level

#ifndef HAVE_GETTID
pid_t gettid(void)
{
    return syscall(__NR_gettid);
}
#endif

#if _BullseyeCoverage
#pragma BullseyeCoverage off
#endif

// Credit for the C++ de-mangler go to:
// http://tombarta.wordpress.com/2008/08/01/c-stack-traces-with-gcc/
#include <cxxabi.h>
void printf_backtrace(void)
{
    char **backtrace_strings;
    void *backtrace_addrs[10];
    int backtrace_depth = backtrace(backtrace_addrs, 10);
    printf("[tid: %d] ------ printf_backtrace ------ \n", gettid());
    backtrace_strings = backtrace_symbols(backtrace_addrs, backtrace_depth);
    for (int i = 1; i < backtrace_depth; i++) {
#if 0
		printf("[%d] %p: %s\n", i, backtrace_addrs[i], backtrace_strings[i]);
#else
        size_t sz = 1024; // just a guess, template names will go much wider
        char *function = NULL;
        char *begin = 0, *end = 0;
        // find the parentheses and address offset surrounding the mangled name
        for (char *j = backtrace_strings[i]; *j; ++j) {
            if (*j == '(') {
                begin = j;
            } else if (*j == '+') {
                end = j;
            }
        }
        if (begin && end) {
            *begin++ = '\0';
            *end = '\0';
            // found our mangled name, now in [begin, end)

            int status;
            function = abi::__cxa_demangle(begin, NULL, &sz, &status);
            if (NULL == function) {
                // demangling failed, just pretend it's a C function with no args
                function = static_cast<char *>(malloc(sz));
                if (function) {
                    status = snprintf(function, sz - 1, "%s()", begin);
                    if (status > 0) {
                        function[status] = '\0';
                    } else {
                        function[0] = '\0';
                    }
                }
            }
            //	        fprintf(out, "    %s:%s\n", stack.backtrace_strings[i], function);
            printf("[%d] %p: %s:%s\n", i, backtrace_addrs[i], backtrace_strings[i],
                   (function ? function : "n/a"));
            if (function) {
                free(function);
            }
        } else {
            // didn't find the mangled name, just print the whole line
            printf("[%d] %p: %s\n", i, backtrace_addrs[i], backtrace_strings[i]);
        }
#endif
    }
    free(backtrace_strings);
}

#if _BullseyeCoverage
#pragma BullseyeCoverage on
#endif

#define PRINT_DOCA_INIT_ERR(err, log_fmt, log_args...)                                             \
    fprintf(stderr, "Initialization error: %s, %s. " log_fmt, doca_error_get_name(err),            \
            doca_error_get_descr(err), ##log_args)

#define PRINT_INIT_ERR(log_fmt, log_args...)                                                       \
    fprintf(stderr, "Initialization error: " log_fmt, ##log_args)

void vlog_start(const char *log_module_name, vlog_levels_t log_level, const char *log_filename)
{
    g_vlogger_file = stderr;

    strncpy(g_vlogger_module_name, log_module_name, sizeof(g_vlogger_module_name) - 1);
    g_vlogger_module_name[sizeof(g_vlogger_module_name) - 1] = '\0';

    char local_log_filename[255];
    if (log_filename != NULL && strcmp(log_filename, "")) {
        sprintf(local_log_filename, "%s", log_filename);
        g_vlogger_fd = open(local_log_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (g_vlogger_fd < 0) {
            PRINT_INIT_ERR("Failed to open logfile: %s\n", local_log_filename);
            std::terminate();
        }
        g_vlogger_file = fdopen(g_vlogger_fd, "w");

        BULLSEYE_EXCLUDE_BLOCK_START
        if (g_vlogger_file == NULL) {
            g_vlogger_file = stderr;
            PRINT_INIT_ERR("Failed to open logfile: %s\n", local_log_filename);
            std::terminate();
        }
        BULLSEYE_EXCLUDE_BLOCK_END
    }

    struct doca_log_backend *g_logger_backend = nullptr;
    const doca_error_t backend_create_status =
        doca_log_backend_create_with_file(g_vlogger_file, &g_logger_backend);

    if (backend_create_status != DOCA_SUCCESS) {
        PRINT_DOCA_INIT_ERR(backend_create_status, "doca_log_backend_create_with_file");
        std::terminate();
    }

    const doca_error_t backend_set_lower_level_status =
        doca_log_backend_set_level_lower_limit(g_logger_backend, log_level);
    if (backend_set_lower_level_status != DOCA_SUCCESS) {
        PRINT_DOCA_INIT_ERR(backend_set_lower_level_status,
                            "doca_log_backend_set_level_lower_limit");
        std::terminate();
    }

    const doca_error_t backend_set_upper_level_status =
        doca_log_backend_set_level_upper_limit(g_logger_backend, log_level);
    if (backend_set_upper_level_status != DOCA_SUCCESS) {
        PRINT_DOCA_INIT_ERR(backend_set_upper_level_status,
                            "doca_log_backend_set_level_upper_limit");
        std::terminate();
    }

    g_vlogger_level = log_level;
    g_p_vlogger_level = &g_vlogger_level;
}

void vlog_stop(void)
{
    // Closing logger

    // Allow only really extreme (PANIC) logs to go out
    g_vlogger_level = VLOG_PANIC;

    // set default module name
    strcpy(g_vlogger_module_name, VLOG_DEFAULT_MODULE_NAME);

    // Close output stream
    if (g_vlogger_file && g_vlogger_file != stderr) {
        FILE *closing_file = g_vlogger_file;
        g_vlogger_file = nullptr;
        fclose(closing_file);
    }

    // fix for using LD_PRELOAD with LBM. Unset the pointer given by the parent process, so a child
    // could get his own pointer without issues.
    unsetenv(XLIO_LOG_CB_ENV_VAR);
}
