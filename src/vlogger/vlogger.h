/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef VLOGGER_H
#define VLOGGER_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <doca_log.h>
#include <time.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <exception>
#include "utils/bullseye.h"
#include "utils/rdtsc.h"

#define TO_STR(a)       TOSTR_HELPER(a)
#define TOSTR_HELPER(a) #a
#define PRODUCT_NAME    "XLIO"

#undef MODULE_HDR
#define MODULE_HDR MODULE_NAME "%d:%s() "

#undef MODULE_HDR_INFO
#define MODULE_HDR_INFO MODULE_NAME "[%p]:%d:%s() "

#undef MODULE_HDR_ENTRY
#define MODULE_HDR_ENTRY "ENTER: "

#undef MODULE_HDR_EXIT
#define MODULE_HDR_EXIT "EXIT: "

#undef __INFO__
#define __INFO__ this

int get_header_source();

#define VLOG_PRINTF(log_level, log_fmt, log_args...)                                               \
    __log_raw(log_level, MODULE_HDR log_fmt "\n", __LINE__, __FUNCTION__, ##log_args)
#define VLOG_PRINTF_INFO(log_level, log_fmt, log_args...)                                          \
    __log_raw(log_level, MODULE_HDR_INFO log_fmt "\n", __INFO__, __LINE__, __FUNCTION__, ##log_args)

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_INFO)
#define VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(...) ((void)0)
#else
#define VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(log_level_once, log_level, log_fmt, log_args...)         \
    do {                                                                                           \
        static vlog_levels_t ___log_level = log_level_once;                                        \
        VLOG_PRINTF_INFO(___log_level, log_fmt, ##log_args);                                       \
        ___log_level = log_level;                                                                  \
    } while (0)
#endif

#define VLOG_PRINTF_ONCE_THEN_ALWAYS(log_level_once, log_level, log_fmt, log_args...)              \
    do {                                                                                           \
        static vlog_levels_t ___log_level = log_level_once;                                        \
        VLOG_PRINTF(___log_level, log_fmt, ##log_args);                                            \
        ___log_level = log_level;                                                                  \
    } while (0)

#define VLOG_PRINTF_ONCE_THEN_DEBUG(log_level_once, log_fmt, log_args...)                          \
    do {                                                                                           \
        static vlog_levels_t ___log_level = log_level_once;                                        \
        __log_raw(___log_level, log_fmt, ##log_args);                                              \
        ___log_level = VLOG_DEBUG;                                                                 \
    } while (0)

#define VLOG_PRINTF_ENTRY(log_level, log_fmt, log_args...)                                         \
    __log_raw(log_level, MODULE_HDR_ENTRY "%s(" log_fmt ")\n", __FUNCTION__, ##log_args)
#define VLOG_PRINTF_EXIT(log_level, log_fmt, log_args...)                                          \
    __log_raw(log_level, MODULE_HDR_EXIT "%s() " log_fmt "\n", __FUNCTION__, ##log_args)

#define __log_panic(log_fmt, log_args...)                                                          \
    do {                                                                                           \
        DOCA_LOG_CRIT(log_fmt, ##log_args);                                                        \
        std::terminate();                                                                          \
    } while (0)
#define __log_err(log_fmt, log_args...)                                                            \
    do {                                                                                           \
        DOCA_LOG_ERR(log_fmt, ##log_args);                                                         \
    } while (0)

#define __log_header_err(log_fmt, log_args...)                                                     \
    do {                                                                                           \
        __log_raw_header(VLOG_ERROR, log_fmt, ##log_args);                                         \
    } while (0)

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_INFO)
#define __log_header_warn(...) ((void)0)
#else
#define __log_header_warn(log_fmt, log_args...)                                                    \
    do {                                                                                           \
        __log_raw_header(VLOG_WARNING, log_fmt, ##log_args);                                       \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_INFO)
#define __log_warn(...) ((void)0)
#else
#define __log_warn(log_fmt, log_args...)                                                           \
    do {                                                                                           \
        DOCA_LOG_WARN(log_fmt, ##log_args);                                                        \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_INFO)
#define __log_header_info(...) ((void)0)
#else
#define __log_header_info(log_fmt, log_args...)                                                    \
    do {                                                                                           \
        __log_raw_header(VLOG_INFO, log_fmt, ##log_args);                                          \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_INFO)
#define __log_info(...) ((void)0)
#else
#define __log_info(log_fmt, log_args...)                                                           \
    do {                                                                                           \
        DOCA_LOG_INFO(log_fmt, ##log_args);                                                        \
    } while (0)
#endif

// Note: always try to minimize raw usage -
// as __log_raw can't be wrapped with optimized out ifdefs
#define __log_raw(log_level, log_fmt, log_args...)                                                 \
    do {                                                                                           \
        DOCA_LOG(log_level, log_fmt, ##log_args);                                                  \
    } while (0)

#define __log_raw_header(log_level, log_fmt, log_args...)                                          \
    do {                                                                                           \
        doca_log(log_level, get_header_source(), __FILE__, __LINE__, __func__, log_fmt,            \
                 ##log_args);                                                                      \
    } while (0)

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_DETAILS)
#define __log_details(log_fmt, log_args...) ((void)0)
#else
#define __log_details(log_fmt, log_args...)                                                        \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_DETAILS)                                                       \
            DOCA_LOG_INFO("[DETAILS] " log_fmt, ##log_args);                                       \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_DEBUG)
#define __log_header_dbg(log_fmt, log_args...) ((void)0)
#else
#define __log_header_dbg(log_fmt, log_args...)                                                     \
    do {                                                                                           \
        __log_raw_header(VLOG_DEBUG, log_fmt, ##log_args);                                         \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_DEBUG)
#define __log_dbg(log_fmt, log_args...) ((void)0)
#else
#define __log_dbg(log_fmt, log_args...)                                                            \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_DEBUG)                                                         \
            DOCA_LOG_DBG(log_fmt, ##log_args);                                                     \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_FINE)
#define __log_fine(log_fmt, log_args...) ((void)0)
#else
#define __log_fine(log_fmt, log_args...)                                                           \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_FINE)                                                          \
            DOCA_LOG_TRC("[FINE] " log_fmt, ##log_args);                                           \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_FINE)
#define __log_header_fine(log_fmt, log_args...) ((void)0)
#else
#define __log_header_fine(log_fmt, log_args...)                                                    \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_FINE)                                                          \
            __log_raw_header(VLOG_FINE, log_fmt, ##log_args);                                      \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_FINER)
#define __log_finer(log_fmt, log_args...) ((void)0)
#else
#define __log_finer(log_fmt, log_args...)                                                          \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_FINER)                                                         \
            DOCA_LOG_TRC("[FINER] " log_fmt, ##log_args);                                          \
    } while (0)
#endif

#define __log_info_panic(log_fmt, log_args...)                                                     \
    do {                                                                                           \
        DOCA_LOG_INFO("PANIC " log_fmt, ##log_args);                                               \
        std::terminate();                                                                          \
    } while (0)
#define __log_info_err(log_fmt, log_args...)                                                       \
    do {                                                                                           \
        DOCA_LOG_INFO("ERROR " log_fmt, ##log_args);                                               \
    } while (0)

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_INFO)
#define __log_info_warn(...) ((void)0)
#else
#define __log_info_warn(log_fmt, log_args...)                                                      \
    do {                                                                                           \
        DOCA_LOG_INFO("WARNING " log_fmt, ##log_args);                                             \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_INFO)
#define __log_info_info(...) ((void)0)
#else
#define __log_info_info(log_fmt, log_args...)                                                      \
    do {                                                                                           \
        DOCA_LOG_INFO("INFO " log_fmt, ##log_args);                                                \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_DETAILS)
#define __log_info_details(log_fmt, log_args...) ((void)0)
#else
#define __log_info_details(log_fmt, log_args...)                                                   \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_DETAILS)                                                       \
            DOCA_LOG_INFO("DETAILS " log_fmt, ##log_args);                                         \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_DEBUG)
#define __log_info_dbg(log_fmt, log_args...) ((void)0)
#else
#define __log_info_dbg(log_fmt, log_args...)                                                       \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_DEBUG)                                                         \
            DOCA_LOG_INFO("DEBUG " log_fmt, ##log_args);                                           \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_FINE)
#define __log_info_fine(log_fmt, log_args...) ((void)0)
#else
#define __log_info_fine(log_fmt, log_args...)                                                      \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_FINE)                                                          \
            DOCA_LOG_INFO("FINE " log_fmt, ##log_args);                                            \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_FINER)
#define __log_info_finer(log_fmt, log_args...) ((void)0)
#else
#define __log_info_finer(log_fmt, log_args...)                                                     \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_FINER)                                                         \
            DOCA_LOG_INFO("FINER " log_fmt, ##log_args);                                           \
    } while (0)
#endif /* MAX_DEFINED_LOG_LEVEL */

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_DEBUG)
#define __log_entry_dbg(log_fmt, log_args...) ((void)0)
#else
#define __log_entry_dbg(log_fmt, log_args...)                                                      \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_DEBUG)                                                         \
            DOCA_LOG_DBG(log_fmt, ##log_args);                                                     \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_FINE)
#define __log_entry_fine(log_fmt, log_args...) ((void)0)
#else
#define __log_entry_fine(log_fmt, log_args...)                                                     \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_FINE)                                                          \
            VLOG_PRINTF_ENTRY(VLOG_FINE, log_fmt, ##log_args);                                     \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_FINER)
#define __log_entry_finer(log_fmt, log_args...) ((void)0)
#else
#define __log_entry_finer(log_fmt, log_args...)                                                    \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_FINER)                                                         \
            VLOG_PRINTF_ENTRY(VLOG_FINER, log_fmt, ##log_args);                                    \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_DEBUG)
#define __log_exit_dbg(log_fmt, log_args...) ((void)0)
#else
#define __log_exit_dbg(log_fmt, log_args...)                                                       \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_DEBUG)                                                         \
            VLOG_PRINTF_EXIT(VLOG_DEBUG, log_fmt, ##log_args);                                     \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_FINE)
#define __log_exit_fine(log_fmt, log_args...) ((void)0)
#else
#define __log_exit_fine(log_fmt, log_args...)                                                      \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_FINE)                                                          \
            VLOG_PRINTF_EXIT(VLOG_FINE, log_fmt, ##log_args);                                      \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_FINER)
#define __log_exit_finer(log_fmt, log_args...) ((void)0)
#else
#define __log_exit_finer(log_fmt, log_args...)                                                     \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_FINER)                                                         \
            VLOG_PRINTF_EXIT(VLOG_FINER, log_fmt, ##log_args);                                     \
    } while (0)
#endif /* MAX_DEFINED_LOG_LEVEL */

#define PRINT_DOCA_ERR(logger, err, log_fmt, log_args...)                                          \
    logger("DOCA error: %s, %s. " log_fmt, doca_error_get_name(err), doca_error_get_descr(err),    \
           ##log_args)

#define VPRINT_DOCA_ERR(level, err, log_fmt, log_args...)                                          \
    __log_raw(level, "DOCA error: %s, %s. " log_fmt, doca_error_get_name(err),                     \
              doca_error_get_descr(err), ##log_args)

#define LOG_FUNCTION_CALL " "

// deprecated functions - only exist for Backward Compatibility.  Please avoid using them!
#define __log_header_func(...)   __log_header_fine(__VA_ARGS__)
#define __log_func(...)          __log_fine(__VA_ARGS__)
#define __log_funcall(...)       __log_finer(__VA_ARGS__)
#define __log_info_func(...)     __log_info_fine(__VA_ARGS__)
#define __log_info_funcall(...)  __log_info_finer(__VA_ARGS__)
#define __log_entry_func(...)    __log_entry_fine(__VA_ARGS__)
#define __log_entry_funcall(...) __log_entry_finer(__VA_ARGS__)
#define __log_exit_func(...)     __log_exit_fine(__VA_ARGS__)
#define __log_exit_funcall(...)  __log_exit_finer(__VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

static_assert(DOCA_LOG_LEVEL_CRIT - DOCA_LOG_LEVEL_DISABLE == 10 &&
                  DOCA_LOG_LEVEL_ERROR - DOCA_LOG_LEVEL_CRIT == 10 &&
                  DOCA_LOG_LEVEL_WARNING - DOCA_LOG_LEVEL_ERROR == 10 &&
                  DOCA_LOG_LEVEL_INFO - DOCA_LOG_LEVEL_WARNING == 10 &&
                  DOCA_LOG_LEVEL_DEBUG - DOCA_LOG_LEVEL_INFO == 10 &&
                  DOCA_LOG_LEVEL_TRACE - DOCA_LOG_LEVEL_DEBUG == 10,
              "DOCA log levels have changed and broke logger assumptions...");

// doca has less log granularity then we have.
// i.e. - In terms of DOCA - VLOG_DETAILS and VLOG_INFO will generate an identical log
// using g_vlogger_level and the macros (e.g. - `__log_finer`) the correct annotation will be added
// e.g. -
// __log_finer will do DOCA_LOG_LEVEL_DEBUG with "[FINER]" prefix iff
// g_vlogger_level >= VLOG_FINER
typedef enum {
    VLOG_INIT = DOCA_LOG_LEVEL_DISABLE - 1,
    VLOG_NONE = DOCA_LOG_LEVEL_DISABLE,
    VLOG_PANIC = DOCA_LOG_LEVEL_CRIT,
    VLOG_ERROR = DOCA_LOG_LEVEL_ERROR,
    VLOG_WARNING = DOCA_LOG_LEVEL_WARNING,
    VLOG_INFO = DOCA_LOG_LEVEL_INFO,
    VLOG_DEFAULT = VLOG_INFO,
    VLOG_DETAILS = VLOG_INFO + 1,
    VLOG_DEBUG = DOCA_LOG_LEVEL_DEBUG,
    VLOG_FINE = DOCA_LOG_LEVEL_TRACE,
    VLOG_FUNC = DOCA_LOG_LEVEL_TRACE + 2,
    VLOG_FINER = DOCA_LOG_LEVEL_TRACE + 3,
    VLOG_FUNC_ALL = DOCA_LOG_LEVEL_TRACE + 4,
    VLOG_ALL = DOCA_LOG_LEVEL_TRACE + 5 /* last element */
} vlog_levels_t;

namespace log_level {
// convert str to vlog_levels_t; upon error - returns the given 'def_value'
vlog_levels_t from_str(const char *str, vlog_levels_t def_value = VLOG_DEFAULT);

// convert int to vlog_levels_t; upon error - returns the given 'def_value'
vlog_levels_t from_int(const int int_log, vlog_levels_t def_value = VLOG_DEFAULT);

const char *to_str(vlog_levels_t level);
} // namespace log_level

#define VLOG_MODULE_MAX_LEN 10

typedef void (*xlio_log_cb_t)(int log_level, const char *str);

extern char g_vlogger_module_name[VLOG_MODULE_MAX_LEN];
extern FILE *g_vlogger_file;
extern int g_vlogger_fd;
extern vlog_levels_t g_vlogger_level;
extern vlog_levels_t *g_p_vlogger_level;

#define vlog_func_enter() __log_func("ENTER %s\n", __PRETTY_FUNCTION__);
#define vlog_func_exit()  __log_func("EXIT %s\n", __PRETTY_FUNCTION__);

#define vlog_func_all_enter() __log_entry_funcall("ENTER %s\n", __PRETTY_FUNCTION__);
#define vlog_func_all_exit()  __log_entry_funcall("EXIT %s\n", __PRETTY_FUNCTION__);

#ifndef HAVE_GETTID
pid_t gettid(void); // Check vlogger.cpp for implementation
#endif

void printf_backtrace(void);

void vlog_start(const char *log_module_name, vlog_levels_t log_level = VLOG_DEFAULT,
                const char *log_filename = NULL);
void vlog_stop(void);

#define VLOGGER_STR_SIZE 512

#ifdef __cplusplus
};
#endif //__cplusplus

#endif // VLOGGER_H
