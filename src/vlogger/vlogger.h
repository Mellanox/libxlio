/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef VLOGGER_H
#define VLOGGER_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iostream>
#include <fstream>
#include <time.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
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

#define vlog_printf(_log_level, _format, ...)                                                      \
    do {                                                                                           \
        if (g_vlogger_level >= (_log_level)) {                                                     \
            vlog_output((_log_level), _format, ##__VA_ARGS__);                                     \
        }                                                                                          \
    } while (0)

#define VLOG_PRINTF(log_level, log_fmt, log_args...)                                               \
    vlog_printf(log_level, MODULE_HDR log_fmt "\n", __LINE__, __FUNCTION__, ##log_args)
#define VLOG_PRINTF_INFO(log_level, log_fmt, log_args...)                                          \
    vlog_printf(log_level, MODULE_HDR_INFO log_fmt "\n", __INFO__, __LINE__, __FUNCTION__,         \
                ##log_args)
#define VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(log_level_once, log_level, log_fmt, log_args...)         \
    do {                                                                                           \
        static vlog_levels_t ___log_level = log_level_once;                                        \
        VLOG_PRINTF_INFO(___log_level, log_fmt, ##log_args);                                       \
        ___log_level = log_level;                                                                  \
    } while (0)

#define VLOG_PRINTF_ONCE_THEN_ALWAYS(log_level_once, log_level, log_fmt, log_args...)              \
    do {                                                                                           \
        static vlog_levels_t ___log_level = log_level_once;                                        \
        VLOG_PRINTF(___log_level, log_fmt, ##log_args);                                            \
        ___log_level = log_level;                                                                  \
    } while (0)

#define VLOG_PRINTF_ONCE_THEN_DEBUG(log_level_once, log_fmt, log_args...)                          \
    do {                                                                                           \
        static vlog_levels_t ___log_level = log_level_once;                                        \
        vlog_printf(___log_level, log_fmt, ##log_args);                                            \
        ___log_level = VLOG_DEBUG;                                                                 \
    } while (0)

#define VLOG_PRINTF_ENTRY(log_level, log_fmt, log_args...)                                         \
    vlog_printf(log_level, MODULE_HDR_ENTRY "%s(" log_fmt ")\n", __FUNCTION__, ##log_args)
#define VLOG_PRINTF_EXIT(log_level, log_fmt, log_args...)                                          \
    vlog_printf(log_level, MODULE_HDR_EXIT "%s() " log_fmt "\n", __FUNCTION__, ##log_args)

#define __log_panic(log_fmt, log_args...)                                                          \
    do {                                                                                           \
        VLOG_PRINTF(VLOG_PANIC, log_fmt, ##log_args);                                              \
        std::terminate();                                                                          \
    } while (0)
#define __log_err(log_fmt, log_args...)                                                            \
    do {                                                                                           \
        VLOG_PRINTF(VLOG_ERROR, log_fmt, ##log_args);                                              \
    } while (0)
#define __log_warn(log_fmt, log_args...)                                                           \
    do {                                                                                           \
        VLOG_PRINTF(VLOG_WARNING, log_fmt, ##log_args);                                            \
    } while (0)
#define __log_info(log_fmt, log_args...)                                                           \
    do {                                                                                           \
        VLOG_PRINTF(VLOG_INFO, log_fmt, ##log_args);                                               \
    } while (0)

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_DETAILS)
#define __log_details(log_fmt, log_args...) ((void)0)
#else
#define __log_details(log_fmt, log_args...)                                                        \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_DETAILS)                                                       \
            VLOG_PRINTF(VLOG_DETAILS, log_fmt, ##log_args);                                        \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_DEBUG)
#define __log_dbg(log_fmt, log_args...) ((void)0)
#else
#define __log_dbg(log_fmt, log_args...)                                                            \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_DEBUG)                                                         \
            VLOG_PRINTF(VLOG_DEBUG, log_fmt, ##log_args);                                          \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_FINE)
#define __log_fine(log_fmt, log_args...) ((void)0)
#else
#define __log_fine(log_fmt, log_args...)                                                           \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_FINE)                                                          \
            VLOG_PRINTF(VLOG_FINE, log_fmt, ##log_args);                                           \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_FINER)
#define __log_finer(log_fmt, log_args...) ((void)0)
#else
#define __log_finer(log_fmt, log_args...)                                                          \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_FINER)                                                         \
            VLOG_PRINTF(VLOG_FINER, log_fmt, ##log_args);                                          \
    } while (0)
#endif /* MAX_DEFINED_LOG_LEVEL */

#define __log_info_panic(log_fmt, log_args...)                                                     \
    do {                                                                                           \
        VLOG_PRINTF_INFO(VLOG_PANIC, log_fmt, ##log_args);                                         \
        std::terminate();                                                                          \
    } while (0)
#define __log_info_err(log_fmt, log_args...)                                                       \
    do {                                                                                           \
        VLOG_PRINTF_INFO(VLOG_ERROR, log_fmt, ##log_args);                                         \
    } while (0)
#define __log_info_warn(log_fmt, log_args...)                                                      \
    do {                                                                                           \
        VLOG_PRINTF_INFO(VLOG_WARNING, log_fmt, ##log_args);                                       \
    } while (0)
#define __log_info_info(log_fmt, log_args...)                                                      \
    do {                                                                                           \
        VLOG_PRINTF_INFO(VLOG_INFO, log_fmt, ##log_args);                                          \
    } while (0)

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_DETAILS)
#define __log_info_details(log_fmt, log_args...) ((void)0)
#else
#define __log_info_details(log_fmt, log_args...)                                                   \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_DETAILS)                                                       \
            VLOG_PRINTF_INFO(VLOG_DETAILS, log_fmt, ##log_args);                                   \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_DEBUG)
#define __log_info_dbg(log_fmt, log_args...) ((void)0)
#else
#define __log_info_dbg(log_fmt, log_args...)                                                       \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_DEBUG)                                                         \
            VLOG_PRINTF_INFO(VLOG_DEBUG, log_fmt, ##log_args);                                     \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_FINE)
#define __log_info_fine(log_fmt, log_args...) ((void)0)
#else
#define __log_info_fine(log_fmt, log_args...)                                                      \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_FINE)                                                          \
            VLOG_PRINTF_INFO(VLOG_FINE, log_fmt, ##log_args);                                      \
    } while (0)
#endif

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_FINER)
#define __log_info_finer(log_fmt, log_args...) ((void)0)
#else
#define __log_info_finer(log_fmt, log_args...)                                                     \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_FINER)                                                         \
            VLOG_PRINTF_INFO(VLOG_FINER, log_fmt, ##log_args);                                     \
    } while (0)
#endif /* MAX_DEFINED_LOG_LEVEL */

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_DEBUG)
#define __log_entry_dbg(log_fmt, log_args...) ((void)0)
#else
#define __log_entry_dbg(log_fmt, log_args...)                                                      \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_DEBUG)                                                         \
            VLOG_PRINTF_ENTRY(VLOG_DEBUG, log_fmt, ##log_args);                                    \
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

// deprecated functions - only exist for Backward Compatibility.  Please avoid using them!
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

typedef enum {
    VLOG_INIT = DEFINED_VLOG_INIT,
    VLOG_NONE = DEFINED_VLOG_NONE,
    VLOG_PANIC = DEFINED_VLOG_PANIC,
    VLOG_ERROR = DEFINED_VLOG_ERROR,
    VLOG_WARNING = DEFINED_VLOG_WARNING,
    VLOG_INFO = DEFINED_VLOG_INFO,
    VLOG_DEFAULT = VLOG_INFO,
    VLOG_DETAILS = DEFINED_VLOG_DETAILS,
    VLOG_DEBUG = DEFINED_VLOG_DEBUG,
    VLOG_FINE = DEFINED_VLOG_FINE,
    VLOG_FUNC = VLOG_FINE,
    VLOG_FINER = DEFINED_VLOG_FINER,
    VLOG_FUNC_ALL = VLOG_FINER,
    VLOG_ALL = DEFINED_VLOG_ALL /* last element */
} vlog_levels_t;

namespace log_level {
// convert str to vlog_levels_t; upon error - returns the given 'def_value'
vlog_levels_t from_str(const char *str, vlog_levels_t def_value = VLOG_DEFAULT);

// convert int to vlog_levels_t; upon error - returns the given 'def_value'
vlog_levels_t from_int(const int int_log, vlog_levels_t def_value = VLOG_DEFAULT);

const char *to_str(vlog_levels_t level);
const char *get_color(vlog_levels_t level);
} // namespace log_level

#define VLOG_SINCE_YEAR     1900
#define VLOG_MODULE_MAX_LEN 10

#define VLOGGER_STR_COLOR_TERMINATION_STR "\e[0m"
#define VLOGGER_STR_TERMINATION_SIZE      6

typedef void (*xlio_log_cb_t)(int log_level, const char *str);

extern char g_vlogger_module_name[VLOG_MODULE_MAX_LEN];
extern FILE *g_vlogger_file;
extern int g_vlogger_fd;
extern vlog_levels_t g_vlogger_level;
extern vlog_levels_t *g_p_vlogger_level;
extern uint8_t g_vlogger_details;
extern uint8_t *g_p_vlogger_details;
extern uint32_t g_vlogger_usec_on_startup;
extern bool g_vlogger_log_in_colors;
extern xlio_log_cb_t g_vlogger_cb;

#define vlog_func_enter() vlog_printf(VLOG_FINE, "ENTER %s\n", __PRETTY_FUNCTION__);
#define vlog_func_exit()  vlog_printf(VLOG_FINE, "EXIT %s\n", __PRETTY_FUNCTION__);

#define vlog_func_all_enter() vlog_printf(VLOG_FINER, "ENTER %s\n", __PRETTY_FUNCTION__);
#define vlog_func_all_exit()  vlog_printf(VLOG_FINER, "EXIT %s\n", __PRETTY_FUNCTION__);

#ifndef HAVE_GETTID
pid_t gettid(void); // Check vlogger.cpp for implementation
#endif

void printf_backtrace(void);

void vlog_start(const char *log_module_name, vlog_levels_t log_level = VLOG_DEFAULT,
                const char *log_filename = NULL, int log_details = 0, bool colored_log = true);
void vlog_stop(void);

static inline uint32_t vlog_get_usec_since_start()
{
    struct timespec ts_now;

    BULLSEYE_EXCLUDE_BLOCK_START
    if (gettime(&ts_now)) {
        printf("%s() gettime() Returned with Error (errno=%d %m)\n", __func__, errno);
        return (uint32_t)-1;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    if (!g_vlogger_usec_on_startup) {
        g_vlogger_usec_on_startup = ts_to_usec(&ts_now);
    }

    return (ts_to_usec(&ts_now) - g_vlogger_usec_on_startup);
}

#define VLOGGER_STR_SIZE 512

void vlog_output(vlog_levels_t log_level, const char *fmt, ...);
void vlog_print_buffer(vlog_levels_t log_level, const char *msg_header, const char *msg_tail,
                       const char *buf_user, int buf_len);

#ifdef __cplusplus
};
#endif //__cplusplus

#endif // VLOGGER_H
