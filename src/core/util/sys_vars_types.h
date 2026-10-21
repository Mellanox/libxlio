/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include "vlogger/vlogger.h"

typedef enum {
    MCE_SPEC_NONE = 0,
    MCE_SPEC_ULTRA_LATENCY,
    MCE_SPEC_LATENCY,
    MCE_SPEC_NGINX,
    MCE_SPEC_NGINX_DPU,
    MCE_SPEC_NVME_BF3,
    MCE_SPEC_ALL /* last element */
} xlio_spec_t;

typedef enum {
    TS_CONVERSION_MODE_DISABLE = 0, // TS_CONVERSION_MODE_DISABLE must be the first enum
    TS_CONVERSION_MODE_RAW,
    TS_CONVERSION_MODE_BEST_POSSIBLE,
    TS_CONVERSION_MODE_SYNC,
    TS_CONVERSION_MODE_PTP,
    TS_CONVERSION_MODE_RTC,
    TS_CONVERSION_MODE_LAST
} ts_conversion_mode_t;

#define AUTO_ON_OFF_DEF AUTO = -1, OFF = 0, ON = 1

#define OPTIONS_FROM_TO_STR_DEF                                                                    \
    mode_t from_str(const char *str, mode_t def_value);                                            \
    mode_t from_int(const int option, mode_t def_value);                                           \
    const char *to_str(mode_t option)

namespace option_3 {
typedef enum { AUTO_ON_OFF_DEF } mode_t;
OPTIONS_FROM_TO_STR_DEF;
}; // namespace option_3

typedef enum {
    BUFFER_BATCHING_NONE = 0,
    BUFFER_BATCHING_WITH_RECLAIM,
    BUFFER_BATCHING_NO_RECLAIM,
    BUFFER_BATCHING_LAST,
} buffer_batching_mode_t;

typedef enum {
    TCP_TS_OPTION_DISABLE = 0, // TCP_TS_OPTION_DISABLE must be the first enum
    TCP_TS_OPTION_ENABLE,
    TCP_TS_OPTION_FOLLOW_OS,
    TCP_TS_OPTION_LAST
} tcp_ts_opt_t;

typedef enum {
    SKIP_POLL_IN_RX_DISABLE = 0,
    SKIP_POLL_IN_RX_ENABLE = 1,
    SKIP_POLL_IN_RX_EPOLL_ONLY = 2
} skip_poll_in_rx_t;

typedef enum {
    MULTILOCK_SPIN = 0,
    MULTILOCK_MUTEX = 1,
} multilock_t;

typedef enum {
    MULTILOCK_RECURSIVE = 0,
    MULTILOCK_NON_RECURSIVE = 1,
} multilock_recursive_t;

namespace option_tcp_ctl_thread {
typedef enum { CTL_THREAD_DISABLE = 0, CTL_THREAD_DELEGATE_TCP_TIMERS, CTL_THREAD_LAST } mode_t;
OPTIONS_FROM_TO_STR_DEF;
} // namespace option_tcp_ctl_thread

namespace option_alloc_type {
typedef enum {
    ANON = 0,
    HUGE = 2,
} mode_t;
OPTIONS_FROM_TO_STR_DEF;
} // namespace option_alloc_type

typedef enum {
    ALLOC_TYPE_ANON = option_alloc_type::ANON,
    ALLOC_TYPE_HUGEPAGES = option_alloc_type::HUGE,
    ALLOC_TYPE_LAST_ALLOWED_TO_USE,

    // Same as ALLOC_TYPE_HUGE, but doesn't print a warning on the fallback
    ALLOC_TYPE_PREFER_HUGE,
    // External type cannot be configured with XLIO_MEM_ALLOC_TYPE
    ALLOC_TYPE_EXTERNAL,
} alloc_mode_t;

#define SYS_VAR_EXCEPTION_HANDLING "XLIO_EXCEPTION_HANDLING"

class xlio_exception_handling {
public:
    static const char *getName() { return "Exception handling mode"; }

    static const char *getSysVar() { return SYS_VAR_EXCEPTION_HANDLING; }

    typedef enum {
        MODE_FIRST = -3,
        MODE_EXIT = -2,
        MODE_DEBUG = -1,
        MODE_UNOFFLOAD = 0,
        MODE_LOG_ERROR,
        MODE_RETURN_ERROR,
        MODE_ABORT,
        MODE_LAST,

        MODE_DEFAULT = MODE_DEBUG
    } mode;

    const char *to_str() const
    {
        switch (m_mode) {
        case MODE_EXIT:
            return "(exit on failed startup)";
        case MODE_DEBUG:
            return "(just log debug message)";
        case MODE_UNOFFLOAD:
            return "(log debug and un-offload)";
        case MODE_LOG_ERROR:
            return "(log error and un-offload)";
        case MODE_RETURN_ERROR:
            return "(Log Error and return error)";
        case MODE_ABORT:
            return "(Log error and Abort!)";
        default:
            break;
        }
        return "unsupported";
    }

    bool is_suit_un_offloading() const
    {
        return m_mode == MODE_UNOFFLOAD || m_mode == MODE_LOG_ERROR;
    }

    vlog_levels_t get_log_severity() const
    {
        switch (m_mode) {
        case MODE_EXIT:
        case MODE_DEBUG:
        case MODE_UNOFFLOAD:
            return VLOG_DEBUG;
        case MODE_LOG_ERROR:
        case MODE_RETURN_ERROR:
        case MODE_ABORT:
        default:
            return VLOG_ERROR;
        }
    }

    //
    // cast constructors and cast operators
    //

    xlio_exception_handling(mode _mode = MODE_DEFAULT)
        : m_mode(_mode)
    {
        if (m_mode >= MODE_LAST || m_mode <= MODE_FIRST) {
            m_mode = MODE_DEFAULT;
        }
    }

    explicit xlio_exception_handling(int _mode)
        : m_mode((mode)_mode)
    {
        if (m_mode >= MODE_LAST || m_mode <= MODE_FIRST) {
            m_mode = MODE_DEFAULT;
        }
    }

    operator mode() const { return m_mode; }

private:
    mode m_mode;
};
