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

#include "config.h"
#ifdef DEFINED_DPCP_PATH_RX_OR_TX
#include <stdlib.h>
#include <vlogger/vlogger.h>
#include "event/event_handler_manager.h"
#include <util/sys_vars.h>
#include "utils/rdtsc.h"
#include "util/instrumentation.h"
#include "util/utils.h"
#include "dev/time_converter_ptp.h"
#include "ib/base/verbs_extra.h"

#ifdef DEFINED_IBV_CLOCK_INFO

#define MODULE_NAME "tc_ptp"
DOCA_LOG_REGISTER(tc_ptp);

#define ibchtc_logerr  __log_err
#define ibchtc_logwarn __log_warn
#define ibchtc_loginfo __log_info
#define ibchtc_logdbg  __log_info_dbg
#define ibchtc_logfine __log_info_fine

#define UPDATE_HW_TIMER_PTP_PERIOD_MS 100

time_converter_ptp::time_converter_ptp(struct ibv_context *ctx)
    : m_p_ibv_context(ctx)
    , m_clock_values_id(0)
{
    for (size_t i = 0; i < ARRAY_SIZE(m_clock_values); i++) {
        memset(&m_clock_values[i], 0, sizeof(m_clock_values[i]));
        if (xlio_ibv_query_clock_info(m_p_ibv_context, &m_clock_values[i])) {
            ibchtc_logerr("xlio_ibv_query_clock_info failure for clock_info, (ibv context %p)",
                          m_p_ibv_context);
        }
    }

    m_timer_handle = g_p_event_handler_manager->register_timer_event(UPDATE_HW_TIMER_PTP_PERIOD_MS,
                                                                     this, PERIODIC_TIMER, nullptr);
    m_converter_status = TS_CONVERSION_MODE_PTP;
}

void time_converter_ptp::handle_timer_expired(void *user_data)
{

    NOT_IN_USE(user_data);

    if (is_cleaned()) {
        return;
    }

    int ret = 0;
    ret = xlio_ibv_query_clock_info(m_p_ibv_context, &m_clock_values[1 - m_clock_values_id]);
    if (ret) {
        ibchtc_logerr(
            "xlio_ibv_query_clock_info failure for clock_info, (ibv context %p) (return value=%d)",
            m_p_ibv_context, ret);
    }

    m_clock_values_id = 1 - m_clock_values_id;
}

void time_converter_ptp::convert_hw_time_to_system_time(uint64_t hwtime, struct timespec *systime)
{
    uint64_t sync_hw_clock = xlio_ibv_convert_ts_to_ns(&m_clock_values[m_clock_values_id], hwtime);
    systime->tv_sec = sync_hw_clock / NSEC_PER_SEC;
    systime->tv_nsec = sync_hw_clock % NSEC_PER_SEC;

    ibchtc_logfine("hwtime: 	%09ld", hwtime);
    ibchtc_logfine("systime:	%ld.%.9ld", systime->tv_sec, systime->tv_nsec);
}
#endif // DEFINED_IBV_CLOCK_INFO
#endif // DEFINED_DPCP_PATH_RX_OR_TX
