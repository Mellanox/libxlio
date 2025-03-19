/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <stdlib.h>
#include <vlogger/vlogger.h>
#include <util/sys_vars.h>
#include "util/utils.h"
#include "dev/time_converter_rtc.h"

#ifdef DEFINED_IBV_CLOCK_INFO

#define MODULE_NAME "tc_rtc"

#define ibchtc_logerr  __log_err
#define ibchtc_logwarn __log_warn
#define ibchtc_loginfo __log_info
#define ibchtc_logdbg  __log_info_dbg
#define ibchtc_logfine __log_info_fine

time_converter_rtc::time_converter_rtc()
{
    m_converter_status = TS_CONVERSION_MODE_RTC;
}

void time_converter_rtc::handle_timer_expired(void *)
{
}

void time_converter_rtc::convert_hw_time_to_system_time(uint64_t hwtime, struct timespec *systime)
{
    hwtime &= 0x7FFFFFFFFFFFFFFF;
    systime->tv_nsec = (uint32_t)(hwtime & ~(0x3UL << 30));
    systime->tv_sec = (uint32_t)(hwtime >> 32);

    ibchtc_logfine("hwtime: 	%09ld", hwtime);
    ibchtc_logfine("systime:	%lld.%.9ld", systime->tv_sec, systime->tv_nsec);
}
#endif // DEFINED_IBV_CLOCK_INFO
