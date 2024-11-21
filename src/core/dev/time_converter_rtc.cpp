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

#include <stdlib.h>
#include <vlogger/vlogger.h>
#include <util/sys_vars.h>
#include "util/utils.h"
#include "dev/time_converter_rtc.h"

#ifdef DEFINED_IBV_CLOCK_INFO

#define MODULE_NAME "tc_rtc"
DOCA_LOG_REGISTER(tc_rtc);

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
    ibchtc_logfine("systime:	%ld.%.9ld", systime->tv_sec, systime->tv_nsec);
}
#endif // DEFINED_IBV_CLOCK_INFO
