/*
 * Copyright (c) 2001-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef V_INSTRUMENTATION_H
#define V_INSTRUMENTATION_H

#include <stdint.h>
#include <unistd.h>
#include "utils/rdtsc.h"
#include "utils/atomic.h"
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "vlogger/vlogger.h"

#if defined(DEFINED_PROF)
#include <ibprof_api.h>

class ibprof_handle {
public:
    ibprof_handle(int id, const char *name)
    {
        m_id = id;
        ibprof_interval_start(id, name);
    }
    ~ibprof_handle() { ibprof_interval_end(m_id); }
    static atomic_t m_current_id;

private:
    int m_id; // unique id for measurement
};

#define PROFILE_FUNC                                                                               \
    static int ibprof_func_id = atomic_fetch_and_inc(&ibprof_handle::m_current_id);                \
    ibprof_handle prof_value_##__LINE__(ibprof_func_id, __FUNCTION__);
#define PROFILE_BLOCK(name)                                                                        \
    static int ibprof_block_id = atomic_fetch_and_inc(&ibprof_handle::m_current_id);               \
    ibprof_handle prof_value_##__LINE__(ibprof_block_id, name);
#else
#define PROFILE_FUNC
#define PROFILE_BLOCK(name)
#endif /* DEFINED_PROF */

#ifdef RDTSC_MEASURE
void init_rdtsc();
void print_rdtsc_summary();

#define RDTSC_PRINT_RATIO       100000
#define RDTSC_TAKE_START(instr) gettimeoftsc(&instr.start)
#define RDTSC_TAKE_END(instr)                                                                      \
    gettimeoftsc(&instr.end);                                                                      \
    instr.cycles +=                                                                                \
        (instr.end < instr.start - g_rdtsc_cost) ? 0 : (instr.end - instr.start - g_rdtsc_cost);   \
    instr.counter++;                                                                               \
    if (instr.print_ratio && instr.counter % instr.print_ratio == 0) {                             \
        uint64_t avg = instr.cycles / instr.counter;                                               \
        vlog_printf(VLOG_ERROR, "%s: %" PRIu64 " \n", g_rdtsc_flow_names[instr.trace_log_idx],     \
                    avg);                                                                          \
    }

enum rdtsc_flow_type {
    RDTSC_FLOW_SENDTO_TO_AFTER_POST_SEND = 0,
    RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM = 1,
    RDTSC_FLOW_TX_VERBS_POST_SEND = 2,
    RDTSC_FLOW_RX_VERBS_IDLE_POLL = 3,
    RDTSC_FLOW_RECEIVEFROM_TO_SENDTO = 4,
    RDTSC_FLOW_MEASURE_RX_LWIP = 5,
    RDTSC_FLOW_RX_DISPATCH_PACKET = 6,
    RDTSC_FLOW_PROCCESS_RX_BUFFER_TO_RECIVEFROM = 7,
    RDTSC_FLOW_RX_XLIO_TCP_IDLE_POLL = 8,
    RDTSC_FLOW_RX_READY_POLL_TO_LWIP = 9,
    RDTSC_FLOW_RX_LWIP_TO_RECEVEFROM = 10,
    RDTSC_FLOW_RX_VERBS_READY_POLL = 11,
    RDTSC_FLOW_MAX = 12
};

typedef struct instr_info {
    tscval_t start;
    tscval_t end;
    uint64_t cycles;
    uint64_t counter;
    uint64_t print_ratio;
    uint16_t trace_log_idx;
} instr_info;

extern uint16_t g_rdtsc_cost;
extern char g_rdtsc_flow_names[RDTSC_FLOW_MAX][256];
extern instr_info g_rdtsc_instr_info_arr[RDTSC_FLOW_MAX];

#endif // RDTS_MEASURE
#endif // INSTRUMENTATION
