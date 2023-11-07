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

#include "config.h"
#include "instrumentation.h"
#include <string.h>

#if defined(DEFINED_PROF)
atomic_t ibprof_handle::m_current_id = atomic_t {1};
#endif /* DEFINED_PROF */

#ifdef RDTSC_MEASURE
uint16_t g_rdtsc_cost = 0;
instr_info g_rdtsc_instr_info_arr[RDTSC_FLOW_MAX];
char g_rdtsc_flow_names[RDTSC_FLOW_MAX][256] = {{"RDTSC_FLOW_TX_SENDTO_TO_AFTER_POST_SEND"},
                                                {"RDTSC_FLOW_RX_CQE_RECEIVEFROM"},
                                                {"RDTSC_FLOW_TX_VERBS_POST_SEND"},
                                                {"RDTSC_FLOW_RX_VERBS_IDLE_POLL"},
                                                {"RDTSC_FLOW_MEASURE_RECEIVEFROM_TO_SENDTO"},
                                                {"RDTSC_FLOW_RX_LWIP"},
                                                {"RDTSC_FLOW_MEASURE_RX_DISPATCH_PACKET"},
                                                {"RDTSC_FLOW_PROCCESS_AFTER_BUFFER_TO_RECIVEFROM "},
                                                {"RDTSC_FLOW_RX_XLIO_TCP_IDLE_POLL"},
                                                {"RDTSC_FLOW_RX_READY_POLL_TO_LWIP"},
                                                {"RDTSC_FLOW_RX_LWIP_TO_RECEVEFROM"},
                                                {"RDTSC_FLOW_RX_VERBS_READY_POLL"}

};

void init_rdtsc()
{
    tscval_t start, end, curr;

    gettimeoftsc(&start);
    for (int i = 0; i < 1000000; i++) {
        gettimeoftsc(&curr);
        gettimeoftsc(&curr);
    }
    gettimeoftsc(&end);
    g_rdtsc_cost = (end - start) / 1000000;
    vlog_printf(VLOG_ERROR, "RDTSC cost is: %u\n", g_rdtsc_cost);

    for (int i = 0; i < RDTSC_FLOW_MAX; i++) {
        memset((void *)(&g_rdtsc_instr_info_arr[i]), 0, sizeof(instr_info));
        g_rdtsc_instr_info_arr[i].print_ratio = RDTSC_PRINT_RATIO;
        g_rdtsc_instr_info_arr[i].trace_log_idx = i;
    }
}

void print_rdtsc_summary()
{
    uint64_t avg;

    vlog_printf(VLOG_ERROR, "*********** RDTSC Summary ************ \n");
    for (int i = 0; i < RDTSC_FLOW_MAX; i++) {
        if (g_rdtsc_instr_info_arr[i].counter) {
            avg = g_rdtsc_instr_info_arr[i].cycles / g_rdtsc_instr_info_arr[i].counter;
            vlog_printf(VLOG_ERROR, "%s: %" PRIu64 " \n",
                        g_rdtsc_flow_names[g_rdtsc_instr_info_arr[i].trace_log_idx], avg);
        }
    }
}

#endif // RDTSC_MEASURE
