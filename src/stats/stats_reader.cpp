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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h> /* getopt()*/
#include <errno.h>
#include <dirent.h>
#include <string.h>
#include <ctime>
#include <iomanip>
#include <vector>
#include <cinttypes>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/stat.h>

#include <cinttypes>
#include <iostream>
#include <list>
#include <vector>
#include <unordered_map>

#include "utils/rdtsc.h"
#include "core/util/utils.h"
#include "core/util/xlio_stats.h"
#include "core/util/sys_vars.h"
#include "stats/stats_data_reader.h"
#include <sstream>

using namespace std;

typedef std::list<int> fd_list_t;

typedef struct {
    ip_addr mc_grp {0};
    fd_list_t fd_list;
} mc_group_fds_t;

typedef enum { e_K = 1024, e_M = 1048576 } units_t;

#define MODULE_NAME "xliostat"
DOCA_LOG_REGISTER(xliostat);
#define PRODUCT_NAME                  "XLIO"
#define log_msg(log_fmt, log_args...) printf(MODULE_NAME ": " log_fmt "\n", ##log_args)
#define log_err(log_fmt, log_args...) fprintf(stderr, MODULE_NAME ": " log_fmt "\n", ##log_args)
#define log_system_err(log_fmt, log_args...)                                                       \
    fprintf(stderr, MODULE_NAME ": " log_fmt " (errno=%d %s)\n", ##log_args, errno, strerror(errno))
#define log_dbg(log_fmt, log_args...) printf(MODULE_NAME ": " log_fmt "\n", ##log_args)

#define BASE_HEADERS_NUM        2
#define BASIC_STATS_LINES_NUM   2
#define UPPER_SHORT_VIEW_HEADER " %-7s %42s %31s\n"
#define LOWER_SHORT_VIEW_HEADER " %-7s %10s %7s %8s %7s %6s %7s %7s %7s %7s\n"
#define RX_SHORT_VIEW           " %-3d %-3s %10u %20" PRIu64 " %8u %7u %6.1f %7u %20" PRIu64 " %7u %7u\n"
#define TX_SHORT_VIEW           " %-3s %-3s %10u %20" PRIu64 " %8u %7u %-6s %7u %20" PRIu64 " %7u %7u\n"
#define IOMUX_FORMAT            "%-8s%-2s %-9s%u%-1s%u %-12s %-9s%-5u %-7s%-4u %-5s%-2.2f%-3s %-5s%d%-1s\n"

#define MEDIUM_HEADERS_NUM        3
#define MEDIUM_STATS_LINES_NUM    2
#define UPPER_MEDIUM_VIEW_HEADER  " %-7s %65s %31s\n"
#define MIDDLE_MEDIUM_VIEW_HEADER " %-7s %10s %10s %7s %8s %7s %6s%23s %7s %7s %7s %7s\n"
#define LOWER_MEDIUM_VIEW_HEADER  " %50s %6s  %6s  %6s \n"
#define RX_MEDIUM_VIEW                                                                             \
    " %-3d %-3s %10u %10" PRIu64 " %" PRIu64 " %8u %7u %6.1f %6u  %6u  %6u %7u %" PRIu64           \
    " %7u %7u\n"
#define TX_MEDIUM_VIEW " %-3s %-3s %10u %10u %" PRIu64 " %8u %7u %29s %7u %" PRIu64 " %7u %7u\n"
#define CYCLES_SEPARATOR                                                                           \
    "-------------------------------------------------------------------------------\n"
#define FORMAT_STATS_32bit     "%-20s %u\n"
#define FORMAT_STATS_s_32bit   "%-20s %d\n"
#define FORMAT_STATS_64bit     "%-20s %" PRIu64 " %-3s\n"
#define FORMAT_STATS_double    "%-20s %.1f\n"
#define FORMAT_RING_PACKETS    "%-20s %zu / %zu [KBs/pkts] %-3s\n"
#define FORMAT_RING_STRIDES    "%-20s %zu / %zu / %zu [total/max-per-packet/packets-per-rwqe] %-3s\n"
#define FORMAT_RING_INTERRUPT  "%-20s %zu / %zu [requests/received] %-3s\n"
#define FORMAT_RING_MODERATION "%-20s %u / %u [frames/usec period]\n"
#define FORMAT_RING_DM_STATS   "%-20s %zu / %zu / %zu [kilobytes/packets/oob] %-3s\n"
#define FORMAT_RING_MASTER     "%-20s %p\n"

#define INTERVAL                1
#define BYTES_TRAFFIC_UNIT      e_K
#define SCREEN_SIZE             24
#define MAX_BUFF_SIZE           256
#define PRINT_DETAILS_MODES_NUM 2
#define VIEW_MODES_NUM          5
#define DEFAULT_DELAY_SEC       1
#define DEFAULT_CYCLES          0
#define DEFAULT_VIEW_MODE       e_basic
#define DEFAULT_DETAILS_MODE    e_totals
#define DEFAULT_PROC_IDENT_MODE e_by_runn_proccess
#define VLOG_DETAILS_NUM        4
#define NANO_TO_MICRO(n)        (((n) + 500) / 1000)
#define SEC_TO_MICRO(n)         ((n)*1000000)
#define TIME_DIFF_in_MICRO(start, end)                                                             \
    (SEC_TO_MICRO((end).tv_sec - (start).tv_sec) + (NANO_TO_MICRO((end).tv_nsec - (start).tv_nsec)))

bool g_b_exit = false;
struct sigaction g_sigact;
uint8_t *g_fd_mask;
uint32_t g_fd_map_size = e_K;

// statistic file
FILE *g_stats_file = stdout;

extern user_params_t user_params;

void usage(const char *argv0)
{
    printf("\n" PRODUCT_NAME " Statistics\n");
    printf("Usage:\n");
    printf("\t%s [-p pid] [-k directory] [-v view] [-d details] [-i interval] \n", argv0);
    printf("\n");
    printf("Defaults:\n");
    printf("\tfind_pid=enabled, directory=\"%s\", view=1, details=1, interval=1, \n",
           MCE_DEFAULT_STATS_SHMEM_DIR);
    printf("\n");
    printf("Options:\n");
    printf("  -p, --pid=<pid>\t\tShow " PRODUCT_NAME " statistics for process with pid: <pid>\n");
    printf("  -k, --directory=<directory>\tSet shared memory directory path to <directory>\n");
    printf("  -n, --name=<application>\tShow " PRODUCT_NAME
           " statistics for application: <application>\n");
    printf("  -f, --find_pid\t\tFind and show statistics for " PRODUCT_NAME
           " instance running (default)\n");
    printf("  -F, --forbid_clean\t\tBy setting this flag inactive shared objects would not be "
           "removed\n");
    printf("  -i, --interval=<n>\t\tPrint report every <n> seconds\n");
    printf("  -c, --cycles=<n>\t\tDo <n> report print cycles and exit, use 0 value for infinite "
           "(default)\n");
    printf("  -v, --view=<1|2|3|4|5>\tSet view type:1- basic info,2- extra info,3- full info,4- mc "
           "groups,5- similar to 'netstat -tunaep'\n");
    printf("  -d, --details=<1|2>\t\tSet details mode:1- to see totals,2- to see deltas\t\t\n");
    printf("  -z, --zero\t\t\tZero counters\n");
    printf(
        "  -l, --log_level=<level>\tSet " PRODUCT_NAME
        " log level to <level>(one of: none/panic/error/warn/info/details/debug/fine/finer/all)\n");
    printf("  -S, --fd_dump=<fd> [<level>]\tDump statistics for fd number <fd> using log level "
           "<level>. use 0 value for all open fds.\n");
    printf("  -D, --details_level=<level>\tSet " PRODUCT_NAME
           " log details level to <level>(0 <= level <= 3)\n");
    printf("  -s, --sockets=<list|range>\tLog only sockets that match <list> or <range>, format: "
           "4-16 or 1,9 (or combination)\n");
    printf("  -C, --csv_file=<file path>\tA path to the statics CSV file\n");
    printf("  -V, --version\t\t\tPrint version\n");
    printf("  -h, --help\t\t\tPrint this help message\n");
}

void update_delta_stat(socket_stats_t *p_curr_stat, socket_stats_t *p_prev_stat)
{
    int delay = user_params.interval;
    p_prev_stat->counters.n_tx_sent_byte_count =
        (p_curr_stat->counters.n_tx_sent_byte_count - p_prev_stat->counters.n_tx_sent_byte_count) /
        delay;
    p_prev_stat->counters.n_tx_sent_pkt_count =
        (p_curr_stat->counters.n_tx_sent_pkt_count - p_prev_stat->counters.n_tx_sent_pkt_count) /
        delay;
    p_prev_stat->counters.n_tx_eagain =
        (p_curr_stat->counters.n_tx_eagain - p_prev_stat->counters.n_tx_eagain) / delay;
    p_prev_stat->counters.n_tx_errors =
        (p_curr_stat->counters.n_tx_errors - p_prev_stat->counters.n_tx_errors) / delay;
    p_prev_stat->counters.n_tx_dummy =
        (p_curr_stat->counters.n_tx_dummy - p_prev_stat->counters.n_tx_dummy) / delay;
    p_prev_stat->counters.n_tx_os_bytes =
        (p_curr_stat->counters.n_tx_os_bytes - p_prev_stat->counters.n_tx_os_bytes) / delay;
    p_prev_stat->counters.n_tx_os_packets =
        (p_curr_stat->counters.n_tx_os_packets - p_prev_stat->counters.n_tx_os_packets) / delay;
    p_prev_stat->counters.n_tx_os_eagain =
        (p_curr_stat->counters.n_tx_os_eagain - p_prev_stat->counters.n_tx_os_eagain) / delay;
    p_prev_stat->counters.n_tx_os_errors =
        (p_curr_stat->counters.n_tx_os_errors - p_prev_stat->counters.n_tx_os_errors) / delay;
    p_prev_stat->counters.n_rx_bytes =
        (p_curr_stat->counters.n_rx_bytes - p_prev_stat->counters.n_rx_bytes) / delay;
    p_prev_stat->counters.n_rx_packets =
        (p_curr_stat->counters.n_rx_packets - p_prev_stat->counters.n_rx_packets) / delay;
    p_prev_stat->counters.n_rx_data_pkts =
        (p_curr_stat->counters.n_rx_data_pkts - p_prev_stat->counters.n_rx_data_pkts) / delay;
    p_prev_stat->counters.n_rx_frags =
        (p_curr_stat->counters.n_rx_frags - p_prev_stat->counters.n_rx_frags) / delay;
    p_prev_stat->counters.n_rx_eagain =
        (p_curr_stat->counters.n_rx_eagain - p_prev_stat->counters.n_rx_eagain) / delay;
    p_prev_stat->counters.n_rx_errors =
        (p_curr_stat->counters.n_rx_errors - p_prev_stat->counters.n_rx_errors) / delay;
    p_prev_stat->counters.n_rx_os_bytes =
        (p_curr_stat->counters.n_rx_os_bytes - p_prev_stat->counters.n_rx_os_bytes) / delay;
    p_prev_stat->counters.n_rx_os_packets =
        (p_curr_stat->counters.n_rx_os_packets - p_prev_stat->counters.n_rx_os_packets) / delay;
    p_prev_stat->counters.n_rx_os_eagain =
        (p_curr_stat->counters.n_rx_os_eagain - p_prev_stat->counters.n_rx_os_eagain) / delay;
    p_prev_stat->counters.n_rx_os_errors =
        (p_curr_stat->counters.n_rx_os_errors - p_prev_stat->counters.n_rx_os_errors) / delay;
    p_prev_stat->counters.n_rx_poll_miss =
        (p_curr_stat->counters.n_rx_poll_miss - p_prev_stat->counters.n_rx_poll_miss) / delay;
    p_prev_stat->counters.n_rx_poll_hit =
        (p_curr_stat->counters.n_rx_poll_hit - p_prev_stat->counters.n_rx_poll_hit) / delay;
    p_prev_stat->n_rx_ready_byte_count = p_curr_stat->n_rx_ready_byte_count;
    p_prev_stat->n_tx_ready_byte_count = p_curr_stat->n_tx_ready_byte_count;
    p_prev_stat->counters.n_rx_ready_byte_max = p_curr_stat->counters.n_rx_ready_byte_max;
    p_prev_stat->counters.n_rx_ready_byte_drop =
        (p_curr_stat->counters.n_rx_ready_byte_drop - p_prev_stat->counters.n_rx_ready_byte_drop) /
        delay;
    p_prev_stat->counters.n_rx_ready_pkt_drop =
        (p_curr_stat->counters.n_rx_ready_pkt_drop - p_prev_stat->counters.n_rx_ready_pkt_drop) /
        delay;
    p_prev_stat->n_rx_ready_pkt_count = p_curr_stat->n_rx_ready_pkt_count;
    p_prev_stat->counters.n_rx_ready_pkt_max = p_curr_stat->counters.n_rx_ready_pkt_max;
    p_prev_stat->strq_counters.n_strq_total_strides =
        (p_curr_stat->strq_counters.n_strq_total_strides -
         p_prev_stat->strq_counters.n_strq_total_strides) /
        delay;
    p_prev_stat->strq_counters.n_strq_max_strides_per_packet =
        p_curr_stat->strq_counters.n_strq_max_strides_per_packet;

#ifdef DEFINED_UTLS
    p_prev_stat->tls_counters.n_tls_tx_records =
        (p_curr_stat->tls_counters.n_tls_tx_records - p_prev_stat->tls_counters.n_tls_tx_records) /
        delay;
    p_prev_stat->tls_counters.n_tls_tx_bytes =
        (p_curr_stat->tls_counters.n_tls_tx_bytes - p_prev_stat->tls_counters.n_tls_tx_bytes) /
        delay;
    p_prev_stat->tls_counters.n_tls_tx_resync =
        (p_curr_stat->tls_counters.n_tls_tx_resync - p_prev_stat->tls_counters.n_tls_tx_resync) /
        delay;
    p_prev_stat->tls_counters.n_tls_tx_resync_replay =
        (p_curr_stat->tls_counters.n_tls_tx_resync_replay -
         p_prev_stat->tls_counters.n_tls_tx_resync_replay) /
        delay;
    p_prev_stat->tls_counters.n_tls_rx_records =
        (p_curr_stat->tls_counters.n_tls_rx_records - p_prev_stat->tls_counters.n_tls_rx_records) /
        delay;
    p_prev_stat->tls_counters.n_tls_rx_records_enc =
        (p_curr_stat->tls_counters.n_tls_rx_records_enc -
         p_prev_stat->tls_counters.n_tls_rx_records_enc) /
        delay;
    p_prev_stat->tls_counters.n_tls_rx_records_partial =
        (p_curr_stat->tls_counters.n_tls_rx_records_partial -
         p_prev_stat->tls_counters.n_tls_rx_records_partial) /
        delay;
    p_prev_stat->tls_counters.n_tls_rx_bytes =
        (p_curr_stat->tls_counters.n_tls_rx_bytes - p_prev_stat->tls_counters.n_tls_rx_bytes) /
        delay;
    p_prev_stat->tls_counters.n_tls_rx_resync =
        (p_curr_stat->tls_counters.n_tls_rx_resync - p_prev_stat->tls_counters.n_tls_rx_resync) /
        delay;
#endif /* DEFINED_UTLS */

    p_prev_stat->threadid_last_rx = p_curr_stat->threadid_last_rx;
    p_prev_stat->threadid_last_tx = p_curr_stat->threadid_last_tx;

    p_prev_stat->counters.n_rx_migrations =
        (p_curr_stat->counters.n_rx_migrations - p_prev_stat->counters.n_rx_migrations) / delay;
    p_prev_stat->counters.n_tx_migrations =
        (p_curr_stat->counters.n_tx_migrations - p_prev_stat->counters.n_tx_migrations) / delay;
    p_prev_stat->counters.n_tx_retransmits =
        (p_curr_stat->counters.n_tx_retransmits - p_prev_stat->counters.n_tx_retransmits) / delay;
    p_prev_stat->counters.n_tx_sendfile_fallbacks =
        (p_curr_stat->counters.n_tx_sendfile_fallbacks -
         p_prev_stat->counters.n_tx_sendfile_fallbacks) /
        delay;
    p_prev_stat->counters.n_tx_sendfile_overflows =
        (p_curr_stat->counters.n_tx_sendfile_overflows -
         p_prev_stat->counters.n_tx_sendfile_overflows) /
        delay;

    p_prev_stat->listen_counters.n_rx_syn =
        (p_curr_stat->listen_counters.n_rx_syn - p_prev_stat->listen_counters.n_rx_syn) / delay;
    p_prev_stat->listen_counters.n_rx_syn_tw =
        (p_curr_stat->listen_counters.n_rx_syn_tw - p_prev_stat->listen_counters.n_rx_syn_tw) /
        delay;
    p_prev_stat->listen_counters.n_rx_fin =
        (p_curr_stat->listen_counters.n_rx_fin - p_prev_stat->listen_counters.n_rx_fin) / delay;
    p_prev_stat->listen_counters.n_conn_established =
        (p_curr_stat->listen_counters.n_conn_established -
         p_prev_stat->listen_counters.n_conn_established) /
        delay;
    p_prev_stat->listen_counters.n_conn_accepted = (p_curr_stat->listen_counters.n_conn_accepted -
                                                    p_prev_stat->listen_counters.n_conn_accepted) /
        delay;
    p_prev_stat->listen_counters.n_conn_dropped = (p_curr_stat->listen_counters.n_conn_dropped -
                                                   p_prev_stat->listen_counters.n_conn_dropped) /
        delay;
}

void update_delta_iomux_stat(iomux_func_stats_t *p_curr_stats, iomux_func_stats_t *p_prev_stats)
{
    int delay = user_params.interval;
    if (p_curr_stats && p_prev_stats) {
        p_prev_stats->n_iomux_errors =
            (p_curr_stats->n_iomux_errors - p_prev_stats->n_iomux_errors) / delay;
        p_prev_stats->n_iomux_os_rx_ready =
            (p_curr_stats->n_iomux_os_rx_ready - p_prev_stats->n_iomux_os_rx_ready) / delay;
        p_prev_stats->n_iomux_poll_hit =
            (p_curr_stats->n_iomux_poll_hit - p_prev_stats->n_iomux_poll_hit) / delay;
        p_prev_stats->n_iomux_poll_miss =
            (p_curr_stats->n_iomux_poll_miss - p_prev_stats->n_iomux_poll_miss) / delay;
        p_prev_stats->n_iomux_rx_ready =
            (p_curr_stats->n_iomux_rx_ready - p_prev_stats->n_iomux_rx_ready) / delay;
        p_prev_stats->n_iomux_timeouts =
            (p_curr_stats->n_iomux_timeouts - p_prev_stats->n_iomux_timeouts) / delay;
        p_prev_stats->threadid_last = p_curr_stats->threadid_last;
    }
}

void update_delta_hwq_tx_stat(hw_queue_tx_stats_t *p_curr_hwq_tx_stats,
                              hw_queue_tx_stats_t *p_prev_hwq_tx_stats)
{
    int delay = user_params.interval;
    p_prev_hwq_tx_stats->n_tx_byte_count =
        (p_curr_hwq_tx_stats->n_tx_byte_count - p_prev_hwq_tx_stats->n_tx_byte_count) / delay;
    p_prev_hwq_tx_stats->n_tx_pkt_count =
        (p_curr_hwq_tx_stats->n_tx_pkt_count - p_prev_hwq_tx_stats->n_tx_pkt_count) / delay;
    p_prev_hwq_tx_stats->n_tx_tso_pkt_count =
        (p_curr_hwq_tx_stats->n_tx_tso_pkt_count - p_prev_hwq_tx_stats->n_tx_tso_pkt_count) / delay;
    p_prev_hwq_tx_stats->n_tx_tso_byte_count =
        (p_curr_hwq_tx_stats->n_tx_tso_byte_count - p_prev_hwq_tx_stats->n_tx_tso_byte_count) /
        delay;
    p_prev_hwq_tx_stats->n_tx_interrupt_received = (p_curr_hwq_tx_stats->n_tx_interrupt_received -
                                                    p_prev_hwq_tx_stats->n_tx_interrupt_received) /
        delay;
    p_prev_hwq_tx_stats->n_tx_interrupt_requests = (p_curr_hwq_tx_stats->n_tx_interrupt_requests -
                                                    p_prev_hwq_tx_stats->n_tx_interrupt_requests) /
        delay;
}

void update_delta_hwq_rx_stat(hw_queue_rx_stats_t *p_curr_hwq_rx_stats,
                              hw_queue_rx_stats_t *p_prev_hwq_rx_stats)
{
    int delay = user_params.interval;
    p_prev_hwq_rx_stats->n_rx_byte_count =
        (p_curr_hwq_rx_stats->n_rx_byte_count - p_prev_hwq_rx_stats->n_rx_byte_count) / delay;
    p_prev_hwq_rx_stats->n_rx_pkt_count =
        (p_curr_hwq_rx_stats->n_rx_pkt_count - p_prev_hwq_rx_stats->n_rx_pkt_count) / delay;
    p_prev_hwq_rx_stats->n_rx_lro_packets =
        (p_curr_hwq_rx_stats->n_rx_lro_packets - p_prev_hwq_rx_stats->n_rx_lro_packets) / delay;
    p_prev_hwq_rx_stats->n_rx_lro_bytes =
        (p_curr_hwq_rx_stats->n_rx_lro_bytes - p_prev_hwq_rx_stats->n_rx_lro_bytes) / delay;
    p_prev_hwq_rx_stats->n_rx_gro_packets =
        (p_curr_hwq_rx_stats->n_rx_gro_packets - p_prev_hwq_rx_stats->n_rx_gro_packets) / delay;
    p_prev_hwq_rx_stats->n_rx_gro_frags =
        (p_curr_hwq_rx_stats->n_rx_gro_frags - p_prev_hwq_rx_stats->n_rx_gro_frags) / delay;
    p_prev_hwq_rx_stats->n_rx_gro_bytes =
        (p_curr_hwq_rx_stats->n_rx_gro_bytes - p_prev_hwq_rx_stats->n_rx_gro_bytes) / delay;
    p_prev_hwq_rx_stats->n_rx_buffer_pool_len = p_curr_hwq_rx_stats->n_rx_buffer_pool_len;
    p_prev_hwq_rx_stats->n_rx_task_error =
        (p_curr_hwq_rx_stats->n_rx_task_error - p_prev_hwq_rx_stats->n_rx_task_error) / delay;
    p_prev_hwq_rx_stats->n_rx_drained_at_once_max = p_curr_hwq_rx_stats->n_rx_drained_at_once_max;
    p_prev_hwq_rx_stats->n_rx_interrupt_received = (p_curr_hwq_rx_stats->n_rx_interrupt_received -
                                                    p_prev_hwq_rx_stats->n_rx_interrupt_received) /
        delay;
    p_prev_hwq_rx_stats->n_rx_interrupt_requests = (p_curr_hwq_rx_stats->n_rx_interrupt_requests -
                                                    p_prev_hwq_rx_stats->n_rx_interrupt_requests) /
        delay;
    p_prev_hwq_rx_stats->n_rx_cq_moderation_count = p_curr_hwq_rx_stats->n_rx_cq_moderation_count;
    p_prev_hwq_rx_stats->n_rx_cq_moderation_period = p_curr_hwq_rx_stats->n_rx_cq_moderation_period;
}

void update_delta_ring_stat(ring_stats_t *p_curr_ring_stats, ring_stats_t *p_prev_ring_stats)
{
    int delay = user_params.interval;
    if (p_curr_ring_stats && p_prev_ring_stats) {
        p_prev_ring_stats->n_tx_retransmits =
            (p_curr_ring_stats->n_tx_retransmits - p_prev_ring_stats->n_tx_retransmits) / delay;
        p_prev_ring_stats->n_tx_dropped_wqes =
            (p_curr_ring_stats->n_tx_dropped_wqes - p_prev_ring_stats->n_tx_dropped_wqes) / delay;
        p_prev_ring_stats->n_tx_num_bufs =
            (p_curr_ring_stats->n_tx_num_bufs - p_prev_ring_stats->n_tx_num_bufs) / delay;
        p_prev_ring_stats->n_zc_num_bufs =
            (p_curr_ring_stats->n_zc_num_bufs - p_prev_ring_stats->n_zc_num_bufs) / delay;
#ifdef DEFINED_UTLS
        p_prev_ring_stats->n_tx_tls_contexts =
            (p_curr_ring_stats->n_tx_tls_contexts - p_prev_ring_stats->n_tx_tls_contexts) / delay;
        p_prev_ring_stats->n_rx_tls_contexts =
            (p_curr_ring_stats->n_rx_tls_contexts - p_prev_ring_stats->n_rx_tls_contexts) / delay;
#endif /* DEFINED_UTLS */
        p_prev_ring_stats->n_tx_dev_mem_allocated = p_curr_ring_stats->n_tx_dev_mem_allocated;
        p_prev_ring_stats->n_tx_dev_mem_byte_count = (p_curr_ring_stats->n_tx_dev_mem_byte_count -
                                                      p_prev_ring_stats->n_tx_dev_mem_byte_count) /
            delay;
        p_prev_ring_stats->n_tx_dev_mem_pkt_count = (p_curr_ring_stats->n_tx_dev_mem_pkt_count -
                                                     p_prev_ring_stats->n_tx_dev_mem_pkt_count) /
            delay;
        p_prev_ring_stats->n_tx_dev_mem_oob =
            (p_curr_ring_stats->n_tx_dev_mem_oob - p_prev_ring_stats->n_tx_dev_mem_oob) / delay;
    }
}

void update_delta_cq_stat(cq_stats_t *p_curr_cq_stats, cq_stats_t *p_prev_cq_stats)
{
    int delay = user_params.interval;
    if (p_curr_cq_stats && p_prev_cq_stats) {
        p_prev_cq_stats->n_rx_pkt_drop =
            (p_curr_cq_stats->n_rx_pkt_drop - p_prev_cq_stats->n_rx_pkt_drop) / delay;
        p_prev_cq_stats->n_rx_sw_queue_len = p_curr_cq_stats->n_rx_sw_queue_len;
        p_prev_cq_stats->n_rx_consumed_rwqe_count = (p_curr_cq_stats->n_rx_consumed_rwqe_count -
                                                     p_prev_cq_stats->n_rx_consumed_rwqe_count) /
            delay;
        p_prev_cq_stats->n_rx_stride_count =
            (p_curr_cq_stats->n_rx_stride_count - p_prev_cq_stats->n_rx_stride_count) / delay;
        p_prev_cq_stats->n_rx_packet_count =
            (p_curr_cq_stats->n_rx_packet_count - p_prev_cq_stats->n_rx_packet_count) / delay;
        p_prev_cq_stats->n_rx_max_stirde_per_packet = p_curr_cq_stats->n_rx_max_stirde_per_packet;
    }
}

void update_delta_bpool_stat(bpool_stats_t *p_curr_bpool_stats, bpool_stats_t *p_prev_bpool_stats)
{
    int delay = user_params.interval;
    if (p_curr_bpool_stats && p_prev_bpool_stats) {
        p_prev_bpool_stats->n_buffer_pool_size = p_curr_bpool_stats->n_buffer_pool_size;
        p_prev_bpool_stats->n_buffer_pool_no_bufs = (p_curr_bpool_stats->n_buffer_pool_no_bufs -
                                                     p_prev_bpool_stats->n_buffer_pool_no_bufs) /
            delay;
    }
}

void update_delta_global_stat(global_stats_t *p_curr_global_stats,
                              global_stats_t *p_prev_global_stats)
{
    int delay = user_params.interval;
    if (p_curr_global_stats && p_prev_global_stats) {
        p_prev_global_stats->n_tcp_seg_pool_size = p_curr_global_stats->n_tcp_seg_pool_size;
        p_prev_global_stats->n_tcp_seg_pool_no_segs =
            (p_curr_global_stats->n_tcp_seg_pool_no_segs -
             p_prev_global_stats->n_tcp_seg_pool_no_segs) /
            delay;
        p_prev_global_stats->n_lso_metadata_pool_size =
            p_curr_global_stats->n_lso_metadata_pool_size;
        p_prev_global_stats->n_lso_metadata_pool_no_segs =
            (p_curr_global_stats->n_lso_metadata_pool_no_segs -
             p_prev_global_stats->n_lso_metadata_pool_no_segs) /
            delay;
        p_prev_global_stats->n_pending_sockets =
            (p_curr_global_stats->n_pending_sockets - p_prev_global_stats->n_pending_sockets) /
            delay;
        p_prev_global_stats->socket_tcp_destructor_counter =
            (p_curr_global_stats->socket_tcp_destructor_counter.load() -
             p_prev_global_stats->socket_tcp_destructor_counter.load()) /
            delay;
        p_prev_global_stats->socket_udp_destructor_counter =
            (p_curr_global_stats->socket_udp_destructor_counter.load() -
             p_prev_global_stats->socket_udp_destructor_counter.load()) /
            delay;
    }
}

void print_ring_stats(ring_instance_block_t *p_ring_inst_arr)
{
    char post_fix[3] = "";

    if (user_params.print_details_mode == e_deltas) {
        strcpy(post_fix, "/s");
    }

    for (int i = 0; i < NUM_OF_SUPPORTED_RINGS; i++) {
        // coverity[missing_lock:FALSE] /* Turn off coverity missing_lock check*/
        if (p_ring_inst_arr[i].b_enabled) {
            ring_stats_t *p_ring_stats = &p_ring_inst_arr[i].ring_stats;
            hw_queue_tx_stats_t *p_hwq_tx_stats = &p_ring_inst_arr[i].hwq_tx_stats;
            hw_queue_rx_stats_t *p_hwq_rx_stats = &p_ring_inst_arr[i].hwq_rx_stats;
            printf("======================================================\n");
            printf("\tETH=[%u]\n", i);

            if (p_ring_stats->p_ring_master) {
                printf(FORMAT_RING_MASTER, "Master:", p_ring_stats->p_ring_master);
            }

            printf(FORMAT_RING_PACKETS,
                   "TX Offload:", p_hwq_tx_stats->n_tx_byte_count / BYTES_TRAFFIC_UNIT,
                   p_hwq_tx_stats->n_tx_pkt_count, post_fix);

            if (p_hwq_tx_stats->n_tx_tso_pkt_count || p_hwq_tx_stats->n_tx_tso_byte_count) {
                printf(FORMAT_RING_PACKETS,
                       "TX TSO Offload:", p_hwq_tx_stats->n_tx_tso_byte_count / BYTES_TRAFFIC_UNIT,
                       p_hwq_tx_stats->n_tx_tso_pkt_count, post_fix);
            }

            if (p_ring_stats->n_tx_retransmits) {
                printf(FORMAT_STATS_64bit, "TX Retransmissions:", p_ring_stats->n_tx_retransmits,
                       post_fix);
            }

            if (p_ring_stats->n_tx_dropped_wqes) {
                printf(FORMAT_STATS_64bit, "TX Dropped Reqs:", p_ring_stats->n_tx_dropped_wqes,
                       post_fix);
            }

            printf(FORMAT_STATS_32bit, "TX buff in use:", p_ring_stats->n_tx_num_bufs);
            printf(FORMAT_STATS_32bit, "TX ZC buff in use:", p_ring_stats->n_zc_num_bufs);

            if (p_hwq_tx_stats->n_tx_interrupt_requests ||
                p_hwq_tx_stats->n_tx_interrupt_received) {
                printf(FORMAT_RING_INTERRUPT,
                       "TX Interrupts:", p_hwq_tx_stats->n_tx_interrupt_requests,
                       p_hwq_tx_stats->n_tx_interrupt_received, post_fix);
            }

            if (p_ring_stats->n_tx_dev_mem_allocated) {
                printf(FORMAT_STATS_32bit,
                       "TX Dev Mem Alloc:", p_ring_stats->n_tx_dev_mem_allocated);
                printf(
                    FORMAT_RING_DM_STATS,
                    "TX Dev Mem Stats:", p_ring_stats->n_tx_dev_mem_byte_count / BYTES_TRAFFIC_UNIT,
                    p_ring_stats->n_tx_dev_mem_pkt_count, p_ring_stats->n_tx_dev_mem_oob, post_fix);
            }

            printf(FORMAT_RING_PACKETS,
                   "RX Offload:", p_hwq_rx_stats->n_rx_byte_count / BYTES_TRAFFIC_UNIT,
                   p_hwq_rx_stats->n_rx_pkt_count, post_fix);

            if (p_hwq_rx_stats->n_rx_lro_packets) {
                printf(FORMAT_RING_PACKETS,
                       "RX LRO Offload:", p_hwq_rx_stats->n_rx_lro_bytes / BYTES_TRAFFIC_UNIT,
                       p_hwq_rx_stats->n_rx_lro_packets, post_fix);
            }

            if (p_hwq_rx_stats->n_rx_gro_packets) {
                printf(FORMAT_RING_PACKETS,
                       "RX GRO:", p_hwq_rx_stats->n_rx_gro_bytes / BYTES_TRAFFIC_UNIT,
                       p_hwq_rx_stats->n_rx_gro_packets, post_fix);
                printf(FORMAT_STATS_64bit, "RX GRO avg pkt size:",
                       p_hwq_rx_stats->n_rx_gro_bytes / p_hwq_rx_stats->n_rx_gro_packets, post_fix);
                printf(FORMAT_STATS_double, "RX GRO frags/pkt:",
                       static_cast<double>(p_hwq_rx_stats->n_rx_gro_frags) /
                           p_hwq_rx_stats->n_rx_gro_packets);
            }

            if (p_hwq_rx_stats->n_rx_interrupt_requests ||
                p_hwq_rx_stats->n_rx_interrupt_received) {
                printf(FORMAT_RING_INTERRUPT,
                       "RX Interrupts:", p_hwq_rx_stats->n_rx_interrupt_requests,
                       p_hwq_rx_stats->n_rx_interrupt_received, post_fix);
            }

            if (p_hwq_rx_stats->n_rx_cq_moderation_count ||
                p_hwq_rx_stats->n_rx_cq_moderation_period) {
                printf(FORMAT_RING_MODERATION,
                       "RX Moderation:", p_hwq_rx_stats->n_rx_cq_moderation_count,
                       p_hwq_rx_stats->n_rx_cq_moderation_period);
            }

            if (p_hwq_rx_stats->n_rx_drained_at_once_max) {
                printf(FORMAT_STATS_32bit,
                       "RX Drained max:", p_hwq_rx_stats->n_rx_drained_at_once_max);
            }

            if (p_hwq_rx_stats->n_rx_task_error) {
                printf(FORMAT_STATS_64bit, "RX Task errors:", p_hwq_rx_stats->n_rx_task_error,
                       post_fix);
            }

            printf(FORMAT_STATS_32bit,
                   "RX Buffer pool size:", p_hwq_rx_stats->n_rx_buffer_pool_len);

#ifdef DEFINED_UTLS
            if (p_ring_stats->n_tx_tls_contexts) {
                printf(FORMAT_STATS_64bit,
                       "TLS TX Context Setups:", (uint64_t)p_ring_stats->n_tx_tls_contexts,
                       post_fix);
            }
            if (p_ring_stats->n_rx_tls_contexts) {
                printf(FORMAT_STATS_64bit,
                       "TLS RX Context Setups:", (uint64_t)p_ring_stats->n_rx_tls_contexts,
                       post_fix);
            }
#endif /* DEFINED_UTLS */
        }
    }
    printf("======================================================\n");
}

void print_cq_stats(cq_instance_block_t *p_cq_inst_arr)
{
    cq_stats_t *p_cq_stats = NULL;
    char post_fix[3] = "";

    if (user_params.print_details_mode == e_deltas) {
        strcpy(post_fix, "/s");
    }

    for (int i = 0; i < NUM_OF_SUPPORTED_CQS; i++) {
        // coverity[missing_lock:FALSE] /* Turn off coverity missing_lock check*/
        if (p_cq_inst_arr[i].b_enabled) {
            p_cq_stats = &p_cq_inst_arr[i].cq_stats;
            printf("======================================================\n");
            printf("\tCQ=[%u]\n", i);
            printf(FORMAT_STATS_64bit, "Packets dropped:", p_cq_stats->n_rx_pkt_drop, post_fix);
            printf(FORMAT_STATS_32bit, "Packets queue len:", p_cq_stats->n_rx_sw_queue_len);
            printf(FORMAT_STATS_64bit, "Packets received:", p_cq_stats->n_rx_packet_count,
                   post_fix);
            printf(FORMAT_STATS_64bit, "Strides received:", p_cq_stats->n_rx_stride_count,
                   post_fix);
            printf(FORMAT_STATS_64bit, "Consumed rwqes:", p_cq_stats->n_rx_consumed_rwqe_count,
                   post_fix);
            printf(FORMAT_STATS_32bit, "Max strides/packet:",
                   static_cast<uint32_t>(p_cq_stats->n_rx_max_stirde_per_packet));
            printf(FORMAT_STATS_double, "Avg strides/packet:",
                   p_cq_stats->n_rx_stride_count /
                       static_cast<double>(p_cq_stats->n_rx_packet_count + 1U));
            printf(FORMAT_STATS_double, "Avg packets/rwqe:",
                   p_cq_stats->n_rx_packet_count /
                       static_cast<double>(p_cq_stats->n_rx_consumed_rwqe_count + 1U));
        }
    }
    printf("======================================================\n");
}

void print_bpool_stats(bpool_instance_block_t *p_bpool_inst_arr)
{
    bpool_stats_t *p_bpool_stats = NULL;
    char post_fix[3] = "";

    if (user_params.print_details_mode == e_deltas) {
        strcpy(post_fix, "/s");
    }

    for (int i = 0; i < NUM_OF_SUPPORTED_BPOOLS; i++) {
        // coverity[missing_lock:FALSE] /* Turn off coverity missing_lock check*/
        if (p_bpool_inst_arr && p_bpool_inst_arr[i].b_enabled) {
            p_bpool_stats = &p_bpool_inst_arr[i].bpool_stats;
            printf("======================================================\n");
            if (p_bpool_stats->is_rx) {
                printf("\tBUFFER_POOL(RX)=[%u]\n", i);
            } else if (p_bpool_stats->is_tx) {
                printf("\tBUFFER_POOL(TX)=[%u]\n", i);
            } else {
                printf("\tBUFFER_POOL=[%u]\n", i);
            }
            printf(FORMAT_STATS_32bit, "Size:", p_bpool_stats->n_buffer_pool_size);
            printf(FORMAT_STATS_32bit, "Buffers in use:",
                   p_bpool_stats->n_buffer_pool_created - p_bpool_stats->n_buffer_pool_size);
            printf(FORMAT_STATS_32bit, "No buffers error:", p_bpool_stats->n_buffer_pool_no_bufs);
            if (p_bpool_stats->n_buffer_pool_expands) {
                printf(FORMAT_STATS_32bit, "Expands:", p_bpool_stats->n_buffer_pool_expands);
            }
        }
    }
    printf("======================================================\n");
}

void print_global_stats(global_instance_block_t *p_global_inst_arr)
{
    global_stats_t *p_global_stats = NULL;
    char post_fix[3] = "";

    if (user_params.print_details_mode == e_deltas) {
        strcpy(post_fix, "/s");
    }

    for (int i = 0; i < NUM_OF_SUPPORTED_GLOBALS; i++) {
        if (p_global_inst_arr && p_global_inst_arr[i].b_enabled) {
            p_global_stats = &p_global_inst_arr[i].global_stats;
            printf("======================================================\n");
            printf("\tTCP_SEG_POOL\n");
            printf(FORMAT_STATS_32bit, "Size:", p_global_stats->n_tcp_seg_pool_size);
            printf(FORMAT_STATS_32bit,
                   "No segments error:", p_global_stats->n_tcp_seg_pool_no_segs);
            printf("======================================================\n");
            printf("\tLSO_METADATA_POOL\n");
            printf(FORMAT_STATS_32bit, "Size:", p_global_stats->n_lso_metadata_pool_size);
            printf(FORMAT_STATS_32bit,
                   "No segments error:", p_global_stats->n_lso_metadata_pool_no_segs);
            printf("======================================================\n");
            printf("\tGLOBAL\n");
            printf(FORMAT_STATS_s_32bit, "Pending sockets:", p_global_stats->n_pending_sockets);
            printf(FORMAT_STATS_s_32bit,
                   "Destructed TCP sockets:", p_global_stats->socket_tcp_destructor_counter.load());
            printf(FORMAT_STATS_s_32bit,
                   "Destructed UDP sockets:", p_global_stats->socket_udp_destructor_counter.load());
        }
    }
    printf("======================================================\n");
}

void print_basic_stats(socket_stats_t *p_stats)
{
    //
    // Socket statistics
    //
    double rx_poll_hit_percentage = 0;

    if (p_stats->counters.n_rx_poll_hit) {
        double rx_poll_hit = (double)p_stats->counters.n_rx_poll_hit;
        rx_poll_hit_percentage =
            (rx_poll_hit / (rx_poll_hit + (double)p_stats->counters.n_rx_poll_miss)) * 100;
    }
    printf(RX_SHORT_VIEW, p_stats->fd, "Rx:", p_stats->counters.n_rx_packets,
           p_stats->counters.n_rx_bytes / BYTES_TRAFFIC_UNIT, p_stats->counters.n_rx_eagain,
           p_stats->counters.n_rx_errors, rx_poll_hit_percentage, p_stats->counters.n_rx_os_packets,
           p_stats->counters.n_rx_os_bytes / BYTES_TRAFFIC_UNIT, p_stats->counters.n_rx_os_eagain,
           p_stats->counters.n_rx_os_errors);

    printf(TX_SHORT_VIEW, " ", "Tx:", p_stats->counters.n_tx_sent_pkt_count,
           p_stats->counters.n_tx_sent_byte_count / BYTES_TRAFFIC_UNIT,
           p_stats->counters.n_tx_eagain, p_stats->counters.n_tx_errors, " ",
           p_stats->counters.n_tx_os_packets, p_stats->counters.n_tx_os_bytes / BYTES_TRAFFIC_UNIT,
           p_stats->counters.n_tx_os_eagain, p_stats->counters.n_tx_os_errors);
}

void print_medium_total_stats(socket_stats_t *p_stats)
{
    //
    // Socket statistics
    //
    double rx_poll_hit_percentage = 0;

    if (p_stats->counters.n_rx_poll_hit) {
        double rx_poll_hit = (double)p_stats->counters.n_rx_poll_hit;
        rx_poll_hit_percentage =
            (rx_poll_hit / (rx_poll_hit + (double)p_stats->counters.n_rx_poll_miss)) * 100;
    }
    printf(RX_MEDIUM_VIEW, p_stats->fd, "Rx:", p_stats->counters.n_rx_packets,
           p_stats->strq_counters.n_strq_total_strides,
           p_stats->counters.n_rx_bytes / BYTES_TRAFFIC_UNIT, p_stats->counters.n_rx_eagain,
           p_stats->counters.n_rx_errors, rx_poll_hit_percentage, p_stats->n_rx_ready_pkt_count,
           p_stats->counters.n_rx_ready_pkt_max, p_stats->counters.n_rx_ready_pkt_drop,
           p_stats->counters.n_rx_os_packets, p_stats->counters.n_rx_os_bytes / BYTES_TRAFFIC_UNIT,
           p_stats->counters.n_rx_os_eagain, p_stats->counters.n_rx_os_errors);

    printf(TX_MEDIUM_VIEW, " ", "Tx:", p_stats->counters.n_tx_sent_pkt_count, 0U,
           p_stats->counters.n_tx_sent_byte_count / BYTES_TRAFFIC_UNIT,
           p_stats->counters.n_tx_eagain, p_stats->counters.n_tx_errors, " ",
           p_stats->counters.n_tx_os_packets, p_stats->counters.n_tx_os_bytes / BYTES_TRAFFIC_UNIT,
           p_stats->counters.n_tx_os_eagain, p_stats->counters.n_tx_os_errors);
}

void print_basic_delta_stats(socket_stats_t *p_curr_stat, socket_stats_t *p_prev_stat)
{
    update_delta_stat(p_curr_stat, p_prev_stat);
    print_basic_stats(p_prev_stat);
}

void print_medium_delta_stats(socket_stats_t *p_curr_stat, socket_stats_t *p_prev_stat)
{
    update_delta_stat(p_curr_stat, p_prev_stat);
    print_medium_total_stats(p_prev_stat);
}

void print_full_delta_stats(socket_stats_t *p_curr_stat, socket_stats_t *p_prev_stat,
                            mc_grp_info_t *p_mc_grp_info)
{
    update_delta_stat(p_curr_stat, p_prev_stat);
    print_full_stats(p_prev_stat, p_mc_grp_info, g_stats_file);
}

void print_basic_mode_headers()
{
    switch (user_params.print_details_mode) {
    case e_totals:
        printf(UPPER_SHORT_VIEW_HEADER, "fd", "------------ total offloaded -------------",
               "--------- total os ----------");
        printf(LOWER_SHORT_VIEW_HEADER, " ", "pkt", "Kbyte", "eagain", "error", "poll%", "pkt",
               "Kbyte", "eagain", "error");
        break;
    case e_deltas:
        printf(UPPER_SHORT_VIEW_HEADER, "fd", "--------------- offloaded ----------------",
               "---------- os ---------");
        printf(LOWER_SHORT_VIEW_HEADER, " ", "pkt/s", "Kbyte/s", "eagain/s", "error/s", "poll%",
               "pkt/s", "Kbyte/s", "eagain/s", "error/s");
        break;
    default:
        break;
    }
}

void print_medium_mode_headers()
{
    switch (user_params.print_details_mode) {
    case e_totals:
        printf(UPPER_MEDIUM_VIEW_HEADER, "fd",
               "----------------------- total offloaded -------------------------",
               "--------- total os ----------");
        printf(MIDDLE_MEDIUM_VIEW_HEADER, " ", "pkt", "stride", "Kbyte", "eagain", "error", "poll%",
               "---- queue pkt -----", "pkt", "Kbyte", "eagain", "error");
        printf(LOWER_MEDIUM_VIEW_HEADER, " ", "cur", "max", "drop");
        break;
    case e_deltas:
        printf(UPPER_MEDIUM_VIEW_HEADER, "fd",
               "---------------------------- offloaded --------------------------",
               "---------- os ---------");
        printf(MIDDLE_MEDIUM_VIEW_HEADER, " ", "pkt/s", "stride/s", "Kbyte/s", "eagain/s",
               "error/s", "poll%", "----- queue pkt ------", "pkt/s", "Kbyte/s", "eagain/s",
               "error/s");
        printf(LOWER_MEDIUM_VIEW_HEADER, " ", "cur", "max", "drop/s");
        break;
    default:
        break;
    }
}

void print_headers()
{
    switch (user_params.view_mode) {
    case e_basic:
        print_basic_mode_headers();
        break;
    case e_medium:
        print_medium_mode_headers();
        break;
    case e_netstat_like:
        print_netstat_like_headers(g_stats_file);
        break;
    default:
        break;
    }
}

void show_basic_stats(socket_instance_block_t *p_instance,
                      socket_instance_block_t *p_prev_instance_block)
{
    switch (user_params.print_details_mode) {
    case e_totals:
        print_basic_stats(&p_instance->skt_stats);
        break;
    case e_deltas:
        if (p_prev_instance_block) {
            print_basic_delta_stats(&p_instance->skt_stats, &p_prev_instance_block->skt_stats);
        }
        break;
    default:
        break;
    }
}

void print_medium_stats(socket_instance_block_t *p_instance,
                        socket_instance_block_t *p_prev_instance_block)
{
    switch (user_params.print_details_mode) {
    case e_totals:
        print_medium_total_stats(&p_instance->skt_stats);
        break;
    case e_deltas:
        if (p_prev_instance_block) {
            print_medium_delta_stats(&p_instance->skt_stats, &p_prev_instance_block->skt_stats);
        }
        break;
    default:
        break;
    }
}

void show_full_stats(socket_instance_block_t *p_instance,
                     socket_instance_block_t *p_prev_instance_block, mc_grp_info_t *p_mc_grp_info)
{
    switch (user_params.print_details_mode) {
    case e_totals:
        print_full_stats(&p_instance->skt_stats, p_mc_grp_info, g_stats_file);
        break;
    case e_deltas:
        if (p_prev_instance_block) {
            print_full_delta_stats(&p_instance->skt_stats, &p_prev_instance_block->skt_stats,
                                   p_mc_grp_info);
        }
        break;
    default:
        break;
    }
}

int show_socket_stats(socket_instance_block_t *p_instance,
                      socket_instance_block_t *p_prev_instance_block, uint32_t num_of_obj,
                      int *p_printed_lines_num, mc_grp_info_t *p_mc_grp_info, int pid)
{
    int num_act_inst = 0;

    if (*p_printed_lines_num >= SCREEN_SIZE && user_params.view_mode != e_full) {
        print_headers();
        switch (user_params.view_mode) {
        case e_basic:
            *p_printed_lines_num = BASE_HEADERS_NUM;
            break;
        case e_medium:
            *p_printed_lines_num = MEDIUM_HEADERS_NUM;
            break;
        default:
            break;
        }
    }

    for (uint32_t i = 0; i < num_of_obj; i++) {
        size_t fd = (size_t)p_instance[i].skt_stats.fd;
        if (p_instance[i].b_enabled && g_fd_mask[fd]) {
            num_act_inst++;
            switch (user_params.view_mode) {
            case e_basic:
                show_basic_stats(&p_instance[i], &p_prev_instance_block[i]);
                *p_printed_lines_num += BASIC_STATS_LINES_NUM;
                break;
            case e_medium:
                print_medium_stats(&p_instance[i], &p_prev_instance_block[i]);
                *p_printed_lines_num += MEDIUM_STATS_LINES_NUM;
                break;
            case e_full:
                show_full_stats(&p_instance[i], &p_prev_instance_block[i], p_mc_grp_info);
                break;
            case e_netstat_like:
                print_netstat_like(&p_instance[i].skt_stats, p_mc_grp_info, g_stats_file, pid);
                break;
            default:
                break;
            }
        }
    }
    return num_act_inst;
}

// Print statistics for select(), poll(), epoll()
void print_full_iomux_stats(const char *func_name, iomux_func_stats_t *p_iomux_stats)
{
    char post_fix[3] = "";

    if (user_params.print_details_mode == e_deltas) {
        strcpy(post_fix, "/s");
    }

    if (p_iomux_stats &&
        (p_iomux_stats->n_iomux_os_rx_ready || p_iomux_stats->n_iomux_rx_ready ||
         p_iomux_stats->n_iomux_timeouts || p_iomux_stats->n_iomux_errors ||
         p_iomux_stats->n_iomux_poll_miss || p_iomux_stats->n_iomux_poll_hit)) {

        printf("======================================================\n");
        printf("\t%s\n", func_name);
        printf("Polling CPU%s:%d%%\n", post_fix, p_iomux_stats->n_iomux_polling_time);
        if (p_iomux_stats->threadid_last != 0) {
            printf("- Thread Id: %5u\n", p_iomux_stats->threadid_last);
        }
        if (p_iomux_stats->n_iomux_os_rx_ready || p_iomux_stats->n_iomux_rx_ready) {
            printf("Rx fds ready: %u / %u [os/offload]%s\n", p_iomux_stats->n_iomux_os_rx_ready,
                   p_iomux_stats->n_iomux_rx_ready, post_fix);
        }
        if (p_iomux_stats->n_iomux_poll_miss + p_iomux_stats->n_iomux_poll_hit) {
            double iomux_poll_hit = (double)p_iomux_stats->n_iomux_poll_hit;
            double iomux_poll_hit_percentage =
                (iomux_poll_hit / (iomux_poll_hit + (double)p_iomux_stats->n_iomux_poll_miss)) *
                100;
            printf("Polls [miss/hit]%s: %u / %u (%2.2f%%)\n", post_fix,
                   p_iomux_stats->n_iomux_poll_miss, p_iomux_stats->n_iomux_poll_hit,
                   iomux_poll_hit_percentage);
            if (p_iomux_stats->n_iomux_timeouts) {
                printf("Timeouts%s: %u\n", post_fix, p_iomux_stats->n_iomux_timeouts);
            }
            if (p_iomux_stats->n_iomux_errors) {
                printf("Errors%s: %u\n", post_fix, p_iomux_stats->n_iomux_errors);
            }
            printf("======================================================\n");
        }
    }
}

void print_basic_iomux_stats(const char *func_name, iomux_func_stats_t *p_iomux_stats,
                             int *p_printed_lines_num)
{
    double rx_poll_hit_percentage = 0;
    char post_fix[3] = "";

    if (user_params.print_details_mode == e_deltas) {
        strcpy(post_fix, "/s");
    }

    if (p_iomux_stats->n_iomux_poll_hit) {
        double iomux_poll_hit = (double)p_iomux_stats->n_iomux_poll_hit;
        rx_poll_hit_percentage =
            (iomux_poll_hit / (iomux_poll_hit + (double)p_iomux_stats->n_iomux_poll_miss)) * 100;
    }

    if (p_iomux_stats->n_iomux_os_rx_ready || p_iomux_stats->n_iomux_rx_ready ||
        p_iomux_stats->n_iomux_timeouts || p_iomux_stats->n_iomux_errors ||
        p_iomux_stats->n_iomux_poll_miss || p_iomux_stats->n_iomux_poll_hit) {
        printf(IOMUX_FORMAT, func_name, post_fix, "Rx Ready:", p_iomux_stats->n_iomux_os_rx_ready,
               "/", p_iomux_stats->n_iomux_rx_ready, "[os/offload]",
               "Timeouts:", p_iomux_stats->n_iomux_timeouts,
               "Errors:", p_iomux_stats->n_iomux_errors, "Poll:", rx_poll_hit_percentage, "%",
               "Polling CPU:", p_iomux_stats->n_iomux_polling_time, "%");
        (*p_printed_lines_num)++;
    }
}

void print_iomux_totals(iomux_stats_t *p_iomux_stats, int *p_printed_lines_num)
{
    if (p_printed_lines_num) {
        print_basic_iomux_stats("poll", &p_iomux_stats->poll, p_printed_lines_num);
        print_basic_iomux_stats("select", &p_iomux_stats->select, p_printed_lines_num);
    } else {
        print_full_iomux_stats("poll", &p_iomux_stats->poll);
        print_full_iomux_stats("select", &p_iomux_stats->select);
    }
    for (int i = 0; i < NUM_OF_SUPPORTED_EPFDS; i++) {
        epoll_stats_t *ep_stats = &p_iomux_stats->epoll[i];
        if (ep_stats->enabled) {
            char epfd_name[20];
            snprintf(epfd_name, sizeof(epfd_name), "epoll[%d]", ep_stats->epfd);
            if (p_printed_lines_num) {
                print_basic_iomux_stats(epfd_name, &ep_stats->stats, p_printed_lines_num);
            } else {
                print_full_iomux_stats(epfd_name, &ep_stats->stats);
            }
        }
    }
}

void update_iomux_deltas(iomux_stats_t *p_curr_iomux_stats, iomux_stats_t *p_prev_iomux_stats)
{
    update_delta_iomux_stat(&p_curr_iomux_stats->poll, &p_prev_iomux_stats->poll);
    update_delta_iomux_stat(&p_curr_iomux_stats->select, &p_prev_iomux_stats->select);
    for (int i = 0; i < NUM_OF_SUPPORTED_EPFDS; i++) {
        if (p_curr_iomux_stats->epoll[i].enabled && p_prev_iomux_stats->epoll[i].enabled) {
            update_delta_iomux_stat(&p_curr_iomux_stats->epoll[i].stats,
                                    &p_prev_iomux_stats->epoll[i].stats);
        }
    }
}

void print_full_iomux_deltas(iomux_stats_t *p_curr_iomux_stats, iomux_stats_t *p_prev_iomux_stats)
{
    if (unlikely(!p_curr_iomux_stats || !p_prev_iomux_stats)) {
        return;
    }
    update_iomux_deltas(p_curr_iomux_stats, p_prev_iomux_stats);
    print_iomux_totals(p_prev_iomux_stats, NULL);
}

void print_basic_iomux_deltas(iomux_stats_t *p_curr_stats, iomux_stats_t *p_prev_stats,
                              int *p_printed_lines_num)
{
    if (unlikely(!p_curr_stats || !p_prev_stats)) {
        return;
    }
    update_iomux_deltas(p_curr_stats, p_prev_stats);
    print_iomux_totals(p_prev_stats, p_printed_lines_num);
}

void print_full_iomux_stats(iomux_stats_t *p_curr_stats, iomux_stats_t *p_prev_stats)
{
    switch (user_params.print_details_mode) {
    case e_totals:
        print_iomux_totals(p_curr_stats, NULL);
        break;
    default:
        print_full_iomux_deltas(p_curr_stats, p_prev_stats);
        break;
    }
}

void print_ring_deltas(ring_instance_block_t *p_curr_ring_stats,
                       ring_instance_block_t *p_prev_ring_stats)
{
    if (unlikely(!p_curr_ring_stats || !p_prev_ring_stats)) {
        return;
    }
    for (int i = 0; i < NUM_OF_SUPPORTED_RINGS; i++) {
        update_delta_hwq_tx_stat(&p_curr_ring_stats[i].hwq_tx_stats,
                                 &p_prev_ring_stats[i].hwq_tx_stats);
        update_delta_hwq_rx_stat(&p_curr_ring_stats[i].hwq_rx_stats,
                                 &p_prev_ring_stats[i].hwq_rx_stats);
        update_delta_ring_stat(&p_curr_ring_stats[i].ring_stats, &p_prev_ring_stats[i].ring_stats);
    }
    print_ring_stats(p_prev_ring_stats);
}

void print_cq_deltas(cq_instance_block_t *p_curr_cq_stats, cq_instance_block_t *p_prev_cq_stats)
{
    if (unlikely(!p_curr_cq_stats || !p_prev_cq_stats)) {
        return;
    }
    for (int i = 0; i < NUM_OF_SUPPORTED_CQS; i++) {
        update_delta_cq_stat(&p_curr_cq_stats[i].cq_stats, &p_prev_cq_stats[i].cq_stats);
    }
    print_cq_stats(p_prev_cq_stats);
}

void print_bpool_deltas(bpool_instance_block_t *p_curr_bpool_stats,
                        bpool_instance_block_t *p_prev_bpool_stats)
{
    if (unlikely(!p_curr_bpool_stats || !p_prev_bpool_stats)) {
        return;
    }
    for (int i = 0; i < NUM_OF_SUPPORTED_BPOOLS; i++) {
        update_delta_bpool_stat(&p_curr_bpool_stats[i].bpool_stats,
                                &p_prev_bpool_stats[i].bpool_stats);
    }
    print_bpool_stats(p_prev_bpool_stats);
}

void print_global_deltas(global_instance_block_t *p_curr_global_stats,
                         global_instance_block_t *p_prev_global_stats)
{
    for (int i = 0; i < NUM_OF_SUPPORTED_GLOBALS; i++) {
        if (!p_curr_global_stats || !p_prev_global_stats) {
            break;
        }
        update_delta_global_stat(&p_curr_global_stats[i].global_stats,
                                 &p_prev_global_stats[i].global_stats);
    }
    print_global_stats(p_prev_global_stats);
}

void show_ring_stats(ring_instance_block_t *p_curr_ring_blocks,
                     ring_instance_block_t *p_prev_ring_blocks)
{
    switch (user_params.print_details_mode) {
    case e_totals:
        print_ring_stats(p_curr_ring_blocks);
        break;
    default:
        print_ring_deltas(p_curr_ring_blocks, p_prev_ring_blocks);
        break;
    }
}

void show_cq_stats(cq_instance_block_t *p_curr_cq_blocks, cq_instance_block_t *p_prev_cq_blocks)
{
    switch (user_params.print_details_mode) {
    case e_totals:
        print_cq_stats(p_curr_cq_blocks);
        break;
    default:
        print_cq_deltas(p_curr_cq_blocks, p_prev_cq_blocks);
        break;
    }
}

void show_bpool_stats(bpool_instance_block_t *p_curr_bpool_blocks,
                      bpool_instance_block_t *p_prev_bpool_blocks)
{
    switch (user_params.print_details_mode) {
    case e_totals:
        print_bpool_stats(p_curr_bpool_blocks);
        break;
    default:
        print_bpool_deltas(p_curr_bpool_blocks, p_prev_bpool_blocks);
        break;
    }
}

void show_global_stats(global_instance_block_t *p_curr_global_blocks,
                       global_instance_block_t *p_prev_global_blocks)
{
    switch (user_params.print_details_mode) {
    case e_totals:
        print_global_stats(p_curr_global_blocks);
        break;
    default:
        print_global_deltas(p_curr_global_blocks, p_prev_global_blocks);
        break;
    }
}

void show_basic_iomux_stats(iomux_stats_t *p_curr_stats, iomux_stats_t *p_prev_stats,
                            int *p_printed_lines_num)
{
    switch (user_params.print_details_mode) {
    case e_totals:
        print_iomux_totals(p_curr_stats, p_printed_lines_num);
        break;
    default:
        print_basic_iomux_deltas(p_curr_stats, p_prev_stats, p_printed_lines_num);
        break;
    }
}

void show_iomux_stats(iomux_stats_t *p_curr_stats, iomux_stats_t *p_prev_stats,
                      int *p_printed_lines_num)
{
    switch (user_params.view_mode) {
    case e_basic:
    case e_medium:
        show_basic_iomux_stats(p_curr_stats, p_prev_stats, p_printed_lines_num);
        break;
    case e_full:
        print_full_iomux_stats(p_curr_stats, p_prev_stats);
        break;
    default:
        break;
    }
}

// Find mc_grp in mc_group_fds array.
// if exist: add the fd to the list.
// if not: add the mc group to the array and the fd to the list
void add_fd_to_array(int fd, ip_addr mc_grp, mc_group_fds_t *mc_group_fds, int *array_size)
{
    // Go over the mc_group_fds array
    int i = 0;
    for (i = 0; i < *array_size; i++) {
        if (mc_grp == mc_group_fds[i].mc_grp) {
            // add fd to the list
            mc_group_fds[i].fd_list.push_back(fd);
            return;
        }
    }
    // the mc_group wasnt found
    // Add this mc group to the array
    // coverity[copy_assignment_call] /* Turn off coverity warning for COPY_INSTEAD_OF_MOVE */
    mc_group_fds[i].mc_grp = mc_grp;
    int fd1 = fd;
    mc_group_fds[i].fd_list.push_back(fd1);
    (*array_size)++;
}

void print_mc_group_fds(mc_group_fds_t *mc_group_fds, int array_size)
{
    printf("\n");
    printf(PRODUCT_NAME " Group Memberships Information\n");
    printf("Group                fd number\n");
    printf("------------------------------\n");
    for (int i = 0; i < array_size; i++) {
        char mcg_str[256];
        sprintf(mcg_str, "[%s]", mc_group_fds[i].mc_grp.to_str().c_str());
        printf("%-22s", mcg_str);
        for (const auto &fd : mc_group_fds[i].fd_list) {
            printf("%d ", fd);
        }
        printf("\n");
    }
}

void show_mc_group_stats(mc_grp_info_t *p_mc_grp_info, socket_instance_block_t *p_instance,
                         uint32_t num_of_obj)
{
    // keep array for all the mc addresses and their fds.
    int array_size = 0;
    mc_group_fds_t *mc_group_fds = new mc_group_fds_t[num_of_obj * MC_TABLE_SIZE];
    if (!mc_group_fds) {
        printf(CYCLES_SEPARATOR);
        printf("Could not allocate enough memory\n");
        printf(CYCLES_SEPARATOR);
        return;
    }
    // go over all the fds and fill the array
    for (uint32_t i = 0; i < num_of_obj; i++) {
        size_t fd = (size_t)p_instance[i].skt_stats.fd;
        if (p_instance[i].b_enabled && g_fd_mask[fd]) {
            socket_stats_t *p_si_stats = &p_instance[i].skt_stats;
            // coverity[missing_lock] /* Turn off coverity missing_lock check*/
            for (int grp_idx = 0; grp_idx < p_mc_grp_info->max_grp_num; grp_idx++) {
                if (p_si_stats->mc_grp_map.test(grp_idx)) {
                    add_fd_to_array(p_si_stats->fd, p_mc_grp_info->mc_grp_tbl[grp_idx].mc_grp,
                                    mc_group_fds, &array_size);
                }
            }
        }
    }
    if (array_size > 0) {
        print_mc_group_fds(mc_group_fds, array_size);
    }
    printf(CYCLES_SEPARATOR);

    delete[] mc_group_fds;
}

int print_app_name(int pid)
{
    char app_base_name[FILE_NAME_MAX_SIZE];

    if (get_procname(pid, app_base_name, sizeof(app_base_name)) < 0) {
        return -1;
    }
    printf("application: %s ", app_base_name);

    return 0;
}

void print_version(int pid)
{
    if (pid == -1) {
        log_msg("Linked with " PRODUCT_NAME " version: %d.%d.%d.%d", PRJ_LIBRARY_MAJOR,
                PRJ_LIBRARY_MINOR, PRJ_LIBRARY_REVISION, PRJ_LIBRARY_RELEASE);
        log_msg("Build Date: %s", __DATE__ " " __TIME__);
    } else {
        printf(MODULE_NAME ": stats for ");
        if (print_app_name(pid) < 0) {
            printf("proccess ");
        }
        printf("with pid: %d\n", pid);
    }
}

int check_xlio_ver_compatability(version_info_t *p_stat_ver_info)
{
    return (p_stat_ver_info->xlio_lib_maj == PRJ_LIBRARY_MAJOR &&
            p_stat_ver_info->xlio_lib_min == PRJ_LIBRARY_MINOR &&
            p_stat_ver_info->xlio_lib_rel == PRJ_LIBRARY_RELEASE &&
            p_stat_ver_info->xlio_lib_rev == PRJ_LIBRARY_REVISION);
}

void cleanup(sh_mem_info *p_sh_mem_info)
{
    if (p_sh_mem_info == NULL) {
        return;
    }
    if (p_sh_mem_info->p_sh_stats != MAP_FAILED) {
        if (munmap(p_sh_mem_info->p_sh_stats, p_sh_mem_info->shmem_size) != 0) {
            log_system_err(
                "file='%s' sh_mem_info.fd_sh_stats=%d; error while munmap shared memory at [%p]\n",
                p_sh_mem_info->filename_sh_stats, p_sh_mem_info->fd_sh_stats,
                p_sh_mem_info->p_sh_stats);
        }
    }
    close(p_sh_mem_info->fd_sh_stats);
}

void stats_reader_sig_handler(int signum)
{
    switch (signum) {
    case SIGINT:
        log_msg("Got Ctrl-C (interrupted by user)");
        break;
    default:
        log_msg("Got signal %d - exiting", signum);
        break;
    }
    g_b_exit = true;
}

void set_signal_action()
{
    g_sigact.sa_handler = stats_reader_sig_handler;
    sigemptyset(&g_sigact.sa_mask);
    g_sigact.sa_flags = 0;

    sigaction(SIGINT, &g_sigact, NULL);
}

void alloc_fd_mask()
{
    struct rlimit rlim;
    if ((getrlimit(RLIMIT_NOFILE, &rlim) == 0) && ((uint32_t)rlim.rlim_max > g_fd_map_size)) {
        g_fd_map_size = rlim.rlim_max;
    }
    g_fd_mask = (uint8_t *)malloc(g_fd_map_size * sizeof(uint8_t));
    if (!g_fd_mask) {
        log_err("Failed to malloc g_fd_mask var\n");
    }
}

void inc_read_counter(sh_mem_t *p_sh_mem)
{
    p_sh_mem->reader_counter++;
}

void set_defaults()
{
    user_params.interval = DEFAULT_DELAY_SEC;
    user_params.view_mode = DEFAULT_VIEW_MODE;
    user_params.print_details_mode = DEFAULT_DETAILS_MODE;
    user_params.proc_ident_mode = DEFAULT_PROC_IDENT_MODE;
    user_params.xlio_log_level = VLOG_INIT;
    user_params.forbid_cleaning = false;
    user_params.zero_counters = false;
    user_params.write_auth = true; // needed to set read flag on
    user_params.cycles = DEFAULT_CYCLES;
    user_params.dump = DUMP_DISABLED;
    user_params.fd_dump = 0;
    user_params.fd_dump_log_level = STATS_FD_STATISTICS_LOG_LEVEL_DEFAULT;
    user_params.xlio_stats_path = MCE_DEFAULT_STATS_SHMEM_DIR;

    alloc_fd_mask();
    if (g_fd_mask) {
        memset((void *)g_fd_mask, 1, sizeof(uint8_t) * g_fd_map_size);
    }
}

bool check_if_process_running(char *pid_str)
{
    char proccess_proc_dir[FILE_NAME_MAX_SIZE] = {0};
    struct stat st;
    int n = -1;

    n = snprintf(proccess_proc_dir, sizeof(proccess_proc_dir), "/proc/%s", pid_str);
    if (likely((0 < n) && (n < (int)sizeof(proccess_proc_dir)))) {
        return stat(proccess_proc_dir, &st) == 0;
    }
    return false;
}

bool check_if_process_running(int pid)
{
    char pid_str[MAX_BUFF_SIZE] = {0};
    int n = -1;

    n = snprintf(pid_str, sizeof(pid_str), "%d", pid);
    if (likely((0 < n) && (n < (int)sizeof(pid_str)))) {
        return check_if_process_running(pid_str);
    }
    return false;
}

void stats_reader_handler(sh_mem_t *p_sh_mem, int pid)
{
    int ret;
    int num_act_inst = 0;
    int cycles = user_params.cycles ? user_params.cycles : -1;
    int printed_line_num = SCREEN_SIZE;
    struct timespec start, end;
    bool proc_running = true;
    socket_instance_block_t *prev_instance_blocks;
    socket_instance_block_t *curr_instance_blocks;
    cq_instance_block_t prev_cq_blocks[NUM_OF_SUPPORTED_CQS];
    cq_instance_block_t curr_cq_blocks[NUM_OF_SUPPORTED_CQS];
    ring_instance_block_t prev_ring_blocks[NUM_OF_SUPPORTED_RINGS];
    ring_instance_block_t curr_ring_blocks[NUM_OF_SUPPORTED_RINGS];
    bpool_instance_block_t prev_bpool_blocks[NUM_OF_SUPPORTED_BPOOLS];
    bpool_instance_block_t curr_bpool_blocks[NUM_OF_SUPPORTED_BPOOLS];
    global_instance_block_t prev_global_blocks[NUM_OF_SUPPORTED_GLOBALS];
    global_instance_block_t curr_global_blocks[NUM_OF_SUPPORTED_GLOBALS];
    iomux_stats_t prev_iomux_blocks;
    iomux_stats_t curr_iomux_blocks;
    socket_listen_counter_aggregate socket_counters {user_params.print_details_mode == e_deltas};
    tls_context_counters_show tls_counters {user_params.print_details_mode == e_deltas};
    global_counters_show global_counters {user_params.print_details_mode == e_deltas};
    cpu_usage_show cpu_usage;
    ring_packet_aggregate ring_packets {user_params.print_details_mode == e_deltas};

    if (user_params.dump != DUMP_DISABLED) {
        static std::unordered_map<int, const char *> dump_type_names = {
            {DUMP_DISABLED, "Unknown"},
            {DUMP_FD, "Fd"},
            {DUMP_ROUTE, "Routing"},
            {DUMP_NEIGH, "Neighboring"}};

        const char *name = dump_type_names[user_params.dump] ?: "Unknown";
        log_msg("Dumping %s information to " PRODUCT_NAME " using log level = %s...", name,
                log_level::to_str(user_params.fd_dump_log_level));
        return;
    }

    prev_instance_blocks = (socket_instance_block_t *)malloc(sizeof(*prev_instance_blocks) *
                                                             p_sh_mem->max_skt_inst_num);
    if (NULL == prev_instance_blocks) {
        return;
    }
    curr_instance_blocks = (socket_instance_block_t *)malloc(sizeof(*curr_instance_blocks) *
                                                             p_sh_mem->max_skt_inst_num);
    if (NULL == curr_instance_blocks) {
        free(prev_instance_blocks);
        return;
    }

    memset((void *)prev_instance_blocks, 0,
           sizeof(socket_instance_block_t) * p_sh_mem->max_skt_inst_num);
    memset((void *)curr_instance_blocks, 0,
           sizeof(socket_instance_block_t) * p_sh_mem->max_skt_inst_num);
    memset((void *)prev_cq_blocks, 0, sizeof(cq_instance_block_t) * NUM_OF_SUPPORTED_CQS);
    memset((void *)curr_cq_blocks, 0, sizeof(cq_instance_block_t) * NUM_OF_SUPPORTED_CQS);
    memset((void *)prev_ring_blocks, 0, sizeof(ring_instance_block_t) * NUM_OF_SUPPORTED_RINGS);
    memset((void *)curr_ring_blocks, 0, sizeof(ring_instance_block_t) * NUM_OF_SUPPORTED_RINGS);
    memset((void *)prev_bpool_blocks, 0, sizeof(bpool_instance_block_t) * NUM_OF_SUPPORTED_BPOOLS);
    memset((void *)curr_bpool_blocks, 0, sizeof(bpool_instance_block_t) * NUM_OF_SUPPORTED_BPOOLS);
    for (int i = 0; i < NUM_OF_SUPPORTED_GLOBALS; i++) {
        prev_global_blocks[i].init();
        curr_global_blocks[i].init();
    }
    memset((void *)prev_global_blocks, 0,
           sizeof(global_instance_block_t) * NUM_OF_SUPPORTED_GLOBALS);
    memset((void *)curr_global_blocks, 0,
           sizeof(global_instance_block_t) * NUM_OF_SUPPORTED_GLOBALS);
    memset(&prev_iomux_blocks, 0, sizeof(prev_iomux_blocks));
    memset(&curr_iomux_blocks, 0, sizeof(curr_iomux_blocks));

    if (user_params.print_details_mode == e_deltas) {
        memcpy((void *)prev_instance_blocks, (void *)p_sh_mem->skt_inst_arr,
               p_sh_mem->max_skt_inst_num * sizeof(socket_instance_block_t));
        memcpy((void *)prev_cq_blocks, (void *)p_sh_mem->cq_inst_arr,
               NUM_OF_SUPPORTED_CQS * sizeof(cq_instance_block_t));
        memcpy((void *)prev_ring_blocks, (void *)p_sh_mem->ring_inst_arr,
               NUM_OF_SUPPORTED_RINGS * sizeof(ring_instance_block_t));
        memcpy((void *)prev_bpool_blocks, (void *)p_sh_mem->bpool_inst_arr,
               NUM_OF_SUPPORTED_BPOOLS * sizeof(bpool_instance_block_t));
        memcpy((void *)prev_global_blocks, (void *)p_sh_mem->global_inst_arr,
               NUM_OF_SUPPORTED_GLOBALS * sizeof(global_instance_block_t));
        prev_iomux_blocks = curr_iomux_blocks;
        uint64_t delay_int_micro = SEC_TO_MICRO(user_params.interval);
        if (!g_b_exit && check_if_process_running(pid)) {
            usleep(delay_int_micro);
        }
    }

    if (user_params.csv_stream.is_open()) {
        user_params.csv_stream << "Date,Time," << ring_packets.hdr_val << socket_counters.hdr_val
                               << tls_counters.hdr_val << global_counters.hdr_val
                               << cpu_usage.hdr_val << "\n";
    }
    set_signal_action();

    while (!g_b_exit && proc_running && cycles) {
        --cycles;

        if (gettime(&start)) {
            log_system_err("gettime()");
            goto out;
        }

        if (user_params.print_details_mode == e_deltas) {
            memcpy((void *)curr_instance_blocks, (void *)p_sh_mem->skt_inst_arr,
                   p_sh_mem->max_skt_inst_num * sizeof(socket_instance_block_t));
            memcpy((void *)curr_cq_blocks, (void *)p_sh_mem->cq_inst_arr,
                   NUM_OF_SUPPORTED_CQS * sizeof(cq_instance_block_t));
            memcpy((void *)curr_ring_blocks, (void *)p_sh_mem->ring_inst_arr,
                   NUM_OF_SUPPORTED_RINGS * sizeof(ring_instance_block_t));
            memcpy((void *)curr_bpool_blocks, (void *)p_sh_mem->bpool_inst_arr,
                   NUM_OF_SUPPORTED_BPOOLS * sizeof(bpool_instance_block_t));
            memcpy((void *)curr_global_blocks, (void *)p_sh_mem->global_inst_arr,
                   NUM_OF_SUPPORTED_GLOBALS * sizeof(global_instance_block_t));
            curr_iomux_blocks = p_sh_mem->iomux;
        }

        if (user_params.csv_stream.is_open()) {
            char buf[64] = "N/A,N/A,";
            time_t t = time(nullptr);
            strftime(buf, sizeof(buf), "%F,%T,", localtime(&t));
            user_params.csv_stream
                << buf << ring_packets.update(p_sh_mem) << socket_counters.update(p_sh_mem)
                << tls_counters.update(p_sh_mem) << global_counters.update(p_sh_mem)
                << cpu_usage.update() << "\n";
        }

        switch (user_params.view_mode) {
        case e_full:
            ret = system("clear");
            NOT_IN_USE(ret);
            break;
        case e_mc_groups:
            show_mc_group_stats(&p_sh_mem->mc_info, p_sh_mem->skt_inst_arr,
                                p_sh_mem->max_skt_inst_num);
            goto out;
            break;
        default:
            break;
        }
        switch (user_params.print_details_mode) {
        case e_totals:
            num_act_inst =
                show_socket_stats(p_sh_mem->skt_inst_arr, NULL, p_sh_mem->max_skt_inst_num,
                                  &printed_line_num, &p_sh_mem->mc_info, pid);
            show_iomux_stats(&p_sh_mem->iomux, NULL, &printed_line_num);
            if (user_params.view_mode == e_full) {
                show_cq_stats(p_sh_mem->cq_inst_arr, NULL);
                show_ring_stats(p_sh_mem->ring_inst_arr, NULL);
                show_bpool_stats(p_sh_mem->bpool_inst_arr, NULL);
                show_global_stats(p_sh_mem->global_inst_arr, NULL);
            }
            break;
        case e_deltas:
            num_act_inst = show_socket_stats(curr_instance_blocks, prev_instance_blocks,
                                             p_sh_mem->max_skt_inst_num, &printed_line_num,
                                             &p_sh_mem->mc_info, pid);
            show_iomux_stats(&curr_iomux_blocks, &prev_iomux_blocks, &printed_line_num);
            if (user_params.view_mode == e_full) {
                show_cq_stats(curr_cq_blocks, prev_cq_blocks);
                show_ring_stats(curr_ring_blocks, prev_ring_blocks);
                show_bpool_stats(curr_bpool_blocks, prev_bpool_blocks);
                show_global_stats(curr_global_blocks, prev_global_blocks);
            }
            memcpy((void *)prev_instance_blocks, (void *)curr_instance_blocks,
                   p_sh_mem->max_skt_inst_num * sizeof(socket_instance_block_t));
            memcpy((void *)prev_cq_blocks, (void *)curr_cq_blocks,
                   NUM_OF_SUPPORTED_CQS * sizeof(cq_instance_block_t));
            memcpy((void *)prev_ring_blocks, (void *)curr_ring_blocks,
                   NUM_OF_SUPPORTED_RINGS * sizeof(ring_instance_block_t));
            memcpy((void *)prev_bpool_blocks, (void *)curr_bpool_blocks,
                   NUM_OF_SUPPORTED_BPOOLS * sizeof(bpool_instance_block_t));
            memcpy((void *)prev_global_blocks, (void *)curr_global_blocks,
                   NUM_OF_SUPPORTED_GLOBALS * sizeof(global_instance_block_t));
            prev_iomux_blocks = curr_iomux_blocks;
            break;
        default:
            break;
        }
        if (user_params.view_mode == e_netstat_like) {
            break;
        }
        if (num_act_inst) {
            printf(CYCLES_SEPARATOR);
            printed_line_num++;
        }
        if (gettime(&end)) {
            log_system_err("gettime()");
            goto out;
        }
        uint64_t delay_int_micro = SEC_TO_MICRO(user_params.interval);
        uint64_t adjasted_delay = delay_int_micro - TIME_DIFF_in_MICRO(start, end);
        if (!g_b_exit && proc_running) {
            if (cycles) {
                usleep(adjasted_delay);
            }
            inc_read_counter(p_sh_mem);
        }
        proc_running = check_if_process_running(pid);
    }
    if (!proc_running) {
        log_msg("Proccess %d ended - exiting", pid);
    }

out:
    free(prev_instance_blocks);
    free(curr_instance_blocks);
}

bool check_if_app_match(char *app_name, char *pid_str)
{
    char app_full_name[PATH_MAX] = {0};
    char proccess_proc_dir[FILE_NAME_MAX_SIZE] = {0};
    char *app_base_name = NULL;
    int n = -1;

    n = snprintf(proccess_proc_dir, sizeof(proccess_proc_dir), "/proc/%s/exe", pid_str);
    if (likely((0 < n) && (n < (int)sizeof(proccess_proc_dir)))) {
        n = readlink(proccess_proc_dir, app_full_name, sizeof(app_full_name) - 1);
        if (n > 0) {
            app_full_name[n] = '\0';
            app_base_name = strrchr(app_full_name, '/');
            if (app_base_name) {
                return strcmp((app_base_name + 1), app_name) == 0;
            }
        }
    }

    return false;
}

void clean_inactive_sh_ibj()
{
    DIR *dir;
    struct dirent *dirent;
    int module_name_size = strlen(MODULE_NAME);
    int pid_offset = module_name_size + 1;

    dir = opendir(user_params.xlio_stats_path.c_str());
    if (dir == NULL) {
        log_system_err("opendir %s failed\n", user_params.xlio_stats_path.c_str());
        return;
    }
    dirent = readdir(dir);
    while (dirent != NULL && !user_params.forbid_cleaning) {
        if (!strncmp("xliostat.", dirent->d_name, module_name_size)) {
            bool proccess_running = false;
            proccess_running = check_if_process_running(dirent->d_name + pid_offset);
            if (!proccess_running) {
                char to_delete[PATH_MAX + 1] = {0};
                int n = -1;

                n = snprintf(to_delete, sizeof(to_delete), "%s/%s",
                             user_params.xlio_stats_path.c_str(), dirent->d_name);
                if (likely((0 < n) && (n < (int)sizeof(to_delete)))) {
                    unlink(to_delete);
                }
            }
        }
        dirent = readdir(dir);
    }
    closedir(dir);
}

char *look_for_xlio_stat_active_sh_obj(char *app_name)
{
    DIR *dir;
    struct dirent *dirent;
    bool found = false;
    char *sh_file_name = NULL;
    int module_name_size = strlen(MODULE_NAME);
    int pid_offset = module_name_size + 1;

    dir = opendir(user_params.xlio_stats_path.c_str());
    if (dir == NULL) {
        log_system_err("opendir %s failed\n", user_params.xlio_stats_path.c_str());
        return NULL;
    }
    dirent = readdir(dir);

    while (dirent != NULL && !found) {
        if (!strncmp("xliostat.", dirent->d_name, module_name_size)) {
            found = check_if_process_running(dirent->d_name + pid_offset);
            if (app_name && found) {
                found = check_if_app_match(app_name, dirent->d_name + pid_offset);
            }
            if (found) {
                sh_file_name = (char *)calloc(FILE_NAME_MAX_SIZE, sizeof(char));
                if (!sh_file_name) {
                    log_err("Failed to malloc sh_file_name var\n");
                    closedir(dir);
                    return NULL;
                }
                strcpy(sh_file_name, dirent->d_name + pid_offset);
            }
        }
        dirent = readdir(dir);
    }
    closedir(dir);
    return sh_file_name;
}

int update_range_of_fds(char *left_str, char *right_str)
{
    int left = 0;
    int right = 0;

    errno = 0;
    left = strtol(left_str, NULL, 0);
    if (errno != 0 || left < 0 || (uint32_t)left > g_fd_map_size) {
        log_err("Invalid fd val: %s", left_str);
        return 1;
    }

    if (right_str) {
        right = strtol(right_str, NULL, 0);
        if (errno != 0 || right < 0 || (uint32_t)right > g_fd_map_size) {
            log_err("Invalid fd val: %s", right_str);
            return 1;
        }
    } else {
        right = left;
    }

    if (right < left) {
        swap(right, left);
    }

    for (int i = left; i <= right; i++) {
        g_fd_mask[i] = 1;
    }

    return 0;
}

int analize_fds_range(char *range)
{
    char *left = range;
    char *right = NULL;
    char *delim_loc = NULL;
    char range_copy[101];

    if (strlen(range) + 1 > sizeof(range_copy)) {
        log_err("Invalid fd val size : %zu, cannot exceed %zu", strlen(range),
                sizeof(range_copy) - 1);
        return 1;
    }

    strncpy(range_copy, range, sizeof(range_copy) - 1);
    range_copy[sizeof(range_copy) - 1] = '\0';
    delim_loc = strchr(range_copy, '-');

    if (delim_loc != NULL) {
        right = delim_loc + 1;
        *delim_loc = '\0';
        left = range;
    }
    return update_range_of_fds(left, right);
}

int update_fds_mask(char *fds_list)
{
    memset((void *)g_fd_mask, 0, sizeof(uint8_t) * g_fd_map_size);
    char delims[] = ",";
    char *curr_fds_range = NULL;
    curr_fds_range = strtok(fds_list, delims);
    while (curr_fds_range != NULL) {
        if (analize_fds_range(curr_fds_range)) {
            return 1;
        }
        curr_fds_range = strtok(NULL, delims);
    }
    return 0;
}

void zero_socket_stats(socket_stats_t *p_socket_stats)
{
    memset((void *)&p_socket_stats->counters, 0, sizeof(socket_counters_t));
}

void zero_iomux_stats(iomux_stats_t *p_iomux_stats)
{
    memset(&p_iomux_stats->select, 0, sizeof(iomux_func_stats_t));
    memset(&p_iomux_stats->poll, 0, sizeof(iomux_func_stats_t));
    for (int i = 0; i < NUM_OF_SUPPORTED_EPFDS; i++) {
        if (p_iomux_stats->epoll[i].enabled) {
            memset((&p_iomux_stats->epoll[i].stats), 0, sizeof(iomux_func_stats_t));
        }
    }

    // memset(p_iomux_stats, 0, sizeof(*p_iomux_stats));
}

void zero_ring_stats(ring_stats_t *p_ring_stats, hw_queue_tx_stats_t *p_hwq_tx_stats,
                     hw_queue_rx_stats_t *p_hwq_rx_stats)
{
    memset(p_hwq_tx_stats, 0, sizeof(*p_hwq_tx_stats));
    memset(p_hwq_rx_stats, 0, sizeof(*p_hwq_rx_stats));

    p_ring_stats->n_tx_retransmits = 0;
#ifdef DEFINED_UTLS
    p_ring_stats->n_tx_tls_contexts = 0;
    p_ring_stats->n_rx_tls_contexts = 0;
#endif /* DEFINED_UTLS */
    p_ring_stats->n_tx_dropped_wqes = 0;
    p_ring_stats->n_tx_dev_mem_byte_count = 0;
    p_ring_stats->n_tx_dev_mem_pkt_count = 0;
    p_ring_stats->n_tx_dev_mem_oob = 0;
    p_ring_stats->n_tx_num_bufs = 0;
    p_ring_stats->n_zc_num_bufs = 0;
}

void zero_cq_stats(cq_stats_t *p_cq_stats)
{
    memset(p_cq_stats, 0, sizeof(*p_cq_stats));
}

void zero_bpool_stats(bpool_stats_t *p_bpool_stats)
{
    p_bpool_stats->n_buffer_pool_size = 0;
    p_bpool_stats->n_buffer_pool_no_bufs = 0;
}

void zero_counters(sh_mem_t *p_sh_mem)
{
    log_msg("Zero counters...");
    for (size_t i = 0; i < p_sh_mem->max_skt_inst_num; i++) {
        size_t fd = (size_t)p_sh_mem->skt_inst_arr[i].skt_stats.fd;
        if (p_sh_mem->skt_inst_arr[i].b_enabled && g_fd_mask[fd]) {
            zero_socket_stats(&p_sh_mem->skt_inst_arr[i].skt_stats);
        }
    }
    zero_iomux_stats(&p_sh_mem->iomux);

    for (int i = 0; i < NUM_OF_SUPPORTED_CQS; i++) {
        zero_cq_stats(&p_sh_mem->cq_inst_arr[i].cq_stats);
    }
    for (int i = 0; i < NUM_OF_SUPPORTED_RINGS; i++) {
        zero_ring_stats(&p_sh_mem->ring_inst_arr[i].ring_stats,
                        &p_sh_mem->ring_inst_arr[i].hwq_tx_stats,
                        &p_sh_mem->ring_inst_arr[i].hwq_rx_stats);
    }
    for (int i = 0; i < NUM_OF_SUPPORTED_BPOOLS; i++) {
        zero_bpool_stats(&p_sh_mem->bpool_inst_arr[i].bpool_stats);
    }
}

int get_pid(char *proc_desc, char *argv0)
{
    char *app_name = NULL;
    int pid = -1;

    if (NULL == proc_desc) {
        return -1;
    }

    if (user_params.proc_ident_mode == e_by_pid_str) {
        errno = 0;
        pid = strtol(proc_desc, NULL, 0);
        if (errno != 0 || pid < 0) {
            log_err("'-p' Invalid pid val: %s", proc_desc);
            usage(argv0);
            cleanup(NULL);
            pid = -1;
        }
    } else {
        if (user_params.proc_ident_mode == e_by_app_name) {
            app_name = proc_desc;
        }

        char *pid_str = look_for_xlio_stat_active_sh_obj(app_name);
        if (pid_str) {
            errno = 0;
            pid = strtol(pid_str, NULL, 0);
            if (errno != 0) {
                log_system_err("Failed to convert:%s", pid_str);
                cleanup(NULL);
                pid = -1;
            };
            free(pid_str);
        } else {
            log_err("Failed to identify process please provide pid of active proccess...\n");
        }
    }

    return pid;
}

void set_dumping_data(sh_mem_t *p_sh_mem)
{
    p_sh_mem->dump = user_params.dump;
    p_sh_mem->fd_dump = user_params.fd_dump;
    p_sh_mem->fd_dump_log_level = user_params.fd_dump_log_level;
}

void set_xlio_log_level(sh_mem_t *p_sh_mem)
{
    p_sh_mem->log_level = user_params.xlio_log_level;
}

//////////////////forward declarations /////////////////////////////
void get_all_processes_pids(std::vector<int> &pids);
int print_processes_stats(const std::vector<int> &pids);

////////////////////////////////////////////////////////////////////
int main(int argc, char **argv)
{
    char proc_desc[MAX_BUFF_SIZE] = {0};

    set_defaults();
    if (!g_fd_mask) {
        return 1;
    }

    while (1) {
        int c = 0;
        int option_index = 0;

        static struct option long_options[] = {{"interval", 1, NULL, 'i'},
                                               {"cycles", 1, NULL, 'c'},
                                               {"view", 1, NULL, 'v'},
                                               {"details", 1, NULL, 'd'},
                                               {"pid", 1, NULL, 'p'},
                                               {"directory", 1, NULL, 'k'},
                                               {"sockets", 1, NULL, 's'},
                                               {"version", 0, NULL, 'V'},
                                               {"zero", 0, NULL, 'z'},
                                               {"log_level", 1, NULL, 'l'},
                                               {"dump", 1, NULL, 0},
                                               {"fd_dump", 1, NULL, 'S'},
                                               {"details_level", 1, NULL, 'D'},
                                               {"name", 1, NULL, 'n'},
                                               {"find_pid", 0, NULL, 'f'},
                                               {"forbid_clean", 0, NULL, 'F'},
                                               {"help", 0, NULL, 'h'},
                                               {"csv_file", 1, NULL, 'C'},
                                               {0, 0, 0, 0}};

        if ((c = getopt_long(argc, argv, "i:c:v:d:p:k:s:Vzl:S:C:D:n:fFh?", long_options,
                             &option_index)) == -1) {
            break;
        }

        switch (c) {
        case 0: {
            if (strcmp("dump", long_options[option_index].name) == 0) {
                if (strcasecmp("fd", optarg) == 0) {
                    user_params.dump = DUMP_FD;
                } else if (strcasecmp("route", optarg) == 0) {
                    user_params.dump = DUMP_ROUTE;
                } else if (strcasecmp("neigh", optarg) == 0) {
                    user_params.dump = DUMP_NEIGH;
                } else {
                    log_err("'--dump' Invalid argument: %s", optarg);
                    usage(argv[0]);
                    cleanup(NULL);
                    return 1;
                }
            }
        } break;
        case 'i': {
            errno = 0;
            int interval = strtol(optarg, NULL, 0);
            if (errno != 0 || interval < 0) {
                log_err("'-%c' Invalid interval val: %s", c, optarg);
                usage(argv[0]);
                cleanup(NULL);
                return 1;
            }
            user_params.interval = interval;
        } break;
        case 'c': {
            errno = 0;
            int cycles = strtol(optarg, NULL, 0);
            if (errno != 0 || cycles < 0) {
                log_err("'-%c' Invalid cycles val: %s", c, optarg);
                usage(argv[0]);
                cleanup(NULL);
                return 1;
            }
            user_params.cycles = cycles;
        } break;
        case 'v': {
            errno = 0;
            int view_mod = 0;
            view_mod = strtol(optarg, NULL, 0);
            if (errno != 0 || view_mod < 1 || view_mod > VIEW_MODES_NUM) {
                log_err("'-%c' Invalid view val: %s", c, optarg);
                usage(argv[0]);
                cleanup(NULL);
                return 1;
            }
            user_params.view_mode = (view_mode_t)view_mod;
        } break;
        case 'd': {
            errno = 0;
            int detail_mode = strtol(optarg, NULL, 0);
            if (errno != 0 || detail_mode < 1 || detail_mode > PRINT_DETAILS_MODES_NUM) {
                log_err("'-%c' Invalid details val: %s", c, optarg);
                usage(argv[0]);
                cleanup(NULL);
                return 1;
            }
            user_params.print_details_mode = (print_details_mode_t)detail_mode;
        } break;
        case 'p':
            user_params.proc_ident_mode = e_by_pid_str;
            strncpy(proc_desc, optarg, sizeof(proc_desc) - 1);
            proc_desc[sizeof(proc_desc) - 1] = '\0';
            break;
        case 'k':
            user_params.xlio_stats_path = std::string((char *)optarg);
            break;
        case 's': {
            if (update_fds_mask(optarg)) {
                usage(argv[0]);
                cleanup(NULL);
                return 1;
            }
        } break;
        case 'V':
            print_version(-1);
            cleanup(NULL);
            return 0;
        case 'z':
            user_params.write_auth = true;
            user_params.zero_counters = true;
            break;
        case 'l': {
            vlog_levels_t log_level = log_level::from_str(optarg, VLOG_INIT);
            if (log_level == VLOG_INIT) {
                log_err("'-%c' Invalid log level val: %s", c, optarg);
                usage(argv[0]);
                cleanup(NULL);
                return 1;
            }
            user_params.write_auth = true;
            user_params.xlio_log_level = log_level;
        } break;
        case 'S': {
            errno = 0;
            optind--;
            int fd_to_dump = strtol(argv[optind], NULL, 0);
            if (errno != 0 || fd_to_dump < 0) {
                log_err("'-%c' Invalid fd val: %s", c, argv[optind]);
                usage(argv[0]);
                cleanup(NULL);
                return 1;
            }
            user_params.dump = DUMP_FD;
            user_params.fd_dump = fd_to_dump;
            if (++optind < argc && *argv[optind] != '-') {
                vlog_levels_t dump_log_level = log_level::from_str(argv[optind], VLOG_INIT);
                if (dump_log_level == VLOG_INIT) {
                    log_err("'-%c' Invalid log level val: %s", c, argv[optind]);
                    usage(argv[0]);
                    cleanup(NULL);
                    return 1;
                }
                user_params.fd_dump_log_level = dump_log_level;
            }
        } break;
        case 'C': {
            user_params.csv_stream.open(optarg);
            if (!user_params.csv_stream.is_open()) {
                log_err("Unable to open file: %s", optarg);
                usage(argv[0]);
                cleanup(NULL);
                return 1;
            }
        } break;
        case 'n':
            user_params.proc_ident_mode = e_by_app_name;
            strncpy(proc_desc, optarg, sizeof(proc_desc) - 1);
            proc_desc[sizeof(proc_desc) - 1] = '\0';
            break;
        case 'f':
            user_params.proc_ident_mode = e_by_runn_proccess;
            break;
        case 'F':
            user_params.forbid_cleaning = true;
            break;
        case '?':
        case 'h':
            usage(argv[0]);
            return 0;
            break;
        default:
            usage(argv[0]);
            cleanup(NULL);
            return 1;
        }
    }

    clean_inactive_sh_ibj();

    std::vector<int> pids;
    if (user_params.view_mode == e_netstat_like) {
        get_all_processes_pids(pids);
    } else {
        int pid = get_pid(proc_desc, argv[0]);
        if (pid != -1) {
            pids.push_back(pid);
        }
    }

    if (pids.size() == 0) {
        free(g_fd_mask);
        if (user_params.view_mode == e_netstat_like) {
            print_headers();
            return 0;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (user_params.view_mode == e_netstat_like) {
        user_params.cycles = 1; // print once and exit
    }

    int ret = print_processes_stats(pids);

    free(g_fd_mask);
    return ret;
}

/////////////////////////////////
int init_print_process_stats(sh_mem_info_t &sh_mem_info)
{
    sh_mem_t *sh_mem;
    int pid = sh_mem_info.pid;

    sprintf(sh_mem_info.filename_sh_stats, "%s/xliostat.%d", user_params.xlio_stats_path.c_str(),
            pid);

    if (user_params.write_auth) { // S_IRUSR | S_IWUSR | S_IRGRP
        sh_mem_info.fd_sh_stats =
            open(sh_mem_info.filename_sh_stats, O_RDWR, __S_IREAD | __S_IWRITE | S_IROTH);
    } else {
        sh_mem_info.fd_sh_stats = open(sh_mem_info.filename_sh_stats, O_RDONLY);
    }

    if (sh_mem_info.fd_sh_stats < 0) {
        log_err(PRODUCT_NAME " statistics data for process id %d not found\n", pid);
        return 1;
    }
    sh_mem_info.p_sh_stats =
        mmap(0, sizeof(sh_mem_t), PROT_READ, MAP_SHARED, sh_mem_info.fd_sh_stats, 0);
    MAP_SH_MEM(sh_mem, sh_mem_info.p_sh_stats);
    if (sh_mem_info.p_sh_stats == MAP_FAILED) {
        log_system_err("MAP_FAILED - %s\n", strerror(errno));
        close(sh_mem_info.fd_sh_stats);
        return 1;
    }

    int version_check = 1;
    if (sizeof(STATS_PROTOCOL_VER) > 1) {
        if (memcmp(sh_mem->stats_protocol_ver, STATS_PROTOCOL_VER,
                   min(sizeof(sh_mem->stats_protocol_ver), sizeof(STATS_PROTOCOL_VER)))) {
            log_err("Version %s is not compatible with stats protocol version %s\n",
                    STATS_PROTOCOL_VER, sh_mem->stats_protocol_ver);
            version_check = 0;
        }
    } else {
        if (!check_xlio_ver_compatability(&sh_mem->ver_info)) {
            log_err("Version %d.%d.%d.%d is not compatible with " PRODUCT_NAME
                    " version %d.%d.%d.%d\n",
                    PRJ_LIBRARY_MAJOR, PRJ_LIBRARY_MINOR, PRJ_LIBRARY_REVISION, PRJ_LIBRARY_RELEASE,
                    sh_mem->ver_info.xlio_lib_maj, sh_mem->ver_info.xlio_lib_min,
                    sh_mem->ver_info.xlio_lib_rev, sh_mem->ver_info.xlio_lib_rel);
            version_check = 0;
        }
    }
    if (!version_check) {
        if (munmap(sh_mem_info.p_sh_stats, sizeof(sh_mem_t)) != 0) {
            log_system_err(
                "file='%s' sh_mem_info.fd_sh_stats=%d; error while munmap shared memory at [%p]\n",
                sh_mem_info.filename_sh_stats, sh_mem_info.fd_sh_stats, sh_mem_info.p_sh_stats);
        }
        close(sh_mem_info.fd_sh_stats);
        return 1;
    }

    sh_mem_info.shmem_size = SHMEM_STATS_SIZE(sh_mem->max_skt_inst_num);
    if (munmap(sh_mem_info.p_sh_stats, sizeof(sh_mem_t)) != 0) {
        log_system_err(
            "file='%s' sh_mem_info.fd_sh_stats=%d; error while munmap shared memory at [%p]\n",
            sh_mem_info.filename_sh_stats, sh_mem_info.fd_sh_stats, sh_mem_info.p_sh_stats);
    }
    if (user_params.write_auth) {
        sh_mem_info.p_sh_stats = mmap(0, sh_mem_info.shmem_size, PROT_WRITE | PROT_READ, MAP_SHARED,
                                      sh_mem_info.fd_sh_stats, 0);
    } else {
        sh_mem_info.p_sh_stats =
            mmap(0, sh_mem_info.shmem_size, PROT_READ, MAP_SHARED, sh_mem_info.fd_sh_stats, 0);
    }

    if (sh_mem_info.p_sh_stats == MAP_FAILED) {
        log_system_err("MAP_FAILED - %s\n", strerror(errno));
        close(sh_mem_info.fd_sh_stats);
        return 1;
    }
    MAP_SH_MEM(sh_mem, sh_mem_info.p_sh_stats);
    if (user_params.view_mode != e_netstat_like) {
        print_version(pid);
    }
    if (user_params.zero_counters == true) {
        zero_counters(sh_mem);
    }
    if (user_params.xlio_log_level != VLOG_INIT) {
        set_xlio_log_level(sh_mem);
    }
    if (user_params.dump != DUMP_DISABLED) {
        set_dumping_data(sh_mem);
    }

    // here we indicate XLIO to write to shmem
    inc_read_counter(sh_mem);
    return 0;
}

////////////////////////////////////////////////////////////////////
int complete_print_process_stats(sh_mem_info_t &sh_mem_info)
{
    sh_mem_t *sh_mem;
    MAP_SH_MEM(sh_mem, sh_mem_info.p_sh_stats);

    stats_reader_handler(sh_mem, sh_mem_info.pid);
    cleanup(&sh_mem_info);
    return 0;
}

///////////////////////////
void get_all_processes_pids(std::vector<int> &pids)
{
    const int MODULE_NAME_SIZE = strlen(MODULE_NAME);
    const int PID_OFFSET = MODULE_NAME_SIZE + 1;

    DIR *dir = opendir(user_params.xlio_stats_path.c_str());
    if (dir == NULL) {
        log_system_err("opendir %s failed\n", user_params.xlio_stats_path.c_str());
        return;
    }

    for (struct dirent *dirent = readdir(dir); dirent != NULL; dirent = readdir(dir)) {
        if (!strncmp("xliostat.", dirent->d_name, MODULE_NAME_SIZE)) {
            char *pid_str = dirent->d_name + PID_OFFSET;
            if (check_if_process_running(pid_str)) {
                errno = 0;
                int pid = strtol(pid_str, NULL, 0);
                if (errno == 0) {
                    pids.push_back(pid);
                } else {
                    log_system_err("Failed to convert:%s", pid_str);
                }
            }
        }
    }
    closedir(dir);
}

///////////////////////////
int print_processes_stats(const std::vector<int> &pids)
{
    const int SIZE = pids.size();

    int num_instances = 0;
    sh_mem_info_t sh_mem_info[SIZE];

    // 1. N * prepare shmem and indicate XLIO to update shmem
    for (int i = 0; i < SIZE; ++i) {
        sh_mem_info[num_instances].pid = pids[i];
        if (0 == init_print_process_stats(sh_mem_info[num_instances])) {
            ++num_instances;
        }
    }

    // 2. one sleep to rule them all
    usleep(STATS_READER_DELAY *
           1000); // After 'init_print_process_stats' we wait for XLIO publisher to recognize
                  // that we asked for statistics, otherwise, the first read will be zero

    // 3. N * read from shmem, write to user, and shmem cleanup
    for (int i = 0; i < num_instances; ++i) {
        complete_print_process_stats(sh_mem_info[i]);
    }

    return 0;
}

///////////////////////////
void cpu_stats::capture()
{
    std::ifstream fileStat("/proc/stat");
    std::string line;
    std::getline(fileStat, line);
    if (!line.compare(0, 3, "cpu")) {
        read(line);
    } else {
        log_system_err("Read /proc/stat failed, unexpected line %s\n", line.c_str());
        enabled = false;
    }
    fileStat.close();
}

void cpu_stats::read(const std::string &line)
{
    std::istringstream ss(line);
    std::string label;
    ss >> label;
    for (int i = 0; i < TOTAL_CONTEXTS; ++i) {
        ss >> times[i];
    }
}

size_t cpu_stats::get_active_time() const
{
    return times[USER] + times[NICE] + times[SYSTEM] + times[IRQ] + times[SOFTIRQ] + times[STEAL] +
        times[GUEST] + times[GUEST_NICE];
}

size_t cpu_stats::get_total_time() const
{
    return times[USER] + times[NICE] + times[SYSTEM] + times[IDLE] + times[IOWAIT] + times[IRQ] +
        times[SOFTIRQ] + times[STEAL] + times[GUEST] + times[GUEST_NICE];
}

size_t cpu_stats::get_context_time(enum cpu_context context) const
{
    return times[context];
}
