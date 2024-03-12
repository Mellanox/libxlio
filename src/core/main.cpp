/*
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

#include "main.h"

#include <string.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <time.h>
#include <mcheck.h>
#include <execinfo.h>
#include <libgen.h>
#include <linux/igmp.h>

#include "vlogger/vlogger.h"
#include "utils/compiler.h"
#include "utils/rdtsc.h"
#include "util/xlio_stats.h"
#include "util/utils.h"
#include "event/event_handler_manager.h"
#include "event/vlogger_timer_handler.h"
#include "dev/buffer_pool.h"
#include "dev/ib_ctx_handler_collection.h"
#include "dev/net_device_table_mgr.h"
#include "proto/ip_frag.h"
#include "proto/xlio_lwip.h"
#include "proto/route_table_mgr.h"
#include "proto/rule_table_mgr.h"
#include "proto/mapping.h"

#include "proto/neighbour_table_mgr.h"
#include "netlink/netlink_wrapper.h"
#include "event/command.h"
#include "sock/sock_stats.h"
#include "sock/sock-redirect.h"
#include "sock/sock-app.h"
#include "sock/fd_collection.h"
#include "sock/sockinfo_tcp.h"
#include "sock/sockinfo_udp.h"
#include "sock/tcp_seg_pool.h"
#include "sock/bind_no_port.h"
#include "iomux/io_mux_call.h"

#include "util/instrumentation.h"
#include "util/agent.h"
#include "xlio.h"

void check_netperf_flags();

// Start of xlio_version_str - used in "$ strings libxlio.so | grep XLIO_VERSION"
#define STR_EXPAND(x) #x
#define STR(x)        STR_EXPAND(x)
const char *xlio_version_str = "XLIO_VERSION: " PACKAGE_VERSION "-" STR(PRJ_LIBRARY_RELEASE)

#if _BullseyeCoverage
    " Bullseye"
#endif
#if defined(PRJ_LIBRARY_RELEASE) && (PRJ_LIBRARY_RELEASE > 0)
    " Release"
#else
    " Development Snapshot"
#endif

    " built on " __DATE__ " " __TIME__

#ifdef _DEBUG
    " -*- DEBUG -*-"
#endif
    ; // End of xlio_version_str - used in "$ strings libxlio.so | grep XLIO_VERSION"

bool g_b_exit = false;
bool g_init_ibv_fork_done = false;
bool g_is_forked_child = false;
bool g_init_global_ctors_done = true;
static command_netlink *s_cmd_nl = nullptr;
#define MAX_VERSION_STR_LEN 128

global_stats_t g_global_stat_static;

static int free_libxlio_resources()
{
    vlog_printf(VLOG_DEBUG, "%s: Closing libxlio resources\n", __FUNCTION__);

    g_b_exit = true;

    // Triggers connection close, relevant for TCP which may need some time to terminate the
    // connection. and for any socket that may wait from another thread
    if (g_p_fd_collection) {
        g_p_fd_collection->prepare_to_close();
    }

    // Handle pending received data, this is critical for proper TCP connection termination
    if (g_p_net_device_table_mgr) {
        g_p_net_device_table_mgr->global_ring_drain_and_procces();
    }

    if (g_p_event_handler_manager) {
        g_p_event_handler_manager->stop_thread();
    }

    if (g_tcp_timers_collection) {
        g_tcp_timers_collection->clean_obj();
    }
    g_tcp_timers_collection = nullptr;

    // Block all sock-redicrt API calls into our offloading core
    fd_collection *g_p_fd_collection_temp = g_p_fd_collection;
    g_p_fd_collection = nullptr;
    if (g_p_fd_collection_temp) {
        delete g_p_fd_collection_temp;
    }

    if (g_p_lwip) {
        delete g_p_lwip;
    }
    g_p_lwip = nullptr;

    if (g_p_route_table_mgr) {
        delete g_p_route_table_mgr;
    }
    g_p_route_table_mgr = nullptr;

    if (g_bind_no_port) {
        delete g_bind_no_port;
    }
    g_bind_no_port = nullptr;

    if (g_p_rule_table_mgr) {
        delete g_p_rule_table_mgr;
    }
    g_p_rule_table_mgr = nullptr;

    if (g_p_net_device_table_mgr) {
        delete g_p_net_device_table_mgr;
    }
    g_p_net_device_table_mgr = nullptr;

    ip_frag_manager *g_p_ip_frag_manager_temp = g_p_ip_frag_manager;
    g_p_ip_frag_manager = nullptr;
    if (g_p_ip_frag_manager_temp) {
        delete g_p_ip_frag_manager_temp;
    }

    if (g_p_neigh_table_mgr) {
        delete g_p_neigh_table_mgr;
    }
    g_p_neigh_table_mgr = nullptr;

    if (g_tcp_seg_pool) {
        delete g_tcp_seg_pool;
    }
    g_tcp_seg_pool = nullptr;

    if (safe_mce_sys().print_report) {
        buffer_pool::print_report_on_errors(VLOG_INFO);
    }

    if (g_buffer_pool_zc) {
        delete g_buffer_pool_zc;
    }
    g_buffer_pool_zc = nullptr;

    if (g_buffer_pool_tx) {
        delete g_buffer_pool_tx;
    }
    g_buffer_pool_tx = nullptr;

    if (g_buffer_pool_rx_stride) {
        delete g_buffer_pool_rx_stride;
    }
    g_buffer_pool_rx_stride = nullptr;

    if (g_buffer_pool_rx_rwqe) {
        delete g_buffer_pool_rx_rwqe;
    }
    g_buffer_pool_rx_rwqe = nullptr;

    if (g_zc_cache) {
        delete g_zc_cache;
    }
    g_zc_cache = nullptr;

    xlio_heap::finalize();

    if (s_cmd_nl) {
        delete s_cmd_nl;
    }
    s_cmd_nl = nullptr;

    if (g_p_netlink_handler) {
        delete g_p_netlink_handler;
    }
    g_p_netlink_handler = nullptr;

    if (g_p_ib_ctx_handler_collection) {
        delete g_p_ib_ctx_handler_collection;
    }
    g_p_ib_ctx_handler_collection = nullptr;

    if (g_p_vlogger_timer_handler) {
        delete g_p_vlogger_timer_handler;
    }
    g_p_vlogger_timer_handler = nullptr;

    if (g_p_event_handler_manager) {
        delete g_p_event_handler_manager;
    }
    g_p_event_handler_manager = nullptr;

    if (g_p_agent) {
        delete g_p_agent;
    }
    g_p_agent = nullptr;

    if (safe_mce_sys().app_name) {
        free(safe_mce_sys().app_name);
    }
    safe_mce_sys().app_name = nullptr;

    vlog_printf(VLOG_DEBUG, "Stopping logger module\n");

    sock_redirect_exit();

    vlog_stop();

    if (g_stats_file) {
        // cosmetics - remove when adding iomux block
        fprintf(g_stats_file, "======================================================\n");
        fclose(g_stats_file);
        g_stats_file = nullptr;
    }

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    if (g_p_app) {
        delete g_p_app;
    }
    g_p_app = nullptr;
#endif

    return 0;
}

static void handle_segfault(int)
{
    vlog_printf(VLOG_ERROR, "Segmentation Fault\n");
    printf_backtrace();

    kill(getpid(), SIGKILL);
}

void check_debug()
{
    if (safe_mce_sys().log_level >= VLOG_DEBUG) {
        vlog_printf(VLOG_WARNING,
                    "*************************************************************\n");
        vlog_printf(VLOG_WARNING,
                    "* " PRODUCT_NAME " is currently configured with high log level          *\n");
        vlog_printf(VLOG_WARNING,
                    "* Application performance will decrease in this log level!  *\n");
        vlog_printf(VLOG_WARNING,
                    "* This log level is recommended for debugging purposes only *\n");
        vlog_printf(VLOG_WARNING,
                    "*************************************************************\n");
    }
}

void check_cpu_speed()
{
    double hz_min = -1, hz_max = -1;
    if (!get_cpu_hz(hz_min, hz_max)) {
        vlog_printf(
            VLOG_DEBUG,
            "***************************************************************************\n");
        vlog_printf(VLOG_DEBUG, "Failure in reading CPU speeds\n");
        vlog_printf(
            VLOG_DEBUG,
            "Time measurements will not be accurate and Max Performance might not be achieved\n");
        vlog_printf(VLOG_DEBUG, "Verify with: cat /proc/cpuinfo | grep \"MHz\\|clock\"\n");
        vlog_printf(
            VLOG_DEBUG,
            "***************************************************************************\n");
    } else if (!compare_double(hz_min, hz_max)) {
        // CPU cores are running at different speed
        // Machine is probably running not in high performance configuration
        vlog_printf(
            VLOG_DEBUG,
            "***************************************************************************\n");
        vlog_printf(VLOG_DEBUG,
                    "CPU cores are running at different speeds: min= %.3lf MHz, max= %.3lf MHz\n",
                    hz_min / 1e6, hz_max / 1e6);
        vlog_printf(
            VLOG_DEBUG,
            "Time measurements will not be accurate and Max Performance might not be achieved\n");
        vlog_printf(VLOG_DEBUG, "Verify with: cat /proc/cpuinfo | grep \"MHz\\|clock\"\n");
        vlog_printf(
            VLOG_DEBUG,
            "***************************************************************************\n");
    } else {
        // CPU cores are all running at identical speed
        vlog_printf(VLOG_DEBUG, "CPU speed for all cores is: %.3lf MHz\n", hz_min / 1e6);
    }
}

void check_locked_mem()
{
    struct rlimit rlim;
    if (getrlimit(RLIMIT_MEMLOCK, &rlim) == 0 && rlim.rlim_max != RLIM_INFINITY) {
        vlog_printf(VLOG_WARNING,
                    "************************************************************************\n");
        vlog_printf(VLOG_WARNING,
                    "Your current max locked memory is: %ld. Please change it to unlimited.\n",
                    rlim.rlim_max);
        vlog_printf(VLOG_WARNING, "Set this user's default to `ulimit -l unlimited`.\n");
        vlog_printf(VLOG_WARNING,
                    "Read more about this topic in the " PRODUCT_NAME "'s User Manual.\n");
        vlog_printf(VLOG_WARNING,
                    "************************************************************************\n");
    }
}

const char *thread_mode_str(thread_mode_t thread_mode)
{
    switch (thread_mode) {
    case THREAD_MODE_SINGLE:
        return "Single";
    case THREAD_MODE_MULTI:
        return "Multi spin lock";
    case THREAD_MODE_MUTEX:
        return "Multi mutex lock";
    case THREAD_MODE_PLENTY:
        return "Multi more threads than cores";
    default:
        break;
    }
    return "";
}

const char *buffer_batching_mode_str(buffer_batching_mode_t buffer_batching_mode)
{
    switch (buffer_batching_mode) {
    case BUFFER_BATCHING_NONE:
        return "(No batching buffers)";
    case BUFFER_BATCHING_WITH_RECLAIM:
        return "(Batch and reclaim buffers)";
    case BUFFER_BATCHING_NO_RECLAIM:
        return "(Batch and don't reclaim buffers)";
    default:
        break;
    }
    return "";
}

#define FORMAT_NUMBER "%-30s %-26d [%s]\n"
#define FORMAT_STRING "%-30s %-26s [%s]\n"
#define FORMAT_NUMSTR "%-30s %-2d%-24s [%s]\n"

#define VLOG_STR_PARAM_DETAILS(param_val, param_def_val, args...)                                  \
    do {                                                                                           \
        if (param_val && strcmp(param_val, param_def_val)) {                                       \
            vlog_printf(VLOG_INFO, ##args);                                                        \
        } else {                                                                                   \
            vlog_printf(VLOG_DETAILS, ##args);                                                     \
        }                                                                                          \
    } while (0);

#define VLOG_NUM_PARAM_DETAILS(param_val, param_def_val, args...)                                  \
    do {                                                                                           \
        if (param_val != param_def_val) {                                                          \
            vlog_printf(VLOG_INFO, ##args);                                                        \
        } else {                                                                                   \
            vlog_printf(VLOG_DETAILS, ##args);                                                     \
        }                                                                                          \
    } while (0);

#define VLOG_STR_PARAM_STRING(param_desc, param_val, param_def_val, param_name, val_desc_str)      \
    VLOG_STR_PARAM_DETAILS(param_val, param_def_val, FORMAT_STRING, param_desc, val_desc_str,      \
                           param_name)

#define VLOG_PARAM_NUMBER(param_desc, param_val, param_def_val, param_name)                        \
    VLOG_NUM_PARAM_DETAILS(param_val, param_def_val, FORMAT_NUMBER, param_desc, param_val,         \
                           param_name)

#define VLOG_PARAM_STRING(param_desc, param_val, param_def_val, param_name, val_desc_str)          \
    VLOG_NUM_PARAM_DETAILS(param_val, param_def_val, FORMAT_STRING, param_desc, val_desc_str,      \
                           param_name)

#define VLOG_PARAM_NUMSTR(param_desc, param_val, param_def_val, param_name, val_desc_str)          \
    VLOG_NUM_PARAM_DETAILS(param_val, param_def_val, FORMAT_NUMSTR, param_desc, param_val,         \
                           val_desc_str, param_name)

int get_ofed_version_info(char *ofed_version_str, int len)
{
    return run_and_retreive_system_command("ofed_info -s 2>/dev/null | head -1 | tr -d '\n'",
                                           ofed_version_str, len);
}

void print_xlio_global_settings()
{
    struct utsname sys_info;
    time_t clock = time(nullptr);
    char ofed_version_info[MAX_VERSION_STR_LEN];

    vlog_printf(VLOG_INFO,
                "---------------------------------------------------------------------------\n");
    vlog_printf(VLOG_INFO, "%s\n", xlio_version_str);
    if (PRJ_GIT_VERSION[0]) {
        vlog_printf(VLOG_INFO, "%s\n", "Git: " PRJ_GIT_VERSION);
    }
    vlog_printf(VLOG_INFO, "Cmd Line: %s\n", safe_mce_sys().app_name);

    // Use DEBUG level logging with more details in RPM release builds
    vlog_levels_t log_level = VLOG_DEBUG;
#if !defined(PRJ_LIBRARY_RELEASE) || (PRJ_LIBRARY_RELEASE == 0)
    // If non RPM (development builds) use more verbosity
    log_level = VLOG_DEFAULT;
#endif
    vlog_printf(log_level, "Current Time: %s", ctime(&clock));
    vlog_printf(log_level, "Pid: %5u\n", getpid());

    ofed_version_info[0] = '\0';
    int ret = get_ofed_version_info(ofed_version_info, MAX_VERSION_STR_LEN);
    if (!ret && strlen(ofed_version_info) > 0) {
        vlog_printf(VLOG_INFO, "OFED Version: %s\n", ofed_version_info);
    }

    if (!uname(&sys_info)) {
        vlog_printf(VLOG_DEBUG, "System: %s\n", sys_info.release);
        vlog_printf(log_level, "Architecture: %s\n", sys_info.machine);
        vlog_printf(log_level, "Node: %s\n", sys_info.nodename);
    }

    vlog_printf(VLOG_INFO,
                "---------------------------------------------------------------------------\n");

    if (safe_mce_sys().mce_spec != MCE_SPEC_NONE) {
        vlog_printf(VLOG_INFO, FORMAT_STRING, "Spec",
                    xlio_spec::to_str((xlio_spec_t)safe_mce_sys().mce_spec), SYS_VAR_SPEC);
    }

    VLOG_STR_PARAM_STRING("Log Level", log_level::to_str(safe_mce_sys().log_level), "",
                          SYS_VAR_LOG_LEVEL, log_level::to_str(safe_mce_sys().log_level));
    VLOG_PARAM_NUMBER("Log Details", safe_mce_sys().log_details, MCE_DEFAULT_LOG_DETAILS,
                      SYS_VAR_LOG_DETAILS);
    VLOG_PARAM_STRING("Log Colors", safe_mce_sys().log_colors, MCE_DEFAULT_LOG_COLORS,
                      SYS_VAR_LOG_COLORS, safe_mce_sys().log_colors ? "Enabled " : "Disabled");
    VLOG_STR_PARAM_STRING("Log File", safe_mce_sys().log_filename, MCE_DEFAULT_LOG_FILE,
                          SYS_VAR_LOG_FILENAME, safe_mce_sys().log_filename);
    VLOG_STR_PARAM_STRING("Stats File", safe_mce_sys().stats_filename, MCE_DEFAULT_STATS_FILE,
                          SYS_VAR_STATS_FILENAME, safe_mce_sys().stats_filename);
    VLOG_STR_PARAM_STRING("Stats shared memory directory", safe_mce_sys().stats_shmem_dirname,
                          MCE_DEFAULT_STATS_SHMEM_DIR, SYS_VAR_STATS_SHMEM_DIRNAME,
                          safe_mce_sys().stats_shmem_dirname);
    VLOG_STR_PARAM_STRING("SERVICE output directory", safe_mce_sys().service_notify_dir,
                          MCE_DEFAULT_SERVICE_FOLDER, SYS_VAR_SERVICE_DIR,
                          safe_mce_sys().service_notify_dir);
    VLOG_PARAM_NUMBER("Stats FD Num (max)", safe_mce_sys().stats_fd_num_max,
                      MCE_DEFAULT_STATS_FD_NUM, SYS_VAR_STATS_FD_NUM);
    VLOG_STR_PARAM_STRING("Conf File", safe_mce_sys().conf_filename, MCE_DEFAULT_CONF_FILE,
                          SYS_VAR_CONF_FILENAME, safe_mce_sys().conf_filename);
    VLOG_STR_PARAM_STRING("Application ID", safe_mce_sys().app_id, MCE_DEFAULT_APP_ID,
                          SYS_VAR_APPLICATION_ID, safe_mce_sys().app_id);
    VLOG_PARAM_STRING("Polling CPU idle usage", safe_mce_sys().select_handle_cpu_usage_stats,
                      MCE_DEFAULT_SELECT_CPU_USAGE_STATS, SYS_VAR_SELECT_CPU_USAGE_STATS,
                      safe_mce_sys().select_handle_cpu_usage_stats ? "Enabled " : "Disabled");
    VLOG_PARAM_STRING("SigIntr Ctrl-C Handle", safe_mce_sys().handle_sigintr,
                      MCE_DEFAULT_HANDLE_SIGINTR, SYS_VAR_HANDLE_SIGINTR,
                      safe_mce_sys().handle_sigintr ? "Enabled " : "Disabled");
    VLOG_PARAM_STRING("SegFault Backtrace", safe_mce_sys().handle_segfault,
                      MCE_DEFAULT_HANDLE_SIGFAULT, SYS_VAR_HANDLE_SIGSEGV,
                      safe_mce_sys().handle_segfault ? "Enabled " : "Disabled");
    VLOG_PARAM_STRING("Print a report", safe_mce_sys().print_report, MCE_DEFAULT_PRINT_REPORT,
                      SYS_VAR_PRINT_REPORT, safe_mce_sys().print_report ? "Enabled " : "Disabled");

    VLOG_PARAM_NUMSTR("Ring allocation logic TX", safe_mce_sys().ring_allocation_logic_tx,
                      MCE_DEFAULT_RING_ALLOCATION_LOGIC_TX, SYS_VAR_RING_ALLOCATION_LOGIC_TX,
                      ring_logic_str(safe_mce_sys().ring_allocation_logic_tx));
    VLOG_PARAM_NUMSTR("Ring allocation logic RX", safe_mce_sys().ring_allocation_logic_rx,
                      MCE_DEFAULT_RING_ALLOCATION_LOGIC_RX, SYS_VAR_RING_ALLOCATION_LOGIC_RX,
                      ring_logic_str(safe_mce_sys().ring_allocation_logic_rx));
    if (safe_mce_sys().ring_allocation_logic_rx == RING_LOGIC_PER_USER_ID) {
        vlog_printf(VLOG_WARNING,
                    "user_id is not supported using "
                    "environment variable , use etra_api, using default\n");
        safe_mce_sys().ring_allocation_logic_rx = MCE_DEFAULT_RING_ALLOCATION_LOGIC_RX;
    }

    if (safe_mce_sys().ring_allocation_logic_tx == RING_LOGIC_PER_USER_ID) {
        vlog_printf(VLOG_WARNING,
                    "user_id is not supported using "
                    "environment variable , use etra_api, using default\n");
        safe_mce_sys().ring_allocation_logic_tx = MCE_DEFAULT_RING_ALLOCATION_LOGIC_TX;
    }

    VLOG_PARAM_NUMBER("Ring migration ratio TX", safe_mce_sys().ring_migration_ratio_tx,
                      (safe_mce_sys().enable_tso ? -1 : MCE_DEFAULT_RING_MIGRATION_RATIO_TX),
                      SYS_VAR_RING_MIGRATION_RATIO_TX);
    VLOG_PARAM_NUMBER("Ring migration ratio RX", safe_mce_sys().ring_migration_ratio_rx,
                      MCE_DEFAULT_RING_MIGRATION_RATIO_RX, SYS_VAR_RING_MIGRATION_RATIO_RX);

    if (safe_mce_sys().ring_limit_per_interface) {
        VLOG_PARAM_NUMBER("Ring limit per interface", safe_mce_sys().ring_limit_per_interface,
                          MCE_DEFAULT_RING_LIMIT_PER_INTERFACE, SYS_VAR_RING_LIMIT_PER_INTERFACE);
    } else {
        VLOG_PARAM_NUMSTR("Ring limit per interface", safe_mce_sys().ring_limit_per_interface,
                          MCE_DEFAULT_RING_LIMIT_PER_INTERFACE, SYS_VAR_RING_LIMIT_PER_INTERFACE,
                          "(no limit)");
    }

    VLOG_PARAM_NUMBER("Ring On Device Memory TX", safe_mce_sys().ring_dev_mem_tx,
                      MCE_DEFAULT_RING_DEV_MEM_TX, SYS_VAR_RING_DEV_MEM_TX);

    if (safe_mce_sys().tcp_max_syn_rate) {
        VLOG_PARAM_NUMSTR("TCP max syn rate", safe_mce_sys().tcp_max_syn_rate,
                          MCE_DEFAULT_TCP_MAX_SYN_RATE, SYS_VAR_TCP_MAX_SYN_RATE, "(per sec)");
    } else {
        VLOG_PARAM_NUMSTR("TCP max syn rate", safe_mce_sys().tcp_max_syn_rate,
                          MCE_DEFAULT_TCP_MAX_SYN_RATE, SYS_VAR_TCP_MAX_SYN_RATE, "(no limit)");
    }

    VLOG_PARAM_STRING("Zerocopy Cache Threshold", safe_mce_sys().zc_cache_threshold,
                      MCE_DEFAULT_ZC_CACHE_THRESHOLD, SYS_VAR_ZC_CACHE_THRESHOLD,
                      option_size::to_str(safe_mce_sys().zc_cache_threshold));
    VLOG_PARAM_NUMBER("Tx Mem Bufs", safe_mce_sys().tx_num_bufs, MCE_DEFAULT_TX_NUM_BUFS,
                      SYS_VAR_TX_NUM_BUFS);
    VLOG_PARAM_STRING("Tx Mem Buf size", safe_mce_sys().tx_buf_size, MCE_DEFAULT_TX_BUF_SIZE,
                      SYS_VAR_TX_BUF_SIZE, option_size::to_str(safe_mce_sys().tx_buf_size));
    VLOG_PARAM_NUMBER("Tx QP WRE", safe_mce_sys().tx_num_wr, MCE_DEFAULT_TX_NUM_WRE,
                      SYS_VAR_TX_NUM_WRE);
    VLOG_PARAM_NUMBER("Tx QP WRE Batching", safe_mce_sys().tx_num_wr_to_signal,
                      MCE_DEFAULT_TX_NUM_WRE_TO_SIGNAL, SYS_VAR_TX_NUM_WRE_TO_SIGNAL);
    VLOG_PARAM_NUMBER("Tx Max QP INLINE", safe_mce_sys().tx_max_inline, MCE_DEFAULT_TX_MAX_INLINE,
                      SYS_VAR_TX_MAX_INLINE);
    VLOG_PARAM_STRING("Tx MC Loopback", safe_mce_sys().tx_mc_loopback_default,
                      MCE_DEFAULT_TX_MC_LOOPBACK, SYS_VAR_TX_MC_LOOPBACK,
                      safe_mce_sys().tx_mc_loopback_default ? "Enabled " : "Disabled");
    VLOG_PARAM_STRING("Tx non-blocked eagains", safe_mce_sys().tx_nonblocked_eagains,
                      MCE_DEFAULT_TX_NONBLOCKED_EAGAINS, SYS_VAR_TX_NONBLOCKED_EAGAINS,
                      safe_mce_sys().tx_nonblocked_eagains ? "Enabled " : "Disabled");
    VLOG_PARAM_NUMBER("Tx Prefetch Bytes", safe_mce_sys().tx_prefetch_bytes,
                      MCE_DEFAULT_TX_PREFETCH_BYTES, SYS_VAR_TX_PREFETCH_BYTES);
    VLOG_PARAM_NUMBER("Tx Bufs Batch TCP", safe_mce_sys().tx_bufs_batch_tcp,
                      MCE_DEFAULT_TX_BUFS_BATCH_TCP, SYS_VAR_TX_BUFS_BATCH_TCP);
    VLOG_PARAM_NUMBER("Tx Segs Batch TCP", safe_mce_sys().tx_segs_batch_tcp,
                      MCE_DEFAULT_TX_SEGS_BATCH_TCP, SYS_VAR_TX_SEGS_BATCH_TCP);
    VLOG_PARAM_NUMBER("Tx Segs Ring Batch TCP", safe_mce_sys().tx_segs_ring_batch_tcp,
                      MCE_DEFAULT_TX_SEGS_RING_BATCH_TCP, SYS_VAR_TX_SEGS_RING_BATCH_TCP);
    VLOG_PARAM_STRING("TCP Send Buffer size", safe_mce_sys().tcp_send_buffer_size,
                      MCE_DEFAULT_TCP_SEND_BUFFER_SIZE, SYS_VAR_TCP_SEND_BUFFER_SIZE,
                      option_size::to_str(safe_mce_sys().tcp_send_buffer_size));
    VLOG_PARAM_NUMBER(
        "Rx Mem Bufs", safe_mce_sys().rx_num_bufs,
        (safe_mce_sys().enable_striding_rq ? MCE_DEFAULT_STRQ_NUM_BUFS : MCE_DEFAULT_RX_NUM_BUFS),
        SYS_VAR_RX_NUM_BUFS);
    VLOG_PARAM_NUMBER(
        "Rx QP WRE", safe_mce_sys().rx_num_wr,
        (safe_mce_sys().enable_striding_rq ? MCE_DEFAULT_STRQ_NUM_WRE : MCE_DEFAULT_RX_NUM_WRE),
        SYS_VAR_RX_NUM_WRE);
    VLOG_PARAM_NUMBER("Rx QP WRE Batching", safe_mce_sys().rx_num_wr_to_post_recv,
                      (safe_mce_sys().enable_striding_rq ? MCE_DEFAULT_STRQ_NUM_WRE_TO_POST_RECV
                                                         : MCE_DEFAULT_RX_NUM_WRE_TO_POST_RECV),
                      SYS_VAR_RX_NUM_WRE_TO_POST_RECV);
    VLOG_PARAM_NUMBER("Rx Byte Min Limit", safe_mce_sys().rx_ready_byte_min_limit,
                      MCE_DEFAULT_RX_BYTE_MIN_LIMIT, SYS_VAR_RX_BYTE_MIN_LIMIT);
    VLOG_PARAM_NUMBER("Rx Poll Loops", safe_mce_sys().rx_poll_num, MCE_DEFAULT_RX_NUM_POLLS,
                      SYS_VAR_RX_NUM_POLLS);
    VLOG_PARAM_NUMBER("Rx Poll Init Loops", safe_mce_sys().rx_poll_num_init,
                      MCE_DEFAULT_RX_NUM_POLLS_INIT, SYS_VAR_RX_NUM_POLLS_INIT);
    if (safe_mce_sys().rx_udp_poll_os_ratio) {
        VLOG_PARAM_NUMBER("Rx UDP Poll OS Ratio", safe_mce_sys().rx_udp_poll_os_ratio,
                          MCE_DEFAULT_RX_UDP_POLL_OS_RATIO, SYS_VAR_RX_UDP_POLL_OS_RATIO);
    } else {
        VLOG_PARAM_STRING("Rx UDP Poll OS Ratio", safe_mce_sys().rx_udp_poll_os_ratio,
                          MCE_DEFAULT_RX_UDP_POLL_OS_RATIO, SYS_VAR_RX_UDP_POLL_OS_RATIO,
                          "Disabled");
    }

    VLOG_PARAM_NUMBER("HW TS Conversion", safe_mce_sys().hw_ts_conversion_mode,
                      MCE_DEFAULT_HW_TS_CONVERSION_MODE, SYS_VAR_HW_TS_CONVERSION_MODE);

    if (safe_mce_sys().rx_poll_yield_loops) {
        VLOG_PARAM_NUMBER("Rx Poll Yield", safe_mce_sys().rx_poll_yield_loops,
                          MCE_DEFAULT_RX_POLL_YIELD, SYS_VAR_RX_POLL_YIELD);
    } else {
        VLOG_PARAM_STRING("Rx Poll Yield", safe_mce_sys().rx_poll_yield_loops,
                          MCE_DEFAULT_RX_POLL_YIELD, SYS_VAR_RX_POLL_YIELD, "Disabled");
    }
    VLOG_PARAM_NUMBER("Rx Prefetch Bytes", safe_mce_sys().rx_prefetch_bytes,
                      MCE_DEFAULT_RX_PREFETCH_BYTES, SYS_VAR_RX_PREFETCH_BYTES);

    VLOG_PARAM_NUMBER("Rx Prefetch Bytes Before Poll", safe_mce_sys().rx_prefetch_bytes_before_poll,
                      MCE_DEFAULT_RX_PREFETCH_BYTES_BEFORE_POLL,
                      SYS_VAR_RX_PREFETCH_BYTES_BEFORE_POLL);

    if (safe_mce_sys().rx_cq_drain_rate_nsec == MCE_RX_CQ_DRAIN_RATE_DISABLED) {
        VLOG_PARAM_STRING("Rx CQ Drain Rate", safe_mce_sys().rx_cq_drain_rate_nsec,
                          MCE_DEFAULT_RX_CQ_DRAIN_RATE, SYS_VAR_RX_CQ_DRAIN_RATE_NSEC, "Disabled");
    } else {
        VLOG_PARAM_NUMBER("Rx CQ Drain Rate (nsec)", safe_mce_sys().rx_cq_drain_rate_nsec,
                          MCE_DEFAULT_RX_CQ_DRAIN_RATE, SYS_VAR_RX_CQ_DRAIN_RATE_NSEC);
    }

    VLOG_PARAM_NUMBER("GRO max streams", safe_mce_sys().gro_streams_max,
                      MCE_DEFAULT_GRO_STREAMS_MAX, SYS_VAR_GRO_STREAMS_MAX);
    VLOG_PARAM_NUMBER("Disable flow tag", safe_mce_sys().disable_flow_tag,
                      MCE_DEFAULT_DISABLE_FLOW_TAG, SYS_VAR_DISABLE_FLOW_TAG);

    VLOG_PARAM_STRING("TCP 3T rules", safe_mce_sys().tcp_3t_rules, MCE_DEFAULT_TCP_3T_RULES,
                      SYS_VAR_TCP_3T_RULES, safe_mce_sys().tcp_3t_rules ? "Enabled " : "Disabled");
    VLOG_PARAM_STRING("UDP 3T rules", safe_mce_sys().udp_3t_rules, MCE_DEFAULT_UDP_3T_RULES,
                      SYS_VAR_UDP_3T_RULES, safe_mce_sys().udp_3t_rules ? "Enabled " : "Disabled");
    VLOG_PARAM_STRING("ETH MC L2 only rules", safe_mce_sys().eth_mc_l2_only_rules,
                      MCE_DEFAULT_ETH_MC_L2_ONLY_RULES, SYS_VAR_ETH_MC_L2_ONLY_RULES,
                      safe_mce_sys().eth_mc_l2_only_rules ? "Enabled " : "Disabled");
    VLOG_PARAM_STRING("Force Flowtag for MC", safe_mce_sys().mc_force_flowtag,
                      MCE_DEFAULT_MC_FORCE_FLOWTAG, SYS_VAR_MC_FORCE_FLOWTAG,
                      safe_mce_sys().mc_force_flowtag ? "Enabled " : "Disabled");
    VLOG_STR_PARAM_STRING("Striding RQ", option_3::to_str(safe_mce_sys().enable_strq_env),
                          option_3::to_str(MCE_DEFAULT_STRQ), SYS_VAR_STRQ,
                          option_3::to_str(safe_mce_sys().enable_strq_env));
    VLOG_PARAM_NUMBER("STRQ Strides per RWQE", safe_mce_sys().strq_stride_num_per_rwqe,
                      MCE_DEFAULT_STRQ_NUM_STRIDES, SYS_VAR_STRQ_NUM_STRIDES);
    VLOG_PARAM_NUMBER("STRQ Stride Size (Bytes)", safe_mce_sys().strq_stride_size_bytes,
                      MCE_DEFAULT_STRQ_STRIDE_SIZE_BYTES, SYS_VAR_STRQ_STRIDE_SIZE_BYTES);
    VLOG_PARAM_NUMBER("STRQ Initial Strides Per Ring", safe_mce_sys().strq_strides_num_bufs,
                      MCE_DEFAULT_STRQ_STRIDES_NUM_BUFS, SYS_VAR_STRQ_STRIDES_NUM_BUFS);
    VLOG_PARAM_NUMBER(
        "STRQ Strides Compensation Level", safe_mce_sys().strq_strides_compensation_level,
        MCE_DEFAULT_STRQ_STRIDES_COMPENSATION_LEVEL, SYS_VAR_STRQ_STRIDES_COMPENSATION_LEVEL);
    VLOG_PARAM_NUMBER("Select Poll (usec)", safe_mce_sys().select_poll_num,
                      MCE_DEFAULT_SELECT_NUM_POLLS, SYS_VAR_SELECT_NUM_POLLS);
    VLOG_PARAM_STRING("Select Poll OS Force", safe_mce_sys().select_poll_os_force,
                      MCE_DEFAULT_SELECT_POLL_OS_FORCE, SYS_VAR_SELECT_POLL_OS_FORCE,
                      safe_mce_sys().select_poll_os_force ? "Enabled " : "Disabled");

    if (safe_mce_sys().select_poll_os_ratio) {
        VLOG_PARAM_NUMBER("Select Poll OS Ratio", safe_mce_sys().select_poll_os_ratio,
                          MCE_DEFAULT_SELECT_POLL_OS_RATIO, SYS_VAR_SELECT_POLL_OS_RATIO);
    } else {
        VLOG_PARAM_STRING("Select Poll OS Ratio", safe_mce_sys().select_poll_os_ratio,
                          MCE_DEFAULT_SELECT_POLL_OS_RATIO, SYS_VAR_SELECT_POLL_OS_RATIO,
                          "Disabled");
    }

    if (safe_mce_sys().select_skip_os_fd_check) {
        VLOG_PARAM_NUMBER("Select Skip OS", safe_mce_sys().select_skip_os_fd_check,
                          MCE_DEFAULT_SELECT_SKIP_OS, SYS_VAR_SELECT_SKIP_OS);
    } else {
        VLOG_PARAM_STRING("Select Skip OS", safe_mce_sys().select_skip_os_fd_check,
                          MCE_DEFAULT_SELECT_SKIP_OS, SYS_VAR_SELECT_SKIP_OS, "Disabled");
    }

    if (safe_mce_sys().progress_engine_interval_msec == MCE_CQ_DRAIN_INTERVAL_DISABLED ||
        safe_mce_sys().progress_engine_wce_max == 0) {
        vlog_printf(VLOG_INFO, FORMAT_STRING, "CQ Drain Thread", "Disabled",
                    SYS_VAR_PROGRESS_ENGINE_INTERVAL);
    } else {
        VLOG_PARAM_NUMBER("CQ Drain Interval (msec)", safe_mce_sys().progress_engine_interval_msec,
                          MCE_DEFAULT_PROGRESS_ENGINE_INTERVAL_MSEC,
                          SYS_VAR_PROGRESS_ENGINE_INTERVAL);
        VLOG_PARAM_NUMBER("CQ Drain WCE (max)", safe_mce_sys().progress_engine_wce_max,
                          MCE_DEFAULT_PROGRESS_ENGINE_WCE_MAX, SYS_VAR_PROGRESS_ENGINE_WCE_MAX);
    }

    VLOG_PARAM_STRING("CQ Interrupts Moderation", safe_mce_sys().cq_moderation_enable,
                      MCE_DEFAULT_CQ_MODERATION_ENABLE, SYS_VAR_CQ_MODERATION_ENABLE,
                      safe_mce_sys().cq_moderation_enable ? "Enabled " : "Disabled");
    VLOG_PARAM_NUMBER("CQ Moderation Count", safe_mce_sys().cq_moderation_count,
                      MCE_DEFAULT_CQ_MODERATION_COUNT, SYS_VAR_CQ_MODERATION_COUNT);
    VLOG_PARAM_NUMBER("CQ Moderation Period (usec)", safe_mce_sys().cq_moderation_period_usec,
                      MCE_DEFAULT_CQ_MODERATION_PERIOD_USEC, SYS_VAR_CQ_MODERATION_PERIOD_USEC);
    VLOG_PARAM_NUMBER("CQ AIM Max Count", safe_mce_sys().cq_aim_max_count,
                      MCE_DEFAULT_CQ_AIM_MAX_COUNT, SYS_VAR_CQ_AIM_MAX_COUNT);
    VLOG_PARAM_NUMBER("CQ AIM Max Period (usec)", safe_mce_sys().cq_aim_max_period_usec,
                      MCE_DEFAULT_CQ_AIM_MAX_PERIOD_USEC, SYS_VAR_CQ_AIM_MAX_PERIOD_USEC);
    if (safe_mce_sys().cq_aim_interval_msec == MCE_CQ_ADAPTIVE_MODERATION_DISABLED) {
        vlog_printf(VLOG_INFO, FORMAT_STRING, "CQ Adaptive Moderation", "Disabled",
                    SYS_VAR_CQ_AIM_INTERVAL_MSEC);
    } else {
        VLOG_PARAM_NUMBER("CQ AIM Interval (msec)", safe_mce_sys().cq_aim_interval_msec,
                          MCE_DEFAULT_CQ_AIM_INTERVAL_MSEC, SYS_VAR_CQ_AIM_INTERVAL_MSEC);
    }
    VLOG_PARAM_NUMBER(
        "CQ AIM Interrupts Rate (per sec)", safe_mce_sys().cq_aim_interrupts_rate_per_sec,
        MCE_DEFAULT_CQ_AIM_INTERRUPTS_RATE_PER_SEC, SYS_VAR_CQ_AIM_INTERRUPTS_RATE_PER_SEC);

    VLOG_PARAM_NUMBER("CQ Poll Batch (max)", safe_mce_sys().cq_poll_batch_max,
                      MCE_DEFAULT_CQ_POLL_BATCH, SYS_VAR_CQ_POLL_BATCH_MAX);
    VLOG_PARAM_STRING("CQ Keeps QP Full", safe_mce_sys().cq_keep_qp_full,
                      MCE_DEFAULT_CQ_KEEP_QP_FULL, SYS_VAR_CQ_KEEP_QP_FULL,
                      safe_mce_sys().cq_keep_qp_full ? "Enabled" : "Disabled");
    VLOG_PARAM_NUMBER("QP Compensation Level", safe_mce_sys().qp_compensation_level,
                      (safe_mce_sys().enable_striding_rq ? MCE_DEFAULT_STRQ_COMPENSATION_LEVEL
                                                         : MCE_DEFAULT_QP_COMPENSATION_LEVEL),
                      SYS_VAR_QP_COMPENSATION_LEVEL);
    VLOG_PARAM_STRING("Offloaded Sockets", safe_mce_sys().offloaded_sockets,
                      MCE_DEFAULT_OFFLOADED_SOCKETS, SYS_VAR_OFFLOADED_SOCKETS,
                      safe_mce_sys().offloaded_sockets ? "Enabled" : "Disabled");
    VLOG_PARAM_NUMBER("Timer Resolution (msec)", safe_mce_sys().timer_resolution_msec,
                      MCE_DEFAULT_TIMER_RESOLUTION_MSEC, SYS_VAR_TIMER_RESOLUTION_MSEC);
    VLOG_PARAM_NUMBER("TCP Timer Resolution (msec)", safe_mce_sys().tcp_timer_resolution_msec,
                      MCE_DEFAULT_TCP_TIMER_RESOLUTION_MSEC, SYS_VAR_TCP_TIMER_RESOLUTION_MSEC);
    VLOG_PARAM_STRING(
        "TCP control thread", option_tcp_ctl_thread::to_str(safe_mce_sys().tcp_ctl_thread),
        option_tcp_ctl_thread::to_str(MCE_DEFAULT_TCP_CTL_THREAD), SYS_VAR_TCP_CTL_THREAD,
        option_tcp_ctl_thread::to_str(safe_mce_sys().tcp_ctl_thread));
    VLOG_PARAM_NUMBER("TCP timestamp option", safe_mce_sys().tcp_ts_opt,
                      MCE_DEFAULT_TCP_TIMESTAMP_OPTION, SYS_VAR_TCP_TIMESTAMP_OPTION);
    VLOG_PARAM_NUMBER("TCP nodelay", safe_mce_sys().tcp_nodelay, MCE_DEFAULT_TCP_NODELAY,
                      SYS_VAR_TCP_NODELAY);
    VLOG_PARAM_NUMBER("TCP nodelay treshold", safe_mce_sys().tcp_nodelay_treshold,
                      MCE_DEFAULT_TCP_NODELAY_TRESHOLD, SYS_VAR_TCP_NODELAY_TRESHOLD);
    VLOG_PARAM_NUMBER("TCP quickack", safe_mce_sys().tcp_quickack, MCE_DEFAULT_TCP_QUICKACK,
                      SYS_VAR_TCP_QUICKACK);
    VLOG_PARAM_NUMSTR(xlio_exception_handling::getName(), (int)safe_mce_sys().exception_handling,
                      xlio_exception_handling::MODE_DEFAULT, xlio_exception_handling::getSysVar(),
                      safe_mce_sys().exception_handling.to_str());
    VLOG_PARAM_STRING("Avoid sys-calls on tcp fd", safe_mce_sys().avoid_sys_calls_on_tcp_fd,
                      MCE_DEFAULT_AVOID_SYS_CALLS_ON_TCP_FD, SYS_VAR_AVOID_SYS_CALLS_ON_TCP_FD,
                      safe_mce_sys().avoid_sys_calls_on_tcp_fd ? "Enabled" : "Disabled");
    VLOG_PARAM_STRING("Allow privileged sock opt", safe_mce_sys().allow_privileged_sock_opt,
                      MCE_DEFAULT_ALLOW_PRIVILEGED_SOCK_OPT, SYS_VAR_ALLOW_PRIVILEGED_SOCK_OPT,
                      safe_mce_sys().allow_privileged_sock_opt ? "Enabled" : "Disabled");
    VLOG_PARAM_NUMBER("Delay after join (msec)", safe_mce_sys().wait_after_join_msec,
                      MCE_DEFAULT_WAIT_AFTER_JOIN_MSEC, SYS_VAR_WAIT_AFTER_JOIN_MSEC);
    VLOG_STR_PARAM_STRING("Internal Thread Affinity", safe_mce_sys().internal_thread_affinity_str,
                          MCE_DEFAULT_INTERNAL_THREAD_AFFINITY_STR,
                          SYS_VAR_INTERNAL_THREAD_AFFINITY,
                          safe_mce_sys().internal_thread_affinity_str);
    VLOG_STR_PARAM_STRING("Internal Thread Cpuset", safe_mce_sys().internal_thread_cpuset,
                          MCE_DEFAULT_INTERNAL_THREAD_CPUSET, SYS_VAR_INTERNAL_THREAD_CPUSET,
                          safe_mce_sys().internal_thread_cpuset);
    VLOG_PARAM_STRING("Internal Thread Arm CQ", safe_mce_sys().internal_thread_arm_cq_enabled,
                      MCE_DEFAULT_INTERNAL_THREAD_ARM_CQ_ENABLED, SYS_VAR_INTERNAL_THREAD_ARM_CQ,
                      safe_mce_sys().internal_thread_arm_cq_enabled ? "Enabled " : "Disabled");
    VLOG_PARAM_STRING("Thread mode", safe_mce_sys().thread_mode, MCE_DEFAULT_THREAD_MODE,
                      SYS_VAR_THREAD_MODE, thread_mode_str(safe_mce_sys().thread_mode));
    VLOG_PARAM_NUMSTR("Buffer batching mode", safe_mce_sys().buffer_batching_mode,
                      MCE_DEFAULT_BUFFER_BATCHING_MODE, SYS_VAR_BUFFER_BATCHING_MODE,
                      buffer_batching_mode_str(safe_mce_sys().buffer_batching_mode));
    VLOG_PARAM_STRING("Mem Allocation type",
                      option_alloc_type::to_str(safe_mce_sys().mem_alloc_type),
                      option_alloc_type::to_str(MCE_DEFAULT_MEM_ALLOC_TYPE), SYS_VAR_MEM_ALLOC_TYPE,
                      option_alloc_type::to_str(safe_mce_sys().mem_alloc_type));
    VLOG_PARAM_STRING("Memory limit", safe_mce_sys().memory_limit, MCE_DEFAULT_MEMORY_LIMIT,
                      SYS_VAR_MEMORY_LIMIT, option_size::to_str(safe_mce_sys().memory_limit));
    VLOG_PARAM_STRING("Memory limit (user allocator)", safe_mce_sys().memory_limit_user,
                      MCE_DEFAULT_MEMORY_LIMIT_USER, SYS_VAR_MEMORY_LIMIT_USER,
                      option_size::to_str(safe_mce_sys().memory_limit_user));
    VLOG_PARAM_STRING("Hugepage size", safe_mce_sys().hugepage_size, MCE_DEFAULT_HUGEPAGE_SIZE,
                      SYS_VAR_HUGEPAGE_SIZE, option_size::to_str(safe_mce_sys().hugepage_size));

    VLOG_PARAM_NUMBER("Num of UC ARPs", safe_mce_sys().neigh_uc_arp_quata,
                      MCE_DEFAULT_NEIGH_UC_ARP_QUATA, SYS_VAR_NEIGH_UC_ARP_QUATA);
    VLOG_PARAM_NUMBER("UC ARP delay (msec)", safe_mce_sys().neigh_wait_till_send_arp_msec,
                      MCE_DEFAULT_NEIGH_UC_ARP_DELAY_MSEC, SYS_VAR_NEIGH_UC_ARP_DELAY_MSEC);
    VLOG_PARAM_NUMBER("Num of neigh restart retries", safe_mce_sys().neigh_num_err_retries,
                      MCE_DEFAULT_NEIGH_NUM_ERR_RETRIES, SYS_VAR_NEIGH_NUM_ERR_RETRIES);

    VLOG_PARAM_STRING("SocketXtreme mode", safe_mce_sys().enable_socketxtreme,
                      MCE_DEFAULT_SOCKETXTREME, SYS_VAR_SOCKETXTREME,
                      safe_mce_sys().enable_socketxtreme ? "Enabled " : "Disabled");
    VLOG_STR_PARAM_STRING("TSO support", option_3::to_str(safe_mce_sys().enable_tso),
                          option_3::to_str(MCE_DEFAULT_TSO), SYS_VAR_TSO,
                          option_3::to_str(safe_mce_sys().enable_tso));
    VLOG_STR_PARAM_STRING("LRO support", option_3::to_str(safe_mce_sys().enable_lro),
                          option_3::to_str(MCE_DEFAULT_LRO), SYS_VAR_LRO,
                          option_3::to_str(safe_mce_sys().enable_lro));
    VLOG_PARAM_STRING("BF (Blue Flame)", safe_mce_sys().handle_bf, MCE_DEFAULT_BF_FLAG, SYS_VAR_BF,
                      safe_mce_sys().handle_bf ? "Enabled " : "Disabled");
#ifdef DEFINED_UTLS
    VLOG_PARAM_STRING("UTLS RX support", safe_mce_sys().enable_utls_rx, MCE_DEFAULT_UTLS_RX,
                      SYS_VAR_UTLS_RX, safe_mce_sys().enable_utls_rx ? "Enabled " : "Disabled");
    VLOG_PARAM_STRING("UTLS TX support", safe_mce_sys().enable_utls_tx, MCE_DEFAULT_UTLS_TX,
                      SYS_VAR_UTLS_TX, safe_mce_sys().enable_utls_tx ? "Enabled " : "Disabled");
    VLOG_PARAM_NUMBER("UTLS high watermark DEK cache size",
                      static_cast<uint32_t>(safe_mce_sys().utls_high_wmark_dek_cache_size),
                      MCE_DEFAULT_UTLS_HIGH_WMARK_DEK_CACHE_SIZE,
                      SYS_VAR_UTLS_HIGH_WMARK_DEK_CACHE_SIZE);
    VLOG_PARAM_NUMBER("UTLS low watermark DEK cache size",
                      static_cast<uint32_t>(safe_mce_sys().utls_low_wmark_dek_cache_size),
                      MCE_DEFAULT_UTLS_LOW_WMARK_DEK_CACHE_SIZE,
                      SYS_VAR_UTLS_LOW_WMARK_DEK_CACHE_SIZE);
#endif /* DEFINED_UTLS */
#if defined(DEFINED_NGINX)
    VLOG_PARAM_NUMBER("Number of Nginx workers",
                      (safe_mce_sys().app.type == APP_NGINX ? safe_mce_sys().app.workers_num
                                                            : MCE_DEFAULT_APP_WORKERS_NUM),
                      MCE_DEFAULT_APP_WORKERS_NUM, SYS_VAR_NGINX_WORKERS_NUM);
    VLOG_PARAM_NUMBER("Size of UDP socket pool", safe_mce_sys().nginx_udp_socket_pool_size,
                      MCE_DEFAULT_NGINX_UDP_POOL_SIZE, SYS_VAR_NGINX_UDP_POOL_SIZE);
    VLOG_PARAM_NUMBER(
        "Max RX reuse buffs UDP pool", safe_mce_sys().nginx_udp_socket_pool_rx_num_buffs_reuse,
        MCE_DEFAULT_NGINX_UDP_POOL_RX_NUM_BUFFS_REUSE, SYS_VAR_NGINX_UDP_POOL_RX_NUM_BUFFS_REUSE);
#endif
#if defined(DEFINED_ENVOY)
    VLOG_PARAM_NUMBER("Number of Envoy workers",
                      (safe_mce_sys().app.type == APP_ENVOY ? safe_mce_sys().app.workers_num
                                                            : MCE_DEFAULT_APP_WORKERS_NUM),
                      MCE_DEFAULT_APP_WORKERS_NUM, SYS_VAR_ENVOY_WORKERS_NUM);
#endif /* DEFINED_ENVOY */
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    VLOG_PARAM_NUMBER("Src port stirde", safe_mce_sys().app.src_port_stride,
                      MCE_DEFAULT_SRC_PORT_STRIDE, SYS_VAR_SRC_PORT_STRIDE);
#endif
    VLOG_PARAM_STRING("fork() support", safe_mce_sys().handle_fork, MCE_DEFAULT_FORK_SUPPORT,
                      SYS_VAR_FORK, safe_mce_sys().handle_fork ? "Enabled " : "Disabled");
    VLOG_PARAM_STRING("close on dup2()", safe_mce_sys().close_on_dup2, MCE_DEFAULT_CLOSE_ON_DUP2,
                      SYS_VAR_CLOSE_ON_DUP2,
                      safe_mce_sys().close_on_dup2 ? "Enabled " : "Disabled");
    switch (safe_mce_sys().mtu) {
    case MTU_FOLLOW_INTERFACE:
        VLOG_PARAM_NUMSTR("MTU", safe_mce_sys().mtu, MCE_DEFAULT_MTU, SYS_VAR_MTU,
                          "(follow actual MTU)");
        break;
    default:
        VLOG_PARAM_NUMBER("MTU", safe_mce_sys().mtu, MCE_DEFAULT_MTU, SYS_VAR_MTU);
        break;
    }
    switch (safe_mce_sys().lwip_mss) {
    case MSS_FOLLOW_MTU:
        VLOG_PARAM_NUMSTR("MSS", safe_mce_sys().lwip_mss, MCE_DEFAULT_MSS, SYS_VAR_MSS,
                          "(follow XLIO_MTU)");
        break;
    default:
        VLOG_PARAM_NUMBER("MSS", safe_mce_sys().lwip_mss, MCE_DEFAULT_MSS, SYS_VAR_MSS);
        break;
    }
    VLOG_PARAM_NUMSTR("TCP CC Algorithm", safe_mce_sys().lwip_cc_algo_mod,
                      MCE_DEFAULT_LWIP_CC_ALGO_MOD, SYS_VAR_TCP_CC_ALGO,
                      lwip_cc_algo_str(safe_mce_sys().lwip_cc_algo_mod));
    VLOG_PARAM_STRING("Deferred close", safe_mce_sys().deferred_close, MCE_DEFAULT_DEFERRED_CLOSE,
                      SYS_VAR_DEFERRED_CLOSE,
                      safe_mce_sys().deferred_close ? "Enabled " : "Disabled");
    VLOG_PARAM_STRING("TCP abort on close", safe_mce_sys().tcp_abort_on_close,
                      MCE_DEFAULT_TCP_ABORT_ON_CLOSE, SYS_VAR_TCP_ABORT_ON_CLOSE,
                      safe_mce_sys().tcp_abort_on_close ? "Enabled " : "Disabled");
    VLOG_PARAM_STRING("Polling Rx on Tx TCP", safe_mce_sys().rx_poll_on_tx_tcp,
                      MCE_DEFAULT_RX_POLL_ON_TX_TCP, SYS_VAR_RX_POLL_ON_TX_TCP,
                      safe_mce_sys().rx_poll_on_tx_tcp ? "Enabled " : "Disabled");
    VLOG_PARAM_STRING("RX CQ wait control", safe_mce_sys().rx_cq_wait_ctrl,
                      MCE_DEFAULT_RX_CQ_WAIT_CTRL, SYS_VAR_RX_CQ_WAIT_CTRL,
                      safe_mce_sys().rx_cq_wait_ctrl ? "Enabled " : "Disabled");
    VLOG_PARAM_STRING(
        "Trig dummy send getsockname()", safe_mce_sys().trigger_dummy_send_getsockname,
        MCE_DEFAULT_TRIGGER_DUMMY_SEND_GETSOCKNAME, SYS_VAR_TRIGGER_DUMMY_SEND_GETSOCKNAME,
        safe_mce_sys().trigger_dummy_send_getsockname ? "Enabled " : "Disabled");
    VLOG_PARAM_STRING(
        "Skip CQ polling in rx", safe_mce_sys().skip_poll_in_rx, MCE_DEFAULT_SKIP_POLL_IN_RX,
        SYS_VAR_SKIP_POLL_IN_RX,
        safe_mce_sys().skip_poll_in_rx
            ? (safe_mce_sys().skip_poll_in_rx == SKIP_POLL_IN_RX_ENABLE ? "Enabled " : "Epoll Only")
            : "Disabled");
    VLOG_PARAM_STRING("Lock Type", safe_mce_sys().multilock, MCE_DEFAULT_MULTILOCK,
                      SYS_VAR_MULTILOCK,
                      (safe_mce_sys().multilock == MULTILOCK_SPIN ? "Spin " : "Mutex"));

    vlog_printf(VLOG_INFO,
                "---------------------------------------------------------------------------\n");
}

void prepare_fork()
{
    if (safe_mce_sys().handle_fork && !g_init_ibv_fork_done) {
        IF_VERBS_FAILURE(ibv_fork_init())
        {
            vlog_printf(VLOG_DEBUG, "ibv_fork_init failed (errno=%d %m)\n", errno);
            vlog_printf(
                VLOG_ERROR,
                "************************************************************************\n");
            vlog_printf(VLOG_ERROR,
                        "ibv_fork_init() failed! The effect of the application calling 'fork()' is "
                        "undefined!\n");
            vlog_printf(VLOG_ERROR,
                        "Read the fork section in the " PRODUCT_NAME
                        "'s User Manual for more information\n");
            vlog_printf(
                VLOG_ERROR,
                "************************************************************************\n");
        }
        else
        {
            g_init_ibv_fork_done = true;
            vlog_printf(VLOG_DEBUG, "ibv_fork_init() succeeded, fork() may be used safely!!\n");
        }
        ENDIF_VERBS_FAILURE;
    }
}

void register_handler_segv()
{
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = handle_segfault;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGSEGV, &act, nullptr);
    vlog_printf(VLOG_INFO, "Registered a SIGSEGV handler\n");
}

extern "C" void sock_redirect_main(void)
{
    vlog_printf(VLOG_DEBUG, "%s()\n", __FUNCTION__);
    //	int ret = atexit(sock_redirect_exit);
    //	if (ret)
    //		vlog_printf(VLOG_ERROR, "%s() ERROR at atexit() (ret=%d %m)\n", __FUNCTION__, ret);

    tv_clear(&g_last_zero_polling_time);

    if (safe_mce_sys().handle_segfault) {
        register_handler_segv();
    }
}

extern "C" void sock_redirect_exit(void)
{
    vlog_printf(VLOG_DEBUG, "%s()\n", __FUNCTION__);

    if (g_init_global_ctors_done) {
        xlio_stats_instance_remove_global_block(&g_global_stat_static);
    }

    xlio_shmem_stats_close();
}

#define NEW_CTOR(ptr, ctor)                                                                        \
    do {                                                                                           \
        if (!ptr) {                                                                                \
            ptr = new ctor;                                                                        \
            BULLSEYE_EXCLUDE_BLOCK_START                                                           \
            if (ptr == NULL) {                                                                     \
                throw_xlio_exception("Failed allocate " #ctor "\n");                               \
                return;                                                                            \
            }                                                                                      \
            BULLSEYE_EXCLUDE_BLOCK_END                                                             \
        }                                                                                          \
    } while (0);

static size_t calc_rx_wqe_buff_size()
{
    size_t buff_size =
        RX_BUF_SIZE(safe_mce_sys().rx_buf_size ? safe_mce_sys().rx_buf_size
                                               : g_p_net_device_table_mgr->get_max_mtu());
    if (safe_mce_sys().enable_striding_rq) {
        size_t min_puff_size = g_p_net_device_table_mgr->get_max_mtu() + ETH_VLAN_HDR_LEN;
        buff_size = safe_mce_sys().strq_stride_num_per_rwqe * safe_mce_sys().strq_stride_size_bytes;
        if (buff_size < min_puff_size) {
            vlog_printf(VLOG_INFO,
                        "The requested " SYS_VAR_STRQ_NUM_STRIDES "(%" PRIu32
                        ") * " SYS_VAR_STRQ_STRIDE_SIZE_BYTES "(%" PRIu32 ") = %zu "
                        "is less then MTU + Headers (%zu)",
                        safe_mce_sys().strq_stride_num_per_rwqe,
                        safe_mce_sys().strq_stride_size_bytes, buff_size, min_puff_size);

            buff_size = g_p_net_device_table_mgr->get_max_mtu() + ETH_VLAN_HDR_LEN;
        }
    }

    return buff_size;
}

static void do_global_ctors_helper()
{
    static lock_spin_recursive g_globals_lock;
    std::lock_guard<decltype(g_globals_lock)> lock(g_globals_lock);

    if (g_init_global_ctors_done) {
        return;
    }
    PROFILE_BLOCK("xlio_ctors")

    g_init_global_ctors_done = true;
    set_env_params();
    prepare_fork();

    // Adjust configuration before subsystems initialization. We do this here
    // not to affect XLIO header output.
    safe_mce_sys().update_multi_process_params();

    if (g_is_forked_child == true) {
        g_is_forked_child = false;
    }

    xlio_heap::initialize();

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    NEW_CTOR(g_p_app, app_conf());
#endif

    /* Open communication with daemon */
    if (safe_mce_sys().service_enable) {
        NEW_CTOR(g_p_agent, agent());
        vlog_printf(VLOG_DEBUG, "Agent setup state: g_p_agent=%p active=%d\n", g_p_agent,
                    (g_p_agent ? g_p_agent->state() : -1));
    } else {
        vlog_printf(VLOG_DEBUG, "Agent is disabled\n");
    }

    // Create all global management objects
    NEW_CTOR(g_p_event_handler_manager, event_handler_manager());

    xlio_shmem_stats_open(&g_p_vlogger_level, &g_p_vlogger_details);
    *g_p_vlogger_level = g_vlogger_level;
    *g_p_vlogger_details = g_vlogger_details;

    sock_stats::instance().init_sock_stats(safe_mce_sys().stats_fd_num_max);

    g_global_stat_static.init();
    xlio_stats_instance_create_global_block(&g_global_stat_static);

    // Create new netlink listener
    NEW_CTOR(g_p_netlink_handler, netlink_wrapper());

    NEW_CTOR(g_p_ib_ctx_handler_collection, ib_ctx_handler_collection());

    NEW_CTOR(g_p_net_device_table_mgr, net_device_table_mgr());

    NEW_CTOR(g_p_neigh_table_mgr, neigh_table_mgr());

    NEW_CTOR(g_p_rule_table_mgr, rule_table_mgr());

    NEW_CTOR(g_p_route_table_mgr, route_table_mgr());

    NEW_CTOR(g_bind_no_port, bind_no_port());

    NEW_CTOR(g_zc_cache, mapping_cache(safe_mce_sys().zc_cache_threshold));

    safe_mce_sys().rx_buf_size = std::min(safe_mce_sys().rx_buf_size, 0xFF00U);
    if (safe_mce_sys().rx_buf_size <=
        get_lwip_tcp_mss(g_p_net_device_table_mgr->get_max_mtu(), safe_mce_sys().lwip_mss)) {
        safe_mce_sys().rx_buf_size = 0;
    }

    NEW_CTOR(g_buffer_pool_rx_rwqe,
             buffer_pool(BUFFER_POOL_RX, calc_rx_wqe_buff_size(),
                         (safe_mce_sys().m_ioctl.user_alloc.flags & IOCTL_USER_ALLOC_RX
                              ? safe_mce_sys().m_ioctl.user_alloc.memalloc
                              : nullptr),
                         (safe_mce_sys().m_ioctl.user_alloc.flags & IOCTL_USER_ALLOC_RX
                              ? safe_mce_sys().m_ioctl.user_alloc.memfree
                              : nullptr)));

    if (safe_mce_sys().enable_striding_rq) {
        NEW_CTOR(g_buffer_pool_rx_stride, buffer_pool(BUFFER_POOL_RX, 0));
        g_buffer_pool_rx_ptr = g_buffer_pool_rx_stride;
    } else {
        g_buffer_pool_rx_ptr = g_buffer_pool_rx_rwqe;
    }

    safe_mce_sys().tx_buf_size = std::min(safe_mce_sys().tx_buf_size, 0xFF00U);
    if (safe_mce_sys().tx_buf_size <=
        get_lwip_tcp_mss(g_p_net_device_table_mgr->get_max_mtu(), safe_mce_sys().lwip_mss)) {
        safe_mce_sys().tx_buf_size = 0;
    }
    NEW_CTOR(g_buffer_pool_tx,
             buffer_pool(BUFFER_POOL_TX,
                         TX_BUF_SIZE(safe_mce_sys().tx_buf_size
                                         ? safe_mce_sys().tx_buf_size
                                         : get_lwip_tcp_mss(g_p_net_device_table_mgr->get_max_mtu(),
                                                            safe_mce_sys().lwip_mss)),
                         (safe_mce_sys().m_ioctl.user_alloc.flags & IOCTL_USER_ALLOC_TX
                              ? safe_mce_sys().m_ioctl.user_alloc.memalloc
                              : nullptr),
                         (safe_mce_sys().m_ioctl.user_alloc.flags & IOCTL_USER_ALLOC_TX
                              ? safe_mce_sys().m_ioctl.user_alloc.memfree
                              : nullptr)));

    NEW_CTOR(g_buffer_pool_zc, buffer_pool(BUFFER_POOL_TX, 0));

    NEW_CTOR(g_tcp_seg_pool, tcp_seg_pool());

    // For delegated TCP timers the global collection is not used.
    if (safe_mce_sys().tcp_ctl_thread != option_tcp_ctl_thread::CTL_THREAD_DELEGATE_TCP_TIMERS) {
        NEW_CTOR(g_tcp_timers_collection, tcp_timers_collection());
    }

    NEW_CTOR(g_p_vlogger_timer_handler, vlogger_timer_handler());

    NEW_CTOR(g_p_ip_frag_manager, ip_frag_manager());

    NEW_CTOR(g_p_fd_collection, fd_collection());

    if (check_if_regular_file(safe_mce_sys().conf_filename)) {
        vlog_printf(VLOG_WARNING,
                    "FAILED to read library configuration file. %s is not a regular file.\n",
                    safe_mce_sys().conf_filename);
        if (strcmp(MCE_DEFAULT_CONF_FILE, safe_mce_sys().conf_filename)) {
            vlog_printf(VLOG_INFO, "Please see README section regarding %s\n",
                        SYS_VAR_CONF_FILENAME);
        }
    } else if (__xlio_parse_config_file(safe_mce_sys().conf_filename)) {
        vlog_printf(VLOG_DEBUG, "FAILED to read library configuration file: %s\n",
                    safe_mce_sys().conf_filename);
    }

    // initialize LWIP tcp/ip stack
    NEW_CTOR(g_p_lwip, xlio_lwip());

    if (g_p_netlink_handler) {
        // Open netlink socket
        BULLSEYE_EXCLUDE_BLOCK_START
        if (g_p_netlink_handler->open_channel()) {
            throw_xlio_exception("Failed in netlink open_channel()\n");
        }

        int fd = g_p_netlink_handler->get_channel();
        if (fd == -1) {
            throw_xlio_exception("Netlink fd == -1\n");
        }

        // Register netlink fd to the event_manager
        s_cmd_nl = new command_netlink(g_p_netlink_handler);
        if (!s_cmd_nl) {
            throw_xlio_exception("Failed allocating command_netlink\n");
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        g_p_event_handler_manager->register_command_event(fd, s_cmd_nl);
        g_p_event_handler_manager->register_timer_event(safe_mce_sys().timer_netlink_update_msec,
                                                        s_cmd_nl, PERIODIC_TIMER, nullptr);
    }

#ifdef DEFINED_UTLS
    xlio_tls_api_setup();
#endif /* DEFINED_UTLS */
}

int do_global_ctors()
{
    int errno_backup = errno;
    try {
        do_global_ctors_helper();
    } catch (const xlio_exception &error) {
        vlog_printf(VLOG_DETAILS, "Error: %s", error.what());
        return -1;
    } catch (const std::exception &error) {
        vlog_printf(VLOG_ERROR, "%s", error.what());
        return -1;
    }
    /* do not return internal errno in case constructor is executed successfully */
    errno = errno_backup;
    return 0;
}

void reset_globals()
{
    g_p_fd_collection = nullptr;
    g_p_ip_frag_manager = nullptr;
    g_zc_cache = nullptr;
    g_buffer_pool_rx_ptr = nullptr;
    g_buffer_pool_rx_stride = nullptr;
    g_buffer_pool_rx_rwqe = nullptr;
    g_buffer_pool_tx = nullptr;
    g_buffer_pool_zc = nullptr;
    g_tcp_seg_pool = nullptr;
    g_tcp_timers_collection = nullptr;
    g_p_vlogger_timer_handler = nullptr;
    g_p_event_handler_manager = nullptr;
    g_p_agent = nullptr;
    g_p_route_table_mgr = nullptr;
    g_bind_no_port = nullptr;
    g_p_rule_table_mgr = nullptr;
    g_stats_file = nullptr;
    g_p_net_device_table_mgr = nullptr;
    g_p_neigh_table_mgr = nullptr;
    g_p_lwip = nullptr;
    g_p_netlink_handler = nullptr;
    g_p_ib_ctx_handler_collection = nullptr;
    s_cmd_nl = nullptr;
    g_cpu_manager.reset();
}

// checks that netserver runs with flags: -D, -f. Otherwise, warn user for wrong usage
// this test is performed since xlio does not support fork, and these flags make sure the netserver
// application will not use fork.
void check_netperf_flags()
{
    char cmd_line[FILENAME_MAX];
    char *pch, *command;
    bool b_D_flag = false, b_f_flag = false;
    char add_flags[4] = {0};

    strncpy(cmd_line, safe_mce_sys().app_name, sizeof(cmd_line) - 1);
    cmd_line[sizeof(cmd_line) - 1] = '\0';
    pch = strtok(cmd_line, " ");

    command = basename(pch); // extract only "netserver" from full path
    if (strcmp(command, "netserver")) {
        return;
    }
    pch = strtok(nullptr, " ");

    while (pch) {
        if (*pch == '-') {
            if (strchr(pch, 'D')) {
                b_D_flag = true;
            }
            if (strchr(pch, 'f')) {
                b_f_flag = true;
            }
        }
        if (b_f_flag && b_D_flag) {
            break;
        }
        pch = strtok(nullptr, " ");
    }
    if (!b_D_flag || !b_f_flag) {
        vlog_printf(VLOG_WARNING, "Running netserver without flags: -D, -f can cause failure\n");
        add_flags[0] = '-'; // check which flags need to be added to the command
        if (!b_D_flag) {
            add_flags[1] = 'D';
        }
        if (!b_f_flag) {
            add_flags[1] == 0 ? add_flags[1] = 'f' : add_flags[2] = 'f';
        }
        vlog_printf(VLOG_WARNING, "Recommended command line: %s %s\n", safe_mce_sys().app_name,
                    add_flags);
    }
}

/*
 * -----------------------------------------------------------------------------
 * library init/exit function
 * sock_redirect_lib_load_constructor(void) is used to be called when
 * library is loaded
 * sock_redirect_lib_load_destructor(void) is used to be called when
 * library is unloaded
 *
 * Note:
 * The POSIX standard actually does not require dlclose() to ever unload a library
 * from address space on function return.
 * See: https://pubs.opengroup.org/onlinepubs/007904975/functions/dlclose.html
 * That means other than invalidating the handle, dlclose() can not required to
 * do anything at all and real unloading can be delayed.
 * Workaround:
 * - xlio_exit symbol should be visible
 * - call dlclose(handle)
 * - call dlopen("library", RTLD_NOW | RTLD_NOLOAD) to check if the library is in memory
 * - do nothing or call xlio_exit() to force the library finalization
 * -----------------------------------------------------------------------------
 */
extern "C" int xlio_init(void)
{
    PROFILE_FUNC

#ifndef XLIO_STATIC_BUILD
    get_orig_funcs();
#endif /* XLIO_STATIC_BUILD */
    safe_mce_sys();

    g_init_global_ctors_done = false;

    vlog_start(PRODUCT_NAME, safe_mce_sys().log_level, safe_mce_sys().log_filename,
               safe_mce_sys().log_details, safe_mce_sys().log_colors);

    print_xlio_global_settings();

    check_debug();
    check_cpu_speed();
    check_locked_mem();
    check_netperf_flags();

    if (*safe_mce_sys().stats_filename) {
        if (check_if_regular_file(safe_mce_sys().stats_filename)) {
            vlog_printf(VLOG_WARNING,
                        "FAILED to create " PRODUCT_NAME
                        " statistics file. %s is not a regular file.\n",
                        safe_mce_sys().stats_filename);
        } else if (!(g_stats_file = fopen(safe_mce_sys().stats_filename, "w"))) {
            vlog_printf(VLOG_WARNING, " Couldn't open statistics file: %s\n",
                        safe_mce_sys().stats_filename);
        }
    }
    safe_mce_sys().stats_file = g_stats_file;

    sock_redirect_main();

    return 0;
}

extern "C" EXPORT_SYMBOL int xlio_exit(void)
{
    int rc = 0;

    PROFILE_FUNC

    if (g_init_global_ctors_done) {
        rc = free_libxlio_resources();
        g_init_global_ctors_done = false;
    }

    return rc;
}
