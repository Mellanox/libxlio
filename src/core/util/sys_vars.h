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

#ifndef SYS_VARS_H
#define SYS_VARS_H

#include <stdio.h>
#include <sched.h>
#include <string>
#include <netinet/in.h>

#include "vtypes.h"
#include "config.h"

#include "core/ib/base/verbs_extra.h"
#include "core/util/sysctl_reader.h"
#include "core/util/agent_def.h"
#include "core/xlio_extra.h"

typedef enum {
    MCE_SPEC_NONE = 0,
    MCE_SPEC_SOCKPERF_ULTRA_LATENCY,
    MCE_SPEC_SOCKPERF_LATENCY,
    MCE_SPEC_LL_MULTI_RING,
    MCE_SPEC_NGINX,
    MCE_SPEC_NGINX_DPU,
    MCE_SPEC_NVME_BF2,
    MCE_SPEC_ALL /* last element */
} xlio_spec_t;

enum {
    IOCTL_USER_ALLOC_TX = (1 << 0),
    IOCTL_USER_ALLOC_RX = (1 << 1),
};

typedef void *(*alloc_t)(size_t);
typedef void (*free_t)(void *);

typedef enum {
    TS_CONVERSION_MODE_DISABLE = 0, // TS_CONVERSION_MODE_DISABLE must be the first enum
    TS_CONVERSION_MODE_RAW,
    TS_CONVERSION_MODE_BEST_POSSIBLE,
    TS_CONVERSION_MODE_SYNC,
    TS_CONVERSION_MODE_PTP,
    TS_CONVERSION_MODE_RTC,
    TS_CONVERSION_MODE_LAST
} ts_conversion_mode_t;

static inline bool is_ring_logic_valid(ring_logic_t logic)
{
    switch (logic) {
    case RING_LOGIC_PER_INTERFACE:
    case RING_LOGIC_PER_IP:
    case RING_LOGIC_PER_SOCKET:
    case RING_LOGIC_PER_THREAD:
    case RING_LOGIC_PER_CORE:
    case RING_LOGIC_PER_CORE_ATTACH_THREADS:
        return true;
    default:
        return false;
    }
}

static inline const char *ring_logic_str(ring_logic_t logic)
{
    switch (logic) {
    case RING_LOGIC_PER_INTERFACE:
        return "(Ring per interface)";
    case RING_LOGIC_PER_IP:
        return "(Ring per ip)";
    case RING_LOGIC_PER_SOCKET:
        return "(Ring per socket)";
    case RING_LOGIC_PER_THREAD:
        return "(Ring per thread)";
    case RING_LOGIC_PER_CORE:
        return "(Ring per core)";
    case RING_LOGIC_PER_CORE_ATTACH_THREADS:
        return "(Ring per core - attach threads)";
    default:
        break;
    }
    return "unsupported";
}

typedef enum {
    THREAD_MODE_SINGLE = 0,
    THREAD_MODE_MULTI,
    THREAD_MODE_MUTEX,
    THREAD_MODE_PLENTY,
    THREAD_MODE_LAST
} thread_mode_t;

typedef enum {
    BUFFER_BATCHING_NONE = 0,
    BUFFER_BATCHING_WITH_RECLAIM,
    BUFFER_BATCHING_NO_RECLAIM,
    BUFFER_BATCHING_LAST,
} buffer_batching_mode_t;

// See ibv_transport_type for general verbs transport types
typedef enum { XLIO_TRANSPORT_UNKNOWN = -1, XLIO_TRANSPORT_ETH } transport_type_t;

typedef enum { APP_NONE, APP_NGINX, APP_ENVOY } app_type_t;

static inline const char *priv_xlio_transport_type_str(transport_type_t transport_type)
{
    BULLSEYE_EXCLUDE_BLOCK_START
    switch (transport_type) {
    case XLIO_TRANSPORT_ETH:
        return "ETH";
    case XLIO_TRANSPORT_UNKNOWN:
    default:
        break;
    }
    return "UNKNOWN";
    BULLSEYE_EXCLUDE_BLOCK_END
}

typedef enum { MSS_FOLLOW_MTU = 0 } mss_mode_t;

typedef enum { MTU_FOLLOW_INTERFACE = 0 } mtu_mode_t;

typedef enum {
    CTL_THREAD_DISABLE = 0,
    CTL_THREAD_DELEGATE_TCP_TIMERS,
    CTL_THREAD_WITH_WAKEUP,
    CTL_THREAD_NO_WAKEUP,
    CTL_THREAD_LAST
} tcp_ctl_thread_t;

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

namespace xlio_spec {
// convert str to vXLIO_spec_t; upon error - returns the given 'def_value'
xlio_spec_t from_str(const char *str, xlio_spec_t def_value = MCE_SPEC_NONE);

// convert int to vXLIO_spec_t; upon error - returns the given 'def_value'
xlio_spec_t from_int(const int int_spec, xlio_spec_t def_value = MCE_SPEC_NONE);

const char *to_str(xlio_spec_t level);
} // namespace xlio_spec

#define AUTO_ON_OFF_DEF AUTO = -1, OFF = 0, ON = 1

#define OPTIONS_FROM_TO_STR_DEF                                                                    \
    mode_t from_str(const char *str, mode_t def_value);                                            \
    mode_t from_int(const int option, mode_t def_value);                                           \
    const char *to_str(mode_t option)

namespace option_size {
size_t from_str(const char *str);
const char *to_str(size_t size);
const char *to_str(size_t size, char *s, size_t len);
} // namespace option_size

namespace option_3 {
typedef enum { AUTO_ON_OFF_DEF } mode_t;
OPTIONS_FROM_TO_STR_DEF;
} // namespace option_3

namespace option_tcp_ctl_thread {
typedef enum {
    CTL_THREAD_DISABLE = 0,
    CTL_THREAD_DELEGATE_TCP_TIMERS,
    CTL_THREAD_WITH_WAKEUP,
    CTL_THREAD_NO_WAKEUP,
    CTL_THREAD_LAST
} mode_t;
OPTIONS_FROM_TO_STR_DEF;
} // namespace option_tcp_ctl_thread

#define tcp_ctl_thread_on(var) ((var) > option_tcp_ctl_thread::CTL_THREAD_DELEGATE_TCP_TIMERS)

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

////////////////////////////////////////////////////////////////////////////////
class xlio_exception_handling {
public:
    static const char *getName() { return "Exception handling mode"; }

    static const char *getSysVar() { return "XLIO_EXCEPTION_HANDLING"; }

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

    const char *to_str()
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

    bool is_suit_un_offloading() { return m_mode == MODE_UNOFFLOAD || m_mode == MODE_LOG_ERROR; }

    vlog_levels_t get_log_severity()
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

////////////////////////////////////////////////////////////////////////////////
struct mce_sys_var {
    static mce_sys_var &instance()
    {
        static mce_sys_var the_instance; // singelton
        return the_instance;
    }

public:
    enum hyper_t { HYPER_NONE = 0, HYPER_XEN, HYPER_KVM, HYPER_MSHV, HYPER_VMWARE };

public:
    void get_env_params();

    // Update parameters for multi-process applications
    void update_multi_process_params();

    char *app_name;
    char app_id[MAX_APP_ID_LENGHT];

    uint32_t mce_spec;

    bool print_report;
    vlog_levels_t log_level;
    uint32_t log_details;
    char log_filename[PATH_MAX];
    char stats_filename[PATH_MAX];
    char stats_shmem_dirname[PATH_MAX];
    char conf_filename[PATH_MAX];
    char service_notify_dir[PATH_MAX];
    bool service_enable;
    bool log_colors;
    bool handle_sigintr;
    bool handle_segfault;
    uint32_t stats_fd_num_max;

    ring_logic_t ring_allocation_logic_tx;
    ring_logic_t ring_allocation_logic_rx;
    int ring_migration_ratio_tx;
    int ring_migration_ratio_rx;
    int ring_limit_per_interface;
    int ring_dev_mem_tx;
    int tcp_max_syn_rate;

    size_t zc_cache_threshold;
    uint32_t tx_num_bufs;
    uint32_t tx_buf_size;
    uint32_t zc_tx_size;
    uint32_t tcp_nodelay_treshold;
    uint32_t tx_num_wr;
    uint32_t tx_num_wr_to_signal;
    uint32_t tx_max_inline;
    bool tx_mc_loopback_default;
    bool tx_nonblocked_eagains;
    uint32_t tx_prefetch_bytes;
    uint32_t tx_bufs_batch_udp;
    uint32_t tx_bufs_batch_tcp;
    uint32_t tx_segs_batch_tcp;

    uint32_t rx_num_bufs;
    uint32_t rx_buf_size;
    uint32_t rx_bufs_batch;
    uint32_t rx_num_wr;
    uint32_t rx_num_wr_to_post_recv;
    int32_t rx_poll_num;
    int32_t rx_poll_num_init;
    uint32_t rx_udp_poll_os_ratio;
    ts_conversion_mode_t hw_ts_conversion_mode;
    uint32_t rx_poll_yield_loops;
    uint32_t rx_ready_byte_min_limit;
    uint32_t rx_prefetch_bytes;
    uint32_t rx_prefetch_bytes_before_poll;
    uint32_t rx_cq_drain_rate_nsec; // If enabled this will cause the Rx to drain all wce in CQ
                                    // before returning to user, Else (Default: Disbaled) it will
                                    // return when first ready packet is in socket queue
    uint32_t rx_delta_tsc_between_cq_polls;

    uint32_t strq_stride_num_per_rwqe;
    uint32_t strq_stride_size_bytes;
    uint32_t strq_strides_num_bufs;
    uint32_t strq_strides_compensation_level;

    uint32_t gro_streams_max;
    bool disable_flow_tag;

    bool enable_striding_rq;
    bool tcp_3t_rules;
    bool udp_3t_rules;
    bool eth_mc_l2_only_rules;
    bool mc_force_flowtag;

    int32_t select_poll_num;
    bool select_poll_os_force;
    uint32_t select_poll_os_ratio;
    uint32_t select_skip_os_fd_check;
    bool select_handle_cpu_usage_stats;

    bool cq_moderation_enable;
    uint32_t cq_moderation_count;
    uint32_t cq_moderation_period_usec;
    uint32_t cq_aim_max_count;
    uint32_t cq_aim_max_period_usec;
    uint32_t cq_aim_interval_msec;
    uint32_t cq_aim_interrupts_rate_per_sec;

    uint32_t cq_poll_batch_max;
    uint32_t progress_engine_interval_msec;
    uint32_t progress_engine_wce_max;
    bool cq_keep_qp_full;
    uint32_t qp_compensation_level;
    size_t user_huge_page_size;

    bool offloaded_sockets;
    uint32_t timer_resolution_msec;
    uint32_t tcp_timer_resolution_msec;
    option_tcp_ctl_thread::mode_t tcp_ctl_thread;
    tcp_ts_opt_t tcp_ts_opt;
    bool tcp_nodelay;
    bool tcp_quickack;
    bool tcp_push_flag;
    xlio_exception_handling exception_handling;
    bool avoid_sys_calls_on_tcp_fd;
    bool allow_privileged_sock_opt;
    uint32_t wait_after_join_msec;
    thread_mode_t thread_mode;
    buffer_batching_mode_t buffer_batching_mode;
    option_alloc_type::mode_t mem_alloc_type;
    size_t memory_limit;
    size_t memory_limit_user;
    size_t heap_metadata_block;
    uint8_t hugepage_log2;
    bool handle_fork;
    bool close_on_dup2;
    uint32_t mtu; /* effective MTU. If mtu==0 then auto calculate the MTU */
    uint32_t lwip_cc_algo_mod;
    uint32_t lwip_mss;
    char internal_thread_cpuset[FILENAME_MAX];
    char internal_thread_affinity_str[FILENAME_MAX];
    cpu_set_t internal_thread_affinity;
    bool internal_thread_arm_cq_enabled;
    bool handle_bf;
    skip_poll_in_rx_t skip_poll_in_rx;
    multilock_t multilock;

    bool enable_socketxtreme;
    option_3::mode_t enable_tso;
    option_3::mode_t enable_lro;
    option_3::mode_t enable_strq_env;
#ifdef DEFINED_UTLS
    bool enable_utls_rx;
    bool enable_utls_tx;
    // DEK cache size high-watermark. Max number of DEKs to be stored in the cache.
    size_t utls_high_wmark_dek_cache_size;
    // DEK cache size low-watermark. Min number of available DEKs required in the cache
    // to perform Crypto-Sync and reuse.
    size_t utls_low_wmark_dek_cache_size;
#endif /* DEFINED_UTLS */
    uint32_t timer_netlink_update_msec;

    // Neigh parameters
    uint32_t neigh_uc_arp_quata;
    uint32_t neigh_wait_till_send_arp_msec;
    uint32_t neigh_num_err_retries;

    sysctl_reader_t &sysctl_reader;
    // Workaround for #3440429: postpone close(2) to the socket destructor, so the sockfd is closed
    // after the rfs rule is destroyed. Otherwise, flow_tag or TCP port can be reused too early.
    bool deferred_close;
    bool tcp_abort_on_close;
    bool rx_poll_on_tx_tcp;
    bool rx_cq_wait_ctrl;
    hyper_t hypervisor;
    bool trigger_dummy_send_getsockname;
#if defined(DEFINED_NGINX)
    int nginx_udp_socket_pool_size;
    int nginx_udp_socket_pool_rx_num_buffs_reuse;
#endif
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    struct {
        app_type_t type;
        int workers_num;
        int src_port_stride;
        bool distribute_cq_interrupts;
    } app;
#endif
    uint32_t tcp_send_buffer_size;
    uint32_t tx_segs_ring_batch_tcp;
    uint32_t tx_segs_pool_batch_tcp;
    FILE *stats_file;
    /* This field should be used to store and use data for XLIO_EXTRA_API_IOCTL */
    struct {
        struct {
            uint8_t flags;
            alloc_t memalloc;
            free_t memfree;
        } user_alloc;
    } m_ioctl;

private:
    void print_xlio_load_failure_msg();
    int list_to_cpuset(char *cpulist, cpu_set_t *cpu_set);
    int hex_to_cpuset(char *start, cpu_set_t *cpu_set);
    int env_to_cpuset(char *orig_start, cpu_set_t *cpu_set);
    void read_env_variable_with_pid(char *mce_sys_name, size_t mce_sys_max_size, char *env_ptr);
    bool check_cpuinfo_flag(const char *flag);
    bool cpuid_hv();
    const char *cpuid_hv_vendor();
    void read_hv();
    void read_strq_strides_num();
    void read_strq_stride_size_bytes();

    // prevent unautothrized creation of objects
    mce_sys_var()
        : sysctl_reader(sysctl_reader_t::instance())
    {
        // coverity[uninit_member]
        get_env_params();
    }
    mce_sys_var(const mce_sys_var &);
    mce_sys_var &operator=(const mce_sys_var &);
};

extern mce_sys_var &safe_mce_sys();

/*
 * This block consists of library specific configuration
 * environment variables
 */
#define SYS_VAR_PRINT_REPORT        "XLIO_PRINT_REPORT"
#define SYS_VAR_LOG_LEVEL           "XLIO_TRACELEVEL"
#define SYS_VAR_LOG_DETAILS         "XLIO_LOG_DETAILS"
#define SYS_VAR_LOG_FILENAME        "XLIO_LOG_FILE"
#define SYS_VAR_STATS_FILENAME      "XLIO_STATS_FILE"
#define SYS_VAR_STATS_SHMEM_DIRNAME "XLIO_STATS_SHMEM_DIR"
#define SYS_VAR_SERVICE_DIR         "XLIO_SERVICE_NOTIFY_DIR"
#define SYS_VAR_SERVICE_ENABLE      "XLIO_SERVICE_ENABLE"
#define SYS_VAR_CONF_FILENAME       "XLIO_CONFIG_FILE"
#define SYS_VAR_LOG_COLORS          "XLIO_LOG_COLORS"
#define SYS_VAR_APPLICATION_ID      "XLIO_APPLICATION_ID"
#define SYS_VAR_HANDLE_SIGINTR      "XLIO_HANDLE_SIGINTR"
#define SYS_VAR_HANDLE_SIGSEGV      "XLIO_HANDLE_SIGSEGV"
#define SYS_VAR_STATS_FD_NUM        "XLIO_STATS_FD_NUM"

#define SYS_VAR_RING_ALLOCATION_LOGIC_TX "XLIO_RING_ALLOCATION_LOGIC_TX"
#define SYS_VAR_RING_ALLOCATION_LOGIC_RX "XLIO_RING_ALLOCATION_LOGIC_RX"
#define SYS_VAR_RING_MIGRATION_RATIO_TX  "XLIO_RING_MIGRATION_RATIO_TX"
#define SYS_VAR_RING_MIGRATION_RATIO_RX  "XLIO_RING_MIGRATION_RATIO_RX"
#define SYS_VAR_RING_LIMIT_PER_INTERFACE "XLIO_RING_LIMIT_PER_INTERFACE"
#define SYS_VAR_RING_DEV_MEM_TX          "XLIO_RING_DEV_MEM_TX"

#define SYS_VAR_ZC_CACHE_THRESHOLD    "XLIO_ZC_CACHE_THRESHOLD"
#define SYS_VAR_TX_NUM_BUFS           "XLIO_TX_BUFS"
#define SYS_VAR_TX_BUF_SIZE           "XLIO_TX_BUF_SIZE"
#define SYS_VAR_ZC_TX_SIZE            "XLIO_ZC_TX_SIZE"
#define SYS_VAR_TCP_NODELAY_TRESHOLD  "XLIO_TCP_NODELAY_TRESHOLD"
#define SYS_VAR_TX_NUM_WRE            "XLIO_TX_WRE"
#define SYS_VAR_TX_NUM_WRE_TO_SIGNAL  "XLIO_TX_WRE_BATCHING"
#define SYS_VAR_TX_MAX_INLINE         "XLIO_TX_MAX_INLINE"
#define SYS_VAR_TX_MC_LOOPBACK        "XLIO_TX_MC_LOOPBACK"
#define SYS_VAR_TX_NONBLOCKED_EAGAINS "XLIO_TX_NONBLOCKED_EAGAINS"
#define SYS_VAR_TX_PREFETCH_BYTES     "XLIO_TX_PREFETCH_BYTES"
#define SYS_VAR_TX_BUFS_BATCH_TCP     "XLIO_TX_BUFS_BATCH_TCP"
#define SYS_VAR_TX_SEGS_BATCH_TCP     "XLIO_TX_SEGS_BATCH_TCP"

#define SYS_VAR_STRQ                            "XLIO_STRQ"
#define SYS_VAR_STRQ_NUM_STRIDES                "XLIO_STRQ_NUM_STRIDES"
#define SYS_VAR_STRQ_STRIDE_SIZE_BYTES          "XLIO_STRQ_STRIDE_SIZE_BYTES"
#define SYS_VAR_STRQ_STRIDES_NUM_BUFS           "XLIO_STRQ_STRIDES_NUM_BUFS"
#define SYS_VAR_STRQ_STRIDES_COMPENSATION_LEVEL "XLIO_STRQ_STRIDES_COMPENSATION_LEVEL"

#define SYS_VAR_RX_NUM_BUFS             "XLIO_RX_BUFS"
#define SYS_VAR_RX_BUF_SIZE             "XLIO_RX_BUF_SIZE"
#define SYS_VAR_RX_NUM_WRE              "XLIO_RX_WRE"
#define SYS_VAR_RX_NUM_WRE_TO_POST_RECV "XLIO_RX_WRE_BATCHING"
#define SYS_VAR_RX_NUM_POLLS            "XLIO_RX_POLL"
#define SYS_VAR_RX_NUM_POLLS_INIT       "XLIO_RX_POLL_INIT"
#define SYS_VAR_RX_UDP_POLL_OS_RATIO    "XLIO_RX_UDP_POLL_OS_RATIO"
#define SYS_VAR_HW_TS_CONVERSION_MODE   "XLIO_HW_TS_CONVERSION"
// The following 2 params were replaced by XLIO_RX_UDP_POLL_OS_RATIO
#define SYS_VAR_RX_POLL_OS_RATIO              "XLIO_RX_POLL_OS_RATIO"
#define SYS_VAR_RX_SKIP_OS                    "XLIO_RX_SKIP_OS"
#define SYS_VAR_RX_POLL_YIELD                 "XLIO_RX_POLL_YIELD"
#define SYS_VAR_RX_BYTE_MIN_LIMIT             "XLIO_RX_BYTES_MIN"
#define SYS_VAR_RX_PREFETCH_BYTES             "XLIO_RX_PREFETCH_BYTES"
#define SYS_VAR_RX_PREFETCH_BYTES_BEFORE_POLL "XLIO_RX_PREFETCH_BYTES_BEFORE_POLL"
#define SYS_VAR_RX_CQ_DRAIN_RATE_NSEC         "XLIO_RX_CQ_DRAIN_RATE_NSEC"
#define SYS_VAR_GRO_STREAMS_MAX               "XLIO_GRO_STREAMS_MAX"
#define SYS_VAR_DISABLE_FLOW_TAG              "XLIO_DISABLE_FLOW_TAG"
#define SYS_VAR_TCP_3T_RULES                  "XLIO_TCP_3T_RULES"
#define SYS_VAR_UDP_3T_RULES                  "XLIO_UDP_3T_RULES"
#define SYS_VAR_ETH_MC_L2_ONLY_RULES          "XLIO_ETH_MC_L2_ONLY_RULES"
#define SYS_VAR_MC_FORCE_FLOWTAG              "XLIO_MC_FORCE_FLOWTAG"
#define SYS_VAR_TX_SEGS_RING_BATCH_TCP        "XLIO_TX_SEGS_RING_BATCH_TCP"
#define SYS_VAR_TX_SEGS_POOL_BATCH_TCP        "XLIO_TX_SEGS_POOL_BATCH_TCP"

#define SYS_VAR_SELECT_CPU_USAGE_STATS "XLIO_CPU_USAGE_STATS"
#define SYS_VAR_SELECT_NUM_POLLS       "XLIO_SELECT_POLL"
#define SYS_VAR_SELECT_POLL_OS_FORCE   "XLIO_SELECT_POLL_OS_FORCE"
#define SYS_VAR_SELECT_POLL_OS_RATIO   "XLIO_SELECT_POLL_OS_RATIO"
#define SYS_VAR_SELECT_SKIP_OS         "XLIO_SELECT_SKIP_OS"

#define SYS_VAR_CQ_MODERATION_ENABLE           "XLIO_CQ_MODERATION_ENABLE"
#define SYS_VAR_CQ_MODERATION_COUNT            "XLIO_CQ_MODERATION_COUNT"
#define SYS_VAR_CQ_MODERATION_PERIOD_USEC      "XLIO_CQ_MODERATION_PERIOD_USEC"
#define SYS_VAR_CQ_AIM_MAX_COUNT               "XLIO_CQ_AIM_MAX_COUNT"
#define SYS_VAR_CQ_AIM_MAX_PERIOD_USEC         "XLIO_CQ_AIM_MAX_PERIOD_USEC"
#define SYS_VAR_CQ_AIM_INTERVAL_MSEC           "XLIO_CQ_AIM_INTERVAL_MSEC"
#define SYS_VAR_CQ_AIM_INTERRUPTS_RATE_PER_SEC "XLIO_CQ_AIM_INTERRUPTS_RATE_PER_SEC"

#define SYS_VAR_CQ_POLL_BATCH_MAX         "XLIO_CQ_POLL_BATCH_MAX"
#define SYS_VAR_PROGRESS_ENGINE_INTERVAL  "XLIO_PROGRESS_ENGINE_INTERVAL"
#define SYS_VAR_PROGRESS_ENGINE_WCE_MAX   "XLIO_PROGRESS_ENGINE_WCE_MAX"
#define SYS_VAR_CQ_KEEP_QP_FULL           "XLIO_CQ_KEEP_QP_FULL"
#define SYS_VAR_QP_COMPENSATION_LEVEL     "XLIO_QP_COMPENSATION_LEVEL"
#define SYS_VAR_USER_HUGE_PAGE_SIZE       "XLIO_USER_HUGE_PAGE_SIZE"
#define SYS_VAR_OFFLOADED_SOCKETS         "XLIO_OFFLOADED_SOCKETS"
#define SYS_VAR_TIMER_RESOLUTION_MSEC     "XLIO_TIMER_RESOLUTION_MSEC"
#define SYS_VAR_TCP_TIMER_RESOLUTION_MSEC "XLIO_TCP_TIMER_RESOLUTION_MSEC"
#define SYS_VAR_TCP_CTL_THREAD            "XLIO_TCP_CTL_THREAD"
#define SYS_VAR_TCP_TIMESTAMP_OPTION      "XLIO_TCP_TIMESTAMP_OPTION"
#define SYS_VAR_TCP_NODELAY               "XLIO_TCP_NODELAY"
#define SYS_VAR_TCP_QUICKACK              "XLIO_TCP_QUICKACK"
#define SYS_VAR_TCP_PUSH_FLAG             "XLIO_TCP_PUSH_FLAG"
#define SYS_VAR_AVOID_SYS_CALLS_ON_TCP_FD "XLIO_AVOID_SYS_CALLS_ON_TCP_FD"
#define SYS_VAR_ALLOW_PRIVILEGED_SOCK_OPT "XLIO_ALLOW_PRIVILEGED_SOCK_OPT"
#define SYS_VAR_WAIT_AFTER_JOIN_MSEC      "XLIO_WAIT_AFTER_JOIN_MSEC"
#define SYS_VAR_THREAD_MODE               "XLIO_THREAD_MODE"
#define SYS_VAR_BUFFER_BATCHING_MODE      "XLIO_BUFFER_BATCHING_MODE"
#define SYS_VAR_MEM_ALLOC_TYPE            "XLIO_MEM_ALLOC_TYPE"
#define SYS_VAR_MEMORY_LIMIT              "XLIO_MEMORY_LIMIT"
#define SYS_VAR_MEMORY_LIMIT_USER         "XLIO_MEMORY_LIMIT_USER"
#define SYS_VAR_HEAP_METADATA_BLOCK       "XLIO_HEAP_METADATA_BLOCK"
#define SYS_VAR_HUGEPAGE_LOG2             "XLIO_HUGEPAGE_LOG2"
#define SYS_VAR_FORK                      "XLIO_FORK"
#define SYS_VAR_BF                        "XLIO_BF"
#define SYS_VAR_CLOSE_ON_DUP2             "XLIO_CLOSE_ON_DUP2"
#define SYS_VAR_MTU                       "XLIO_MTU"
#if defined(DEFINED_NGINX)
#define SYS_VAR_NGINX_WORKERS_NUM                 "XLIO_NGINX_WORKERS_NUM"
#define SYS_VAR_NGINX_UDP_POOL_SIZE               "XLIO_NGINX_UDP_POOL_SIZE"
#define SYS_VAR_NGINX_UDP_POOL_RX_NUM_BUFFS_REUSE "XLIO_NGINX_UDP_POOL_REUSE_BUFFS"
#endif
#if defined(DEFINED_ENVOY)
#define SYS_VAR_ENVOY_WORKERS_NUM "XLIO_ENVOY_WORKERS_NUM"
#endif /* DEFINED_ENVOY */
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
#define SYS_VAR_SRC_PORT_STRIDE "XLIO_SRC_PORT_STRIDE"
#define SYS_VAR_DISTRIBUTE_CQ   "XLIO_DISTRIBUTE_CQ"
#endif
#define SYS_VAR_TCP_MAX_SYN_RATE "XLIO_TCP_MAX_SYN_RATE"
#define SYS_VAR_MSS              "XLIO_MSS"
#define SYS_VAR_TCP_CC_ALGO      "XLIO_TCP_CC_ALGO"
#define SYS_VAR_SPEC             "XLIO_SPEC"

#define SYS_VAR_SOCKETXTREME "XLIO_SOCKETXTREME"
#define SYS_VAR_TSO          "XLIO_TSO"
#ifdef DEFINED_UTLS
#define SYS_VAR_UTLS_RX                        "XLIO_UTLS_RX"
#define SYS_VAR_UTLS_TX                        "XLIO_UTLS_TX"
#define SYS_VAR_UTLS_HIGH_WMARK_DEK_CACHE_SIZE "XLIO_UTLS_HIGH_WMARK_DEK_CACHE_SIZE"
#define SYS_VAR_UTLS_LOW_WMARK_DEK_CACHE_SIZE  "XLIO_UTLS_LOW_WMARK_DEK_CACHE_SIZE"
#endif /* DEFINED_UTLS */

#define SYS_VAR_LRO "XLIO_LRO"

#define SYS_VAR_INTERNAL_THREAD_AFFINITY "XLIO_INTERNAL_THREAD_AFFINITY"
#define SYS_VAR_INTERNAL_THREAD_CPUSET   "XLIO_INTERNAL_THREAD_CPUSET"
#define SYS_VAR_INTERNAL_THREAD_ARM_CQ   "XLIO_INTERNAL_THREAD_ARM_CQ"

#define SYS_VAR_NETLINK_TIMER_MSEC "XLIO_NETLINK_TIMER"

#define SYS_VAR_NEIGH_UC_ARP_QUATA      "XLIO_NEIGH_UC_ARP_QUATA"
#define SYS_VAR_NEIGH_UC_ARP_DELAY_MSEC "XLIO_NEIGH_UC_ARP_DELAY_MSEC"
#define SYS_VAR_NEIGH_NUM_ERR_RETRIES   "XLIO_NEIGH_NUM_ERR_RETRIES"

#define SYS_VAR_DEFERRED_CLOSE                 "XLIO_DEFERRED_CLOSE"
#define SYS_VAR_TCP_ABORT_ON_CLOSE             "XLIO_TCP_ABORT_ON_CLOSE"
#define SYS_VAR_RX_POLL_ON_TX_TCP              "XLIO_RX_POLL_ON_TX_TCP"
#define SYS_VAR_RX_CQ_WAIT_CTRL                "XLIO_RX_CQ_WAIT_CTRL"
#define SYS_VAR_TRIGGER_DUMMY_SEND_GETSOCKNAME "XLIO_TRIGGER_DUMMY_SEND_GETSOCKNAME"
#define SYS_VAR_TCP_SEND_BUFFER_SIZE           "XLIO_TCP_SEND_BUFFER_SIZE"
#define SYS_VAR_SKIP_POLL_IN_RX                "XLIO_SKIP_POLL_IN_RX"
#define SYS_VAR_MULTILOCK                      "XLIO_MULTILOCK"

/*
 * This block consists of default values for library specific
 * configuration variables
 */
#define MCE_DEFAULT_PRINT_REPORT             (false)
#define MCE_DEFAULT_TCP_SEND_BUFFER_SIZE     (1024 * 1024)
#define MCE_DEFAULT_LOG_FILE                 ("")
#define MCE_DEFAULT_CONF_FILE                ("/etc/libxlio.conf")
#define MCE_DEFAULT_STATS_FILE               ("")
#define MCE_DEFAULT_STATS_SHMEM_DIR          (XLIO_AGENT_PATH)
#define MCE_DEFAULT_SERVICE_FOLDER           (XLIO_AGENT_PATH)
#define MCE_DEFAULT_SERVICE_ENABLE           (false)
#define MCE_DEFAULT_LOG_DETAILS              (0)
#define MCE_DEFAULT_LOG_COLORS               (true)
#define MCE_DEFAULT_APP_ID                   ("XLIO_DEFAULT_APPLICATION_ID")
#define MCE_DEFAULT_HANDLE_SIGINTR           (true)
#define MCE_DEFAULT_HANDLE_SIGFAULT          (false)
#define MCE_DEFAULT_STATS_FD_NUM             100
#define MCE_DEFAULT_RING_ALLOCATION_LOGIC_TX (RING_LOGIC_PER_INTERFACE)
#define MCE_DEFAULT_RING_ALLOCATION_LOGIC_RX (RING_LOGIC_PER_INTERFACE)
#define MCE_DEFAULT_RING_MIGRATION_RATIO_TX  (-1)
#define MCE_DEFAULT_RING_MIGRATION_RATIO_RX  (-1)
#define MCE_DEFAULT_RING_LIMIT_PER_INTERFACE (0)
#define MCE_DEFAULT_RING_DEV_MEM_TX          (0)
#define MCE_DEFAULT_TCP_MAX_SYN_RATE         (0)
#define MCE_DEFAULT_ZC_TX_SIZE               (32768)
#define MCE_DEFAULT_TCP_NODELAY_TRESHOLD     (0)
#define MCE_DEFAULT_ZC_CACHE_THRESHOLD       (10LU * 1024 * 1024 * 1024) // 10GB
#define MCE_DEFAULT_TX_NUM_BUFS              (200000)
#define MCE_DEFAULT_TX_BUF_SIZE              (0)
#define MCE_DEFAULT_TX_NUM_WRE               (32768)
#define MCE_DEFAULT_TX_NUM_WRE_TO_SIGNAL     (64)
#define MCE_DEFAULT_TX_MAX_INLINE            (204) //+18(always inline ETH header) = 222
#define MCE_DEFAULT_TX_BUILD_IP_CHKSUM       (true)
#define MCE_DEFAULT_TX_MC_LOOPBACK           (true)
#define MCE_DEFAULT_TX_NONBLOCKED_EAGAINS    (false)
#define MCE_DEFAULT_TX_PREFETCH_BYTES        (256)
#define MCE_DEFAULT_TX_BUFS_BATCH_UDP        (8)
#define MCE_DEFAULT_TX_BUFS_BATCH_TCP        (16)
#define MCE_DEFAULT_TX_SEGS_BATCH_TCP        (64)
#define MCE_DEFAULT_TX_SEGS_RING_BATCH_TCP   (1024)
#define MCE_DEFAULT_TX_SEGS_POOL_BATCH_TCP   (16384)
#define MCE_DEFAULT_TX_NUM_SGE               (4)

#define MCE_DEFAULT_STRQ                            (option_3::ON)
#define MCE_DEFAULT_STRQ_NUM_STRIDES                (16384)
#define MCE_DEFAULT_STRQ_STRIDE_SIZE_BYTES          (512)
#define MCE_DEFAULT_STRQ_NUM_BUFS                   (64)
#define MCE_DEFAULT_STRQ_NUM_WRE                    (8)
#define MCE_DEFAULT_STRQ_NUM_WRE_TO_POST_RECV       (1)
#define MCE_DEFAULT_STRQ_COMPENSATION_LEVEL         (1)
#define MCE_DEFAULT_STRQ_STRIDES_NUM_BUFS           (262144)
#define MCE_DEFAULT_STRQ_STRIDES_COMPENSATION_LEVEL (16384)

#define MCE_DEFAULT_RX_NUM_BUFS                   (200000)
#define MCE_DEFAULT_RX_BUF_SIZE                   (0)
#define MCE_DEFAULT_RX_BUFS_BATCH                 (64)
#define MCE_DEFAULT_RX_NUM_WRE                    (16000)
#define MCE_DEFAULT_RX_NUM_WRE_TO_POST_RECV       (1024)
#define MCE_DEFAULT_RX_NUM_SGE                    (1)
#define MCE_DEFAULT_RX_NUM_POLLS                  (100000)
#define MCE_DEFAULT_RX_NUM_POLLS_INIT             (0)
#define MCE_DEFAULT_RX_UDP_POLL_OS_RATIO          (100)
#define MCE_DEFAULT_HW_TS_CONVERSION_MODE         (TS_CONVERSION_MODE_SYNC)
#define MCE_DEFAULT_RX_POLL_YIELD                 (0)
#define MCE_DEFAULT_RX_BYTE_MIN_LIMIT             (65536)
#define MCE_DEFAULT_RX_PREFETCH_BYTES             (256)
#define MCE_DEFAULT_RX_PREFETCH_BYTES_BEFORE_POLL (0)
#define MCE_DEFAULT_RX_CQ_DRAIN_RATE              (MCE_RX_CQ_DRAIN_RATE_DISABLED)
#define MCE_DEFAULT_GRO_STREAMS_MAX               (32)
#define MCE_DEFAULT_DISABLE_FLOW_TAG              (false)
#define MCE_DEFAULT_TCP_3T_RULES                  (false)
#define MCE_DEFAULT_UDP_3T_RULES                  (true)
#define MCE_DEFAULT_ETH_MC_L2_ONLY_RULES          (false)
#define MCE_DEFAULT_MC_FORCE_FLOWTAG              (false)
#define MCE_DEFAULT_SELECT_NUM_POLLS              (100000)
#define MCE_DEFAULT_SELECT_POLL_OS_FORCE          (0)
#define MCE_DEFAULT_SELECT_POLL_OS_RATIO          (10)
#define MCE_DEFAULT_SELECT_SKIP_OS                (4)
#define MCE_DEFAULT_SELECT_CPU_USAGE_STATS        (false)
#ifdef DEFINED_IBV_CQ_ATTR_MODERATE
#define MCE_DEFAULT_CQ_MODERATION_ENABLE (true)
#else
#define MCE_DEFAULT_CQ_MODERATION_ENABLE (false)
#endif
#define MCE_DEFAULT_CQ_MODERATION_COUNT            (48)
#define MCE_DEFAULT_CQ_MODERATION_PERIOD_USEC      (50)
#define MCE_DEFAULT_CQ_AIM_MAX_COUNT               (560)
#define MCE_DEFAULT_CQ_AIM_MAX_PERIOD_USEC         (250)
#define MCE_DEFAULT_CQ_AIM_INTERVAL_MSEC           (250)
#define MCE_DEFAULT_CQ_AIM_INTERRUPTS_RATE_PER_SEC (5000)
#define MCE_DEFAULT_CQ_POLL_BATCH                  (16)
#define MCE_DEFAULT_PROGRESS_ENGINE_INTERVAL_MSEC  (10)
#define MCE_DEFAULT_PROGRESS_ENGINE_WCE_MAX        (10000)
#define MCE_DEFAULT_CQ_KEEP_QP_FULL                (true)
#define MCE_DEFAULT_QP_COMPENSATION_LEVEL          (256)
#define MCE_DEFAULT_USER_HUGE_PAGE_SIZE            (2 * 1024 * 1024)
#define MCE_DEFAULT_INTERNAL_THREAD_ARM_CQ_ENABLED (false)
#define MCE_DEFAULT_QP_FORCE_MC_ATTACH             (false)
#define MCE_DEFAULT_OFFLOADED_SOCKETS              (true)
#define MCE_DEFAULT_TIMER_RESOLUTION_MSEC          (10)
#define MCE_DEFAULT_TCP_TIMER_RESOLUTION_MSEC      (100)
#define MCE_DEFAULT_TCP_CTL_THREAD                 (option_tcp_ctl_thread::CTL_THREAD_DISABLE)
#define MCE_DEFAULT_TCP_TIMESTAMP_OPTION           (TCP_TS_OPTION_DISABLE)
#define MCE_DEFAULT_TCP_NODELAY                    (false)
#define MCE_DEFAULT_TCP_QUICKACK                   (false)
#define MCE_DEFAULT_TCP_PUSH_FLAG                  (true)
#define MCE_DEFAULT_AVOID_SYS_CALLS_ON_TCP_FD      (false)
#define MCE_DEFAULT_ALLOW_PRIVILEGED_SOCK_OPT      (true)
#define MCE_DEFAULT_WAIT_AFTER_JOIN_MSEC           (0)
#define MCE_DEFAULT_THREAD_MODE                    (THREAD_MODE_MULTI)
#define MCE_DEFAULT_BUFFER_BATCHING_MODE           (BUFFER_BATCHING_WITH_RECLAIM)
#define MCE_DEFAULT_MEM_ALLOC_TYPE                 (option_alloc_type::HUGE)
#define MCE_DEFAULT_MEMORY_LIMIT                   (2LU * 1024 * 1024 * 1024)
#define MCE_DEFAULT_MEMORY_LIMIT_USER              (0)
#define MCE_DEFAULT_HEAP_METADATA_BLOCK            (32LU * 1024 * 1024)
#define MCE_DEFAULT_HUGEPAGE_LOG2                  (0)
#define MCE_DEFAULT_FORK_SUPPORT                   (true)
#define MCE_DEFAULT_BF_FLAG                        (true)
#define MCE_DEFAULT_CLOSE_ON_DUP2                  (true)
#define MCE_DEFAULT_MTU                            (0)
#if defined(DEFINED_NGINX)
#define MCE_DEFAULT_NGINX_UDP_POOL_SIZE               (0)
#define MCE_DEFAULT_NGINX_UDP_POOL_RX_NUM_BUFFS_REUSE (0)
#endif
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
#define MCE_DEFAULT_APP_WORKERS_NUM (0)
#define MCE_DEFAULT_SRC_PORT_STRIDE (2)
#define MCE_DEFAULT_DISTRIBUTE_CQ   (false)
#endif
#define MCE_DEFAULT_MSS                          (0)
#define MCE_DEFAULT_LWIP_CC_ALGO_MOD             (0)
#define MCE_DEFAULT_INTERNAL_THREAD_AFFINITY     (-1)
#define MCE_DEFAULT_INTERNAL_THREAD_AFFINITY_STR ("-1")
#define MCE_DEFAULT_INTERNAL_THREAD_CPUSET       ("")
#define MCE_DEFAULT_NETLINK_TIMER_MSEC           (10000)

#define MCE_DEFAULT_NEIGH_UC_ARP_QUATA      3
#define MCE_DEFAULT_NEIGH_UC_ARP_DELAY_MSEC 10000
#define MCE_DEFAULT_NEIGH_NUM_ERR_RETRIES   1

#define MCE_MIN_NUM_SGE                     (1)
#define MCE_MAX_NUM_SGE                     (32)
#define MCE_MIN_RX_NUM_POLLS                (-1)
#define MCE_MAX_RX_NUM_POLLS                (100000000)
#define MCE_MIN_RX_PREFETCH_BYTES           (32) /* Just enough for headers (IPoIB+IP+UDP)*/
#define MCE_MAX_RX_PREFETCH_BYTES           (2044)
#define MCE_MAX_ZC_TX_SIZE                  (65535)
#define MCE_RX_CQ_DRAIN_RATE_DISABLED       (0)
#define MCE_CQ_DRAIN_INTERVAL_DISABLED      (0)
#define MCE_CQ_ADAPTIVE_MODERATION_DISABLED (0)
#define MCE_MIN_CQ_POLL_BATCH               (1)
#define MCE_MAX_CQ_POLL_BATCH               (128)
#define MCE_DEFAULT_SOCKETXTREME            (false)
#define MCE_DEFAULT_TSO                     (option_3::AUTO)
#ifdef DEFINED_UTLS
#define MCE_DEFAULT_UTLS_RX                        (false)
#define MCE_DEFAULT_UTLS_TX                        (true)
#define MCE_DEFAULT_UTLS_HIGH_WMARK_DEK_CACHE_SIZE (1024)
#define MCE_DEFAULT_UTLS_LOW_WMARK_DEK_CACHE_SIZE  (512)
#endif /* DEFINED_UTLS */

#define MCE_DEFAULT_LRO                            (option_3::AUTO)
#define MCE_DEFAULT_DEFERRED_CLOSE                 (false)
#define MCE_DEFAULT_TCP_ABORT_ON_CLOSE             (false)
#define MCE_DEFAULT_RX_POLL_ON_TX_TCP              (false)
#define MCE_DEFAULT_TRIGGER_DUMMY_SEND_GETSOCKNAME (false)
#define MCE_DEFAULT_RX_CQ_WAIT_CTRL                (false)
#define MCE_ALIGNMENT                              ((unsigned long)63)
#define MCE_DEFAULT_SKIP_POLL_IN_RX                (SKIP_POLL_IN_RX_DISABLE)
#define MCE_DEFAULT_MULTILOCK                      (MULTILOCK_SPIN)

/*
 * This block consists of auxiliary constants
 */
#define RX_BUF_SIZE(mtu) (mtu)
#define TX_BUF_SIZE(mtu)                                                                           \
    ((mtu) + 92) // Tx buffers are larger in Ethernet (they include L2 for RAW QP)
#define NUM_TX_WRE_TO_SIGNAL_MAX            64
#define NUM_RX_WRE_TO_POST_RECV_MAX         1024
#define MAX_MLX5_CQ_SIZE_ITEMS              4194304
#define TCP_MAX_SYN_RATE_TOP_LIMIT          100000
#define DEFAULT_MC_TTL                      64
#define DEFAULT_MC_HOP_LIMIT                1
#define IFTYPE_PARAM_FILE                   "/sys/class/net/%s/type"
#define IFADDR_MTU_PARAM_FILE               "/sys/class/net/%s/mtu"
#define UMCAST_PARAM_FILE                   "/sys/class/net/%s/umcast"
#define VERBS_DEVICE_PORT_PARAM_FILE        "/sys/class/net/%s/dev_port"
#define VERBS_DEVICE_ID_PARAM_FILE          "/sys/class/net/%s/dev_id"
#define BONDING_MODE_PARAM_FILE             "/sys/class/net/%s/bonding/mode"
#define BONDING_SLAVES_PARAM_FILE           "/sys/class/net/%s/bonding/slaves"
#define BONDING_ACTIVE_SLAVE_PARAM_FILE     "/sys/class/net/%s/bonding/active_slave"
#define BONDING_FAILOVER_MAC_PARAM_FILE     "/sys/class/net/%s/bonding/fail_over_mac"
#define BONDING_XMIT_HASH_POLICY_PARAM_FILE "/sys/class/net/%s/bonding/xmit_hash_policy"
#define BONDING_ROCE_LAG_FILE               "/sys/class/net/%s/device/roce_lag_enable"
/* BONDING_SLAVE_STATE_PARAM_FILE is for kernel  > 3.14 or RH7.2 and higher */
#define BONDING_SLAVE_STATE_PARAM_FILE "/sys/class/net/%s/bonding_slave/state"
#define L2_ADDR_FILE_FMT               "/sys/class/net/%.*s/address"
#define L2_BR_ADDR_FILE_FMT            "/sys/class/net/%.*s/broadcast"
#define OPER_STATE_PARAM_FILE          "/sys/class/net/%s/operstate"
#define FLOW_STEERING_MGM_ENTRY_SIZE_PARAM_FILE                                                    \
    "/sys/module/mlx4_core/parameters/log_num_mgm_entry_size"
#define VIRTUAL_DEVICE_FOLDER    "/sys/devices/virtual/net/%s/"
#define BOND_DEVICE_FILE         "/proc/net/bonding/%s"
#define NETVSC_DEVICE_CLASS_FILE "/sys/class/net/%s/device/class_id"
#define NETVSC_DEVICE_LOWER_FILE "/sys/class/net/%s/lower_%s/ifindex"
#define NETVSC_DEVICE_UPPER_FILE "/sys/class/net/%s/upper_%s/ifindex"
#define NETVSC_ID                "{f8615163-df3e-46c5-913f-f2d2f965ed0e}\n"

#define MAX_STATS_FD_NUM   1024
#define MAX_WINDOW_SCALING 14

#define STRQ_MIN_STRIDES_NUM       512
#define STRQ_MAX_STRIDES_NUM       65536
#define STRQ_MIN_STRIDE_SIZE_BYTES 64
#define STRQ_MAX_STRIDE_SIZE_BYTES 8192

#define VIRTUALIZATION_FLAG "hypervisor"

extern bool g_b_exit;
extern bool g_is_forked_child;
extern bool g_init_global_ctors_done;

#endif
