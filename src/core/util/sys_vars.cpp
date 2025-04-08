/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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
#include <math.h>

#include "vlogger/vlogger.h"
#include "utils/rdtsc.h"
#include "core/util/hugepage_mgr.h"
#include "core/util/xlio_stats.h"
#include "core/util/utils.h"
#include "core/event/event_handler_manager.h"
#include "core/event/vlogger_timer_handler.h"
#include "core/dev/buffer_pool.h"
#include "core/dev/ib_ctx_handler_collection.h"
#include "core/dev/net_device_table_mgr.h"
#include "core/proto/ip_frag.h"
#include "core/proto/xlio_lwip.h"

#include "core/proto/neighbour_table_mgr.h"
#include "core/netlink/netlink_wrapper.h"
#include "core/event/command.h"

#include "core/sock/sock-redirect.h"
#include "core/sock/fd_collection.h"
#include "core/sock/sockinfo_tcp.h"
#include "core/sock/sockinfo_udp.h"
#include "core/iomux/io_mux_call.h"

#include "core/util/instrumentation.h"

#include "core/config/config_registry.h"
#include "core/config/loaders/json_loader.h"
#include "core/config/loaders/inline_loader.h"
#include "core/config/descriptor_providers/json_descriptor_provider.h"

void check_netperf_flags();

// Do not rely on global variable initialization in code that might be called from library
// constructor
mce_sys_var &safe_mce_sys()
{
    return mce_sys_var::instance();
}

#define MAX_BACKTRACE       25
#define MAX_VERSION_STR_LEN 128
#define MAX_CMD_LINE        2048

void mce_sys_var::print_xlio_load_failure_msg()
{
    vlog_printf(VLOG_ERROR,
                "***************************************************************************\n");
    vlog_printf(VLOG_ERROR,
                "* Failed loading " PRODUCT_NAME
                " library! Try executing the application without " PRODUCT_NAME ".  *\n");
    vlog_printf(VLOG_ERROR,
                "* 'unset LD_PRELOAD' environment variable and rerun the application.      *\n");
    vlog_printf(VLOG_ERROR,
                "***************************************************************************\n");
}

namespace xlio_spec {
typedef struct {
    xlio_spec_t level;
    const char *output_name;
    const char **input_names;
} xlio_spec_names;

static const char *names_none[] = {"none", nullptr};
static const char *spec_names_ulatency[] = {"ultra-latency", nullptr};
static const char *spec_names_latency[] = {"latency", nullptr};
static const char *spec_names_nginx[] = {"nginx", nullptr};
static const char *spec_names_nginx_dpu[] = {"nginx_dpu", nullptr};
static const char *spec_names_nvme_bf3[] = {"nvme_bf3", nullptr};

// must be by order because "to_str" relies on that!
static const xlio_spec_names specs[] = {
    {MCE_SPEC_NONE, "NONE", (const char **)names_none},
    {MCE_SPEC_SOCKPERF_ULTRA_LATENCY, "Ultra Latency", (const char **)spec_names_ulatency},
    {MCE_SPEC_SOCKPERF_LATENCY, "Latency", (const char **)spec_names_latency},
    {MCE_SPEC_NGINX, "Nginx Profile", (const char **)spec_names_nginx},
    {MCE_SPEC_NGINX_DPU, "Nginx Profile for DPU", (const char **)spec_names_nginx_dpu},
    {MCE_SPEC_NVME_BF3, "NVMEoTCP Profile for BF3", (const char **)spec_names_nvme_bf3}};

// convert str to _spec_t; upon error - returns the given 'def_value'
xlio_spec_t from_str(const char *str, xlio_spec_t def_value)
{
    size_t num_levels = sizeof(specs) / sizeof(specs[0]);
    for (size_t i = 0; i < num_levels; ++i) {
        const char **input_name = specs[i].input_names;
        while (*input_name) {
            if (strcasecmp(str, *input_name) == 0) {
                return specs[i].level;
            }
            input_name++;
        }
    }

    return def_value; // not found. use given def_value
}

// convert int to _spec_t; upon error - returns the given 'def_value'
xlio_spec_t from_int(const int int_spec, xlio_spec_t def_value)
{
    if (int_spec >= MCE_SPEC_NONE && int_spec <= MCE_SPEC_ALL) {
        return static_cast<xlio_spec_t>(int_spec);
    }
    return def_value; // not found. use given def_value
}

const char *to_str(xlio_spec_t level)
{
    static int base = MCE_SPEC_NONE;
    return specs[level - base].output_name;
}

} // namespace xlio_spec

namespace option_size {
enum {
    ONE_BYTE = 1U,
    ONE_KB = 1024U,
    ONE_MB = 1024U * 1024U,
    ONE_GB = 1024U * 1024U * 1024U,
};

// Supported base: dec, hex, oct
// Supported suffixes: one letter (K, M, G) and two letters (KB, MB, GB)
//                     in lower or upper case
//
// All other formats or extra letters are considered as invalid input and
// 0 is returned. Currently, there is no difference between 0 input and
// a failure.
size_t from_str(const char *str)
{
    char *endptr;
    unsigned long val = strtoul(str, &endptr, 0);

    struct size_suffix {
        std::vector<const char *> vals;
        unsigned long multiplier;
    };
    static const std::vector<size_suffix> suffixes = {{
                                                          {"B", ""},
                                                          ONE_BYTE,
                                                      },
                                                      {
                                                          {"KB", "K"},
                                                          ONE_KB,
                                                      },
                                                      {
                                                          {"MB", "M"},
                                                          ONE_MB,
                                                      },
                                                      {
                                                          {"GB", "G"},
                                                          ONE_GB,
                                                      }};

    for (auto &suffix : suffixes) {
        for (auto sfx : suffix.vals) {
            if (strcasecmp(sfx, endptr) == 0) {
                return static_cast<size_t>(val * suffix.multiplier);
            }
        }
    }

    // Invalid suffix in the input string
    return 0U;
}

const char *to_str(size_t size, char *s, size_t len)
{
    static const char *suffixes[] = {"", " KB", " MB", " GB", nullptr};
    int sfx_idx = 0;

    while ((size / 1024U >= 10 || (size > 0 && size % 1024U == 0)) && suffixes[sfx_idx + 1]) {
        ++sfx_idx;
        size /= 1024U;
    }
    snprintf(s, len, "%zu%s", size, suffixes[sfx_idx]);

    return s;
}

const char *to_str(size_t size)
{
    static char str[64];
    return to_str(size, str, sizeof(str));
}
} // namespace option_size

namespace option_x {
template <typename MODE, typename OPT, size_t N>
MODE from_str(const char *str, MODE def_value, const OPT (&options)[N])
{
    for (size_t i = 0; i < N; ++i) {
        /* option integer value can be used as valid name
         * during environment name processing so
         * check it first
         */
        std::string str_option = std::to_string((int)options[i].option);
        if (strcasecmp(str, str_option.c_str()) == 0) {
            return options[i].option;
        }
        const char *const *input_name = options[i].input_names;
        while (*input_name) {
            if (strcasecmp(str, *input_name) == 0) {
                return options[i].option;
            }
            input_name++;
        }
    }

    return def_value;
}

template <typename MODE, typename OPT, size_t N>
MODE from_int(const int option, MODE def_value, const OPT (&options)[N])
{
    for (size_t i = 0; i < N; ++i) {
        if ((int)options[i].option == option) {
            return options[i].option;
        }
    }

    return def_value;
}

template <typename MODE, typename OPT, size_t N>
const char *to_str(MODE option, const OPT (&options)[N])
{
    for (size_t i = 0; i < N; ++i) {
        if (options[i].option == option) {
            return options[i].output_name;
        }
    }

    return nullptr;
}
} // namespace option_x

#define OPTION_FROM_TO_STR_IMPL                                                                    \
    mode_t from_str(const char *str, mode_t def_value)                                             \
    {                                                                                              \
        return option_x::from_str(str, def_value, options);                                        \
    }                                                                                              \
    mode_t from_int(const int option, mode_t def_value)                                            \
    {                                                                                              \
        return option_x::from_int(option, def_value, options);                                     \
    }                                                                                              \
    const char *to_str(mode_t option)                                                              \
    {                                                                                              \
        return option_x::to_str(option, options);                                                  \
    }

#define AUTO_ON_OFF_IMPL                                                                           \
    {AUTO, "Auto", {"auto", NULL, NULL}}, {ON, "Enabled", {"on", "enabled", NULL}},                \
    {                                                                                              \
        OFF, "Disabled",                                                                           \
        {                                                                                          \
            "off", "disabled", NULL                                                                \
        }                                                                                          \
    }

template <typename MODE> struct option_t {
    MODE option;
    const char *output_name;
    const char *input_names[3];
};

namespace option_3 {
static option_t<mode_t> options[] = {AUTO_ON_OFF_IMPL};
OPTION_FROM_TO_STR_IMPL
} // namespace option_3

namespace option_tcp_ctl_thread {
static option_t<mode_t> options[] = {
    {CTL_THREAD_DISABLE, "Disabled", {"disable", "disabled", NULL}},
    {CTL_THREAD_DELEGATE_TCP_TIMERS, "Delegated TCP timers", {"delegate", NULL, NULL}},
    {CTL_THREAD_WITH_WAKEUP, "With Wakeup", {"with_wakeup", NULL, NULL}},
    {CTL_THREAD_NO_WAKEUP, "No Wakeup", {"no_wakeup", NULL, NULL}}};
OPTION_FROM_TO_STR_IMPL
} // namespace option_tcp_ctl_thread

namespace option_alloc_type {
static option_t<mode_t> options[] = {{ANON, "Regular pages", {"ANON", "ANONYMOUS", NULL}},
                                     {HUGE, "Huge pages", {"HUGE", "HUGEPAGES", NULL}}};
OPTION_FROM_TO_STR_IMPL
} // namespace option_alloc_type

int mce_sys_var::list_to_cpuset(char *cpulist, cpu_set_t *cpu_set)
{
    char comma[] = ",";
    char dash[] = "-";
    char *comma_saveptr, *dash_saveptr;

    char *token, *subtoken, *endptr;
    int range_start, range_end;
    int i;

    CPU_ZERO(cpu_set);

    /*
     * When passed a CPU list, we expect comma(',') delimited values.
     */
    token = strtok_r(cpulist, comma, &comma_saveptr);
    if (!token) {
        return -1;
    }

    /*
     * For each comma delimited value we need to parse the token based
     * on a dash('-') to see if we are dealing with a single cpu digit
     * or a range.
     */
    while (token) {

        subtoken = strtok_r(token, dash, &dash_saveptr);
        if (!subtoken) {
            return -1;
        }

        while (subtoken) {

            errno = 0;
            range_start = strtol(subtoken, &endptr, 10);
            if ((!range_start && *endptr) || errno) {
                return -1;
            }

            /*
             * Here we assume that if we get a second subtoken
             * then we must be processing a range.
             */
            subtoken = strtok_r(nullptr, dash, &dash_saveptr);
            if (subtoken) {
                errno = 0;
                range_end = strtol(subtoken, &endptr, 10);
                if ((!range_end && *endptr) || errno) {
                    return -1;
                }
                subtoken = nullptr;
            } else {
                range_end = range_start;
            }

            for (i = range_start; i <= range_end; i++) {
                if (i > (CPU_SETSIZE - 1)) {
                    return -1;
                } else {
                    CPU_SET(i, cpu_set);
                }
            }
        }

        token = strtok_r(nullptr, comma, &comma_saveptr);
    }

    return 0;
}

int mce_sys_var::hex_to_cpuset(char *start, cpu_set_t *cpu_set)
{
    const char *end;
    char hexc[2];
    int i, length, digit;
    int bit = 0, set_one = 0;

    /*
     * The least significant bits are at the end of the
     * string, so we need to start our processing at the
     * last character and work our way back to the start.
     */
    length = strlen(start);
    end = start + (length - 1);

    CPU_ZERO(cpu_set);
    while (length) {

        *hexc = *end;
        *(hexc + 1) = 0; // NULL terminate the string or strtol can be buggy.
        if (!isxdigit(*hexc)) {
            return -1;
        }

        digit = strtol(hexc, nullptr, 16);

        /*
         * Each hex digit is 4 bits. For each bit set per
         * in the hex value set the corresponding CPU number
         * in the cpu_set.
         *
         * Since we are working on a single hex digit in a string
         * of unknown length we need to keep a running bit counter
         * so we don't lose track of our progress.
         */
        for (i = 0; i < 4; i++) {
            if (digit & (1 << i)) {
                if (bit > (CPU_SETSIZE - 1)) {
                    return -1;
                } else {
                    CPU_SET(bit, cpu_set);
                    set_one++;
                }
            }

            bit++;
        }

        /* move the end pointer back a character */
        end--;

        /* one less character to process */
        length--;
    }

    /*
     * passing all 0's is not legal.  if no bits were set
     * and we make it to the end of the function then return
     * failure.
     */
    if (!set_one) {
        return -1;
    } else {
        return 0;
    }
}

int mce_sys_var::env_to_cpuset(char *orig_start, cpu_set_t *cpu_set)
{
    int ret;
    char *start = strdup(orig_start); // save the caller string from strtok destruction.

    /*
     * We expect a hex number or comma delimited cpulist.  Check for
     * starting characters of "0x" or "0X" and if present then parse
     * the string as a hexidecimal value, otherwise treat it as a
     * cpulist.
     */
    if ((strlen(start) > 2) && (start[0] == '0') && ((start[1] == 'x') || (start[1] == 'X'))) {
        ret = hex_to_cpuset(start + 2, cpu_set);
    } else {
        ret = list_to_cpuset(start, cpu_set);
    }

    free(start);
    return ret;
}

void mce_sys_var::read_env_variable_with_pid(char *mce_sys_name, size_t mce_sys_max_size,
                                             char *env_ptr)
{
    int n = -1;
    char *d_pos = nullptr;

    if (!env_ptr || !mce_sys_name || mce_sys_max_size < 2) {
        return;
    }

    d_pos = strstr(env_ptr, "%d");
    if (!d_pos) { // no %d in the string
        n = snprintf(mce_sys_name, mce_sys_max_size - 1, "%s", env_ptr);
        if (unlikely((((int)mce_sys_max_size - 1) < n) || (n < 0))) {
            mce_sys_name[0] = '\0';
        }
    } else { // has at least one occurrence of %d - replace the first one with the process PID
        size_t bytes_num = std::min<size_t>(d_pos - env_ptr, mce_sys_max_size - 1);
        strncpy(mce_sys_name, env_ptr, bytes_num);
        mce_sys_name[bytes_num] = '\0';
        n = snprintf(mce_sys_name + bytes_num, mce_sys_max_size - bytes_num - 1, "%d", getpid());
        if (likely((0 < n) && (n < ((int)mce_sys_max_size - (int)bytes_num - 1)))) {
            bytes_num += n;
            snprintf(mce_sys_name + bytes_num, mce_sys_max_size - bytes_num, "%s", d_pos + 2);
        }
    }
}

bool mce_sys_var::check_cpuinfo_flag(const char *flag)
{
    FILE *fp;
    char *line;
    bool ret = false;

    fp = fopen("/proc/cpuinfo", "r");
    if (!fp) {
        vlog_printf(VLOG_ERROR, "error while fopen\n");
        print_xlio_load_failure_msg();
        return false;
    }
    line = (char *)malloc(MAX_CMD_LINE);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!line) {
        vlog_printf(VLOG_ERROR, "error while malloc\n");
        print_xlio_load_failure_msg();
        goto exit;
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    while (fgets(line, MAX_CMD_LINE, fp)) {
        if (strncmp(line, "flags\t", 5) == 0) {
            if (strstr(line, flag)) {
                ret = true;
                goto exit;
            }
        }
    }

exit:
    fclose(fp);
    free(line);
    return ret;
}

/*
 * Intel and AMD CPUs have reserved bit 31 of ECX of CPUID leaf 0x1 as the hypervisor present bit.
 * This bit allows hypervisors to indicate their presence to the guest operating system.
 * Hypervisors set this bit and physical CPUs (all existing and future CPUs) set this bit to zero.
 * Guest operating systems can test bit 31 to detect if they are running inside a virtual machine.
 */
bool mce_sys_var::cpuid_hv()
{
#if defined(__x86_64__)
    uint32_t _eax, _ebx, _ecx, _edx;
    __asm__("cpuid" : "=a"(_eax), "=b"(_ebx), "=c"(_ecx), "=d"(_edx) : "a"(0x1));
    return (bool)((_ecx >> 31) & 0x1);
#else
    return check_cpuinfo_flag(VIRTUALIZATION_FLAG);
#endif
}

/*
 * Intel and AMD have also reserved CPUID leaves 0x40000000 - 0x400000FF for software use.
 * Hypervisors can use these leaves to provide an interface to pass information from the
 * hypervisor to the guest operating system running inside a virtual machine.
 * The hypervisor bit indicates the presence of a hypervisor and that it is safe to test
 * these additional software leaves. VMware defines the 0x40000000 leaf as the hypervisor CPUID
 * information leaf. Code running on a VMware hypervisor can test the CPUID information leaf
 * for the hypervisor signature. VMware stores the string "VMwareVMware" in
 * EBX, ECX, EDX of CPUID leaf 0x40000000.
 */
const char *mce_sys_var::cpuid_hv_vendor()
{
    static __thread char vendor[13] = {0};

    if (!cpuid_hv()) {
        return nullptr;
    }
#if defined(__x86_64__)
    uint32_t _ebx = 0, _ecx = 0, _edx = 0;
    __asm__ __volatile__("cpuid" : "=b"(_ebx), "=c"(_ecx), "=d"(_edx) : "a"(0x40000000));
    sprintf(vendor, "%c%c%c%c", _ebx, (_ebx >> 8), (_ebx >> 16), (_ebx >> 24));
    sprintf(vendor + 4, "%c%c%c%c", _ecx, (_ecx >> 8), (_ecx >> 16), (_ecx >> 24));
    sprintf(vendor + 8, "%c%c%c%c", _edx, (_edx >> 8), (_edx >> 16), (_edx >> 24));
    vendor[12] = 0x00;
#endif
    return vendor;
}

void mce_sys_var::read_hv()
{
    const char *hyper_vendor_id = nullptr;

    hypervisor = mce_sys_var::HYPER_NONE;
    hyper_vendor_id = cpuid_hv_vendor();
    if (hyper_vendor_id) {
        if (!strncmp("XenVMMXenVMM", hyper_vendor_id, 12)) {
            hypervisor = HYPER_XEN;
        } else if (!strncmp("KVMKVMKVM", hyper_vendor_id, 9)) {
            hypervisor = HYPER_KVM;
        } else if (!strncmp("Microsoft Hv", hyper_vendor_id, 12)) {
            hypervisor = HYPER_MSHV;
        } else if (!strncmp("VMwareVMware", hyper_vendor_id, 12)) {
            hypervisor = HYPER_VMWARE;
        } else {
            hypervisor = HYPER_NONE;
        }
    }
}

void mce_sys_var::read_strq_strides_num()
{
    char *env_ptr = nullptr;
    if (!enable_striding_rq || !((env_ptr = getenv(SYS_VAR_STRQ_NUM_STRIDES)))) {
        return;
    }

    int stirdes_num = atoi(env_ptr);
    bool isOK = true;
    if (stirdes_num < STRQ_MIN_STRIDES_NUM) {
        stirdes_num = STRQ_MIN_STRIDES_NUM;
        isOK = false;
    } else if (stirdes_num > STRQ_MAX_STRIDES_NUM) {
        stirdes_num = STRQ_MAX_STRIDES_NUM;
        isOK = false;
    } else if (!is_ilog2(static_cast<unsigned int>(stirdes_num))) {
        stirdes_num = align32pow2(static_cast<uint32_t>(stirdes_num));
        isOK = false;
    }

    if (!isOK) {
        vlog_printf(VLOG_INFO,
                    " Invalid " SYS_VAR_STRQ_NUM_STRIDES
                    ": Must be power of 2 and in the range of (%d,%d). Using: %d.\n",
                    STRQ_MIN_STRIDES_NUM, STRQ_MAX_STRIDES_NUM, stirdes_num);
    }

    strq_stride_num_per_rwqe = static_cast<uint32_t>(stirdes_num);
}

void mce_sys_var::read_strq_stride_size_bytes()
{
    char *env_ptr = nullptr;
    if (!enable_striding_rq || !((env_ptr = getenv(SYS_VAR_STRQ_STRIDE_SIZE_BYTES)))) {
        return;
    }

    int stirde_size_bytes = atoi(env_ptr);
    bool isOK = true;
    if (stirde_size_bytes < STRQ_MIN_STRIDE_SIZE_BYTES) {
        stirde_size_bytes = STRQ_MIN_STRIDE_SIZE_BYTES;
        isOK = false;
    } else if (stirde_size_bytes > STRQ_MAX_STRIDE_SIZE_BYTES) {
        stirde_size_bytes = STRQ_MAX_STRIDE_SIZE_BYTES;
        isOK = false;
    } else if (!is_ilog2(static_cast<unsigned int>(stirde_size_bytes))) {
        stirde_size_bytes = align32pow2(static_cast<uint32_t>(stirde_size_bytes));
        isOK = false;
    }

    if (!isOK) {
        vlog_printf(VLOG_INFO,
                    " Invalid " SYS_VAR_STRQ_STRIDE_SIZE_BYTES
                    ": Must be power of 2 and in the range of (%d,%d). Using: %d.\n",
                    STRQ_MIN_STRIDE_SIZE_BYTES, STRQ_MAX_STRIDE_SIZE_BYTES, stirde_size_bytes);
    }

    strq_stride_size_bytes = static_cast<uint32_t>(stirde_size_bytes);
}

void mce_sys_var::update_multi_process_params()
{
#if defined(DEFINED_NGINX)
    bool is_nginx = app.type == APP_NGINX;
    bool is_nginx_master = is_nginx && (!g_p_app || g_p_app->get_worker_id() == -1);
    if (is_nginx) {
        // Memory limit is per application, so distribute it across processes.
        memory_limit /= std::max<size_t>(app.workers_num, 1U);
        if (is_nginx_master) {
            // We don't want to waste memory on the master process which doesn't handle traffic.
            // Set parameters to preallocate minimum resources.
            mem_alloc_type = option_alloc_type::ANON;
            memory_limit = 12LU * 1024 * 1024;
            heap_metadata_block = 2LU * 1024 * 1024;
            tx_bufs_batch_tcp = 1;
            tx_segs_batch_tcp = 1;
            tx_segs_pool_batch_tcp = 256;
            rx_num_wr = 1;
            strq_strides_compensation_level = 32;
            strq_stride_num_per_rwqe = STRQ_MIN_STRIDES_NUM;
            tx_buf_size = 0;
            rx_buf_size = 0;
        }
    }
#endif /* DEFINED_NGINX */
}

void mce_sys_var::legacy_get_env_params()
{
    char *env_ptr;
    memset(log_filename, 0, sizeof(log_filename));
    memset(stats_filename, 0, sizeof(stats_filename));
    memset(stats_shmem_dirname, 0, sizeof(stats_shmem_dirname));
    memset(service_notify_dir, 0, sizeof(service_notify_dir));
    strcpy(stats_filename, MCE_DEFAULT_STATS_FILE);
    strcpy(service_notify_dir, MCE_DEFAULT_SERVICE_FOLDER);
    strcpy(stats_shmem_dirname, MCE_DEFAULT_STATS_SHMEM_DIR);
    strcpy(transport_control_context, MCE_DEFAULT_CONF_FILE);
    strcpy(app_id, MCE_DEFAULT_APP_ID);
    strcpy(internal_thread_cpuset, MCE_DEFAULT_INTERNAL_THREAD_CPUSET);
    strcpy(internal_thread_affinity_str, MCE_DEFAULT_INTERNAL_THREAD_AFFINITY_STR);

    service_enable = MCE_DEFAULT_SERVICE_ENABLE;

    print_report = MCE_DEFAULT_PRINT_REPORT;
    quick_start = MCE_DEFAULT_QUICK_START;
    log_level = VLOG_DEFAULT;
    log_details = MCE_DEFAULT_LOG_DETAILS;
    log_colors = MCE_DEFAULT_LOG_COLORS;
    handle_sigintr = MCE_DEFAULT_HANDLE_SIGINTR;
    handle_segfault = MCE_DEFAULT_HANDLE_SIGFAULT;
    stats_fd_num_max = MCE_DEFAULT_STATS_FD_NUM;
    stats_fd_num_monitor = MCE_DEFAULT_STATS_FD_NUM;

    ring_allocation_logic_tx = MCE_DEFAULT_RING_ALLOCATION_LOGIC_TX;
    ring_allocation_logic_rx = MCE_DEFAULT_RING_ALLOCATION_LOGIC_RX;
    ring_migration_ratio_tx = MCE_DEFAULT_RING_MIGRATION_RATIO_TX;
    ring_migration_ratio_rx = MCE_DEFAULT_RING_MIGRATION_RATIO_RX;
    ring_limit_per_interface = MCE_DEFAULT_RING_LIMIT_PER_INTERFACE;
    ring_dev_mem_tx = MCE_DEFAULT_RING_DEV_MEM_TX;

    tcp_max_syn_rate = MCE_DEFAULT_TCP_MAX_SYN_RATE;

    zc_cache_threshold = MCE_DEFAULT_ZC_CACHE_THRESHOLD;
    tx_buf_size = MCE_DEFAULT_TX_BUF_SIZE;
    tcp_nodelay_treshold = MCE_DEFAULT_TCP_NODELAY_TRESHOLD;
    tx_num_wr = MCE_DEFAULT_TX_NUM_WRE;
    tx_num_wr_to_signal = MCE_DEFAULT_TX_NUM_WRE_TO_SIGNAL;
    tx_max_inline = MCE_DEFAULT_TX_MAX_INLINE;
    tx_mc_loopback_default = MCE_DEFAULT_TX_MC_LOOPBACK;
    tx_nonblocked_eagains = MCE_DEFAULT_TX_NONBLOCKED_EAGAINS;
    tx_prefetch_bytes = MCE_DEFAULT_TX_PREFETCH_BYTES;
    tx_bufs_batch_udp = MCE_DEFAULT_TX_BUFS_BATCH_UDP;
    tx_bufs_batch_tcp = MCE_DEFAULT_TX_BUFS_BATCH_TCP;
    tx_segs_batch_tcp = MCE_DEFAULT_TX_SEGS_BATCH_TCP;
    tx_segs_ring_batch_tcp = MCE_DEFAULT_TX_SEGS_RING_BATCH_TCP;
    tx_segs_pool_batch_tcp = MCE_DEFAULT_TX_SEGS_POOL_BATCH_TCP;
    rx_buf_size = MCE_DEFAULT_RX_BUF_SIZE;
    rx_bufs_batch = MCE_DEFAULT_RX_BUFS_BATCH;
    rx_num_wr = MCE_DEFAULT_RX_NUM_WRE;
    rx_num_wr_to_post_recv = MCE_DEFAULT_RX_NUM_WRE_TO_POST_RECV;
    rx_poll_num = MCE_DEFAULT_RX_NUM_POLLS;
    rx_poll_num_init = MCE_DEFAULT_RX_NUM_POLLS_INIT;
    rx_udp_poll_os_ratio = MCE_DEFAULT_RX_UDP_POLL_OS_RATIO;
    hw_ts_conversion_mode = MCE_DEFAULT_HW_TS_CONVERSION_MODE;
    rx_poll_yield_loops = MCE_DEFAULT_RX_POLL_YIELD;
    select_handle_cpu_usage_stats = MCE_DEFAULT_SELECT_CPU_USAGE_STATS;
    rx_ready_byte_min_limit = MCE_DEFAULT_RX_BYTE_MIN_LIMIT;
    rx_prefetch_bytes = MCE_DEFAULT_RX_PREFETCH_BYTES;
    rx_prefetch_bytes_before_poll = MCE_DEFAULT_RX_PREFETCH_BYTES_BEFORE_POLL;
    rx_cq_drain_rate_nsec = MCE_DEFAULT_RX_CQ_DRAIN_RATE;
    rx_delta_tsc_between_cq_polls = 0;

    enable_strq_env = MCE_DEFAULT_STRQ;
    strq_stride_num_per_rwqe = MCE_DEFAULT_STRQ_NUM_STRIDES;
    strq_stride_size_bytes = MCE_DEFAULT_STRQ_STRIDE_SIZE_BYTES;
    strq_strides_compensation_level = MCE_DEFAULT_STRQ_STRIDES_COMPENSATION_LEVEL;

    gro_streams_max = MCE_DEFAULT_GRO_STREAMS_MAX;
    disable_flow_tag = MCE_DEFAULT_DISABLE_FLOW_TAG;

    tcp_2t_rules = MCE_DEFAULT_TCP_2T_RULES;
    tcp_3t_rules = MCE_DEFAULT_TCP_3T_RULES;
    udp_3t_rules = MCE_DEFAULT_UDP_3T_RULES;
    eth_mc_l2_only_rules = MCE_DEFAULT_ETH_MC_L2_ONLY_RULES;
    mc_force_flowtag = MCE_DEFAULT_MC_FORCE_FLOWTAG;

    select_poll_num = MCE_DEFAULT_SELECT_NUM_POLLS;
    select_poll_os_force = MCE_DEFAULT_SELECT_POLL_OS_FORCE;
    select_poll_os_ratio = MCE_DEFAULT_SELECT_POLL_OS_RATIO;
    select_skip_os_fd_check = MCE_DEFAULT_SELECT_SKIP_OS;

    cq_moderation_enable = MCE_DEFAULT_CQ_MODERATION_ENABLE;
    cq_moderation_count = MCE_DEFAULT_CQ_MODERATION_COUNT;
    cq_moderation_period_usec = MCE_DEFAULT_CQ_MODERATION_PERIOD_USEC;
    cq_aim_max_count = MCE_DEFAULT_CQ_AIM_MAX_COUNT;
    cq_aim_max_period_usec = MCE_DEFAULT_CQ_AIM_MAX_PERIOD_USEC;
    cq_aim_interval_msec = MCE_DEFAULT_CQ_AIM_INTERVAL_MSEC;
    cq_aim_interrupts_rate_per_sec = MCE_DEFAULT_CQ_AIM_INTERRUPTS_RATE_PER_SEC;

    cq_poll_batch_max = MCE_DEFAULT_CQ_POLL_BATCH;
    progress_engine_interval_msec = MCE_DEFAULT_PROGRESS_ENGINE_INTERVAL_MSEC;
    progress_engine_wce_max = MCE_DEFAULT_PROGRESS_ENGINE_WCE_MAX;
    cq_keep_qp_full = MCE_DEFAULT_CQ_KEEP_QP_FULL;
    max_tso_sz = MCE_DEFAULT_MAX_TSO_SIZE;
    user_huge_page_size = MCE_DEFAULT_USER_HUGE_PAGE_SIZE;
    internal_thread_arm_cq_enabled = MCE_DEFAULT_INTERNAL_THREAD_ARM_CQ_ENABLED;

    offloaded_sockets = MCE_DEFAULT_OFFLOADED_SOCKETS;
    timer_resolution_msec = MCE_DEFAULT_TIMER_RESOLUTION_MSEC;
    tcp_timer_resolution_msec = MCE_DEFAULT_TCP_TIMER_RESOLUTION_MSEC;
    tcp_ctl_thread = MCE_DEFAULT_TCP_CTL_THREAD;
    tcp_ts_opt = MCE_DEFAULT_TCP_TIMESTAMP_OPTION;
    tcp_nodelay = MCE_DEFAULT_TCP_NODELAY;
    tcp_quickack = MCE_DEFAULT_TCP_QUICKACK;
    tcp_push_flag = MCE_DEFAULT_TCP_PUSH_FLAG;
    //	exception_handling is handled by its CTOR
    avoid_sys_calls_on_tcp_fd = MCE_DEFAULT_AVOID_SYS_CALLS_ON_TCP_FD;
    allow_privileged_sock_opt = MCE_DEFAULT_ALLOW_PRIVILEGED_SOCK_OPT;
    wait_after_join_msec = MCE_DEFAULT_WAIT_AFTER_JOIN_MSEC;
    buffer_batching_mode = MCE_DEFAULT_BUFFER_BATCHING_MODE;
    mem_alloc_type = MCE_DEFAULT_MEM_ALLOC_TYPE;
    memory_limit = MCE_DEFAULT_MEMORY_LIMIT;
    memory_limit_user = MCE_DEFAULT_MEMORY_LIMIT_USER;
    heap_metadata_block = MCE_DEFAULT_HEAP_METADATA_BLOCK;
    hugepage_size = MCE_DEFAULT_HUGEPAGE_SIZE;
    enable_socketxtreme = MCE_DEFAULT_SOCKETXTREME;
    enable_tso = MCE_DEFAULT_TSO;
#ifdef DEFINED_UTLS
    enable_utls_rx = MCE_DEFAULT_UTLS_RX;
    enable_utls_tx = MCE_DEFAULT_UTLS_TX;
    utls_high_wmark_dek_cache_size = MCE_DEFAULT_UTLS_HIGH_WMARK_DEK_CACHE_SIZE;
    utls_low_wmark_dek_cache_size = MCE_DEFAULT_UTLS_LOW_WMARK_DEK_CACHE_SIZE;
#endif /* DEFINED_UTLS */
    enable_lro = MCE_DEFAULT_LRO;
    handle_fork = MCE_DEFAULT_FORK_SUPPORT;
    close_on_dup2 = MCE_DEFAULT_CLOSE_ON_DUP2;
    mtu = MCE_DEFAULT_MTU;
#if defined(DEFINED_NGINX)
    nginx_udp_socket_pool_size = MCE_DEFAULT_NGINX_UDP_POOL_SIZE;
    nginx_udp_socket_pool_rx_num_buffs_reuse = MCE_DEFAULT_NGINX_UDP_POOL_RX_NUM_BUFFS_REUSE;
#endif
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    app.type = APP_NONE;
    app.workers_num = MCE_DEFAULT_APP_WORKERS_NUM;
    app.src_port_stride = MCE_DEFAULT_SRC_PORT_STRIDE;
    app.distribute_cq_interrupts = MCE_DEFAULT_DISTRIBUTE_CQ;
#endif
    lwip_mss = MCE_DEFAULT_MSS;
    lwip_cc_algo_mod = MCE_DEFAULT_LWIP_CC_ALGO_MOD;
    mce_spec = MCE_SPEC_NONE;

    neigh_num_err_retries = MCE_DEFAULT_NEIGH_NUM_ERR_RETRIES;
    neigh_uc_arp_quata = MCE_DEFAULT_NEIGH_UC_ARP_QUATA;
    neigh_wait_till_send_arp_msec = MCE_DEFAULT_NEIGH_UC_ARP_DELAY_MSEC;
    timer_netlink_update_msec = MCE_DEFAULT_NETLINK_TIMER_MSEC;

    deferred_close = MCE_DEFAULT_DEFERRED_CLOSE;
    tcp_abort_on_close = MCE_DEFAULT_TCP_ABORT_ON_CLOSE;
    rx_poll_on_tx_tcp = MCE_DEFAULT_RX_POLL_ON_TX_TCP;
    rx_cq_wait_ctrl = MCE_DEFAULT_RX_CQ_WAIT_CTRL;
    trigger_dummy_send_getsockname = MCE_DEFAULT_TRIGGER_DUMMY_SEND_GETSOCKNAME;
    tcp_send_buffer_size = MCE_DEFAULT_TCP_SEND_BUFFER_SIZE;
    skip_poll_in_rx = MCE_DEFAULT_SKIP_POLL_IN_RX;
    multilock = MCE_DEFAULT_MULTILOCK;

    read_hv();

    /* Configure enable_socketxtreme as first because
     * this mode has some special predefined parameter limitations
     */
    if ((env_ptr = getenv(SYS_VAR_SOCKETXTREME))) {
        enable_socketxtreme = atoi(env_ptr) ? true : false;
    }
    if (enable_socketxtreme) {
        /* Set following parameters as default for SocketXtreme mode */
        gro_streams_max = 0;
        progress_engine_interval_msec = MCE_CQ_DRAIN_INTERVAL_DISABLED;
    }

    if ((env_ptr = getenv(SYS_VAR_STRQ))) {
        enable_strq_env = option_3::from_str(env_ptr, MCE_DEFAULT_STRQ);
    }

    enable_striding_rq = (enable_strq_env == option_3::ON || enable_strq_env == option_3::AUTO);

    if (enable_striding_rq) {
        rx_num_wr = MCE_DEFAULT_STRQ_NUM_WRE;
        rx_num_wr_to_post_recv = MCE_DEFAULT_STRQ_NUM_WRE_TO_POST_RECV;
    }

    if ((env_ptr = getenv(SYS_VAR_SPEC))) {
        mce_spec = (uint32_t)xlio_spec::from_str(env_ptr, MCE_SPEC_NONE);
    }

    /*
     * Check for specific application configuration first. We can make decisions
     * based on number of workers or application type further.
     */
#if defined(DEFINED_NGINX)
    if ((env_ptr = getenv(SYS_VAR_NGINX_WORKERS_NUM))) {
        app.workers_num = (uint32_t)atoi(env_ptr);
        if (app.workers_num > 0) {
            app.type = APP_NGINX;
            // In order to ease the usage of Nginx cases, we apply Nginx profile when
            // user will choose to use Nginx workers environment variable.
            if (mce_spec == MCE_SPEC_NONE) {
                mce_spec = MCE_SPEC_NGINX;
            }
        }
    }
#endif // DEFINED_NGINX
#if defined(DEFINED_ENVOY)
    if ((env_ptr = getenv(SYS_VAR_ENVOY_WORKERS_NUM)) != NULL) {
        app.workers_num = (uint32_t)atoi(env_ptr);
        if (app.workers_num > 0) {
            app.type = APP_ENVOY;
        }
    }
#endif /* DEFINED_ENVOY */

    switch (mce_spec) {
    case MCE_SPEC_SOCKPERF_ULTRA_LATENCY:
        memory_limit = 128LU * 1024 * 1024;
        tx_num_wr = 256;
        tx_num_wr_to_signal = 4;
        tx_prefetch_bytes = MCE_DEFAULT_TX_PREFETCH_BYTES;
        tx_bufs_batch_udp = 1;
        tx_bufs_batch_tcp = 1;
        rx_bufs_batch = 4;
        rx_poll_num = -1;
        enable_tso = option_3::OFF;
        rx_udp_poll_os_ratio = 0;
        rx_prefetch_bytes = MCE_DEFAULT_RX_PREFETCH_BYTES;
        rx_prefetch_bytes_before_poll = 256;
        select_poll_num = -1;
        select_poll_os_ratio = 0;
        select_skip_os_fd_check = 0;
        avoid_sys_calls_on_tcp_fd = true;
        gro_streams_max = 0;
        progress_engine_interval_msec = 0;
        cq_keep_qp_full = false;
        tcp_nodelay = true;
        ring_dev_mem_tx = 16384;
        strcpy(internal_thread_affinity_str, "0");

        if (enable_striding_rq) {
            rx_num_wr = 4U;
        } else {
            rx_num_wr = 256;
            rx_num_wr_to_post_recv = 4;
        }
        break;

    case MCE_SPEC_SOCKPERF_LATENCY:
        tx_num_wr = 256;
        tx_num_wr_to_signal = 4;
        tx_bufs_batch_udp = 1;
        tx_bufs_batch_tcp = 1;
        rx_bufs_batch = 4;

        rx_poll_num = -1;
        enable_tso = option_3::OFF;
        rx_prefetch_bytes_before_poll = 256;
        select_poll_num = -1;
        avoid_sys_calls_on_tcp_fd = true;
        gro_streams_max = 0;
        cq_keep_qp_full = false;
        strcpy(internal_thread_affinity_str, "0");
        progress_engine_interval_msec = 100;
        select_poll_os_ratio = 100;
        select_poll_os_force = 1;
        tcp_nodelay = true;
        ring_dev_mem_tx = 16384;

        if (enable_striding_rq) {
            rx_num_wr = 4U;
        } else {
            rx_num_wr = 256;
            rx_num_wr_to_post_recv = 4;
        }

        break;

#ifdef DEFINED_NGINX
    case MCE_SPEC_NGINX:
        // Fallthrough
    case MCE_SPEC_NGINX_DPU:
        ring_allocation_logic_tx = RING_LOGIC_PER_INTERFACE;
        ring_allocation_logic_rx = RING_LOGIC_PER_INTERFACE;
        progress_engine_interval_msec = 0; // Disable internal thread CQ draining logic.
        cq_poll_batch_max = 128; // Maximum CQEs to poll in one batch.
        enable_tso = option_3::ON; // Enable TCP Segmentation Offload(=TSO).
        timer_resolution_msec = 32; // Reduce CPU utilization of internal thread.
        tcp_timer_resolution_msec = 256; // Reduce CPU utilization of internal thread.
        tcp_send_buffer_size = 2 * 1024 * 1024; // LWIP TCP send buffer size.
        tcp_push_flag = false; // When false, we don't set PSH flag in outgoing TCP segments.
        select_poll_num = 0; // Poll CQ only once before going to sleep.
        select_skip_os_fd_check = 1000; // Poll OS every X epoll_waits if we do not sleep.
        tcp_3t_rules = true; // Use 3 tuple instead rules of 5 tuple rules.
        app.distribute_cq_interrupts = true;
        rx_cq_wait_ctrl = true;

        if (mce_spec == MCE_SPEC_NGINX) {
            memory_limit = (app.workers_num > 16 ? 3072LU : 4096LU) * 1024 * 1024;
            memory_limit *= std::max(app.workers_num, 1);
            rx_bufs_batch = 8; // RX buffers batch size.

            // Do polling on RX queue on TX operations, helpful to maintain TCP stack management.
            rx_poll_on_tx_tcp = true;
        } else if (mce_spec == MCE_SPEC_NGINX_DPU) {
            memory_limit = (app.workers_num == 16 ? 512LU : 1024LU) * 1024 * 1024;
            memory_limit *= std::max(app.workers_num, 1);
            buffer_batching_mode = BUFFER_BATCHING_NONE;
        }
        break;
#endif // DEFINED_NGINX
    case MCE_SPEC_NVME_BF3:
        strq_stride_num_per_rwqe = 8192U;
        enable_lro = option_3::ON;
        handle_fork = false;
        strcpy(internal_thread_affinity_str, "0x01");
        gro_streams_max = 0;
        tx_num_wr_to_signal = 128U;
        tx_num_wr = 1024U;
        rx_num_wr = 32U;
        enable_tso = option_3::ON;
        rx_prefetch_bytes_before_poll = 256U;
        ring_dev_mem_tx = 1024;
        cq_keep_qp_full = false;
        cq_aim_interval_msec = MCE_CQ_ADAPTIVE_MODERATION_DISABLED;
        progress_engine_interval_msec = 0U;
        tcp_abort_on_close = true;
        memory_limit = 256U * 1024U * 1024U;
        memory_limit_user = 2U * 1024U * 1024U * 1024U;

        tx_bufs_batch_udp = 1;
        tx_bufs_batch_tcp = 1;
        rx_bufs_batch = 4;
        tcp_nodelay = true;
    case MCE_SPEC_NONE:
    default:
        break;
    }

    if ((env_ptr = getenv(SYS_VAR_PRINT_REPORT))) {
        print_report = option_3::from_str(env_ptr, MCE_DEFAULT_PRINT_REPORT);
    }

    if ((env_ptr = getenv(SYS_VAR_QUICK_START))) {
        quick_start = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_LOG_FILENAME))) {
        read_env_variable_with_pid(log_filename, sizeof(log_filename), env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_STATS_FILENAME))) {
        read_env_variable_with_pid(stats_filename, sizeof(stats_filename), env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_STATS_SHMEM_DIRNAME))) {
        read_env_variable_with_pid(stats_shmem_dirname, sizeof(stats_shmem_dirname), env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_transport_control_context))) {
        read_env_variable_with_pid(transport_control_context, sizeof(transport_control_context),
                                   env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_SERVICE_DIR))) {
        read_env_variable_with_pid(service_notify_dir, sizeof(service_notify_dir), env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_SERVICE_ENABLE))) {
        service_enable = atoi(env_ptr) ? true : false;
    }
    if (HYPER_MSHV == hypervisor && !service_enable) {
        service_enable = true;
        vlog_printf(VLOG_DEBUG, "%s parameter is forced to 'true' for MSHV hypervisor\n",
                    SYS_VAR_SERVICE_ENABLE);
    }

    if ((env_ptr = getenv(SYS_VAR_LOG_LEVEL))) {
        log_level = log_level::from_str(env_ptr, VLOG_DEFAULT);
    }

    if (log_level >= VLOG_DEBUG) {
        log_details = 2;
    }

    if ((env_ptr = getenv(SYS_VAR_LOG_DETAILS))) {
        log_details = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_LOG_COLORS))) {
        log_colors = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_APPLICATION_ID))) {
        read_env_variable_with_pid(app_id, sizeof(app_id), env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_HANDLE_SIGINTR))) {
        handle_sigintr = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_HANDLE_SIGSEGV))) {
        handle_segfault = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_STATS_FD_NUM))) {
        stats_fd_num_max = (uint32_t)atoi(env_ptr);
        stats_fd_num_monitor = std::min(stats_fd_num_max, MAX_STATS_FD_NUM);
        if (stats_fd_num_max > MAX_STATS_FD_NUM) {
            vlog_printf(VLOG_INFO, "xlio_stats monitoring will be limited by %d sockets\n",
                        MAX_STATS_FD_NUM);
        }
    }

    read_strq_strides_num();
    read_strq_stride_size_bytes();

    if ((env_ptr = getenv(SYS_VAR_STRQ_STRIDES_COMPENSATION_LEVEL))) {
        strq_strides_compensation_level = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_ZC_CACHE_THRESHOLD))) {
        zc_cache_threshold = option_size::from_str(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_TX_BUF_SIZE))) {
        tx_buf_size = (uint32_t)option_size::from_str(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_NODELAY_TRESHOLD))) {
        tcp_nodelay_treshold = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_TX_NUM_WRE))) {
        tx_num_wr = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_TX_NUM_WRE_TO_SIGNAL))) {
        tx_num_wr_to_signal =
            std::min<uint32_t>(NUM_TX_WRE_TO_SIGNAL_MAX, std::max(1, atoi(env_ptr)));
    }
    if (tx_num_wr <= (tx_num_wr_to_signal * 2)) {
        tx_num_wr = tx_num_wr_to_signal * 2;
    }

    if ((env_ptr = getenv(SYS_VAR_TX_MAX_INLINE))) {
        tx_max_inline = (uint32_t)atoi(env_ptr);
    }
    if (tx_max_inline > MAX_SUPPORTED_IB_INLINE_SIZE) {
        vlog_printf(VLOG_WARNING, "%s must be smaller or equal to %d [%d]\n", SYS_VAR_TX_MAX_INLINE,
                    MAX_SUPPORTED_IB_INLINE_SIZE, tx_max_inline);
        tx_max_inline = MAX_SUPPORTED_IB_INLINE_SIZE;
    }

    if ((env_ptr = getenv(SYS_VAR_TX_MC_LOOPBACK))) {
        tx_mc_loopback_default = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_TX_NONBLOCKED_EAGAINS))) {
        tx_nonblocked_eagains = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_TX_PREFETCH_BYTES))) {
        tx_prefetch_bytes = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_TX_BUFS_BATCH_TCP))) {
        tx_bufs_batch_tcp = (uint32_t)std::max<int32_t>(atoi(env_ptr), 1);
    }

    if ((env_ptr = getenv(SYS_VAR_TX_SEGS_BATCH_TCP))) {
        tx_segs_batch_tcp = (uint32_t)std::max<int32_t>(atoi(env_ptr), 1);
    }

    if ((env_ptr = getenv(SYS_VAR_TX_SEGS_RING_BATCH_TCP))) {
        tx_segs_ring_batch_tcp = (uint32_t)std::max<int32_t>(atoi(env_ptr), 1);
    }

    if ((env_ptr = getenv(SYS_VAR_TX_SEGS_POOL_BATCH_TCP))) {
        tx_segs_pool_batch_tcp = (uint32_t)std::max<int32_t>(atoi(env_ptr), 1);
    }

    if ((env_ptr = getenv(SYS_VAR_RING_ALLOCATION_LOGIC_TX))) {
        ring_allocation_logic_tx = (ring_logic_t)atoi(env_ptr);
        if (!is_ring_logic_valid(ring_allocation_logic_tx)) {
            vlog_printf(VLOG_WARNING, "%s = %d is not valid, setting logic to default = %d\n",
                        SYS_VAR_RING_ALLOCATION_LOGIC_TX, ring_allocation_logic_tx,
                        MCE_DEFAULT_RING_ALLOCATION_LOGIC_TX);
            ring_allocation_logic_tx = MCE_DEFAULT_RING_ALLOCATION_LOGIC_TX;
        }
    }

    if ((env_ptr = getenv(SYS_VAR_RING_ALLOCATION_LOGIC_RX))) {
        ring_allocation_logic_rx = (ring_logic_t)atoi(env_ptr);
        if (!is_ring_logic_valid(ring_allocation_logic_rx)) {
            vlog_printf(VLOG_WARNING, "%s = %d is not valid, setting logic to default = %d\n",
                        SYS_VAR_RING_ALLOCATION_LOGIC_RX, ring_allocation_logic_rx,
                        MCE_DEFAULT_RING_ALLOCATION_LOGIC_RX);
            ring_allocation_logic_rx = MCE_DEFAULT_RING_ALLOCATION_LOGIC_RX;
        }
    }

    if ((env_ptr = getenv(SYS_VAR_RING_MIGRATION_RATIO_TX))) {
        ring_migration_ratio_tx = atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_RING_MIGRATION_RATIO_RX))) {
        ring_migration_ratio_rx = atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_RING_LIMIT_PER_INTERFACE))) {
        ring_limit_per_interface = std::max(0, atoi(env_ptr));
    }

    if ((env_ptr = getenv(SYS_VAR_RING_DEV_MEM_TX))) {
        ring_dev_mem_tx = std::max(0, atoi(env_ptr));
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_MAX_SYN_RATE))) {
        tcp_max_syn_rate = std::min(TCP_MAX_SYN_RATE_TOP_LIMIT, std::max(0, atoi(env_ptr)));
    }

    if ((env_ptr = getenv(SYS_VAR_RX_BUF_SIZE))) {
        rx_buf_size = (uint32_t)option_size::from_str(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_RX_NUM_WRE_TO_POST_RECV))) {
        rx_num_wr_to_post_recv = std::min(NUM_RX_WRE_TO_POST_RECV_MAX, std::max(1, atoi(env_ptr)));
    }

    if ((env_ptr = getenv(SYS_VAR_RX_NUM_WRE))) {
        rx_num_wr = (uint32_t)atoi(env_ptr);
    }

    if (enable_striding_rq && (strq_stride_num_per_rwqe * rx_num_wr > MAX_MLX5_CQ_SIZE_ITEMS)) {
        rx_num_wr = MAX_MLX5_CQ_SIZE_ITEMS / strq_stride_num_per_rwqe;

        vlog_printf(VLOG_WARNING,
                    "Requested " SYS_VAR_STRQ_NUM_STRIDES " * " SYS_VAR_RX_NUM_WRE
                    " > Maximum CQE per CQ (%d)."
                    " Decreasing " SYS_VAR_RX_NUM_WRE " to %" PRIu32 "\n",
                    MAX_MLX5_CQ_SIZE_ITEMS, rx_num_wr);
    }

    if (rx_num_wr <= (rx_num_wr_to_post_recv * 2)) {
        rx_num_wr = rx_num_wr_to_post_recv * 2;
    }

    if ((env_ptr = getenv(SYS_VAR_RX_NUM_POLLS))) {
        rx_poll_num = atoi(env_ptr);
    }
    if (rx_poll_num < MCE_MIN_RX_NUM_POLLS || rx_poll_num > MCE_MAX_RX_NUM_POLLS) {
        vlog_printf(VLOG_WARNING, "Rx Poll loops should be between %d and %d [%d]\n",
                    MCE_MIN_RX_NUM_POLLS, MCE_MAX_RX_NUM_POLLS, rx_poll_num);
        rx_poll_num = MCE_DEFAULT_RX_NUM_POLLS;
    }
    if ((env_ptr = getenv(SYS_VAR_RX_NUM_POLLS_INIT))) {
        rx_poll_num_init = atoi(env_ptr);
    }
    if (rx_poll_num_init < MCE_MIN_RX_NUM_POLLS || rx_poll_num_init > MCE_MAX_RX_NUM_POLLS) {
        vlog_printf(VLOG_WARNING, "Rx Poll loops should be between %d and %d [%d]\n",
                    MCE_MIN_RX_NUM_POLLS, MCE_MAX_RX_NUM_POLLS, rx_poll_num_init);
        rx_poll_num_init = MCE_DEFAULT_RX_NUM_POLLS_INIT;
    }
    if (rx_poll_num == 0) {
        rx_poll_num = 1; // Force at least one good polling loop
    }

    if ((env_ptr = getenv(SYS_VAR_RX_UDP_POLL_OS_RATIO))) {
        rx_udp_poll_os_ratio = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_HW_TS_CONVERSION_MODE))) {
        hw_ts_conversion_mode = (ts_conversion_mode_t)atoi(env_ptr);
        if ((uint32_t)hw_ts_conversion_mode >= TS_CONVERSION_MODE_LAST) {
            vlog_printf(
                VLOG_WARNING,
                "HW TS conversion size out of range [%d] (min=%d, max=%d). using default [%d]\n",
                hw_ts_conversion_mode, TS_CONVERSION_MODE_DISABLE, TS_CONVERSION_MODE_LAST - 1,
                MCE_DEFAULT_HW_TS_CONVERSION_MODE);
            hw_ts_conversion_mode = MCE_DEFAULT_HW_TS_CONVERSION_MODE;
        }
    }

    if ((env_ptr = getenv(SYS_VAR_RX_POLL_YIELD))) {
        rx_poll_yield_loops = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_SELECT_CPU_USAGE_STATS))) {
        select_handle_cpu_usage_stats = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_RX_BYTE_MIN_LIMIT))) {
        rx_ready_byte_min_limit = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_RX_PREFETCH_BYTES))) {
        rx_prefetch_bytes = (uint32_t)atoi(env_ptr);
    }
    if (rx_prefetch_bytes < MCE_MIN_RX_PREFETCH_BYTES ||
        rx_prefetch_bytes > MCE_MAX_RX_PREFETCH_BYTES) {
        vlog_printf(VLOG_WARNING, "Rx prefetch bytes size out of range [%d] (min=%d, max=%d)\n",
                    rx_prefetch_bytes, MCE_MIN_RX_PREFETCH_BYTES, MCE_MAX_RX_PREFETCH_BYTES);
        rx_prefetch_bytes = MCE_DEFAULT_RX_PREFETCH_BYTES;
    }

    if ((env_ptr = getenv(SYS_VAR_RX_PREFETCH_BYTES_BEFORE_POLL))) {
        rx_prefetch_bytes_before_poll = (uint32_t)atoi(env_ptr);
    }
    if (rx_prefetch_bytes_before_poll != 0 &&
        (rx_prefetch_bytes_before_poll < MCE_MIN_RX_PREFETCH_BYTES ||
         rx_prefetch_bytes_before_poll > MCE_MAX_RX_PREFETCH_BYTES)) {
        vlog_printf(
            VLOG_WARNING, "Rx prefetch bytes size out of range [%d] (min=%d, max=%d, disabled=0)\n",
            rx_prefetch_bytes_before_poll, MCE_MIN_RX_PREFETCH_BYTES, MCE_MAX_RX_PREFETCH_BYTES);
        rx_prefetch_bytes_before_poll = MCE_DEFAULT_RX_PREFETCH_BYTES_BEFORE_POLL;
    }

    if ((env_ptr = getenv(SYS_VAR_RX_CQ_DRAIN_RATE_NSEC))) {
        rx_cq_drain_rate_nsec = atoi(env_ptr);
    }
    // Update the rx cq polling rate for draining logic
    tscval_t tsc_per_second = get_tsc_rate_per_second();
    rx_delta_tsc_between_cq_polls = tsc_per_second * rx_cq_drain_rate_nsec / NSEC_PER_SEC;

    if ((env_ptr = getenv(SYS_VAR_GRO_STREAMS_MAX))) {
        gro_streams_max = std::max(atoi(env_ptr), 0);
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_2T_RULES))) {
        tcp_2t_rules = atoi(env_ptr) ? true : false;
    }
    if ((env_ptr = getenv(SYS_VAR_TCP_3T_RULES))) {
        tcp_3t_rules = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_UDP_3T_RULES))) {
        udp_3t_rules = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_ETH_MC_L2_ONLY_RULES))) {
        eth_mc_l2_only_rules = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_DISABLE_FLOW_TAG))) {
        disable_flow_tag = std::max(atoi(env_ptr), 0) ? true : false;
    }
    // mc_force_flowtag must be after disable_flow_tag
    if ((env_ptr = getenv(SYS_VAR_MC_FORCE_FLOWTAG))) {
        mc_force_flowtag = atoi(env_ptr) ? true : false;
        if (disable_flow_tag) {
            vlog_printf(VLOG_WARNING, "%s and %s can't be set together. Disabling %s\n",
                        SYS_VAR_DISABLE_FLOW_TAG, SYS_VAR_MC_FORCE_FLOWTAG,
                        SYS_VAR_MC_FORCE_FLOWTAG);
            mc_force_flowtag = 0;
        }
    }

    if ((env_ptr = getenv(SYS_VAR_SELECT_NUM_POLLS))) {
        select_poll_num = atoi(env_ptr);
    }

    if (select_poll_num < MCE_MIN_RX_NUM_POLLS || select_poll_num > MCE_MAX_RX_NUM_POLLS) {
        vlog_printf(VLOG_WARNING, "Select Poll loops can not be below zero [%d]\n",
                    select_poll_num);
        select_poll_num = MCE_DEFAULT_SELECT_NUM_POLLS;
    }

    if ((env_ptr = getenv(SYS_VAR_SELECT_POLL_OS_FORCE))) {
        select_poll_os_force = (uint32_t)atoi(env_ptr);
    }

    if (select_poll_os_force) {
        select_poll_os_ratio = 1;
        select_skip_os_fd_check = 1;
    }

    if ((env_ptr = getenv(SYS_VAR_SELECT_POLL_OS_RATIO))) {
        select_poll_os_ratio = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_SELECT_SKIP_OS))) {
        select_skip_os_fd_check = (uint32_t)atoi(env_ptr);
    }

#ifdef DEFINED_IBV_CQ_ATTR_MODERATE
    if (rx_poll_num < 0 || select_poll_num < 0) {
        cq_moderation_enable = false;
    }
    if ((env_ptr = getenv(SYS_VAR_CQ_MODERATION_ENABLE))) {
        cq_moderation_enable = atoi(env_ptr) ? true : false;
    }
    if ((env_ptr = getenv(SYS_VAR_CQ_MODERATION_COUNT))) {
        cq_moderation_count = (uint32_t)atoi(env_ptr);
    }

    uint32_t max_cq_moderation_count =
        (!enable_striding_rq ? rx_num_wr : (strq_stride_num_per_rwqe * rx_num_wr)) / 2U;
    if (cq_moderation_count > max_cq_moderation_count) {
        cq_moderation_count = max_cq_moderation_count;
    }

    if ((env_ptr = getenv(SYS_VAR_CQ_MODERATION_PERIOD_USEC))) {
        cq_moderation_period_usec = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_CQ_AIM_MAX_COUNT))) {
        cq_aim_max_count = (uint32_t)atoi(env_ptr);
    }

    uint32_t max_cq_aim_max_count =
        (!enable_striding_rq ? rx_num_wr : (strq_stride_num_per_rwqe * rx_num_wr)) / 2U;
    if (cq_aim_max_count > max_cq_aim_max_count) {
        cq_aim_max_count = max_cq_aim_max_count;
    }

    if ((env_ptr = getenv(SYS_VAR_CQ_AIM_MAX_PERIOD_USEC))) {
        cq_aim_max_period_usec = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_CQ_AIM_INTERVAL_MSEC))) {
        cq_aim_interval_msec = (uint32_t)atoi(env_ptr);
    }

    if (!cq_moderation_enable) {
        cq_aim_interval_msec = MCE_CQ_ADAPTIVE_MODERATION_DISABLED;
    }

    if ((env_ptr = getenv(SYS_VAR_CQ_AIM_INTERRUPTS_RATE_PER_SEC))) {
        cq_aim_interrupts_rate_per_sec = (uint32_t)atoi(env_ptr);
    }
#else
    if ((env_ptr = getenv(SYS_VAR_CQ_MODERATION_ENABLE)) != NULL) {
        vlog_printf(VLOG_WARNING, "'%s' is not supported on this environment\n",
                    SYS_VAR_CQ_MODERATION_ENABLE);
    }
    if ((env_ptr = getenv(SYS_VAR_CQ_MODERATION_COUNT)) != NULL) {
        vlog_printf(VLOG_WARNING, "'%s' is not supported on this environment\n",
                    SYS_VAR_CQ_MODERATION_COUNT);
    }
    if ((env_ptr = getenv(SYS_VAR_CQ_MODERATION_PERIOD_USEC)) != NULL) {
        vlog_printf(VLOG_WARNING, "'%s' is not supported on this environment\n",
                    SYS_VAR_CQ_MODERATION_PERIOD_USEC);
    }
    if ((env_ptr = getenv(SYS_VAR_CQ_AIM_MAX_COUNT)) != NULL) {
        vlog_printf(VLOG_WARNING, "'%s' is not supported on this environment\n",
                    SYS_VAR_CQ_AIM_MAX_COUNT);
    }
    if ((env_ptr = getenv(SYS_VAR_CQ_AIM_MAX_PERIOD_USEC)) != NULL) {
        vlog_printf(VLOG_WARNING, "'%s' is not supported on this environment\n",
                    SYS_VAR_CQ_AIM_MAX_PERIOD_USEC);
    }
    if ((env_ptr = getenv(SYS_VAR_CQ_AIM_INTERVAL_MSEC)) != NULL) {
        vlog_printf(VLOG_WARNING, "'%s' is not supported on this environment\n",
                    SYS_VAR_CQ_AIM_INTERVAL_MSEC);
    }
    if ((env_ptr = getenv(SYS_VAR_CQ_AIM_INTERRUPTS_RATE_PER_SEC)) != NULL) {
        vlog_printf(VLOG_WARNING, "'%s' is not supported on this environment\n",
                    SYS_VAR_CQ_AIM_INTERRUPTS_RATE_PER_SEC);
    }
#endif /* DEFINED_IBV_CQ_ATTR_MODERATE */

    if ((env_ptr = getenv(SYS_VAR_CQ_POLL_BATCH_MAX))) {
        cq_poll_batch_max = (uint32_t)atoi(env_ptr);
    }
    if (cq_poll_batch_max < MCE_MIN_CQ_POLL_BATCH || cq_poll_batch_max > MCE_MAX_CQ_POLL_BATCH) {
        vlog_printf(VLOG_WARNING, "Rx number of cq poll batchs should be between %d and %d [%d]\n",
                    MCE_MIN_CQ_POLL_BATCH, MCE_MAX_CQ_POLL_BATCH, cq_poll_batch_max);
        cq_poll_batch_max = MCE_DEFAULT_CQ_POLL_BATCH;
    }

    if ((env_ptr = getenv(SYS_VAR_PROGRESS_ENGINE_INTERVAL))) {
        progress_engine_interval_msec = (uint32_t)atoi(env_ptr);
    }
    if (enable_socketxtreme && (progress_engine_interval_msec != MCE_CQ_DRAIN_INTERVAL_DISABLED)) {
        progress_engine_interval_msec = MCE_CQ_DRAIN_INTERVAL_DISABLED;
        vlog_printf(VLOG_DEBUG, "%s parameter is forced to %d in case %s is enabled\n",
                    SYS_VAR_PROGRESS_ENGINE_INTERVAL, progress_engine_interval_msec,
                    SYS_VAR_SOCKETXTREME);
    }

    if ((env_ptr = getenv(SYS_VAR_PROGRESS_ENGINE_WCE_MAX))) {
        progress_engine_wce_max = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_CQ_KEEP_QP_FULL))) {
        cq_keep_qp_full = atoi(env_ptr) ? true : false;
    }

    qp_compensation_level = rx_num_wr / 2U;
    if ((env_ptr = getenv(SYS_VAR_QP_COMPENSATION_LEVEL))) {
        qp_compensation_level = (uint32_t)atoi(env_ptr);
    }
    if (qp_compensation_level < rx_num_wr_to_post_recv) {
        qp_compensation_level = rx_num_wr_to_post_recv;
    }

    if ((env_ptr = getenv(SYS_VAR_USER_HUGE_PAGE_SIZE))) {
        user_huge_page_size = option_size::from_str(env_ptr);
        if (user_huge_page_size == 0) {
            user_huge_page_size = g_hugepage_mgr.get_default_hugepage();
        }
    }

    if ((env_ptr = getenv(SYS_VAR_OFFLOADED_SOCKETS))) {
        offloaded_sockets = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_TIMER_RESOLUTION_MSEC))) {
        timer_resolution_msec = atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_TIMER_RESOLUTION_MSEC))) {
        tcp_timer_resolution_msec = atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_CTL_THREAD))) {
        tcp_ctl_thread = option_tcp_ctl_thread::from_str(env_ptr, MCE_DEFAULT_TCP_CTL_THREAD);
        if (tcp_ctl_thread == option_tcp_ctl_thread::CTL_THREAD_DELEGATE_TCP_TIMERS) {
            if (progress_engine_interval_msec != MCE_CQ_DRAIN_INTERVAL_DISABLED) {
                vlog_printf(VLOG_DEBUG, "%s parameter is forced to %d in case %s=%s is enabled\n",
                            SYS_VAR_PROGRESS_ENGINE_INTERVAL, MCE_CQ_DRAIN_INTERVAL_DISABLED,
                            SYS_VAR_TCP_CTL_THREAD, option_tcp_ctl_thread::to_str(tcp_ctl_thread));

                progress_engine_interval_msec = MCE_CQ_DRAIN_INTERVAL_DISABLED;
            }
            if (ring_allocation_logic_tx != RING_LOGIC_PER_THREAD ||
                ring_allocation_logic_rx != RING_LOGIC_PER_THREAD) {
                vlog_printf(VLOG_DEBUG,
                            "%s,%s parameter is forced to %s in case %s=%s is enabled\n",
                            SYS_VAR_RING_ALLOCATION_LOGIC_TX, SYS_VAR_RING_ALLOCATION_LOGIC_RX,
                            ring_logic_str(RING_LOGIC_PER_THREAD), SYS_VAR_TCP_CTL_THREAD,
                            option_tcp_ctl_thread::to_str(tcp_ctl_thread));

                ring_allocation_logic_tx = ring_allocation_logic_rx = RING_LOGIC_PER_THREAD;
            }
        }
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_TIMESTAMP_OPTION))) {
        tcp_ts_opt = (tcp_ts_opt_t)atoi(env_ptr);
        if ((uint32_t)tcp_ts_opt >= TCP_TS_OPTION_LAST) {
            vlog_printf(VLOG_WARNING,
                        "TCP timestamp option value is out of range [%d] (min=%d, max=%d). using "
                        "default [%d]\n",
                        tcp_ts_opt, TCP_TS_OPTION_DISABLE, TCP_TS_OPTION_LAST - 1,
                        MCE_DEFAULT_TCP_TIMESTAMP_OPTION);
            tcp_ts_opt = MCE_DEFAULT_TCP_TIMESTAMP_OPTION;
        }
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_NODELAY))) {
        tcp_nodelay = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_QUICKACK))) {
        tcp_quickack = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_PUSH_FLAG))) {
        tcp_push_flag = atoi(env_ptr) ? true : false;
    }

    // TODO: this should be replaced by calling "exception_handling.init()" that will be called from
    // init()
    if ((env_ptr = getenv(xlio_exception_handling::getSysVar()))) {
        exception_handling = xlio_exception_handling(strtol(
            env_ptr, nullptr, 10)); // xlio_exception_handling is responsible for its invariant
    }

    if ((env_ptr = getenv(SYS_VAR_AVOID_SYS_CALLS_ON_TCP_FD))) {
        avoid_sys_calls_on_tcp_fd = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_ALLOW_PRIVILEGED_SOCK_OPT))) {
        allow_privileged_sock_opt = atoi(env_ptr) ? true : false;
    }

    if (tcp_timer_resolution_msec < timer_resolution_msec) {
        vlog_printf(VLOG_WARNING,
                    "TCP timer resolution [%s=%d] cannot be smaller than timer resolution "
                    "[%s=%d]. Setting TCP timer resolution to %d msec.\n",
                    SYS_VAR_TCP_TIMER_RESOLUTION_MSEC, tcp_timer_resolution_msec,
                    SYS_VAR_TIMER_RESOLUTION_MSEC, timer_resolution_msec, timer_resolution_msec);
        tcp_timer_resolution_msec = timer_resolution_msec;
    }

    if ((env_ptr = getenv(SYS_VAR_INTERNAL_THREAD_ARM_CQ))) {
        internal_thread_arm_cq_enabled = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_INTERNAL_THREAD_CPUSET))) {
        snprintf(internal_thread_cpuset, FILENAME_MAX, "%s", env_ptr);
    }

    // handle internal thread affinity - default is CPU-0
    if ((env_ptr = getenv(SYS_VAR_INTERNAL_THREAD_AFFINITY))) {
        int n = snprintf(internal_thread_affinity_str, sizeof(internal_thread_affinity_str), "%s",
                         env_ptr);
        if (unlikely(((int)sizeof(internal_thread_affinity_str) < n) || (n < 0))) {
            vlog_printf(VLOG_WARNING, "Failed to process: %s.\n", SYS_VAR_INTERNAL_THREAD_AFFINITY);
        }
    }
    if (env_to_cpuset(internal_thread_affinity_str, &internal_thread_affinity)) {
        vlog_printf(VLOG_WARNING,
                    "Failed to set internal thread affinity: %s...  deferring to cpu-0.\n",
                    internal_thread_affinity_str);
    }

    if ((env_ptr = getenv(SYS_VAR_WAIT_AFTER_JOIN_MSEC))) {
        wait_after_join_msec = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_BUFFER_BATCHING_MODE))) {
        buffer_batching_mode = (buffer_batching_mode_t)atoi(env_ptr);
        if (buffer_batching_mode < 0 || buffer_batching_mode >= BUFFER_BATCHING_LAST) {
            buffer_batching_mode = MCE_DEFAULT_BUFFER_BATCHING_MODE;
        }
    }

    if (buffer_batching_mode == BUFFER_BATCHING_NONE) {
        tx_bufs_batch_tcp = 1;
        tx_bufs_batch_udp = 1;
        rx_bufs_batch = 1;
    }

    if ((env_ptr = getenv(SYS_VAR_NETLINK_TIMER_MSEC))) {
        timer_netlink_update_msec = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_NEIGH_NUM_ERR_RETRIES))) {
        neigh_num_err_retries = (uint32_t)atoi(env_ptr);
    }
    if ((env_ptr = getenv(SYS_VAR_NEIGH_UC_ARP_DELAY_MSEC))) {
        neigh_wait_till_send_arp_msec = (uint32_t)atoi(env_ptr);
    }
    if ((env_ptr = getenv(SYS_VAR_NEIGH_UC_ARP_QUATA))) {
        neigh_uc_arp_quata = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_MEM_ALLOC_TYPE))) {
        mem_alloc_type = option_alloc_type::from_str(env_ptr, MCE_DEFAULT_MEM_ALLOC_TYPE);
    }
    if ((env_ptr = getenv(SYS_VAR_MEMORY_LIMIT))) {
        memory_limit = option_size::from_str(env_ptr) ?: MCE_DEFAULT_MEMORY_LIMIT;
    }
    if ((env_ptr = getenv(SYS_VAR_MEMORY_LIMIT_USER))) {
        memory_limit_user = option_size::from_str(env_ptr);
    }
    if ((env_ptr = getenv(SYS_VAR_HEAP_METADATA_BLOCK))) {
        heap_metadata_block = option_size::from_str(env_ptr) ?: MCE_DEFAULT_HEAP_METADATA_BLOCK;
    }
    if ((env_ptr = getenv(SYS_VAR_HUGEPAGE_SIZE))) {
        hugepage_size = option_size::from_str(env_ptr);
        if (hugepage_size & (hugepage_size - 1)) {
            vlog_printf(VLOG_WARNING, "%s must be a power of 2. Fallback to default value (%s)\n",
                        SYS_VAR_HUGEPAGE_SIZE, option_size::to_str(MCE_DEFAULT_HUGEPAGE_SIZE));
            hugepage_size = MCE_DEFAULT_HUGEPAGE_SIZE;
        }
        if (hugepage_size > static_cast<int64_t>(MCE_MAX_HUGEPAGE_SIZE)) {
            vlog_printf(VLOG_WARNING, "%s exceeds maximum possible hugepage size (%s)\n",
                        SYS_VAR_HUGEPAGE_SIZE, option_size::to_str(MCE_MAX_HUGEPAGE_SIZE));
            hugepage_size = MCE_DEFAULT_HUGEPAGE_SIZE;
        }
    }

    if ((env_ptr = getenv(SYS_VAR_FORK))) {
        handle_fork = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_TSO))) {
        enable_tso = option_3::from_str(env_ptr, MCE_DEFAULT_TSO);
    }

    if ((env_ptr = getenv(SYS_VAR_MAX_TSO_SIZE))) {
        max_tso_sz = option_size::from_str(env_ptr);
    }

    if ((enable_tso != option_3::OFF) && (ring_migration_ratio_tx != -1)) {
        ring_migration_ratio_tx = -1;
        vlog_printf(VLOG_DEBUG, "%s parameter is forced to %d in case %s is enabled\n",
                    SYS_VAR_RING_MIGRATION_RATIO_TX, -1, SYS_VAR_TSO);
    }

#ifdef DEFINED_UTLS
    if ((env_ptr = getenv(SYS_VAR_UTLS_RX)) != NULL) {
        enable_utls_rx = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_UTLS_TX)) != NULL) {
        enable_utls_tx = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_UTLS_HIGH_WMARK_DEK_CACHE_SIZE)) != NULL) {
        int temp = atoi(env_ptr);
        utls_high_wmark_dek_cache_size = (temp >= 0 ? static_cast<size_t>(temp) : 0);
    }

    if ((env_ptr = getenv(SYS_VAR_UTLS_LOW_WMARK_DEK_CACHE_SIZE)) != NULL) {
        int temp = atoi(env_ptr);
        utls_low_wmark_dek_cache_size = (temp >= 0 ? static_cast<size_t>(temp) : 0);
        if (utls_low_wmark_dek_cache_size >= utls_high_wmark_dek_cache_size) {
            utls_low_wmark_dek_cache_size = utls_high_wmark_dek_cache_size / 2U;
        }
    }
#endif /* DEFINED_UTLS */

    if ((env_ptr = getenv(SYS_VAR_LRO))) {
        enable_lro = option_3::from_str(env_ptr, MCE_DEFAULT_LRO);
    }

    if ((env_ptr = getenv(SYS_VAR_CLOSE_ON_DUP2))) {
        close_on_dup2 = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_MTU))) {
        mtu = (uint32_t)atoi(env_ptr);
    }

#if defined(DEFINED_NGINX)
    if ((env_ptr = getenv(SYS_VAR_NGINX_UDP_POOL_SIZE))) {
        nginx_udp_socket_pool_size = (uint32_t)atoi(env_ptr);
    }
    if ((env_ptr = getenv(SYS_VAR_NGINX_UDP_POOL_RX_NUM_BUFFS_REUSE))) {
        nginx_udp_socket_pool_rx_num_buffs_reuse = (uint32_t)atoi(env_ptr);
    }
#endif // DEFINED_NGINX
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    if ((env_ptr = getenv(SYS_VAR_SRC_PORT_STRIDE))) {
        app.src_port_stride = (uint32_t)atoi(env_ptr);
    }
    if ((env_ptr = getenv(SYS_VAR_DISTRIBUTE_CQ))) {
        app.distribute_cq_interrupts = atoi(env_ptr) ? true : false;
    }
#endif
    if ((env_ptr = getenv(SYS_VAR_MSS))) {
        lwip_mss = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_CC_ALGO))) {
        lwip_cc_algo_mod = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_DEFERRED_CLOSE))) {
        deferred_close = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_ABORT_ON_CLOSE))) {
        tcp_abort_on_close = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_RX_POLL_ON_TX_TCP))) {
        rx_poll_on_tx_tcp = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_RX_CQ_WAIT_CTRL))) {
        rx_cq_wait_ctrl = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_TRIGGER_DUMMY_SEND_GETSOCKNAME))) {
        trigger_dummy_send_getsockname = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_SEND_BUFFER_SIZE))) {
        tcp_send_buffer_size = (uint32_t)option_size::from_str(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_SKIP_POLL_IN_RX))) {
        int temp = atoi(env_ptr);
        if (temp < 0 || temp > SKIP_POLL_IN_RX_EPOLL_ONLY) {
            temp = 0;
        }
        skip_poll_in_rx = (skip_poll_in_rx_t)temp;
    }

    if ((env_ptr = getenv(SYS_VAR_MULTILOCK))) {
        int temp = atoi(env_ptr);
        if (temp < 0 || temp > MULTILOCK_MUTEX) {
            temp = 0;
        }
        multilock = (multilock_t)temp;
    }
}

static void set_string_member(char *sys_var_member, size_t sys_var_member_size,
                              const std::string &value)
{
    memset(sys_var_member, 0, sys_var_member_size);
    if (value.empty()) {
        return;
    }
    snprintf(sys_var_member, sys_var_member_size, "%s", value.c_str());
}

static void set_path_member(char *sys_var_member, size_t sys_var_member_size,
                            const std::string &value, bool add_pid)
{
    memset(sys_var_member, 0, sys_var_member_size);
    if (value.empty()) {
        return;
    }

    if (add_pid) {
        snprintf(sys_var_member, sys_var_member_size, "%s.%d", value.c_str(), getpid());
    } else {
        snprintf(sys_var_member, sys_var_member_size, "%s", value.c_str());
    }
}

std::string transport_control_to_legacy(
    const std::vector<std::experimental::any> &transport_control)
{
    std::string result;

    for (size_t i = 0; i < transport_control.size(); i++) {
        auto rule_object =
            std::experimental::any_cast<std::map<std::string, std::experimental::any>>(
                transport_control[i]);

        // Add application info
        result += "application-id " +
            std::experimental::any_cast<std::string>(rule_object["name"]) + " " +
            std::experimental::any_cast<std::string>(rule_object["id"]) + ",";

        // Add actions
        auto actions = std::experimental::any_cast<std::vector<std::experimental::any>>(
            rule_object["actions"]);

        for (size_t j = 0; j < actions.size(); j++) {
            result += std::experimental::any_cast<std::string>(actions[j]);
            if (j < actions.size() - 1) {
                result += ",";
            }
        }

        // Add separator between rules
        if (i < transport_control.size() - 1) {
            result += ";";
        }
    }

    return result;
}

void mce_sys_var::apply_settings(const config_registry &registry)
{
    const bool core_append_pid_to_path = registry.get_value<bool>("core.append_pid_to_path");

    const std::string net_offload_transport_control =
        transport_control_to_legacy(registry.get_value<std::vector<std::experimental::any>>(
            "net.offload.transport_control"));
    set_string_member(transport_control_context, sizeof(transport_control_context),
                      net_offload_transport_control);

    const std::string net_offload_app_id =
        registry.get_value<std::string>("net.offload.app_id");
    set_string_member(app_id, sizeof(app_id), net_offload_app_id);

    const std::string core_log_file_path =
        registry.get_value<std::string>("core.log.file_path");
    set_path_member(log_filename, sizeof(log_filename), core_log_file_path,
                    core_append_pid_to_path);

    const std::string core_stats_file_path =
        registry.get_value<std::string>("core.stats.file_path");
    set_path_member(stats_filename, sizeof(stats_filename), core_stats_file_path,
                    core_append_pid_to_path);

    const std::string core_stats_shmem_dir =
        registry.get_value<std::string>("core.stats.shmem_dir");
    set_path_member(stats_shmem_dirname, sizeof(stats_shmem_dirname), core_stats_shmem_dir,
                    core_append_pid_to_path);

    const std::string xlio_daemon_dir = registry.get_value<std::string>("xlio.daemon.dir");
    set_path_member(service_notify_dir, sizeof(service_notify_dir), xlio_daemon_dir,
                    core_append_pid_to_path);

    service_enable = registry.get_value<bool>("xlio.daemon.enable");

    memset(internal_thread_cpuset, 0, sizeof(internal_thread_cpuset));
    const std::string core_cpu_cpuset = registry.get_value<std::string>("core.cpu.cpuset");
    snprintf(internal_thread_cpuset, sizeof(internal_thread_cpuset), "%s", core_cpu_cpuset.c_str());

    memset(internal_thread_affinity_str, 0, sizeof(internal_thread_affinity_str));
    const std::string core_cpu_affinity =
        registry.get_value<std::string>("core.cpu.affinity");
    snprintf(internal_thread_affinity_str, sizeof(internal_thread_affinity_str), "%s",
             core_cpu_affinity.c_str());

    print_report = registry.get_value<bool>("core.exit_report");

    quick_start = registry.get_value<bool>("core.init.quick");

    log_level = static_cast<vlog_levels_t>(registry.get_value<int>("core.log.level"));

    log_details = registry.get_value<decltype(log_details)>("xlio.log.details");

    log_colors = registry.get_value<bool>("xlio.log.colors");

    handle_sigintr =
        registry.get_value<bool>("core.signals.sigint.exit");

    handle_segfault =
        registry.get_value<bool>("core.signals.sigsegv.backtrace");

    stats_fd_num_max = registry.get_value<decltype(stats_fd_num_max)>("core.stats.fd_num");
    stats_fd_num_monitor = stats_fd_num_max;

    ring_allocation_logic_tx =
        static_cast<ring_logic_t>(registry.get_value<int>("xlio.ring.tx.alloc_logic"));

    ring_allocation_logic_rx =
        static_cast<ring_logic_t>(registry.get_value<int>("xlio.ring.rx.alloc_logic"));

    ring_migration_ratio_tx =
        registry.get_value<decltype(ring_migration_ratio_tx)>("xlio.ring.tx.migration_ratio");

    ring_migration_ratio_rx =
        registry.get_value<decltype(ring_migration_ratio_rx)>("xlio.ring.rx.migration_ratio");

    ring_limit_per_interface =
        registry.get_value<decltype(ring_limit_per_interface)>("xlio.ring.max_per_interface");

    ring_dev_mem_tx =
        registry.get_value<decltype(ring_dev_mem_tx)>("xlio.ring.tx.max_on_device_memory");

    tcp_max_syn_rate =
        registry.get_value<decltype(tcp_max_syn_rate)>("net.tcp.max_syn_rate");

    zc_cache_threshold =
        registry.get_value<decltype(zc_cache_threshold)>("xlio.api.sendfile_limit");

    tx_buf_size =
        registry.get_value<decltype(tx_buf_size)>("xlio.sq.buf.size");

    tcp_nodelay_treshold =
        registry.get_value<decltype(tcp_nodelay_treshold)>("net.tcp.nodelay.byte_threshold");

    tx_num_wr =
        registry.get_value<decltype(tx_num_wr)>("xlio.sq.wre.global_array_size");

    tx_num_wr_to_signal =
        registry.get_value<decltype(tx_num_wr_to_signal)>("xlio.sq.wre.completion_batch_size");

    tx_max_inline =
        registry.get_value<decltype(tx_max_inline)>("xlio.sq.wre.max_inline_size");

    tx_mc_loopback_default =
        registry.get_value<bool>("xlio.udp.mc_loopback");

    tx_nonblocked_eagains =
        registry.get_value<bool>("xlio.sq.nonblocking.eagain");

    tx_prefetch_bytes =
        registry.get_value<decltype(tx_prefetch_bytes)>("xlio.sq.prefetch.cache_size");

    tx_bufs_batch_udp =
        registry.get_value<decltype(tx_bufs_batch_udp)>("xlio.udp.buf.batch_size");

    tx_bufs_batch_tcp =
        registry.get_value<decltype(tx_bufs_batch_tcp)>("xlio.sq.buf.batch_size");

    tx_segs_batch_tcp =
        registry.get_value<decltype(tx_segs_batch_tcp)>("xlio.sq.segments.socket_batch_size");

    tx_segs_ring_batch_tcp =
        registry.get_value<decltype(tx_segs_ring_batch_tcp)>("xlio.sq.segments.ring_batch_size");

    tx_segs_pool_batch_tcp =
        registry.get_value<decltype(tx_segs_pool_batch_tcp)>("xlio.sq.segments.pool_batch_size");

    rx_buf_size = registry.get_value<decltype(rx_buf_size)>("xlio.rq.buf.size");

    rx_bufs_batch = registry.get_value<decltype(rx_bufs_batch)>("xlio.rq.buf.batch_size");

    rx_num_wr = registry.get_value<decltype(rx_num_wr)>("xlio.rq.wre.global_array_size");

    rx_num_wr_to_post_recv = registry.get_value<decltype(rx_num_wr_to_post_recv)>("xlio.rq.wre.rx_batch_size");

    rx_poll_num = registry.get_value<decltype(rx_poll_num)>("xlio.cq.rx_poll_count");

    rx_poll_num_init = registry.get_value<decltype(rx_poll_num_init)>("xlio.udp.offload_transition_poll_count");

    rx_udp_poll_os_ratio = registry.get_value<decltype(rx_udp_poll_os_ratio)>("xlio.udp.rx_kernel_fd_attention_level");

    hw_ts_conversion_mode = static_cast<ts_conversion_mode_t>(registry.get_value<int>("xlio.ts_conversion"));

    rx_poll_yield_loops = registry.get_value<bool>("xlio.udp.yield_on_poll");

    select_handle_cpu_usage_stats = registry.get_value<bool>("core.stats.cpu_usage");

    rx_ready_byte_min_limit = registry.get_value<decltype(rx_ready_byte_min_limit)>("xlio.rq.buf.override_rcvbuf_limit");

    rx_prefetch_bytes = registry.get_value<decltype(rx_prefetch_bytes)>("xlio.rq.prefetch.cache_size");

    rx_prefetch_bytes_before_poll = registry.get_value<bool>("xlio.rq.prefetch.fetch_before_poll") ? rx_prefetch_bytes : 0;

    rx_cq_drain_rate_nsec = registry.get_value<decltype(rx_cq_drain_rate_nsec)>("xlio.cq.rx_drain_rate_nsec");

    // Update the rx cq polling rate for draining logic
    tscval_t tsc_per_second = get_tsc_rate_per_second();
    rx_delta_tsc_between_cq_polls = tsc_per_second * rx_cq_drain_rate_nsec / NSEC_PER_SEC;

    const bool xlio_rq_striding_enable = registry.get_value<bool>("xlio.rq.striding.enable");
    enable_strq_env = xlio_rq_striding_enable ? option_3::ON : option_3::OFF;
    enable_striding_rq = xlio_rq_striding_enable;

    strq_stride_num_per_rwqe =
        registry.get_value<decltype(strq_stride_num_per_rwqe)>("xlio.rq.striding.strides");

    strq_stride_size_bytes =
        registry.get_value<decltype(strq_stride_size_bytes)>("xlio.rq.striding.stride_size");

    strq_strides_compensation_level =
        registry.get_value<decltype(strq_strides_compensation_level)>("xlio.rq.striding.spare_strides");

    gro_streams_max =
        registry.get_value<decltype(gro_streams_max)>("xlio.rq.max_gro_streams");

    disable_flow_tag =
        registry.get_value<bool>("xlio.udp.mc_disable_flowtag");

    tcp_2t_rules =
        registry.get_value<bool>("xlio.ring.tcp_2t_rules");

    tcp_3t_rules =
        registry.get_value<bool>("xlio.ring.tcp_3t_rules");

    udp_3t_rules =
        registry.get_value<bool>("xlio.udp.3t_rules");

    eth_mc_l2_only_rules =
        registry.get_value<bool>("xlio.udp.only_mc_l2_rules");

    mc_force_flowtag =
        registry.get_value<bool>("xlio.udp.mc_flowtag_acceleration");

    select_poll_num =
        registry.get_value<decltype(select_poll_num)>("net.poll.rx_duration_usec");

    select_poll_os_force =
        MCE_DEFAULT_SELECT_POLL_OS_FORCE; // TODO - discovered to be buggy - see libvma patch

    select_poll_os_ratio =
        registry.get_value<decltype(select_poll_os_ratio)>("net.poll.kernel_fd_attention_level");

    select_skip_os_fd_check =
        registry.get_value<decltype(select_skip_os_fd_check)>("net.poll.offload_fd_priority");

    cq_moderation_enable =
        registry.get_value<bool>("xlio.cq.interrupt_moderation.enable");

    cq_moderation_count =
        registry.get_value<decltype(cq_moderation_count)>("xlio.cq.interrupt_moderation.packet_count");

    cq_moderation_period_usec =
        registry.get_value<decltype(cq_moderation_period_usec)>("xlio.cq.interrupt_moderation.period_usec");

    cq_aim_max_count =
        registry.get_value<decltype(cq_aim_max_count)>("xlio.cq.interrupt_moderation.adaptive_count");

    cq_aim_max_period_usec =
        registry.get_value<decltype(cq_aim_max_period_usec)>("xlio.cq.interrupt_moderation.adaptive_period_usec");

    cq_aim_interval_msec =
        registry.get_value<decltype(cq_aim_interval_msec)>("xlio.cq.interrupt_moderation.adaptive_change_frequency_msec");

    cq_aim_interrupts_rate_per_sec =
        registry.get_value<decltype(cq_aim_interrupts_rate_per_sec)>("xlio.cq.interrupt_moderation.interrupt_per_sec");

    cq_poll_batch_max =
        registry.get_value<decltype(cq_poll_batch_max)>("net.poll.rx_buffer_max_count");

    progress_engine_interval_msec =
        registry.get_value<decltype(progress_engine_interval_msec)>("xlio.cq.periodic_drain_msec");

    progress_engine_wce_max =
        registry.get_value<decltype(progress_engine_wce_max)>("xlio.cq.periodic_drain_max_cqes");

    cq_keep_qp_full =
        registry.get_value<bool>("xlio.cq.keep_full");

    max_tso_sz =
        registry.get_value<decltype(max_tso_sz)>("xlio.sq.tso.max_size");

    user_huge_page_size =
        registry.get_value<decltype(user_huge_page_size)>("xlio.api.hugepages.size");

    internal_thread_arm_cq_enabled =
        registry.get_value<bool>("xlio.cq.interrupt_per_packet");

    offloaded_sockets =
        registry.get_value<bool>("net.offload.enable");

    timer_resolution_msec =
        registry.get_value<decltype(timer_resolution_msec)>("core.handlers.timer_msec");

    tcp_timer_resolution_msec =
        registry.get_value<decltype(tcp_timer_resolution_msec)>("net.tcp.timer_msec");

    tcp_ts_opt =
        static_cast<tcp_ts_opt_t>(registry.get_value<int>("net.tcp.timestamps"));

    tcp_nodelay =
        registry.get_value<bool>("net.tcp.nodelay.enable");

    tcp_quickack =
        registry.get_value<bool>("net.tcp.quickack");

    tcp_push_flag =
        registry.get_value<bool>("net.tcp.push");

    avoid_sys_calls_on_tcp_fd =
        registry.get_value<bool>("net.tcp.offload.enable_posix_ctl");

    allow_privileged_sock_opt =
        registry.get_value<bool>("net.tcp.offload.allow_privileged_sockopt");

    //	exception_handling is handled by its CTOR

    wait_after_join_msec =
        MCE_DEFAULT_WAIT_AFTER_JOIN_MSEC; // TODO - not in use - should be deleted

    buffer_batching_mode =
        static_cast<buffer_batching_mode_t>(registry.get_value<int>("xlio.batching_mode"));

    const bool core_memory_hugepages_enable =
        registry.get_value<bool>("core.memory.hugepages.enable");
    mem_alloc_type = core_memory_hugepages_enable ? option_alloc_type::mode_t::HUGE
                                                  : option_alloc_type::mode_t::ANON;

    memory_limit =
        registry.get_value<decltype(memory_limit)>("core.memory.limit");

    memory_limit_user =
        registry.get_value<decltype(memory_limit_user)>("xlio.memory.external.limit");

    heap_metadata_block =
        registry.get_value<decltype(heap_metadata_block)>("core.memory.heap_metadata_block_size");

    hugepage_size =
        registry.get_value<decltype(hugepage_size)>("core.memory.hugepages.size");

    enable_socketxtreme =
        registry.get_value<bool>("xlio.api.socketextreme");

    const int64_t xlio_sq_tso_enable = registry.get_value<int64_t>("xlio.sq.tso.enable");
    enable_tso = xlio_sq_tso_enable ? option_3::ON : option_3::OFF;

#ifdef DEFINED_UTLS

    const bool xlio_rq_tls_offload_enable =
        registry.get_value<bool>("xlio.rq.tls_offload.enable");
    enable_utls_rx = xlio_rq_tls_offload_enable;

    const bool xlio_sq_tls_offload_enable =
        registry.get_value<bool>("xlio.sq.tls_offload.enable");
    enable_utls_tx = xlio_sq_tls_offload_enable;

    utls_high_wmark_dek_cache_size =
        registry.get_value<decltype(utls_high_wmark_dek_cache_size)>("xlio.sq.tls_offload.dek_cache_max_size");

    utls_low_wmark_dek_cache_size =
        registry.get_value<decltype(utls_low_wmark_dek_cache_size)>("xlio.sq.tls_offload.dek_cache_min_size");

    if (utls_low_wmark_dek_cache_size >= utls_high_wmark_dek_cache_size) {
        utls_low_wmark_dek_cache_size = utls_high_wmark_dek_cache_size / 2U;
    }

#endif /* DEFINED_UTLS */

    const int64_t xlio_rq_lro = registry.get_value<int64_t>("xlio.rq.lro");
    enable_lro = xlio_rq_lro ? option_3::ON : option_3::OFF;

    handle_fork =
        registry.get_value<bool>("xlio.syscall.fork_support");

    close_on_dup2 =
        registry.get_value<bool>("core.syscall.dup2_support");

    mtu =
        registry.get_value<decltype(mtu)>("net.mtu");

#if defined(DEFINED_NGINX)

    nginx_udp_socket_pool_size =
        registry.get_value<decltype(nginx_udp_socket_pool_size)>("xlio.nginx.udp_pool_size");

    nginx_udp_socket_pool_rx_num_buffs_reuse =
        registry.get_value<bool>("xlio.nginx.udp_socket_pool_reuse");

#endif
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    app.workers_num =
        registry.get_value<decltype(app.workers_num)>("xlio.nginx.workers_num");

    app.src_port_stride =
        registry.get_value<decltype(app.src_port_stride)>("xlio.nginx.src_port_stride");

    app.distribute_cq_interrupts =
        registry.get_value<bool>("xlio.nginx.distribute_cq");
#endif

    lwip_mss =
        registry.get_value<decltype(lwip_mss)>("net.tcp.mss");

    lwip_cc_algo_mod =
        registry.get_value<decltype(lwip_cc_algo_mod)>("net.tcp.congestion_control");

    mce_spec =
        registry.get_value<decltype(mce_spec)>("xlio.spec");

    neigh_num_err_retries =
        registry.get_value<decltype(neigh_num_err_retries)>("net.neighbor.errors_before_reset");

    neigh_uc_arp_quata =
        registry.get_value<decltype(neigh_uc_arp_quata)>("net.neighbor.uc_arp_retries");

    neigh_wait_till_send_arp_msec =
        registry.get_value<decltype(neigh_wait_till_send_arp_msec)>("net.neighbor.uc_arp_delay_msec");

    timer_netlink_update_msec =
        registry.get_value<decltype(timer_netlink_update_msec)>("net.neighbor.update_interval_msec");

    deferred_close =
        registry.get_value<bool>("net.deferred_close");

    tcp_abort_on_close =
        registry.get_value<bool>("net.tcp.linger_0");

    rx_poll_on_tx_tcp =
        registry.get_value<bool>("xlio.poll.rx_poll_on_tx");

    rx_cq_wait_ctrl =
        registry.get_value<bool>("xlio.poll.rx_cq_wait_ctrl");

    trigger_dummy_send_getsockname =
        registry.get_value<bool>("xlio.syscall.getsockname_dummy_send");

    tcp_send_buffer_size =
        registry.get_value<decltype(tcp_send_buffer_size)>("net.tcp.wmem");

    skip_poll_in_rx =
        static_cast<skip_poll_in_rx_t>(registry.get_value<int>("xlio.poll.skip_cq_on_rx"));

    const bool core_mutex_over_spinlock =
        registry.get_value<bool>("core.mutex_over_spinlock");
    multilock =
        core_mutex_over_spinlock ? multilock_t::MULTILOCK_MUTEX : multilock_t::MULTILOCK_SPIN;

    const int64_t core_exception_mode = registry.get_value<int64_t>("core.exception.mode");

    // TODO (old - not config): this should be replaced by calling "exception_handling.init()" that
    // will be called from init()
    exception_handling = xlio_exception_handling(
        core_exception_mode); // xlio_exception_handling is responsible for its invariant
}

void mce_sys_var::pre_profile_adjust_settings()
{
    /* Configure enable_socketxtreme as first because
     * this mode has some special predefined parameter limitations
     */
    if (enable_socketxtreme) {
        /* Set following parameters as default for SocketXtreme mode */
        gro_streams_max = 0;
        progress_engine_interval_msec = MCE_CQ_DRAIN_INTERVAL_DISABLED;
    }

    if (enable_striding_rq) {
        rx_num_wr = MCE_DEFAULT_STRQ_NUM_WRE;
        rx_num_wr_to_post_recv = MCE_DEFAULT_STRQ_NUM_WRE_TO_POST_RECV;
    }

    /*
    * Check for specific application configuration first. We can make decisions
    * based on number of workers or application type further.
    */
    #if defined(DEFINED_NGINX)
        if (app.workers_num > 0) {
            app.type = APP_NGINX;
            // In order to ease the usage of Nginx cases, we apply Nginx profile when
            // user will choose to use Nginx workers environment variable.
            if (mce_spec == MCE_SPEC_NONE) {
                mce_spec = MCE_SPEC_NGINX;
            }
        }
    #endif // DEFINED_NGINX
}

void mce_sys_var::apply_profile_settings()
{   
    switch (mce_spec) {
    case MCE_SPEC_SOCKPERF_ULTRA_LATENCY:
        memory_limit = 128LU * 1024 * 1024;
        tx_num_wr = 256;
        tx_num_wr_to_signal = 4;
        tx_prefetch_bytes = MCE_DEFAULT_TX_PREFETCH_BYTES;
        tx_bufs_batch_udp = 1;
        tx_bufs_batch_tcp = 1;
        rx_bufs_batch = 4;
        rx_poll_num = -1;
        enable_tso = option_3::OFF;
        rx_udp_poll_os_ratio = 0;
        rx_prefetch_bytes = MCE_DEFAULT_RX_PREFETCH_BYTES;
        rx_prefetch_bytes_before_poll = 256;
        select_poll_num = -1;
        select_poll_os_ratio = 0;
        select_skip_os_fd_check = 0;
        avoid_sys_calls_on_tcp_fd = true;
        gro_streams_max = 0;
        progress_engine_interval_msec = 0;
        cq_keep_qp_full = false;
        tcp_nodelay = true;
        ring_dev_mem_tx = 16384;
        strcpy(internal_thread_affinity_str, "0");

        if (enable_striding_rq) {
            rx_num_wr = 4U;
        } else {
            rx_num_wr = 256;
            rx_num_wr_to_post_recv = 4;
        }
        break;

    case MCE_SPEC_SOCKPERF_LATENCY:
        tx_num_wr = 256;
        tx_num_wr_to_signal = 4;
        tx_bufs_batch_udp = 1;
        tx_bufs_batch_tcp = 1;
        rx_bufs_batch = 4;

        rx_poll_num = -1;
        enable_tso = option_3::OFF;
        rx_prefetch_bytes_before_poll = 256;
        select_poll_num = -1;
        avoid_sys_calls_on_tcp_fd = true;
        gro_streams_max = 0;
        cq_keep_qp_full = false;
        strcpy(internal_thread_affinity_str, "0");
        progress_engine_interval_msec = 100;
        select_poll_os_ratio = 100;
        select_poll_os_force = 1;
        tcp_nodelay = true;
        ring_dev_mem_tx = 16384;

        if (enable_striding_rq) {
            rx_num_wr = 4U;
        } else {
            rx_num_wr = 256;
            rx_num_wr_to_post_recv = 4;
        }

        break;

#ifdef DEFINED_NGINX
    case MCE_SPEC_NGINX:
        // Fallthrough
    case MCE_SPEC_NGINX_DPU:
        ring_allocation_logic_tx = RING_LOGIC_PER_INTERFACE;
        ring_allocation_logic_rx = RING_LOGIC_PER_INTERFACE;
        progress_engine_interval_msec = 0; // Disable internal thread CQ draining logic.
        cq_poll_batch_max = 128; // Maximum CQEs to poll in one batch.
        enable_tso = option_3::ON; // Enable TCP Segmentation Offload(=TSO).
        timer_resolution_msec = 32; // Reduce CPU utilization of internal thread.
        tcp_timer_resolution_msec = 256; // Reduce CPU utilization of internal thread.
        tcp_send_buffer_size = 2 * 1024 * 1024; // LWIP TCP send buffer size.
        tcp_push_flag = false; // When false, we don't set PSH flag in outgoing TCP segments.
        select_poll_num = 0; // Poll CQ only once before going to sleep.
        select_skip_os_fd_check = 1000; // Poll OS every X epoll_waits if we do not sleep.
        tcp_3t_rules = true; // Use 3 tuple instead rules of 5 tuple rules.
        app.distribute_cq_interrupts = true;
        rx_cq_wait_ctrl = true;

        if (mce_spec == MCE_SPEC_NGINX) {
            memory_limit = (app.workers_num > 16 ? 3072LU : 4096LU) * 1024 * 1024;
            memory_limit *= std::max(app.workers_num, 1);
            rx_bufs_batch = 8; // RX buffers batch size.

            // Do polling on RX queue on TX operations, helpful to maintain TCP stack management.
            rx_poll_on_tx_tcp = true;
        } else if (mce_spec == MCE_SPEC_NGINX_DPU) {
            memory_limit = (app.workers_num == 16 ? 512LU : 1024LU) * 1024 * 1024;
            memory_limit *= std::max(app.workers_num, 1);
            buffer_batching_mode = BUFFER_BATCHING_NONE;
        }
        break;
#endif // DEFINED_NGINX
    case MCE_SPEC_NVME_BF3:
        strq_stride_num_per_rwqe = 8192U;
        enable_lro = option_3::ON;
        handle_fork = false;
        strcpy(internal_thread_affinity_str, "0x01");
        gro_streams_max = 0;
        tx_num_wr_to_signal = 128U;
        tx_num_wr = 1024U;
        rx_num_wr = 32U;
        enable_tso = option_3::ON;
        rx_prefetch_bytes_before_poll = 256U;
        ring_dev_mem_tx = 1024;
        cq_keep_qp_full = false;
        cq_aim_interval_msec = MCE_CQ_ADAPTIVE_MODERATION_DISABLED;
        progress_engine_interval_msec = 0U;
        tcp_abort_on_close = true;
        memory_limit = 256U * 1024U * 1024U;
        memory_limit_user = 2U * 1024U * 1024U * 1024U;

        tx_bufs_batch_udp = 1;
        tx_bufs_batch_tcp = 1;
        rx_bufs_batch = 4;
        tcp_nodelay = true;
    case MCE_SPEC_NONE:
    default:
        break;
    }
}

void mce_sys_var::post_profile_adjust_settings(const config_registry &registry)
{
    if (HYPER_MSHV == hypervisor && !service_enable) {
        service_enable = true;
        vlog_printf(VLOG_DEBUG, "%s parameter is forced to 'true' for MSHV hypervisor\n",
                    SYS_VAR_SERVICE_ENABLE);
    }

    if (log_level >= VLOG_DEBUG) {
        log_details = 2;
    }

    stats_fd_num_monitor = std::min(stats_fd_num_max, MAX_STATS_FD_NUM);
    if (stats_fd_num_max > MAX_STATS_FD_NUM) {
        vlog_printf(VLOG_INFO, "xlio_stats monitoring will be limited by %d sockets\n",
                    MAX_STATS_FD_NUM);
    }

    int64_t strides_num = strq_stride_num_per_rwqe;

    // TODO - have power of 2 constraint in config descriptor
    bool is_strides_num_ok = true;
    if (!is_ilog2(static_cast<unsigned int>(strides_num))) {
        strides_num = align32pow2(static_cast<uint32_t>(strides_num));
        is_strides_num_ok = false;
    }

    if (!is_strides_num_ok) {
        vlog_printf(VLOG_INFO,
                    " Invalid xlio.rq.striding.strides: Must be power of 2. Using: %d.\n",
                    strides_num);
    }

    strq_stride_num_per_rwqe = static_cast<uint32_t>(strides_num);

    // TODO - have power of 2 constraint in config descriptor
    bool is_stride_size_ok = true;
    int64_t stride_size = strq_stride_size_bytes;
    if (!is_ilog2(static_cast<unsigned int>(stride_size))) {
        stride_size = align32pow2(static_cast<uint32_t>(stride_size));
        is_stride_size_ok = false;
    }

    if (!is_stride_size_ok) {
        vlog_printf(VLOG_INFO,
                    " Invalid xlio.rq.striding.stride_size: Must be power of 2. Using: %d.\n",
                    stride_size);
    }

    strq_stride_size_bytes = static_cast<uint32_t>(stride_size);

    if (tx_num_wr <= (tx_num_wr_to_signal * 2)) {
        tx_num_wr = tx_num_wr_to_signal * 2;
    }

    // TODO - have a joint constraint
    if (enable_striding_rq && (strq_stride_num_per_rwqe * rx_num_wr > MAX_MLX5_CQ_SIZE_ITEMS)) {
        rx_num_wr = MAX_MLX5_CQ_SIZE_ITEMS / strq_stride_num_per_rwqe;

        vlog_printf(VLOG_WARNING,
                    "Requested " SYS_VAR_STRQ_NUM_STRIDES " * " SYS_VAR_RX_NUM_WRE
                    " > Maximum CQE per CQ (%d)."
                    " Decreasing " SYS_VAR_RX_NUM_WRE " to %" PRIu32 "\n",
                    MAX_MLX5_CQ_SIZE_ITEMS, rx_num_wr);
    }

    if (rx_num_wr <= (rx_num_wr_to_post_recv * 2)) {
        rx_num_wr = rx_num_wr_to_post_recv * 2;
    }

    if (rx_poll_num == 0) {
        rx_poll_num = 1; // Force at least one good polling loop
    }

    // Update the rx cq polling rate for draining logic
    tscval_t tsc_per_second = get_tsc_rate_per_second();
    rx_delta_tsc_between_cq_polls = tsc_per_second * rx_cq_drain_rate_nsec / NSEC_PER_SEC;

    // mc_force_flowtag must be adjusted based on disable_flow_tag
    if (disable_flow_tag) {
        vlog_printf(VLOG_WARNING, "%s and %s can't be set together. Disabling %s\n",
                    SYS_VAR_DISABLE_FLOW_TAG, SYS_VAR_MC_FORCE_FLOWTAG, SYS_VAR_MC_FORCE_FLOWTAG);
        mc_force_flowtag = 0;
    }

    if (select_poll_os_force) {
        select_poll_os_ratio = 1;
        select_skip_os_fd_check = 1;
    }

#ifdef DEFINED_IBV_CQ_ATTR_MODERATE
    if (rx_poll_num < 0 || select_poll_num < 0) {
        cq_moderation_enable = false;
    }

    uint32_t max_cq_moderation_count =
        (!enable_striding_rq ? rx_num_wr : (strq_stride_num_per_rwqe * rx_num_wr)) / 2U;
    if (cq_moderation_count > max_cq_moderation_count) {
        cq_moderation_count = max_cq_moderation_count;
    }

    uint32_t max_cq_aim_max_count =
        (!enable_striding_rq ? rx_num_wr : (strq_stride_num_per_rwqe * rx_num_wr)) / 2U;
    if (cq_aim_max_count > max_cq_aim_max_count) {
        cq_aim_max_count = max_cq_aim_max_count;
    }

    if (!cq_moderation_enable) {
        cq_aim_interval_msec = MCE_CQ_ADAPTIVE_MODERATION_DISABLED;
    }

#else
    if (cq_moderation_enable == true) {
        vlog_printf(VLOG_WARNING,
                    "'xlio.cq.interrupt_moderation.enable' is not supported on this environment\n");
    }
    if (max_cq_moderation_count != 0) {
        vlog_printf(
            VLOG_WARNING,
            "'xlio.cq.interrupt_moderation.packet_count' is not supported on this environment\n");
    }
    if (cq_moderation_period_usec != 0) {
        vlog_printf(
            VLOG_WARNING,
            "'xlio.cq.interrupt_moderation.period_usec' is not supported on this environment\n");
    }
    if (cq_aim_max_count != 0) {
        vlog_printf(
            VLOG_WARNING,
            "'xlio.cq.interrupt_moderation.adaptive_count' is not supported on this environment\n");
    }
    if (cq_aim_max_period_usec != 0) {
        vlog_printf(VLOG_WARNING,
                    "'xlio.cq.interrupt_moderation.adaptive_period_usec' is not supported on this "
                    "environment\n");
    }
    if (cq_aim_interval_msec != 0) {
        vlog_printf(VLOG_WARNING,
                    "'xlio.cq.interrupt_moderation.adaptive_change_frequency_ms' is not supported "
                    "on this environment\n");
    }
    if (cq_aim_interrupts_rate_per_sec != 0) {
        vlog_printf(VLOG_WARNING,
                    "'xlio.cq.interrupt_moderation.interrupt_per_sec' is not supported on this "
                    "environment\n");
    }
#endif /* DEFINED_IBV_CQ_ATTR_MODERATE */

    if (enable_socketxtreme && (progress_engine_interval_msec != MCE_CQ_DRAIN_INTERVAL_DISABLED)) {
        progress_engine_interval_msec = MCE_CQ_DRAIN_INTERVAL_DISABLED;
        vlog_printf(VLOG_DEBUG,
                    "xlio.cq.periodic_drain_ms parameter is forced to %d in case "
                    "xlio.api.socketextreme is enabled\n",
                    progress_engine_interval_msec);
    }

    qp_compensation_level = rx_num_wr / 2U;

    const int64_t xlio_cq_buf_rx_spare = registry.get_value<int64_t>("xlio.cq.buf.rx_spare");
    qp_compensation_level = xlio_cq_buf_rx_spare;
    if (qp_compensation_level < rx_num_wr_to_post_recv) {
        qp_compensation_level = rx_num_wr_to_post_recv;
    }

    if (user_huge_page_size == 0) {
        user_huge_page_size = g_hugepage_mgr.get_default_hugepage();
    }

    const int64_t core_handlers_behavior =
        registry.get_value<int64_t>("core.handlers.behavior");
    tcp_ctl_thread = static_cast<option_tcp_ctl_thread::mode_t>(core_handlers_behavior);
    if (tcp_ctl_thread == option_tcp_ctl_thread::CTL_THREAD_DELEGATE_TCP_TIMERS) {
        if (progress_engine_interval_msec != MCE_CQ_DRAIN_INTERVAL_DISABLED) {
            vlog_printf(VLOG_DEBUG,
                        "xlio.cq.periodic_drain_ms parameter is forced to %d in case "
                        "core.handlers.behavior=%s is enabled\n",
                        MCE_CQ_DRAIN_INTERVAL_DISABLED,
                        option_tcp_ctl_thread::to_str(tcp_ctl_thread));

            progress_engine_interval_msec = MCE_CQ_DRAIN_INTERVAL_DISABLED;
        }
        if (ring_allocation_logic_tx != RING_LOGIC_PER_THREAD ||
            ring_allocation_logic_rx != RING_LOGIC_PER_THREAD) {
            vlog_printf(VLOG_DEBUG,
                        "xlio.ring.tx.alloc_logic,xlio.ring.rx.alloc_logic parameter is forced to "
                        "%s in case core.handlers.behavior=%s is enabled\n",
                        ring_logic_str(RING_LOGIC_PER_THREAD),
                        option_tcp_ctl_thread::to_str(tcp_ctl_thread));

            ring_allocation_logic_tx = ring_allocation_logic_rx = RING_LOGIC_PER_THREAD;
        }
    }

    // TODO - add dependencies and joint constraints
    if (tcp_timer_resolution_msec < timer_resolution_msec) {
        vlog_printf(
            VLOG_WARNING,
            "TCP timer resolution [net.tcp.timer_msec=%d] cannot be smaller than timer resolution "
            "[core.handlers.timer_msec=%d]. Setting TCP timer resolution to %d msec.\n",
            tcp_timer_resolution_msec, timer_resolution_msec, timer_resolution_msec);
        tcp_timer_resolution_msec = timer_resolution_msec;
    }

    // handle internal thread affinity - default is CPU-0
    if (env_to_cpuset(internal_thread_affinity_str, &internal_thread_affinity)) {
        vlog_printf(VLOG_WARNING,
                    "Failed to set internal thread affinity: %s...  deferring to cpu-0.\n",
                    internal_thread_affinity_str);
    }

    if (buffer_batching_mode == BUFFER_BATCHING_NONE) {
        tx_bufs_batch_tcp = 1;
        tx_bufs_batch_udp = 1;
        rx_bufs_batch = 1;
    }

    if (hugepage_size & (hugepage_size - 1)) {
        vlog_printf(VLOG_WARNING, "%s must be a power of 2. Fallback to default value (%s)\n",
                    SYS_VAR_HUGEPAGE_SIZE, option_size::to_str(MCE_DEFAULT_HUGEPAGE_SIZE));
        hugepage_size = MCE_DEFAULT_HUGEPAGE_SIZE;
    }

    if ((enable_tso != option_3::OFF) && (ring_migration_ratio_tx != -1)) {
        ring_migration_ratio_tx = -1;
        vlog_printf(VLOG_DEBUG, "%s parameter is forced to %d in case %s is enabled\n",
                    SYS_VAR_RING_MIGRATION_RATIO_TX, -1, SYS_VAR_TSO);
    }

}

void mce_sys_var::apply_config_from_registry()
{
    config_registry registry;
    apply_settings(registry);
    
    read_hv();
    pre_profile_adjust_settings();
    apply_profile_settings();

    post_profile_adjust_settings(registry);
}

void mce_sys_var::get_app_name()
{
    int c = 0, len = 0;
    FILE *fp = nullptr;
    int app_name_size = MAX_CMD_LINE;

    fp = fopen("/proc/self/cmdline", "r");
    if (!fp) {
        vlog_printf(VLOG_ERROR, "error while fopen\n");
        print_xlio_load_failure_msg();
        exit(1);
    }

    app_name = (char *)malloc(app_name_size);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!app_name) {
        vlog_printf(VLOG_ERROR, "error while malloc\n");
        print_xlio_load_failure_msg();
        exit(1);
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    while ((c = fgetc(fp)) != EOF) {
        app_name[len++] = (c == 0 ? ' ' : c);
        if (len >= app_name_size) {
            app_name_size = app_name_size * 2;
            app_name = (char *)realloc(app_name, app_name_size);
            BULLSEYE_EXCLUDE_BLOCK_START
            if (!app_name) {
                vlog_printf(VLOG_ERROR, "error while malloc\n");
                print_xlio_load_failure_msg();
                exit(1);
            }
            BULLSEYE_EXCLUDE_BLOCK_END
        }
    }

    app_name[len - 1] = '\0';
    fclose(fp);
}

void mce_sys_var::get_params()
{
    get_app_name();

    // legacy method - config registry is not relevant for this case
    if (std::getenv("XLIO_USE_DEPRECATED_CONFIG")) {
        vlog_printf(VLOG_WARNING, "Using deprecated environment variables.\n");
        vlog_printf(
            VLOG_WARNING,
            "---------------------------------------------------------------------------\n");
        legacy_get_env_params();
    } else {
        apply_config_from_registry();
    }
}

void set_env_params()
{
    // Need to call setenv() only after getenv() is done, because /bin/sh has
    // a custom setenv() which overrides original environment.

    /*
     * MLX5_DEVICE_FATAL_CLEANUP/RDMAV_ALLOW_DISASSOC_DESTROY
     * tells ibv_destroy functions we want to get success errno value
     * in case of calling them when the device was removed.
     * It helps to destroy resources in DEVICE_FATAL state
     */
    setenv("MLX5_DEVICE_FATAL_CLEANUP", "1", 1);
    setenv("RDMAV_ALLOW_DISASSOC_DESTROY", "1", 1);

    const char *ibv_alloc_type = "PREFER_CONTIG";

    switch (safe_mce_sys().mem_alloc_type) {
    case option_alloc_type::ANON:
        ibv_alloc_type = "ANON";
        break;
    case option_alloc_type::HUGE:
        setenv("RDMAV_HUGEPAGES_SAFE", "1", 0);
        // Don't request hugepages from rdma-core in case of giant default hugepage size,
        // otherwise, we will waste a lot of memory. Consider 32MB hugepages as acceptable.
        if (g_hugepage_mgr.get_default_hugepage() <= 32U * 1024U * 1024U) {
            ibv_alloc_type = "ALL";
        }
        break;
    default:
        // Use default allocation type.
        break;
    }

    // Don't override user defined values.
    if (!getenv("MLX_QP_ALLOC_TYPE")) {
        setenv("MLX_QP_ALLOC_TYPE", ibv_alloc_type, 0);
    }
    if (!getenv("MLX_CQ_ALLOC_TYPE")) {
        setenv("MLX_CQ_ALLOC_TYPE", ibv_alloc_type, 0);
    }
}
