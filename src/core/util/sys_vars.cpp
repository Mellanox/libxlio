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

static const char *names_none[] = {"none", NULL};
static const char *spec_names_ulatency[] = {"ultra-latency", NULL};
static const char *spec_names_latency[] = {"latency", NULL};
static const char *spec_names_multi_ring[] = {"multi_ring_latency", NULL};
static const char *spec_names_nginx[] = {"nginx", NULL};
static const char *spec_names_nginx_dpu[] = {"nginx_dpu", NULL};
static const char *spec_names_nvme_bf2[] = {"nvme_bf2", NULL};

// must be by order because "to_str" relies on that!
static const xlio_spec_names specs[] = {
    {MCE_SPEC_NONE, "NONE", (const char **)names_none},
    {MCE_SPEC_SOCKPERF_ULTRA_LATENCY, "Ultra Latency", (const char **)spec_names_ulatency},
    {MCE_SPEC_SOCKPERF_LATENCY, "Latency", (const char **)spec_names_latency},
    {MCE_SPEC_LL_MULTI_RING, "Multi Ring Latency Profile", (const char **)spec_names_multi_ring},
    {MCE_SPEC_NGINX, "Nginx Profile", (const char **)spec_names_nginx},
    {MCE_SPEC_NGINX_DPU, "Nginx Profile for DPU", (const char **)spec_names_nginx_dpu},
    {MCE_SPEC_NVME_BF2, "NVMEoTCP BF2 Profile", (const char **)spec_names_nvme_bf2}};

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

const char *to_str(size_t size)
{
    static char str[64];
    static const char *suffixes[] = {"", " KB", " MB", " GB", nullptr};
    int sfx_idx = 0;

    while ((size / 1024U >= 10 || (size > 0 && size % 1024U == 0)) && suffixes[sfx_idx + 1]) {
        ++sfx_idx;
        size /= 1024U;
    }
    snprintf(str, sizeof(str), "%zu%s", size, suffixes[sfx_idx]);

    return str;
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

    return NULL;
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
    const char *to_str(mode_t option) { return option_x::to_str(option, options); }

#define AUTO_ON_OFF_IMPL                                                                           \
    {AUTO, "Auto", {"auto", NULL, NULL}}, {ON, "Enabled", {"on", "enabled", NULL}},                \
    {                                                                                              \
        OFF, "Disabled", { "off", "disabled", NULL }                                               \
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

namespace option_strq {
static option_t<mode_t> options[] = {AUTO_ON_OFF_IMPL,
                                     {REGULAR_RQ, "Regular RQ", {"regular_rq", NULL, NULL}}};
OPTION_FROM_TO_STR_IMPL
} // namespace option_strq

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
            subtoken = strtok_r(NULL, dash, &dash_saveptr);
            if (subtoken) {
                errno = 0;
                range_end = strtol(subtoken, &endptr, 10);
                if ((!range_end && *endptr) || errno) {
                    return -1;
                }
                subtoken = NULL;
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

        token = strtok_r(NULL, comma, &comma_saveptr);
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

        digit = strtol(hexc, NULL, 16);

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
    char *d_pos = NULL;

    if (NULL == env_ptr || NULL == mce_sys_name || mce_sys_max_size < 2) {
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
        return NULL;
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
    const char *hyper_vendor_id = NULL;

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

void mce_sys_var::get_env_params()
{
    int c = 0, len = 0;
    char *env_ptr;
    FILE *fp = NULL;
    int app_name_size = MAX_CMD_LINE;
    // Large buffer size to avoid need for realloc

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

    memset(xlio_time_measure_filename, 0, sizeof(xlio_time_measure_filename));
    strcpy(xlio_time_measure_filename, MCE_DEFAULT_TIME_MEASURE_DUMP_FILE);
    memset(log_filename, 0, sizeof(log_filename));
    memset(stats_filename, 0, sizeof(stats_filename));
    memset(stats_shmem_dirname, 0, sizeof(stats_shmem_dirname));
    memset(service_notify_dir, 0, sizeof(service_notify_dir));
    strcpy(stats_filename, MCE_DEFAULT_STATS_FILE);
    strcpy(service_notify_dir, MCE_DEFAULT_SERVICE_FOLDER);
    strcpy(stats_shmem_dirname, MCE_DEFAULT_STATS_SHMEM_DIR);
    strcpy(conf_filename, MCE_DEFAULT_CONF_FILE);
    strcpy(app_id, MCE_DEFAULT_APP_ID);
    strcpy(internal_thread_cpuset, MCE_DEFAULT_INTERNAL_THREAD_CPUSET);
    strcpy(internal_thread_affinity_str, MCE_DEFAULT_INTERNAL_THREAD_AFFINITY_STR);

    service_enable = MCE_DEFAULT_SERVICE_ENABLE;

    log_level = VLOG_DEFAULT;
    log_details = MCE_DEFAULT_LOG_DETAILS;
    log_colors = MCE_DEFAULT_LOG_COLORS;
    handle_sigintr = MCE_DEFAULT_HANDLE_SIGINTR;
    handle_segfault = MCE_DEFAULT_HANDLE_SIGFAULT;
    stats_fd_num_max = MCE_DEFAULT_STATS_FD_NUM;

    ring_allocation_logic_tx = MCE_DEFAULT_RING_ALLOCATION_LOGIC_TX;
    ring_allocation_logic_rx = MCE_DEFAULT_RING_ALLOCATION_LOGIC_RX;
    ring_migration_ratio_tx = MCE_DEFAULT_RING_MIGRATION_RATIO_TX;
    ring_migration_ratio_rx = MCE_DEFAULT_RING_MIGRATION_RATIO_RX;
    ring_limit_per_interface = MCE_DEFAULT_RING_LIMIT_PER_INTERFACE;
    ring_dev_mem_tx = MCE_DEFAULT_RING_DEV_MEM_TX;

    tcp_max_syn_rate = MCE_DEFAULT_TCP_MAX_SYN_RATE;

    zc_num_bufs = MCE_DEFAULT_ZC_NUM_BUFS;
    zc_cache_threshold = MCE_DEFAULT_ZC_CACHE_THRESHOLD;
    tx_num_segs_tcp = MCE_DEFAULT_TX_NUM_SEGS_TCP;
    tx_num_bufs = MCE_DEFAULT_TX_NUM_BUFS;
    tx_buf_size = MCE_DEFAULT_TX_BUF_SIZE;
    zc_tx_size = MCE_DEFAULT_ZC_TX_SIZE;
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
    rx_num_bufs = MCE_DEFAULT_RX_NUM_BUFS;
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
    strq_strides_num_bufs = MCE_DEFAULT_STRQ_STRIDES_NUM_BUFS;
    strq_strides_compensation_level = MCE_DEFAULT_STRQ_STRIDES_COMPENSATION_LEVEL;

    gro_streams_max = MCE_DEFAULT_GRO_STREAMS_MAX;
    disable_flow_tag = MCE_DEFAULT_DISABLE_FLOW_TAG;

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
    qp_compensation_level = MCE_DEFAULT_QP_COMPENSATION_LEVEL;
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
    thread_mode = MCE_DEFAULT_THREAD_MODE;
    buffer_batching_mode = MCE_DEFAULT_BUFFER_BATCHING_MODE;
    mem_alloc_type = MCE_DEFAULT_MEM_ALLOC_TYPE;
    hugepage_log2 = MCE_DEFAULT_HUGEPAGE_LOG2;
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
    handle_bf = MCE_DEFAULT_BF_FLAG;
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
#ifdef XLIO_TIME_MEASURE
    xlio_time_measure_num_samples = MCE_DEFAULT_TIME_MEASURE_NUM_SAMPLES;
#endif

    read_hv();

    /* Configure enable_socketxtreme as first because
     * this mode has some special predefined parameter limitations
     */
    if ((env_ptr = getenv(SYS_VAR_SOCKETXTREME)) != NULL) {
        enable_socketxtreme = atoi(env_ptr) ? true : false;
    }
    if (enable_socketxtreme) {
        /* Set following parameters as default for SocketXtreme mode */
        gro_streams_max = 0;
        progress_engine_interval_msec = MCE_CQ_DRAIN_INTERVAL_DISABLED;
    }

#if defined(DEFINED_DPCP)
    if ((env_ptr = getenv(SYS_VAR_STRQ)) != NULL) {
        enable_strq_env = option_strq::from_str(env_ptr, MCE_DEFAULT_STRQ);
    }
#endif

    enable_striding_rq =
        (enable_strq_env == option_strq::ON || enable_strq_env == option_strq::AUTO);
    enable_dpcp_rq = (enable_striding_rq || (enable_strq_env == option_strq::REGULAR_RQ));

    if (enable_striding_rq) {
        rx_num_bufs = MCE_DEFAULT_STRQ_NUM_BUFS;
        rx_num_wr = MCE_DEFAULT_STRQ_NUM_WRE;
        rx_num_wr_to_post_recv = MCE_DEFAULT_STRQ_NUM_WRE_TO_POST_RECV;
        qp_compensation_level = MCE_DEFAULT_STRQ_COMPENSATION_LEVEL;
    }

    if ((env_ptr = getenv(SYS_VAR_SPEC)) != NULL) {
        mce_spec = (uint32_t)xlio_spec::from_str(env_ptr, MCE_SPEC_NONE);
    }

#if defined(DEFINED_NGINX)
    if ((env_ptr = getenv(SYS_VAR_NGINX_WORKERS_NUM)) != NULL) {
        // In order to ease the usage of Nginx cases, we apply Nginx profile when
        // user will choose to use Nginx workers environment variable.
        if (atoi(env_ptr) > 0 && mce_spec == MCE_SPEC_NONE) {
            mce_spec = MCE_SPEC_NGINX;
        }
    }
#endif // DEFINED_NGINX

    switch (mce_spec) {
    case MCE_SPEC_SOCKPERF_ULTRA_LATENCY:
        tx_num_segs_tcp = 512; // MCE_DEFAULT_TX_NUM_SEGS_TCP (1000000)
        tx_num_bufs = 512; // MCE_DEFAULT_TX_NUM_BUFS (200000)
        tx_num_wr = 256; // MCE_DEFAULT_TX_NUM_WRE (3000)
        tx_num_wr_to_signal = 4; // MCE_DEFAULT_TX_NUM_WRE_TO_SIGNAL (64)
        tx_prefetch_bytes = MCE_DEFAULT_TX_PREFETCH_BYTES; //(256)
        tx_bufs_batch_udp = 1; // MCE_DEFAULT_TX_BUFS_BATCH_UDP (8)
        tx_bufs_batch_tcp = 1; // MCE_DEFAULT_TX_BUFS_BATCH_TCP;
        rx_bufs_batch = 4; // MCE_DEFAULT_RX_BUFS_BATCH (64)
        rx_poll_num = -1; // MCE_DEFAULT_RX_NUM_POLLS
        enable_tso = option_3::OFF; // MCE_DEFAULT_TSO (option_3::AUTO)
        rx_udp_poll_os_ratio = 0; // MCE_DEFAULT_RX_UDP_POLL_OS_RATIO
        rx_prefetch_bytes = MCE_DEFAULT_RX_PREFETCH_BYTES; //(256)
        rx_prefetch_bytes_before_poll = 256; // MCE_DEFAULT_RX_PREFETCH_BYTES_BEFORE_POLL 0
        select_poll_num = -1;
        select_poll_os_ratio = 0;
        select_skip_os_fd_check = 0;
        avoid_sys_calls_on_tcp_fd = true; // MCE_DEFAULT_AVOID_SYS_CALLS_ON_TCP_FD (false)
        gro_streams_max = 0; // MCE_DEFAULT_GRO_STREAMS_MAX (32)
        progress_engine_interval_msec = 0;
        cq_keep_qp_full = false; // MCE_DEFAULT_CQ_KEEP_QP_FULL(true)
        thread_mode = THREAD_MODE_SINGLE;
        tcp_nodelay = true; // MCE_DEFAULT_TCP_NODELAY (false)
        ring_dev_mem_tx = 16384; // MCE_DEFAULT_RING_DEV_MEM_TX (0)
        strcpy(internal_thread_affinity_str, "0"); // MCE_DEFAULT_INTERNAL_THREAD_AFFINITY_STR;

        if (enable_striding_rq) {
            rx_num_bufs = 16; // MCE_DEFAULT_RX_NUM_BUFS (64)
            strq_strides_num_bufs = 131072; // MCE_DEFAULT_STRQ_NUM_BUFS(262144)
            strq_stride_num_per_rwqe = 65536; // MCE_DEFAULT_STRQ_NUM_STRIDES(16384)
            strq_stride_size_bytes = 64; // MCE_DEFAULT_STRQ_STRIDE_SIZE_BYTES(512)
        } else {
            rx_num_bufs = 1024; // MCE_DEFAULT_RX_NUM_BUFS (200000)
            rx_num_wr = 256; // MCE_DEFAULT_RX_NUM_WRE (16000)
            rx_num_wr_to_post_recv = 4; // MCE_DEFAULT_RX_NUM_WRE_TO_POST_RECV (64)
        }
        break;

    case MCE_SPEC_SOCKPERF_LATENCY:
        tx_num_wr = 256; // MCE_DEFAULT_TX_NUM_WRE (3000)
        tx_num_wr_to_signal = 4; // MCE_DEFAULT_TX_NUM_WRE_TO_SIGNAL(64)
        tx_bufs_batch_udp = 1; // MCE_DEFAULT_TX_BUFS_BATCH_UDP (8)
        tx_bufs_batch_tcp = 1; // MCE_DEFAULT_TX_BUFS_BATCH_TCP (16)
        rx_bufs_batch = 4; // MCE_DEFAULT_RX_BUFS_BATCH (64)

        rx_poll_num = -1; // MCE_DEFAULT_RX_NUM_POLLS (100000)
        enable_tso = option_3::OFF; // MCE_DEFAULT_TSO (option_3::AUTO)
        rx_prefetch_bytes_before_poll = 256; // MCE_DEFAULT_RX_PREFETCH_BYTES_BEFORE_POLL (0)
        select_poll_num = -1; // MCE_DEFAULT_SELECT_NUM_POLLS (100000)
        avoid_sys_calls_on_tcp_fd = true; // MCE_DEFAULT_AVOID_SYS_CALLS_ON_TCP_FD (false)
        gro_streams_max = 0; // MCE_DEFAULT_GRO_STREAMS_MAX (32)
        cq_keep_qp_full = false; // MCE_DEFAULT_CQ_KEEP_QP_FULL (true)
        thread_mode = THREAD_MODE_SINGLE; // MCE_DEFAULT_THREAD_MODE (THREAD_MODE_MULTI)
        strcpy(internal_thread_affinity_str, "0"); // MCE_DEFAULT_INTERNAL_THREAD_AFFINITY_STR
                                                   // ("-1")
        progress_engine_interval_msec = 100; // MCE_DEFAULT_PROGRESS_ENGINE_INTERVAL_MSEC (10)
        select_poll_os_ratio = 100; // MCE_DEFAULT_SELECT_POLL_OS_RATIO (10)
        select_poll_os_force = 1; // MCE_DEFAULT_SELECT_POLL_OS_FORCE (0)
        tcp_nodelay = true; // MCE_DEFAULT_TCP_NODELAY (falst)
        ring_dev_mem_tx = 16384; // MCE_DEFAULT_RING_DEV_MEM_TX (0)

        if (enable_striding_rq) {
            strq_strides_num_bufs = 131072; // MCE_DEFAULT_STRQ_NUM_BUFS(262144)
            strq_stride_num_per_rwqe = 32768; // MCE_DEFAULT_STRQ_NUM_STRIDES(16384)
            strq_stride_size_bytes = 64; // MCE_DEFAULT_STRQ_STRIDE_SIZE_BYTES(512)
        } else {
            rx_num_wr = 256; // MCE_DEFAULT_RX_NUM_WRE (16000)
            rx_num_wr_to_post_recv = 4; // MCE_DEFAULT_RX_NUM_WRE_TO_POST_RECV (64)
        }

        break;
    case MCE_SPEC_LL_MULTI_RING:
        select_poll_num = -1; // MCE_DEFAULT_SELECT_NUM_POLLS (100000)
        rx_poll_num = -1; // MCE_DEFAULT_RX_NUM_POLLS(100000)
        ring_allocation_logic_tx =
            RING_LOGIC_PER_THREAD; // MCE_DEFAULT_RING_ALLOCATION_LOGIC_TX(RING_LOGIC_PER_INTERFACE)
        ring_allocation_logic_rx =
            RING_LOGIC_PER_THREAD; // MCE_DEFAULT_RING_ALLOCATION_LOGIC_RX(RING_LOGIC_PER_INTERFACE)
        select_poll_os_ratio = 0; // MCE_DEFAULT_SELECT_POLL_OS_RATIO(10)
        select_skip_os_fd_check = 0; // MCE_DEFAULT_SELECT_SKIP_OS(4)
        rx_poll_on_tx_tcp = true; // MCE_DEFAULT_RX_POLL_ON_TX_TCP (false)
        trigger_dummy_send_getsockname = true; // MCE_DEFAULT_TRIGGER_DUMMY_SEND_GETSOCKNAME (false)
        break;

#ifdef DEFINED_NGINX
    case MCE_SPEC_NGINX:
        rx_bufs_batch = 8; // MCE_DEFAULT_RX_BUFS_BATCH (64), RX buffers batch size.
        tx_num_bufs =
            1000000; // MCE_DEFAULT_TX_NUM_BUFS (200000), Global TX data buffers allocated.
        tx_num_segs_tcp = 4000000; // MCE_DEFAULT_TX_NUM_SEGS_TCP (1000000), Number of TX TCP
                                   // segments in the pool.
        tx_buf_size = 0; // MCE_DEFAULT_TX_BUF_SIZE (0), Size of single data buffer.
        zc_tx_size = 32768; // MCE_DEFAULT_ZC_TX_SIZE (32768), zero copy segment maximum size.
        progress_engine_interval_msec = 0; // MCE_DEFAULT_PROGRESS_ENGINE_INTERVAL_MSEC (10),
                                           // Disable internal thread CQ draining logic.
        cq_moderation_period_usec =
            1024; // MCE_DEFAULT_CQ_MODERATION_PERIOD_USEC (50), CQ moderation threshold in time.
        cq_moderation_count =
            1024; // MCE_DEFAULT_CQ_MODERATION_COUNT(48), CQ moderation threshold in WCEs.
        cq_aim_interval_msec =
            0; // MCE_DEFAULT_CQ_AIM_INTERVAL_MSEC (250), Disable adaptive CQ moderation.
        cq_poll_batch_max =
            128; // MCE_DEFAULT_CQ_POLL_BATCH (16), Maximum CQEs to poll in one batch.
        thread_mode = THREAD_MODE_SINGLE; // MCE_DEFAULT_THREAD_MODE (THREAD_MODE_MULTI), Single
                                          // threaded mode to reduce locking.
        rx_poll_on_tx_tcp = true; // MCE_DEFAULT_RX_POLL_ON_TX_TCP(false), Do polling on RX queue on
                                  // TX operations, helpful to maintain TCP stack management.
        enable_tso =
            option_3::ON; // MCE_DEFAULT_TSO(option_3::AUTO), Enable TCP Segmentation Offload(=TSO).
        timer_resolution_msec = 256; // MCE_DEFAULT_TIMER_RESOLUTION_MSEC (10), Internal thread
                                     // timer resolution, reduce CPU utilization of internal thread.
        tcp_timer_resolution_msec =
            256; // MCE_DEFAULT_TCP_TIMER_RESOLUTION_MSEC (10), TCP logical timer resolution, reduce
                 // CPU utilization of internal thread.
        tcp_send_buffer_size =
            2 * 1024 * 1024; // MCE_DEFAULT_TCP_SEND_BUFFER_SIZE (1 MB), LWIP TCP send buffer size.
        tcp_push_flag = false; // MCE_DEFAULT_TCP_PUSH_FLAG (true), When false, we don't set PSH
                               // flag in outgoing TCP segments.
        progress_engine_wce_max =
            0; // MCE_DEFAULT_PROGRESS_ENGINE_WCE_MAX (10000), Don't drain WCEs.
        select_poll_num = 0; // MCE_DEFAULT_SELECT_NUM_POLLS (100000),  Don't poll the hardware on
                             // RX (before sleeping in epoll/select, etc).
        tcp_3t_rules =
            true; // MCE_DEFAULT_TCP_3T_RULES(false), Use 3 tuple instead rules of 5 tuple rules.

        if (enable_striding_rq) {
            rx_num_wr = 256; // MCE_DEFAULT_STRQ_NUM_WRE(8)
            rx_num_bufs = 512; // MCE_DEFAULT_RX_NUM_BUFS (64)
            strq_stride_num_per_rwqe = 4096; // MCE_DEFAULT_STRQ_NUM_STRIDES(16384)
        } else {
            rx_num_wr = 32000; // MCE_DEFAULT_RX_NUM_WRE (16000), Amount of WREs in RX queue.
        }

        break;

    case MCE_SPEC_NGINX_DPU:
        // The top part is different from NGINX SPEC
        rx_poll_on_tx_tcp = false; // MCE_DEFAULT_RX_POLL_ON_TX_TCP(false), Do polling on RX queue
                                   // on TX operations, helpful to maintain TCP stack management.

        zc_num_bufs = 87500; // MCE_DEFAULT_ZC_NUM_BUFS (200000), Global ZC data buffers allocated.
        tx_num_bufs = 87500; // MCE_DEFAULT_TX_NUM_BUFS (200000), Global TX data buffers allocated.
        tx_bufs_batch_tcp = 2; // MCE_DEFAULT_TX_BUFS_BATCH_TCP (16)
        tx_segs_batch_tcp = 4; // MCE_DEFAULT_TX_SEGS_BATCH_TCP (64)
        tx_num_segs_tcp =
            200000; // MCE_DEFAULT_TX_NUM_SEGS_TCP (1000000), Number of TX TCP segments in the pool.
        rx_bufs_batch = 8; // MCE_DEFAULT_RX_BUFS_BATCH (64), RX buffers batch size.
        tx_buf_size = 0; // MCE_DEFAULT_TX_BUF_SIZE (0), Size of single data buffer.
        zc_tx_size = 32768; // MCE_DEFAULT_ZC_TX_SIZE (32768), zero copy segment maximum size.
        progress_engine_interval_msec = 0; // MCE_DEFAULT_PROGRESS_ENGINE_INTERVAL_MSEC (10),
                                           // Disable internal thread CQ draining logic.
        cq_moderation_period_usec =
            1024; // MCE_DEFAULT_CQ_MODERATION_PERIOD_USEC (50), CQ moderation threshold in time.
        cq_moderation_count =
            1024; // MCE_DEFAULT_CQ_MODERATION_COUNT(48), CQ moderation threshold in WCEs.
        cq_aim_interval_msec =
            0; // MCE_DEFAULT_CQ_AIM_INTERVAL_MSEC (250), Disable adaptive CQ moderation.
        cq_poll_batch_max =
            128; // MCE_DEFAULT_CQ_POLL_BATCH (16), Maximum CQEs to poll in one batch.
        thread_mode = THREAD_MODE_SINGLE; // MCE_DEFAULT_THREAD_MODE (THREAD_MODE_MULTI), Single
                                          // threaded mode to reduce locking.
        enable_tso =
            option_3::ON; // MCE_DEFAULT_TSO(true), Enable TCP Segmentation Offload(=TSO) mechanism.
        timer_resolution_msec = 32; // MCE_DEFAULT_TIMER_RESOLUTION_MSEC (10), Internal thread timer
                                    // resolution, reduce CPU utilization of internal thread.
        tcp_timer_resolution_msec =
            256; // MCE_DEFAULT_TCP_TIMER_RESOLUTION_MSEC (10), TCP logical timer resolution, reduce
                 // CPU utilization of internal thread.
        tcp_send_buffer_size =
            2 * 1024 * 1024; // MCE_DEFAULT_TCP_SEND_BUFFER_SIZE (1 MB), LWIP TCP send buffer size.
        tcp_push_flag = false; // MCE_DEFAULT_TCP_PUSH_FLAG (true), When false, we don't set PSH
                               // flag in outgoing TCP segments.
        progress_engine_wce_max =
            0; // MCE_DEFAULT_PROGRESS_ENGINE_WCE_MAX (10000), Don't drain WCEs.
        select_poll_num = 0; // MCE_DEFAULT_SELECT_NUM_POLLS (100000),  Don't poll the hardware on
                             // RX (before sleeping in epoll/select, etc).
        tcp_3t_rules =
            true; // MCE_DEFAULT_TCP_3T_RULES(false), Use 3 tuple instead rules of 5 tuple rules.

        if (enable_striding_rq) {
            rx_num_wr = 128; // MCE_DEFAULT_STRQ_NUM_WRE(8)
            rx_num_bufs = 256; // MCE_DEFAULT_RX_NUM_BUFS (64)
            strq_stride_num_per_rwqe = 2048; // MCE_DEFAULT_STRQ_NUM_STRIDES(16384)
        } else {
            rx_num_bufs =
                87500; // MCE_DEFAULT_RX_NUM_BUFS (200000), Global RX data buffers allocated.
            rx_num_wr = 32000; // MCE_DEFAULT_RX_NUM_WRE (16000), Amount of WREs in RX queue.
        }

        break;
#endif // DEFINED_NGINX
    case MCE_SPEC_NVME_BF2:
        ring_allocation_logic_tx = RING_LOGIC_PER_CORE;
        ring_allocation_logic_rx = RING_LOGIC_PER_CORE;
        handle_fork = false;
        cq_aim_interval_msec = 0;
        cq_aim_max_count = 256;
        select_skip_os_fd_check = 1;
        tcp_nodelay = true;

        if (enable_striding_rq) {
            rx_num_bufs = 512;
            qp_compensation_level = 8;
            strq_strides_compensation_level = 32768;
            enable_lro = option_3::ON;
            rx_num_wr = 16;
            rx_num_wr_to_post_recv = 2;

            // Derived from Latency profile but changed.
            strq_stride_num_per_rwqe = 8192;
            strq_strides_num_bufs = 131072;
            strq_stride_size_bytes = 64;
        }

        // Derived from Latency
        tx_bufs_batch_udp = 1;
        tx_bufs_batch_tcp = 1;
        rx_bufs_batch = 4;
        strcpy(internal_thread_affinity_str, "0");
        gro_streams_max = 0;
        rx_poll_num = -1;
        rx_prefetch_bytes_before_poll = 256;
        ring_dev_mem_tx = 16384;
        avoid_sys_calls_on_tcp_fd = true;
        select_poll_num = -1;
        select_poll_os_force = 1;
        select_poll_os_ratio = 1;

        // Derived from Latency but changed.
        thread_mode = THREAD_MODE_PLENTY;
        tx_num_wr = 16;
        tx_num_wr_to_signal = 2;
        enable_tso = option_3::ON;
        cq_keep_qp_full = true;
        progress_engine_interval_msec = 0;

        break;
    case MCE_SPEC_NONE:
    default:
        break;
    }

    if ((env_ptr = getenv(SYS_VAR_LOG_FILENAME)) != NULL) {
        read_env_variable_with_pid(log_filename, sizeof(log_filename), env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_STATS_FILENAME)) != NULL) {
        read_env_variable_with_pid(stats_filename, sizeof(stats_filename), env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_STATS_SHMEM_DIRNAME)) != NULL) {
        read_env_variable_with_pid(stats_shmem_dirname, sizeof(stats_shmem_dirname), env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_CONF_FILENAME)) != NULL) {
        read_env_variable_with_pid(conf_filename, sizeof(conf_filename), env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_SERVICE_DIR)) != NULL) {
        read_env_variable_with_pid(service_notify_dir, sizeof(service_notify_dir), env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_SERVICE_ENABLE)) != NULL) {
        service_enable = atoi(env_ptr) ? true : false;
    }
    if (HYPER_MSHV == hypervisor && !service_enable) {
        service_enable = true;
        vlog_printf(VLOG_DEBUG, "%s parameter is forced to 'true' for MSHV hypervisor\n",
                    SYS_VAR_SERVICE_ENABLE);
    }

    if ((env_ptr = getenv(SYS_VAR_LOG_LEVEL)) != NULL) {
        log_level = log_level::from_str(env_ptr, VLOG_DEFAULT);
    }

    if (log_level >= VLOG_DEBUG) {
        log_details = 2;
    }

    if ((env_ptr = getenv(SYS_VAR_LOG_DETAILS)) != NULL) {
        log_details = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_LOG_COLORS)) != NULL) {
        log_colors = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_APPLICATION_ID)) != NULL) {
        read_env_variable_with_pid(app_id, sizeof(app_id), env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_HANDLE_SIGINTR)) != NULL) {
        handle_sigintr = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_HANDLE_SIGSEGV)) != NULL) {
        handle_segfault = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_STATS_FD_NUM)) != NULL) {
        stats_fd_num_max = (uint32_t)atoi(env_ptr);
        if (stats_fd_num_max > MAX_STATS_FD_NUM) {
            vlog_printf(VLOG_WARNING, " Can only monitor maximum %d sockets in statistics \n",
                        MAX_STATS_FD_NUM);
            stats_fd_num_max = MAX_STATS_FD_NUM;
        }
    }

    read_strq_strides_num();
    read_strq_stride_size_bytes();

    if ((env_ptr = getenv(SYS_VAR_STRQ_STRIDES_NUM_BUFS)) != NULL) {
        strq_strides_num_bufs = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_STRQ_STRIDES_COMPENSATION_LEVEL)) != NULL) {
        strq_strides_compensation_level = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_ZC_NUM_BUFS)) != NULL) {
        zc_num_bufs = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_ZC_CACHE_THRESHOLD)) != NULL) {
        zc_cache_threshold = option_size::from_str(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_TX_NUM_SEGS_TCP)) != NULL) {
        tx_num_segs_tcp = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_TX_NUM_BUFS)) != NULL) {
        tx_num_bufs = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_TX_BUF_SIZE)) != NULL) {
        tx_buf_size = (uint32_t)option_size::from_str(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_ZC_TX_SIZE)) != NULL) {
        zc_tx_size = (uint32_t)option_size::from_str(env_ptr);
        if (zc_tx_size > MCE_MAX_ZC_TX_SIZE) {
            vlog_printf(VLOG_WARNING,
                        "ZC TX size [%u] exceeds the maximum (max=%u), setting to default.\n",
                        zc_tx_size, MCE_MAX_ZC_TX_SIZE);
            zc_tx_size = MCE_DEFAULT_ZC_TX_SIZE;
        }
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_NODELAY_TRESHOLD)) != NULL) {
        tcp_nodelay_treshold = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_TX_NUM_WRE)) != NULL) {
        tx_num_wr = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_TX_NUM_WRE_TO_SIGNAL)) != NULL) {
        tx_num_wr_to_signal =
            std::min<uint32_t>(NUM_TX_WRE_TO_SIGNAL_MAX, std::max(1, atoi(env_ptr)));
    }
    if (tx_num_wr <= (tx_num_wr_to_signal * 2)) {
        tx_num_wr = tx_num_wr_to_signal * 2;
    }

    if ((env_ptr = getenv(SYS_VAR_TX_MAX_INLINE)) != NULL) {
        tx_max_inline = (uint32_t)atoi(env_ptr);
    }
    if (tx_max_inline > MAX_SUPPORTED_IB_INLINE_SIZE) {
        vlog_printf(VLOG_WARNING, "%s  must be smaller or equal to %d [%d]\n",
                    SYS_VAR_TX_MAX_INLINE, MAX_SUPPORTED_IB_INLINE_SIZE, tx_max_inline);
        tx_max_inline = MAX_SUPPORTED_IB_INLINE_SIZE;
    }

    if ((env_ptr = getenv(SYS_VAR_TX_MC_LOOPBACK)) != NULL) {
        tx_mc_loopback_default = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_TX_NONBLOCKED_EAGAINS)) != NULL) {
        tx_nonblocked_eagains = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_TX_PREFETCH_BYTES)) != NULL) {
        tx_prefetch_bytes = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_TX_BUFS_BATCH_TCP)) != NULL) {
        tx_bufs_batch_tcp = (uint32_t)atoi(env_ptr);
        if (tx_bufs_batch_tcp < 1) {
            tx_bufs_batch_tcp = 1;
        }
    }

    if ((env_ptr = getenv(SYS_VAR_TX_SEGS_BATCH_TCP)) != NULL) {
        tx_segs_batch_tcp = (uint32_t)atoi(env_ptr);
        if (tx_segs_batch_tcp < 1) {
            tx_segs_batch_tcp = 1;
        }
    }

    if ((env_ptr = getenv(SYS_VAR_TX_SEGS_RING_BATCH_TCP)) != NULL) {
        tx_segs_ring_batch_tcp = (uint32_t)atoi(env_ptr);
        if (tx_segs_ring_batch_tcp < 1) {
            tx_segs_ring_batch_tcp = 1;
        }
    }

    if ((env_ptr = getenv(SYS_VAR_RING_ALLOCATION_LOGIC_TX)) != NULL) {
        ring_allocation_logic_tx = (ring_logic_t)atoi(env_ptr);
        if (!is_ring_logic_valid(ring_allocation_logic_tx)) {
            vlog_printf(VLOG_WARNING, "%s = %d is not valid, setting logic to default = %d\n",
                        SYS_VAR_RING_ALLOCATION_LOGIC_TX, ring_allocation_logic_tx,
                        MCE_DEFAULT_RING_ALLOCATION_LOGIC_TX);
            ring_allocation_logic_tx = MCE_DEFAULT_RING_ALLOCATION_LOGIC_TX;
        }
    }

    if ((env_ptr = getenv(SYS_VAR_RING_ALLOCATION_LOGIC_RX)) != NULL) {
        ring_allocation_logic_rx = (ring_logic_t)atoi(env_ptr);
        if (!is_ring_logic_valid(ring_allocation_logic_rx)) {
            vlog_printf(VLOG_WARNING, "%s = %d is not valid, setting logic to default = %d\n",
                        SYS_VAR_RING_ALLOCATION_LOGIC_RX, ring_allocation_logic_rx,
                        MCE_DEFAULT_RING_ALLOCATION_LOGIC_RX);
            ring_allocation_logic_rx = MCE_DEFAULT_RING_ALLOCATION_LOGIC_RX;
        }
    }

    if ((env_ptr = getenv(SYS_VAR_RING_MIGRATION_RATIO_TX)) != NULL) {
        ring_migration_ratio_tx = atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_RING_MIGRATION_RATIO_RX)) != NULL) {
        ring_migration_ratio_rx = atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_RING_LIMIT_PER_INTERFACE)) != NULL) {
        ring_limit_per_interface = std::max(0, atoi(env_ptr));
    }

    if ((env_ptr = getenv(SYS_VAR_RING_DEV_MEM_TX)) != NULL) {
        ring_dev_mem_tx = std::max(0, atoi(env_ptr));
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_MAX_SYN_RATE)) != NULL) {
        tcp_max_syn_rate = std::min(TCP_MAX_SYN_RATE_TOP_LIMIT, std::max(0, atoi(env_ptr)));
    }

    if ((env_ptr = getenv(SYS_VAR_RX_NUM_BUFS)) != NULL) {
        rx_num_bufs = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_RX_BUF_SIZE)) != NULL) {
        rx_buf_size = (uint32_t)option_size::from_str(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_RX_NUM_WRE_TO_POST_RECV)) != NULL) {
        rx_num_wr_to_post_recv = std::min(NUM_RX_WRE_TO_POST_RECV_MAX, std::max(1, atoi(env_ptr)));
    }

    if ((env_ptr = getenv(SYS_VAR_RX_NUM_WRE)) != NULL) {
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

    if ((env_ptr = getenv(SYS_VAR_RX_NUM_POLLS)) != NULL) {
        rx_poll_num = atoi(env_ptr);
    }
    if (rx_poll_num < MCE_MIN_RX_NUM_POLLS || rx_poll_num > MCE_MAX_RX_NUM_POLLS) {
        vlog_printf(VLOG_WARNING, " Rx Poll loops should be between %d and %d [%d]\n",
                    MCE_MIN_RX_NUM_POLLS, MCE_MAX_RX_NUM_POLLS, rx_poll_num);
        rx_poll_num = MCE_DEFAULT_RX_NUM_POLLS;
    }
    if ((env_ptr = getenv(SYS_VAR_RX_NUM_POLLS_INIT)) != NULL) {
        rx_poll_num_init = atoi(env_ptr);
    }
    if (rx_poll_num_init < MCE_MIN_RX_NUM_POLLS || rx_poll_num_init > MCE_MAX_RX_NUM_POLLS) {
        vlog_printf(VLOG_WARNING, " Rx Poll loops should be between %d and %d [%d]\n",
                    MCE_MIN_RX_NUM_POLLS, MCE_MAX_RX_NUM_POLLS, rx_poll_num_init);
        rx_poll_num_init = MCE_DEFAULT_RX_NUM_POLLS_INIT;
    }
    if (rx_poll_num == 0) {
        rx_poll_num = 1; // Force at least one good polling loop
    }

    if ((env_ptr = getenv(SYS_VAR_RX_UDP_POLL_OS_RATIO)) != NULL) {
        rx_udp_poll_os_ratio = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_HW_TS_CONVERSION_MODE)) != NULL) {
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

    // The following 2 params were replaced by SYS_VAR_RX_UDP_POLL_OS_RATIO
    if ((env_ptr = getenv(SYS_VAR_RX_POLL_OS_RATIO)) != NULL) {
        rx_udp_poll_os_ratio = (uint32_t)atoi(env_ptr);
        vlog_printf(VLOG_WARNING,
                    "The parameter %s is no longer in use. Parameter %s was set to %d instead\n",
                    SYS_VAR_RX_POLL_OS_RATIO, SYS_VAR_RX_UDP_POLL_OS_RATIO, rx_udp_poll_os_ratio);
    }
    if ((env_ptr = getenv(SYS_VAR_RX_SKIP_OS)) != NULL) {
        rx_udp_poll_os_ratio = (uint32_t)atoi(env_ptr);
        vlog_printf(VLOG_WARNING,
                    "The parameter %s is no longer in use. Parameter %s was set to %d instead\n",
                    SYS_VAR_RX_SKIP_OS, SYS_VAR_RX_UDP_POLL_OS_RATIO, rx_udp_poll_os_ratio);
    }

    if ((env_ptr = getenv(SYS_VAR_RX_POLL_YIELD)) != NULL) {
        rx_poll_yield_loops = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_SELECT_CPU_USAGE_STATS)) != NULL) {
        select_handle_cpu_usage_stats = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_RX_BYTE_MIN_LIMIT)) != NULL) {
        rx_ready_byte_min_limit = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_RX_PREFETCH_BYTES)) != NULL) {
        rx_prefetch_bytes = (uint32_t)atoi(env_ptr);
    }
    if (rx_prefetch_bytes < MCE_MIN_RX_PREFETCH_BYTES ||
        rx_prefetch_bytes > MCE_MAX_RX_PREFETCH_BYTES) {
        vlog_printf(VLOG_WARNING, " Rx prefetch bytes size out of range [%d] (min=%d, max=%d)\n",
                    rx_prefetch_bytes, MCE_MIN_RX_PREFETCH_BYTES, MCE_MAX_RX_PREFETCH_BYTES);
        rx_prefetch_bytes = MCE_DEFAULT_RX_PREFETCH_BYTES;
    }

    if ((env_ptr = getenv(SYS_VAR_RX_PREFETCH_BYTES_BEFORE_POLL)) != NULL) {
        rx_prefetch_bytes_before_poll = (uint32_t)atoi(env_ptr);
    }
    if (rx_prefetch_bytes_before_poll != 0 &&
        (rx_prefetch_bytes_before_poll < MCE_MIN_RX_PREFETCH_BYTES ||
         rx_prefetch_bytes_before_poll > MCE_MAX_RX_PREFETCH_BYTES)) {
        vlog_printf(VLOG_WARNING,
                    " Rx prefetch bytes size out of range [%d] (min=%d, max=%d, disabled=0)\n",
                    rx_prefetch_bytes_before_poll, MCE_MIN_RX_PREFETCH_BYTES,
                    MCE_MAX_RX_PREFETCH_BYTES);
        rx_prefetch_bytes_before_poll = MCE_DEFAULT_RX_PREFETCH_BYTES_BEFORE_POLL;
    }

    if ((env_ptr = getenv(SYS_VAR_RX_CQ_DRAIN_RATE_NSEC)) != NULL) {
        rx_cq_drain_rate_nsec = atoi(env_ptr);
    }
    // Update the rx cq polling rate for draining logic
    tscval_t tsc_per_second = get_tsc_rate_per_second();
    rx_delta_tsc_between_cq_polls = tsc_per_second * rx_cq_drain_rate_nsec / NSEC_PER_SEC;

    if ((env_ptr = getenv(SYS_VAR_GRO_STREAMS_MAX)) != NULL) {
        gro_streams_max = std::max(atoi(env_ptr), 0);
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_3T_RULES)) != NULL) {
        tcp_3t_rules = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_UDP_3T_RULES)) != NULL) {
        udp_3t_rules = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_ETH_MC_L2_ONLY_RULES)) != NULL) {
        eth_mc_l2_only_rules = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_DISABLE_FLOW_TAG)) != NULL) {
        disable_flow_tag = std::max(atoi(env_ptr), 0) ? true : false;
    }
    // mc_force_flowtag must be after disable_flow_tag
    if ((env_ptr = getenv(SYS_VAR_MC_FORCE_FLOWTAG)) != NULL) {
        mc_force_flowtag = atoi(env_ptr) ? true : false;
        if (disable_flow_tag) {
            vlog_printf(VLOG_WARNING, "%s and %s can't be set together. Disabling %s\n",
                        SYS_VAR_DISABLE_FLOW_TAG, SYS_VAR_MC_FORCE_FLOWTAG,
                        SYS_VAR_MC_FORCE_FLOWTAG);
            mc_force_flowtag = 0;
        }
    }

    if ((env_ptr = getenv(SYS_VAR_SELECT_NUM_POLLS)) != NULL) {
        select_poll_num = atoi(env_ptr);
    }

    if (select_poll_num < MCE_MIN_RX_NUM_POLLS || select_poll_num > MCE_MAX_RX_NUM_POLLS) {
        vlog_printf(VLOG_WARNING, " Select Poll loops can not be below zero [%d]\n",
                    select_poll_num);
        select_poll_num = MCE_DEFAULT_SELECT_NUM_POLLS;
    }

    if ((env_ptr = getenv(SYS_VAR_SELECT_POLL_OS_FORCE)) != NULL) {
        select_poll_os_force = (uint32_t)atoi(env_ptr);
    }

    if (select_poll_os_force) {
        select_poll_os_ratio = 1;
        select_skip_os_fd_check = 1;
    }

    if ((env_ptr = getenv(SYS_VAR_SELECT_POLL_OS_RATIO)) != NULL) {
        select_poll_os_ratio = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_SELECT_SKIP_OS)) != NULL) {
        select_skip_os_fd_check = (uint32_t)atoi(env_ptr);
    }

#ifdef DEFINED_IBV_CQ_ATTR_MODERATE
    if ((mce_spec != MCE_SPEC_NVME_BF2) && (rx_poll_num < 0 || select_poll_num < 0)) {
        cq_moderation_enable = false;
    }
    if ((env_ptr = getenv(SYS_VAR_CQ_MODERATION_ENABLE)) != NULL) {
        cq_moderation_enable = atoi(env_ptr) ? true : false;
    }
    if ((env_ptr = getenv(SYS_VAR_CQ_MODERATION_COUNT)) != NULL) {
        cq_moderation_count = (uint32_t)atoi(env_ptr);
    }

    uint32_t max_cq_moderation_count =
        (!enable_striding_rq ? rx_num_wr : (strq_stride_num_per_rwqe * rx_num_wr)) / 2U;
    if (cq_moderation_count > max_cq_moderation_count) {
        cq_moderation_count = max_cq_moderation_count;
    }

    if ((env_ptr = getenv(SYS_VAR_CQ_MODERATION_PERIOD_USEC)) != NULL) {
        cq_moderation_period_usec = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_CQ_AIM_MAX_COUNT)) != NULL) {
        cq_aim_max_count = (uint32_t)atoi(env_ptr);
    }

    uint32_t max_cq_aim_max_count =
        (!enable_striding_rq ? rx_num_wr : (strq_stride_num_per_rwqe * rx_num_wr)) / 2U;
    if (cq_aim_max_count > max_cq_aim_max_count) {
        cq_aim_max_count = max_cq_aim_max_count;
    }

    if ((env_ptr = getenv(SYS_VAR_CQ_AIM_MAX_PERIOD_USEC)) != NULL) {
        cq_aim_max_period_usec = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_CQ_AIM_INTERVAL_MSEC)) != NULL) {
        cq_aim_interval_msec = (uint32_t)atoi(env_ptr);
    }

    if (!cq_moderation_enable) {
        cq_aim_interval_msec = MCE_CQ_ADAPTIVE_MODERATION_DISABLED;
    }

    if ((env_ptr = getenv(SYS_VAR_CQ_AIM_INTERRUPTS_RATE_PER_SEC)) != NULL) {
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

    if ((env_ptr = getenv(SYS_VAR_CQ_POLL_BATCH_MAX)) != NULL) {
        cq_poll_batch_max = (uint32_t)atoi(env_ptr);
    }
    if (cq_poll_batch_max < MCE_MIN_CQ_POLL_BATCH || cq_poll_batch_max > MCE_MAX_CQ_POLL_BATCH) {
        vlog_printf(VLOG_WARNING, " Rx number of cq poll batchs should be between %d and %d [%d]\n",
                    MCE_MIN_CQ_POLL_BATCH, MCE_MAX_CQ_POLL_BATCH, cq_poll_batch_max);
        cq_poll_batch_max = MCE_DEFAULT_CQ_POLL_BATCH;
    }

    if ((env_ptr = getenv(SYS_VAR_PROGRESS_ENGINE_INTERVAL)) != NULL) {
        progress_engine_interval_msec = (uint32_t)atoi(env_ptr);
    }
    if (enable_socketxtreme && (progress_engine_interval_msec != MCE_CQ_DRAIN_INTERVAL_DISABLED)) {
        progress_engine_interval_msec = MCE_CQ_DRAIN_INTERVAL_DISABLED;
        vlog_printf(VLOG_DEBUG, "%s parameter is forced to %d in case %s is enabled\n",
                    SYS_VAR_PROGRESS_ENGINE_INTERVAL, progress_engine_interval_msec,
                    SYS_VAR_SOCKETXTREME);
    }

    if ((env_ptr = getenv(SYS_VAR_PROGRESS_ENGINE_WCE_MAX)) != NULL) {
        progress_engine_wce_max = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_CQ_KEEP_QP_FULL)) != NULL) {
        cq_keep_qp_full = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_QP_COMPENSATION_LEVEL)) != NULL) {
        qp_compensation_level = (uint32_t)atoi(env_ptr);
    }
    if (qp_compensation_level < rx_num_wr_to_post_recv) {
        qp_compensation_level = rx_num_wr_to_post_recv;
    }

    if ((env_ptr = getenv(SYS_VAR_USER_HUGE_PAGE_SIZE)) != NULL) {
        user_huge_page_size = option_size::from_str(env_ptr);
        if (user_huge_page_size == 0) {
            user_huge_page_size = g_hugepage_mgr.get_default_hugepage();
        }
    }

    if ((env_ptr = getenv(SYS_VAR_OFFLOADED_SOCKETS)) != NULL) {
        offloaded_sockets = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_TIMER_RESOLUTION_MSEC)) != NULL) {
        timer_resolution_msec = atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_TIMER_RESOLUTION_MSEC)) != NULL) {
        tcp_timer_resolution_msec = atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_CTL_THREAD)) != NULL) {
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

    if ((env_ptr = getenv(SYS_VAR_TCP_TIMESTAMP_OPTION)) != NULL) {
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

    if ((env_ptr = getenv(SYS_VAR_TCP_NODELAY)) != NULL) {
        tcp_nodelay = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_QUICKACK)) != NULL) {
        tcp_quickack = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_PUSH_FLAG)) != NULL) {
        tcp_push_flag = atoi(env_ptr) ? true : false;
    }

    // TODO: this should be replaced by calling "exception_handling.init()" that will be called from
    // init()
    if ((env_ptr = getenv(xlio_exception_handling::getSysVar())) != NULL) {
        exception_handling = xlio_exception_handling(
            strtol(env_ptr, NULL, 10)); // xlio_exception_handling is responsible for its invariant
    }

    if ((env_ptr = getenv(SYS_VAR_AVOID_SYS_CALLS_ON_TCP_FD)) != NULL) {
        avoid_sys_calls_on_tcp_fd = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_ALLOW_PRIVILEGED_SOCK_OPT)) != NULL) {
        allow_privileged_sock_opt = atoi(env_ptr) ? true : false;
    }

    if (tcp_timer_resolution_msec < timer_resolution_msec) {
        vlog_printf(VLOG_WARNING,
                    " TCP timer resolution [%s=%d] cannot be smaller than timer resolution "
                    "[%s=%d]. Setting TCP timer resolution to %d msec.\n",
                    SYS_VAR_TCP_TIMER_RESOLUTION_MSEC, tcp_timer_resolution_msec,
                    SYS_VAR_TIMER_RESOLUTION_MSEC, timer_resolution_msec, timer_resolution_msec);
        tcp_timer_resolution_msec = timer_resolution_msec;
    }

    if ((env_ptr = getenv(SYS_VAR_INTERNAL_THREAD_ARM_CQ)) != NULL) {
        internal_thread_arm_cq_enabled = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_INTERNAL_THREAD_CPUSET)) != NULL) {
        snprintf(internal_thread_cpuset, FILENAME_MAX, "%s", env_ptr);
    }

    // handle internal thread affinity - default is CPU-0
    if ((env_ptr = getenv(SYS_VAR_INTERNAL_THREAD_AFFINITY)) != NULL) {
        int n = snprintf(internal_thread_affinity_str, sizeof(internal_thread_affinity_str), "%s",
                         env_ptr);
        if (unlikely(((int)sizeof(internal_thread_affinity_str) < n) || (n < 0))) {
            vlog_printf(VLOG_WARNING, "Failed to process: %s.\n", SYS_VAR_INTERNAL_THREAD_AFFINITY);
        }
    }
    if (env_to_cpuset(internal_thread_affinity_str, &internal_thread_affinity)) {
        vlog_printf(VLOG_WARNING,
                    " Failed to set internal thread affinity: %s...  deferring to cpu-0.\n",
                    internal_thread_affinity_str);
    }

    if ((env_ptr = getenv(SYS_VAR_WAIT_AFTER_JOIN_MSEC)) != NULL) {
        wait_after_join_msec = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_THREAD_MODE)) != NULL) {
        thread_mode = (thread_mode_t)atoi(env_ptr);
        if (thread_mode < 0 || thread_mode >= THREAD_MODE_LAST) {
            thread_mode = MCE_DEFAULT_THREAD_MODE;
        }
    }

    if ((env_ptr = getenv(SYS_VAR_BUFFER_BATCHING_MODE)) != NULL) {
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

    if ((env_ptr = getenv(SYS_VAR_NETLINK_TIMER_MSEC)) != NULL) {
        timer_netlink_update_msec = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_NEIGH_NUM_ERR_RETRIES)) != NULL) {
        neigh_num_err_retries = (uint32_t)atoi(env_ptr);
    }
    if ((env_ptr = getenv(SYS_VAR_NEIGH_UC_ARP_DELAY_MSEC)) != NULL) {
        neigh_wait_till_send_arp_msec = (uint32_t)atoi(env_ptr);
    }
    if ((env_ptr = getenv(SYS_VAR_NEIGH_UC_ARP_QUATA)) != NULL) {
        neigh_uc_arp_quata = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_MEM_ALLOC_TYPE)) != NULL) {
        mem_alloc_type = option_alloc_type::from_str(env_ptr, MCE_DEFAULT_MEM_ALLOC_TYPE);
    }
    if ((env_ptr = getenv(SYS_VAR_HUGEPAGE_LOG2)) != NULL) {
        unsigned val = (unsigned)atoi(env_ptr);

        // mmap() uses 6 bits for the hugepage size log2
        if (val < 64U) {
            hugepage_log2 = val;
        } else {
            hugepage_log2 = MCE_DEFAULT_HUGEPAGE_LOG2;
            vlog_printf(VLOG_WARNING, "%s parameter can be in range [0, 63], but set to %u\n",
                        SYS_VAR_HUGEPAGE_LOG2, val);
        }
        if (hugepage_log2 != 0 && !g_hugepage_mgr.is_hugepage_supported(1LU << hugepage_log2)) {
            vlog_printf(VLOG_WARNING,
                        "Requested hugepage %zu kB is not supported. "
                        "XLIO will autodetect optimal hugepage.",
                        (1LU << hugepage_log2) / 1024LU);
            /* Value 0 means default autodetection behavior. Don't set MCE_DEFAULT_HUGEPAGE_LOG2
             * here, because it can be defined to an unsupported specific value.
             */
            hugepage_log2 = 0;
        }
    }

    if ((env_ptr = getenv(SYS_VAR_BF)) != NULL) {
        handle_bf = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_FORK)) != NULL) {
        handle_fork = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_TSO)) != NULL) {
        enable_tso = option_3::from_str(env_ptr, MCE_DEFAULT_TSO);
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

    if ((env_ptr = getenv(SYS_VAR_LRO)) != NULL) {
        enable_lro = option_3::from_str(env_ptr, MCE_DEFAULT_LRO);
    }

    if ((env_ptr = getenv(SYS_VAR_CLOSE_ON_DUP2)) != NULL) {
        close_on_dup2 = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_MTU)) != NULL) {
        mtu = (uint32_t)atoi(env_ptr);
    }

#if defined(DEFINED_NGINX)
    if ((env_ptr = getenv(SYS_VAR_NGINX_WORKERS_NUM)) != NULL) {
        app.type = APP_NGINX;
        app.workers_num = (uint32_t)atoi(env_ptr);
    }
    if ((env_ptr = getenv(SYS_VAR_NGINX_UDP_POOL_SIZE)) != NULL) {
        nginx_udp_socket_pool_size = (uint32_t)atoi(env_ptr);
    }
    if ((env_ptr = getenv(SYS_VAR_NGINX_UDP_POOL_RX_NUM_BUFFS_REUSE)) != NULL) {
        nginx_udp_socket_pool_rx_num_buffs_reuse = (uint32_t)atoi(env_ptr);
    }
#endif // DEFINED_NGINX
#if defined(DEFINED_ENVOY)
    if ((env_ptr = getenv(SYS_VAR_ENVOY_WORKERS_NUM)) != NULL) {
        app.type = APP_ENVOY;
        app.workers_num = (uint32_t)atoi(env_ptr);
    }
#endif /* DEFINED_ENVOY */
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    if ((env_ptr = getenv(SYS_VAR_SRC_PORT_STRIDE)) != NULL) {
        app.src_port_stride = (uint32_t)atoi(env_ptr);
    }
    if ((env_ptr = getenv(SYS_VAR_DISTRIBUTE_CQ)) != NULL) {
        app.distribute_cq_interrupts = atoi(env_ptr) ? true : false;
    }
#endif
    if ((env_ptr = getenv(SYS_VAR_MSS)) != NULL) {
        lwip_mss = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_CC_ALGO)) != NULL) {
        lwip_cc_algo_mod = (uint32_t)atoi(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_DEFERRED_CLOSE)) != NULL) {
        deferred_close = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_ABORT_ON_CLOSE)) != NULL) {
        tcp_abort_on_close = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_RX_POLL_ON_TX_TCP)) != NULL) {
        rx_poll_on_tx_tcp = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_RX_CQ_WAIT_CTRL)) != NULL) {
        rx_cq_wait_ctrl = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_TRIGGER_DUMMY_SEND_GETSOCKNAME)) != NULL) {
        trigger_dummy_send_getsockname = atoi(env_ptr) ? true : false;
    }

    if ((env_ptr = getenv(SYS_VAR_TCP_SEND_BUFFER_SIZE)) != NULL) {
        tcp_send_buffer_size = (uint32_t)option_size::from_str(env_ptr);
    }

    if ((env_ptr = getenv(SYS_VAR_SKIP_POLL_IN_RX)) != NULL) {
        int temp = atoi(env_ptr);
        if (temp < 0 || temp > SKIP_POLL_IN_RX_EPOLL_ONLY) {
            temp = 0;
        }
        skip_poll_in_rx = (skip_poll_in_rx_t)temp;
    }

    if ((env_ptr = getenv(SYS_VAR_MULTILOCK)) != NULL) {
        int temp = atoi(env_ptr);
        if (temp < 0 || temp > MULTILOCK_MUTEX) {
            temp = 0;
        }
        multilock = (multilock_t)temp;
    }

#ifdef XLIO_TIME_MEASURE
    if ((env_ptr = getenv(SYS_VAR_TIME_MEASURE_NUM_SAMPLES)) != NULL) {
        xlio_time_measure_num_samples = (uint32_t)atoi(env_ptr);
        if (xlio_time_measure_num_samples > INST_SIZE) {
            vlog_printf(
                VLOG_WARNING,
                "The value of '%s' is bigger than %d. Time samples over %d will be dropped.\n",
                SYS_VAR_TIME_MEASURE_NUM_SAMPLES, INST_SIZE, INST_SIZE);
        }
    }

    if ((env_ptr = getenv(SYS_VAR_TIME_MEASURE_DUMP_FILE)) != NULL) {
        read_env_variable_with_pid(xlio_time_measure_filename, sizeof(xlio_time_measure_filename),
                                   env_ptr);
    }
#endif
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

    if (safe_mce_sys().handle_bf) {
        setenv("MLX5_POST_SEND_PREFER_BF", "1", 1);
    } else {
        /* todo - these seem not to work if inline is on, since libmlx is doing (inl || bf) when
         * deciding to bf*/
        setenv("MLX5_POST_SEND_PREFER_BF", "0", 1);
    }

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
    if (getenv("MLX_QP_ALLOC_TYPE") == nullptr) {
        setenv("MLX_QP_ALLOC_TYPE", ibv_alloc_type, 0);
    }
    if (getenv("MLX_CQ_ALLOC_TYPE") == nullptr) {
        setenv("MLX_CQ_ALLOC_TYPE", ibv_alloc_type, 0);
    }
}
