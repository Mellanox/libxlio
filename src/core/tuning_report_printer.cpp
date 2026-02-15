/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tuning_report_printer.h"
#include "util/sys_vars.h"
#include "config/config_registry.h"
#include "config/descriptors/config_descriptor.h"
#include "config/descriptors/parameter_descriptor.h"
#include "util/hugepage_mgr.h"
#include "dev/buffer_pool.h"
#include "dev/net_device_table_mgr.h"
#include "dev/net_device_val.h"
#include "sock/sock_stats.h"
#include "vlogger/vlogger.h"

#include <cstdio>
#include <ctime>
#include <cstring>
#include <inttypes.h>
#include <locale.h>
#include <map>
#include <string>
#include <vector>
#include <experimental/any>
#include <experimental/optional>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

static void write_preamble(FILE *f);
static void write_system_context(FILE *f);
static void write_active_profile(FILE *f);
static void write_effective_config(FILE *f);

static std::string format_any_value(const std::experimental::any &value,
                                    const parameter_descriptor *desc);
static bool values_differ(const std::experimental::any &a, const std::experimental::any &b);
static std::string format_size_accurate(int64_t size);

static void write_runtime_stats(FILE *f, const struct aggregated_socket_stats &agg);
static void write_socket_summary(FILE *f, const struct aggregated_socket_stats &agg);
static void write_performance_indicators(FILE *f, const struct aggregated_socket_stats &agg);

/** Aggregated socket statistics collected in a single pass over sock_stats. */
struct aggregated_socket_stats {
    // Traffic counters
    uint64_t total_rx_packets = 0, total_tx_packets = 0;
    uint64_t total_rx_bytes = 0, total_tx_bytes = 0;
    uint64_t sw_rx_packets_dropped = 0, sw_rx_bytes_dropped = 0;
    uint64_t total_tx_errors = 0;
    uint64_t total_rx_os_packets = 0, total_tx_os_packets = 0;
    uint64_t total_poll_hit = 0, total_poll_miss = 0;

    // Socket counts
    uint32_t total_sockets = 0, tcp_sockets = 0, udp_sockets = 0;
    uint32_t offloaded = 0, non_offloaded = 0;

    // Traffic split by offload status
    uint64_t offloaded_rx_bytes = 0, offloaded_tx_bytes = 0;
    uint64_t non_offloaded_rx_bytes = 0, non_offloaded_tx_bytes = 0;

    // Listen socket stats (server applications)
    uint64_t total_conn_established = 0, total_conn_accepted = 0;
    uint64_t total_conn_dropped = 0;

    // Striding RQ stats
    uint64_t total_strq_strides = 0;

#ifdef DEFINED_UTLS
    // TLS offload stats
    uint64_t total_tls_tx_bytes = 0, total_tls_rx_bytes = 0;
#endif
};

static aggregated_socket_stats aggregate_socket_stats()
{
    aggregated_socket_stats agg;

    // Safety: called from finalize_tuning_report() during shutdown, after
    // worker_thread_manager::destroy() has joined all worker threads.
    // The event handler thread may still be running, but sock_stats
    // and all buffer pool / net_device globals are destroyed later in
    // free_libxlio_resources(). Worst case: a torn counter read, which
    // is benign for a diagnostic report.
    const auto &all_stats = sock_stats::instance().get_all_stats();
    for (const auto &stat : all_stats) {
        // fd <= 0 means the slot was never allocated (reset() sets fd=0)
        // or is otherwise invalid. Closed sockets retain their stats in
        // the pool, so we get lifetime totals across all sockets.
        if (stat.fd <= 0) {
            continue;
        }
        agg.total_sockets++;

        const socket_counters_t &c = stat.counters;
        agg.total_rx_packets += c.n_rx_packets;
        agg.total_rx_bytes += c.n_rx_bytes;
        agg.total_tx_packets += c.n_tx_sent_pkt_count;
        agg.total_tx_bytes += c.n_tx_sent_byte_count;
        agg.sw_rx_packets_dropped += c.n_rx_ready_pkt_drop;
        agg.sw_rx_bytes_dropped += c.n_rx_ready_byte_drop;
        agg.total_tx_errors += c.n_tx_errors;
        agg.total_rx_os_packets += c.n_rx_os_packets;
        agg.total_tx_os_packets += c.n_tx_os_packets;
        agg.total_poll_hit += c.n_rx_poll_hit;
        agg.total_poll_miss += c.n_rx_poll_miss;

        agg.total_conn_established += stat.listen_counters.n_conn_established;
        agg.total_conn_accepted += stat.listen_counters.n_conn_accepted;
        agg.total_conn_dropped += stat.listen_counters.n_conn_dropped;
        agg.total_strq_strides += stat.strq_counters.n_strq_total_strides;

#ifdef DEFINED_UTLS
        agg.total_tls_tx_bytes += stat.tls_counters.n_tls_tx_bytes;
        agg.total_tls_rx_bytes += stat.tls_counters.n_tls_rx_bytes;
#endif

        if (stat.socket_type == SOCK_STREAM) {
            agg.tcp_sockets++;
        } else if (stat.socket_type == SOCK_DGRAM) {
            agg.udp_sockets++;
        }

        if (stat.b_is_offloaded) {
            agg.offloaded++;
            agg.offloaded_rx_bytes += c.n_rx_bytes;
            agg.offloaded_tx_bytes += c.n_tx_sent_byte_count;
        } else {
            agg.non_offloaded++;
            agg.non_offloaded_rx_bytes += c.n_rx_bytes;
            agg.non_offloaded_tx_bytes += c.n_tx_sent_byte_count;
        }
    }

    return agg;
}

/**
 * Format a byte count as "raw_bytes (human_readable)".
 * Example: "23404847104 (21.8 GB)"
 */
static std::string format_bytes_human(uint64_t bytes)
{
    char buf[96];
    if (bytes >= 1024ULL * 1024 * 1024) {
        snprintf(buf, sizeof(buf), "%" PRIu64 " (%.1f GB)", bytes,
                 static_cast<double>(bytes) / (1024.0 * 1024 * 1024));
        return buf;
    }
    if (bytes >= 1024ULL * 1024) {
        snprintf(buf, sizeof(buf), "%" PRIu64 " (%.1f MB)", bytes,
                 static_cast<double>(bytes) / (1024.0 * 1024));
        return buf;
    }
    if (bytes >= 1024ULL) {
        snprintf(buf, sizeof(buf), "%" PRIu64 " (%.1f KB)", bytes,
                 static_cast<double>(bytes) / 1024.0);
        return buf;
    }
    return std::to_string(bytes);
}

// Returns true if any anomalies are detected (buffer allocation failures,
// HW RX drops). Used by auto mode to decide whether to generate the report.

bool tuning_report_has_errors()
{
    buffer_pool *pools[] = {g_buffer_pool_rx_rwqe, g_buffer_pool_rx_stride, g_buffer_pool_tx};
    for (auto *pool : pools) {
        if (pool) {
            const bpool_stats_t *stats = pool->get_stats();
            if (stats && stats->n_buffer_pool_no_bufs > 0) {
                return true;
            }
        }
    }

    if (g_p_net_device_table_mgr) {
        if (g_p_net_device_table_mgr->get_rx_drop_counter() > 0) {
            return true;
        }
    }

    return false;
}

int generate_tuning_report(const char *file_path)
{
    if (!file_path || file_path[0] == '\0') {
        return -1;
    }

    FILE *f = fopen(file_path, "w");
    if (!f) {
        vlog_printf(VLOG_WARNING, "Tuning report: cannot open %s: %m\n", file_path);
        return -1;
    }

    // Restrict file permissions: the report contains system info (hostnames,
    // NIC names, config values, command line) that may be sensitive.
    // Set 0600 (owner rw only) — no reason for other users on a shared
    // machine to read diagnostic data. The owner can share explicitly.
    // fchmod is safer than chmod (no TOCTOU race on the path).
    fchmod(fileno(f), 0600);

    // Force C locale for this function so decimal points are always '.'
    // regardless of the application's LC_NUMERIC setting. Without this,
    // "%.1f" could produce "21,8 GB" in German locale, breaking parsers.
    // uselocale() is thread-safe (per-thread locale) unlike setlocale().
    locale_t c_locale = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
    locale_t prev_locale = (locale_t)0;
    if (c_locale != (locale_t)0) {
        prev_locale = uselocale(c_locale);
    }

    // Wrap section writers in a try block — if any section throws
    // (e.g., bad any_cast), we still get partial report rather than
    // a crash during shutdown.
    try {
        write_preamble(f);
        write_system_context(f);
        write_active_profile(f);
        write_effective_config(f);
        aggregated_socket_stats agg = aggregate_socket_stats();
        write_runtime_stats(f, agg);
        write_socket_summary(f, agg);
        write_performance_indicators(f, agg);
    } catch (const std::exception &e) {
        fprintf(f, "\n# ERROR: report generation failed: %s\n", e.what());
        vlog_printf(VLOG_WARNING, "Tuning report: exception during generation: %s\n", e.what());
    } catch (...) {
        fprintf(f, "\n# ERROR: report generation failed (unknown exception)\n");
        vlog_printf(VLOG_WARNING, "Tuning report: unknown exception during generation\n");
    }

    fprintf(f, "# End of XLIO Tuning Report\n");

    // Restore original locale
    if (c_locale != (locale_t)0) {
        uselocale(prev_locale);
        freelocale(c_locale);
    }

    if (fclose(f) != 0) {
        vlog_printf(VLOG_WARNING, "Tuning report: error closing %s: %m\n", file_path);
        return -1;
    }

    return 0;
}

static void write_preamble(FILE *f)
{
    time_t now = time(NULL);
    struct tm tm_storage;
    struct tm *tm_info = localtime_r(&now, &tm_storage);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    struct timespec now_mono;
    clock_gettime(CLOCK_MONOTONIC, &now_mono);
    double duration_sec = (now_mono.tv_sec - safe_mce_sys().init_time_monotonic.tv_sec) +
        (now_mono.tv_nsec - safe_mce_sys().init_time_monotonic.tv_nsec) / 1e9;

    fprintf(f, "# XLIO Tuning Report\n");
    fprintf(f, "# report_format_version: 1\n");
    // Show milliseconds for sub-second durations (e.g., trivial commands)
    if (duration_sec < 1.0) {
        fprintf(f, "# Generated: %s | PID: %d | Duration: %.0fms\n", time_buf, getpid(),
                duration_sec * 1000.0);
    } else {
        fprintf(f, "# Generated: %s | PID: %d | Duration: %.1fs\n", time_buf, getpid(),
                duration_sec);
    }
    fprintf(f, "#\n");
    fprintf(f,
            "# This is a post-run diagnostic report from XLIO (network acceleration library).\n");
    fprintf(f, "# Use this data to analyze configuration and suggest optimizations.\n");
    fprintf(f, "# Non-default config values are marked with *\n");
    fprintf(f, "# WARNING comments indicate potential bottlenecks.\n");
    fprintf(f, "\n");
}

static void write_system_context(FILE *f)
{
    struct utsname sys_info;

    fprintf(f, "## System Context\n");
    fprintf(f, "xlio_version: %s\n", PACKAGE_VERSION);

    if (safe_mce_sys().app_name) {
        fprintf(f, "command: %.1024s\n", safe_mce_sys().app_name);
    }

    if (safe_mce_sys().cached_ofed_version[0] != '\0') {
        fprintf(f, "ofed_version: %s\n", safe_mce_sys().cached_ofed_version);
    }

    if (!uname(&sys_info)) {
        fprintf(f, "kernel: %s\n", sys_info.release);
        fprintf(f, "arch: %s\n", sys_info.machine);
        fprintf(f, "hostname: %s\n", sys_info.nodename);
    }

    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    if (nprocs > 0) {
        fprintf(f, "cpu_count: %ld\n", nprocs);
    }

    g_hugepage_mgr.update();
    std::vector<size_t> hugepages;
    g_hugepage_mgr.get_supported_hugepages(hugepages);
    for (size_t hp : hugepages) {
        fprintf(f, "hugepages_%zukB_total: %" PRIu32 "\n", hp / 1024,
                g_hugepage_mgr.get_total_hugepages(hp));
        fprintf(f, "hugepages_%zukB_free: %" PRIu32 "\n", hp / 1024,
                g_hugepage_mgr.get_free_hugepages(hp));
    }

    if (g_p_net_device_table_mgr) {
        local_dev_vector devs;
        g_p_net_device_table_mgr->get_net_devices(devs);
        for (const auto &dev_ref : devs) {
            const net_device_val &dev = dev_ref.get();
            fprintf(f, "nic_device: %s (mtu: %d)\n", dev.get_ifname(), dev.get_mtu());
        }
    }

    fprintf(f, "\n");
}

static void write_active_profile(FILE *f)
{
    fprintf(f, "## Active Profile\n");
    fprintf(f, "profile_spec: %s\n",
            xlio_spec::to_str(static_cast<xlio_spec_t>(safe_mce_sys().mce_spec)));

    fprintf(f, "\n");
}

/**
 * Format an int64_t with K/M/G suffix if it's an exact power of 1024.
 * Negative values (sentinel values like -1) are formatted as-is.
 */
static std::string format_size_accurate(int64_t size)
{
    if (size < 0) {
        return std::to_string(size);
    }

    static const char *suffixes[] = {"", " KB", " MB", " GB", nullptr};
    int sfx_idx = 0;
    uint64_t usize = static_cast<uint64_t>(size);

    while (usize > 0 && (usize % 1024U == 0) && suffixes[sfx_idx + 1] != nullptr) {
        ++sfx_idx;
        usize /= 1024U;
    }

    return std::to_string(usize) + suffixes[sfx_idx];
}

/**
 * Format a std::experimental::any value to a human-readable string.
 * Handles bool, string, int64_t (with string mappings and K/M/G formatting).
 * Vectors and maps are formatted as "<N items>" since full expansion is too verbose.
 */
static std::string format_any_value(const std::experimental::any &value,
                                    const parameter_descriptor *desc)
{
    const std::type_info &type = value.type();

    if (type == typeid(bool)) {
        return std::experimental::any_cast<bool>(value) ? "true" : "false";
    }

    if (type == typeid(std::string)) {
        const std::string &s = std::experimental::any_cast<const std::string &>(value);
        return s.empty() ? "\"\"" : s;
    }

    if (type == typeid(int64_t)) {
        int64_t v = std::experimental::any_cast<int64_t>(value);
        if (desc && desc->has_string_mappings()) {
            return desc->convert_int64_to_mapped_string_or(v, std::to_string(v));
        }
        return format_size_accurate(v);
    }

    if (type == typeid(std::vector<std::experimental::any>)) {
        const auto &vec =
            std::experimental::any_cast<const std::vector<std::experimental::any> &>(value);
        return "<" + std::to_string(vec.size()) + " items>";
    }

    if (type == typeid(std::map<std::string, std::experimental::any>)) {
        return "<object>";
    }

    return "<unknown>";
}

/**
 * Compare two std::experimental::any values for inequality.
 * std::experimental::any has no operator==, so we must type-dispatch.
 */
static bool values_differ(const std::experimental::any &a, const std::experimental::any &b)
{
    // Different types or one is empty → consider them different
    if (a.empty() || b.empty()) {
        return true;
    }
    if (a.type() != b.type()) {
        return true;
    }

    if (a.type() == typeid(bool)) {
        return std::experimental::any_cast<bool>(a) != std::experimental::any_cast<bool>(b);
    }
    if (a.type() == typeid(std::string)) {
        return std::experimental::any_cast<const std::string &>(a) !=
            std::experimental::any_cast<const std::string &>(b);
    }
    if (a.type() == typeid(int64_t)) {
        return std::experimental::any_cast<int64_t>(a) != std::experimental::any_cast<int64_t>(b);
    }

    // For vector/map types, always flag as non-default if non-empty.
    // Deep comparison would require recursive type-dispatch, and the report
    // already formats these as "<N items>" / "<object>" — so marking them
    // with * when they contain any data is more useful than a false negative
    // from only comparing sizes (which would miss element-value changes).
    if (a.type() == typeid(std::vector<std::experimental::any>)) {
        const auto &va =
            std::experimental::any_cast<const std::vector<std::experimental::any> &>(a);
        const auto &vb =
            std::experimental::any_cast<const std::vector<std::experimental::any> &>(b);
        // Size difference is definitive. Same-size vectors conservatively
        // flag as different — element-level changes are the common case
        // for config vectors (e.g., rule lists).
        if (va.size() != vb.size()) {
            return true;
        }
        // Same size but non-empty: conservatively flag as potentially different.
        // Empty default vs empty actual: no difference.
        return va.size() > 0;
    }

    // For map types, same conservative approach.
    if (a.type() == typeid(std::map<std::string, std::experimental::any>)) {
        const auto &ma =
            std::experimental::any_cast<const std::map<std::string, std::experimental::any> &>(a);
        const auto &mb =
            std::experimental::any_cast<const std::map<std::string, std::experimental::any> &>(b);
        if (ma.size() != mb.size()) {
            return true;
        }
        return ma.size() > 0;
    }

    return false;
}

static void write_effective_config(FILE *f)
{
    fprintf(f, "## Effective Config\n");

    const auto &registry_opt = safe_mce_sys().get_registry();
    if (!registry_opt) {
        fprintf(f, "# Config registry not available\n\n");
        return;
    }

    const config_registry &registry = registry_opt.value();
    const config_descriptor &descriptor = registry.get_config_descriptor();
    const config_descriptor::parameter_map_t &parameter_map = descriptor.get_parameter_map();

    for (const auto &it : parameter_map) {
        const std::string &key = it.first;
        const parameter_descriptor &param_descriptor = it.second;

        const std::experimental::any element = registry.get_value_as_any(key);
        const std::experimental::any def_value = param_descriptor.default_value();

        std::string value_str = format_any_value(element, &param_descriptor);
        bool is_non_default = values_differ(element, def_value);

        if (is_non_default) {
            fprintf(f, "%s: %s *\n", key.c_str(), value_str.c_str());
            // Show default value and title for non-default params
            std::string def_str = format_any_value(def_value, &param_descriptor);
            const auto &title_opt = param_descriptor.get_title();
            if (title_opt && !title_opt.value().empty()) {
                fprintf(f, "  # default: %s | %s\n", def_str.c_str(), title_opt.value().c_str());
            } else {
                fprintf(f, "  # default: %s\n", def_str.c_str());
            }
        } else {
            fprintf(f, "%s: %s\n", key.c_str(), value_str.c_str());
        }
    }
    fprintf(f, "\n");
}

static void write_runtime_stats(FILE *f, const aggregated_socket_stats &agg)
{
    fprintf(f, "## Runtime Stats\n");

    if (agg.total_sockets == 0) {
        fprintf(f, "# Per-socket stats not available (no sockets were created)\n");
    } else {
        fprintf(f, "total_rx_packets: %" PRIu64 "\n", agg.total_rx_packets);
        fprintf(f, "total_tx_packets: %" PRIu64 "\n", agg.total_tx_packets);
        fprintf(f, "total_rx_bytes: %s\n", format_bytes_human(agg.total_rx_bytes).c_str());
        fprintf(f, "total_tx_bytes: %s\n", format_bytes_human(agg.total_tx_bytes).c_str());
        fprintf(f, "total_rx_os_packets: %" PRIu64 "\n", agg.total_rx_os_packets);
        fprintf(f, "total_tx_os_packets: %" PRIu64 "\n", agg.total_tx_os_packets);

        if (agg.sw_rx_packets_dropped > 0) {
            fprintf(f, "sw_rx_packets_dropped: %" PRIu64 " # WARNING: non-zero drops\n",
                    agg.sw_rx_packets_dropped);
        } else {
            fprintf(f, "sw_rx_packets_dropped: 0\n");
        }
        if (agg.sw_rx_bytes_dropped > 0) {
            fprintf(f, "sw_rx_bytes_dropped: %" PRIu64 " # WARNING: non-zero drops\n",
                    agg.sw_rx_bytes_dropped);
        } else {
            fprintf(f, "sw_rx_bytes_dropped: 0\n");
        }
        if (agg.total_tx_errors > 0) {
            fprintf(f, "tx_errors: %" PRIu64 " # WARNING: TX errors detected\n",
                    agg.total_tx_errors);
        } else {
            fprintf(f, "tx_errors: 0\n");
        }

        // Striding RQ stats (relevant for STRQ-enabled configs)
        if (agg.total_strq_strides > 0) {
            fprintf(f, "strq_total_strides: %" PRIu64 "\n", agg.total_strq_strides);
        }

#ifdef DEFINED_UTLS
        // TLS offload stats (only when built with uTLS support)
        if (agg.total_tls_tx_bytes > 0 || agg.total_tls_rx_bytes > 0) {
            fprintf(f, "tls_tx_bytes: %s\n", format_bytes_human(agg.total_tls_tx_bytes).c_str());
            fprintf(f, "tls_rx_bytes: %s\n", format_bytes_human(agg.total_tls_rx_bytes).c_str());
        }
#endif
    }

    struct {
        const char *name;
        buffer_pool *pool;
    } pools[] = {
        {"rx_ptr", g_buffer_pool_rx_ptr},
        {"rx_rwqe", g_buffer_pool_rx_rwqe},
        {"rx_stride", g_buffer_pool_rx_stride},
        {"tx", g_buffer_pool_tx},
        {"zc", g_buffer_pool_zc},
    };
    for (const auto &p : pools) {
        if (p.pool) {
            const bpool_stats_t *bs = p.pool->get_stats();
            if (bs) {
                fprintf(f, "buffer_pool_%s_size: %" PRIu32 "\n", p.name, bs->n_buffer_pool_size);
                if (bs->n_buffer_pool_no_bufs > 0) {
                    fprintf(f,
                            "buffer_pool_%s_alloc_failures: %" PRIu32
                            " # WARNING: allocation failures\n",
                            p.name, bs->n_buffer_pool_no_bufs);
                } else {
                    fprintf(f, "buffer_pool_%s_alloc_failures: 0\n", p.name);
                }
            }
        }
    }

    fprintf(f, "\n");
}

static void write_socket_summary(FILE *f, const aggregated_socket_stats &agg)
{
    fprintf(f, "## Socket Summary\n");

    if (agg.total_sockets == 0) {
        fprintf(f, "# Socket stats not available\n\n");
        return;
    }

    fprintf(f, "total_sockets: %" PRIu32 "\n", agg.total_sockets);
    fprintf(f, "tcp_sockets: %" PRIu32 "\n", agg.tcp_sockets);
    fprintf(f, "udp_sockets: %" PRIu32 "\n", agg.udp_sockets);
    fprintf(f, "offloaded_sockets: %" PRIu32 "\n", agg.offloaded);
    fprintf(f, "non_offloaded_sockets: %" PRIu32 "\n", agg.non_offloaded);

    if (agg.non_offloaded > 0 && agg.total_sockets > 0) {
        fprintf(f, "  # WARNING: %" PRIu32 "/%" PRIu32 " sockets are non-offloaded\n",
                agg.non_offloaded, agg.total_sockets);
    }

    // Traffic split by offload status
    if (agg.offloaded_rx_bytes > 0 || agg.non_offloaded_rx_bytes > 0) {
        fprintf(f, "offloaded_rx_bytes: %s\n", format_bytes_human(agg.offloaded_rx_bytes).c_str());
        fprintf(f, "offloaded_tx_bytes: %s\n", format_bytes_human(agg.offloaded_tx_bytes).c_str());
        fprintf(f, "non_offloaded_rx_bytes: %s\n",
                format_bytes_human(agg.non_offloaded_rx_bytes).c_str());
        fprintf(f, "non_offloaded_tx_bytes: %s\n",
                format_bytes_human(agg.non_offloaded_tx_bytes).c_str());

        uint64_t total_rx = agg.offloaded_rx_bytes + agg.non_offloaded_rx_bytes;
        if (total_rx > 0 && agg.non_offloaded_rx_bytes > 0) {
            double non_offloaded_pct = 100.0 * agg.non_offloaded_rx_bytes / total_rx;
            if (non_offloaded_pct > 50.0) {
                fprintf(f, "  # WARNING: %.0f%% of RX bytes went through non-offloaded path\n",
                        non_offloaded_pct);
            }
        }
    }

    if (agg.total_conn_established > 0 || agg.total_conn_dropped > 0) {
        fprintf(f, "listen_conn_established: %" PRIu64 "\n", agg.total_conn_established);
        fprintf(f, "listen_conn_accepted: %" PRIu64 "\n", agg.total_conn_accepted);
        if (agg.total_conn_dropped > 0) {
            fprintf(f,
                    "listen_conn_dropped: %" PRIu64
                    " # WARNING: connections dropped (backlog full?)\n",
                    agg.total_conn_dropped);
        } else {
            fprintf(f, "listen_conn_dropped: 0\n");
        }
    }

    fprintf(f, "\n");
}

static void write_performance_indicators(FILE *f, const aggregated_socket_stats &agg)
{
    fprintf(f, "## Performance Indicators\n");

    // 1. Poll hit ratio — from aggregated counters
    uint64_t total_polls = agg.total_poll_hit + agg.total_poll_miss;
    if (total_polls > 0) {
        double hit_rate = 100.0 * agg.total_poll_hit / total_polls;
        fprintf(f, "poll_hit_rate: %.1f%%", hit_rate);
        if (hit_rate < 80.0) {
            fprintf(f, " # WARNING: low poll hit rate\n");
        } else {
            fprintf(f, "\n");
        }
    }

    // 2. SW RX drop rate — uses packet-level drops for dimensional consistency.
    if (agg.total_rx_packets > 0) {
        double drop_rate = 100.0 * agg.sw_rx_packets_dropped / agg.total_rx_packets;
        fprintf(f, "sw_rx_drop_rate: %.4f%%", drop_rate);
        if (drop_rate > 0.01) {
            fprintf(f, " # WARNING: non-zero drop rate\n");
        } else {
            fprintf(f, "\n");
        }
    }

    // 3. HW RX drops — from net_device_table_mgr
    if (g_p_net_device_table_mgr) {
        uint64_t hw_drops = g_p_net_device_table_mgr->get_rx_drop_counter();
        fprintf(f, "hw_rx_packets_dropped: %" PRIu64, hw_drops);
        if (hw_drops > 0) {
            fprintf(f, " # WARNING: HW drops detected\n");
        } else {
            fprintf(f, "\n");
        }
    }

    fprintf(f, "\n");
}

/**
 * Log a compact summary of key anomaly metrics to vlog.
 */
static void log_summary_to_vlog(const char *path, vlog_levels_t level)
{
    uint64_t hw_drops = 0;
    uint32_t alloc_failures = 0;

    if (g_p_net_device_table_mgr) {
        hw_drops = g_p_net_device_table_mgr->get_rx_drop_counter();
    }

    buffer_pool *pools[] = {g_buffer_pool_rx_rwqe, g_buffer_pool_rx_stride, g_buffer_pool_tx,
                            g_buffer_pool_rx_ptr, g_buffer_pool_zc};
    for (auto *pool : pools) {
        if (pool) {
            const bpool_stats_t *stats = pool->get_stats();
            if (stats) {
                alloc_failures += stats->n_buffer_pool_no_bufs;
            }
        }
    }

    vlog_printf(level,
                "Tuning report: %s "
                "(hw_rx_drops=%" PRIu64 ", buf_alloc_failures=%" PRIu32 ")\n",
                path, hw_drops, alloc_failures);
}

void finalize_tuning_report()
{
    if (safe_mce_sys().print_report == option_3::OFF) {
        return;
    }

    if (safe_mce_sys().print_report != option_3::ON && !tuning_report_has_errors()) {
        return;
    }
    bool auto_triggered = (safe_mce_sys().print_report != option_3::ON);
    const char *path = safe_mce_sys().report_file_path;

    int rc = generate_tuning_report(path);
    if (rc != 0) {
        vlog_printf(VLOG_WARNING, "Failed to write tuning report to %s\n", path);
        return;
    }

    if (auto_triggered) {
        vlog_printf(VLOG_WARNING,
                    "XLIO detected performance anomalies. "
                    "Diagnostic report written to: %s\n"
                    "Share this report with your XLIO support engineer "
                    "for tuning recommendations.\n",
                    path);
    }

    log_summary_to_vlog(path, auto_triggered ? VLOG_WARNING : VLOG_INFO);
}
