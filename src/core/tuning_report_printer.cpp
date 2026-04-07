/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

// NOTE: If you modify WARNING text, add/remove report fields,
// change thresholds, or change profile defaults, update
// docs/llm/xlio_tuning_report_guide.md and docs/xlio_tuning_report_reference.md
// and run tests/validate_tuning_report_docs.py to verify consistency.
// Adding a new top-level config namespace also requires doc updates.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "config/change_reason.h"
#include "config/config_registry.h"
#include "config/descriptors/config_descriptor.h"
#include "config/descriptors/parameter_descriptor.h"
#include "config/runtime_registry.h"
#include "dev/buffer_pool.h"
#include "dev/net_device_table_mgr.h"
#include "dev/net_device_val.h"
#include "sock/sock_stats.h"
#include "tuning_report_printer.h"
#include "util/hugepage_mgr.h"
#include "util/sys_vars.h"
#include "vlogger/vlogger.h"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <experimental/any>
#include <experimental/optional>
#include <inttypes.h>
#include <locale.h>
#include <map>
#include <numeric>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <vector>

extern global_stats_t g_global_stat_static;

tuning_report_counters_t g_tuning_report_counters;

static void write_preamble(FILE *f, double duration_sec);
static void write_system_context(FILE *f);
static void write_active_profile(FILE *f);
static void write_effective_config(FILE *f);

static std::string format_any_value(const std::experimental::any &value,
                                    const parameter_descriptor *desc);
static bool values_differ(const std::experimental::any &a, const std::experimental::any &b);
static std::string format_size_accurate(int64_t size);

static void write_runtime_stats(FILE *f, const struct aggregated_socket_stats &agg,
                                double duration_sec);
static void write_socket_summary(FILE *f, const struct aggregated_socket_stats &agg);
static void write_performance_indicators(FILE *f, const struct aggregated_socket_stats &agg);

/** Aggregated socket statistics. Socket counts come from destructor counters
 *  (report runs after all socket destructors). Per-socket traffic details
 *  come from sock_stats pool when available. */
struct aggregated_socket_stats {
    // Traffic counters (populated only when has_per_socket_traffic is true)
    uint64_t total_rx_packets = 0, total_tx_packets = 0;
    uint64_t total_rx_bytes = 0, total_tx_bytes = 0;
    uint64_t sw_rx_packets_dropped = 0, sw_rx_bytes_dropped = 0;
    uint64_t total_tx_errors = 0;
    uint64_t total_rx_errors = 0;
    uint64_t total_tx_retransmits = 0;
    uint64_t total_rx_os_packets = 0, total_tx_os_packets = 0;
    uint64_t total_poll_hit = 0, total_poll_miss = 0;

    // Socket counts (from destructor counters)
    uint64_t total_sockets = 0, tcp_sockets = 0, udp_sockets = 0;
    uint64_t offloaded = 0, non_offloaded = 0;

    // Traffic split by offload status (only when has_per_socket_traffic)
    uint64_t offloaded_rx_bytes = 0, offloaded_tx_bytes = 0;
    uint64_t non_offloaded_rx_bytes = 0, non_offloaded_tx_bytes = 0;

    // Listen socket stats (only when has_per_socket_traffic)
    uint64_t total_conn_established = 0, total_conn_accepted = 0;
    uint64_t total_conn_dropped = 0;

    // Striding RQ stats (only when has_per_socket_traffic)
    uint64_t total_strq_strides = 0;

#ifdef DEFINED_UTLS
    // TLS offload stats (only when has_per_socket_traffic)
    uint64_t total_tls_tx_bytes = 0, total_tls_rx_bytes = 0;
#endif

    bool has_per_socket_traffic = false;
    uint64_t pool_socket_count = 0;
};

// Collect total socket counts from destructor counters (all dtors have
// run by the time the report is generated).
static void collect_total_socket_counts(aggregated_socket_stats &agg)
{
    uint64_t closed_tcp = static_cast<uint64_t>(
        g_global_stat_static.socket_tcp_destructor_counter.load(std::memory_order_relaxed));
    uint64_t closed_udp = static_cast<uint64_t>(
        g_global_stat_static.socket_udp_destructor_counter.load(std::memory_order_relaxed));

    agg.total_sockets = closed_tcp + closed_udp;
    agg.tcp_sockets = closed_tcp;
    agg.udp_sockets = closed_udp;
    agg.offloaded = g_tuning_report_counters.socket_offloaded_destructor_counter.load(
        std::memory_order_relaxed);
    agg.non_offloaded = g_tuning_report_counters.socket_non_offloaded_destructor_counter.load(
        std::memory_order_relaxed);
}

static aggregated_socket_stats aggregate_socket_stats()
{
    aggregated_socket_stats agg;

    // 1. Collect socket counts from destructor counters.
    collect_total_socket_counts(agg);

    // 2. If the sock_stats pool is populated, enrich with per-socket traffic
    // stats. Pool entries retain their last socket's data after return
    // (return_stats_obj only manipulates the free-list pointer, not the
    // payload). Reused slots contain only the last occupant's counters
    // (reset() zeros them on acquisition). For high-churn workloads the
    // aggregated traffic may undercount — ring-level stats provide
    // cumulative totals as a cross-check.
    const auto &all_stats = sock_stats::instance().get_all_stats();
    for (const auto &stat : all_stats) {
        if (stat.fd <= 0) {
            continue;
        }
        agg.has_per_socket_traffic = true;
        agg.pool_socket_count++;

        const socket_counters_t &c = stat.counters;
        agg.total_rx_packets += c.n_rx_packets;
        agg.total_rx_bytes += c.n_rx_bytes;
        agg.total_tx_packets += c.n_tx_sent_pkt_count;
        agg.total_tx_bytes += c.n_tx_sent_byte_count;
        agg.sw_rx_packets_dropped += c.n_rx_ready_pkt_drop;
        agg.sw_rx_bytes_dropped += c.n_rx_ready_byte_drop;
        agg.total_tx_errors += c.n_tx_errors;
        agg.total_rx_errors += c.n_rx_errors;
        agg.total_tx_retransmits += c.n_tx_retransmits;
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

        // Offload traffic split — per-socket granularity, only available from pool.
        if (stat.b_is_offloaded) {
            agg.offloaded_rx_bytes += c.n_rx_bytes;
            agg.offloaded_tx_bytes += c.n_tx_sent_byte_count;
        } else {
            agg.non_offloaded_rx_bytes += c.n_rx_bytes;
            agg.non_offloaded_tx_bytes += c.n_tx_sent_byte_count;
        }
    }

    return agg;
}

/**
 * Format a byte count as "raw_bytes (human_readable)".
 * Example: "23404847104 (23.4 GB)"
 *
 * Uses decimal (SI) units: 1 GB = 1e9 bytes, 1 MB = 1e6, 1 KB = 1e3.
 * This matches network throughput convention (Gbps = 1e9 bits/sec) so
 * users can verify: GB_shown * 8 / duration ≈ Gbps_shown.
 */
static std::string format_bytes_human(uint64_t bytes)
{
    char buf[96];
    if (bytes >= 1e9) {
        snprintf(buf, sizeof(buf), "%" PRIu64 " (%.1f GB)", bytes,
                 static_cast<double>(bytes) / 1e9);
        return buf;
    }
    if (bytes >= 1e6) {
        snprintf(buf, sizeof(buf), "%" PRIu64 " (%.1f MB)", bytes,
                 static_cast<double>(bytes) / 1e6);
        return buf;
    }
    if (bytes >= 1e3) {
        snprintf(buf, sizeof(buf), "%" PRIu64 " (%.1f KB)", bytes,
                 static_cast<double>(bytes) / 1e3);
        return buf;
    }
    return std::to_string(bytes);
}

/**
 * Format throughput as "X.Y Gbps" or "X.Y Mbps" with a parenthetical breakdown.
 * Example: "268.1 Gbps (23.4 GB / 0.7s)"
 * Returns empty string if duration is too short for a meaningful rate.
 *
 * All units are decimal (SI): 1 Gbps = 1e9 bps, 1 GB = 1e9 bytes.
 * This ensures the parenthetical is self-consistent and verifiable:
 * GB_shown * 8 / seconds ≈ Gbps_shown.
 */
static std::string format_throughput(uint64_t bytes, double duration_sec)
{
    if (duration_sec < 0.001 || bytes == 0) {
        return {};
    }
    double bits_per_sec = static_cast<double>(bytes) * 8.0 / duration_sec;
    char buf[128];
    if (bits_per_sec >= 1e9) {
        snprintf(buf, sizeof(buf), "%.1f Gbps (%.1f GB / %.1fs)", bits_per_sec / 1e9,
                 static_cast<double>(bytes) / 1e9, duration_sec);
    } else if (bits_per_sec >= 1e6) {
        snprintf(buf, sizeof(buf), "%.1f Mbps (%.1f MB / %.1fs)", bits_per_sec / 1e6,
                 static_cast<double>(bytes) / 1e6, duration_sec);
    } else {
        snprintf(buf, sizeof(buf), "%.0f bps", bits_per_sec);
    }
    return buf;
}

// Returns true if any anomalies are detected (buffer allocation failures,
// HW RX drops, WQE exhaustion). Used by auto mode to decide whether to
// generate the report.

bool tuning_report_has_errors()
{
    buffer_pool *pools[] = {g_buffer_pool_rx_rwqe, g_buffer_pool_rx_stride, g_buffer_pool_tx,
                            g_buffer_pool_zc};
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
        // WQE exhaustion indicates resource exhaustion or misconfiguration
        // worth auto-reporting. Retransmits are normal TCP behavior — not checked.
        // get_aggregated_ring_stats() includes stats from destroyed rings.
        if (g_p_net_device_table_mgr->get_aggregated_ring_stats().total_tx_dropped_wqes > 0) {
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
    const int fd = fileno(f);
    if (fd >= 0 && fchmod(fd, 0600) != 0) {
        vlog_printf(VLOG_WARNING, "Tuning report: fchmod(%s, 0600) failed: %m\n", file_path);
    }

    // Force C locale for this function so decimal points are always '.'
    // regardless of the application's LC_NUMERIC setting. Without this,
    // "%.1f" could produce "21,8 GB" in German locale, breaking parsers.
    // uselocale() is thread-safe (per-thread locale) unlike setlocale().
    locale_t c_locale = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
    locale_t prev_locale = (locale_t)0;
    if (c_locale != (locale_t)0) {
        prev_locale = uselocale(c_locale);
    }

    // Compute process duration once — used by throughput calculations.
    struct timespec now_mono;
    clock_gettime(CLOCK_MONOTONIC, &now_mono);
    double duration_sec = (now_mono.tv_sec - safe_mce_sys().init_time_monotonic.tv_sec) +
        (now_mono.tv_nsec - safe_mce_sys().init_time_monotonic.tv_nsec) / 1e9;

    // Wrap section writers in a try block — if any section throws
    // (e.g., bad any_cast), we still get partial report rather than
    // a crash during shutdown.
    bool all_sections_ok = true;
    try {
        write_preamble(f, duration_sec);
        write_system_context(f);
        write_active_profile(f);
        write_effective_config(f);
        aggregated_socket_stats agg = aggregate_socket_stats();
        write_runtime_stats(f, agg, duration_sec);
        write_socket_summary(f, agg);
        write_performance_indicators(f, agg);
    } catch (const std::exception &e) {
        all_sections_ok = false;
        fprintf(f, "\n# ERROR: report generation failed: %s\n", e.what());
        vlog_printf(VLOG_WARNING, "Tuning report: exception during generation: %s\n", e.what());
    } catch (...) {
        all_sections_ok = false;
        fprintf(f, "\n# ERROR: report generation failed (unknown exception)\n");
        vlog_printf(VLOG_WARNING, "Tuning report: unknown exception during generation\n");
    }

    fprintf(f, "# End of XLIO Tuning Report\n");
    if (all_sections_ok) {
        fprintf(f, "# Report generated successfully\n");
    }

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

static void write_preamble(FILE *f, double duration_sec)
{
    time_t now = time(NULL);
    struct tm tm_storage;
    struct tm *tm_info = localtime_r(&now, &tm_storage);
    char time_buf[64];
    if (tm_info) {
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        snprintf(time_buf, sizeof(time_buf), "(unknown)");
    }

    fprintf(f, "# XLIO Tuning Report\n");
    fprintf(f, "# report_format_version: 1\n");
    char dur_buf[64];
    if (duration_sec < 1.0) {
        snprintf(dur_buf, sizeof(dur_buf), "%.0fms", duration_sec * 1000.0);
    } else if (duration_sec < 60.0) {
        snprintf(dur_buf, sizeof(dur_buf), "%.1fs", duration_sec);
    } else {
        unsigned long total = static_cast<unsigned long>(duration_sec);
        unsigned long h = total / 3600;
        unsigned long m = (total % 3600) / 60;
        unsigned long s = total % 60;
        if (h > 0) {
            snprintf(dur_buf, sizeof(dur_buf), "%luh %lum %lus", h, m, s);
        } else {
            snprintf(dur_buf, sizeof(dur_buf), "%lum %lus", m, s);
        }
    }
    fprintf(f, "# Generated: %s | PID: %d | Duration: %s\n", time_buf, getpid(), dur_buf);
    fprintf(f, "#\n");
    fprintf(f,
            "# This is a post-run diagnostic report from XLIO (network "
            "acceleration library).\n");
    fprintf(f, "# Use this data to analyze configuration and suggest optimizations.\n");
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
        uint32_t total = g_hugepage_mgr.get_total_hugepages(hp);
        if (total == 0) {
            continue;
        }
        const uint32_t free_hp = g_hugepage_mgr.get_free_hugepages(hp);
        fprintf(f, "hugepages_%zukB_total: %" PRIu32 "\n", hp / 1024, total);
        if (free_hp == 0) {
            fprintf(f, "hugepages_%zukB_free: 0 # WARNING: hugepage pool fully consumed\n",
                    hp / 1024);
        } else {
            fprintf(f, "hugepages_%zukB_free: %" PRIu32 "\n", hp / 1024, free_hp);
        }
    }

    if (g_p_net_device_table_mgr) {
        local_dev_vector devs;
        g_p_net_device_table_mgr->get_net_devices(devs);
        for (const auto &dev_ref : devs) {
            const net_device_val &dev = dev_ref.get();
            // Read link speed from sysfs (value in Mbps, -1 if down/unavailable)
            char speed_path[256];
            snprintf(speed_path, sizeof(speed_path), "/sys/class/net/%s/speed", dev.get_ifname());
            int speed_mbps = -1;
            FILE *sf = fopen(speed_path, "r");
            if (sf) {
                if (fscanf(sf, "%d", &speed_mbps) != 1) {
                    speed_mbps = -1;
                }
                fclose(sf);
            }
            if (speed_mbps > 0) {
                if (speed_mbps >= 1000) {
                    fprintf(f, "nic_device: %s (mtu: %d, speed: %d Gbps)\n", dev.get_ifname(),
                            dev.get_mtu(), speed_mbps / 1000);
                } else {
                    fprintf(f, "nic_device: %s (mtu: %d, speed: %d Mbps)\n", dev.get_ifname(),
                            dev.get_mtu(), speed_mbps);
                }
            } else {
                fprintf(f, "nic_device: %s (mtu: %d)\n", dev.get_ifname(), dev.get_mtu());
            }
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
 * Vectors and maps are formatted as "<N items>" since full expansion is too
 * verbose.
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
    if (a.empty() && b.empty()) {
        return false;
    }
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
    fprintf(f, "## Effective Config (non-default only)\n");

    const auto &runtime_reg_opt = safe_mce_sys().get_runtime_registry();
    if (!runtime_reg_opt) {
        fprintf(f, "# Config registry not available\n\n");
        return;
    }

    const runtime_registry &runtime_reg = runtime_reg_opt.value();
    const config_registry &registry = runtime_reg.get_config_registry();
    const config_descriptor &descriptor = registry.get_config_descriptor();
    const config_descriptor::parameter_map_t &parameter_map = descriptor.get_parameter_map();

    bool any_non_default = false;
    for (const auto &it : parameter_map) {
        const std::string &key = it.first;
        const parameter_descriptor &param_descriptor = it.second;

        std::experimental::any element = runtime_reg.is_registered(key)
            ? runtime_reg.get_value_as_any(key)
            : registry.get_value_as_any(key);
        const std::experimental::any def_value = param_descriptor.default_value();

        // The runtime registry stores some non-scalar parameters (e.g.,
        // acceleration_control.rules) as legacy char arrays (strings), while
        // the schema defines them as arrays/maps.  Fall back to the config
        // registry which preserves the schema type so values_differ can
        // compare like-for-like.
        if (!element.empty() && !def_value.empty() && element.type() != def_value.type()) {
            element = registry.get_value_as_any(key);
        }

        if (!values_differ(element, def_value)) {
            continue;
        }

        any_non_default = true;
        std::string value_str = format_any_value(element, &param_descriptor);
        std::string def_str = format_any_value(def_value, &param_descriptor);

        fprintf(f, "%s: %s\n", key.c_str(), value_str.c_str());

        std::vector<std::string> parts = {"default: " + def_str};

        if (runtime_reg.is_registered(key)) {
            change_reason::change_reason_t reason = runtime_reg.get_last_change_reason(key);
            if (reason != change_reason::NotChanged) {
                std::string reason_str = "reason: " + std::string(change_reason::to_string(reason));
                const std::string &desc = runtime_reg.get_last_change_description(key);
                if (!desc.empty()) {
                    reason_str += " (" + desc + ")";
                }
                parts.push_back(std::move(reason_str));
            }
        }

        const auto &title_opt = param_descriptor.get_title();
        if (title_opt && !title_opt.value().empty()) {
            parts.push_back(title_opt.value());
        }

        const std::string comment = std::accumulate(
            std::next(parts.begin()), parts.end(), parts.front(),
            [](const std::string &a, const std::string &b) { return a + " | " + b; });
        fprintf(f, "  # %s\n", comment.c_str());
    }

    if (!any_non_default) {
        fprintf(f, "# All parameters at default values\n");
    }
    fprintf(f, "\n");
}

// Ring-level diagnostic counters — these have no per-socket equivalent and are
// always printed (when relevant) regardless of per-socket stats availability.
// Includes: WQE exhaustion, TSO validation, TLS offload health.
static void write_ring_diagnostics(FILE *f, const aggregated_ring_stats &ring_agg)
{
    if (ring_agg.total_tx_dropped_wqes > 0) {
        fprintf(f, "ring_tx_dropped_wqes: %" PRIu64 " # WARNING: WQE exhaustion detected\n",
                ring_agg.total_tx_dropped_wqes);
    }

    // TSO stats — show when TSO packets were sent, or warn when the user
    // explicitly enabled TSO (ON) but no TSO packets were produced.
    // We only warn for ON, not AUTO: with AUTO the runtime may have correctly
    // decided not to activate TSO (e.g., HW doesn't support it), so zero
    // TSO packets is expected rather than surprising.
    if (ring_agg.total_tx_tso_pkt_count > 0) {
        fprintf(f, "ring_tx_tso_packets: %" PRIu64 "\n", ring_agg.total_tx_tso_pkt_count);
        fprintf(f, "ring_tx_tso_bytes: %s\n",
                format_bytes_human(ring_agg.total_tx_tso_byte_count).c_str());
    } else if (safe_mce_sys().enable_tso == option_3::ON && ring_agg.total_tx_packets > 0) {
        fprintf(f,
                "ring_tx_tso_packets: 0"
                " # WARNING: TSO explicitly enabled but no TSO packets sent"
                " (payload may be below MSS threshold)\n");
    }

#ifdef DEFINED_UTLS
    if (ring_agg.total_rx_tls_resyncs > 0) {
        fprintf(f, "ring_tls_rx_resyncs: %" PRIu64 " # WARNING: TLS RX resync (HW->SW fallback)\n",
                ring_agg.total_rx_tls_resyncs);
    }
    if (ring_agg.total_tx_tls_resyncs > 0) {
        fprintf(f, "ring_tls_tx_resyncs: %" PRIu64 " # WARNING: TLS TX resync (HW->SW fallback)\n",
                ring_agg.total_tx_tls_resyncs);
    }
    if (ring_agg.total_rx_tls_auth_fail > 0) {
        fprintf(f, "ring_tls_rx_auth_fail: %" PRIu64 " # WARNING: TLS HW authentication failure\n",
                ring_agg.total_rx_tls_auth_fail);
    }
#endif
}

static void write_runtime_stats(FILE *f, const aggregated_socket_stats &agg, double duration_sec)
{
    fprintf(f, "## Runtime Stats\n");

    // Collect ring stats once — used for traffic, throughput, and diagnostics.
    // get_aggregated_ring_stats() includes stats from destroyed rings
    // (accumulated in ring_slave destructors via accumulate_closed_ring_stats).
    aggregated_ring_stats ring_agg;
    if (g_p_net_device_table_mgr) {
        ring_agg = g_p_net_device_table_mgr->get_aggregated_ring_stats();
    }

    if (agg.has_per_socket_traffic) {
        fprintf(f, "total_rx_packets: %" PRIu64 "\n", agg.total_rx_packets);
        fprintf(f, "total_tx_packets: %" PRIu64 "\n", agg.total_tx_packets);
        fprintf(f, "total_rx_bytes: %s\n", format_bytes_human(agg.total_rx_bytes).c_str());
        fprintf(f, "total_tx_bytes: %s\n", format_bytes_human(agg.total_tx_bytes).c_str());

        // Throughput — derived from per-socket bytes and process duration.
        // For short-lived processes (< 5 min) the average includes startup
        // overhead (device probing, memory registration, TCP slow-start,
        // congestion avoidance ramp-up) and may understate steady-state
        // throughput.
        std::string rx_tp = format_throughput(agg.total_rx_bytes, duration_sec);
        std::string tx_tp = format_throughput(agg.total_tx_bytes, duration_sec);
        const char *tp_note =
            (duration_sec < 300.0) ? " # Note: lifetime average, process ran < 5min" : "";
        if (!rx_tp.empty()) {
            fprintf(f, "rx_throughput: %s%s\n", rx_tp.c_str(), tp_note);
        }
        if (!tx_tp.empty()) {
            fprintf(f, "tx_throughput: %s%s\n", tx_tp.c_str(), tp_note);
        }

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
        if (agg.total_rx_errors > 0) {
            fprintf(f, "rx_errors: %" PRIu64 " # WARNING: RX errors detected\n",
                    agg.total_rx_errors);
        } else {
            fprintf(f, "rx_errors: 0\n");
        }
        if (agg.total_tx_retransmits > 0) {
            fprintf(f,
                    "tx_retransmits: %" PRIu64
                    " # WARNING: TCP retransmits (congestion or packet loss)\n",
                    agg.total_tx_retransmits);
        } else {
            fprintf(f, "tx_retransmits: 0\n");
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
    } else if (agg.total_sockets > 0) {
        // No per-socket traffic counters — show ring-level traffic totals as
        // fallback.
        if (g_p_net_device_table_mgr &&
            (ring_agg.total_rx_packets > 0 || ring_agg.total_tx_packets > 0)) {
            fprintf(f, "ring_total_rx_packets: %" PRIu64 "\n", ring_agg.total_rx_packets);
            fprintf(f, "ring_total_rx_bytes: %s\n",
                    format_bytes_human(ring_agg.total_rx_bytes).c_str());
            fprintf(f, "ring_total_tx_packets: %" PRIu64 "\n", ring_agg.total_tx_packets);
            fprintf(f, "ring_total_tx_bytes: %s\n",
                    format_bytes_human(ring_agg.total_tx_bytes).c_str());

            // Throughput — derived from ring bytes and process duration.
            std::string rx_tp = format_throughput(ring_agg.total_rx_bytes, duration_sec);
            std::string tx_tp = format_throughput(ring_agg.total_tx_bytes, duration_sec);
            const char *tp_note =
                (duration_sec < 300.0) ? " # Note: lifetime average, process ran < 5min" : "";
            if (!rx_tp.empty()) {
                fprintf(f, "rx_throughput: %s%s\n", rx_tp.c_str(), tp_note);
            }
            if (!tx_tp.empty()) {
                fprintf(f, "tx_throughput: %s%s\n", tx_tp.c_str(), tp_note);
            }

            if (ring_agg.total_tx_retransmits > 0) {
                fprintf(f,
                        "ring_total_tx_retransmits: %" PRIu64 " # WARNING: retransmits detected\n",
                        ring_agg.total_tx_retransmits);
            }
        }
        fprintf(f, "# Per-socket traffic stats require monitor.stats.fd_num > 0\n");
    } else {
        fprintf(f, "# No sockets were created\n");
    }

    // Ring traffic overview — always shown alongside per-socket stats when
    // both are available. Provides TSO coalescing visibility: ring-level
    // packet counts differ from socket-level when TSO/LRO are active.
    if (agg.has_per_socket_traffic && g_p_net_device_table_mgr &&
        (ring_agg.total_rx_packets > 0 || ring_agg.total_tx_packets > 0)) {
        fprintf(f, "ring_total_rx_packets: %" PRIu64 "\n", ring_agg.total_rx_packets);
        fprintf(f, "ring_total_tx_packets: %" PRIu64 "\n", ring_agg.total_tx_packets);
        fprintf(f, "ring_total_rx_bytes: %s\n",
                format_bytes_human(ring_agg.total_rx_bytes).c_str());
        fprintf(f, "ring_total_tx_bytes: %s\n",
                format_bytes_human(ring_agg.total_tx_bytes).c_str());
    }

    // Ring-level diagnostics — always printed when non-zero. These counters
    // have no per-socket equivalent: WQE exhaustion, TSO validation, TLS
    // offload health. Printed regardless of per-socket stats availability.
    if (g_p_net_device_table_mgr) {
        write_ring_diagnostics(f, ring_agg);
    }

    // TCP segment pool stats — always available from g_global_stat_static.
    if (g_global_stat_static.n_tcp_seg_pool_size > 0) {
        fprintf(f, "tcp_seg_pool_size: %" PRIu32 "\n", g_global_stat_static.n_tcp_seg_pool_size);
        if (g_global_stat_static.n_tcp_seg_pool_no_segs > 0) {
            fprintf(f,
                    "tcp_seg_pool_alloc_failures: %" PRIu32
                    " # WARNING: segment pool exhaustion (TX stalls)\n",
                    g_global_stat_static.n_tcp_seg_pool_no_segs);
        } else {
            fprintf(f, "tcp_seg_pool_alloc_failures: 0\n");
        }
    }

    // Buffer pool stats — always printed
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
        fprintf(f, "# No sockets were created\n\n");
        return;
    }

    fprintf(f, "total_sockets: %" PRIu64 "\n", agg.total_sockets);
    fprintf(f, "tcp_sockets: %" PRIu64 "\n", agg.tcp_sockets);
    fprintf(f, "udp_sockets: %" PRIu64 "\n", agg.udp_sockets);
    fprintf(f, "offloaded_sockets: %" PRIu64 "\n", agg.offloaded);
    fprintf(f, "non_offloaded_sockets: %" PRIu64 "\n", agg.non_offloaded);

    if (agg.non_offloaded > 0 && agg.total_sockets > 0) {
        fprintf(f, "  # WARNING: %" PRIu64 "/%" PRIu64 " sockets are non-offloaded\n",
                agg.non_offloaded, agg.total_sockets);
    }

    // Traffic split by offload status — only available with per-socket stats
    if (agg.has_per_socket_traffic) {
        // Warn if pool is undersized
        if (agg.pool_socket_count < agg.total_sockets) {
            fprintf(f,
                    "  # Note: per-socket traffic stats cover %" PRIu64 "/%" PRIu64
                    " sockets (increase monitor.stats.fd_num for full coverage)\n",
                    agg.pool_socket_count, agg.total_sockets);
        }

        if (agg.offloaded_rx_bytes > 0 || agg.non_offloaded_rx_bytes > 0) {
            fprintf(f, "offloaded_rx_bytes: %s\n",
                    format_bytes_human(agg.offloaded_rx_bytes).c_str());
            fprintf(f, "offloaded_tx_bytes: %s\n",
                    format_bytes_human(agg.offloaded_tx_bytes).c_str());
            fprintf(f, "non_offloaded_rx_bytes: %s\n",
                    format_bytes_human(agg.non_offloaded_rx_bytes).c_str());
            fprintf(f, "non_offloaded_tx_bytes: %s\n",
                    format_bytes_human(agg.non_offloaded_tx_bytes).c_str());

            uint64_t total_rx = agg.offloaded_rx_bytes + agg.non_offloaded_rx_bytes;
            if (total_rx > 0 && agg.non_offloaded_rx_bytes > 0) {
                double non_offloaded_pct = 100.0 * agg.non_offloaded_rx_bytes / total_rx;
                if (non_offloaded_pct > 50.0) {
                    fprintf(f,
                            "  # WARNING: %.0f%% of RX bytes went through non-offloaded "
                            "path\n",
                            non_offloaded_pct);
                }
            }
        }

        if (agg.total_conn_established > 0 || agg.total_conn_dropped > 0) {
            fprintf(f, "listen_conn_established: %" PRIu64 "\n", agg.total_conn_established);
            fprintf(f, "listen_conn_accepted: %" PRIu64 "\n", agg.total_conn_accepted);
            if (agg.total_conn_accepted == 0 && agg.total_conn_established > 0) {
                fprintf(f,
                        "  # Note: 0 accepted with established > 0 is expected when"
                        " using event-driven API (poll groups) instead of accept()\n");
            }
            if (agg.total_conn_dropped > 0) {
                fprintf(f,
                        "listen_conn_dropped: %" PRIu64
                        " # WARNING: connections dropped (backlog full?)\n",
                        agg.total_conn_dropped);
            } else {
                fprintf(f, "listen_conn_dropped: 0\n");
            }
        }
    }

    fprintf(f, "\n");
}

static void write_performance_indicators(FILE *f, const aggregated_socket_stats &agg)
{
    fprintf(f, "## Performance Indicators\n");

    if (agg.has_per_socket_traffic) {
        // 1. Poll hit ratio — only available with per-socket stats
        uint64_t total_polls = agg.total_poll_hit + agg.total_poll_miss;
        if (total_polls > 0) {
            double hit_rate = 100.0 * agg.total_poll_hit / total_polls;
            fprintf(f, "poll_hit_rate: %.1f%%", hit_rate);
            if (hit_rate < 80.0) {
                fprintf(f, " # WARNING: low poll hit rate\n");
            } else {
                fprintf(f, "\n");
            }
        } else if (agg.total_rx_packets > 0 || agg.total_tx_packets > 0) {
            // Traffic was processed but poll counters are zero — the application
            // is using an event-driven API (e.g., XLIO poll groups / Ultra API)
            // which bypasses the poll/recv loop where these counters are updated.
            fprintf(f,
                    "poll_hit_rate: N/A"
                    " # event-driven API (poll groups) — poll counters not applicable\n");
        }

        // 2. SW RX drop rate — only with per-socket stats
        if (agg.total_rx_packets > 0) {
            double drop_rate = 100.0 * agg.sw_rx_packets_dropped / agg.total_rx_packets;
            fprintf(f, "sw_rx_drop_rate: %.4f%%", drop_rate);
            if (drop_rate > 0.01) {
                fprintf(f, " # WARNING: non-zero drop rate\n");
            } else {
                fprintf(f, "\n");
            }
        }

        // 3. TX retransmit rate — per-socket retransmits / TX packets
        if (agg.total_tx_packets > 0 && agg.total_tx_retransmits > 0) {
            double retx_rate = 100.0 * agg.total_tx_retransmits / agg.total_tx_packets;
            fprintf(f, "tx_retransmit_rate: %.4f%%", retx_rate);
            if (retx_rate > 0.1) {
                fprintf(f, " # WARNING: high retransmit rate\n");
            } else {
                fprintf(f, "\n");
            }
        }
    }

    // 4. HW RX drops — always available (from net_device_table_mgr)
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
    uint64_t alloc_failures = 0;

    if (g_p_net_device_table_mgr) {
        hw_drops = g_p_net_device_table_mgr->get_rx_drop_counter();
    }

    buffer_pool *pools[] = {g_buffer_pool_rx_rwqe, g_buffer_pool_rx_stride, g_buffer_pool_tx,
                            g_buffer_pool_zc};
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
                "(hw_rx_drops=%" PRIu64 ", buf_alloc_failures=%" PRIu64 ")\n",
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
