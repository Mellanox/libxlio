/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "util/sys_vars_configurator.h"

#include <cinttypes>
#include <experimental/any>
#include <numeric>
#include <unistd.h>

#include "config/change_reason.h"
#include "config/config_var_definitions.h"
#include "util/sys_vars.h"
#include "vlogger/vlogger.h"

const config_var_info_t<option_3::mode_t, int64_t> CONFIG_VAR_PRINT_REPORT {"monitor.exit_report"};
const config_var_info_t<vlog_levels_t, int64_t> CONFIG_VAR_LOG_LEVEL {"monitor.log.level"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_LOG_DETAILS {"monitor.log.details"};

const config_var_info_t<std::string> CONFIG_VAR_LOG_FILENAME {"monitor.log.file_path"};
const config_var_info_t<std::string> CONFIG_VAR_STATS_FILENAME {"monitor.stats.file_path"};
const config_var_info_t<std::string> CONFIG_VAR_STATS_SHMEM_DIRNAME {"monitor.stats.shmem_dir"};
const config_var_info_t<std::string> CONFIG_VAR_SERVICE_DIR {"core.daemon.dir"};
const config_var_info_t<std::string> CONFIG_VAR_APPLICATION_ID {"acceleration_control.app_id"};
const config_var_info_t<std::string> CONFIG_VAR_ACCEL_CONTROL_RULES {"acceleration_control.rules"};
const config_var_info_t<std::string> CONFIG_VAR_INTERNAL_THREAD_AFFINITY {
    "performance.threading.cpu_affinity"};
const config_var_info_t<std::string> CONFIG_VAR_INTERNAL_THREAD_CPUSET {
    "performance.threading.cpuset"};

const config_var_info_t<bool> CONFIG_VAR_SERVICE_ENABLE {"core.daemon.enable"};
const config_var_info_t<bool> CONFIG_VAR_LOG_COLORS {"monitor.log.colors"};
const config_var_info_t<bool> CONFIG_VAR_HANDLE_SIGINTR {"core.signals.sigint.exit"};
const config_var_info_t<bool> CONFIG_VAR_HANDLE_SIGSEGV {"core.signals.sigsegv.backtrace"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_STATS_FD_NUM {"monitor.stats.fd_num"};
const config_var_info_t<bool> CONFIG_VAR_QUICK_START {"core.quick_init"};

const config_var_info_t<ring_logic_t, int64_t> CONFIG_VAR_RING_ALLOCATION_LOGIC_TX {
    "performance.rings.tx.allocation_logic"};
const config_var_info_t<ring_logic_t, int64_t> CONFIG_VAR_RING_ALLOCATION_LOGIC_RX {
    "performance.rings.rx.allocation_logic"};
const config_var_info_t<int, int64_t> CONFIG_VAR_RING_MIGRATION_RATIO_TX {
    "performance.rings.tx.migration_ratio"};
const config_var_info_t<int, int64_t> CONFIG_VAR_RING_MIGRATION_RATIO_RX {
    "performance.rings.rx.migration_ratio"};
const config_var_info_t<int, int64_t> CONFIG_VAR_RING_LIMIT_PER_INTERFACE {
    "performance.rings.max_per_interface"};
const config_var_info_t<int, int64_t> CONFIG_VAR_RING_DEV_MEM_TX {
    "performance.rings.tx.max_on_device_memory"};

const config_var_info_t<size_t, int64_t> CONFIG_VAR_ZC_CACHE_THRESHOLD {
    "core.syscall.sendfile_cache_limit"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TX_BUF_SIZE {
    "performance.buffers.tx.buf_size"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TCP_NODELAY_TRESHOLD {
    "network.protocols.tcp.nodelay.byte_threshold"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TX_NUM_WRE {
    "performance.rings.tx.ring_elements_count"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TX_NUM_WRE_TO_SIGNAL {
    "performance.rings.tx.completion_batch_size"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TX_MAX_INLINE {
    "performance.rings.tx.max_inline_size"};
const config_var_info_t<bool> CONFIG_VAR_TX_MC_LOOPBACK {"network.multicast.mc_loopback"};
const config_var_info_t<bool> CONFIG_VAR_TX_NONBLOCKED_EAGAINS {
    "performance.polling.nonblocking_eagain"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TX_PREFETCH_BYTES {
    "performance.buffers.tx.prefetch_size"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TX_BUFS_BATCH_UDP {
    "performance.rings.tx.udp_buffer_batch"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TX_BUFS_BATCH_TCP {
    "performance.rings.tx.tcp_buffer_batch"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TX_SEGS_BATCH_TCP {
    "performance.buffers.tcp_segments.socket_batch_size"};

const config_var_info_t<bool> CONFIG_VAR_STRQ {"hardware_features.striding_rq.enable"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_STRQ_NUM_STRIDES {
    "hardware_features.striding_rq.strides_num"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_STRQ_STRIDE_SIZE_BYTES {
    "hardware_features.striding_rq.stride_size"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_STRQ_STRIDES_COMPENSATION_LEVEL {
    "performance.rings.rx.spare_strides"};

const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_RX_BUF_SIZE {
    "performance.buffers.rx.buf_size"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_RX_NUM_WRE {
    "performance.rings.rx.ring_elements_count"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_RX_NUM_WRE_TO_POST_RECV {
    "performance.rings.rx.post_batch_size"};
const config_var_info_t<int32_t, int64_t> CONFIG_VAR_RX_NUM_POLLS {
    "performance.polling.blocking_rx_poll_usec"};
const config_var_info_t<int32_t, int64_t> CONFIG_VAR_RX_NUM_POLLS_INIT {
    "performance.polling.offload_transition_poll_count"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_RX_UDP_POLL_OS_RATIO {
    "performance.polling.rx_kernel_fd_attention_level"};
const config_var_info_t<ts_conversion_mode_t, int64_t> CONFIG_VAR_HW_TS_CONVERSION_MODE {
    "network.timing.hw_ts_conversion"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_RX_POLL_YIELD {
    "performance.polling.yield_on_poll"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_RX_BYTE_MIN_LIMIT {
    "performance.override_rcvbuf_limit"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_RX_PREFETCH_BYTES {
    "performance.buffers.rx.prefetch_size"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_RX_PREFETCH_BYTES_BEFORE_POLL {
    "performance.buffers.rx.prefetch_before_poll"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_RX_CQ_DRAIN_RATE_NSEC {
    "performance.completion_queue.rx_drain_rate_nsec"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_GRO_STREAMS_MAX {
    "performance.max_gro_streams"};
const config_var_info_t<bool> CONFIG_VAR_DISABLE_FLOW_TAG {
    "performance.steering_rules.disable_flowtag"};
const config_var_info_t<bool> CONFIG_VAR_TCP_2T_RULES {"performance.steering_rules.tcp.2t_rules"};
const config_var_info_t<bool> CONFIG_VAR_TCP_3T_RULES {"performance.steering_rules.tcp.3t_rules"};
const config_var_info_t<bool> CONFIG_VAR_UDP_3T_RULES {"performance.steering_rules.udp.3t_rules"};
const config_var_info_t<bool> CONFIG_VAR_ETH_MC_L2_ONLY_RULES {
    "performance.steering_rules.udp.only_mc_l2_rules"};
const config_var_info_t<bool> CONFIG_VAR_MC_FORCE_FLOWTAG {
    "network.multicast.mc_flowtag_acceleration"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TX_SEGS_RING_BATCH_TCP {
    "performance.buffers.tcp_segments.ring_batch_size"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TX_SEGS_POOL_BATCH_TCP {
    "performance.buffers.tcp_segments.pool_batch_size"};

const config_var_info_t<bool> CONFIG_VAR_SELECT_CPU_USAGE_STATS {"monitor.stats.cpu_usage"};
const config_var_info_t<int32_t, int64_t> CONFIG_VAR_SELECT_NUM_POLLS {
    "performance.polling.iomux.poll_usec"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_SELECT_POLL_OS_RATIO {
    "performance.polling.iomux.poll_os_ratio"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_SELECT_SKIP_OS {
    "performance.polling.iomux.skip_os"};

const config_var_info_t<bool> CONFIG_VAR_CQ_MODERATION_ENABLE {
    "performance.completion_queue.interrupt_moderation.enable"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_CQ_MODERATION_COUNT {
    "performance.completion_queue.interrupt_moderation.packet_count"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_CQ_MODERATION_PERIOD_USEC {
    "performance.completion_queue.interrupt_moderation.period_usec"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_CQ_AIM_MAX_COUNT {
    "performance.completion_queue.interrupt_moderation.adaptive_count"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_CQ_AIM_MAX_PERIOD_USEC {
    "performance.completion_queue.interrupt_moderation.adaptive_period_usec"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_CQ_AIM_INTERVAL_MSEC {
    "performance.completion_queue.interrupt_moderation.adaptive_change_frequency_msec"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_CQ_AIM_INTERRUPTS_RATE_PER_SEC {
    "performance.completion_queue.interrupt_moderation.adaptive_interrupt_per_sec"};

const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_CQ_POLL_BATCH_MAX {
    "performance.polling.max_rx_poll_batch"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_PROGRESS_ENGINE_INTERVAL {
    "performance.completion_queue.periodic_drain_msec"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_PROGRESS_ENGINE_WCE_MAX {
    "performance.completion_queue.periodic_drain_max_cqes"};
const config_var_info_t<bool> CONFIG_VAR_CQ_KEEP_QP_FULL {"performance.completion_queue.keep_full"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_QP_COMPENSATION_LEVEL {
    "performance.rings.rx.spare_buffers"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_MAX_TSO_SIZE {
    "hardware_features.tcp.tso.max_size"};
const config_var_info_t<uint16_t, int64_t> CONFIG_VAR_WORKER_THREADS {
    "performance.threading.worker_threads"};
const config_var_info_t<bool> CONFIG_VAR_OFFLOADED_SOCKETS {
    "acceleration_control.default_acceleration"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TIMER_RESOLUTION_MSEC {
    "performance.threading.internal_handler.timer_msec"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TCP_TIMER_RESOLUTION_MSEC {
    "network.protocols.tcp.timer_msec"};
const config_var_info_t<option_tcp_ctl_thread::mode_t, int64_t> CONFIG_VAR_TCP_CTL_THREAD {
    "performance.threading.internal_handler.behavior"};
const config_var_info_t<tcp_ts_opt_t, int64_t> CONFIG_VAR_TCP_TIMESTAMP_OPTION {
    "network.protocols.tcp.timestamps"};
const config_var_info_t<bool> CONFIG_VAR_TCP_NODELAY {"network.protocols.tcp.nodelay.enable"};
const config_var_info_t<bool> CONFIG_VAR_TCP_QUICKACK {"network.protocols.tcp.quickack"};
const config_var_info_t<bool> CONFIG_VAR_TCP_PUSH_FLAG {"network.protocols.tcp.push"};
const config_var_info_t<bool> CONFIG_VAR_AVOID_SYS_CALLS_ON_TCP_FD {
    "core.syscall.avoid_ctl_syscalls"};
const config_var_info_t<bool> CONFIG_VAR_ALLOW_PRIVILEGED_SOCK_OPT {
    "core.syscall.allow_privileged_sockopt"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_WAIT_AFTER_JOIN_MSEC {
    "network.multicast.wait_after_join_msec"};
const config_var_info_t<buffer_batching_mode_t, int64_t> CONFIG_VAR_BUFFER_BATCHING_MODE {
    "performance.buffers.batching_mode"};
const config_var_info_t<option_alloc_type::mode_t, bool> CONFIG_VAR_MEM_ALLOC_TYPE {
    "core.resources.hugepages.enable"};
const config_var_info_t<size_t, int64_t> CONFIG_VAR_MEMORY_LIMIT {"core.resources.memory_limit"};
const config_var_info_t<size_t, int64_t> CONFIG_VAR_MEMORY_LIMIT_USER {
    "core.resources.external_memory_limit"};
const config_var_info_t<size_t, int64_t> CONFIG_VAR_HEAP_METADATA_BLOCK {
    "core.resources.heap_metadata_block_size"};
const config_var_info_t<size_t, int64_t> CONFIG_VAR_HUGEPAGE_SIZE {"core.resources.hugepages.size"};
const config_var_info_t<bool> CONFIG_VAR_FORK {"core.syscall.fork_support"};
const config_var_info_t<bool> CONFIG_VAR_CLOSE_ON_DUP2 {"core.syscall.dup2_close_fd"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_MTU {"network.protocols.ip.mtu"};
#if defined(DEFINED_NGINX)
const config_var_info_t<int, int64_t> CONFIG_VAR_NGINX_UDP_POOL_SIZE {
    "applications.nginx.udp_pool_size"};
const config_var_info_t<int, int64_t> CONFIG_VAR_NGINX_UDP_POOL_RX_NUM_BUFFS_REUSE {
    "applications.nginx.udp_socket_pool_reuse"};
#endif
const config_var_info_t<int, int64_t> CONFIG_VAR_NGINX_WORKERS_NUM {
    "applications.nginx.workers_num"};
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
const config_var_info_t<int, int64_t> CONFIG_VAR_SRC_PORT_STRIDE {
    "applications.nginx.src_port_stride"};
const config_var_info_t<bool> CONFIG_VAR_DISTRIBUTE_CQ {"applications.nginx.distribute_cq"};
#endif
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_MSS {"network.protocols.tcp.mss"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TCP_CC_ALGO {
    "network.protocols.tcp.congestion_control"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_SPEC {"profiles.spec"};

const config_var_info_t<option_3::mode_t, int64_t> CONFIG_VAR_TSO {
    "hardware_features.tcp.tso.enable"};
#ifdef DEFINED_UTLS
const config_var_info_t<bool> CONFIG_VAR_UTLS_RX {"hardware_features.tcp.tls_offload.rx_enable"};
const config_var_info_t<bool> CONFIG_VAR_UTLS_TX {"hardware_features.tcp.tls_offload.tx_enable"};
const config_var_info_t<size_t, int64_t> CONFIG_VAR_UTLS_HIGH_WMARK_DEK_CACHE_SIZE {
    "hardware_features.tcp.tls_offload.dek_cache_max_size"};
const config_var_info_t<size_t, int64_t> CONFIG_VAR_UTLS_LOW_WMARK_DEK_CACHE_SIZE {
    "hardware_features.tcp.tls_offload.dek_cache_min_size"};
#endif /* DEFINED_UTLS */

const config_var_info_t<option_3::mode_t, int64_t> CONFIG_VAR_LRO {"hardware_features.tcp.lro"};

const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_NETLINK_TIMER_MSEC {
    "network.neighbor.update_interval_msec"};

const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_NEIGH_UC_ARP_QUATA {
    "network.neighbor.arp.uc_retries"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_NEIGH_UC_ARP_DELAY_MSEC {
    "network.neighbor.arp.uc_delay_msec"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_NEIGH_NUM_ERR_RETRIES {
    "network.neighbor.errors_before_reset"};

const config_var_info_t<bool> CONFIG_VAR_DEFERRED_CLOSE {"core.syscall.deferred_close"};
const config_var_info_t<bool> CONFIG_VAR_TCP_ABORT_ON_CLOSE {"network.protocols.tcp.linger_0"};
const config_var_info_t<bool> CONFIG_VAR_RX_POLL_ON_TX_TCP {
    "performance.polling.rx_poll_on_tx_tcp"};
const config_var_info_t<bool> CONFIG_VAR_RX_CQ_WAIT_CTRL {"performance.polling.rx_cq_wait_ctrl"};
const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TCP_SEND_BUFFER_SIZE {
    "network.protocols.tcp.wmem"};
const config_var_info_t<skip_poll_in_rx_t, int64_t> CONFIG_VAR_SKIP_POLL_IN_RX {
    "performance.polling.skip_cq_on_rx"};
const config_var_info_t<multilock_t, bool> CONFIG_VAR_MULTILOCK {
    "performance.threading.mutex_over_spinlock"};

const config_var_info_t<xlio_exception_handling, int64_t> CONFIG_VAR_EXCEPTION_HANDLING {
    "core.exception_handling.mode"};

sys_var_configurator::sys_var_configurator(runtime_registry &runtime_registry,
                                           mce_sys_var &sys_vars)
    : m_runtime_registry(runtime_registry)
    , m_config_registry(m_runtime_registry.get_config_registry())
    , m_sys_vars(sys_vars)
{
}

void sys_var_configurator::configure()
{
    const auto &source_list = m_config_registry.get_sources();
    std::string sources;
    if (!source_list.empty()) {
        sources = std::accumulate(
            std::next(source_list.begin()), source_list.end(), source_list.front(),
            [](const std::string &a, const std::string &b) { return a + ", " + b; });
    }

    vlog_printf(VLOG_INFO, "Config sources: %s\n", sources.c_str());
    vlog_printf(VLOG_INFO, "Process ID: %d\n", getpid());

    initialize_base_variables();

    configure_striding_rq();
    configure_running_mode();
    detect_application_profile();
    apply_spec_profile_optimizations();

    configure_before_user_settings();

    // Scans config registry for all user settings and sets
    // run-time variables accordingly
    m_runtime_registry.set_all_configured_values();

    // Check and overrides some run-time variables
    configure_after_user_settings();
}

static std::string acceleration_rules_to_legacy(
    const std::vector<std::experimental::any> &acceleration_rules)
{
    std::string result;

    for (size_t i = 0; i < acceleration_rules.size(); i++) {
        auto rule_object =
            std::experimental::any_cast<std::map<std::string, std::experimental::any>>(
                acceleration_rules[i]);

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
        if (i < acceleration_rules.size() - 1) {
            result += ";";
        }
    }

    return result;
}

static uint32_t round_to_power_of_2(uint32_t value, const std::string &key)
{
    bool isOK = true;
    if (!is_ilog2(static_cast<unsigned int>(value))) {
        value = align32pow2(static_cast<uint32_t>(value));
        isOK = false;
    }
    if (!isOK) {
        vlog_printf(VLOG_INFO, " Invalid %s: Must be power of 2. Using: %d.\n", key.c_str(), value);
    }
    return value;
}

static option_alloc_type::mode_t translate_alloc_type_c2r(bool value, const std::string &)
{
    return value ? option_alloc_type::HUGE : option_alloc_type::ANON;
}

static bool translate_alloc_type_r2c(option_alloc_type::mode_t value)
{
    return value == option_alloc_type::HUGE ? true : false;
}

static multilock_t translate_multilock_c2r(bool value, const std::string &)
{
    return value ? MULTILOCK_MUTEX : MULTILOCK_SPIN;
}

static bool translate_multilock_r2c(multilock_t value)
{
    return value == MULTILOCK_MUTEX ? true : false;
}

void sys_var_configurator::initialize_base_variables()
{
    // Here we register all variables which can be set from the config registry.
    // Note: register_and_set_default_value() deduces template types from the config_var_info_t
    // parameter. Supported registry types are int64_t, bool, and std::string.

    m_runtime_registry.register_char_array_and_set_default_value(
        m_sys_vars.log_filename, sizeof(m_sys_vars.log_filename), CONFIG_VAR_LOG_FILENAME);
    m_runtime_registry.register_char_array_and_set_default_value(
        m_sys_vars.stats_filename, sizeof(m_sys_vars.stats_filename), CONFIG_VAR_STATS_FILENAME);
    m_runtime_registry.register_char_array_and_set_default_value(
        m_sys_vars.stats_shmem_dirname, sizeof(m_sys_vars.stats_shmem_dirname),
        CONFIG_VAR_STATS_SHMEM_DIRNAME);
    m_runtime_registry.register_char_array_and_set_default_value(
        m_sys_vars.service_notify_dir, sizeof(m_sys_vars.service_notify_dir),
        CONFIG_VAR_SERVICE_DIR);

    // Accelaration rules read actual value from registry (not default) and
    // need translation to legacy format
    const std::string net_offload_acceleration_rules = acceleration_rules_to_legacy(
        m_runtime_registry.get_config_registry().get_value<std::vector<std::experimental::any>>(
            CONFIG_VAR_ACCEL_CONTROL_RULES.name));
    m_runtime_registry.register_char_array_and_set_explicit_value(
        m_sys_vars.acceleration_rules, sizeof(m_sys_vars.acceleration_rules),
        CONFIG_VAR_ACCEL_CONTROL_RULES, std::string(net_offload_acceleration_rules));

    m_runtime_registry.register_char_array_and_set_default_value(
        m_sys_vars.app_id, sizeof(m_sys_vars.app_id), CONFIG_VAR_APPLICATION_ID);
    m_runtime_registry.register_char_array_and_set_default_value(
        m_sys_vars.internal_thread_cpuset, sizeof(m_sys_vars.internal_thread_cpuset),
        CONFIG_VAR_INTERNAL_THREAD_CPUSET);
    m_runtime_registry.register_char_array_and_set_default_value(
        m_sys_vars.internal_thread_affinity_str, sizeof(m_sys_vars.internal_thread_affinity_str),
        CONFIG_VAR_INTERNAL_THREAD_AFFINITY);

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.service_enable,
                                                      CONFIG_VAR_SERVICE_ENABLE);

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.print_report,
                                                      CONFIG_VAR_PRINT_REPORT);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.quick_start,
                                                      CONFIG_VAR_QUICK_START);

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.log_level, CONFIG_VAR_LOG_LEVEL);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.log_details,
                                                      CONFIG_VAR_LOG_DETAILS);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.log_colors,
                                                      CONFIG_VAR_LOG_COLORS);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.handle_sigintr,
                                                      CONFIG_VAR_HANDLE_SIGINTR);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.handle_segfault,
                                                      CONFIG_VAR_HANDLE_SIGSEGV);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.stats_fd_num_max,
                                                      CONFIG_VAR_STATS_FD_NUM);
    // Not in config_registry
    m_sys_vars.stats_fd_num_monitor = m_sys_vars.stats_fd_num_max;

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.ring_allocation_logic_tx,
                                                      CONFIG_VAR_RING_ALLOCATION_LOGIC_TX);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.ring_allocation_logic_rx,
                                                      CONFIG_VAR_RING_ALLOCATION_LOGIC_RX);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.ring_migration_ratio_tx,
                                                      CONFIG_VAR_RING_MIGRATION_RATIO_TX);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.ring_migration_ratio_rx,
                                                      CONFIG_VAR_RING_MIGRATION_RATIO_RX);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.ring_limit_per_interface,
                                                      CONFIG_VAR_RING_LIMIT_PER_INTERFACE);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.ring_dev_mem_tx,
                                                      CONFIG_VAR_RING_DEV_MEM_TX);

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.zc_cache_threshold,
                                                      CONFIG_VAR_ZC_CACHE_THRESHOLD);

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tx_buf_size,
                                                      CONFIG_VAR_TX_BUF_SIZE);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tcp_nodelay_treshold,
                                                      CONFIG_VAR_TCP_NODELAY_TRESHOLD);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tx_num_wr, CONFIG_VAR_TX_NUM_WRE);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tx_num_wr_to_signal,
                                                      CONFIG_VAR_TX_NUM_WRE_TO_SIGNAL);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tx_max_inline,
                                                      CONFIG_VAR_TX_MAX_INLINE);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tx_mc_loopback_default,
                                                      CONFIG_VAR_TX_MC_LOOPBACK);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tx_nonblocked_eagains,
                                                      CONFIG_VAR_TX_NONBLOCKED_EAGAINS);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tx_prefetch_bytes,
                                                      CONFIG_VAR_TX_PREFETCH_BYTES);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tx_bufs_batch_udp,
                                                      CONFIG_VAR_TX_BUFS_BATCH_UDP);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tx_bufs_batch_tcp,
                                                      CONFIG_VAR_TX_BUFS_BATCH_TCP);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tx_segs_batch_tcp,
                                                      CONFIG_VAR_TX_SEGS_BATCH_TCP);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tx_segs_ring_batch_tcp,
                                                      CONFIG_VAR_TX_SEGS_RING_BATCH_TCP);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tx_segs_pool_batch_tcp,
                                                      CONFIG_VAR_TX_SEGS_POOL_BATCH_TCP);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.rx_buf_size,
                                                      CONFIG_VAR_RX_BUF_SIZE);

    // Not in config_registry
    m_sys_vars.rx_bufs_batch = MCE_DEFAULT_RX_BUFS_BATCH;

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.rx_num_wr, CONFIG_VAR_RX_NUM_WRE);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.rx_num_wr_to_post_recv,
                                                      CONFIG_VAR_RX_NUM_WRE_TO_POST_RECV);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.rx_poll_num,
                                                      CONFIG_VAR_RX_NUM_POLLS);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.rx_poll_num_init,
                                                      CONFIG_VAR_RX_NUM_POLLS_INIT);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.rx_udp_poll_os_ratio,
                                                      CONFIG_VAR_RX_UDP_POLL_OS_RATIO);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.hw_ts_conversion_mode,
                                                      CONFIG_VAR_HW_TS_CONVERSION_MODE);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.rx_poll_yield_loops,
                                                      CONFIG_VAR_RX_POLL_YIELD);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.select_handle_cpu_usage_stats,
                                                      CONFIG_VAR_SELECT_CPU_USAGE_STATS);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.rx_ready_byte_min_limit,
                                                      CONFIG_VAR_RX_BYTE_MIN_LIMIT);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.rx_prefetch_bytes,
                                                      CONFIG_VAR_RX_PREFETCH_BYTES);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.rx_prefetch_bytes_before_poll,
                                                      CONFIG_VAR_RX_PREFETCH_BYTES_BEFORE_POLL);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.rx_cq_drain_rate_nsec,
                                                      CONFIG_VAR_RX_CQ_DRAIN_RATE_NSEC);
    // Not in config_registry
    m_sys_vars.rx_delta_tsc_between_cq_polls = 0;

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.enable_striding_rq,
                                                      CONFIG_VAR_STRQ);
    // Translator ensures it is a power of 2
    m_runtime_registry.register_and_set_default_value(
        &m_sys_vars.strq_stride_num_per_rwqe, CONFIG_VAR_STRQ_NUM_STRIDES,
        runtime_registry::translator_c2r_t<int64_t, uint32_t>(
            [](int64_t v, const std::string &key) {
                return round_to_power_of_2(static_cast<uint32_t>(v), key);
            }));

    // Translator ensures it is a power of 2
    m_runtime_registry.register_and_set_default_value(
        &m_sys_vars.strq_stride_size_bytes, CONFIG_VAR_STRQ_STRIDE_SIZE_BYTES,
        runtime_registry::translator_c2r_t<int64_t, uint32_t>(
            [](int64_t v, const std::string &key) {
                return round_to_power_of_2(static_cast<uint32_t>(v), key);
            }));

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.strq_strides_compensation_level,
                                                      CONFIG_VAR_STRQ_STRIDES_COMPENSATION_LEVEL);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.qp_compensation_level,
                                                      CONFIG_VAR_QP_COMPENSATION_LEVEL);

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.gro_streams_max,
                                                      CONFIG_VAR_GRO_STREAMS_MAX);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.disable_flow_tag,
                                                      CONFIG_VAR_DISABLE_FLOW_TAG);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tcp_2t_rules,
                                                      CONFIG_VAR_TCP_2T_RULES);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tcp_3t_rules,
                                                      CONFIG_VAR_TCP_3T_RULES);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.udp_3t_rules,
                                                      CONFIG_VAR_UDP_3T_RULES);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.eth_mc_l2_only_rules,
                                                      CONFIG_VAR_ETH_MC_L2_ONLY_RULES);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.mc_force_flowtag,
                                                      CONFIG_VAR_MC_FORCE_FLOWTAG);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.select_poll_num,
                                                      CONFIG_VAR_SELECT_NUM_POLLS);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.select_poll_os_ratio,
                                                      CONFIG_VAR_SELECT_POLL_OS_RATIO);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.select_skip_os_fd_check,
                                                      CONFIG_VAR_SELECT_SKIP_OS);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.cq_moderation_enable,
                                                      CONFIG_VAR_CQ_MODERATION_ENABLE);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.cq_moderation_count,
                                                      CONFIG_VAR_CQ_MODERATION_COUNT);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.cq_moderation_period_usec,
                                                      CONFIG_VAR_CQ_MODERATION_PERIOD_USEC);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.cq_aim_max_count,
                                                      CONFIG_VAR_CQ_AIM_MAX_COUNT);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.cq_aim_max_period_usec,
                                                      CONFIG_VAR_CQ_AIM_MAX_PERIOD_USEC);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.cq_aim_interval_msec,
                                                      CONFIG_VAR_CQ_AIM_INTERVAL_MSEC);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.cq_aim_interrupts_rate_per_sec,
                                                      CONFIG_VAR_CQ_AIM_INTERRUPTS_RATE_PER_SEC);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.cq_poll_batch_max,
                                                      CONFIG_VAR_CQ_POLL_BATCH_MAX);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.progress_engine_interval_msec,
                                                      CONFIG_VAR_PROGRESS_ENGINE_INTERVAL);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.progress_engine_wce_max,
                                                      CONFIG_VAR_PROGRESS_ENGINE_WCE_MAX);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.cq_keep_qp_full,
                                                      CONFIG_VAR_CQ_KEEP_QP_FULL);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.max_tso_sz,
                                                      CONFIG_VAR_MAX_TSO_SIZE);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.worker_threads,
                                                      CONFIG_VAR_WORKER_THREADS);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.offloaded_sockets,
                                                      CONFIG_VAR_OFFLOADED_SOCKETS);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.timer_resolution_msec,
                                                      CONFIG_VAR_TIMER_RESOLUTION_MSEC);

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tcp_timer_resolution_msec,
                                                      CONFIG_VAR_TCP_TIMER_RESOLUTION_MSEC);

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tcp_ctl_thread,
                                                      CONFIG_VAR_TCP_CTL_THREAD);

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tcp_ts_opt,
                                                      CONFIG_VAR_TCP_TIMESTAMP_OPTION);

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tcp_nodelay,
                                                      CONFIG_VAR_TCP_NODELAY);

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tcp_quickack,
                                                      CONFIG_VAR_TCP_QUICKACK);

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tcp_push_flag,
                                                      CONFIG_VAR_TCP_PUSH_FLAG);

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.exception_handling,
                                                      CONFIG_VAR_EXCEPTION_HANDLING);

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.avoid_sys_calls_on_tcp_fd,
                                                      CONFIG_VAR_AVOID_SYS_CALLS_ON_TCP_FD);

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.allow_privileged_sock_opt,
                                                      CONFIG_VAR_ALLOW_PRIVILEGED_SOCK_OPT);

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.wait_after_join_msec,
                                                      CONFIG_VAR_WAIT_AFTER_JOIN_MSEC);

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.buffer_batching_mode,
                                                      CONFIG_VAR_BUFFER_BATCHING_MODE);

    m_runtime_registry.register_and_set_default_value(
        &m_sys_vars.mem_alloc_type, CONFIG_VAR_MEM_ALLOC_TYPE,
        runtime_registry::translator_c2r_t<bool, option_alloc_type::mode_t>(
            translate_alloc_type_c2r),
        runtime_registry::translator_r2c_t<option_alloc_type::mode_t, bool>(
            translate_alloc_type_r2c));

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.memory_limit,
                                                      CONFIG_VAR_MEMORY_LIMIT);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.memory_limit_user,
                                                      CONFIG_VAR_MEMORY_LIMIT_USER);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.heap_metadata_block,
                                                      CONFIG_VAR_HEAP_METADATA_BLOCK);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.hugepage_size,
                                                      CONFIG_VAR_HUGEPAGE_SIZE);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.enable_tso, CONFIG_VAR_TSO);

#ifdef DEFINED_UTLS
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.enable_utls_rx,
                                                      CONFIG_VAR_UTLS_RX);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.enable_utls_tx,
                                                      CONFIG_VAR_UTLS_TX);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.utls_high_wmark_dek_cache_size,
                                                      CONFIG_VAR_UTLS_HIGH_WMARK_DEK_CACHE_SIZE);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.utls_low_wmark_dek_cache_size,
                                                      CONFIG_VAR_UTLS_LOW_WMARK_DEK_CACHE_SIZE);
#endif /* DEFINED_UTLS */
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.enable_lro, CONFIG_VAR_LRO);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.handle_fork, CONFIG_VAR_FORK);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.close_on_dup2,
                                                      CONFIG_VAR_CLOSE_ON_DUP2);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.mtu, CONFIG_VAR_MTU);
#if defined(DEFINED_NGINX)
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.nginx_udp_socket_pool_size,
                                                      CONFIG_VAR_NGINX_UDP_POOL_SIZE);
    m_runtime_registry.register_and_set_default_value(
        &m_sys_vars.nginx_udp_socket_pool_rx_num_buffs_reuse,
        CONFIG_VAR_NGINX_UDP_POOL_RX_NUM_BUFFS_REUSE);
#endif
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    m_sys_vars.app.type = APP_NONE; // not a config key
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.app.workers_num,
                                                      CONFIG_VAR_NGINX_WORKERS_NUM);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.app.src_port_stride,
                                                      CONFIG_VAR_SRC_PORT_STRIDE);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.app.distribute_cq_interrupts,
                                                      CONFIG_VAR_DISTRIBUTE_CQ);
#endif
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.lwip_mss, CONFIG_VAR_MSS);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.lwip_cc_algo_mod,
                                                      CONFIG_VAR_TCP_CC_ALGO);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.mce_spec, CONFIG_VAR_SPEC);

    m_runtime_registry.register_and_set_default_value(&m_sys_vars.neigh_num_err_retries,
                                                      CONFIG_VAR_NEIGH_NUM_ERR_RETRIES);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.neigh_uc_arp_quata,
                                                      CONFIG_VAR_NEIGH_UC_ARP_QUATA);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.neigh_wait_till_send_arp_msec,
                                                      CONFIG_VAR_NEIGH_UC_ARP_DELAY_MSEC);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.timer_netlink_update_msec,
                                                      CONFIG_VAR_NETLINK_TIMER_MSEC);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.deferred_close,
                                                      CONFIG_VAR_DEFERRED_CLOSE);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tcp_abort_on_close,
                                                      CONFIG_VAR_TCP_ABORT_ON_CLOSE);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.rx_poll_on_tx_tcp,
                                                      CONFIG_VAR_RX_POLL_ON_TX_TCP);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.rx_cq_wait_ctrl,
                                                      CONFIG_VAR_RX_CQ_WAIT_CTRL);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.tcp_send_buffer_size,
                                                      CONFIG_VAR_TCP_SEND_BUFFER_SIZE);
    m_runtime_registry.register_and_set_default_value(&m_sys_vars.skip_poll_in_rx,
                                                      CONFIG_VAR_SKIP_POLL_IN_RX);
    m_runtime_registry.register_and_set_default_value(
        &m_sys_vars.multilock, CONFIG_VAR_MULTILOCK,
        runtime_registry::translator_c2r_t<bool, multilock_t>(translate_multilock_c2r),
        runtime_registry::translator_r2c_t<multilock_t, bool>(translate_multilock_r2c));
}

void sys_var_configurator::configure_striding_rq()
{
    // Read user-set value from registry info enable_striding_rq now, so that it will be used in the
    // next line.
    m_runtime_registry.set_value_if_exists(CONFIG_VAR_STRQ.name);

    if (m_sys_vars.enable_striding_rq) {
        m_runtime_registry.set_value(CONFIG_VAR_RX_NUM_WRE,
                                     static_cast<int64_t>(MCE_DEFAULT_STRQ_NUM_WRE),
                                     change_reason::AutoCorrected, "Striding RQ is enabled");
        m_runtime_registry.set_value(CONFIG_VAR_RX_NUM_WRE_TO_POST_RECV,
                                     static_cast<int64_t>(MCE_DEFAULT_STRQ_NUM_WRE_TO_POST_RECV),
                                     change_reason::AutoCorrected, "Striding RQ is enabled");
    }
}

void sys_var_configurator::configure_running_mode()
{
    // Read user-set value from registry info worker_threads now, so that it will be used in the
    // next line.
    m_runtime_registry.set_value_if_exists(CONFIG_VAR_WORKER_THREADS.name);

    if (m_sys_vars.worker_threads > 0) {
        m_runtime_registry.set_value(CONFIG_VAR_TX_BUF_SIZE, static_cast<int64_t>(256U * 1024U),
                                     change_reason::AutoCorrected,
                                     std::string(CONFIG_VAR_WORKER_THREADS.name) + " > 0");
        m_runtime_registry.set_value(CONFIG_VAR_TX_BUFS_BATCH_TCP, static_cast<int64_t>(1),
                                     change_reason::AutoCorrected,
                                     std::string(CONFIG_VAR_WORKER_THREADS.name) + " > 0");
    }
}

void sys_var_configurator::detect_application_profile()
{
    // Read user-set value from registry info mce_spec now, so that it will be used in the next
    // line.
    m_runtime_registry.set_value_if_exists(CONFIG_VAR_SPEC.name);

    /*
     * Check for specific application configuration first. We can make decisions
     * based on number of workers or application type further.
     */
#if defined(DEFINED_NGINX)
    // Read user-set value from registry info app.workers_num now, so that it will be used in the
    // next line.
    m_runtime_registry.set_value_if_exists(CONFIG_VAR_NGINX_WORKERS_NUM.name);
    if (m_sys_vars.app.workers_num > 0) {
        m_sys_vars.app.type = APP_NGINX;
        // In order to ease the usage of Nginx cases, we apply Nginx profile when
        // user will choose to use Nginx workers environment variable.
        if (m_sys_vars.mce_spec == MCE_SPEC_NONE) {
            m_runtime_registry.set_value(CONFIG_VAR_SPEC, static_cast<int64_t>(MCE_SPEC_NGINX),
                                         change_reason::Profile,
                                         std::string(CONFIG_VAR_NGINX_WORKERS_NUM.name) + " > 0");
        }
    }

#endif // DEFINED_NGINX
#if defined(DEFINED_ENVOY)
    // TODO - config - add to schema
    // applications.envoy.workers_num is not in the schema, we use the nginx workers number.
    m_runtime_registry.set_value_if_exists(CONFIG_VAR_NGINX_WORKERS_NUM.name);
    if (m_sys_vars.app.workers_num > 0) {
        m_sys_vars.app.type = APP_ENVOY;
    }
#endif /* DEFINED_ENVOY */
}

void sys_var_configurator::apply_spec_profile_optimizations()
{
    switch (m_sys_vars.mce_spec) {
    case MCE_SPEC_ULTRA_LATENCY:
        apply_ultra_latency_profile();
        break;

    case MCE_SPEC_LATENCY:
        apply_latency_profile();
        break;

#ifdef DEFINED_NGINX
    case MCE_SPEC_NGINX:
    case MCE_SPEC_NGINX_DPU:
        apply_nginx_profile();
        break;
#endif // DEFINED_NGINX

    case MCE_SPEC_NVME_BF3:
        apply_nvme_bf3_profile();
        break;

    case MCE_SPEC_NONE:
    default:
        break;
    }
}

void sys_var_configurator::apply_ultra_latency_profile()
{
    const char *desc = "Ultra latency profile";
    m_runtime_registry.set_value(CONFIG_VAR_MEMORY_LIMIT, static_cast<int64_t>(128LU * 1024 * 1024),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TX_NUM_WRE, static_cast<int64_t>(256),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TX_NUM_WRE_TO_SIGNAL, static_cast<int64_t>(4),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TX_PREFETCH_BYTES,
                                 static_cast<int64_t>(MCE_DEFAULT_TX_PREFETCH_BYTES),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TX_BUFS_BATCH_UDP, static_cast<int64_t>(1),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TX_BUFS_BATCH_TCP, static_cast<int64_t>(1),
                                 change_reason::Profile, desc);
    m_sys_vars.rx_bufs_batch = 4; // not a config key
    m_runtime_registry.set_value(CONFIG_VAR_RX_NUM_POLLS, static_cast<int64_t>(-1),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TSO, static_cast<int64_t>(option_3::OFF),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_RX_UDP_POLL_OS_RATIO, static_cast<int64_t>(0),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_RX_PREFETCH_BYTES,
                                 static_cast<int64_t>(MCE_DEFAULT_RX_PREFETCH_BYTES),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_RX_PREFETCH_BYTES_BEFORE_POLL,
                                 static_cast<int64_t>(256), change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_SELECT_NUM_POLLS, static_cast<int64_t>(-1),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_SELECT_POLL_OS_RATIO, static_cast<int64_t>(0),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_SELECT_SKIP_OS, static_cast<int64_t>(0),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_AVOID_SYS_CALLS_ON_TCP_FD, true, change_reason::Profile,
                                 desc);
    m_runtime_registry.set_value(CONFIG_VAR_GRO_STREAMS_MAX, static_cast<int64_t>(0),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_PROGRESS_ENGINE_INTERVAL, static_cast<int64_t>(0),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_CQ_KEEP_QP_FULL, false, change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TCP_NODELAY, true, change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_RING_DEV_MEM_TX, static_cast<int64_t>(16384),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_INTERNAL_THREAD_AFFINITY, std::string("0"),
                                 change_reason::Profile, desc);

    if (m_sys_vars.enable_striding_rq) {
        m_runtime_registry.set_value(CONFIG_VAR_RX_NUM_WRE, static_cast<int64_t>(4U),
                                     change_reason::Profile, desc);
    } else {
        m_runtime_registry.set_value(CONFIG_VAR_RX_NUM_WRE, static_cast<int64_t>(256),
                                     change_reason::Profile, desc);
        m_runtime_registry.set_value(CONFIG_VAR_RX_NUM_WRE_TO_POST_RECV, static_cast<int64_t>(4),
                                     change_reason::Profile, desc);
    }
}

void sys_var_configurator::apply_latency_profile()
{
    const char *desc = "Latency profile";
    m_runtime_registry.set_value(CONFIG_VAR_TX_NUM_WRE, static_cast<int64_t>(256),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TX_NUM_WRE_TO_SIGNAL, static_cast<int64_t>(4),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TX_BUFS_BATCH_UDP, static_cast<int64_t>(1),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TX_BUFS_BATCH_TCP, static_cast<int64_t>(1),
                                 change_reason::Profile, desc);
    m_sys_vars.rx_bufs_batch = 4; // not a config key
    m_runtime_registry.set_value(CONFIG_VAR_RX_NUM_POLLS, static_cast<int64_t>(-1),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TSO, static_cast<int64_t>(option_3::OFF),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_RX_PREFETCH_BYTES_BEFORE_POLL,
                                 static_cast<int64_t>(256), change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_SELECT_NUM_POLLS, static_cast<int64_t>(-1),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_AVOID_SYS_CALLS_ON_TCP_FD, true, change_reason::Profile,
                                 desc);
    m_runtime_registry.set_value(CONFIG_VAR_GRO_STREAMS_MAX, static_cast<int64_t>(0),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_CQ_KEEP_QP_FULL, false, change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_INTERNAL_THREAD_AFFINITY, std::string("0"),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_PROGRESS_ENGINE_INTERVAL, static_cast<int64_t>(100),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_SELECT_POLL_OS_RATIO, static_cast<int64_t>(100),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TCP_NODELAY, true, change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_RING_DEV_MEM_TX, static_cast<int64_t>(16384),
                                 change_reason::Profile, desc);
    if (m_sys_vars.enable_striding_rq) {
        m_runtime_registry.set_value(CONFIG_VAR_RX_NUM_WRE, static_cast<int64_t>(4U),
                                     change_reason::Profile, desc);
    } else {
        m_runtime_registry.set_value(CONFIG_VAR_RX_NUM_WRE, static_cast<int64_t>(256),
                                     change_reason::Profile, desc);
        m_runtime_registry.set_value(CONFIG_VAR_RX_NUM_WRE_TO_POST_RECV, static_cast<int64_t>(4),
                                     change_reason::Profile, desc);
    }
}

#ifdef DEFINED_NGINX
void sys_var_configurator::apply_nginx_profile()
{
    const char *desc = "Nginx profile";
    m_runtime_registry.set_value(CONFIG_VAR_RING_ALLOCATION_LOGIC_TX,
                                 static_cast<int64_t>(RING_LOGIC_PER_INTERFACE),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_RING_ALLOCATION_LOGIC_RX,
                                 static_cast<int64_t>(RING_LOGIC_PER_INTERFACE),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_PROGRESS_ENGINE_INTERVAL, static_cast<int64_t>(0),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_CQ_POLL_BATCH_MAX, static_cast<int64_t>(128),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TSO, static_cast<int64_t>(option_3::ON),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TIMER_RESOLUTION_MSEC, static_cast<int64_t>(32),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TCP_TIMER_RESOLUTION_MSEC, static_cast<int64_t>(256),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TCP_SEND_BUFFER_SIZE,
                                 static_cast<int64_t>(2 * 1024 * 1024), change_reason::Profile,
                                 desc);
    m_runtime_registry.set_value(CONFIG_VAR_TCP_PUSH_FLAG, false, change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_SELECT_NUM_POLLS, static_cast<int64_t>(0),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_SELECT_SKIP_OS, static_cast<int64_t>(1000),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TCP_3T_RULES, true, change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_DISTRIBUTE_CQ, true, change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_RX_CQ_WAIT_CTRL, true, change_reason::Profile, desc);
    if (m_sys_vars.mce_spec == MCE_SPEC_NGINX) {
        size_t mem = (m_sys_vars.app.workers_num > 16 ? 3072LU : 4096LU) * 1024 * 1024;
        mem *= std::max(m_sys_vars.app.workers_num, 1);
        m_runtime_registry.set_value(CONFIG_VAR_MEMORY_LIMIT, static_cast<int64_t>(mem),
                                     change_reason::Profile, desc);
        m_sys_vars.rx_bufs_batch = 8; // not a config key
        m_runtime_registry.set_value(CONFIG_VAR_RX_POLL_ON_TX_TCP, true, change_reason::Profile,
                                     desc);
    } else if (m_sys_vars.mce_spec == MCE_SPEC_NGINX_DPU) {
        size_t mem = (m_sys_vars.app.workers_num == 16 ? 512LU : 1024LU) * 1024 * 1024;
        mem *= std::max(m_sys_vars.app.workers_num, 1);
        m_runtime_registry.set_value(CONFIG_VAR_MEMORY_LIMIT, static_cast<int64_t>(mem),
                                     change_reason::Profile, desc);
        m_runtime_registry.set_value(CONFIG_VAR_BUFFER_BATCHING_MODE,
                                     static_cast<int64_t>(BUFFER_BATCHING_NONE),
                                     change_reason::Profile, desc);
    }
}
#endif // DEFINED_NGINX

void sys_var_configurator::apply_nvme_bf3_profile()
{
    const char *desc = "NVMe BF3 profile";
    m_runtime_registry.set_value(CONFIG_VAR_STRQ_NUM_STRIDES, static_cast<int64_t>(8192U),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_LRO, static_cast<int64_t>(option_3::ON),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_FORK, false, change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_INTERNAL_THREAD_AFFINITY, std::string("0x01"),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_GRO_STREAMS_MAX, static_cast<int64_t>(0),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TX_NUM_WRE_TO_SIGNAL, static_cast<int64_t>(128U),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TX_NUM_WRE, static_cast<int64_t>(1024U),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_RX_NUM_WRE, static_cast<int64_t>(32U),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TSO, static_cast<int64_t>(option_3::ON),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_RX_PREFETCH_BYTES_BEFORE_POLL,
                                 static_cast<int64_t>(256U), change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_RING_DEV_MEM_TX, static_cast<int64_t>(1024),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_CQ_KEEP_QP_FULL, false, change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_CQ_AIM_INTERVAL_MSEC,
                                 static_cast<int64_t>(MCE_CQ_ADAPTIVE_MODERATION_DISABLED),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_PROGRESS_ENGINE_INTERVAL, static_cast<int64_t>(0U),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TCP_ABORT_ON_CLOSE, true, change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_MEMORY_LIMIT,
                                 static_cast<int64_t>(256U * 1024U * 1024U), change_reason::Profile,
                                 desc);
    m_runtime_registry.set_value(CONFIG_VAR_MEMORY_LIMIT_USER,
                                 static_cast<int64_t>(2U * 1024U * 1024U * 1024U),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TX_BUFS_BATCH_UDP, static_cast<int64_t>(1),
                                 change_reason::Profile, desc);
    m_runtime_registry.set_value(CONFIG_VAR_TX_BUFS_BATCH_TCP, static_cast<int64_t>(1),
                                 change_reason::Profile, desc);
    m_sys_vars.rx_bufs_batch = 4; // not a config key
    m_runtime_registry.set_value(CONFIG_VAR_TCP_NODELAY, true, change_reason::Profile, desc);
}

void sys_var_configurator::configure_before_user_settings()
{
    // Here are configuration changes which can be over-ridden by the user.
    // When wanting to take into account user settings, we must
    // call m_runtime_registry.set_value_if_exists() to make sure that
    // the runtime variable is updated with the user settings.

    // From configure_monitor()
    m_runtime_registry.set_value_if_exists(CONFIG_VAR_LOG_LEVEL.name);
    if (m_sys_vars.log_level >= VLOG_DEBUG) {
        m_runtime_registry.set_value(CONFIG_VAR_LOG_DETAILS, static_cast<int64_t>(2),
                                     change_reason::AutoCorrected, "Log level >= DEBUG");
    }
}

void sys_var_configurator::configure_after_user_settings()
{
    // Here are configuration changes which are stronger than user settings

    if (m_sys_vars.hypervisor == mce_sys_var::HYPER_MSHV && !m_sys_vars.service_enable) {
        m_runtime_registry.set_value(CONFIG_VAR_SERVICE_ENABLE, true, change_reason::AutoCorrected,
                                     "Forced for MSHV hypervisor");
        vlog_printf(VLOG_DEBUG, "%s parameter is forced to 'true' for MSHV hypervisor\n",
                    CONFIG_VAR_SERVICE_ENABLE.name);
    }

    m_sys_vars.stats_fd_num_monitor =
        std::min(m_sys_vars.stats_fd_num_max, MAX_STATS_FD_NUM); // not a config key
    if (m_sys_vars.stats_fd_num_max > MAX_STATS_FD_NUM) {
        vlog_printf(VLOG_INFO, "xlio_stats monitoring will be limited by %d sockets\n",
                    MAX_STATS_FD_NUM);
    }

    if (m_sys_vars.tx_num_wr <= (m_sys_vars.tx_num_wr_to_signal * 2)) {
        m_runtime_registry.set_value(CONFIG_VAR_TX_NUM_WRE,
                                     static_cast<int64_t>(m_sys_vars.tx_num_wr_to_signal * 2),
                                     change_reason::AutoCorrected,
                                     std::string(CONFIG_VAR_TX_NUM_WRE.name) + " must be > 2 * " +
                                         CONFIG_VAR_TX_NUM_WRE_TO_SIGNAL.name);
    }

    if (m_sys_vars.enable_striding_rq &&
        (m_sys_vars.strq_stride_num_per_rwqe * m_sys_vars.rx_num_wr > MAX_MLX5_CQ_SIZE_ITEMS)) {
        uint32_t new_rx_num_wr = MAX_MLX5_CQ_SIZE_ITEMS / m_sys_vars.strq_stride_num_per_rwqe;
        m_runtime_registry.set_value(CONFIG_VAR_RX_NUM_WRE, static_cast<int64_t>(new_rx_num_wr),
                                     change_reason::AutoCorrected,
                                     std::string(CONFIG_VAR_STRQ_NUM_STRIDES.name) + " * " +
                                         CONFIG_VAR_RX_NUM_WRE.name + " capped by max CQ size");
        vlog_printf(VLOG_WARNING,
                    "Requested %s * %s > Maximum CQE per CQ (%d)."
                    " Decreasing %s to %" PRIu32 "\n",
                    CONFIG_VAR_STRQ_NUM_STRIDES.name, CONFIG_VAR_RX_NUM_WRE.name,
                    MAX_MLX5_CQ_SIZE_ITEMS, CONFIG_VAR_RX_NUM_WRE.name, m_sys_vars.rx_num_wr);
    }
    if (m_sys_vars.rx_num_wr <= (m_sys_vars.rx_num_wr_to_post_recv * 2)) {
        m_runtime_registry.set_value(CONFIG_VAR_RX_NUM_WRE,
                                     static_cast<int64_t>(m_sys_vars.rx_num_wr_to_post_recv * 2),
                                     change_reason::AutoCorrected,
                                     std::string(CONFIG_VAR_RX_NUM_WRE.name) + " must be > 2 * " +
                                         CONFIG_VAR_RX_NUM_WRE_TO_POST_RECV.name);
    }

    if (m_sys_vars.rx_poll_num == 0) {
        m_runtime_registry.set_value(CONFIG_VAR_RX_NUM_POLLS, static_cast<int64_t>(1),
                                     change_reason::AutoCorrected,
                                     "Zero is invalid, forcing at least one polling loop");
    }

    // Update the rx cq polling rate for draining logic
    // Not in config_registry
    tscval_t tsc_per_second = get_tsc_rate_per_second();
    m_sys_vars.rx_delta_tsc_between_cq_polls =
        tsc_per_second * m_sys_vars.rx_cq_drain_rate_nsec / NSEC_PER_SEC;

    if (m_sys_vars.disable_flow_tag && m_sys_vars.mc_force_flowtag) {
        // Emit a warning only if the user has explicitly set the value we are abiout to reset
        if (m_runtime_registry.get_config_registry().value_exists(
                CONFIG_VAR_MC_FORCE_FLOWTAG.name)) {
            vlog_printf(VLOG_WARNING, "%s and %s can't be set together. Disabling %s\n",
                        CONFIG_VAR_DISABLE_FLOW_TAG.name, CONFIG_VAR_MC_FORCE_FLOWTAG.name,
                        CONFIG_VAR_MC_FORCE_FLOWTAG.name);
        }
        m_runtime_registry.set_value(
            CONFIG_VAR_MC_FORCE_FLOWTAG, false, change_reason::AutoCorrected,
            std::string("Incompatible with ") + CONFIG_VAR_DISABLE_FLOW_TAG.name);
    }

#ifdef DEFINED_IBV_CQ_ATTR_MODERATE
    if (m_sys_vars.rx_poll_num < 0) {
        m_runtime_registry.set_value(CONFIG_VAR_CQ_MODERATION_ENABLE, false,
                                     change_reason::AutoCorrected,
                                     std::string(CONFIG_VAR_RX_NUM_POLLS.name) + " is < 0");
    } else if (m_sys_vars.select_poll_num < 0) {
        m_runtime_registry.set_value(CONFIG_VAR_CQ_MODERATION_ENABLE, false,
                                     change_reason::AutoCorrected,
                                     std::string(CONFIG_VAR_SELECT_NUM_POLLS.name) + " is < 0");
    }

    // User config has the final word about cq_moderation_enable
    m_runtime_registry.set_value_if_exists(CONFIG_VAR_CQ_MODERATION_ENABLE.name);

    uint32_t max_cq_moderation_count =
        (!m_sys_vars.enable_striding_rq
             ? m_sys_vars.rx_num_wr
             : (m_sys_vars.strq_stride_num_per_rwqe * m_sys_vars.rx_num_wr)) /
        2U;
    if (m_sys_vars.cq_moderation_count > max_cq_moderation_count) {
        m_runtime_registry.set_value(CONFIG_VAR_CQ_MODERATION_COUNT,
                                     static_cast<int64_t>(max_cq_moderation_count),
                                     change_reason::AutoCorrected, "Capped by CQ size");
    }

    uint32_t max_cq_aim_max_count =
        (!m_sys_vars.enable_striding_rq
             ? m_sys_vars.rx_num_wr
             : (m_sys_vars.strq_stride_num_per_rwqe * m_sys_vars.rx_num_wr)) /
        2U;
    if (m_sys_vars.cq_aim_max_count > max_cq_aim_max_count) {
        m_runtime_registry.set_value(CONFIG_VAR_CQ_AIM_MAX_COUNT,
                                     static_cast<int64_t>(max_cq_aim_max_count),
                                     change_reason::AutoCorrected, "Capped by CQ size");
    }

    if (!m_sys_vars.cq_moderation_enable) {
        m_runtime_registry.set_value(CONFIG_VAR_CQ_AIM_INTERVAL_MSEC,
                                     static_cast<int64_t>(MCE_CQ_ADAPTIVE_MODERATION_DISABLED),
                                     change_reason::AutoCorrected, "CQ moderation disabled");
    }
#else
    if (m_config_registry.value_exists(CONFIG_VAR_CQ_MODERATION_ENABLE.name)) {
        vlog_printf(VLOG_WARNING, "%s is not supported on this environment\n",
                    CONFIG_VAR_CQ_MODERATION_ENABLE.name);
    }
    if (m_config_registry.value_exists(CONFIG_VAR_CQ_MODERATION_COUNT.name)) {
        vlog_printf(VLOG_WARNING, "%s is not supported on this environment\n",
                    CONFIG_VAR_CQ_MODERATION_COUNT.name);
    }
    if (m_config_registry.value_exists(CONFIG_VAR_CQ_MODERATION_PERIOD_USEC.name)) {
        vlog_printf(VLOG_WARNING, "%s is not supported on this environment\n",
                    CONFIG_VAR_CQ_MODERATION_PERIOD_USEC.name);
    }
    if (m_config_registry.value_exists(CONFIG_VAR_CQ_AIM_MAX_COUNT.name)) {
        vlog_printf(VLOG_WARNING, "%s is not supported on this environment\n",
                    CONFIG_VAR_CQ_AIM_MAX_COUNT.name);
    }
    if (m_config_registry.value_exists(CONFIG_VAR_CQ_AIM_MAX_PERIOD_USEC.name)) {
        vlog_printf(VLOG_WARNING, "%s is not supported on this environment\n",
                    CONFIG_VAR_CQ_AIM_MAX_PERIOD_USEC.name);
    }
    if (m_config_registry.value_exists(CONFIG_VAR_CQ_AIM_INTERVAL_MSEC.name)) {
        vlog_printf(VLOG_WARNING, "%s is not supported on this environment\n",
                    CONFIG_VAR_CQ_AIM_INTERVAL_MSEC.name);
    }
    if (m_config_registry.value_exists(CONFIG_VAR_CQ_AIM_INTERRUPTS_RATE_PER_SEC.name)) {
        vlog_printf(VLOG_WARNING, "%s is not supported on this environment\n",
                    CONFIG_VAR_CQ_AIM_INTERRUPTS_RATE_PER_SEC.name);
    }
#endif /* DEFINED_IBV_CQ_ATTR_MODERATE */

    // Default value depends on rx_num_wr, not hard-coded in schema
    m_runtime_registry.set_value(
        CONFIG_VAR_QP_COMPENSATION_LEVEL, static_cast<int64_t>(m_sys_vars.rx_num_wr / 2U),
        change_reason::AutoCorrected, std::string("Default from ") + CONFIG_VAR_RX_NUM_WRE.name);
    // Override qp_compensation_level if configured by user
    m_runtime_registry.set_value_if_exists(CONFIG_VAR_QP_COMPENSATION_LEVEL.name);

    if (m_sys_vars.qp_compensation_level < m_sys_vars.rx_num_wr_to_post_recv) {
        m_runtime_registry.set_value(
            CONFIG_VAR_QP_COMPENSATION_LEVEL,
            static_cast<int64_t>(m_sys_vars.rx_num_wr_to_post_recv), change_reason::AutoCorrected,
            std::string("Min value is ") + CONFIG_VAR_RX_NUM_WRE_TO_POST_RECV.name);
    }

    if (m_sys_vars.tcp_ctl_thread == option_tcp_ctl_thread::CTL_THREAD_DELEGATE_TCP_TIMERS) {
        if (m_sys_vars.progress_engine_interval_msec != MCE_CQ_DRAIN_INTERVAL_DISABLED) {
            vlog_printf(VLOG_DEBUG, "%s is forced to %d in case %s=%s\n",
                        CONFIG_VAR_PROGRESS_ENGINE_INTERVAL.name, MCE_CQ_DRAIN_INTERVAL_DISABLED,
                        CONFIG_VAR_TCP_CTL_THREAD.name,
                        option_tcp_ctl_thread::to_str(m_sys_vars.tcp_ctl_thread));

            m_runtime_registry.set_value(
                CONFIG_VAR_PROGRESS_ENGINE_INTERVAL,
                static_cast<int64_t>(MCE_CQ_DRAIN_INTERVAL_DISABLED), change_reason::AutoCorrected,
                std::string("Forced when ") + CONFIG_VAR_TCP_CTL_THREAD.name +
                    "=DELEGATE_TCP_TIMERS");
        }
        if (m_sys_vars.ring_allocation_logic_tx != RING_LOGIC_PER_THREAD ||
            m_sys_vars.ring_allocation_logic_rx != RING_LOGIC_PER_THREAD) {
            vlog_printf(VLOG_DEBUG, "%s,%s are forced to %s in case %s=%s\n",
                        CONFIG_VAR_RING_ALLOCATION_LOGIC_TX.name,
                        CONFIG_VAR_RING_ALLOCATION_LOGIC_RX.name,
                        ring_logic_str(RING_LOGIC_PER_THREAD), CONFIG_VAR_TCP_CTL_THREAD.name,
                        option_tcp_ctl_thread::to_str(m_sys_vars.tcp_ctl_thread));

            m_runtime_registry.set_value(
                CONFIG_VAR_RING_ALLOCATION_LOGIC_TX, static_cast<int64_t>(RING_LOGIC_PER_THREAD),
                change_reason::AutoCorrected,
                std::string("Forced when ") + CONFIG_VAR_TCP_CTL_THREAD.name +
                    "=DELEGATE_TCP_TIMERS");
            m_runtime_registry.set_value(
                CONFIG_VAR_RING_ALLOCATION_LOGIC_RX, static_cast<int64_t>(RING_LOGIC_PER_THREAD),
                change_reason::AutoCorrected,
                std::string("Forced when ") + CONFIG_VAR_TCP_CTL_THREAD.name +
                    "=DELEGATE_TCP_TIMERS");
        }
    }

    if ((uint32_t)m_sys_vars.tcp_ts_opt >= TCP_TS_OPTION_LAST) {
        vlog_printf(VLOG_WARNING,
                    "TCP timestamp option value is out of range [%d] (min=%d, "
                    "max=%d). using "
                    "default [%d]\n",
                    m_sys_vars.tcp_ts_opt, TCP_TS_OPTION_DISABLE, TCP_TS_OPTION_LAST - 1,
                    MCE_DEFAULT_TCP_TIMESTAMP_OPTION);
        m_runtime_registry.set_value(CONFIG_VAR_TCP_TIMESTAMP_OPTION,
                                     static_cast<int64_t>(MCE_DEFAULT_TCP_TIMESTAMP_OPTION),
                                     change_reason::AutoCorrected, "Out of range, using default");
    }

    if (m_sys_vars.tcp_timer_resolution_msec < m_sys_vars.timer_resolution_msec) {
        vlog_printf(VLOG_WARNING,
                    "TCP timer resolution (%s=%d) cannot be smaller than timer resolution "
                    "(%s=%d). Setting TCP timer resolution to %d msec.\n",
                    CONFIG_VAR_TCP_TIMER_RESOLUTION_MSEC.name, m_sys_vars.tcp_timer_resolution_msec,
                    CONFIG_VAR_TIMER_RESOLUTION_MSEC.name, m_sys_vars.timer_resolution_msec,
                    m_sys_vars.timer_resolution_msec);
        m_runtime_registry.set_value(
            CONFIG_VAR_TCP_TIMER_RESOLUTION_MSEC,
            static_cast<int64_t>(m_sys_vars.timer_resolution_msec), change_reason::AutoCorrected,
            std::string("Cannot be smaller than ") + CONFIG_VAR_TIMER_RESOLUTION_MSEC.name);
    }

    if (strcmp(m_sys_vars.internal_thread_affinity_str, "-1") != 0) {
        if (mce_sys_var::env_to_cpuset(m_sys_vars.internal_thread_affinity_str,
                                       &m_sys_vars.internal_thread_affinity)) {
            vlog_printf(VLOG_WARNING,
                        "Failed to set internal thread affinity: %s...  deferring to cpu-0.\n",
                        m_sys_vars.internal_thread_affinity_str);
        }
    }

    if (m_sys_vars.buffer_batching_mode == BUFFER_BATCHING_NONE) {
        m_runtime_registry.set_value(CONFIG_VAR_TX_BUFS_BATCH_TCP, static_cast<int64_t>(1),
                                     change_reason::AutoCorrected,
                                     std::string(CONFIG_VAR_BUFFER_BATCHING_MODE.name) + "=NONE");
        m_runtime_registry.set_value(CONFIG_VAR_TX_BUFS_BATCH_UDP, static_cast<int64_t>(1),
                                     change_reason::AutoCorrected,
                                     std::string(CONFIG_VAR_BUFFER_BATCHING_MODE.name) + "=NONE");
        m_sys_vars.rx_bufs_batch = 1; // not a config key
    }

    if (m_sys_vars.memory_limit == 0) {
        m_runtime_registry.set_value(CONFIG_VAR_MEMORY_LIMIT,
                                     static_cast<int64_t>(MCE_DEFAULT_MEMORY_LIMIT),
                                     change_reason::AutoCorrected, "Default if zero");
    }
    if (m_sys_vars.heap_metadata_block == 0) {
        m_runtime_registry.set_value(CONFIG_VAR_HEAP_METADATA_BLOCK,
                                     static_cast<int64_t>(MCE_DEFAULT_HEAP_METADATA_BLOCK),
                                     change_reason::AutoCorrected, "Default if zero");
    }

    if (m_sys_vars.hugepage_size & (m_sys_vars.hugepage_size - 1)) {
        vlog_printf(VLOG_WARNING, "%s must be a power of 2. Fallback to default value (%s)\n",
                    CONFIG_VAR_HUGEPAGE_SIZE.name, option_size::to_str(MCE_DEFAULT_HUGEPAGE_SIZE));
        m_runtime_registry.set_value(CONFIG_VAR_HUGEPAGE_SIZE,
                                     static_cast<int64_t>(MCE_DEFAULT_HUGEPAGE_SIZE),
                                     change_reason::AutoCorrected, "Must be power of 2");
    }
    if (m_sys_vars.hugepage_size > MCE_MAX_HUGEPAGE_SIZE) {
        vlog_printf(
            VLOG_WARNING,
            "%s exceeds maximum possible hugepage size (%s). Fallback to default value (%s)\n",
            CONFIG_VAR_HUGEPAGE_SIZE.name, option_size::to_str(MCE_MAX_HUGEPAGE_SIZE),
            option_size::to_str(MCE_DEFAULT_HUGEPAGE_SIZE));
        m_runtime_registry.set_value(CONFIG_VAR_HUGEPAGE_SIZE,
                                     static_cast<int64_t>(MCE_DEFAULT_HUGEPAGE_SIZE),
                                     change_reason::AutoCorrected, "Capped by max hugepage size");
    }

    if ((m_sys_vars.enable_tso != option_3::OFF) && (m_sys_vars.ring_migration_ratio_tx != -1)) {
        m_runtime_registry.set_value(CONFIG_VAR_RING_MIGRATION_RATIO_TX, static_cast<int64_t>(-1),
                                     change_reason::AutoCorrected, "Forced when TSO enabled");
        vlog_printf(VLOG_DEBUG, "%s parameter is forced to %d in case %s is enabled\n",
                    CONFIG_VAR_RING_MIGRATION_RATIO_TX.name, -1, CONFIG_VAR_TSO.name);
    }
#ifdef DEFINED_UTLS
    m_runtime_registry.set_value(
        CONFIG_VAR_UTLS_HIGH_WMARK_DEK_CACHE_SIZE,
        static_cast<int64_t>(std::max(m_sys_vars.utls_high_wmark_dek_cache_size, 0LU)),
        change_reason::AutoCorrected, "Minimum 0");
    m_runtime_registry.set_value(
        CONFIG_VAR_UTLS_LOW_WMARK_DEK_CACHE_SIZE,
        static_cast<int64_t>(std::max(m_sys_vars.utls_low_wmark_dek_cache_size, 0LU)),
        change_reason::AutoCorrected, "Minimum 0");
    if (m_sys_vars.utls_low_wmark_dek_cache_size >= m_sys_vars.utls_high_wmark_dek_cache_size) {
        m_runtime_registry.set_value(
            CONFIG_VAR_UTLS_LOW_WMARK_DEK_CACHE_SIZE,
            static_cast<int64_t>(m_sys_vars.utls_high_wmark_dek_cache_size / 2U),
            change_reason::AutoCorrected,
            std::string("Must be < ") + CONFIG_VAR_UTLS_HIGH_WMARK_DEK_CACHE_SIZE.name);
    }

#endif /* DEFINED_UTLS */

    if (m_sys_vars.skip_poll_in_rx < 0 || m_sys_vars.skip_poll_in_rx > SKIP_POLL_IN_RX_EPOLL_ONLY) {
        m_runtime_registry.set_value(
            CONFIG_VAR_SKIP_POLL_IN_RX, static_cast<int64_t>(SKIP_POLL_IN_RX_DISABLE),
            change_reason::AutoCorrected,
            "Out of range 0-" + std::to_string(SKIP_POLL_IN_RX_EPOLL_ONLY));
    }

    // From fixup_params
    if (m_sys_vars.worker_threads > 0) {
        m_runtime_registry.set_value(
            CONFIG_VAR_SELECT_NUM_POLLS, static_cast<int64_t>(-1), change_reason::AutoCorrected,
            "Working in threads mode:" + std::string(CONFIG_VAR_WORKER_THREADS.name) + " > 0");
        m_runtime_registry.set_value(
            CONFIG_VAR_PROGRESS_ENGINE_INTERVAL, static_cast<int64_t>(0),
            change_reason::AutoCorrected,
            "Working in threads mode:" + std::string(CONFIG_VAR_WORKER_THREADS.name) + " > 0");
    }

    // From main.cpp
    if (m_sys_vars.ring_allocation_logic_rx == RING_LOGIC_PER_USER_ID) {
        vlog_printf(VLOG_WARNING,
                    "%s==user_id is not supported in configuration, use extra_api. Using default\n",
                    CONFIG_VAR_RING_ALLOCATION_LOGIC_RX.name);
        m_runtime_registry.set_value(
            CONFIG_VAR_RING_ALLOCATION_LOGIC_RX,
            static_cast<int64_t>(MCE_DEFAULT_RING_ALLOCATION_LOGIC_RX),
            change_reason::AutoCorrected,
            std::string(CONFIG_VAR_RING_ALLOCATION_LOGIC_RX.name) +
                "=user_id is not supported in configuration, use extra_api");
    }

    if (m_sys_vars.ring_allocation_logic_tx == RING_LOGIC_PER_USER_ID) {
        vlog_printf(VLOG_WARNING,
                    "%s==user_id is not supported in configuration, use extra_api. Using default\n",
                    CONFIG_VAR_RING_ALLOCATION_LOGIC_TX.name);
        m_runtime_registry.set_value(
            CONFIG_VAR_RING_ALLOCATION_LOGIC_TX,
            static_cast<int64_t>(MCE_DEFAULT_RING_ALLOCATION_LOGIC_TX),
            change_reason::AutoCorrected,
            std::string(CONFIG_VAR_RING_ALLOCATION_LOGIC_TX.name) +
                "=user_id is not supported in configuration, use extra_api");
    }
}
