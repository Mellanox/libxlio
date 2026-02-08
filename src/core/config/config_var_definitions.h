/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdint>

#include "config_var_info.h"
#include "core/util/sys_vars_types.h"
#include "core/xlio_types.h"
#include "vlogger/vlogger.h"

// Here we declare all configuration variables, for use by any code
// that needs to access the configuration variable names.
// The actual definitions of these variables are in sys_vars_configurator.cpp

// See comments in config_var_info.h for more information
extern const config_var_info_t<option_3::mode_t, int64_t> CONFIG_VAR_PRINT_REPORT;
extern const config_var_info_t<vlog_levels_t, int64_t> CONFIG_VAR_LOG_LEVEL;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_LOG_DETAILS;

extern const config_var_info_t<std::string> CONFIG_VAR_LOG_FILENAME;
extern const config_var_info_t<std::string> CONFIG_VAR_STATS_FILENAME;
extern const config_var_info_t<std::string> CONFIG_VAR_STATS_SHMEM_DIRNAME;
extern const config_var_info_t<std::string> CONFIG_VAR_SERVICE_DIR;
extern const config_var_info_t<std::string> CONFIG_VAR_APPLICATION_ID;
extern const config_var_info_t<std::string> CONFIG_VAR_ACCEL_CONTROL_RULES;
extern const config_var_info_t<std::string> CONFIG_VAR_INTERNAL_THREAD_AFFINITY;
extern const config_var_info_t<std::string> CONFIG_VAR_INTERNAL_THREAD_CPUSET;

extern const config_var_info_t<bool> CONFIG_VAR_SERVICE_ENABLE;
extern const config_var_info_t<bool> CONFIG_VAR_LOG_COLORS;
extern const config_var_info_t<bool> CONFIG_VAR_HANDLE_SIGINTR;
extern const config_var_info_t<bool> CONFIG_VAR_HANDLE_SIGSEGV;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_STATS_FD_NUM;
extern const config_var_info_t<bool> CONFIG_VAR_QUICK_START;

extern const config_var_info_t<ring_logic_t, int64_t> CONFIG_VAR_RING_ALLOCATION_LOGIC_TX;
extern const config_var_info_t<ring_logic_t, int64_t> CONFIG_VAR_RING_ALLOCATION_LOGIC_RX;
extern const config_var_info_t<int, int64_t> CONFIG_VAR_RING_MIGRATION_RATIO_TX;
extern const config_var_info_t<int, int64_t> CONFIG_VAR_RING_MIGRATION_RATIO_RX;
extern const config_var_info_t<int, int64_t> CONFIG_VAR_RING_LIMIT_PER_INTERFACE;
extern const config_var_info_t<int, int64_t> CONFIG_VAR_RING_DEV_MEM_TX;

extern const config_var_info_t<size_t, int64_t> CONFIG_VAR_ZC_CACHE_THRESHOLD;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TX_BUF_SIZE;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TCP_NODELAY_TRESHOLD;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TX_NUM_WRE;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TX_NUM_WRE_TO_SIGNAL;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TX_MAX_INLINE;
extern const config_var_info_t<bool> CONFIG_VAR_TX_MC_LOOPBACK;
extern const config_var_info_t<bool> CONFIG_VAR_TX_NONBLOCKED_EAGAINS;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TX_PREFETCH_BYTES;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TX_BUFS_BATCH_UDP;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TX_BUFS_BATCH_TCP;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TX_SEGS_BATCH_TCP;

extern const config_var_info_t<bool> CONFIG_VAR_STRQ;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_STRQ_NUM_STRIDES;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_STRQ_STRIDE_SIZE_BYTES;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_STRQ_STRIDES_COMPENSATION_LEVEL;

extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_RX_BUF_SIZE;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_RX_NUM_WRE;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_RX_NUM_WRE_TO_POST_RECV;
extern const config_var_info_t<int32_t, int64_t> CONFIG_VAR_RX_NUM_POLLS;
extern const config_var_info_t<int32_t, int64_t> CONFIG_VAR_RX_NUM_POLLS_INIT;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_RX_UDP_POLL_OS_RATIO;
extern const config_var_info_t<ts_conversion_mode_t, int64_t> CONFIG_VAR_HW_TS_CONVERSION_MODE;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_RX_POLL_YIELD;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_RX_BYTE_MIN_LIMIT;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_RX_PREFETCH_BYTES;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_RX_PREFETCH_BYTES_BEFORE_POLL;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_RX_CQ_DRAIN_RATE_NSEC;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_GRO_STREAMS_MAX;
extern const config_var_info_t<bool> CONFIG_VAR_DISABLE_FLOW_TAG;
extern const config_var_info_t<bool> CONFIG_VAR_TCP_2T_RULES;
extern const config_var_info_t<bool> CONFIG_VAR_TCP_3T_RULES;
extern const config_var_info_t<bool> CONFIG_VAR_UDP_3T_RULES;
extern const config_var_info_t<bool> CONFIG_VAR_ETH_MC_L2_ONLY_RULES;
extern const config_var_info_t<bool> CONFIG_VAR_MC_FORCE_FLOWTAG;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TX_SEGS_RING_BATCH_TCP;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TX_SEGS_POOL_BATCH_TCP;

extern const config_var_info_t<bool> CONFIG_VAR_SELECT_CPU_USAGE_STATS;
extern const config_var_info_t<int32_t, int64_t> CONFIG_VAR_SELECT_NUM_POLLS;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_SELECT_POLL_OS_RATIO;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_SELECT_SKIP_OS;

extern const config_var_info_t<bool> CONFIG_VAR_CQ_MODERATION_ENABLE;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_CQ_MODERATION_COUNT;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_CQ_MODERATION_PERIOD_USEC;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_CQ_AIM_MAX_COUNT;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_CQ_AIM_MAX_PERIOD_USEC;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_CQ_AIM_INTERVAL_MSEC;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_CQ_AIM_INTERRUPTS_RATE_PER_SEC;

extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_CQ_POLL_BATCH_MAX;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_PROGRESS_ENGINE_INTERVAL;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_PROGRESS_ENGINE_WCE_MAX;
extern const config_var_info_t<bool> CONFIG_VAR_CQ_KEEP_QP_FULL;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_QP_COMPENSATION_LEVEL;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_MAX_TSO_SIZE;
extern const config_var_info_t<uint16_t, int64_t> CONFIG_VAR_WORKER_THREADS;
extern const config_var_info_t<bool> CONFIG_VAR_OFFLOADED_SOCKETS;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TIMER_RESOLUTION_MSEC;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TCP_TIMER_RESOLUTION_MSEC;
extern const config_var_info_t<option_tcp_ctl_thread::mode_t, int64_t> CONFIG_VAR_TCP_CTL_THREAD;
extern const config_var_info_t<tcp_ts_opt_t, int64_t> CONFIG_VAR_TCP_TIMESTAMP_OPTION;
extern const config_var_info_t<bool> CONFIG_VAR_TCP_NODELAY;
extern const config_var_info_t<bool> CONFIG_VAR_TCP_QUICKACK;
extern const config_var_info_t<bool> CONFIG_VAR_TCP_PUSH_FLAG;
extern const config_var_info_t<bool> CONFIG_VAR_AVOID_SYS_CALLS_ON_TCP_FD;
extern const config_var_info_t<bool> CONFIG_VAR_ALLOW_PRIVILEGED_SOCK_OPT;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_WAIT_AFTER_JOIN_MSEC;
extern const config_var_info_t<buffer_batching_mode_t, int64_t> CONFIG_VAR_BUFFER_BATCHING_MODE;
extern const config_var_info_t<option_alloc_type::mode_t, bool> CONFIG_VAR_MEM_ALLOC_TYPE;
extern const config_var_info_t<size_t, int64_t> CONFIG_VAR_MEMORY_LIMIT;
extern const config_var_info_t<size_t, int64_t> CONFIG_VAR_MEMORY_LIMIT_USER;
extern const config_var_info_t<size_t, int64_t> CONFIG_VAR_HEAP_METADATA_BLOCK;
extern const config_var_info_t<size_t, int64_t> CONFIG_VAR_HUGEPAGE_SIZE;
extern const config_var_info_t<bool> CONFIG_VAR_FORK;
extern const config_var_info_t<bool> CONFIG_VAR_CLOSE_ON_DUP2;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_MTU;
#if defined(DEFINED_NGINX)
extern const config_var_info_t<int, int64_t> CONFIG_VAR_NGINX_UDP_POOL_SIZE;
extern const config_var_info_t<int, int64_t> CONFIG_VAR_NGINX_UDP_POOL_RX_NUM_BUFFS_REUSE;
#endif
extern const config_var_info_t<int, int64_t> CONFIG_VAR_NGINX_WORKERS_NUM;
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
extern const config_var_info_t<int, int64_t> CONFIG_VAR_SRC_PORT_STRIDE;
extern const config_var_info_t<bool> CONFIG_VAR_DISTRIBUTE_CQ;
#endif
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_MSS;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TCP_CC_ALGO;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_SPEC;

extern const config_var_info_t<option_3::mode_t, int64_t> CONFIG_VAR_TSO;
#ifdef DEFINED_UTLS
extern const config_var_info_t<bool> CONFIG_VAR_UTLS_RX;
extern const config_var_info_t<bool> CONFIG_VAR_UTLS_TX;
extern const config_var_info_t<size_t, int64_t> CONFIG_VAR_UTLS_HIGH_WMARK_DEK_CACHE_SIZE;
extern const config_var_info_t<size_t, int64_t> CONFIG_VAR_UTLS_LOW_WMARK_DEK_CACHE_SIZE;
#endif /* DEFINED_UTLS */

extern const config_var_info_t<option_3::mode_t, int64_t> CONFIG_VAR_LRO;

extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_NETLINK_TIMER_MSEC;

extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_NEIGH_UC_ARP_QUATA;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_NEIGH_UC_ARP_DELAY_MSEC;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_NEIGH_NUM_ERR_RETRIES;

extern const config_var_info_t<bool> CONFIG_VAR_DEFERRED_CLOSE;
extern const config_var_info_t<bool> CONFIG_VAR_TCP_ABORT_ON_CLOSE;
extern const config_var_info_t<bool> CONFIG_VAR_RX_POLL_ON_TX_TCP;
extern const config_var_info_t<bool> CONFIG_VAR_RX_CQ_WAIT_CTRL;
extern const config_var_info_t<uint32_t, int64_t> CONFIG_VAR_TCP_SEND_BUFFER_SIZE;
extern const config_var_info_t<skip_poll_in_rx_t, int64_t> CONFIG_VAR_SKIP_POLL_IN_RX;
extern const config_var_info_t<multilock_t, bool> CONFIG_VAR_MULTILOCK;

extern const config_var_info_t<xlio_exception_handling, int64_t> CONFIG_VAR_EXCEPTION_HANDLING;
