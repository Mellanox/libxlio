/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "utils/rdtsc.h"
#include "vlogger/vlogger.h"

#include "core/event/event_handler_manager.h"
#include "core/sock/sockinfo_tcp.h"
#include "core/lwip/tcp_impl.h"
#include "xlio_lwip.h"

// debugging macros
#define MODULE_NAME "lwip"
#undef MODULE_HDR_INFO
#define MODULE_HDR_INFO MODULE_NAME ":%s%d:%s() "
#undef __INFO__
#define __INFO__ ""

#define lwip_logpanic   __log_info_panic
#define lwip_logerr     __log_info_err
#define lwip_logwarn    __log_info_warn
#define lwip_loginfo    __log_info_info
#define lwip_logdbg     __log_info_dbg
#define lwip_logfunc    __log_info_func
#define lwip_logfuncall __log_info_funcall

int32_t enable_wnd_scale = 0;
u32_t rcv_wnd_scale = 0;

u32_t xlio_lwip::sys_now(void)
{
    struct timespec now;

    gettimefromtsc(&now);
    return now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

u8_t xlio_lwip::read_tcp_timestamp_option(void)
{
    u8_t res = (safe_mce_sys().tcp_ts_opt == TCP_TS_OPTION_FOLLOW_OS)
        ? safe_mce_sys().sysctl_reader.get_net_ipv4_tcp_timestamps()
        : (safe_mce_sys().tcp_ts_opt == TCP_TS_OPTION_ENABLE ? 1 : 0);
    if (res) {
#if LWIP_TCP_TIMESTAMPS
        lwip_logdbg("TCP timestamp option has been enabled");
#else
        lwip_logwarn(
            "Cannot enable TCP timestamp option because LWIP_TCP_TIMESTAMPS is not defined");
        res = 0;
#endif
    }
    return res;
}

xlio_lwip *g_p_lwip = nullptr;

/**
 * LWIP "network" driver code
 */

xlio_lwip::xlio_lwip()
{
    m_run_timers = false;

    if (*g_p_vlogger_level >= VLOG_DEBUG) {
        __xlio_print_conf_file(__instance_list);
    }

    lwip_logdbg("");

    lwip_cc_algo_module = (enum cc_algo_mod)safe_mce_sys().lwip_cc_algo_mod;

    lwip_tcp_mss = get_lwip_tcp_mss(safe_mce_sys().mtu);
    lwip_tcp_nodelay_treshold = safe_mce_sys().tcp_nodelay_treshold;

    enable_push_flag = !!safe_mce_sys().tcp_push_flag;
    enable_ts_option = read_tcp_timestamp_option();
    int is_window_scaling_enabled = safe_mce_sys().sysctl_reader.get_tcp_window_scaling();
    if (is_window_scaling_enabled) {
        int rmem_max_value = safe_mce_sys().sysctl_reader.get_tcp_rmem()->max_value;
        int core_rmem_max = safe_mce_sys().sysctl_reader.get_net_core_rmem_max();
        enable_wnd_scale = 1;
        rcv_wnd_scale = get_window_scaling_factor(rmem_max_value, core_rmem_max);
    } else {
        enable_wnd_scale = 0;
        rcv_wnd_scale = 0;
    }

    // In case of batching is not requested we fetch tcp_seg from the ring directly.
    // This creates hot segments, CPU cache wise.
    if (safe_mce_sys().tx_segs_batch_tcp == 1U) {
        register_tcp_seg_alloc(sockinfo_tcp::tcp_seg_alloc_direct);
        register_tcp_seg_free(sockinfo_tcp::tcp_seg_free_direct);
    } else {
        register_tcp_seg_alloc(sockinfo_tcp::tcp_seg_alloc_cached);
        register_tcp_seg_free(sockinfo_tcp::tcp_seg_free_cached);
    }

    register_tcp_tx_pbuf_alloc(sockinfo_tcp::tcp_tx_pbuf_alloc);
    register_tcp_tx_pbuf_free(sockinfo_tcp::tcp_tx_pbuf_free);
    register_tcp_rx_pbuf_free(sockinfo_tcp::tcp_rx_pbuf_free);
    register_tcp_state_observer(sockinfo_tcp::tcp_state_observer);
    register_ip_route_mtu(sockinfo_tcp::get_route_mtu);
    register_sys_now(sys_now);
    set_tmr_resolution(safe_mce_sys().tcp_timer_resolution_msec);
    // tcp_ticks increases in the rate of tcp slow_timer
    void *node = g_p_event_handler_manager->register_timer_event(
        safe_mce_sys().tcp_timer_resolution_msec * 2, this, PERIODIC_TIMER, nullptr);
    if (!node) {
        lwip_logdbg("LWIP: failed to register timer event");
        free_lwip_resources();
        throw_xlio_exception("LWIP: failed to register timer event");
    }
    lwip_logdbg("LWIP subsystem initialized");
}

xlio_lwip::~xlio_lwip()
{
    free_lwip_resources();
}

void xlio_lwip::free_lwip_resources(void)
{
    /* TODO - revert the constructor */
}

void xlio_lwip::handle_timer_expired(void *user_data)
{
    NOT_IN_USE(user_data);
    tcp_ticks++;
}

uint32_t get_lwip_tcp_mss(uint32_t mtu)
{
    /*
     * TCP MSS is derived from MTU: MSS = MTU - 40 (IP + TCP headers).
     * mtu==0: follow per-interface MTU (return 0, lwIP calculates per connection).
     * mtu!=0: use fixed MSS = mtu - 40, at least 1.
     */
    if (mtu == 0) {
        return 0;
    }
    return (std::max(mtu, (IP_HLEN + TCP_HLEN + 1)) - IP_HLEN - TCP_HLEN);
}
