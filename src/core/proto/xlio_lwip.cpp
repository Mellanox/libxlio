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

    lwip_tcp_mss = get_lwip_tcp_mss(safe_mce_sys().mtu, safe_mce_sys().lwip_mss);
    lwip_tcp_snd_buf = safe_mce_sys().tcp_send_buffer_size;
    lwip_tcp_nodelay_treshold = safe_mce_sys().tcp_nodelay_treshold;
    BULLSEYE_EXCLUDE_BLOCK_END

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

uint32_t get_lwip_tcp_mss(uint32_t mtu, uint32_t lwip_mss)
{
    uint32_t _lwip_tcp_mss;

    /*
     * lwip_tcp_mss calculation
     * 1. safe_mce_sys().mtu==0 && safe_mce_sys().lwip_mss==0 ==> lwip_tcp_mss = 0 (namelyl-must be
     * calculated per interface)
     * 2. safe_mce_sys().mtu==0 && safe_mce_sys().lwip_mss!=0 ==> lwip_tcp_mss =
     * safe_mce_sys().lwip_mss
     * 3. safe_mce_sys().mtu!=0 && safe_mce_sys().lwip_mss==0 ==> lwip_tcp_mss = safe_mce_sys().mtu
     * - IP header len - TCP header len (must be positive)
     * 4. safe_mce_sys().mtu!=0 && safe_mce_sys().lwip_mss!=0 ==> lwip_tcp_mss =
     * safe_mce_sys().lwip_mss
     */
    switch (lwip_mss) {
    case MSS_FOLLOW_MTU: /* 0 */
        switch (mtu) {
        case MTU_FOLLOW_INTERFACE:
            _lwip_tcp_mss = 0; /* MSS must follow the specific MTU per interface */
            break;
        default:
            // set MSS to match XLIO_MTU, MSS is equal to (XLIO_MTU-40), but forced to be at
            // least 1.
            _lwip_tcp_mss = (std::max(mtu, (IP_HLEN + TCP_HLEN + 1)) - IP_HLEN - TCP_HLEN);
            break;
        }
        break;
    default:
        _lwip_tcp_mss = (std::max(lwip_mss, 1U));
        break;
    }
    return _lwip_tcp_mss;
}
