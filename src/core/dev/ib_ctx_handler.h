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

#ifndef IB_CTX_HANDLER_H
#define IB_CTX_HANDLER_H

#include <infiniband/verbs.h>
#include <unordered_map>

#include "event/event_handler_ibverbs.h"
#include "dev/time_converter.h"
#include "ib/base/verbs_extra.h"
#include "utils/lock_wrapper.h"
#include <mellanox/dpcp.h>
#include <doca_dev.h>
#include <doca_flow.h>
#include <doca_pe.h>

typedef std::unordered_map<uint32_t, struct ibv_mr *> mr_map_lkey_t;

struct pacing_caps_t {
    uint32_t rate_limit_min;
    uint32_t rate_limit_max;
    bool burst;

    pacing_caps_t()
        : rate_limit_min(0)
        , rate_limit_max(0)
        , burst(false) {};
};

// client to event manager 'command' invoker (??)
//
class ib_ctx_handler : public event_handler_ibverbs {
public:
public:
    ib_ctx_handler(doca_devinfo *devinfo, const char *ibname, ibv_device *ibvdevice);
    virtual ~ib_ctx_handler();

    /*
     * on init or constructor:
     *      register to event manager with m_channel and this.
     * */
    ibv_pd *get_ibv_pd() { return m_p_ibv_pd; }
    ibv_device *get_ibv_device() { return m_p_ibv_device; }
    doca_dev *get_doca_device() const { return m_doca_dev; }
    doca_flow_port *get_doca_flow_port();
    doca_flow_pipe *get_doca_root_pipe();
    const std::string &get_ibname() const { return m_ibname; }
    struct ibv_context *get_ibv_context() { return m_p_ibv_context; }
    dpcp::adapter *set_dpcp_adapter();
    dpcp::adapter *get_dpcp_adapter() { return m_p_adapter; }
    void check_capabilities();
    void stop_doca_flow_port();
    xlio_ibv_device_attr *get_ibv_device_attr()
    {
        return xlio_get_device_orig_attr(m_p_ibv_device_attr);
    }
    xlio_ibv_device_attr_ex *get_ibv_device_attr_ex() { return m_p_ibv_device_attr; }
    uint32_t mem_reg(void *addr, size_t length, uint64_t access);
    void mem_dereg(uint32_t lkey);
    struct ibv_mr *get_mem_reg(uint32_t lkey);
    uint32_t user_mem_reg(void *addr, size_t length, uint64_t access);
    bool is_removed() { return m_removed; }
    void set_ctx_time_converter_status(ts_conversion_mode_t conversion_mode);
    void set_flow_tag_capability(bool flow_tag_capability);
    bool get_flow_tag_capability() { return m_flow_tag_enabled; } // m_flow_tag_capability
    void set_burst_capability(bool burst);
    bool get_burst_capability() { return m_pacing_caps.burst; }
    bool is_packet_pacing_supported(uint32_t rate = 1);
    size_t get_on_device_memory_size() { return m_on_device_memory; }
    bool is_active(int port_num);
    bool is_mlx4() { return is_mlx4(get_ibname().c_str()); }
    bool is_notification_affinity_supported() const { return m_notification_affinity_cap; }
    static bool is_mlx4(const char *dev) { return strncmp(dev, "mlx4", 4) == 0; }
    virtual void handle_event_ibverbs_cb(void *ev_data, void *ctx);

    void print_val();

    inline void convert_hw_time_to_system_time(uint64_t hwtime, struct timespec *systime)
    {
        m_p_ctx_time_converter->convert_hw_time_to_system_time(hwtime, systime);
    }

private:
    void open_doca_dev(doca_devinfo *devinfo);
    void check_doca_dev_caps(doca_devinfo *devinfo);
    void handle_event_device_fatal();
    doca_error_t start_doca_flow_port();
    doca_error_t create_doca_root_pipe();

    ibv_device *m_p_ibv_device; // HCA handle
    struct ibv_context *m_p_ibv_context = nullptr;
    dpcp::adapter *m_p_adapter;
    doca_dev *m_doca_dev = nullptr;
    doca_flow_port *m_doca_port = nullptr;
    doca_flow_pipe *m_doca_root_pipe = nullptr;
    xlio_ibv_device_attr_ex *m_p_ibv_device_attr;
    ibv_pd *m_p_ibv_pd;
    bool m_flow_tag_enabled;
    pacing_caps_t m_pacing_caps;
    size_t m_on_device_memory;
    bool m_removed;
    bool m_notification_affinity_cap = false;
    lock_spin m_lock_umr;
    time_converter *m_p_ctx_time_converter;
    mr_map_lkey_t m_mr_map_lkey;
    std::unordered_map<void *, uint32_t> m_user_mem_lkey_map;
    std::string m_ibname;
};

#endif
