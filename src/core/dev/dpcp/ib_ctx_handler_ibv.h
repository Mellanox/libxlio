/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef IB_CTX_HANDLER_IBV_H
#define IB_CTX_HANDLER_IBV_H

#include "util/vtypes.h"
#ifdef DEFINED_DPCP_PATH_RX_OR_TX
#include <infiniband/verbs.h>
#include <unordered_map>
#include "event/event_handler_ibverbs.h"
#include "ib/base/verbs_extra.h"
#include <mellanox/dpcp.h>
#include "dev/time_converter.h"
#include "utils/lock_wrapper.h"

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

class ib_ctx_handler_ibv : public event_handler_ibverbs {
public:
    ib_ctx_handler_ibv(ibv_device *ibvdevice, std::string &ibname);
    virtual ~ib_ctx_handler_ibv();
    ibv_pd *get_ibv_pd() { return m_p_ibv_pd; }
    ibv_device *get_ibv_device() { return m_p_ibv_device; }
    struct ibv_context *get_ibv_context() { return m_p_ibv_context; }
    dpcp::adapter *set_dpcp_adapter();
    dpcp::adapter *get_dpcp_adapter() { return m_p_adapter; }
    void check_capabilities();
    xlio_ibv_device_attr_ex *get_ibv_device_attr_ex() { return m_p_ibv_device_attr; }
    uint32_t mem_reg(void *addr, size_t length, uint64_t access);
    void mem_dereg(uint32_t lkey);
    struct ibv_mr *get_mem_reg(uint32_t lkey);
    uint32_t user_mem_reg(void *addr, size_t length, uint64_t access);
    void set_burst_capability(bool burst);
    bool get_burst_capability() const { return m_pacing_caps.burst; }
    bool is_packet_pacing_supported(uint32_t rate) const;
    size_t get_on_device_memory_size() { return m_on_device_memory; }
    void set_ctx_time_converter_status(ts_conversion_mode_t conversion_mode);
    virtual void handle_event_ibverbs_cb(void *ev_data, void *ctx);
    bool is_removed() { return m_removed; }
    void set_flow_tag_capability(bool flow_tag_capability)
    {
        m_flow_tag_enabled = flow_tag_capability;
    }
    bool get_flow_tag_capability() const { return m_flow_tag_enabled; }

    xlio_ibv_device_attr *get_ibv_device_attr()
    {
        return xlio_get_device_orig_attr(m_p_ibv_device_attr);
    }

    void convert_hw_time_to_system_time(uint64_t hwtime, struct timespec *systime)
    {
        m_p_ctx_time_converter->convert_hw_time_to_system_time(hwtime, systime);
    }

private:
    void handle_event_device_fatal();

    ibv_device *m_p_ibv_device; // HCA handle
    struct ibv_context *m_p_ibv_context = nullptr;
    dpcp::adapter *m_p_adapter;
    xlio_ibv_device_attr_ex *m_p_ibv_device_attr;
    ibv_pd *m_p_ibv_pd;
    lock_spin m_lock_umr;
    time_converter *m_p_ctx_time_converter;
    mr_map_lkey_t m_mr_map_lkey;
    std::unordered_map<void *, uint32_t> m_user_mem_lkey_map;
    pacing_caps_t m_pacing_caps;
    size_t m_on_device_memory;
    bool m_flow_tag_enabled;
    bool m_removed;
    std::string &m_ibname;
};
#endif // DEFINED_DPCP_PATH_RX_OR_TX
#endif // IB_CTX_HANDLER_IBV_H
