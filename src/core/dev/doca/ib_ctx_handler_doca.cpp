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

#include "util/vtypes.h"
#ifndef DEFINED_DPCP_PATH_RX_AND_TX
#include "vlogger/vlogger.h"
#include <util/sys_vars.h>
#include "dev/ib_ctx_handler.h"
#include "dev/time_converter_rtc.h"
#include "sock/sock-app.h"

#define MODULE_NAME "ibch"
DOCA_LOG_REGISTER(ibch);

#define ibch_logpanic   __log_panic
#define ibch_logerr     __log_err
#define ibch_logwarn    __log_warn
#define ibch_loginfo    __log_info
#define ibch_logdbg     __log_info_dbg
#define ibch_logfunc    __log_info_func
#define ibch_logfuncall __log_info_funcall

ib_ctx_handler_doca::ib_ctx_handler_doca(doca_devinfo *devinfo, std::string &ibname,
                                         const char *ifname)
    : m_ifname(ifname)
    , m_ibname(ibname)
{
    if (!devinfo) {
        ibch_logpanic("Nullptr devinfo in ib_ctx_handler");
    }

    open_doca_dev(devinfo);
    ibch_logdbg("Device opened doca_dev: %p", m_doca_dev);
}

ib_ctx_handler_doca::~ib_ctx_handler_doca()
{
    stop_doca_flow_port();
    if (m_doca_dev) {
        doca_error_t err = doca_dev_close(m_doca_dev);
        if (DOCA_IS_ERROR(err)) {
            PRINT_DOCA_ERR(ibch_logerr, err, "doca_dev_close dev: %p,%s. PID: %d", m_doca_dev,
                           m_ibname.c_str(), static_cast<int>(getpid()));
        }
    }
}

void ib_ctx_handler_doca::open_doca_dev(doca_devinfo *devinfo)
{
#ifdef DEFINED_NGINX
    if (g_p_app && g_p_app->type == APP_NGINX && (g_p_app->get_worker_id() == -1)) {
        return;
    }
#endif

    doca_error_t err = doca_dev_open(devinfo, &m_doca_dev);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(ibch_logpanic, err, "doca_dev_open devinfo: %p,%s", devinfo,
                       m_ibname.c_str());
    }
}

doca_flow_port *ib_ctx_handler_doca::get_doca_flow_port()
{
    if (unlikely(!m_doca_port)) {
        doca_error_t err = start_doca_flow_port();
        if (DOCA_IS_ERROR(err)) {
            PRINT_DOCA_ERR(ibch_logerr, err, "start_doca_flow_port dev: %p,%s", m_doca_dev,
                           m_ibname.c_str());
            return nullptr;
        }
    }

    return m_doca_port;
}

doca_flow_pipe *ib_ctx_handler_doca::get_doca_root_pipe()
{
    if (!get_doca_flow_port()) {
        return nullptr;
    }

    if (!m_doca_root_pipe) {
        doca_error_t err = create_doca_root_pipe();
        if (DOCA_IS_ERROR(err)) {
            PRINT_DOCA_ERR(ibch_logerr, err, "create_doca_root_pipe dev/pipe: %p,%s", m_doca_dev,
                           m_ibname.c_str());
            return nullptr;
        }
    }

    return m_doca_root_pipe;
}

doca_error_t ib_ctx_handler_doca::start_doca_flow_port()
{
    doca_error_t close_result;
    struct doca_flow_port_cfg *port_cfg = nullptr;

    doca_error_t err = doca_flow_port_cfg_create(&port_cfg);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(ibch_logerr, err, "doca_flow_port_cfg_create");
        goto destroy_port_cfg;
    }

    err = doca_flow_port_cfg_set_dev(port_cfg, m_doca_dev);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(ibch_logerr, err, "doca_flow_port_cfg_set_dev dev/portcfg: %p,%s,%p",
                       m_doca_dev, m_ibname.c_str(), port_cfg);
        goto destroy_port_cfg;
    }

    err = doca_flow_port_start(port_cfg, &m_doca_port);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(ibch_logerr, err, "doca_flow_port_start dev/portcfg: %p,%s,%p", m_doca_dev,
                       m_ibname.c_str(), port_cfg);
        goto destroy_port_cfg;
    }

    ibch_logdbg("DOCA Flow Port initialized. dev/port: %p,%s,%p", m_doca_dev, m_ibname.c_str(),
                m_doca_port);

destroy_port_cfg:
    close_result = doca_flow_port_cfg_destroy(port_cfg);
    if (DOCA_IS_ERROR(close_result)) {
        PRINT_DOCA_ERR(ibch_logerr, err, "doca_flow_port_start dev/port: %p,%s,%p", m_doca_dev,
                       m_ibname.c_str(), m_doca_port);
        DOCA_ERROR_PROPAGATE(err, close_result);
    }

    return err;
}

void ib_ctx_handler_doca::stop_doca_flow_port()
{
    if (m_doca_root_pipe) {
        doca_flow_pipe_destroy(m_doca_root_pipe);
        m_doca_root_pipe = nullptr;
    }

    if (m_doca_port) {
        doca_error_t err = doca_flow_port_stop(m_doca_port);
        if (DOCA_IS_ERROR(err)) {
            PRINT_DOCA_ERR(ibch_logerr, err, "doca_flow_port_stop port: %p,%s", m_doca_port,
                           m_ibname.c_str());
        }
        m_doca_port = nullptr;
        ibch_logdbg("DOCA port stopped %s", m_ibname.c_str());
    }
}

doca_error_t ib_ctx_handler_doca::create_doca_root_pipe()
{
    doca_flow_pipe_cfg *pipe_cfg = nullptr;

    doca_error_t tmp_rc;
    doca_error_t rc = doca_flow_pipe_cfg_create(&pipe_cfg, m_doca_port);
    if (DOCA_IS_ERROR(rc)) {
        PRINT_DOCA_ERR(ibch_logerr, rc, "doca_flow_port_stop port/dev: %p,%s", m_doca_port,
                       m_ibname.c_str());
        return rc;
    }

    std::string pipe_name = "ROOT_PIPE-";
    pipe_name += m_ibname;

    rc = doca_flow_pipe_cfg_set_name(pipe_cfg, pipe_name.c_str());
    if (DOCA_IS_ERROR(rc)) {
        PRINT_DOCA_ERR(ibch_logerr, rc, "doca_flow_pipe_cfg_set_name port/dev: %p,%s", m_doca_port,
                       m_ibname.c_str());
        goto destroy_pipe_cfg;
    }

    rc = doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_CONTROL);
    if (DOCA_IS_ERROR(rc)) {
        PRINT_DOCA_ERR(ibch_logerr, rc, "doca_flow_pipe_cfg_set_type port/dev: %p,%s", m_doca_port,
                       m_ibname.c_str());
        goto destroy_pipe_cfg;
    }

    rc = doca_flow_pipe_cfg_set_is_root(pipe_cfg, true);
    if (DOCA_IS_ERROR(rc)) {
        PRINT_DOCA_ERR(ibch_logerr, rc, "doca_flow_pipe_cfg_set_is_root port/dev: %p,%s",
                       m_doca_port, m_ibname.c_str());
        goto destroy_pipe_cfg;
    }

    doca_flow_match match_mask;
    memset(&match_mask, 0, sizeof(match_mask));

    rc = doca_flow_pipe_cfg_set_match(pipe_cfg, nullptr, &match_mask);
    if (DOCA_IS_ERROR(rc)) {
        PRINT_DOCA_ERR(ibch_logerr, rc, "doca_flow_pipe_cfg_set_match port/dev: %p,%s", m_doca_port,
                       m_ibname.c_str());
        goto destroy_pipe_cfg;
    }

    rc = doca_flow_pipe_create(pipe_cfg, nullptr, nullptr, &m_doca_root_pipe);
    if (DOCA_IS_ERROR(rc)) {
        PRINT_DOCA_ERR(ibch_logerr, rc, "doca_flow_pipe_create port/dev: %p,%s", m_doca_port,
                       m_ibname.c_str());
        goto destroy_pipe_cfg;
    }

    ibch_logdbg("DOCA Flow Root Pipe created. dev/port/pipe: %s,%p,%p", m_ibname.c_str(),
                m_doca_port, m_doca_root_pipe);

destroy_pipe_cfg:
    tmp_rc = doca_flow_pipe_cfg_destroy(pipe_cfg);
    if (DOCA_IS_ERROR(tmp_rc)) {
        PRINT_DOCA_ERR(ibch_logerr, tmp_rc, "doca_flow_pipe_cfg_destroy port/dev: %p,%s",
                       m_doca_port, m_ibname.c_str());
        DOCA_ERROR_PROPAGATE(rc, tmp_rc);
    }

    return rc;
}

void ib_ctx_handler_doca::set_ctx_time_converter_status(ts_conversion_mode_t conversion_mode)
{
    if (m_p_ctx_time_converter) {
        /*
         * Don't override time_converter object. Current method may be
         * called more than once if multiple slaves point to the same
         * ib_context.
         * If we overrode the time_converter we would lose the object
         * and wouldn't be able to stop its timer and destroy it.
         */
        return;
    }

    switch (conversion_mode) {
    case TS_CONVERSION_MODE_RTC:
    default:
        m_p_ctx_time_converter = new time_converter_rtc();
        break;
    }
}

void ib_ctx_handler_doca::convert_hw_time_to_system_time(uint64_t hwtime, struct timespec *systime)
{
    m_p_ctx_time_converter->convert_hw_time_to_system_time(hwtime, systime);
}

#endif // !DEFINED_DPCP_PATH_RX_AND_TX
