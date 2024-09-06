/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
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

#include <array>
#include <mutex>
#include <infiniband/verbs.h>

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include <util/sys_vars.h>
#include "dev/ib_ctx_handler.h"
#include "ib/base/verbs_extra.h"
#include "dev/time_converter_ib_ctx.h"
#include "dev/time_converter_ptp.h"
#include "dev/time_converter_rtc.h"
#include "util/valgrind.h"
#include "event/event_handler_manager.h"
#include "sock/sock-app.h"

#define MODULE_NAME "ibch"

#define ibch_logpanic   __log_panic
#define ibch_logerr     __log_err
#define ibch_logwarn    __log_warn
#define ibch_loginfo    __log_info
#define ibch_logdbg     __log_info_dbg
#define ibch_logfunc    __log_info_func
#define ibch_logfuncall __log_info_funcall

ib_ctx_handler::ib_ctx_handler(doca_devinfo *devinfo, const char *ibname, ibv_device *ibvdevice)
    : m_flow_tag_enabled(false)
    , m_on_device_memory(0)
    , m_removed(false)
    , m_lock_umr("spin_lock_umr")
    , m_p_ctx_time_converter(nullptr)
{
    if (!devinfo) {
        ibch_logpanic("Nullptr devinfo in ib_ctx_handler");
    }

    if (!ibvdevice) {
        ibch_logpanic("Nullptr ibv_device in ib_ctx_handler");
    }

    m_ibname = ibname;

    open_doca_dev(devinfo);
    check_doca_dev_caps(devinfo);

    m_p_ibv_device = ibvdevice;

    m_p_adapter = set_dpcp_adapter();
    if (!m_p_adapter) {
        ibch_logpanic("ibv device %p adapter allocation failure (errno=%d %m)", m_p_ibv_device,
                      errno);
    }

    ibch_logdbg("Device opened doca_dev: %p", m_doca_dev);

    VALGRIND_MAKE_MEM_DEFINED(m_p_ibv_pd, sizeof(struct ibv_pd));

    m_p_ibv_device_attr = new xlio_ibv_device_attr_ex();
    if (!m_p_ibv_device_attr) {
        ibch_logpanic("ibv device %p attr allocation failure (ibv context %p) (errno=%d %m)",
                      m_p_ibv_device, m_p_ibv_context, errno);
    }
    xlio_ibv_device_attr_comp_mask(m_p_ibv_device_attr);
    IF_VERBS_FAILURE(xlio_ibv_query_device(m_p_ibv_context, m_p_ibv_device_attr))
    {
        ibch_logerr("ibv_query_device failed on ibv device %p (ibv context %p) (errno=%d %m)",
                    m_p_ibv_device, m_p_ibv_context, errno);
        goto err;
    }
    ENDIF_VERBS_FAILURE;

    // update device memory capabilities
    m_on_device_memory = xlio_ibv_dm_size(m_p_ibv_device_attr);

#ifdef DEFINED_IBV_PACKET_PACING_CAPS
    if (xlio_is_pacing_caps_supported(m_p_ibv_device_attr)) {
        m_pacing_caps.rate_limit_min = m_p_ibv_device_attr->packet_pacing_caps.qp_rate_limit_min;
        m_pacing_caps.rate_limit_max = m_p_ibv_device_attr->packet_pacing_caps.qp_rate_limit_max;
    }
#endif // DEFINED_IBV_PACKET_PACING_CAPS

    g_p_event_handler_manager->register_ibverbs_event(m_p_ibv_context->async_fd, this,
                                                      m_p_ibv_context, 0);

    return;

err:
    if (m_p_ibv_device_attr) {
        delete m_p_ibv_device_attr;
    }

    if (m_p_ibv_pd) {
        ibv_dealloc_pd(m_p_ibv_pd);
    }

    if (m_p_adapter) {
        delete m_p_adapter;
        m_p_ibv_context = nullptr;
    }
}

ib_ctx_handler::~ib_ctx_handler()
{
    if (!m_removed) {
        g_p_event_handler_manager->unregister_ibverbs_event(m_p_ibv_context->async_fd, this);
    }

    // must delete ib_ctx_handler only after freeing all resources that
    // are still associated with the PD m_p_ibv_pd
    BULLSEYE_EXCLUDE_BLOCK_START

    mr_map_lkey_t::iterator iter;
    while ((iter = m_mr_map_lkey.begin()) != m_mr_map_lkey.end()) {
        mem_dereg(iter->first);
    }
    if (m_p_ibv_pd) {
        IF_VERBS_FAILURE_EX(ibv_dealloc_pd(m_p_ibv_pd), EIO)
        {
            ibch_logdbg("pd deallocation failure (errno=%d %m)", errno);
        }
        ENDIF_VERBS_FAILURE;
        VALGRIND_MAKE_MEM_UNDEFINED(m_p_ibv_pd, sizeof(struct ibv_pd));
        m_p_ibv_pd = nullptr;
    }

    if (m_p_ctx_time_converter) {
        m_p_ctx_time_converter->clean_obj();
    }
    delete m_p_ibv_device_attr;

    if (m_p_adapter) {
        delete m_p_adapter;
        m_p_ibv_context = nullptr;
    }

    BULLSEYE_EXCLUDE_BLOCK_END

    stop_doca_flow_port();

    if (m_doca_dev) {
        doca_error_t err = doca_dev_close(m_doca_dev);
        if (DOCA_IS_ERROR(err)) {
            PRINT_DOCA_ERR(ibch_logerr, err, "doca_dev_close dev: %p,%s. PID: %d", m_doca_dev,
                           m_ibname.c_str(), static_cast<int>(getpid()));
        }
    }
}

void ib_ctx_handler::open_doca_dev(doca_devinfo *devinfo)
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

void ib_ctx_handler::check_doca_dev_caps(doca_devinfo *devinfo)
{
    uint8_t temprc = 0U;
    doca_error_t err = doca_pe_is_set_notification_affinity_supported(devinfo, &temprc);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(ibch_logerr, err,
                       "doca_pe_is_set_notification_affinity_supported devinfo: %p,%s", devinfo,
                       m_ibname.c_str());
    } else {
        m_notification_affinity_cap = (temprc != 0);
    }
}

doca_flow_port *ib_ctx_handler::get_doca_flow_port()
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

doca_flow_pipe *ib_ctx_handler::get_doca_root_pipe()
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

doca_error_t ib_ctx_handler::start_doca_flow_port()
{
    doca_error_t tmp_result;
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
    tmp_result = doca_flow_port_cfg_destroy(port_cfg);
    if (DOCA_IS_ERROR(tmp_result)) {
        PRINT_DOCA_ERR(ibch_logerr, err, "doca_flow_port_start dev/port: %p,%s,%p", m_doca_dev,
                       m_ibname.c_str(), m_doca_port);
        DOCA_ERROR_PROPAGATE(err, tmp_result);
    }

    return err;
}

void ib_ctx_handler::stop_doca_flow_port()
{
    if (m_doca_root_pipe) {
        doca_flow_pipe_destroy(m_doca_root_pipe);
        m_doca_root_pipe = nullptr;
    }

    if (m_doca_port) {
        doca_error_t err = doca_flow_port_stop(m_doca_port);
        m_doca_port = nullptr;
        if (DOCA_IS_ERROR(err)) {
            PRINT_DOCA_ERR(ibch_logerr, err, "doca_flow_port_stop port: %p,%s", m_doca_port,
                           m_ibname.c_str());
        }
        ibch_logdbg("DOCA port stopped %s", m_ibname.c_str());
    }
}

doca_error_t ib_ctx_handler::create_doca_root_pipe()
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

void ib_ctx_handler::print_val()
{
    char str_x[512] = {0};
    char temp_str[512];

    temp_str[0] = '\0';

    str_x[0] = '\0';
    sprintf(str_x, " %s:", get_ibname().c_str());
    strcat(temp_str, str_x);

    str_x[0] = '\0';
    sprintf(str_x, " port(s): %d", get_ibv_device_attr()->phys_port_cnt);
    strcat(temp_str, str_x);

    str_x[0] = '\0';
    sprintf(str_x, " vendor: %d", get_ibv_device_attr()->vendor_part_id);
    strcat(temp_str, str_x);

    str_x[0] = '\0';
    sprintf(str_x, " fw: %s", get_ibv_device_attr()->fw_ver);
    strcat(temp_str, str_x);

    str_x[0] = '\0';
    sprintf(str_x, " max_qp_wr: %d", get_ibv_device_attr()->max_qp_wr);
    strcat(temp_str, str_x);

    str_x[0] = '\0';
    sprintf(str_x, " on_device_memory: %zu", m_on_device_memory);
    strcat(temp_str, str_x);

    str_x[0] = '\0';
    sprintf(str_x, " packet_pacing_caps: min rate %u, max rate %u", m_pacing_caps.rate_limit_min,
            m_pacing_caps.rate_limit_max);
    strcat(temp_str, str_x);

    ibch_logdbg("%s", temp_str);
}

int parse_dpcp_version(const char *dpcp_ver)
{
    static const std::string s_delimiter(".");
    static const std::array<int, 3> s_multiplier = {1, 100, 10000};
    std::string str_ver(dpcp_ver);
    str_ver += '.'; // For generic loop parsing.

    int ver = 0;
    size_t loops = s_multiplier.size();
    for (size_t pos = str_ver.find(s_delimiter); (pos != std::string::npos) && (loops-- > 0U);
         str_ver.erase(0, pos + s_delimiter.length()), pos = str_ver.find(s_delimiter)) {
        ver += std::stoi(str_ver.substr(0, pos)) * s_multiplier[loops];
    }

    return (loops == 0U ? ver : 0);
}

dpcp::adapter *ib_ctx_handler::set_dpcp_adapter()
{
    dpcp::status status = dpcp::DPCP_ERR_NO_SUPPORT;
    dpcp::provider *p_provider = nullptr;
    dpcp::adapter_info *dpcp_lst = nullptr;
    size_t adapters_num = 0;
    size_t i = 0;
    int dpcp_ver = 0;

    m_p_adapter = nullptr;
    if (!m_p_ibv_device) {
        return nullptr;
    }

    status = dpcp::provider::get_instance(p_provider);
    if (dpcp::DPCP_OK != status) {
        ibch_logerr("failed getting provider status = %d", status);
        goto err;
    }

    dpcp_ver = parse_dpcp_version(p_provider->get_version());
    if (dpcp_ver < DEFINED_DPCP_MIN) {
        ibch_logerr("Incompatible dpcp vesrion %d. Min supported version %d", dpcp_ver,
                    DEFINED_DPCP_MIN);
        goto err;
    }

    /*
     * get_adapter_info_lst() returns number of adapters in response to NULL or
     * 0 arguments along with DPCP_ERR_OUT_OF_RANGE error. On success, the
     * number of actual adapters is not set, so we need a separate call here.
     */
    status = p_provider->get_adapter_info_lst(nullptr, adapters_num);
    if (dpcp::DPCP_ERR_OUT_OF_RANGE != status || 0 == adapters_num) {
        ibch_logdbg("found no adapters status = %d", status);
        goto err;
    }

    dpcp_lst = new (std::nothrow) dpcp::adapter_info[static_cast<unsigned>(adapters_num)];
    if (!dpcp_lst) {
        ibch_logerr("failed allocating memory for devices");
        goto err;
    }

    status = p_provider->get_adapter_info_lst(dpcp_lst, adapters_num);
    if (dpcp::DPCP_OK != status) {
        ibch_logerr("failed getting adapter list");
        goto err;
    }

    for (i = 0; i < adapters_num; i++) {
        if (dpcp_lst[i].name == m_p_ibv_device->name) {
            dpcp::adapter *adapter = nullptr;

            status = p_provider->open_adapter(dpcp_lst[i].name, adapter);
            if ((dpcp::DPCP_OK == status) && (adapter)) {
                int ret = 0;
                struct ibv_context *ctx = nullptr;
                struct ibv_pd *pd = nullptr;
                mlx5dv_obj mlx5_obj;

                ctx = (ibv_context *)adapter->get_ibv_context();
                if (!ctx) {
                    ibch_logerr("failed getting context for adapter %p (errno=%d %m) ", adapter,
                                errno);
                    delete adapter;
                    goto err;
                }

                pd = ibv_alloc_pd(ctx);
                if (!pd) {
                    ibch_logerr("failed pd allocation for %p context (errno=%d %m) ", ctx, errno);
                    delete adapter;
                    goto err;
                }

                mlx5_obj.pd.in = pd;
                mlx5dv_pd out_pd;
                mlx5_obj.pd.out = &out_pd;

                ret = xlio_ib_mlx5dv_init_obj(&mlx5_obj, MLX5DV_OBJ_PD);
                if (ret) {
                    ibch_logerr("failed getting mlx5_pd for %p (errno=%d %m) ", m_p_ibv_pd, errno);
                    ibv_dealloc_pd(pd);
                    delete adapter;
                    goto err;
                }

                adapter->set_pd(out_pd.pdn, pd);
                status = adapter->open();
                if (dpcp::DPCP_OK != status) {
                    ibch_logerr("failed opening dpcp adapter %s got %d",
                                adapter->get_name().c_str(), status);
                    ibv_dealloc_pd(pd);
                    delete adapter;
                    goto err;
                }

                m_p_adapter = adapter;
                m_p_ibv_context = ctx;
                m_p_ibv_pd = pd;
                check_capabilities();
                ibch_logdbg("dpcp adapter: %s is up", adapter->get_name().c_str());
            }

            break;
        }
    }

err:
    if (dpcp_lst) {
        delete[] dpcp_lst;
    }

    return m_p_adapter;
}

void ib_ctx_handler::check_capabilities()
{
    dpcp::adapter_hca_capabilities caps;
    dpcp::status rc = m_p_adapter->get_hca_capabilities(caps);
    if (rc == dpcp::DPCP_OK) {
        set_flow_tag_capability(caps.flow_table_caps.receive.is_flow_action_tag_supported);
        ibch_logdbg("Flow Tag Support: %s", get_flow_tag_capability() ? "Yes" : "No");
    }
}

void ib_ctx_handler::set_ctx_time_converter_status(ts_conversion_mode_t conversion_mode)
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

#ifdef DEFINED_IBV_CQ_TIMESTAMP
    switch (conversion_mode) {
    case TS_CONVERSION_MODE_DISABLE:
        m_p_ctx_time_converter =
            new time_converter_ib_ctx(m_p_ibv_context, TS_CONVERSION_MODE_DISABLE, 0);
        break;
    case TS_CONVERSION_MODE_PTP: {
#ifdef DEFINED_IBV_CLOCK_INFO
        if (is_mlx4()) {
            m_p_ctx_time_converter = new time_converter_ib_ctx(
                m_p_ibv_context, TS_CONVERSION_MODE_SYNC, m_p_ibv_device_attr->hca_core_clock);
            ibch_logwarn("ptp is not supported for mlx4 devices, reverting to mode "
                         "TS_CONVERSION_MODE_SYNC (ibv context %p)",
                         m_p_ibv_context);
        } else {
            xlio_ibv_clock_info clock_info;
            memset(&clock_info, 0, sizeof(clock_info));
            int ret = xlio_ibv_query_clock_info(m_p_ibv_context, &clock_info);
            if (ret == 0) {
                m_p_ctx_time_converter = new time_converter_ptp(m_p_ibv_context);
            } else {
                m_p_ctx_time_converter = new time_converter_ib_ctx(
                    m_p_ibv_context, TS_CONVERSION_MODE_SYNC, m_p_ibv_device_attr->hca_core_clock);
                ibch_logwarn("xlio_ibv_query_clock_info failure for clock_info, reverting to mode "
                             "TS_CONVERSION_MODE_SYNC (ibv context %p) (ret %d)",
                             m_p_ibv_context, ret);
            }
        }
#else
        m_p_ctx_time_converter = new time_converter_ib_ctx(m_p_ibv_context, TS_CONVERSION_MODE_SYNC,
                                                           m_p_ibv_device_attr->hca_core_clock);
        ibch_logwarn("PTP is not supported by the underlying Infiniband verbs. "
                     "DEFINED_IBV_CLOCK_INFO not defined. "
                     "reverting to mode TS_CONVERSION_MODE_SYNC");
#endif // DEFINED_IBV_CLOCK_INFO
    } break;
    case TS_CONVERSION_MODE_RTC:
        m_p_ctx_time_converter = new time_converter_rtc();
        break;
    default:
        m_p_ctx_time_converter = new time_converter_ib_ctx(m_p_ibv_context, conversion_mode,
                                                           m_p_ibv_device_attr->hca_core_clock);
        break;
    }
#else
    m_p_ctx_time_converter =
        new time_converter_ib_ctx(m_p_ibv_context, TS_CONVERSION_MODE_DISABLE, 0);
    if (conversion_mode != TS_CONVERSION_MODE_DISABLE) {
        ibch_logwarn("time converter mode not applicable (configuration "
                     "value=%d). set to TS_CONVERSION_MODE_DISABLE.",
                     conversion_mode);
    }
#endif // DEFINED_IBV_CQ_TIMESTAMP
}

uint32_t ib_ctx_handler::mem_reg(void *addr, size_t length, uint64_t access)
{
    struct ibv_mr *mr = nullptr;
    uint32_t lkey = LKEY_ERROR;

    mr = ibv_reg_mr(m_p_ibv_pd, addr, length, access);
    VALGRIND_MAKE_MEM_DEFINED(mr, sizeof(ibv_mr));
    if (!mr) {
        print_warning_rlimit_memlock(length, errno);
    } else {
        m_mr_map_lkey[mr->lkey] = mr;
        lkey = mr->lkey;

        ibch_logdbg("dev:%s (%p) addr=%p length=%lu pd=%p", get_ibname().c_str(), m_p_ibv_device,
                    addr, length, m_p_ibv_pd);
    }

    return lkey;
}

void ib_ctx_handler::mem_dereg(uint32_t lkey)
{
    auto iter = m_mr_map_lkey.find(lkey);
    if (iter != m_mr_map_lkey.end()) {
        struct ibv_mr *mr = iter->second;
        ibch_logdbg("dev:%s (%p) addr=%p length=%lu pd=%p", get_ibname().c_str(), m_p_ibv_device,
                    mr->addr, mr->length, m_p_ibv_pd);
        IF_VERBS_FAILURE_EX(ibv_dereg_mr(mr), EIO)
        {
            ibch_logdbg("failed de-registering a memory region "
                        "(errno=%d %m)",
                        errno);
        }
        ENDIF_VERBS_FAILURE;
        VALGRIND_MAKE_MEM_UNDEFINED(mr, sizeof(ibv_mr));
        m_mr_map_lkey.erase(iter);
    }
}

struct ibv_mr *ib_ctx_handler::get_mem_reg(uint32_t lkey)
{
    auto iter = m_mr_map_lkey.find(lkey);
    if (iter != m_mr_map_lkey.end()) {
        return iter->second;
    }

    return nullptr;
}

uint32_t ib_ctx_handler::user_mem_reg(void *addr, size_t length, uint64_t access)
{
    std::lock_guard<decltype(m_lock_umr)> lock(m_lock_umr);
    uint32_t lkey;

    auto iter = m_user_mem_lkey_map.find(addr);
    if (iter != m_user_mem_lkey_map.end()) {
        lkey = iter->second;
    } else {
        lkey = mem_reg(addr, length, access);
        if (lkey == LKEY_ERROR) {
            ibch_logerr("Can't register user memory addr %p len %lx", addr, length);
        } else {
            m_user_mem_lkey_map[addr] = lkey;
        }
    }

    return lkey;
}

void ib_ctx_handler::set_flow_tag_capability(bool flow_tag_capability)
{
    m_flow_tag_enabled = flow_tag_capability;
}

void ib_ctx_handler::set_burst_capability(bool burst)
{
    m_pacing_caps.burst = burst;
}

bool ib_ctx_handler::is_packet_pacing_supported(uint32_t rate /* =1 */)
{
    if (rate) {
        return m_pacing_caps.rate_limit_min <= rate && rate <= m_pacing_caps.rate_limit_max;
    } else {
        return true;
    }
}

bool ib_ctx_handler::is_active(int port_num)
{
    ibv_port_attr port_attr;

    memset(&port_attr, 0, sizeof(ibv_port_attr));
    IF_VERBS_FAILURE(ibv_query_port(m_p_ibv_context, port_num, &port_attr))
    {
        ibch_logdbg("ibv_query_port failed on ibv device %p, port %d "
                    "(errno=%d)",
                    m_p_ibv_context, port_num, errno);
    }
    ENDIF_VERBS_FAILURE;
    VALGRIND_MAKE_MEM_DEFINED(&port_attr.state, sizeof(port_attr.state));
    return port_attr.state == IBV_PORT_ACTIVE;
}

void ib_ctx_handler::handle_event_ibverbs_cb(void *ev_data, void *ctx)
{
    NOT_IN_USE(ctx);

    struct ibv_async_event *ibv_event = (struct ibv_async_event *)ev_data;
    ibch_logdbg("received ibv_event '%s' (%d)", priv_ibv_event_desc_str(ibv_event->event_type),
                ibv_event->event_type);

    if (ibv_event->event_type == IBV_EVENT_DEVICE_FATAL) {
        handle_event_device_fatal();
    }
}

void ib_ctx_handler::handle_event_device_fatal()
{
    m_removed = true;

    ibch_logdbg("IBV_EVENT_DEVICE_FATAL for ib_ctx_handler=%p", this);

    /* After getting IBV_EVENT_DEVICE_FATAL event rdma library returns
     * an EIO from destroy commands when the kernel resources were already released.
     * This comes to prevent memory leakage in the
     * user space area upon device disassociation. Applications cannot
     * call ibv_get_cq_event or ibv_get_async_event concurrently with any call to an
     * object destruction function.
     */
    g_p_event_handler_manager->unregister_ibverbs_event(m_p_ibv_context->async_fd, this);
    if (m_p_ctx_time_converter) {
        m_p_ctx_time_converter->clean_obj();
        m_p_ctx_time_converter = nullptr;
    }
}
