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

#ifndef IB_CTX_HANDLER_DOCA_H
#define IB_CTX_HANDLER_DOCA_H

#include <doca_dev.h>
#include <doca_flow.h>
#include <doca_pe.h>
#include "dev/time_converter.h"

class ib_ctx_handler_doca {
public:
    ib_ctx_handler_doca(doca_devinfo *devinfo, std::string &ibname, const char *ifname);
    ~ib_ctx_handler_doca();
    doca_dev *get_doca_device() const { return m_doca_dev; }
    doca_flow_port *get_doca_flow_port();
    doca_flow_pipe *get_doca_root_pipe();
    void stop_doca_flow_port();
    void set_ctx_time_converter_status(ts_conversion_mode_t conversion_mode);
    void convert_hw_time_to_system_time(uint64_t hwtime, struct timespec *systime);
    const std::string &get_ifname() const { return m_ifname; }

private:
    void open_doca_dev(doca_devinfo *devinfo);
    doca_error_t start_doca_flow_port();
    doca_error_t create_doca_root_pipe();

    doca_dev *m_doca_dev = nullptr;
    doca_flow_port *m_doca_port = nullptr;
    doca_flow_pipe *m_doca_root_pipe = nullptr;
    time_converter *m_p_ctx_time_converter = nullptr;
    std::string m_ifname;
    std::string &m_ibname;
};

#endif // IB_CTX_HANDLER_DOCA_H