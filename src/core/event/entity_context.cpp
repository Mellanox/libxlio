/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-3-Clause
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

#include "entity_context.h"
#include "vlogger/vlogger.h"

#define MODULE_NAME "worker_thread"

#define ctx_logpanic __log_panic
#define ctx_logerr   __log_err
#define ctx_logwarn  __log_warn
#define ctx_loginfo  __log_info_info
#define ctx_logdbg   __log_info_dbg

entity_context::entity_context()
    : poll_group(xlio_poll_group_attr {XLIO_GROUP_FLAG_SAFE | XLIO_GROUP_FLAG_DIRTY, nullptr,
                                       nullptr, nullptr, nullptr})
{
    ctx_logdbg("Entity Context created");
}

entity_context::~entity_context()
{
    ctx_logdbg("Entity Context destroyed");
}

void entity_context::process()
{
    poll();

    auto jobs = m_job_queue.get_all();
    for (auto &job : jobs) {
        switch (job.job_id) {
        case JOB_TYPE_SOCK_ADD_AND_CONNECT:
            if (job.sock->get_protocol() == PROTO_TCP) {
                add_socket(reinterpret_cast<sockinfo_tcp *>(job.sock));
                ctx_loginfo("New socket added (sock: %p)", job.sock);
            }
            break;
        case JOB_TYPE_SOCK_TX:
            // Handle socket transmit job
            // TODO: implement transmit logic
            break;
        case JOB_TYPE_SOCK_RX_BUF_RETURN:
            // Handle socket receive buffer return job
            // TODO: implement buffer return logic
            break;
        case JOB_TYPE_SOCK_RX_ACK:
            // Handle socket receive ack job
            // TODO: implement ack logic
            break;
        default:
            // Unknown job type
            break;
        }
    }

    flush();
}

void entity_context::add_job(const job_desc &job)
{
    m_job_queue.insert_job(job);
}