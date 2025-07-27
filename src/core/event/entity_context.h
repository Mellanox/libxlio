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

#ifndef ENTITY_CONTEXT_H
#define ENTITY_CONTEXT_H

#include "event/poll_group.h"
#include "event/job_queue.h"

class sockinfo;
class mem_buf_desc_t;

class entity_context : public poll_group {
public:
    enum job_type {
        JOB_TYPE_SOCK_ADD_AND_CONNECT,
        JOB_TYPE_SOCK_TX,
        JOB_TYPE_SOCK_RX_BUF_RETURN,
        JOB_TYPE_SOCK_RX_ACK
    };

    struct job_desc {
        job_type job_id;
        sockinfo *sock;
        mem_buf_desc_t *buf;
    };

    entity_context();
    ~entity_context();

    void process();
    void add_job(const job_desc &job);

private:
    void connect_socket_job(sockinfo *sock);

    job_queue<job_desc> m_job_queue;
};

#endif