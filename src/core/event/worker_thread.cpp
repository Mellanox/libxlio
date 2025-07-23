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

#include "worker_thread.h"
#include "vlogger/vlogger.h"

#define MODULE_NAME "worker_thread"

#define wt_logpanic __log_panic
#define wt_logerr   __log_err
#define wt_logwarn  __log_warn
#define wt_loginfo  __log_info_info
#define wt_logdbg   __log_info_dbg

void worker_thread::worker_thread_main(worker_thread &t, entity_context *ctx)
{
    t.m_entity_ctx = ctx;

    t.worker_thread_loop();
}

void worker_thread::start_thread(entity_context *ctx)
{
    m_thread = std::thread(worker_thread_main, std::ref(*this), ctx);
    while (!m_running.load()) {
        // We must wait for the thread to start to avoid races of API usage while
        // the thread can still not be ready.
    }

    wt_logdbg("Worker Thread started (tid: %d, entctx: %p)", gettid(), ctx);
}

void worker_thread::stop_thread()
{
    m_running.store(false);
    m_thread.join();
    wt_logdbg("Worker Thread terminated (tid: %d, entctx: %p)", gettid(), m_entity_ctx);
}

void worker_thread::worker_thread_loop()
{
    m_running.store(true);
    while (m_running.load(std::memory_order_relaxed)) {
        m_entity_ctx->process();
    }
}
