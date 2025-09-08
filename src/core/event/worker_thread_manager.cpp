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

#include "worker_thread_manager.h"
#include "worker_thread.h"
#include "entity_context_manager.h"
#include "util/sys_vars.h"

// Static
worker_thread_manager *worker_thread_manager::s_p_worker_thread_manager = nullptr;

// Static
worker_thread_manager *worker_thread_manager::instance()
{
    return s_p_worker_thread_manager;
}

// Static
void worker_thread_manager::create()
{
    if (!s_p_worker_thread_manager) {
        s_p_worker_thread_manager = new worker_thread_manager();
    }
}

// Static
void worker_thread_manager::destroy()
{
    if (s_p_worker_thread_manager) {
        delete s_p_worker_thread_manager;
        s_p_worker_thread_manager = nullptr;
    }
}

// Static
void worker_thread_manager::fork_nullify()
{
    // Just nullify the pointer so it can be recreated on next create.
    // Since fork works with copy-on-write, the old pointer is just abondend and thus never copied.
    s_p_worker_thread_manager = nullptr;
}

worker_thread_manager::worker_thread_manager()
{
    size_t threads_num = safe_mce_sys().worker_threads;
    if (threads_num == 0U) {
        return;
    }

    m_worker_threads = std::make_unique<worker_thread[]>(threads_num);

    // Assumed that number of all_ctxs is at least as number of worker threads.
    auto &all_ctxs = entity_context_manager::instance()->get_all_contexts();

    size_t next_ctx = 0;
    std::for_each(
        m_worker_threads.get(), m_worker_threads.get() + threads_num,
        [&next_ctx, &all_ctxs](worker_thread &t) { t.start_thread(all_ctxs[next_ctx++]); });
}

// coverity[UNCAUGHT_EXCEPT]
worker_thread_manager::~worker_thread_manager()
{
    size_t threads_num = safe_mce_sys().worker_threads;
    std::for_each(m_worker_threads.get(), m_worker_threads.get() + threads_num,
                  [](worker_thread &t) { t.stop_thread(); });
}
