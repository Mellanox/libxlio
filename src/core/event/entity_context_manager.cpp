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

#include "entity_context_manager.h"
#include "util/sys_vars.h"
#include "sock/sockinfo_tcp.h"

// Static
entity_context_manager *entity_context_manager::s_p_entity_context_manager = nullptr;

// Static
entity_context_manager *entity_context_manager::instance()
{
    return s_p_entity_context_manager;
}

// Static
void entity_context_manager::create()
{
    if (!s_p_entity_context_manager) {
        s_p_entity_context_manager = new entity_context_manager();
    }
}

// Static
void entity_context_manager::destroy()
{
    if (s_p_entity_context_manager) {
        delete s_p_entity_context_manager;
        s_p_entity_context_manager = nullptr;
    }
}

// Static
void entity_context_manager::fork_nullify()
{
    // Just nullify the pointer so it can be recreated on next create.
    // Since fork works with copy-on-write, the old pointer is just abondend and thus never copied.
    s_p_entity_context_manager = nullptr;
}

entity_context_manager::entity_context_manager()
{
    m_entity_contexts.reserve(safe_mce_sys().worker_threads);

    for (size_t i = 0; i < safe_mce_sys().worker_threads; i++) {
        m_entity_contexts.push_back(new entity_context(i));
    }
}

entity_context_manager::~entity_context_manager()
{
    std::for_each(m_entity_contexts.begin(), m_entity_contexts.end(),
                  [](entity_context *ctx) { delete ctx; });
}

void entity_context_manager::distribute_socket(sockinfo *si, entity_context::job_type jobtype)
{
    uint16_t next_idx = m_next_distribute.fetch_add(1U) % safe_mce_sys().worker_threads;
    m_entity_contexts[next_idx]->add_job(entity_context::job_desc {jobtype, si, nullptr, 0U});
}

void entity_context_manager::distribute_listen_socket(sockinfo_tcp *si)
{
    for (size_t i = 0; i < safe_mce_sys().worker_threads &&
         i < si->get_listen_context()->get_listen_rss_children_size();
         ++i) {
        sockinfo_tcp *listen_rss_child = si->get_listen_context()->get_listen_rss_child(i);
        listen_rss_child->get_listen_context()->set_steering_index(i);
        m_entity_contexts[i]->add_job(entity_context::job_desc {
            entity_context::JOB_TYPE_SOCK_ADD_AND_LISTEN, listen_rss_child, nullptr, 0U});
    }
}

int entity_context_manager::calculate_entity_context_pow2()
{
    int worker_threads = safe_mce_sys().worker_threads;

    if (worker_threads == 0 || worker_threads == 1) {
        return worker_threads;
    }

    // Find next power of 2 that is >= worker_threads
    // Assume the number doesn't exceed 32bit.
    int pow2 = 1;
    while (pow2 < worker_threads) {
        pow2 <<= 1;
    }

    return pow2;
}
