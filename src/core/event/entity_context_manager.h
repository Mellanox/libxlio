/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef ENTITY_CONTEXT_MANAGER_H
#define ENTITY_CONTEXT_MANAGER_H

#include <vector>
#include <atomic>
#include "entity_context.h"

class sockinfo;
class sockinfo_tcp;

class entity_context_manager {
public:
    entity_context_manager();
    ~entity_context_manager();

    static entity_context_manager *instance();
    static void create();
    static void destroy();
    static void fork_nullify();

    void distribute_socket(sockinfo *si, entity_context::job_type jobtype);
    void distribute_listen_socket(sockinfo_tcp *si);

    const std::vector<entity_context *> &get_all_contexts() const { return m_entity_contexts; }

    static int calculate_entity_context_pow2();

private:
    static entity_context_manager *s_p_entity_context_manager;

    std::vector<entity_context *> m_entity_contexts;
    std::atomic_uint16_t m_next_distribute {0};
};

#endif
