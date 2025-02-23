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

#ifndef XLIO_THREAD_MANAGER_H
#define XLIO_THREAD_MANAGER_H

#include <memory>
#include <cstdint>
#include "xlio_thread.h"

class sockinfo_tcp;

class xlio_thread_manager
{
public:
    xlio_thread_manager(size_t threads);
    ~xlio_thread_manager();

    int add_listen_socket(sockinfo_tcp *sock);
    int add_accepted_socket(sockinfo_tcp *sock);

private:

    // The std::vector is not usable here since it requires the object
    // to be CopyAssignable 
    std::unique_ptr<xlio_thread[]> m_xlio_threads;
    size_t m_threads_num = 0U;
    size_t m_next_add_group = 0U;
};

extern xlio_thread_manager *g_p_xlio_thread_manager;

#endif // XLIO_THREAD_MANAGER_H
