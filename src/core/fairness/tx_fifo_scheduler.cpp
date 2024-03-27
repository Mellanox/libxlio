/*
 * Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include "tx_fifo_scheduler.h"

tx_fifo_scheduler::tx_fifo_scheduler(ring_tx_scheduler_interface &r, size_t max_requests)
    : tx_scheduler(r, max_requests)
{
}

tx_fifo_scheduler::~tx_fifo_scheduler()
{
    noify_all_completions();
}

void tx_fifo_scheduler::schedule_tx()
{
    /* Schedule on sufficiently empty send queue - scheduling moderation */
    if (m_num_requests == 0 || double(m_max_requests) / m_num_requests >= 2.0f) {
        noify_all_completions();
    }
}
void tx_fifo_scheduler::schedule_tx(sockinfo_tx_scheduler_interface *sock, bool)
{
    sq_proxy proxy {*this, m_max_requests - m_num_requests, reinterpret_cast<uintptr_t>(sock),
                    m_completions[sock]};
    sock->do_send(proxy);
    m_completions.erase(sock);
}

void tx_fifo_scheduler::notify_completion(uintptr_t metadata, size_t num_completions)
{
    sockinfo_tx_scheduler_interface *socket =
        reinterpret_cast<sockinfo_tx_scheduler_interface *>(metadata);
    m_completions[socket] += num_completions;
    m_num_requests -= num_completions;
}

void tx_fifo_scheduler::noify_all_completions()
{
    for (auto sock_with_completions : m_completions) {
        sockinfo_tx_scheduler_interface *sock = sock_with_completions.first;
        sq_proxy proxy {*this, 0, reinterpret_cast<uintptr_t>(sock), sock_with_completions.second};
        /* Just notify */
        sock->do_send(proxy);
    }
    m_completions.clear();
}
