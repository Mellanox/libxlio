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
#include "tx_round_robin_scheduler.h"

tx_round_robin_scheduler::tx_round_robin_scheduler(ring_tx_scheduler_interface &r,
                                                   size_t max_requests)
    : tx_scheduler(r, max_requests)
{
}

void tx_round_robin_scheduler::schedule_tx()
{
    size_t num_messages = fair_num_requests();
    size_t num_sockets = m_queue.size();

    while (num_sockets && m_max_requests - m_num_requests >= num_messages) {
        sockinfo_tx_scheduler_interface *sock = m_queue.front();
        m_queue.pop_front();
        num_sockets--;

        send_status status = single_socket_send(sock, num_messages);
        if (status == send_status::OK) {
            m_queue.push_back(sock);
        }
    }
}

#include <algorithm>
#include <cassert>
void tx_round_robin_scheduler::schedule_tx(sockinfo_tx_scheduler_interface *sock, bool is_first)
{
    if (is_first) {
        assert(std::find(m_queue.cbegin(), m_queue.cend(), sock) == m_queue.cend());
        m_queue.push_back(sock);
    }

    assert(std::find(m_queue.cbegin(), m_queue.cend(), sock) != m_queue.cend());

    schedule_tx();
}

void tx_round_robin_scheduler::notify_completion(uintptr_t metadata, size_t num_completions)
{
    auto socket = reinterpret_cast<sockinfo_tx_scheduler_interface *>(metadata);
    if (socket) {
        socket->notify_completions(num_completions);
    }
    m_num_requests -= num_completions;
}

send_status tx_round_robin_scheduler::single_socket_send(sockinfo_tx_scheduler_interface *sock,
                                                         size_t requests)
{
    sq_proxy proxy {*this, requests, reinterpret_cast<uintptr_t>(sock)};

    return sock->do_send(proxy);
}

/*
 * In the round robin implementation, we allocated the same number of requests per sender.
 * If the available requests exceed the number of senders, each sender may receive more than one
 * opportunity to send.
 * If the number of senders exceed the available requests, each sender should receive at least
 * one opportunity to send.
 */
size_t tx_round_robin_scheduler::fair_num_requests()
{
    /* If the queue is empty, make the denominator 1 to eliminate the divide-by-zero error */
    return std::max(1UL, (m_max_requests - m_num_requests) / (std::max(1UL, m_queue.size())));
}
