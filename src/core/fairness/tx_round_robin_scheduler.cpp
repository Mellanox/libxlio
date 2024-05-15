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
    , m_used_requests(0U)
    , m_last_scheduled()
{
}

#include <stdio.h>
using namespace std::chrono_literals;
void tx_round_robin_scheduler::schedule_tx()
{
    while (!m_queue.empty() && !m_ring_full) {
        sockinfo_tx_scheduler_interface *sock = m_queue.front();
        m_queue.pop_front();
        if (!sock) {
            continue;
        }

        if (single_socket_send(sock, 1) == send_status::OK) {
            m_queue.push_back(sock);
        } else {
            m_unique_sockets.erase(sock);
            //printf("%s:%d [%s] size queue %zu [%u] <= [%zu]\n", __FILE__, __LINE__, __func__, m_queue.size(), m_socket_counters[sock], num_messages);
        }
    }
}

#include <algorithm>
#include <cassert>
void tx_round_robin_scheduler::schedule_tx(sockinfo_tx_scheduler_interface *sock, bool)
{
    if (m_unique_sockets.count(sock) == 0) {
        m_unique_sockets.insert(sock);
        m_queue.push_back(sock);
 //       size_t num_messages = m_used_requests / (m_socket_counters.size() + 1U);
 //       if (m_socket_counters[sock] >= num_messages ||
 //           single_socket_send(sock, 15U) == send_status::OK) {
 //           m_unique_sockets.insert(sock);
 //           m_queue.push_back(sock);
 //       }
    }

    // assert(std::find(m_queue.cbegin(), m_queue.cend(), sock) != m_queue.cend());

    schedule_tx();
}

send_status tx_round_robin_scheduler::single_socket_send(sockinfo_tx_scheduler_interface *sock,
                                                         size_t requests)
{
    sq_proxy proxy {*this, requests, reinterpret_cast<uintptr_t>(sock)};
    auto status = sock->do_send(proxy);

    // printf("%s:%d [%s] tx_round_robin_scheduler sock %p size queue %zu status [%s]\n", __FILE__,
    // __LINE__, __func__, sock, m_queue.size(),  send_status::OK == status ? "OK" :
    // "NO_MORE_MESSAGES");

    return status;
    // return sock->do_send(proxy);
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
    return (1UL + m_max_requests / (1UL + m_socket_counters.size())) ? : 1U;
}

void tx_round_robin_scheduler::track_used_requests(size_t used_requests, uintptr_t metadata)
{
    auto sock = reinterpret_cast<sockinfo_tx_scheduler_interface *>(metadata);
    if (m_used_requests > m_max_requests * 10) {
        m_used_requests = 0;
        m_socket_counters.clear();
    }
    //  printf("%s:%d [%s] sock %p size queue %zu sock ctr [%u] used_requests [%lu]\n", __FILE__,
    //         __LINE__, __func__, sock, m_queue.size(), m_socket_counters[sock], m_used_requests);
    m_used_requests += used_requests;
    m_socket_counters[sock] += used_requests;
}
