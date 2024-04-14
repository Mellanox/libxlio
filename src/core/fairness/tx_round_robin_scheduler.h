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
#ifndef _TX_ROUND_ROBIN_SCHEDULER_H_
#define _TX_ROUND_ROBIN_SCHEDULER_H_

#include <cstddef>
#include <cstdint>
#include <deque>
#include <unordered_map>

#include "tx_scheduler.h"
#include "ring_tx_scheduler_interface.h"
#include "sockinfo_tx_scheduler_interface.h"

class tx_round_robin_scheduler final : public tx_scheduler {
public:
    tx_round_robin_scheduler(ring_tx_scheduler_interface &r, size_t max_requests);
    ~tx_round_robin_scheduler() override = default;

    /* is_first should be true in two cases:
     *     1. The first time the socket is ready to send.
     *     2. The first time, since the socket returned NO_MORE_MESSAGES from do_send.
     */
    void schedule_tx(sockinfo_tx_scheduler_interface *sock, bool is_first) override;

    void schedule_tx() override;

private:
    send_status single_socket_send(sockinfo_tx_scheduler_interface *sock, size_t requests);

    /*
     * In the round robin implementation, we allocated the same number of requests per sender.
     * If the available requests exceed the number of senders, each sender may receive more than one
     * opportunity to send.
     * If the number of senders exceed the available requests, each sender should receive at least
     * one opportunity to send.
     */
    size_t fair_num_requests();

private:
    std::deque<sockinfo_tx_scheduler_interface *> m_queue;
};

#endif // _TX_ROUND_ROBIN_SCHEDULER_H_
