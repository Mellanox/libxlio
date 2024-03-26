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

#include <mutex>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "tx_scheduler.h"

using ::testing::_; // Matcher for any argument
using ::testing::Return;

/* Mock classes created for testing tx_scheduler */
class sockinfo_mock : public sockinfo {
public:
    MOCK_METHOD(void, notify_completion, (size_t), (override));
    MOCK_METHOD(tx_scheduler::status, do_send, (sq_proxy), (override));
};

class ring_mock : public ring {
public:
    ring_mock() = default;
    ~ring_mock() override = default;

    MOCK_METHOD(void, notify_complete, (uintptr_t), (override));

    // Mock the send methods
    MOCK_METHOD(bool, send, (tcp_segment &, uintptr_t), (override));
    MOCK_METHOD(bool, send, (udp_datagram &, uintptr_t), (override));
    MOCK_METHOD(bool, send, (control_msg &, uintptr_t), (override));
};

TEST(tx_fifo_scheduler, send_max_num_requests)
{
    ring_mock ring {};
    sockinfo_mock socket {};
    size_t max_iflight_requests = 10;
    tx_fifo_scheduler fifo(ring, max_iflight_requests);

    EXPECT_CALL(socket, do_send(_))
        .Times(1)
        .WillOnce(Return(tx_scheduler::status::OK)); // Always return status_OK

    fifo.notify_ready_to_send(&socket, true);
}

TEST(tx_fifo_scheduler, fifo_does_no_do_send_in_schedule_tx)
{
    ring_mock ring {};
    sockinfo_mock socket {};
    size_t max_iflight_requests = 10;
    tx_fifo_scheduler fifo(ring, max_iflight_requests);

    EXPECT_CALL(socket, do_send(_)).Times(0);

    fifo.schedule_tx();
}

TEST(tx_fifo_scheduler, fifo_notifies_sockets_in_schedule_tx)
{
    ring_mock ring {};
    sockinfo_mock socket {};
    size_t max_iflight_requests = 10;
    tx_fifo_scheduler fifo(ring, max_iflight_requests);

    fifo.notify_completion(reinterpret_cast<uintptr_t>(&socket), 42);
    EXPECT_CALL(socket, notify_completion(42)).Times(1);

    fifo.schedule_tx();
}

TEST(tx_fifo_scheduler, fifo_notifies_no_sockets_when_completions_empty_in_schedule_tx)
{
    ring_mock ring {};
    sockinfo_mock socket {};
    size_t max_iflight_requests = 10;
    tx_fifo_scheduler fifo(ring, max_iflight_requests);

    EXPECT_CALL(socket, notify_completion(_)).Times(0);
    fifo.schedule_tx();
}

TEST(tx_fifo_scheduler, fifo_notifies_once_per_sockets_in_schedule_tx)
{
    ring_mock ring {};
    sockinfo_mock socket {};
    size_t max_iflight_requests = 10;
    tx_fifo_scheduler fifo(ring, max_iflight_requests);

    fifo.notify_completion(reinterpret_cast<uintptr_t>(&socket), 22);
    fifo.notify_completion(reinterpret_cast<uintptr_t>(&socket), 20);
    EXPECT_CALL(socket, notify_completion(42)).Times(1);

    fifo.schedule_tx();
}
