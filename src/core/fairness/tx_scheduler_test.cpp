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

using namespace ::testing;

struct tcp_segment {
};

class greedy_test_socket : public sockinfo {
public:
    tx_scheduler::status do_send(sq_proxy &sq) {
        tcp_segment tcp{};
        while (sq.send(tcp)) {}
        return tx_scheduler::status::OK;
    }
};

class limited_test_socket : public sockinfo {
public:
    limited_test_socket(size_t inflight_requests) : m_inflight_requests(inflight_requests) {}
    tx_scheduler::status do_send(sq_proxy &sq) {
        tcp_segment tcp{};
        m_inflight_requests += sq.m_completions;
        while (m_inflight_requests && sq.send(tcp)) {
            --m_inflight_requests;
        }
        return tx_scheduler::status::OK;
    }
    size_t m_inflight_requests;
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

TEST(tx_fifo_scheduler, fifo_with_greedy_socket_sends_max_times)
{
    ring_mock ring {};
    greedy_test_socket socket {};
    size_t max_iflight_requests = 10;
    tx_fifo_scheduler fifo(ring, max_iflight_requests);

    EXPECT_CALL(ring, send(An<tcp_segment&>(), _))
        .Times(max_iflight_requests);
    fifo.schedule_tx(&socket, true);
}

TEST(tx_fifo_scheduler, fifo_with_limited_socket_sends_up_to_limit)
{
    ring_mock ring {};
    size_t socket_inflight_limit = 7;
    limited_test_socket socket {socket_inflight_limit};
    size_t max_iflight_requests = 10;
    tx_fifo_scheduler fifo(ring, max_iflight_requests);

    EXPECT_CALL(ring, send(An<tcp_segment&>(), _))
        .Times(socket_inflight_limit);
    fifo.schedule_tx(&socket, true);
}

TEST(tx_fifo_scheduler, fifo_schedule_tx_no_args_notifies_socket_completions_without_sending)
{
    ring_mock ring {};
    greedy_test_socket socket {};
    size_t max_iflight_requests = 10;
    tx_fifo_scheduler fifo(ring, max_iflight_requests);

    EXPECT_CALL(ring, send(An<tcp_segment&>(), _))
        .Times(max_iflight_requests);
    fifo.schedule_tx(&socket, true);

    fifo.notify_completion(reinterpret_cast<uintptr_t>(&socket), 5);
    EXPECT_CALL(ring, send(An<tcp_segment&>(), _))
        .Times(0);
    fifo.schedule_tx();
}
/*
TEST(tx_fifo_scheduler, fifo_notifies_no_sockets_when_completions_empty_in_schedule_tx)
{
    ring_mock ring {};
    test_socket socket {};
    size_t max_iflight_requests = 10;
    tx_fifo_scheduler fifo(ring, max_iflight_requests);

    EXPECT_CALL(socket, do_send(_)).Times(0);
    fifo.schedule_tx();
}

TEST(tx_fifo_scheduler, fifo_notifies_once_per_sockets_in_schedule_tx)
{
    ring_mock ring {};
    test_socket socket {};
    size_t max_iflight_requests = 10;
    tx_fifo_scheduler fifo(ring, max_iflight_requests);

    fifo.notify_completion(reinterpret_cast<uintptr_t>(&socket), 22);
    fifo.notify_completion(reinterpret_cast<uintptr_t>(&socket), 20);
    EXPECT_CALL(socket, do_send(Field(&sq_proxy::m_completions, Eq(42)))).Times(1);

    fifo.schedule_tx();
}

TEST(tx_round_robin_scheduler, schedule_tx_invokes_do_send_at_least_once)
{
    ring_mock ring {};
    test_socket socket {};
    size_t max_iflight_requests = 10;
    tx_round_robin_scheduler round_robin(ring, max_iflight_requests);

    EXPECT_CALL(socket, do_send(_))
        .Times(testing::AtLeast(1))
        .WillOnce(Return(tx_scheduler::status::OK)); // Always return status_OK

    round_robin.schedule_tx(&socket, true);
}

TEST(tx_round_robin_scheduler, round_robin_does_no_do_send_in_schedule_tx)
{
    ring_mock ring {};
    test_socket socket {};
    size_t max_iflight_requests = 10;
    tx_round_robin_scheduler round_robin(ring, max_iflight_requests);

    EXPECT_CALL(socket, do_send(_)).Times(0);

    round_robin.schedule_tx();
}

TEST(tx_round_robin_scheduler, round_robin_notifies_sockets_in_schedule_tx)
{
    ring_mock ring {};
    test_socket socket {};
    size_t max_iflight_requests = 10;
    tx_round_robin_scheduler round_robin(ring, max_iflight_requests);

    round_robin.notify_completion(reinterpret_cast<uintptr_t>(&socket), 42);
    EXPECT_CALL(socket, do_send(Field(&sq_proxy::m_completions, Eq(42)))).Times(1);

    round_robin.schedule_tx();
}

TEST(tx_round_robin_scheduler, round_robin_does_not_call_do_send_when_no_completions_and_no_sockets)
{
    ring_mock ring {};
    test_socket socket {};
    size_t max_iflight_requests = 10;
    tx_round_robin_scheduler round_robin(ring, max_iflight_requests);

    EXPECT_CALL(socket, do_send(_)).Times(0);
    round_robin.schedule_tx();
}

TEST(tx_round_robin_scheduler, round_robin_calls_do_send_once_with_the_right_completions_number)
{
    ring_mock ring {};
    test_socket socket {};
    size_t max_iflight_requests = 10;
    tx_round_robin_scheduler round_robin(ring, max_iflight_requests);

    round_robin.notify_completion(reinterpret_cast<uintptr_t>(&socket), 22);
    round_robin.notify_completion(reinterpret_cast<uintptr_t>(&socket), 20);
    EXPECT_CALL(socket, do_send(Field(&sq_proxy::m_completions, Eq(42)))).Times(1);

    round_robin.schedule_tx();
}
*/
