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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "tx_scheduler.h"
#include "tx_fifo_scheduler.h"
#include "tx_round_robin_scheduler.h"

using namespace ::testing;

struct tcp_segment {};

class greedy_test_socket : public sockinfo_tx_scheduler_interface {
public:
    send_status do_send(sq_proxy &sq)
    {
        tcp_segment tcp {};
        while (sq.send(tcp)) {
        }
        return send_status::OK;
    }

    void notify_completions(size_t) {}
};

class limited_test_socket : public sockinfo_tx_scheduler_interface {
public:
    limited_test_socket(size_t inflight_requests)
        : m_inflight_requests(inflight_requests)
    {
    }
    send_status do_send(sq_proxy &sq)
    {
        tcp_segment tcp {};
        while (m_inflight_requests && sq.send(tcp)) {
            --m_inflight_requests;
        }
        return send_status::OK;
    }

    void notify_completions(size_t completions) { m_inflight_requests += completions; }

    size_t m_inflight_requests;
};

class ring_mock : public ring_tx_scheduler_interface {
public:
    ring_mock() = default;
    ~ring_mock() override = default;

    MOCK_METHOD(void, notify_complete, (uintptr_t), (override));

    // Mock the send methods
    MOCK_METHOD(size_t, send, (tcp_segment &, uintptr_t), (override));
    MOCK_METHOD(size_t, send, (udp_datagram &, uintptr_t), (override));
    MOCK_METHOD(size_t, send, (control_msg &, uintptr_t), (override));
};

TEST(tx_fifo_scheduler, greedy_socket_sends_max_times_when_consuming_one_credit)
{
    ring_mock ring {};
    greedy_test_socket socket {};
    size_t max_iflight_requests = 10;
    tx_fifo_scheduler fifo(ring, max_iflight_requests);

    EXPECT_CALL(ring, send(An<tcp_segment &>(), _))
        .Times(max_iflight_requests)
        .WillRepeatedly(Return(1U));
    fifo.schedule_tx(&socket, true);
}

TEST(tx_fifo_scheduler, greedy_socket_sends_half_of_max_times_when_consuming_two_credits)
{
    ring_mock ring {};
    greedy_test_socket socket {};
    size_t max_iflight_requests = 10;
    tx_fifo_scheduler fifo(ring, max_iflight_requests);

    EXPECT_CALL(ring, send(An<tcp_segment &>(), _))
        .Times(max_iflight_requests / 2)
        .WillRepeatedly(Return(2U));
    fifo.schedule_tx(&socket, true);
}

TEST(tx_fifo_scheduler, greedy_socket_limits_the_socket_until_credits_are_returned)
{
    ring_mock ring {};
    greedy_test_socket socket {};
    size_t max_iflight_requests = 10;
    tx_fifo_scheduler fifo(ring, max_iflight_requests);

    EXPECT_CALL(ring, send(An<tcp_segment &>(), _))
        .Times(2)
        .WillOnce(Return(9U))
        .WillOnce(Return(0U));
    fifo.schedule_tx(&socket, true);

    fifo.notify_completion(reinterpret_cast<uintptr_t>(&socket), 6);
    EXPECT_CALL(ring, send(An<tcp_segment &>(), _)).Times(1).WillOnce(Return(7U));
    fifo.schedule_tx(&socket, true);
}

TEST(tx_fifo_scheduler, limited_socket_sends_up_to_limit)
{
    ring_mock ring {};
    size_t socket_inflight_limit = 7;
    limited_test_socket socket {socket_inflight_limit};
    size_t max_iflight_requests = 10;
    tx_fifo_scheduler fifo(ring, max_iflight_requests);

    EXPECT_CALL(ring, send(An<tcp_segment &>(), _))
        .Times(socket_inflight_limit)
        .WillRepeatedly(Return(1U));
    fifo.schedule_tx(&socket, true);
}

TEST(tx_fifo_scheduler, limited_socket_limits_the_socket_until_credits_are_returned)
{
    ring_mock ring {};
    size_t socket_inflight_limit = 2;
    limited_test_socket socket {socket_inflight_limit};
    size_t max_iflight_requests = 10;
    tx_fifo_scheduler fifo(ring, max_iflight_requests);

    EXPECT_CALL(ring, send(An<tcp_segment &>(), _))
        .Times(2)
        .WillOnce(Return(3U))
        .WillOnce(Return(4U));
    fifo.schedule_tx(&socket, true);

    fifo.notify_completion(reinterpret_cast<uintptr_t>(&socket), 1);
    EXPECT_CALL(ring, send(An<tcp_segment &>(), _)).Times(1).WillOnce(Return(1U));
    fifo.schedule_tx(&socket, false);
}

TEST(tx_round_robin_scheduler, limited_socket_sends_up_to_limit)
{
    ring_mock ring {};
    size_t socket_inflight_limit = 7;
    limited_test_socket socket {socket_inflight_limit};
    size_t max_iflight_requests = 10;
    tx_round_robin_scheduler rr(ring, max_iflight_requests);

    EXPECT_CALL(ring, send(An<tcp_segment &>(), _))
        .Times(socket_inflight_limit)
        .WillRepeatedly(Return(1U));
    rr.schedule_tx(&socket, true);
}

TEST(tx_round_robin_scheduler, limited_sockets_get_all_the_credits_required)
{
    ring_mock ring {};
    size_t socket_inflight_limit = 2;
    limited_test_socket socket1 {socket_inflight_limit}, socket2 {socket_inflight_limit};
    size_t max_iflight_requests = 10;
    tx_round_robin_scheduler rr(ring, max_iflight_requests);

    EXPECT_CALL(ring, send(An<tcp_segment &>(), _))
        .Times(socket_inflight_limit * 2 /* For both of the sockets */)
        .WillRepeatedly(Return(1U));
    rr.schedule_tx(&socket1, true);
    rr.schedule_tx(&socket2, true);
}

TEST(tx_round_robin_scheduler,
     num_limited_sockets_equals_available_credits_provide_one_tx_oppurtunity_per_socket)
{
    ring_mock ring {};
    size_t socket_inflight_limit = 10;
    limited_test_socket socket1 {socket_inflight_limit}, socket2 {socket_inflight_limit};
    size_t max_iflight_requests = 2;
    tx_round_robin_scheduler rr(ring, max_iflight_requests);

    EXPECT_CALL(ring, send(An<tcp_segment &>(), _))
        .Times(max_iflight_requests)
        .WillRepeatedly(Return(1U));
    rr.schedule_tx(&socket1, true);

    rr.notify_completion(reinterpret_cast<uintptr_t>(&socket1), max_iflight_requests);

    /* Setup complete all "requests" are complete" */

    EXPECT_CALL(ring, send(An<tcp_segment &>(), reinterpret_cast<uintptr_t>(&socket2)))
        .Times(1)
        .WillRepeatedly(Return(1U));
    EXPECT_CALL(ring, send(An<tcp_segment &>(), reinterpret_cast<uintptr_t>(&socket1)))
        .Times(1)
        .WillRepeatedly(Return(1U));
    rr.schedule_tx(&socket2, true);
}
/*
TEST(tx_round_robin_scheduler,
num_limited_sockets_greater_than_available_credits_provide_one_tx_oppurtunity_per_socket)
{
    ring_mock ring {};
    size_t socket_inflight_limit = 10;
    limited_test_socket socket1 {socket_inflight_limit}, socket2 {socket_inflight_limit}, socket3
{socket_inflight_limit}; size_t max_iflight_requests = 2; tx_round_robin_scheduler rr(ring,
max_iflight_requests);

    EXPECT_CALL(ring, send(An<tcp_segment &>(), _))
        .Times(max_iflight_requests)
        .WillRepeatedly(Return(1U));
    rr.schedule_tx(&socket1, true);

    rr.notify_completion(reinterpret_cast<uintptr_t>(&socket1), max_iflight_requests);

    EXPECT_CALL(ring, send(An<tcp_segment &>(), reinterpret_cast<uintptr_t>(&socket1)))
        .Times(1)
        .WillRepeatedly(Return(1U));
    EXPECT_CALL(ring, send(An<tcp_segment &>(), reinterpret_cast<uintptr_t>(&socket2)))
        .Times(1)
        .WillRepeatedly(Return(1U));
    rr.schedule_tx(&socket2, true);

    rr.notify_completion(reinterpret_cast<uintptr_t>(&socket1), 1);
    rr.notify_completion(reinterpret_cast<uintptr_t>(&socket2), 1);

    // Setup complete all "requests" are complete"

    EXPECT_CALL(ring, send(An<tcp_segment &>(), reinterpret_cast<uintptr_t>(&socket3)))
        .Times(1)
        .WillRepeatedly(Return(1U));
    EXPECT_CALL(ring, send(An<tcp_segment &>(), reinterpret_cast<uintptr_t>(&socket2)))
        .Times(1)
        .WillRepeatedly(Return(1U));
    rr.schedule_tx(&socket3, true);
}

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
        .WillOnce(Return(send_status::OK)); // Always return status_OK

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
