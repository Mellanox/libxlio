/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/*
 * blocking_wait_results.h tables. No socket, ring, NIC, or XLIO preload.
 */

#include "common/def.h"

#include "util/blocking_wait.h"
#include "sock/blocking_wait_results.h"

using result = blocking_wait::result;

TEST(rx_sleep_wait_result, ready_with_data_returns_one_no_eagain)
{
    rx_sleep_wait_outcome o = map_rx_sleep_wait_result(result::READY, /*has_rx_data=*/true);
    EXPECT_TRUE(o.proceed);
    EXPECT_EQ(0, o.err);
}

TEST(rx_sleep_wait_result, ready_no_data_returns_eagain)
{
    rx_sleep_wait_outcome o = map_rx_sleep_wait_result(result::READY, /*has_rx_data=*/false);
    EXPECT_FALSE(o.proceed);
    EXPECT_EQ(EAGAIN, o.err);
}

TEST(rx_sleep_wait_result, timeout_returns_eagain)
{
    rx_sleep_wait_outcome o = map_rx_sleep_wait_result(result::TIMEOUT, /*has_rx_data=*/false);
    EXPECT_FALSE(o.proceed);
    EXPECT_EQ(EAGAIN, o.err);
}

TEST(rx_sleep_wait_result, interrupted_returns_error_preserving_errno)
{
    rx_sleep_wait_outcome o = map_rx_sleep_wait_result(result::INTERRUPTED, /*has_rx_data=*/false);
    EXPECT_FALSE(o.proceed);
    EXPECT_EQ(0, o.err);
}

TEST(rx_sleep_wait_result, error_returns_error_preserving_errno)
{
    rx_sleep_wait_outcome o = map_rx_sleep_wait_result(result::ERROR, /*has_rx_data=*/false);
    EXPECT_FALSE(o.proceed);
    EXPECT_EQ(0, o.err);
}

TEST(tx_wait_result, ready_with_space_proceeds_no_errno)
{
    tx_wait_outcome o = map_tx_wait_result(result::READY, /*has_space=*/true, /*exiting=*/false);
    EXPECT_TRUE(o.has_space);
    EXPECT_EQ(0, o.err);
}

TEST(tx_wait_result, ready_space_wins_over_terminal)
{
    tx_wait_outcome o = map_tx_wait_result(result::READY, /*has_space=*/true, /*exiting=*/true);
    EXPECT_TRUE(o.has_space);
    EXPECT_EQ(0, o.err);
}

TEST(tx_wait_result, ready_no_space_exiting_returns_eintr)
{
    tx_wait_outcome o = map_tx_wait_result(result::READY, /*has_space=*/false, /*exiting=*/true);
    EXPECT_FALSE(o.has_space);
    EXPECT_EQ(EINTR, o.err);
}

// Call site !is_rts() maps ECONNRESET.
TEST(tx_wait_result, ready_no_space_leaves_errno)
{
    tx_wait_outcome o = map_tx_wait_result(result::READY, /*has_space=*/false, /*exiting=*/false);
    EXPECT_FALSE(o.has_space);
    EXPECT_EQ(0, o.err);
}

TEST(tx_wait_result, timeout_returns_eagain)
{
    tx_wait_outcome o =
        map_tx_wait_result(result::TIMEOUT, /*has_space=*/false, /*exiting=*/false);
    EXPECT_FALSE(o.has_space);
    EXPECT_EQ(EAGAIN, o.err);
}

TEST(tx_wait_result, interrupted_returns_error_preserving_errno)
{
    tx_wait_outcome o =
        map_tx_wait_result(result::INTERRUPTED, /*has_space=*/false, /*exiting=*/false);
    EXPECT_FALSE(o.has_space);
    EXPECT_EQ(0, o.err);
}

TEST(tx_wait_result, error_returns_error_preserving_errno)
{
    tx_wait_outcome o = map_tx_wait_result(result::ERROR, /*has_space=*/false, /*exiting=*/false);
    EXPECT_FALSE(o.has_space);
    EXPECT_EQ(0, o.err);
}

TEST(connect_wait_result, ready_connected_returns_success_no_errno)
{
    connect_wait_outcome o = map_connect_wait_result(result::READY, /*connected=*/true,
                                                     /*timed_out=*/false,
                                                     /*exiting=*/false);
    EXPECT_TRUE(o.ok);
    EXPECT_EQ(0, o.err);
}

TEST(connect_wait_result, ready_connected_wins_over_exit)
{
    connect_wait_outcome o = map_connect_wait_result(result::READY, /*connected=*/true,
                                                     /*timed_out=*/false,
                                                     /*exiting=*/true);
    EXPECT_TRUE(o.ok);
    EXPECT_EQ(0, o.err);
}

TEST(connect_wait_result, ready_exiting_returns_eintr)
{
    connect_wait_outcome o = map_connect_wait_result(result::READY, /*connected=*/false,
                                                     /*timed_out=*/false,
                                                     /*exiting=*/true);
    EXPECT_FALSE(o.ok);
    EXPECT_EQ(EINTR, o.err);
}

TEST(connect_wait_result, ready_exit_priority_over_terminal)
{
    connect_wait_outcome o = map_connect_wait_result(result::READY, /*connected=*/false,
                                                     /*timed_out=*/true,
                                                     /*exiting=*/true);
    EXPECT_FALSE(o.ok);
    EXPECT_EQ(EINTR, o.err);
}

TEST(connect_wait_result, ready_timed_out_returns_etimedout)
{
    connect_wait_outcome o = map_connect_wait_result(result::READY, /*connected=*/false,
                                                     /*timed_out=*/true,
                                                     /*exiting=*/false);
    EXPECT_FALSE(o.ok);
    EXPECT_EQ(ETIMEDOUT, o.err);
}

TEST(connect_wait_result, ready_refused_returns_econnrefused)
{
    connect_wait_outcome o = map_connect_wait_result(result::READY, /*connected=*/false,
                                                     /*timed_out=*/false,
                                                     /*exiting=*/false);
    EXPECT_FALSE(o.ok);
    EXPECT_EQ(ECONNREFUSED, o.err);
}

// Caller passes -1 today. Mapping for when a deadline exists.
TEST(connect_wait_result, timeout_returns_etimedout)
{
    connect_wait_outcome o = map_connect_wait_result(result::TIMEOUT, /*connected=*/false,
                                                     /*timed_out=*/false,
                                                     /*exiting=*/false);
    EXPECT_FALSE(o.ok);
    EXPECT_EQ(ETIMEDOUT, o.err);
}

TEST(connect_wait_result, interrupted_returns_error_preserving_errno)
{
    connect_wait_outcome o = map_connect_wait_result(result::INTERRUPTED, /*connected=*/false,
                                                     /*timed_out=*/false,
                                                     /*exiting=*/false);
    EXPECT_FALSE(o.ok);
    EXPECT_EQ(0, o.err);
}

TEST(connect_wait_result, error_returns_error_preserving_errno)
{
    connect_wait_outcome o = map_connect_wait_result(result::ERROR, /*connected=*/false,
                                                     /*timed_out=*/false,
                                                     /*exiting=*/false);
    EXPECT_FALSE(o.ok);
    EXPECT_EQ(0, o.err);
}

TEST(connect_wait_result, ready_passthrough_returns_minus_one_no_errno)
{
    connect_wait_outcome o = map_connect_wait_result(result::READY, /*connected=*/false,
                                                     /*timed_out=*/false,
                                                     /*exiting=*/false, /*passthrough=*/true);
    EXPECT_FALSE(o.ok);
    EXPECT_EQ(0, o.err);
}

TEST(connect_wait_result, ready_connected_wins_over_passthrough)
{
    connect_wait_outcome o = map_connect_wait_result(result::READY, /*connected=*/true,
                                                     /*timed_out=*/false,
                                                     /*exiting=*/false, /*passthrough=*/true);
    EXPECT_TRUE(o.ok);
    EXPECT_EQ(0, o.err);
}

// Redirect OS-connect owns errno. Not EINTR/ETIMEDOUT/ECONNREFUSED.
TEST(connect_wait_result, ready_passthrough_wins_over_terminal_and_exit)
{
    connect_wait_outcome o = map_connect_wait_result(result::READY, /*connected=*/false,
                                                     /*timed_out=*/true,
                                                     /*exiting=*/true, /*passthrough=*/true);
    EXPECT_FALSE(o.ok);
    EXPECT_EQ(0, o.err);
}

TEST(accept_wait_result, ready_conn_returns_success_no_errno)
{
    accept_wait_outcome o = map_accept_wait_result(result::READY, /*conn_ready=*/true,
                                                   /*exiting=*/false, /*listen_closed=*/false);
    EXPECT_TRUE(o.ok);
    EXPECT_EQ(0, o.err);
}

// Table: conn_ready wins. accept_helper post-loop g_b_exit is teardown-wins (R2C).
TEST(accept_wait_result, ready_conn_wins_over_exit)
{
    accept_wait_outcome o = map_accept_wait_result(result::READY, /*conn_ready=*/true,
                                                   /*exiting=*/true, /*listen_closed=*/false);
    EXPECT_TRUE(o.ok);
    EXPECT_EQ(0, o.err);
}

TEST(accept_wait_result, ready_exiting_returns_eintr)
{
    accept_wait_outcome o = map_accept_wait_result(result::READY, /*conn_ready=*/false,
                                                   /*exiting=*/true, /*listen_closed=*/false);
    EXPECT_FALSE(o.ok);
    EXPECT_EQ(EINTR, o.err);
}

TEST(accept_wait_result, ready_exit_priority_over_listen_closed)
{
    accept_wait_outcome o = map_accept_wait_result(result::READY, /*conn_ready=*/false,
                                                   /*exiting=*/true, /*listen_closed=*/true);
    EXPECT_FALSE(o.ok);
    EXPECT_EQ(EINTR, o.err);
}

TEST(accept_wait_result, ready_listen_closed_returns_einval)
{
    accept_wait_outcome o = map_accept_wait_result(result::READY, /*conn_ready=*/false,
                                                   /*exiting=*/false, /*listen_closed=*/true);
    EXPECT_FALSE(o.ok);
    EXPECT_EQ(EINVAL, o.err);
}

// Pred should not produce this. Fail-open so accept_helper re-enters the wait loop.
TEST(accept_wait_result, ready_none_defensive_returns_success)
{
    accept_wait_outcome o = map_accept_wait_result(result::READY, /*conn_ready=*/false,
                                                   /*exiting=*/false, /*listen_closed=*/false);
    EXPECT_TRUE(o.ok);
    EXPECT_EQ(0, o.err);
}

// Caller passes -1 today. Mapping for when a deadline exists.
TEST(accept_wait_result, timeout_returns_eagain)
{
    accept_wait_outcome o = map_accept_wait_result(result::TIMEOUT, /*conn_ready=*/false,
                                                   /*exiting=*/false, /*listen_closed=*/false);
    EXPECT_FALSE(o.ok);
    EXPECT_EQ(EAGAIN, o.err);
}

TEST(accept_wait_result, interrupted_returns_error_preserving_errno)
{
    accept_wait_outcome o = map_accept_wait_result(result::INTERRUPTED, /*conn_ready=*/false,
                                                   /*exiting=*/false, /*listen_closed=*/false);
    EXPECT_FALSE(o.ok);
    EXPECT_EQ(0, o.err);
}

TEST(accept_wait_result, error_returns_error_preserving_errno)
{
    accept_wait_outcome o = map_accept_wait_result(result::ERROR, /*conn_ready=*/false,
                                                   /*exiting=*/false, /*listen_closed=*/false);
    EXPECT_FALSE(o.ok);
    EXPECT_EQ(0, o.err);
}
