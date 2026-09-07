/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef BLOCKING_WAIT_RESULTS_H
#define BLOCKING_WAIT_RESULTS_H

#include <cerrno>

#include "util/blocking_wait.h"

/*
 * Four wait_until() tables: post-wait state -> (return, errno) for recv/send/connect/accept.
 * err == 0 means leave errno (EINTR from block() must survive). Else the caller sets errno.
 */

struct rx_sleep_wait_outcome {
    bool proceed; // true -> rx_sleep_wait() returns 1; false -> -1, handle_rx_error()
    int err;
};

// Data before terminal. No RX bytes -> EAGAIN; handle_rx_error() maps FIN/RST/exit.
inline rx_sleep_wait_outcome map_rx_sleep_wait_result(blocking_wait::result r, bool has_rx_data)
{
    switch (r) {
    case blocking_wait::result::TIMEOUT:
        return {false, EAGAIN};
    case blocking_wait::result::INTERRUPTED:
    case blocking_wait::result::ERROR:
        return {false, 0};
    case blocking_wait::result::READY:
        break;
    }
    if (has_rx_data) {
        return {true, 0};
    }
    return {false, EAGAIN};
}

struct tx_wait_outcome {
    bool has_space; // true -> tx_wait() returns sndbuf size; false -> 0
    int err;
};

// Space before terminal. No space: exiting -> EINTR; else leave errno (call site maps
// !is_rts() to ECONNRESET).
inline tx_wait_outcome map_tx_wait_result(blocking_wait::result r, bool has_space, bool exiting)
{
    switch (r) {
    case blocking_wait::result::TIMEOUT:
        return {false, EAGAIN};
    case blocking_wait::result::INTERRUPTED:
    case blocking_wait::result::ERROR:
        return {false, 0};
    case blocking_wait::result::READY:
        break;
    }
    if (has_space) {
        return {true, 0};
    }
    if (exiting) {
        return {false, EINTR};
    }
    return {false, 0};
}

struct connect_wait_outcome {
    bool ok; // true -> connect() returns 0; false -> -1
    int err;
};

// Connected before passthrough before exiting. Passthrough leaves errno for the OS-connect
// redirect. TIMEOUT is unreachable today (caller passes -1).
inline connect_wait_outcome map_connect_wait_result(blocking_wait::result r, bool connected,
                                                    bool timed_out, bool exiting,
                                                    bool passthrough = false)
{
    switch (r) {
    case blocking_wait::result::TIMEOUT:
        return {false, ETIMEDOUT};
    case blocking_wait::result::INTERRUPTED:
    case blocking_wait::result::ERROR:
        return {false, 0};
    case blocking_wait::result::READY:
        break;
    }
    if (connected) {
        return {true, 0};
    }
    if (passthrough) {
        return {false, 0};
    }
    if (exiting) {
        return {false, EINTR};
    }
    if (timed_out) {
        return {false, ETIMEDOUT};
    }
    return {false, ECONNREFUSED};
}

struct accept_wait_outcome {
    bool ok; // true -> pop accept queue; false -> accept_helper() returns -1
    int err;
};

// conn_ready here; accept_helper() post-loop g_b_exit is teardown-wins. exiting before
// listen_closed. TIMEOUT maps to EAGAIN when SO_RCVTIMEO expires.
inline accept_wait_outcome map_accept_wait_result(blocking_wait::result r, bool conn_ready,
                                                  bool exiting, bool listen_closed)
{
    switch (r) {
    case blocking_wait::result::TIMEOUT:
        return {false, EAGAIN};
    case blocking_wait::result::INTERRUPTED:
    case blocking_wait::result::ERROR:
        return {false, 0};
    case blocking_wait::result::READY:
        break;
    }
    if (conn_ready) {
        return {true, 0};
    }
    if (exiting) {
        return {false, EINTR};
    }
    if (listen_closed) {
        return {false, EINVAL};
    }
    return {true, 0};
}

#endif /* BLOCKING_WAIT_RESULTS_H */
