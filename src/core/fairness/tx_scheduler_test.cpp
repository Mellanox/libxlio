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

/* Mock classes created for testing tx_scheduler */
class sockinfo_mock : public sockinfo {
public:
    MOCK_METHOD(void, notify_completion, (size_t num_cpmpletions), (override));
    MOCK_METHOD(bool, do_send, (ring *), (override));
};

class ring_mock : public ring {
public:

    ring_mock() = default;
	~ring_mock() override = default;

    MOCK_METHOD(void, notify_complete, (uintptr_t), (override));

    // Mock the send methods
    MOCK_METHOD(bool, send, (tcp_segment *, sockinfo *), (override));
    MOCK_METHOD(bool, send, (udp_datagram *, sockinfo *), (override));
    MOCK_METHOD(bool, send, (control_msg *, sockinfo *), (override));
};

TEST(tx_scheduler, constructor)
{
    ring_mock r{};
    tx_fifo_scheduler fifo(&r);
}
