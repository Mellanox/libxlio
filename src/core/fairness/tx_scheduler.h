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
#ifndef _TX_SCHEDULER_H_
#define _TX_SCHEDULER_H_

class ring;
class tcp_segment;
class udp_datagram;
class control_msg;

class sockinfo {
public:
    sockinfo() = default;
    virtual ~sockinfo() = default;

    virtual void notify_completion(size_t num_completions = 1) = 0;
    virtual bool do_send(ring *) = 0;
};

class ring {
public:
    virtual ~ring() = default;

    virtual void notify_complete(uintptr_t) = 0;
    virtual bool send(tcp_segment *, sockinfo *) = 0;
    virtual bool send(udp_datagram *, sockinfo *) = 0;
    virtual bool send(control_msg *, sockinfo *) = 0;
};

class tx_scheduler {
public:
    tx_scheduler() = default;
    ~tx_scheduler() = default;

    virtual void notify_ready_to_send(sockinfo *, bool) = 0;
    virtual void notify_completion(sockinfo *, size_t num_completions = 0) = 0;
    virtual void fair_send() = 0;
};

/* TODO In future migrate to tx_fifo_scheduler.h */
#include <iostream>
#include <cassert>

class tx_fifo_scheduler final : public tx_scheduler {
public:
    tx_fifo_scheduler(ring *r)
        : m_ring(r) {};
    ~tx_fifo_scheduler() = default;

    void notify_ready_to_send(sockinfo *, bool) override { }

    void notify_completion(sockinfo *, size_t num_completions = 0) override { }

    void fair_send() override { }

private:
    ring *m_ring;
};
#endif // _TX_SCHEDULER_H_
