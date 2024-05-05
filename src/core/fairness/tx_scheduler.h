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

#include <cstddef>
#include <cstdint>

#include "ring_tx_scheduler_interface.h"
#include "sockinfo_tx_scheduler_interface.h"

class tcp_segment;
class udp_datagram;
class control_msg;
class sockinfo_tx_scheduler_interface;

class tx_scheduler {
public:
    tx_scheduler(ring_tx_scheduler_interface &r, size_t max_requests);
    virtual ~tx_scheduler() = default;

    virtual void schedule_tx(sockinfo_tx_scheduler_interface *, bool = true) = 0;
    virtual void schedule_tx() = 0;
    virtual void notify_completion(uintptr_t, size_t = 1) = 0;

    template <class Msg> bool send(Msg &msg, uintptr_t metadata)
    {
        if (m_num_requests < m_max_requests) {
            m_num_requests++;
            m_ring.send(msg, metadata);
            return true;
        }
        return false;
    }

protected:
    ring_tx_scheduler_interface &m_ring;
    size_t m_max_requests;
    size_t m_num_requests;
};

class sq_proxy final {
public:
    sq_proxy(tx_scheduler &sched, size_t num_messages, uintptr_t metadata, size_t completions = 0);
    ~sq_proxy() = default;

    template <class Msg> bool send(Msg &msg)
    {
        if (m_num_messages) {
            m_num_messages--;
            return m_scheduler.send(msg, m_metadata);
        }
        return false;
    }

private:
    tx_scheduler &m_scheduler;
    size_t m_num_messages;
    uintptr_t m_metadata;

public:
    size_t m_completions;
};
#endif // _TX_SCHEDULER_H_
