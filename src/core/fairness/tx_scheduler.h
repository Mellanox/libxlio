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

class tcp_segment;
class udp_datagram;
class control_msg;
class sockinfo;

class ring {
public:
    virtual ~ring() = default;

    virtual void notify_complete(uintptr_t) = 0;
    virtual bool send(tcp_segment &, uintptr_t) = 0;
    virtual bool send(udp_datagram &, uintptr_t) = 0;
    virtual bool send(control_msg &, uintptr_t) = 0;
};

class tx_scheduler {
public:
    tx_scheduler(ring &r, size_t max_requests)
        : m_ring(r)
        , m_max_requests(max_requests)
        , m_num_requests(0UL)
    {
    }

    ~tx_scheduler() = default;

    virtual void notify_ready_to_send(sockinfo *, bool = true) = 0;
    virtual void notify_completion(uintptr_t, size_t = 1) = 0;
    virtual void schedule_tx() = 0;

    enum status { OK, NO_MORE_MESSAGES, ERROR };

    template <class Msg> inline bool send(Msg &msg, uintptr_t metadata)
    {
        if (m_num_requests < m_max_requests) {
            m_num_requests++;
            m_ring.send(msg, metadata);
            return true;
        }
        return false;
    }

protected:
    ring &m_ring;
    size_t m_max_requests;
    size_t m_num_requests;
};

class sq_proxy final {
public:
    sq_proxy(tx_scheduler &sched, size_t num_messages, uintptr_t metadata)
        : m_scheduler(sched)
        , m_num_messages(num_messages)
        , m_metadata(metadata)
    {
    }
    ~sq_proxy() = default;

    template <class Msg> inline bool send(Msg &msg)
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
};

class sockinfo {
public:
    sockinfo() = default;
    virtual ~sockinfo() = default;

    virtual void notify_completion(size_t num_completions = 1) = 0;
    virtual tx_scheduler::status do_send(sq_proxy sq) = 0;
};

#include <map>
class tx_fifo_scheduler final : public tx_scheduler {
public:
    tx_fifo_scheduler(ring &r, size_t max_requests)
        : tx_scheduler(r, max_requests)
    {
    }

    ~tx_fifo_scheduler() = default;

    void notify_ready_to_send(sockinfo *sock, bool) override
    {
        sock->do_send({*this, m_max_requests - m_num_requests, reinterpret_cast<uintptr_t>(sock)});
    }

    void notify_completion(uintptr_t metadata, size_t num_completions = 1) override
    {
        sockinfo *socket = reinterpret_cast<sockinfo *>(metadata);
        m_notifications[socket] += num_completions;
    }

    void schedule_tx() override
    {
        /* The sockets are not allowed to destruct before all notifications received */
        for (auto tx_notify : m_notifications) {
            tx_notify.first->notify_completion(tx_notify.second);
        }
        m_notifications.clear();
    }

private:
    std::map<sockinfo *, size_t> m_notifications;
    ring *m_ring;
    size_t m_max_requests;
    size_t m_num_requests;
};

#endif // _TX_SCHEDULER_H_
