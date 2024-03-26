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

    virtual ~tx_scheduler() = default;

    virtual void schedule_tx(sockinfo *, bool = true) = 0;
    virtual void schedule_tx() = 0;
    virtual void notify_completion(uintptr_t, size_t = 1) = 0;

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
    sq_proxy(tx_scheduler &sched, size_t num_messages, uintptr_t metadata, size_t completions=0)
        : m_scheduler(sched)
        , m_num_messages(num_messages)
        , m_metadata(metadata)
        , m_completions(completions)
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

public:
    size_t m_completions;
private:
    tx_scheduler &m_scheduler;
    size_t m_num_messages;
    uintptr_t m_metadata;
};

class sockinfo {
public:
    sockinfo() = default;
    virtual ~sockinfo() = default;

    virtual tx_scheduler::status do_send(sq_proxy &sq) = 0;
};

#include <map>
#include <iostream>

class tx_fifo_scheduler final : public tx_scheduler {
public:
    tx_fifo_scheduler(ring &r, size_t max_requests)
        : tx_scheduler(r, max_requests)
    {
    }

    ~tx_fifo_scheduler() override = default;

    void schedule_tx(sockinfo *sock, bool) override
    {
        sq_proxy proxy{*this, m_max_requests - m_num_requests, reinterpret_cast<uintptr_t>(sock), m_completions[sock]};
        sock->do_send(proxy);
        m_completions.erase(sock);
    }

    void schedule_tx() override {
        /* Schedule on sufficiently empty send queue - scheduling moderation */
        if (m_num_requests == 0 || double(m_max_requests) / m_num_requests >= 2.0f) {
            for (auto sock_with_completions : m_completions) {
                sockinfo *sock = sock_with_completions.first;
                sq_proxy proxy{*this, 0, reinterpret_cast<uintptr_t>(sock), sock_with_completions.second};
                sock->do_send(proxy);
            }
            m_completions.clear();
        }
    }

    void notify_completion(uintptr_t metadata, size_t num_completions = 1) override
    {
        sockinfo *socket = reinterpret_cast<sockinfo *>(metadata);
        m_completions[socket] += num_completions;
        m_num_requests -= num_completions;
    }

private:
    std::map<sockinfo *, size_t> m_completions;
};

/* ----------------------------------------------------- */
#include <deque>

class tx_round_robin_scheduler final : public tx_scheduler {
public:
    tx_round_robin_scheduler(ring &r, size_t max_requests)
        : tx_scheduler(r, max_requests)
    {
    }

    ~tx_round_robin_scheduler() override { }

    /* is_first should be true in two cases:
     *     1. The first time the socket is ready to send.
     *     2. The first time, since the socket returned NO_MORE_MESSAGES from do_send.
     */
    void schedule_tx(sockinfo *sock, bool is_first) override
    {
        if (is_first) {
            m_queue.push_back(sock);
        }

        /* Schedule on sufficiently empty send queue - scheduling moderation */
        if (!m_num_requests || double(m_max_requests) / m_num_requests >= 2.0f) {
            schedule_tx();
        }
    }

    void schedule_tx() override {
        size_t num_messages = fair_num_requests();
        size_t num_sockets = m_queue.size();

        while (num_sockets && m_max_requests - m_num_requests >= num_messages) {
            sockinfo *sock = m_queue.front();
            m_queue.pop_front();
            num_sockets--;

            tx_scheduler::status status = single_socket_send(sock, num_messages);
            if (status == tx_scheduler::status::OK) {
                m_queue.push_back(sock);
            }
        }
    }

    void notify_completion(uintptr_t metadata, size_t num_completions = 1) override
    {
        sockinfo *socket = reinterpret_cast<sockinfo *>(metadata);
        m_completions[socket] += num_completions;
        m_num_requests -= num_completions;
    }

private:

    tx_scheduler::status single_socket_send(sockinfo *sock, size_t requests) {
        sq_proxy proxy{*this, requests, reinterpret_cast<uintptr_t>(sock), m_completions[sock]};
        m_completions.erase(sock);
        return sock->do_send(proxy);
    }

    /*
    * In the round robin implementation, we allocated the same number of requests per sender.
    * If the available requests exceed the number of senders, each sender may receive more than one
    * opportunity to send.
    * If the number of senders exceed the available requests, each sender should receive at least
    * one opportunity to send.
    */
    size_t fair_num_requests() {
        /* If the queue is empty, make the denominator 1 to eliminate the divide-by-zero error */
        return std::max(1UL, (m_max_requests - m_num_requests) / (std::max(1UL, m_queue.size())));
    }

private:
    std::deque<sockinfo *> m_queue;
    std::map<sockinfo *, size_t> m_completions;
};
#endif // _TX_SCHEDULER_H_
