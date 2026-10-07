/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <sys/epoll.h>
#include <poll.h>
#include <signal.h>
#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "tcp_base.h"

class tcp_stream_integrity : public tcp_base {
protected:
    // Prime length, so the pattern never lines up with segment, stride or read sizes.
    static constexpr size_t PATTERN_SIZE = 65521U;
    static constexpr size_t CONN_SHIFT = 7919U;
    static constexpr size_t MAX_READ = 16384U;
    static constexpr size_t MAX_WRITE = 65536U;
    static constexpr int MAX_EVENTS = 64;

    struct conn_state {
        // Accepted socket descriptor for this stream.
        int fd = -1;

        // Client-provided connection ID, or UINT32_MAX until the full ID is received.
        uint32_t id = UINT32_MAX;

        // Staging buffer for the connection ID, which may span multiple recv() calls.
        uint8_t hdr[sizeof(uint32_t)] = {};

        // Number of connection-ID bytes currently stored in hdr.
        size_t hdr_len = 0U;

        // Number of payload bytes consumed, excluding the connection ID.
        uint64_t received = 0U;

        // True after EOF or a terminal receive error removes the socket from epoll.
        bool eof = false;

        // True after a validation failure; suppresses further data and byte-count checks.
        bool corrupt = false;
    };

    // Initialize the test duration, connection count, and deterministic payload pattern.
    void SetUp() override
    {
        tcp_base::SetUp();
        m_nconns = env_int("XLIO_GTEST_STREAM_CONNS", 64);
        m_seconds = env_int("XLIO_GTEST_STREAM_SEC", 3);
        m_pattern.resize(PATTERN_SIZE);
        uint64_t x = 0x9E3779B97F4A7C15ULL;
        for (auto &b : m_pattern) {
            x = x * 6364136223846793005ULL + 1442695040888963407ULL;
            b = static_cast<uint8_t>(x >> 56);
        }
    }

    // Read a positive integer from an environment variable, or return the supplied default.
    static int env_int(const char *name, int def)
    {
        const char *val = getenv(name);
        return (val && atoi(val) > 0) ? atoi(val) : def;
    }

    // Choose a randomized receive size biased toward sub-segment reads and partial consumption.
    static size_t next_read_size(unsigned &seed)
    {
        unsigned r = static_cast<unsigned>(rand_r(&seed));
        return 1U + ((r & 3U) ? r % 2048U : r % MAX_READ);
    }

    // Return expected stream data at an offset, trimming len at the pattern wrap boundary.
    const uint8_t *stream_at(uint32_t conn, uint64_t offset, size_t &len) const
    {
        size_t pos = (offset + static_cast<uint64_t>(conn) * CONN_SHIFT) % PATTERN_SIZE;
        len = std::min(len, PATTERN_SIZE - pos);
        return &m_pattern[pos];
    }

    // Compare received payload with the expected per-connection stream across pattern wraps.
    bool matches(uint32_t conn, uint64_t offset, const uint8_t *data, size_t len) const
    {
        while (len) {
            size_t n = len;
            const uint8_t *expected = stream_at(conn, offset, n);
            if (memcmp(data, expected, n)) {
                return false;
            }
            data += n;
            offset += n;
            len -= n;
        }
        return true;
    }

    // Assemble and validate the connection ID, then verify and account for received payload.
    void consume(conn_state &cs, std::vector<bool> &seen, const uint8_t *data, size_t len)
    {
        size_t off = 0U;
        while (cs.hdr_len < sizeof(cs.hdr) && off < len) {
            cs.hdr[cs.hdr_len++] = data[off++];
        }
        if (cs.hdr_len < sizeof(cs.hdr)) {
            return;
        }
        if (cs.id == UINT32_MAX && !cs.corrupt) {
            uint32_t id;
            memcpy(&id, cs.hdr, sizeof(id));
            if (id >= static_cast<uint32_t>(m_nconns) || seen[id]) {
                ADD_FAILURE() << "fd " << cs.fd << ": invalid connection id " << id;
                cs.corrupt = true;
            } else {
                cs.id = id;
                seen[id] = true;
            }
        }
        size_t payload = len - off;
        if (!cs.corrupt && !matches(cs.id, cs.received, data + off, payload)) {
            ADD_FAILURE() << "connection " << cs.id << ": stream mismatch within " << payload
                          << " bytes read at offset " << cs.received;
            cs.corrupt = true;
        }
        cs.received += payload;
    }

    // Open all client streams, send patterned data, report byte totals, and close cleanly.
    void run_client(int totals_fd)
    {
        std::vector<int> fds(m_nconns, -1);
        std::vector<uint64_t> sent(m_nconns, 0U);
        int efd = epoll_create1(0);
        ASSERT_LE(0, efd);

        for (int i = 0; i < m_nconns; ++i) {
            fds[i] = tcp_base::sock_create();
            ASSERT_LE(0, fds[i]);
            ASSERT_EQ(0, bind(fds[i], &client_addr.addr, sizeof(client_addr))) << errno;
            ASSERT_EQ(0, connect(fds[i], &server_addr.addr, sizeof(server_addr))) << errno;
            uint32_t id = static_cast<uint32_t>(i);
            ASSERT_EQ(static_cast<ssize_t>(sizeof(id)),
                      send(fds[i], &id, sizeof(id), MSG_NOSIGNAL));
            ASSERT_EQ(0, sock_noblock(fds[i]));
            epoll_event ev = {};
            ev.events = EPOLLOUT;
            ev.data.u32 = static_cast<uint32_t>(i);
            ASSERT_EQ(0, epoll_ctl(efd, EPOLL_CTL_ADD, fds[i], &ev));
        }
        log_trace("Client: %d connections established\n", m_nconns);

        epoll_event events[MAX_EVENTS];
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(m_seconds);
        while (std::chrono::steady_clock::now() < deadline) {
            int n = epoll_wait(efd, events, MAX_EVENTS, 100);
            for (int e = 0; e < n; ++e) {
                uint32_t c = events[e].data.u32;
                size_t len = MAX_WRITE;
                const uint8_t *data = stream_at(c, sent[c], len);
                ssize_t rc = send(fds[c], data, len, MSG_NOSIGNAL);
                if (rc > 0) {
                    sent[c] += static_cast<uint64_t>(rc);
                } else if (rc < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    ADD_FAILURE() << "connection " << c << ": send() errno " << errno;
                    epoll_ctl(efd, EPOLL_CTL_DEL, fds[c], nullptr);
                }
            }
        }

        size_t totals_len = sent.size() * sizeof(uint64_t);
        EXPECT_EQ(static_cast<ssize_t>(totals_len), write(totals_fd, sent.data(), totals_len));
        for (int fd : fds) {
            shutdown(fd, SHUT_WR);
        }
        // Data queued in this process is lost if it exits before the server has read it.
        for (int fd : fds) {
            pollfd pfd = {fd, POLLIN, 0};
            char byte;
            while (poll(&pfd, 1, 10000) > 0 && recv(fd, &byte, 1, 0) > 0) {
            }
            close(fd);
        }
        close(efd);
    }

    // Accept and verify all streams, then compare received byte counts with the client totals.
    void run_server(int l_fd, int totals_fd)
    {
        std::vector<conn_state> conns(m_nconns);
        std::vector<bool> seen(m_nconns, false);
        int efd = epoll_create1(0);
        EXPECT_LE(0, efd);

        int accepted = 0;
        for (; accepted < m_nconns; ++accepted) {
            int fd = accept(l_fd, nullptr, nullptr);
            if (fd < 0) {
                ADD_FAILURE() << "accept() " << accepted << " errno " << errno;
                break;
            }
            conns[accepted].fd = fd;
            EXPECT_EQ(0, sock_noblock(fd));
            epoll_event ev = {};
            ev.events = EPOLLIN;
            ev.data.u32 = static_cast<uint32_t>(accepted);
            EXPECT_EQ(0, epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev));
        }
        log_trace("Server: %d connections accepted\n", accepted);

        std::vector<uint8_t> buf(MAX_READ);
        unsigned seed = 1U;
        int open = accepted;
        epoll_event events[MAX_EVENTS];
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(m_seconds + 30);
        while (open && std::chrono::steady_clock::now() < deadline) {
            int n = epoll_wait(efd, events, MAX_EVENTS, 100);
            for (int e = 0; e < n; ++e) {
                conn_state &cs = conns[events[e].data.u32];
                while (!cs.eof) {
                    ssize_t rc = recv(cs.fd, buf.data(), next_read_size(seed), 0);
                    if (rc > 0) {
                        consume(cs, seen, buf.data(), static_cast<size_t>(rc));
                        continue;
                    }
                    if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                        break;
                    }
                    if (rc < 0) {
                        ADD_FAILURE() << "connection " << cs.id << ": recv() errno " << errno;
                    } else if (cs.hdr_len < sizeof(cs.hdr)) {
                        ADD_FAILURE() << "fd " << cs.fd << ": EOF after " << cs.hdr_len << " of "
                                      << sizeof(cs.hdr) << " connection ID bytes";
                        cs.corrupt = true;
                    }
                    cs.eof = true;
                    epoll_ctl(efd, EPOLL_CTL_DEL, cs.fd, nullptr);
                    --open;
                }
            }
        }
        EXPECT_EQ(0, open) << "connections did not reach EOF in time";

        std::vector<uint64_t> totals(m_nconns, 0U);
        size_t totals_len = totals.size() * sizeof(uint64_t);
        size_t got = 0U;
        pollfd pfd = {totals_fd, POLLIN, 0};
        while (got < totals_len && poll(&pfd, 1, 10000) > 0) {
            ssize_t rc =
                read(totals_fd, reinterpret_cast<char *>(totals.data()) + got, totals_len - got);
            if (rc <= 0) {
                break;
            }
            got += static_cast<size_t>(rc);
        }
        EXPECT_EQ(totals_len, got) << "client did not report its totals";

        uint64_t total_received = 0U;
        for (int i = 0; i < accepted; ++i) {
            const conn_state &cs = conns[i];
            total_received += cs.received;
            if (got == totals_len && !cs.corrupt && cs.id != UINT32_MAX) {
                EXPECT_EQ(totals[cs.id], cs.received)
                    << "connection " << cs.id << " received a different byte count than sent";
            }
            close(cs.fd);
        }
        log_trace("Server: %" PRIu64 " bytes verified\n", total_received);
        close(efd);
    }

    int m_nconns = 0;
    int m_seconds = 0;
    std::vector<uint8_t> m_pattern;
};

/**
 * @test tcp_stream_integrity.multi_conn_partial_reads
 * @brief
 *    Every byte of many concurrent TCP streams arrives in order, and EOF arrives only after the
 *    whole stream.
 *
 * @details
 *    The child opens XLIO_GTEST_STREAM_CONNS connections (default 64) and sends each one a
 *    distinct pseudo-random pattern for XLIO_GTEST_STREAM_SEC seconds (default 3), prefixed with
 *    the connection id. It reports the byte count it sent per connection over a pipe, shuts
 *    the connections down, and waits for the server to close them.
 *    The parent receives with epoll and random read sizes, mostly smaller than one segment, so
 *    receive buffers are often only partly consumed. It compares every byte with the expected
 *    pattern and each connection's received byte count with the sent count.
 *    In worker threads mode the worker thread queues received buffers while the application
 *    thread consumes them, so missing synchronization between them shows up as a stream
 *    mismatch or as an early EOF.
 */
TEST_F(tcp_stream_integrity, multi_conn_partial_reads)
{
    int totals_pipe[2];
    ASSERT_EQ(0, pipe(totals_pipe));

    int pid = fork();
    ASSERT_LE(0, pid);
    if (0 == pid) { /* I am the child */
        close(totals_pipe[0]);
        barrier_fork(pid);

        run_client(totals_pipe[1]);
        close(totals_pipe[1]);

        /* This exit is very important, otherwise the fork
         * keeps running and may duplicate other tests.
         */
        exit(testing::Test::HasFailure());
    } else { /* I am the parent */
        close(totals_pipe[1]);

        bool listener_ready = false;
        int l_fd = tcp_base::sock_create();
        EXPECT_LE_ERRNO(0, l_fd);
        if (0 <= l_fd) {
            int rc = set_socket_rcv_timeout(l_fd, 10);
            EXPECT_EQ_ERRNO(0, rc);

            if (0 == rc) {
                rc = bind(l_fd, &server_addr.addr, sizeof(server_addr));
                EXPECT_EQ_ERRNO(0, rc);
                if (0 == rc) {
                    rc = listen(l_fd, m_nconns);
                    EXPECT_EQ_ERRNO(0, rc);
                    listener_ready = (0 == rc);
                }
            }
            if (listener_ready) {
                barrier_fork(pid);
                run_server(l_fd, totals_pipe[0]);
            }
            close(l_fd);
        }
        close(totals_pipe[0]);

        if (!listener_ready) {
            EXPECT_EQ(0, kill(pid, SIGKILL)) << errno;
        }
        EXPECT_EQ(listener_ready ? 0 : -2, wait_fork(pid));
    }
}
