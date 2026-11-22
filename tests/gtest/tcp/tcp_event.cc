/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "tcp_base.h"
#include "core/xlio_extra.h"
#include <vector>
#include <chrono>

class tcp_event : public tcp_base {
protected:
    std::vector<int> m_fds;
    pid_t m_child = -1;
    int m_control = -1;
    int m_socket = -1;
    int m_epfd = -1;
    bool m_peer_stopped = false;
    bool m_peer_connected = false;

    int track(int fd)
    {
        if (fd >= 0) {
            m_fds.push_back(fd);
        }
        return fd;
    }

    void finish_connection()
    {
        // Keep the child alive to acknowledge our FIN. Otherwise its _exit()
        // can leave the parent's offloaded flow attached when the tuple is reused.
        ASSERT_NO_FATAL_FAILURE(command('C'));
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        bool sent_fin = false;
        tcp_info info = {};
        do {
            // EOF stays readable. Poll without POLLIN so XLIO checks the
            // receive queue for the final ACK even after recv() returns zero.
            pollfd pfd = {m_socket, 0, 0};
            int ready = poll(&pfd, 1, 1);
            if (ready < 0 && errno == EINTR) {
                continue;
            }
            ASSERT_GE(ready, 0);
            socklen_t len = sizeof(info);
            ASSERT_EQ(0, getsockopt(m_socket, IPPROTO_TCP, TCP_INFO, &info, &len));
            if (info.tcpi_state == TCP_CLOSE || info.tcpi_state == TCP_TIME_WAIT) {
                return;
            }

            // Drain any test data before closing. A local SHUT_RD also returns
            // EOF, so wait for CLOSE_WAIT to confirm the peer's FIN arrived.
            char buffer[64];
            ssize_t rc = recv(m_socket, buffer, sizeof(buffer), MSG_DONTWAIT);
            if (rc < 0) {
                ASSERT_TRUE(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                    << strerror(errno);
            }
            if (rc == 0 && info.tcpi_state == TCP_CLOSE_WAIT && !sent_fin) {
                ASSERT_EQ(0, shutdown(m_socket, SHUT_WR));
                sent_fin = true;
            }
        } while (std::chrono::steady_clock::now() < deadline);
        ADD_FAILURE() << "Timed out waiting for TCP close, state=" << unsigned(info.tcpi_state);
    }

    void close_tracked_fds()
    {
        for (auto it = m_fds.rbegin(); it != m_fds.rend(); ++it) {
            close(*it);
        }
    }

    void TearDown() override
    {
        if (m_peer_stopped) {
            EXPECT_EQ(0, kill(m_child, SIGCONT));
        } else if (m_peer_connected) {
            finish_connection();
        }
        // Closing the control channel releases the peer even after a fatal assertion.
        close_tracked_fds();
        if (m_child > 0) {
            EXPECT_EQ(0, wait_fork(m_child));
        }
    }

    static int receive_control(int control, char &value, int tcp_fd = -1)
    {
        // During teardown, poll TCP as well so a delegated peer processes the
        // parent's FIN while it waits for the control channel to close.
        pollfd fds[] = {{control, POLLIN, 0}, {tcp_fd, 0, 0}};
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        do {
            int rc = poll(fds, 2, tcp_fd >= 0 ? 10 : 10000);
            if (rc < 0 && errno != EINTR) {
                return -1;
            }
            if (rc > 0 && fds[0].revents) {
                return recv(control, &value, 1, 0);
            }
        } while (std::chrono::steady_clock::now() < deadline);
        return -1;
    }

    void peer(int control)
    {
        int listener = track(sock_create_to(m_family, true, 10));
        ASSERT_GE(listener, 0);
        ASSERT_EQ(0, bind(listener, &server_addr.addr, sizeof(server_addr)));
        ASSERT_EQ(0, listen(listener, SOMAXCONN));
        ASSERT_EQ(1, send(control, "L", 1, MSG_NOSIGNAL));
        int fd = track(accept(listener, nullptr, nullptr));
        const int accept_errno = errno;
        ASSERT_GE(fd, 0) << "accept errno=" << accept_errno << " (" << strerror(accept_errno)
                         << ")";
        ASSERT_EQ(1, send(control, "A", 1, MSG_NOSIGNAL));
        bool sent_fin = false;
        for (;;) {
            char command = 0;
            int rc = receive_control(control, command);
            if (rc == 0) {
                return;
            }
            ASSERT_EQ(1, rc);
            if (command == 'D') {
                ASSERT_EQ(1, send(fd, "x", 1, MSG_NOSIGNAL));
            } else if (command == 'F' || command == 'C') {
                if (!sent_fin) {
                    ASSERT_EQ(0, shutdown(fd, SHUT_WR));
                    sent_fin = true;
                }
            } else if (command == 'R') {
                linger abortive = {1, 0};
                ASSERT_EQ(0, setsockopt(fd, SOL_SOCKET, SO_LINGER, &abortive, sizeof(abortive)));
                ASSERT_EQ(0, close(fd));
                m_fds.pop_back(); // The accepted socket was tracked last.
            } else {
                FAIL() << "Unexpected peer command " << command;
            }
            ASSERT_EQ(1, send(control, &command, 1, MSG_NOSIGNAL));
            if (command == 'C') {
                EXPECT_EQ(0, receive_control(control, command, fd));
                return;
            }
        }
    }

    void connected_pair()
    {
        int control[2];
        ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, control));
        m_child = fork();
        if (m_child < 0) {
            const int fork_errno = errno;
            close(control[0]);
            close(control[1]);
            FAIL() << "fork errno=" << fork_errno << " (" << strerror(fork_errno) << ")";
        }
        if (m_child == 0) {
            close(control[0]);
            peer(control[1]);
            close_tracked_fds();
            close(control[1]);
            // Fatal assertions in peer() must not return into the parent test body.
            _exit(testing::Test::HasFailure() ? 1 : 0);
        }
        close(control[1]);
        m_control = track(control[0]);
        char response = 0;
        ASSERT_EQ(1, receive_control(m_control, response));
        ASSERT_EQ('L', response);
        m_socket = track(sock_create_nb());
        ASSERT_GE(m_socket, 0);
        sockaddr_store_t local = client_addr;
        sys_set_port(&local.addr, 0);
        ASSERT_EQ(0, bind(m_socket, &local.addr, sizeof(local)));
        ASSERT_EQ(-1, connect(m_socket, &server_addr.addr, sizeof(server_addr)));
        ASSERT_EQ(EINPROGRESS, errno);
        m_epfd = track(epoll_create1(0));
        ASSERT_GE(m_epfd, 0);
        ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_ADD, EPOLLOUT));
        // Allow slow connection setup; established-connection checks keep the default timeout.
        ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLOUT, 1, 10000));
        int error = -1;
        socklen_t len = sizeof(error);
        ASSERT_EQ(0, getsockopt(m_socket, SOL_SOCKET, SO_ERROR, &error, &len));
        ASSERT_EQ(0, error);
        ASSERT_EQ(1, receive_control(m_control, response));
        ASSERT_EQ('A', response);
        m_peer_connected = true;
    }

    void command(char value)
    {
        ASSERT_EQ(1, send(m_control, &value, 1, MSG_NOSIGNAL));
        char response = 0;
        ASSERT_EQ(1, receive_control(m_control, response));
        ASSERT_EQ(value, response);
        if (value == 'R') {
            m_peer_connected = false;
        }
    }

    void interest(int operation, uint32_t events, uint64_t data = 1)
    {
        epoll_event event = {};
        event.events = events;
        event.data.u64 = data;
        ASSERT_EQ(0, epoll_ctl(m_epfd, operation, m_socket, &event));
    }

    void expect_events(uint32_t expected, uint64_t data = 1, int timeout_ms = 1000)
    {
        epoll_event event = {};
        int rc = epoll_wait(m_epfd, &event, 1, timeout_ms);
        if (rc != 1) {
            const int wait_errno = rc < 0 ? errno : 0;
            tcp_info info = {};
            socklen_t len = sizeof(info);
            int info_rc = getsockopt(m_socket, IPPROTO_TCP, TCP_INFO, &info, &len);
            const int info_errno = info_rc < 0 ? errno : 0;
            // SO_ERROR is read only on failure: reading it clears the pending error.
            int socket_error = -1;
            len = sizeof(socket_error);
            int error_rc = getsockopt(m_socket, SOL_SOCKET, SO_ERROR, &socket_error, &len);
            const int error_errno = error_rc < 0 ? errno : 0;
            FAIL() << "epoll_wait returned " << rc << ", expected events=" << expected
                   << ", errno=" << wait_errno << " (" << strerror(wait_errno) << ")"
                   << "; TCP_INFO rc=" << info_rc << ", errno=" << info_errno
                   << ", state=" << (info_rc == 0 ? int(info.tcpi_state) : -1)
                   << "; SO_ERROR rc=" << error_rc << ", errno=" << error_errno
                   << ", value=" << socket_error;
        }
        EXPECT_EQ(expected, event.events);
        EXPECT_EQ(data, event.data.u64);
    }

    void expect_quiet()
    {
        epoll_event event = {};
        EXPECT_EQ(0, epoll_wait(m_epfd, &event, 1, 0));
    }

    void receive_fin(bool buffered)
    {
        if (buffered) {
            // Observe FIN through RDHUP without consuming the preceding byte.
            // TCP_INFO alone is insufficient with a worker: CLOSE_WAIT can be
            // visible before the receive-shutdown callback finishes.
            ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLRDHUP));
            ASSERT_NO_FATAL_FAILURE(command('D'));
        }
        ASSERT_NO_FATAL_FAILURE(command('F'));
        if (buffered) {
            ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLRDHUP));
            ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, 0));
            return;
        }
        // EOF proves receive shutdown has been processed, without consuming
        // any pending epoll notification. No sleeps or packet-arrival guesses.
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        ssize_t received;
        do {
            char byte;
            received = recv(m_socket, &byte, 1, MSG_DONTWAIT);
            if (received == 0) {
                break;
            }
            ASSERT_EQ(-1, received);
            ASSERT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);
        } while (std::chrono::steady_clock::now() < deadline);
        ASSERT_EQ(0, received);
    }

    void expect_rdhup_persistent(int operation)
    {
        ASSERT_NO_FATAL_FAILURE(interest(operation, EPOLLRDHUP | EPOLLONESHOT, 10));
        epoll_event event = {};
        ASSERT_EQ(1, epoll_wait(m_epfd, &event, 1, 10000));
        ASSERT_NE(0U, event.events & EPOLLRDHUP);
        EXPECT_EQ(10U, event.data.u64);
        // MOD must reconstruct shutdown after the one-shot RDHUP was consumed.
        ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLRDHUP | EPOLLONESHOT, 11));
        event = {};
        ASSERT_EQ(1, epoll_wait(m_epfd, &event, 1, 1000));
        ASSERT_NE(0U, event.events & EPOLLRDHUP);
        EXPECT_EQ(11U, event.data.u64);
        ASSERT_EQ(0, epoll_ctl(m_epfd, EPOLL_CTL_DEL, m_socket, nullptr));
        ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_ADD, EPOLLRDHUP, 12));
        event = {};
        ASSERT_EQ(1, epoll_wait(m_epfd, &event, 1, 1000));
        ASSERT_NE(0U, event.events & EPOLLRDHUP);
        EXPECT_EQ(12U, event.data.u64);
    }

    int wait_for_timeout_event(epoll_event &event)
    {
        // Delegate mode advances TCP timers on entry to epoll_wait(). Use short
        // waits so the TCP timeout can fire within the overall 10-second deadline.
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        for (;;) {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                       deadline - std::chrono::steady_clock::now())
                                       .count();
            if (remaining <= 0) {
                return 0;
            }
            int rc = epoll_wait(m_epfd, &event, 1, remaining < 50 ? remaining : 50);
            if (rc != 0 && !(rc < 0 && errno == EINTR)) {
                return rc;
            }
        }
    }

    void handshake_timeout(bool nonblocking)
    {
        SKIP_TRUE(xlio_get_api(), "Requires XLIO external VLAN tagging");
        // As in tcp_sockopt.ti_4_ext_vlan_tag_connect_fail, send a tagged SYN
        // to an untagged listener. No firewall changes or unreachable IP guesses.
        int listener = track(sock_create());
        ASSERT_GE(listener, 0);
        ASSERT_EQ(0, bind(listener, &server_addr.addr, sizeof(server_addr)));
        ASSERT_EQ(0, listen(listener, SOMAXCONN));
        m_socket = track(nonblocking ? sock_create_nb() : sock_create());
        ASSERT_GE(m_socket, 0);
        sockaddr_store_t local = client_addr;
        sys_set_port(&local.addr, 0);
        ASSERT_EQ(0, bind(m_socket, &local.addr, sizeof(local)));
        int vlan = 1;
        ASSERT_EQ(0, setsockopt(m_socket, SOL_SOCKET, SO_XLIO_EXT_VLAN_TAG, &vlan, sizeof(vlan)));
        unsigned int timeout_ms = 1000;
        ASSERT_EQ(
            0,
            setsockopt(m_socket, IPPROTO_TCP, TCP_USER_TIMEOUT, &timeout_ms, sizeof(timeout_ms)));
        timeval limit = {10, 0};
        ASSERT_EQ(0, setsockopt(m_socket, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit)));
        m_epfd = track(epoll_create1(0));
        ASSERT_GE(m_epfd, 0);
        if (nonblocking) {
            ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_ADD, EPOLLRDHUP));
        }
        ASSERT_EQ(-1, connect(m_socket, &server_addr.addr, sizeof(server_addr)));
        ASSERT_EQ(nonblocking ? EINPROGRESS : ETIMEDOUT, errno);
        if (nonblocking) {
            epoll_event event = {};
            ASSERT_EQ(1, wait_for_timeout_event(event));
            ASSERT_NE(0U, event.events & EPOLLRDHUP);
            int error = 0;
            socklen_t len = sizeof(error);
            ASSERT_EQ(0, getsockopt(m_socket, SOL_SOCKET, SO_ERROR, &error, &len));
            ASSERT_EQ(ETIMEDOUT, error);
        }
        ASSERT_NO_FATAL_FAILURE(
            expect_rdhup_persistent(nonblocking ? EPOLL_CTL_MOD : EPOLL_CTL_ADD));
    }

    void refused_connection(uint32_t requested)
    {
        // Use loopback for refusal: unlike the connected tests below, this
        // deliberately exercises passthrough. A same-host offloaded SYN to an
        // unlistened NIC address need not receive a kernel RST. Reserve the
        // port so no external service or assumed-unused port is needed.
        int reserved = track(sock_create());
        ASSERT_GE(reserved, 0);
        sockaddr_store_t address = {};
        address.addr.sa_family = m_family;
        if (m_family == AF_INET) {
            inet_pton(AF_INET, "127.0.0.1", &address.addr4.sin_addr);
        } else {
            inet_pton(AF_INET6, "::1", &address.addr6.sin6_addr);
        }
        sys_set_port(&address.addr, 0);
        ASSERT_EQ(0, bind(reserved, &address.addr, sizeof(address)));
        socklen_t len = sizeof(address);
        ASSERT_EQ(0, getsockname(reserved, &address.addr, &len));
        m_socket = track(sock_create_nb());
        ASSERT_GE(m_socket, 0);
        sockaddr_store_t local = address;
        sys_set_port(&local.addr, 0);
        ASSERT_EQ(0, bind(m_socket, &local.addr, sizeof(local)));
        ASSERT_EQ(-1, connect(m_socket, &address.addr, len));
        ASSERT_EQ(EINPROGRESS, errno);
        m_epfd = track(epoll_create1(0));
        ASSERT_GE(m_epfd, 0);
        ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_ADD, requested));
        epoll_event event = {};
        ASSERT_EQ(1, epoll_wait(m_epfd, &event, 1, 1000));
        EXPECT_EQ(uint32_t(EPOLLERR | EPOLLHUP) | requested, event.events);
        int error = 0;
        len = sizeof(error);
        ASSERT_EQ(0, getsockopt(m_socket, SOL_SOCKET, SO_ERROR, &error, &len));
        EXPECT_EQ(ECONNREFUSED, error);
    }
};

// Replace the disabled ti_1/ti_3/ti_4 and fixed-loopback ti_2 cases with
// controlled refused connections, preserving their error-event coverage.
TEST_F(tcp_event, refused_without_interest)
{
    refused_connection(0);
}
TEST_F(tcp_event, refused_in)
{
    refused_connection(EPOLLIN);
}
TEST_F(tcp_event, refused_out)
{
    refused_connection(EPOLLOUT);
}
TEST_F(tcp_event, refused_in_out)
{
    refused_connection(EPOLLIN | EPOLLOUT);
}

// Replaces the compiled-out ti_5: the peer runs in a separate process and
// stays open until teardown, so its close cannot race the OUT assertion.
TEST_F(tcp_event, connected_out)
{
    ASSERT_NO_FATAL_FAILURE(connected_pair());
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLOUT));
}

TEST_F(tcp_event, in_level_and_mod)
{
    ASSERT_NO_FATAL_FAILURE(connected_pair());
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLIN));
    expect_quiet();
    ASSERT_NO_FATAL_FAILURE(command('D'));
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLIN));
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLIN));
    // MOD must rediscover data already queued and update the application data.
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, 0));
    expect_quiet();
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLIN, 2));
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLIN, 2));
    char byte = 0;
    ASSERT_EQ(1, recv(m_socket, &byte, 1, MSG_DONTWAIT));
    EXPECT_EQ('x', byte);
    expect_quiet();
}

TEST_F(tcp_event, out_mod)
{
    ASSERT_NO_FATAL_FAILURE(connected_pair());
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, 0));
    expect_quiet();
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLOUT, 2));
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLOUT, 2));
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLOUT, 2));
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLIN));
    expect_quiet();
}

TEST_F(tcp_event, in_out_mod)
{
    ASSERT_NO_FATAL_FAILURE(connected_pair());
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLIN));
    ASSERT_NO_FATAL_FAILURE(command('D'));
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLIN));
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLIN | EPOLLOUT));
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLIN | EPOLLOUT));
}

TEST_F(tcp_event, in_rearm)
{
    ASSERT_NO_FATAL_FAILURE(connected_pair());
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLIN));
    ASSERT_NO_FATAL_FAILURE(command('D'));
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLIN));
    for (uint32_t mode :
         {uint32_t(EPOLLET), uint32_t(EPOLLONESHOT), uint32_t(EPOLLET | EPOLLONESHOT)}) {
        SCOPED_TRACE(mode);
        ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLIN | mode));
        ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLIN));
        expect_quiet();
        ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLIN | mode, 2));
        ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLIN, 2));
        expect_quiet();
    }
}

TEST_F(tcp_event, out_rearm)
{
    ASSERT_NO_FATAL_FAILURE(connected_pair());
    for (uint32_t mode :
         {uint32_t(EPOLLET), uint32_t(EPOLLONESHOT), uint32_t(EPOLLET | EPOLLONESHOT)}) {
        SCOPED_TRACE(mode);
        ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLOUT | mode));
        ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLOUT));
        expect_quiet();
        ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLOUT | mode, 2));
        ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLOUT, 2));
        expect_quiet();
    }
}

TEST_F(tcp_event, rdhup_mod_after_fin)
{
    ASSERT_NO_FATAL_FAILURE(connected_pair());
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, 0));
    ASSERT_NO_FATAL_FAILURE(receive_fin(false));
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLRDHUP));
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLRDHUP));
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLRDHUP));
}

TEST_F(tcp_event, rdhup_mod_preserves_pending)
{
    ASSERT_NO_FATAL_FAILURE(connected_pair());
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLIN | EPOLLRDHUP));
    ASSERT_NO_FATAL_FAILURE(receive_fin(false));
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLRDHUP, 2));
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLRDHUP, 2));
}

TEST_F(tcp_event, rdhup_mod_with_buffered_data)
{
    ASSERT_NO_FATAL_FAILURE(connected_pair());
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, 0));
    ASSERT_NO_FATAL_FAILURE(receive_fin(true));
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLIN | EPOLLRDHUP));
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLIN | EPOLLRDHUP));
    char byte = 0;
    ASSERT_EQ(1, recv(m_socket, &byte, 1, MSG_DONTWAIT));
    EXPECT_EQ('x', byte);
    ASSERT_EQ(0, recv(m_socket, &byte, 1, MSG_DONTWAIT));
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLIN | EPOLLRDHUP, 2));
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLIN | EPOLLRDHUP, 2));
}

TEST_F(tcp_event, rdhup_rearm)
{
    ASSERT_NO_FATAL_FAILURE(connected_pair());
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLIN | EPOLLRDHUP));
    ASSERT_NO_FATAL_FAILURE(receive_fin(false));
    for (uint32_t mode :
         {uint32_t(EPOLLET), uint32_t(EPOLLONESHOT), uint32_t(EPOLLET | EPOLLONESHOT)}) {
        SCOPED_TRACE(mode);
        ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLIN | EPOLLRDHUP | mode));
        ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLIN | EPOLLRDHUP));
        expect_quiet();
        ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLIN | EPOLLRDHUP | mode, 2));
        ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLIN | EPOLLRDHUP, 2));
        expect_quiet();
    }
}

TEST_F(tcp_event, rdhup_not_ready_while_receive_open)
{
    ASSERT_NO_FATAL_FAILURE(connected_pair());
    ASSERT_NO_FATAL_FAILURE(command('D'));
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLIN));
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLIN));
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLRDHUP));
    expect_quiet();
    // Local write shutdown must not be mistaken for receive shutdown.
    ASSERT_EQ(0, shutdown(m_socket, SHUT_WR));
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLRDHUP));
    expect_quiet();
}

TEST_F(tcp_event, rdhup_mod_local_read_shutdown)
{
    ASSERT_NO_FATAL_FAILURE(connected_pair());
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, 0));
    ASSERT_EQ(0, shutdown(m_socket, SHUT_RD));
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLRDHUP));
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLRDHUP));
}

TEST_F(tcp_event, rdhup_add_after_fin)
{
    ASSERT_NO_FATAL_FAILURE(connected_pair());
    ASSERT_EQ(0, epoll_ctl(m_epfd, EPOLL_CTL_DEL, m_socket, nullptr));
    ASSERT_NO_FATAL_FAILURE(receive_fin(false));
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_ADD, EPOLLRDHUP));
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLRDHUP));
}

TEST_F(tcp_event, rdhup_mod_racing_fin)
{
    ASSERT_NO_FATAL_FAILURE(connected_pair());
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, 0));
    // Do not wait for the peer's acknowledgement: FIN may be processed before,
    // during, or after the interest updates (also run with worker threads).
    ASSERT_EQ(1, send(m_control, "F", 1, MSG_NOSIGNAL));
    for (uint64_t i = 1; i <= 100; ++i) {
        ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLRDHUP, i));
    }
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLRDHUP, 100));
    char response = 0;
    ASSERT_EQ(1, receive_control(m_control, response));
    ASSERT_EQ('F', response);
}

TEST_F(tcp_event, rdhup_local_read_shutdown_notification)
{
    ASSERT_NO_FATAL_FAILURE(connected_pair());
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLRDHUP));
    ASSERT_EQ(0, shutdown(m_socket, SHUT_RD));
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLRDHUP));
}

TEST_F(tcp_event, rdhup_local_full_shutdown)
{
    ASSERT_NO_FATAL_FAILURE(connected_pair());
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLIN | EPOLLRDHUP));
    ASSERT_EQ(0, shutdown(m_socket, SHUT_RDWR));
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLIN | EPOLLRDHUP | EPOLLHUP));
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLIN | EPOLLRDHUP, 2));
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLIN | EPOLLRDHUP | EPOLLHUP, 2));
}

TEST_F(tcp_event, rdhup_mod_after_reset)
{
    ASSERT_NO_FATAL_FAILURE(connected_pair());
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLRDHUP));
    ASSERT_NO_FATAL_FAILURE(command('R'));
    epoll_event event = {};
    ASSERT_EQ(1, epoll_wait(m_epfd, &event, 1, 1000));
    ASSERT_NE(0U, event.events & EPOLLRDHUP);
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLRDHUP, 2));
    ASSERT_EQ(1, epoll_wait(m_epfd, &event, 1, 1000));
    // Focus on RDHUP reconstruction; ERR/HUP reconstruction is independent.
    EXPECT_NE(0U, event.events & EPOLLRDHUP);
    EXPECT_EQ(2U, event.data.u64);
}

TEST_F(tcp_event, reset_mod_in_out_notifies)
{
    SKIP_TRUE(xlio_get_api(), "Checks XLIO's current reset event mask");
    ASSERT_NO_FATAL_FAILURE(connected_pair());
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLRDHUP | EPOLLET | EPOLLONESHOT));
    ASSERT_NO_FATAL_FAILURE(command('R'));
    epoll_event event = {};
    ASSERT_EQ(1, epoll_wait(m_epfd, &event, 1, 10000));
    ASSERT_NE(0U, event.events & EPOLLRDHUP);
    // ET consumes the queued terminal flags; leave the socket error pending.
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLIN | EPOLLOUT, 2));
    // This exact mask verifies the current implementation. Once MR#5431605 is
    // fixed, update the expected mask to include the reconstructed terminal events
    // so this test passes with the corrected behavior.
    ASSERT_NO_FATAL_FAILURE(expect_events(EPOLLIN | EPOLLOUT, 2));
    char byte = 0;
    ASSERT_EQ(-1, recv(m_socket, &byte, 1, MSG_DONTWAIT));
    EXPECT_EQ(ECONNRESET, errno);
}

TEST_F(tcp_event, rdhup_worker_rejected_reconnect)
{
    // Run this test only in worker-thread mode. After SHUT_RDWR, worker mode
    // rejects connect() while preserving the socket's receive-shutdown state.
    // R2C instead tears down TCP resources on this unsupported reconnect, so a
    // subsequent EPOLL_CTL_MOD can fail with ENOENT, independently of RDHUP.
    // CI excludes this test from broad R2C runs. When running gtest directly
    // in R2C mode, exclude it with --gtest_filter. Worker mode can also be
    // configured through JSON.
    ASSERT_NO_FATAL_FAILURE(connected_pair());
    ASSERT_EQ(0, shutdown(m_socket, SHUT_RDWR));
    ASSERT_EQ(-1, connect(m_socket, &server_addr.addr, sizeof(server_addr)));
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLRDHUP));
    epoll_event event = {};
    ASSERT_EQ(1, epoll_wait(m_epfd, &event, 1, 1000));
    EXPECT_NE(0U, event.events & EPOLLRDHUP);
}

TEST_F(tcp_event, rdhup_nonblocking_handshake_timeout)
{
    ASSERT_NO_FATAL_FAILURE(handshake_timeout(true));
}

TEST_F(tcp_event, rdhup_blocking_handshake_timeout)
{
    ASSERT_NO_FATAL_FAILURE(handshake_timeout(false));
}

TEST_F(tcp_event, rdhup_established_timeout)
{
    SKIP_TRUE(xlio_get_api(), "Requires an XLIO peer whose TCP progress can be paused");
    ASSERT_NO_FATAL_FAILURE(connected_pair());
    unsigned int timeout_ms = 1000;
    ASSERT_EQ(0,
              setsockopt(m_socket, IPPROTO_TCP, TCP_USER_TIMEOUT, &timeout_ms, sizeof(timeout_ms)));
    ASSERT_NO_FATAL_FAILURE(interest(EPOLL_CTL_MOD, EPOLLRDHUP));
    // Stop every peer thread so the next byte remains unacknowledged.
    // TearDown resumes the peer even on assertion failure.
    ASSERT_EQ(0, kill(m_child, SIGSTOP));
    m_peer_stopped = true;
    int status = 0;
    ASSERT_EQ(m_child, waitpid(m_child, &status, WUNTRACED));
    ASSERT_TRUE(WIFSTOPPED(status));
    ASSERT_EQ(1, send(m_socket, "x", 1, MSG_NOSIGNAL));
    epoll_event event = {};
    ASSERT_EQ(1, wait_for_timeout_event(event));
    ASSERT_NE(0U, event.events & EPOLLRDHUP);
    int error = 0;
    socklen_t len = sizeof(error);
    ASSERT_EQ(0, getsockopt(m_socket, SOL_SOCKET, SO_ERROR, &error, &len));
    ASSERT_EQ(ETIMEDOUT, error);
    ASSERT_NO_FATAL_FAILURE(expect_rdhup_persistent(EPOLL_CTL_MOD));
}
