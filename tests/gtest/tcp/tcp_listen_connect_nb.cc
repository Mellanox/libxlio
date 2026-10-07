/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2022-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#include "tcp_base.h"
#include <chrono>
#include <vector>

class tcp_listen_connect_nb : public tcp_base {};

/**
 * @test tcp_listen_connect_nb.server_client_nb
 * @brief
 *    Non-blocking TCP server/client connection establishment
 *
 * @details
 *    This test validates non-blocking socket operations :
 *    - Server/client non-blocking socket creation and connection establishment
 *    - Data exchange using peer_wait() mechanism
 *    - Proper cleanup and synchronization in forked processes
 */
TEST_F(tcp_listen_connect_nb, server_client_nb)
{
    int pid = fork();

    if (0 == pid) { // Child
        int fd, rc;
        int optval;
        socklen_t optlen;

        barrier_fork(pid);

        fd = tcp_base::sock_create_nb();
        EXPECT_LE_ERRNO(0, fd);
        if (fd <= 0) {
            goto child_error;
        }

        rc = bind(fd, &client_addr.addr, sizeof(client_addr));
        EXPECT_EQ_ERRNO(0, rc);
        if (rc != 0) {
            goto child_cleanup;
        }

        rc = connect(fd, &server_addr.addr, sizeof(server_addr));
        EXPECT_EQ(EINPROGRESS, errno);
        EXPECT_EQ((-1), rc);
        if (rc != -1 || errno != EINPROGRESS) {
            goto child_cleanup;
        }

        rc = wait_for_event(fd, EPOLLOUT);
        if (rc <= 0) {
            goto child_cleanup;
        }

        // Verify connection is established using getsockopt
        optval = 0;
        optlen = sizeof(optval);
        rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &optval, &optlen);
        EXPECT_EQ(0, rc);
        EXPECT_EQ(0, optval);
        if (rc != 0 || optval != 0) {
            goto child_cleanup;
        }

        log_trace("Established connection: fd=%d to %s from %s\n", fd, SOCK_STR(server_addr),
                  SOCK_STR(client_addr));
        peer_wait(fd);

    child_cleanup:
        close(fd);
    child_error:
        // This exit is very important, otherwise the fork
        // keeps running and may duplicate other tests.
        exit(testing::Test::HasFailure());
    } else { // Parent
        int l_fd, rc, fd;
        sockaddr_store_t peer_addr;
        struct sockaddr *ppeer;
        socklen_t socklen;
        char buffer[64];
        ssize_t bytes_read;

        l_fd = tcp_base::sock_create_nb();
        EXPECT_LE_ERRNO(0, l_fd);
        if (l_fd < 0) {
            goto parent_error;
        }

        rc = bind(l_fd, &server_addr.addr, sizeof(server_addr));
        EXPECT_EQ_ERRNO(0, rc);
        if (rc != 0) {
            goto parent_cleanup;
        }

        rc = listen(l_fd, 5);
        EXPECT_EQ_ERRNO(0, rc);
        if (rc != 0) {
            goto parent_cleanup;
        }

        barrier_fork(pid);

        rc = wait_for_event(l_fd, EPOLLIN);
        if (rc <= 0) {
            goto parent_cleanup;
        }

        fd = -1;
        ppeer = &peer_addr.addr;
        socklen = sizeof(peer_addr);
        memset(&peer_addr, 0, socklen);
        fd = accept(l_fd, ppeer, &socklen);
        EXPECT_LE_ERRNO(0, fd);
        if (fd < 0) {
            goto parent_cleanup;
        }

        log_trace("Accepted connection: fd=%d from %s\n", fd, SOCK_STR(ppeer));

        // Read data from client (peer_wait sends multiple 1-byte messages)
        rc = wait_for_event(fd, EPOLLIN);

        bytes_read = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);
        EXPECT_GT(bytes_read, 0);
        if (bytes_read > 0) {
            EXPECT_EQ(1, buffer[0]);
        }

        close(fd);

    parent_cleanup:
        close(l_fd);
    parent_error:
        EXPECT_EQ(0, wait_fork(pid));
    }
}

/**
 * @test tcp_listen_connect_nb.rss_accept_progress
 * @brief Accept continues to make progress while worker threads finish handshakes.
 */
TEST_F(tcp_listen_connect_nb, rss_accept_progress)
{
    using clock = std::chrono::steady_clock;
    constexpr unsigned int connections = 512;

    // Give the server its own process so a deadlocked accept() can be stopped
    // by the client, without hanging the rest of the gtest executable.
    const int pid = fork();
    ASSERT_LE(0, pid);
    if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);

        // Listen on the fixture address before releasing the client barrier.
        const int listener = sock_create_nb();
        EXPECT_LE(0, listener);
        bool ready = listener >= 0;
        if (ready) {
            int rc = bind(listener, &server_addr.addr, sizeof(server_addr));
            EXPECT_EQ_ERRNO(0, rc);
            ready = rc == 0;
        }
        if (ready) {
            int rc = listen(listener, 128);
            EXPECT_EQ_ERRNO(0, rc);
            ready = rc == 0;
        }
        barrier_fork(pid, true);

        // Busy-harvest accepted sockets while the workers finish handshakes.
        // Before the fix, these paths take the parent/child locks in opposite
        // orders and can deadlock even though the listener is non-blocking.
        std::vector<int> accepted;
        const auto deadline = clock::now() + std::chrono::seconds(30);
        while (ready && accepted.size() < connections && clock::now() < deadline) {
            const int fd = accept(listener, nullptr, nullptr);
            if (fd >= 0) {
                accepted.push_back(fd);
                const char acknowledgement = 1;
                EXPECT_EQ_ERRNO(1, send(fd, &acknowledgement, 1, MSG_NOSIGNAL));
            } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                ADD_FAILURE() << "accept: " << strerror(errno);
                break;
            }
        }
        EXPECT_EQ(connections, accepted.size());

        // Retain every accepted socket until the workload finishes, avoiding
        // tuple reuse and the independent stale-flow-tag reconnect issue.
        for (const int fd : accepted) {
            close(fd);
        }
        if (listener >= 0) {
            close(listener);
        }
        exit(testing::Test::HasFailure());
    }

    // Connect from the fixture's source address, using a new live tuple for
    // each handshake. No XLIO settings are changed by the test.
    barrier_fork(pid, true);
    sockaddr_store_t source = client_addr;
    sys_set_port(&source.addr, 0);
    std::vector<int> clients;
    unsigned int acknowledged = 0;
    const auto deadline = clock::now() + std::chrono::seconds(30);
    for (unsigned int i = 0; i < connections && clock::now() < deadline; ++i) {
        const int fd = sock_create_nb();
        EXPECT_LE(0, fd);
        if (fd < 0) {
            break;
        }
        clients.push_back(fd);
        int rc = bind(fd, &source.addr, sizeof(source));
        EXPECT_EQ_ERRNO(0, rc);
        if (rc != 0) {
            break;
        }
        rc = connect(fd, &server_addr.addr, sizeof(server_addr));
        if (rc != 0 && errno != EINPROGRESS) {
            ADD_FAILURE() << "connect: " << strerror(errno);
            break;
        }

        // Require a byte from the accepted peer: connect readiness alone does
        // not prove the application's accept() completed. Polling also drives
        // receive progress and delegated timers in configurations without workers.
        char acknowledgement = 0;
        ssize_t received = -1;
        while (clock::now() < deadline) {
            pollfd event = {fd, POLLIN, 0};
            rc = poll(&event, 1, 0);
            if (rc < 0 && errno == EINTR) {
                continue;
            }
            if (rc < 0 || (event.revents & POLLNVAL)) {
                ADD_FAILURE() << "poll: " << strerror(errno);
                break;
            }
            if (rc > 0) {
                received = recv(fd, &acknowledgement, 1, MSG_DONTWAIT);
                if (received >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
                    break;
                }
            }
        }
        EXPECT_EQ(1, received) << "Connection " << i << " was not accepted before the deadline";
        EXPECT_EQ(1, acknowledgement);
        if (received != 1 || acknowledgement != 1) {
            break;
        }
        ++acknowledged;
    }
    EXPECT_EQ(connections, acknowledged);

    // Kill a stalled server before reaping it, then release all client tuples.
    // The old lock inversion cannot be interrupted by the server's own deadline.
    if (acknowledged != connections || testing::Test::HasFailure()) {
        kill(pid, SIGKILL);
    }
    EXPECT_EQ(0, wait_fork(pid));
    for (const int fd : clients) {
        close(fd);
    }
}
