/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"

#include "tcp_base.h"

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

class tcp_connect_nb : public tcp_base {};

/**
 * @test tcp_connect_nb.ti_1
 * @brief
 *    Loop of blocking connect() to ip on the same node
 * @details
 */
TEST_F(tcp_connect_nb, ti_1)
{
}

/**
 * A failed asynchronous connect must publish its error before SO_ERROR can
 * consume it. The timeout/RST callback announces readiness while holding the
 * connection lock, before storing the terminal error (RM 5324363). Concurrent
 * SO_ERROR consumers must also read and clear each error exactly once.
 *
 * The second application thread drives receive processing in R2C; workers do
 * that in threads mode. No child process or XLIO configuration is needed.
 * Run with socket locks enabled; CI excludes this test from delegated-timer runs.
 */
TEST_F(tcp_connect_nb, so_error_connect_completion)
{
    // Use the fixture's addresses and ephemeral ports, leaving the current
    // XLIO configuration unchanged and avoiding fixed-port conflicts.
    using clock = std::chrono::steady_clock;
    const unsigned int connections = 256;
    sockaddr_store_t peer = server_addr;
    sockaddr_store_t local = client_addr;
    sys_set_port(&peer.addr, 0);
    sys_set_port(&local.addr, 0);

    // Reserve a port without listening: a SYN is either refused or times out,
    // and no server can accidentally turn this into a successful connection.
    const int reserved = sock_create();
    ASSERT_LE(0, reserved);
    int rc = bind(reserved, &peer.addr, sizeof(peer));
    socklen_t peer_length = sizeof(peer);
    if (rc == 0) {
        rc = getsockname(reserved, &peer.addr, &peer_length);
    }
    if (rc != 0) {
        const int error = errno;
        close(reserved);
        FAIL() << "Port reservation: " << strerror(error);
    }
    // Create an epoll instance to observe each asynchronous connect's completion.
    const int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        close(reserved);
        FAIL() << "epoll_create1: " << strerror(errno);
    }

    // Start nonblocking connects to the reserved port. Register each socket
    // before connecting so even an immediate refusal is observed; use a short
    // TCP user timeout to bound connects whose SYN receives no response.
    std::vector<pollfd> clients;
    std::vector<bool> checked(connections, false);
    for (unsigned int i = 0; i < connections; ++i) {
        const int fd = sock_create_nb();
        if (fd < 0) {
            ADD_FAILURE() << "socket: " << strerror(errno);
            break;
        }
        clients.push_back({fd, POLLIN | POLLOUT, 0});
        const unsigned int timeout_ms = 1;
        rc = setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &timeout_ms, sizeof(timeout_ms));
        if (rc == 0) {
            rc = bind(fd, &local.addr, sizeof(local));
        }
        epoll_event event = {};
        event.events = EPOLLIN | EPOLLOUT;
        event.data.u32 = i;
        if (rc == 0) {
            rc = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event);
        }
        if (rc != 0) {
            ADD_FAILURE() << "Socket setup: " << strerror(errno);
            break;
        }
        rc = connect(fd, &peer.addr, peer_length);
        if (rc != -1 || errno != EINPROGRESS) {
            ADD_FAILURE() << "Expected asynchronous connect, rc=" << rc << " errno=" << errno;
            break;
        }
    }

    // Several consumers must not receive the same nonzero SO_ERROR. This
    // also exercises the missing lock without relying on the tiny interval
    // between the callback's state and error stores or on optional debug logs.
    const unsigned int readers = 32;
    pthread_barrier_t ready;
    const int barrier_rc = pthread_barrier_init(&ready, nullptr, readers);
    if (barrier_rc != 0) {
        for (const auto &client : clients) {
            close(client.fd);
        }
        close(epfd);
        close(reserved);
        FAIL() << "pthread_barrier_init: " << strerror(barrier_rc);
    }
    std::vector<std::vector<int>> errors(readers, std::vector<int>(clients.size(), -1));
    std::vector<std::thread> threads;
    // Release all readers together for each socket and record their SO_ERROR
    // results separately, making concurrent read-and-clear operations overlap.
    for (unsigned int reader = 0; reader < readers; ++reader) {
        threads.emplace_back([&, reader]() {
            for (unsigned int i = 0; i < clients.size(); ++i) {
                pthread_barrier_wait(&ready);
                socklen_t length = sizeof(int);
                if (getsockopt(clients[i].fd, SOL_SOCKET, SO_ERROR, &errors[reader][i], &length) !=
                        0 ||
                    length != sizeof(int)) {
                    errors[reader][i] = -1;
                }
            }
        });
    }
    // Wait until every reader finishes before inspecting results or destroying
    // the barrier shared by the reader threads.
    for (auto &thread : threads) {
        thread.join();
    }
    pthread_barrier_destroy(&ready);
    // Check that EINPROGRESS and the eventual terminal error are each consumed
    // at most once. Remember terminal errors already consumed by these readers
    // so the later completion check expects zero for those sockets.
    std::vector<unsigned int> terminal_errors(clients.size(), 0);
    for (unsigned int i = 0; i < clients.size(); ++i) {
        unsigned int in_progress = 0;
        for (unsigned int reader = 0; reader < readers; ++reader) {
            const int error = errors[reader][i];
            EXPECT_TRUE(error == 0 || error == EINPROGRESS || error == ETIMEDOUT ||
                        error == ECONNREFUSED)
                << "Connection " << i << ": unexpected SO_ERROR: " << error;
            in_progress += error == EINPROGRESS;
            terminal_errors[i] += error == ETIMEDOUT || error == ECONNREFUSED;
        }
        EXPECT_LE(in_progress, 1U) << "Connection " << i << ": EINPROGRESS consumed more than once";
        EXPECT_LE(terminal_errors[i], 1U)
            << "Connection " << i << ": terminal error consumed more than once";
    }

    // Drive receive processing in a separate application thread for R2C.
    // In threads mode XLIO's workers perform that processing; the same polling
    // loop remains valid without selecting a different configuration.
    const auto deadline = clock::now() + std::chrono::seconds(15);
    std::atomic<bool> stop {false};
    std::atomic<int> progress_error {0};
    std::thread progress([&]() {
        while (!stop && clock::now() < deadline) {
            if (poll(clients.data(), clients.size(), 0) < 0 && errno != EINTR) {
                progress_error = errno;
                break;
            }
            std::this_thread::yield();
        }
    });

    // Drain all connect completions, even after an earlier assertion failed,
    // so normal cleanup closes sockets after their connect jobs have finished.
    unsigned int completed = 0;
    while (completed < clients.size() && clock::now() < deadline) {
        epoll_event event = {};
        rc = epoll_wait(epfd, &event, 1, 0);
        if (rc < 0 && errno != EINTR) {
            ADD_FAILURE() << "epoll_wait: " << strerror(errno);
            break;
        }
        if (rc > 0) {
            const unsigned int i = event.data.u32;
            if (i >= clients.size() || checked[i]) {
                ADD_FAILURE() << "Unexpected/duplicate completion: " << i;
                break;
            }
            checked[i] = true;
            // After readiness, SO_ERROR must contain the terminal error unless
            // a reader already consumed it. EINPROGRESS here would be stale.
            int error = -1;
            socklen_t error_length = sizeof(error);
            rc = getsockopt(clients[i].fd, SOL_SOCKET, SO_ERROR, &error, &error_length);
            EXPECT_EQ(0, rc);
            EXPECT_EQ(sizeof(error), error_length);
            if (terminal_errors[i] == 0) {
                EXPECT_TRUE(error == ECONNREFUSED || error == ETIMEDOUT)
                    << "Connection " << i << ": SO_ERROR after readiness: " << strerror(error);
            } else {
                EXPECT_EQ(0, error) << "Connection " << i << ": terminal error returned again";
            }
            // A second read must return zero. Remove the completed socket from
            // epoll so its persistent error/hangup readiness is not counted again.
            error = -1;
            error_length = sizeof(error);
            rc = getsockopt(clients[i].fd, SOL_SOCKET, SO_ERROR, &error, &error_length);
            EXPECT_EQ(0, rc);
            EXPECT_EQ(0, error) << "SO_ERROR must consume the terminal error exactly once";
            EXPECT_EQ(0, epoll_ctl(epfd, EPOLL_CTL_DEL, clients[i].fd, nullptr));
            ++completed;
        } else {
            std::this_thread::yield();
        }
    }
    // Stop and join the progress thread before closing any descriptor it polls.
    stop = true;
    progress.join();
    // No descriptor can close or be reused while the progress thread polls it.
    for (const auto &client : clients) {
        close(client.fd);
    }
    // Release the epoll instance and reserved port, then verify that polling
    // succeeded and every requested connection reached completion.
    close(epfd);
    close(reserved);
    EXPECT_EQ(0, progress_error.load());
    EXPECT_EQ(connections, completed);
}
