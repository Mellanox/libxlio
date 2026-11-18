/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/*
 * RM 5397559: exercise real accept queues, rather than only the wait-result map.
 * Run with libxlio preloaded and --addr=<client mlx5 IP>,<server mlx5 IP>.
 * Select XLIO configuration before launching gtest: exclude *wt_only* in R2C
 * runs and *r2c_only* in WT runs. Tests never change XLIO configuration.
 * A child isolates SIGINT's persistent XLIO exit flag from subsequent tests.
 * The addresses must be local, non-loopback IPv4 addresses with an offloadable
 * path between them (the same local mlx5 address works on supported hardware).
 * The TCP client is a separate process, as in the other fork-based TCP gtests;
 * it must not share the listener's process and XLIO resources. No fixed ports,
 * external client, or sleeps are required.
 *
 * For prequeued cases, EPOLLIN proves that the handshake reached the listener.
 * Readiness checks do not harvest worker child queues; only accept does. Thus
 * SIGINT precedes either a parent-queue accept (R2C) or the first child harvest
 * (worker mode). A raw kernel poll must report no connection, preventing a
 * silently passing kernel fallback from masquerading as XLIO coverage.
 *
 * Blocked cases use the same libiomux_wait_hook.so as iomux_wakeup.cc. It sits
 * AFTER XLIO in LD_PRELOAD. The next blocking OS epoll wait on the accept thread
 * starts the client, then returns normally before the callback raises SIGINT.
 * This places exit after accept's initial empty-queue check, but before its
 * post-wait predicate can harvest the child queue. The empty blocked control
 * waits for an OS wakeup or SO_RCVTIMEO expiry, then raises SIGINT at that boundary;
 * it must return EINTR, not timeout/EAGAIN. The helper fabricates no events.
 *
 * The queued R2C, queued worker, and blocked worker cases respectively protect
 * the final accept_helper exit guard and the two distinct exit-path harvests.
 * Build with make -C tests/gtest. For blocked cases, the caller must preload
 * the helper after XLIO before starting gtest:
 *   LD_PRELOAD=<libxlio.so>:<gtest-build-dir>/.libs/libiomux_wait_hook.so
 * Filter tcp_accept_shutdown.* together with the appropriate mode exclusion.
 * Missing XLIO/helper or unspecified/loopback/non-IPv4 addresses
 * cause a skip; a configured path that fails to offload fails the test.
 */

#include <dlfcn.h>
#include <functional>
#include <memory>
#include <sys/syscall.h>

#include "common/def.h"
#include "common/log.h"
#include "common/cmn.h"
#include "common/base.h"
#include "xlio_extra.h"

namespace {
using arm_block_t = void (*)(void (*)(), void (*)(int));
std::function<void()> before_block;
std::function<void(int)> after_block;
volatile sig_atomic_t got_sigint;

void on_sigint(int)
{
    got_sigint = 1;
}
void before_callback()
{
    before_block();
}
void after_callback(int rc)
{
    after_block(rc);
}

// Raw syscalls keep test coordination independent of XLIO's shutdown flag.
class gate {
public:
    gate()
        : fd(eventfd(0, EFD_CLOEXEC))
    {
    }
    ~gate() { close(fd); }
    bool notify()
    {
        uint64_t value = 1;
        return syscall(SYS_write, fd, &value, sizeof(value)) == sizeof(value);
    }
    bool wait()
    {
        pollfd pfd = {fd, POLLIN, 0};
        int rc;
        do {
            timespec timeout = {5, 0};
            rc = syscall(SYS_ppoll, &pfd, 1, &timeout, nullptr, 0);
        } while (rc < 0 && errno == EINTR);
        uint64_t value;
        return rc == 1 && syscall(SYS_read, fd, &value, sizeof(value)) == sizeof(value);
    }
    int fd;
};

class client_connection {
public:
    client_connection(const sockaddr_in &source, const sockaddr_in &destination)
        : pid(test_base::fork_child([this, source, destination]() {
            if (!start.wait()) {
                ADD_FAILURE() << "Client was not released by the accept test";
                return;
            }
            int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            EXPECT_LE(0, fd);
            int rc = bind(fd, reinterpret_cast<const sockaddr *>(&source), sizeof(source));
            EXPECT_EQ(0, rc) << "client bind errno=" << errno;
            if (rc == 0) {
                rc = connect(fd, reinterpret_cast<const sockaddr *>(&destination),
                             sizeof(destination));
                if (rc < 0 && errno == EINPROGRESS) {
                    pollfd pfd = {fd, POLLOUT, 0};
                    rc = poll(&pfd, 1, 5000);
                    EXPECT_EQ(1, rc) << "client connect poll errno=" << errno;
                    int error = -1;
                    socklen_t len = sizeof(error);
                    EXPECT_EQ(0, getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len));
                    EXPECT_EQ(0, error);
                } else {
                    EXPECT_EQ(0, rc) << "client connect errno=" << errno;
                }
            }
            EXPECT_TRUE(connected.notify());
            EXPECT_TRUE(finish.wait());
            close(fd);
        }))
    {
        EXPECT_LT(0, pid);
    }
    ~client_connection()
    {
        start.notify();
        finish.notify();
        if (pid > 0) {
            EXPECT_EQ(0, test_base::wait_fork(pid));
        }
    }
    gate start;
    gate connected;
    gate finish;

private:
    pid_t pid;
};
} // namespace

class tcp_accept_shutdown : public testing::Test {
protected:
    void run(bool queued, bool blocked)
    {
        const auto &client = gtest_conf.client_addr.addr4;
        const auto &server = gtest_conf.server_addr.addr4;
        if (client.sin_family != AF_INET || server.sin_family != AF_INET ||
            client.sin_addr.s_addr == INADDR_ANY || server.sin_addr.s_addr == INADDR_ANY ||
            (ntohl(client.sin_addr.s_addr) >> 24) == 127 ||
            (ntohl(server.sin_addr.s_addr) >> 24) == 127) {
            GTEST_SKIP() << "Requires --addr=<client mlx5 IPv4>,<server mlx5 IPv4>";
        }
        auto api = xlio_get_api();
        if (!api) {
            GTEST_SKIP() << "Requires libxlio preloaded";
        }
        auto arm =
            reinterpret_cast<arm_block_t>(dlsym(RTLD_DEFAULT, "iomux_arm_blocking_wait_hook"));
        if (blocked && !arm) {
            GTEST_SKIP() << "Preload libiomux_wait_hook.so after libxlio.so before launching gtest";
        }
        pid_t pid = test_base::fork_child([&]() {
            alarm(20);
            exercise(queued, blocked, arm);
        });
        ASSERT_LE(0, pid);
        EXPECT_EQ(0, test_base::wait_fork(pid));
    }

    void exercise(bool queued, bool blocked, arm_block_t arm)
    {
        sockaddr_in address = gtest_conf.server_addr.addr4;
        address.sin_port = 0;
        int listener = socket(AF_INET, SOCK_STREAM, 0);
        ASSERT_LE(0, listener);
        ASSERT_EQ(0, bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)));
        ASSERT_EQ(0, listen(listener, 8));
        socklen_t len = sizeof(address);
        ASSERT_EQ(0, getsockname(listener, reinterpret_cast<sockaddr *>(&address), &len));
        timeval timeout = {queued ? 5 : 0, queued ? 0 : 100000};
        ASSERT_EQ(0, setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
        int epfd = epoll_create1(EPOLL_CLOEXEC);
        ASSERT_LE(0, epfd);
        epoll_event event = {};
        event.events = EPOLLIN;
        event.data.fd = listener;
        ASSERT_EQ(0, epoll_ctl(epfd, EPOLL_CTL_ADD, listener, &event));
        struct sigaction action = {};
        action.sa_handler = on_sigint;
        sigemptyset(&action.sa_mask);
        ASSERT_EQ(0, sigaction(SIGINT, &action, nullptr));

        sockaddr_in source = gtest_conf.client_addr.addr4;
        source.sin_port = 0;
        std::unique_ptr<client_connection> client;
        if (queued) {
            client.reset(new client_connection(source, address));
        }
        auto check_ready = [&]() {
            ASSERT_EQ(1, epoll_wait(epfd, &event, 1, 5000)) << "listener readiness errno=" << errno;
            ASSERT_EQ(listener, event.data.fd);
            ASSERT_TRUE(event.events & EPOLLIN);
            pollfd kernel_fd = {listener, POLLIN, 0};
            timespec zero_timeout = {};
            ASSERT_EQ(0, syscall(SYS_ppoll, &kernel_fd, 1, &zero_timeout, nullptr, 0))
                << "Connection reached the kernel listener, not XLIO's accept queue";
            ASSERT_TRUE(client->connected.wait());
        };
        bool entered_wait = false;
        bool returned_wait = false;
        if (blocked) {
            before_block = [&]() {
                entered_wait = true;
                if (client) {
                    EXPECT_TRUE(client->start.notify());
                }
            };
            after_block = [&](int rc) {
                returned_wait = true;
                if (queued) {
                    EXPECT_LT(0, rc);
                    check_ready();
                } else {
                    EXPECT_LE(0, rc); // Empty wakeup or timeout, followed by shutdown.
                }
                EXPECT_EQ(0, raise(SIGINT));
            };
            arm(before_callback, after_callback);
        } else {
            if (client) {
                ASSERT_TRUE(client->start.notify());
                check_ready();
                ASSERT_FALSE(testing::Test::HasFailure());
            }
            ASSERT_EQ(0, raise(SIGINT));
        }

        errno = 0;
        int accepted = accept(listener, nullptr, nullptr);
        int accept_errno = errno;
        if (blocked) {
            EXPECT_TRUE(entered_wait);
            EXPECT_TRUE(returned_wait);
        }
        EXPECT_EQ(1, got_sigint);
        if (queued) {
            EXPECT_LE(0, accepted) << "accept errno=" << accept_errno;
            if (accepted >= 0) {
                sockaddr_in peer = {};
                len = sizeof(peer);
                EXPECT_EQ(0, getpeername(accepted, reinterpret_cast<sockaddr *>(&peer), &len));
                EXPECT_EQ(source.sin_addr.s_addr, peer.sin_addr.s_addr);
                close(accepted);
            }
        } else {
            EXPECT_EQ(-1, accepted);
            EXPECT_EQ(EINTR, accept_errno);
        }
        client.reset();
        close(epfd);
        close(listener);
    }
};

TEST_F(tcp_accept_shutdown, parent_queue_survives_sigint_r2c_only)
{
    run(true, false);
}
TEST_F(tcp_accept_shutdown, worker_child_queue_survives_sigint_wt_only)
{
    run(true, false);
}
TEST_F(tcp_accept_shutdown, blocked_worker_accept_survives_sigint_wt_only)
{
    run(true, true);
}
TEST_F(tcp_accept_shutdown, empty_parent_queue_returns_eintr_r2c_only)
{
    run(false, false);
}
TEST_F(tcp_accept_shutdown, empty_worker_queue_returns_eintr_wt_only)
{
    run(false, false);
}
TEST_F(tcp_accept_shutdown, blocked_empty_worker_accept_returns_eintr_wt_only)
{
    run(false, true);
}
