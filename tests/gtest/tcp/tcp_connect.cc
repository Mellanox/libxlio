/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-3-Clause
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

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "src/core/util/sock_addr.h"
#include <list>
#include <algorithm>
#include "tcp_base.h"

class tcp_connect : public tcp_base {};

/**
 * @test tcp_connect.ti_1
 * @brief
 *    Loop of blocking connect() to ip on the same node
 * @details
 */
TEST_F(tcp_connect, DISABLED_ti_1)
{
    int rc = EOK;
    int fd;
    int i;

    fd = socket(m_family, SOCK_STREAM, IPPROTO_IP);
    ASSERT_LE(0, fd);

    rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
    ASSERT_EQ(EOK, errno);
    ASSERT_EQ(0, rc);

    for (i = 0; i < 10; i++) {
        rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_TRUE(ECONNREFUSED == errno) << "connect() attempt = " << i;
        ASSERT_EQ((-1), rc) << "connect() attempt = " << i;
        usleep(500);
    }

    close(fd);
}

/**
 * @test tcp_connect.ti_2
 * @brief
 *    Loop of blocking connect() to remote ip
 * @details
 */
TEST_F(tcp_connect, DISABLED_ti_2)
{
    int rc = EOK;
    int fd;
    int i;

    fd = socket(m_family, SOCK_STREAM, IPPROTO_IP);
    ASSERT_LE(0, fd);

    rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
    ASSERT_EQ(EOK, errno);
    ASSERT_EQ(0, rc);

    for (i = 0; i < 10; i++) {
        rc = connect(fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
        ASSERT_TRUE(ECONNREFUSED == errno || ETIMEDOUT == errno) << "connect() attempt = " << i;
        ASSERT_EQ((-1), rc) << "connect() attempt = " << i;
        usleep(500);
        if (ETIMEDOUT == errno) {
            log_warn("Routing issue, consider another remote address instead of %s\n",
                     sys_addr2str((struct sockaddr *)&remote_addr));
            break;
        }
    }

    close(fd);
}

/**
 * @test tcp_connect.ti_3
 * @brief
 *    Loop of blocking connect() to unreachable ip
 * @details
 */
TEST_F(tcp_connect, DISABLED_ti_3)
{
    int rc = EOK;
    int fd;
    int i;

    fd = socket(m_family, SOCK_STREAM, IPPROTO_IP);
    ASSERT_LE(0, fd);

    rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
    ASSERT_EQ(EOK, errno);
    ASSERT_EQ(0, rc);

    for (i = 0; i < 10; i++) {
        rc = connect(fd, (struct sockaddr *)&bogus_addr, sizeof(bogus_addr));
        ASSERT_EQ(EHOSTUNREACH, errno) << "connect() attempt = " << i;
        ASSERT_EQ((-1), rc) << "connect() attempt = " << i;
        usleep(500);
    }

    close(fd);
}

/**
 * @test tcp_connect.ti_4_rto_racing
 * @brief
 *    Loop of blocking connect() to unreachable ip
 * @details
 */
TEST_F(tcp_connect, ti_4_rto_racing)
{
    SKIP_TRUE(!getenv("XLIO_SOCKETXTREME"), "Skip Socketxtreme");

    int pid = fork();

    if (0 == pid) { /* I am the child */
        int lfd = tcp_base::sock_create();
        EXPECT_LE(0, lfd);
        if (lfd > 0) {
            int rc = bind(lfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            EXPECT_EQ(0, rc);
            if (rc == 0) {
                rc = listen(lfd, 1024);
                EXPECT_EQ(0, rc);
                if (rc == 0) {
                    barrier_fork(pid, true);

                    int fd = accept(lfd, nullptr, nullptr);
                    EXPECT_LE(0, fd);
                    if (fd > 0) {
                        // Force RST on close -> Prevent socket to enter TIME_WAIT without XLIO.
                        struct linger sl = {1, 0};
                        setsockopt(fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
                        close(fd);
                    }
                }
            }

            close(lfd);
        }

        // This exit is very important, otherwise the fork
        // keeps running and may duplicate other tests.
        exit(testing::Test::HasFailure());
    } else { /* I am the parent */
        auto connect_fn = [this](const sockaddr_store_t &server_addr_in, std::list<int> &fns,
                                 int rts) -> int {
            int fd = tcp_base::sock_create();
            EXPECT_LE(0, fd);
            if (fd <= 0) {
                return fd;
            }

            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            int rc = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            EXPECT_EQ(0, rc);
            if (rc != 0) {
                close(fd);
                return -1;
            }

            log_trace("Connecting...\n");
            while (--rts >= 0) {
                log_trace("Connecting... %d\n", rts);
                rc = connect(fd, reinterpret_cast<const sockaddr *>(&server_addr_in),
                             sizeof(server_addr_in));

                if (0 == rc) {
                    fns.push_back(fd);
                    log_trace("Connected %zu sockets.\n", fns.size());
                    return fd;
                }

                sleep(3);
            }

            close(fd);
            return -1;
        };

        std::list<int> fns;

        barrier_fork(pid, true);

        int retries = 2;
        while (connect_fn(server_addr, fns, 2) > 0 || --retries > 0) {
            ;
        }

        ASSERT_EQ(0, wait_fork(pid));

        std::for_each(std::begin(fns), std::end(fns), [](int fd) { EXPECT_EQ(0, close(fd)); });
    }

    sleep(1U); // XLIO timers to clean fd.
}

/**
 * @test tcp_connect.ti_5_multi_connect
 * @brief
 *    Multiple connect on the same socket
 * @details
 */
TEST_F(tcp_connect, ti_5_multi_connect)
{
    SKIP_TRUE(!getenv("XLIO_SOCKETXTREME"), "Skip Socketxtreme");

    int fd = tcp_base::sock_create();
    ASSERT_LE(0, fd);

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    int rc = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    EXPECT_EQ(0, rc);
    if (rc != 0) {
        close(fd);
    }

    // Failing connect
    rc = connect(fd, reinterpret_cast<const sockaddr *>(&server_addr), sizeof(server_addr));
    EXPECT_NE(0, rc);

    int pid = fork();

    if (0 == pid) { /* I am the child */
        rc = -1;

        int lfd = tcp_base::sock_create_fa(m_family, true);
        EXPECT_LE(0, lfd);
        if (lfd > 0) {
            rc = bind(lfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            EXPECT_EQ(0, rc);
            if (rc != 0) {
                log_trace("Bind errno: %d\n", errno);
            } else {
                rc = listen(lfd, 1024);
                EXPECT_EQ(0, rc);
                if (rc == 0) {
                    barrier_fork(pid, true);
                    fd = accept(lfd, nullptr, nullptr);
                    EXPECT_LE(0, lfd);
                    if (fd > 0) {
                        // Force RST on close -> Prevent socket to enter TIME_WAIT without XLIO.
                        struct linger sl = {1, 0};
                        setsockopt(fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
                        close(fd);
                    }
                } else {
                    log_trace("Listen errno: %d\n", errno);
                }
            }

            close(lfd);
        }

        if (rc != 0) {
            barrier_fork(pid, true);
        }

        // This exit is very important, otherwise the fork
        // keeps running and may duplicate other tests.
        exit(testing::Test::HasFailure());
    } else { /* I am the parent */
        barrier_fork(pid, true);

        rc = connect(fd, reinterpret_cast<const sockaddr *>(&server_addr), sizeof(server_addr));
        EXPECT_TRUE(0 == rc || errno == ECONNABORTED);
        if (rc != 0) {
            log_trace("Connected errno: %d\n", errno);

            rc = close(fd);
            EXPECT_EQ(0, rc);

            // Get the child process out of the accept.
            fd = tcp_base::sock_create();
            if (fd > 0) {
                rc = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                EXPECT_EQ(0, rc);
                if (rc == 0) {
                    rc = connect(fd, reinterpret_cast<const sockaddr *>(&server_addr),
                                 sizeof(server_addr));
                    if (rc != 0) {
                        log_trace("Final connected errno: %d\n", errno);
                    }
                }
            }
        }

        close(fd);

        if (0 != rc) {
            kill(pid, SIGKILL);
        }

        wait_fork(pid);
    }
}

/**
 * @test tcp_connect.mapped_ipv4_connect
 * @brief
 *    IPv6 mapped IPv4 connect
 *
 * @details
 */
TEST_F(tcp_connect, mapped_ipv4_connect)
{
    SKIP_TRUE(!getenv("XLIO_SOCKETXTREME"), "Skip Socketxtreme");

    if (!test_mapped_ipv4()) {
        return;
    }

    auto check_connect = [this](bool withbind) {
        int pid = fork();
        if (0 == pid) { // Child
            barrier_fork(pid);

            int fd = tcp_base::sock_create_fa(AF_INET6, false);
            EXPECT_LE_ERRNO(0, fd);
            if (0 <= fd) {
                sockaddr_store_t client_ipv4 = client_addr;
                sockaddr_store_t server_ipv4 = server_addr;
                ipv4_to_mapped(client_ipv4);
                ipv4_to_mapped(server_ipv4);

                int rc = 0;
                if (withbind) {
                    rc = bind(fd, &client_ipv4.addr, sizeof(client_ipv4));
                }

                EXPECT_EQ_ERRNO(0, rc);
                if (0 == rc) {
                    rc = connect(fd, &server_ipv4.addr, sizeof(server_ipv4));
                    EXPECT_EQ_ERRNO(0, rc);
                    if (0 == rc) {
                        log_trace("Established connection: fd=%d to %s from %s\n", fd,
                                  SOCK_STR(server_ipv4), SOCK_STR(client_ipv4));

                        sockaddr_store_t peer_addr;
                        struct sockaddr *ppeer = &peer_addr.addr;
                        socklen_t socklen = sizeof(peer_addr);
                        memset(&peer_addr, 0, socklen);

                        getpeername(fd, ppeer, &socklen);
                        EXPECT_EQ_MAPPED_IPV4(peer_addr.addr6, server_addr.addr4.sin_addr.s_addr);

                        if (withbind) {
                            socklen = sizeof(peer_addr);
                            memset(&peer_addr, 0, socklen);
                            getsockname(fd, ppeer, &socklen);
                            EXPECT_EQ_MAPPED_IPV4(peer_addr.addr6,
                                                  client_addr.addr4.sin_addr.s_addr);
                        }

                        peer_wait(fd);
                    }
                }

                close(fd);
            }

            // This exit is very important, otherwise the fork
            // keeps running and may duplicate other tests.
            exit(testing::Test::HasFailure());
        } else { // Parent
            int l_fd = tcp_base::sock_create_to(AF_INET, false, 10);
            EXPECT_LE_ERRNO(0, l_fd);
            if (0 <= l_fd) {
                int rc = bind(l_fd, &server_addr.addr, sizeof(server_addr));
                EXPECT_EQ_ERRNO(0, rc);
                if (0 == rc) {
                    rc = listen(l_fd, 5);
                    EXPECT_EQ_ERRNO(0, rc);
                    if (0 == rc) {
                        barrier_fork(pid);

                        int fd = accept(l_fd, nullptr, 0U);
                        EXPECT_LE_ERRNO(0, fd);
                        if (0 <= fd) {
                            log_trace("Accepted connection: fd=%d\n", fd);

                            close(fd);
                        }
                    }
                }

                close(l_fd);
            }

            EXPECT_EQ(0, wait_fork(pid));
        }
    };

    log_trace("Without bind\n");
    check_connect(false);
    log_trace("With bind\n");
    check_connect(true);
}

/**
 * @test tcp_connect.mapped_ipv4_connect_v6only
 * @brief
 *    IPv6 mapped IPv4 connect IPv6-Only socket
 * @details
 */
TEST_F(tcp_connect, mapped_ipv4_connect_v6only)
{
    if (!test_mapped_ipv4()) {
        return;
    }

    int fd = tcp_base::sock_create_fa(AF_INET6, false);
    EXPECT_LE_ERRNO(0, fd);
    if (0 <= fd) {
        sockaddr_store_t server_ipv4 = server_addr;
        ipv4_to_mapped(server_ipv4);

        int ipv6only = 1;
        int rc = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only));
        EXPECT_EQ_ERRNO(0, rc);

        rc = connect(fd, &server_ipv4.addr, sizeof(server_ipv4));
        EXPECT_LE_ERRNO(rc, -1);
        EXPECT_EQ(errno, ENETUNREACH);

        close(fd);
    }
}

/**
 * @test tcp_connect.ti_6_incoming_conn
 * @brief
 *    Test API compliance for an incoming connection socket.
 * @details
 */
TEST_F(tcp_connect, ti_6_incoming_conn)
{
    SKIP_TRUE(!getenv("XLIO_SOCKETXTREME"), "Skip Socketxtreme");

    int rc = EOK;
    int pid = fork();

    if (0 == pid) { /* I am the child, client */
        barrier_fork(pid);

        int fd = tcp_base::sock_create();
        ASSERT_LE(0, fd);

        rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
        ASSERT_EQ(0, rc);

        rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        peer_wait(fd);

        close(fd);

        // This exit is very important, otherwise the fork
        // keeps running and may duplicate other tests.
        exit(testing::Test::HasFailure());
    } else { /* I am the parent, server */
        int l_fd = tcp_base::sock_create();
        ASSERT_LE(0, l_fd);

        rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        rc = listen(l_fd, 5);
        ASSERT_EQ(0, rc);

        barrier_fork(pid);

        struct sockaddr_storage peer_addr;
        socklen_t socklen = sizeof(peer_addr);
        int fd = accept(l_fd, (struct sockaddr *)&peer_addr, &socklen);
        ASSERT_LE(0, fd);
        log_trace("Accepted connection: fd=%d from %s\n", fd,
                  sys_addr2str((struct sockaddr *)&peer_addr));

        // Try to bind accepted socket, expect EINVAL
        rc = bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(-1, rc);
        ASSERT_EQ(EINVAL, errno);

        // Try to listen on accepted socket, expect EINVAL
        rc = listen(fd, 5);
        ASSERT_EQ(-1, rc);
        ASSERT_EQ(EINVAL, errno);

        // Try to connect on accepted socket, expect EISCONN
        rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(-1, rc);
        ASSERT_EQ(EISCONN, errno);

        // Set TCP_CORK option
        int optval = 1;
        rc = setsockopt(fd, IPPROTO_TCP, TCP_CORK, &optval, sizeof(optval));
        ASSERT_EQ(0, rc);

        // Set TCP_LINGER2 option which is not supported by XLIO
        rc = setsockopt(fd, IPPROTO_TCP, TCP_LINGER2, &optval, sizeof(optval));
        ASSERT_TRUE(0 == rc || errno == ENOPROTOOPT);

        close(l_fd);
        close(fd);

        ASSERT_EQ(0, wait_fork(pid));
    }
}

/**
 * @test tcp_connect.ti_with_tcp_user_timeout
 * @brief
 *    Test connect with TCP user timeout.
 * @details
 *    This test should pass the following combination
 *    1. Default
 *    2. XLIO_SOCKETXTREME=1
 *    3. XLIO_TCP_CTL_THREAD=delegate
 *    4. XLIO_RX_POLL=-1
 *    5. XLIO_SOCKETXTREME=1 XLIO_RX_POLL=-1
 *    6. XLIO_SOCKETXTREME=1 XLIO_TCP_CTL_THREAD=delegate
 *    7. XLIO_SOCKETXTREME=1 XLIO_TCP_CTL_THREAD=delegate XLIO_RX_POLL=-1
 *    8. XLIO_TCP_CTL_THREAD=delegate XLIO_RX_POLL=-1
 */
TEST_F(tcp_connect, ti_with_tcp_user_timeout)
{
    int fd = tcp_base::sock_create();
    ASSERT_LE(0, fd);

    unsigned int user_timeout_ms = 2000U;
    int rc =
        setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_ms, sizeof(user_timeout_ms));
    EXPECT_EQ(0, rc);

    sockaddr_store_t unresponsive_server;
    memcpy(&unresponsive_server, &server_addr, sizeof(server_addr));
    if (unresponsive_server.addr.sa_family == AF_INET) {
        reinterpret_cast<uint8_t *>(&unresponsive_server.addr4.sin_addr)[3] = 255;
    } else {
        reinterpret_cast<uint8_t *>(&unresponsive_server.addr6.sin6_addr)[15] = 255;
    }
    rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    ASSERT_EQ(-1, rc);
    ASSERT_EQ(110, errno);

    rc = close(fd);
    ASSERT_EQ(0, rc);
}
