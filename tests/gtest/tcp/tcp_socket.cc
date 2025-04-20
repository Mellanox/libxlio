/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "tcp_base.h"
#include <thread>
class tcp_socket : public tcp_base {};

/**
 * @test tcp_socket.ti_1_ipv4
 * @brief
 *    Create IPv4 TCP socket
 * @details
 */
TEST_F(tcp_socket, ti_1_ip_socket)
{
    int fd;

    fd = socket(m_family, SOCK_STREAM, IPPROTO_IP);
    EXPECT_LE(0, fd);
    EXPECT_EQ(errno, EOK);

    close(fd);
}

/**
 * @test tcp_socket.ti_2_ipv6only_listen_all
 * @brief
 *    Try IPv4 connection to IPv6 listen all socket with and without IPV6_V6ONLY.
 * @details
 */
TEST_F(tcp_socket, ti_2_ipv6only_listen_all)
{
    // Test only for IPv4 to IPv6 mode.
    if (server_addr.addr.sa_family != AF_INET6 || client_addr.addr.sa_family != AF_INET) {
        return;
    }

    auto test_lambda = [this](bool with_ipv6only) {
        int rc = EOK;
        int pid = fork();

        if (0 == pid) { /* I am the child */
            barrier_fork(pid);

            int fd = tcp_base::sock_create_fa(client_addr.addr.sa_family);
            ASSERT_LE(0, fd);

            rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
            ASSERT_EQ(0, rc);

            rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            if (with_ipv6only) {
                ASSERT_NE(0, rc);

                close(fd);

                fd = tcp_base::sock_create_fa(AF_INET6);
                ASSERT_LE(0, fd);

                rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
                ASSERT_EQ(0, rc);
            } else {
                ASSERT_EQ(0, rc);
            }

            /* This exit is very important, otherwise the fork
             * keeps running and may duplicate other tests.
             */
            exit(testing::Test::HasFailure());
        } else { /* I am the parent */
            int l_fd;
            struct sockaddr peer_addr;
            socklen_t socklen;

            l_fd = tcp_base::sock_create();
            ASSERT_LE(0, l_fd);

            sockaddr_in6 server_addr_all;
            memset(&server_addr_all, 0, sizeof(server_addr_all));
            server_addr_all.sin6_family = AF_INET6;
            server_addr_all.sin6_port = server_addr.addr6.sin6_port;

            int ipv6only = (with_ipv6only ? 1 : 0);
            rc = setsockopt(l_fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only));
            ASSERT_EQ(0, rc);

            ipv6only = (with_ipv6only ? 0 : 1);
            socklen_t valsz = sizeof(ipv6only);
            rc = getsockopt(l_fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, &valsz);
            ASSERT_EQ(0, rc);
            ASSERT_EQ(valsz, sizeof(ipv6only));
            ASSERT_EQ((with_ipv6only ? 1 : 0), ipv6only);

            rc = bind(l_fd, (struct sockaddr *)&server_addr_all, sizeof(server_addr_all));
            ASSERT_EQ(0, rc);

            rc = listen(l_fd, 5);
            ASSERT_EQ(0, rc);

            barrier_fork(pid);

            socklen = sizeof(peer_addr);
            int fd = accept(l_fd, &peer_addr, &socklen);
            ASSERT_LE(0, fd);
            close(l_fd);

            log_trace("Accepted connection: fd=%d from %s\n", fd,
                      sys_addr2str((struct sockaddr *)&peer_addr));

            peer_wait(fd);

            close(fd);

            ASSERT_EQ(0, wait_fork(pid));
        }
    };

    test_lambda(true);
    test_lambda(false);
}

/**
 * @test tcp_socket.ti_3_socket_closed_different_thread_works
 * @brief
 *    Test that a socket can be closed after its creator thread terminates
 * @details
 *    Creates a socket in a separate thread, then closes it from the main thread
 *    after the creator thread has terminated. This verifies that socket cleanup
 *    works correctly across thread boundaries.
 */
TEST_F(tcp_socket, ti_3_socket_closed_different_thread_works)
{
    int fd = -1;

    std::thread t([&fd]() {
        fd = socket(m_family, SOCK_STREAM, IPPROTO_IP);
        EXPECT_LE(0, fd);
        EXPECT_EQ(errno, EOK);
    });

    t.join();

    EXPECT_LE(0, fd);
    close(fd);
}
