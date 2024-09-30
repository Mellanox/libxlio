/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include "tcp_base.h"

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
