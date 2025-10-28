/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "common/cmn.h"
#include "udp_base.h"
#include "src/core/util/sock_addr.h"

class udp_connect : public udp_base {};

/**
 * @test udp_connect.ti_1
 * @brief
 *    Loop of blocking connect() to ip on the same node
 * @details
 */
TEST_F(udp_connect, ti_1)
{
    int rc = EOK;
    int fd;
    int i;

    fd = udp_base::sock_create();
    ASSERT_LE(0, fd);

    errno = EOK;
    rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    errno = EOK;
    rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    for (i = 0; i < 10; i++) {
        rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(EOK, errno) << "connect() attempt = " << i << "\n" << close(fd);
        ASSERT_EQ(0, rc) << "connect() attempt = " << i << "\n" << close(fd);
        usleep(500);
    }

    close(fd);
}

/**
 * @test udp_connect.ti_2
 * @brief
 *    Loop of blocking connect() to remote ip
 * @details
 */
TEST_F(udp_connect, ti_2)
{
    int rc = EOK;
    int fd;
    int i;

    fd = udp_base::sock_create();
    ASSERT_LE(0, fd);

    errno = EOK;
    rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    for (i = 0; i < 10; i++) {
        rc = connect(fd, (struct sockaddr *)&remote_routable_addr, sizeof(remote_routable_addr));
        ASSERT_TRUE(EOK == errno) << "connect() attempt = " << i << "\n" << close(fd);
        ASSERT_EQ(0, rc) << "connect() attempt = " << i << "\n" << close(fd);
        usleep(500);
    }

    close(fd);
}

/**
 * @test udp_connect.ti_3
 * @brief
 *    Loop of blocking connect() to unreachable ip
 * @details
 */
TEST_F(udp_connect, ti_3)
{
    int rc = EOK;
    int fd;
    int i;

    fd = udp_base::sock_create();
    ASSERT_LE(0, fd);

    errno = EOK;
    rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
    CHECK_ERR_OK(rc);

    for (i = 0; i < 10; i++) {
        rc = connect(fd, (struct sockaddr *)&bogus_addr, sizeof(bogus_addr));
        EXPECT_EQ(0, rc) << "connect() attempt = " << i << "\n" << close(fd);
        if (rc < 0) {
            ASSERT_EQ(EOK, errno) << "connect() attempt = " << i << "\n" << close(fd);
        }

        usleep(500);
    }

    close(fd);
}

/**
 * @test udp_connect.ti_4
 * @brief
 *    Loop of blocking connect() to zero port
 * @details
 */
TEST_F(udp_connect, ti_4)
{
    int rc = EOK;
    int fd;
    sockaddr_store_t addr;

    fd = udp_base::sock_create();
    ASSERT_LE(0, fd);

    errno = EOK;
    rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    memcpy(&addr, &server_addr, sizeof(addr));
    sys_set_port((struct sockaddr *)&addr, 0);

    errno = EOK;
    rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    close(fd);
}

/**
 * @test udp_connect.mapped_ipv4_connect
 * @brief
 *    IPv6 mapped IPv4 connect
 *
 * @details
 */
TEST_F(udp_connect, mapped_ipv4_connect)
{
    if (!test_mapped_ipv4()) {
        return;
    }

    auto check_connect = [this](bool withbind) {
        int pid = fork();
        if (0 == pid) { // Child
            barrier_fork(pid);

            int fd = udp_base::sock_create_fa(AF_INET6, false);
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

                        char buffer[8] = {0};
                        rc = send(fd, buffer, sizeof(buffer), 0);
                        EXPECT_EQ_ERRNO(8, rc);
                    }
                }

                close(fd);
            }

            // This exit is very important, otherwise the fork
            // keeps running and may duplicate other tests.
            exit(testing::Test::HasFailure());
        } else { // Parent
            int fd = udp_base::sock_create_to(AF_INET, false, 10);
            EXPECT_LE_ERRNO(0, fd);
            if (0 <= fd) {
                int rc = bind(fd, &server_addr.addr, sizeof(server_addr));
                EXPECT_EQ_ERRNO(0, rc);
                if (0 == rc) {
                    barrier_fork(pid);

                    char buffer[8] = {0};
                    do {
                        rc = recv(fd, buffer, sizeof(buffer), 0);
                    } while (rc < 0 && errno == EINTR);
                    EXPECT_EQ_ERRNO(8, rc);
                }

                close(fd);
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
 * @test udp_connect.mapped_ipv4_connect_v6only
 * @brief
 *    IPv6 mapped IPv4 connect IPv6-Only socket
 * @details
 */
TEST_F(udp_connect, mapped_ipv4_connect_v6only)
{
    if (!test_mapped_ipv4()) {
        return;
    }

    int fd = udp_base::sock_create_fa(AF_INET6, false);
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
