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
#include "src/core/util/sock_addr.h"
#include "tcp_base.h"

class tcp_bind : public tcp_base {
public:
    tcp_bind()
        : m_src_port(server_addr.addr.sa_family == AF_INET ? server_addr.addr4.sin_port
                                                           : server_addr.addr6.sin6_port)
        , m_addr_all_ipv4(AF_INET, &ip_address::any_addr().get_in4_addr(), m_src_port)
        , m_addr_all_ipv6(AF_INET6, &ip_address::any_addr().get_in6_addr(), m_src_port)
    {
    }

protected:
    bool create_ipv4_ipv6_sockets(bool reuse_addr)
    {
        m_fd4 = tcp_base::sock_create_fa(AF_INET, reuse_addr);
        m_fd6 = tcp_base::sock_create_fa(AF_INET6, reuse_addr);
        EXPECT_LE(0, m_fd4);
        EXPECT_LE(0, m_fd6);
        return (m_fd4 > 0 && m_fd6 > 0);
    }

    bool recreate_ipv6_socket(bool reuse_addr)
    {
        int rc = close(m_fd6);
        usleep(500000U); // XLIO timers to clean fd.
        EXPECT_EQ(0, rc);
        m_fd6 = tcp_base::sock_create_fa(AF_INET6, reuse_addr);
        EXPECT_LE(0, m_fd6);
        return (m_fd6 > 0);
    }

    bool close_ipv4_ipv6_sockets()
    {
        int rc4 = close(m_fd4);
        EXPECT_EQ(0, rc4);
        int rc6 = close(m_fd6);
        EXPECT_EQ(0, rc6);
        sleep(1U); // XLIO timers to clean fd.
        return (rc4 == 0 && rc6 == 0);
    }

    bool set_ipv6only(bool ipv6only)
    {
        int val = (ipv6only ? 1 : 0);
        int rc = setsockopt(m_fd6, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));
        EXPECT_EQ(0, rc);
        return (rc == 0);
    }

    int bind_all4()
    {
        return bind(m_fd4, m_addr_all_ipv4.get_p_sa(), m_addr_all_ipv4.get_socklen());
    }

    int bind_all6()
    {
        return bind(m_fd6, m_addr_all_ipv6.get_p_sa(), m_addr_all_ipv6.get_socklen());
    }

    int listen4() { return listen(m_fd4, 16); }

    int listen6() { return listen(m_fd6, 16); }

private:
    int m_fd4 = 0;
    int m_fd6 = 0;
    in_port_t m_src_port;
    sock_addr m_addr_all_ipv4;
    sock_addr m_addr_all_ipv6;
};

/**
 * @test tcp_bind.ti_1
 * @brief
 *    bind(SOCK_STREAM) socket to local ip
 * @details
 */
TEST_F(tcp_bind, ti_1)
{
    int rc = EOK;
    int fd;

    fd = tcp_base::sock_create();
    ASSERT_LE(0, fd);

    errno = EOK;
    rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    close(fd);
}

/**
 * @test tcp_bind.ti_2
 * @brief
 *    bind(SOCK_STREAM) socket to remote ip
 * @details
 */
TEST_F(tcp_bind, ti_2)
{
    int rc = EOK;
    int fd;

    fd = tcp_base::sock_create();
    ASSERT_LE(0, fd);

    errno = EOK;
    rc = bind(fd, (struct sockaddr *)&remote_unreachable_addr, sizeof(remote_unreachable_addr));
    EXPECT_EQ(EADDRNOTAVAIL, errno);
    EXPECT_GT(0, rc);

    close(fd);
}

/**
 * @test tcp_bind.ti_3
 * @brief
 *    bind(SOCK_STREAM) socket twice
 * @details
 */
TEST_F(tcp_bind, ti_3)
{
    int rc = EOK;
    int fd;
    sockaddr_store_t addr1;
    sockaddr_store_t addr2;

    fd = tcp_base::sock_create();
    ASSERT_LE(0, fd);

    errno = EOK;
    memcpy(&addr1, &client_addr, sizeof(addr1));
    sys_set_port((struct sockaddr *)&addr1, 17001);
    rc = bind(fd, (struct sockaddr *)&addr1, sizeof(addr1));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    errno = EOK;
    memcpy(&addr2, &client_addr, sizeof(addr2));
    sys_set_port((struct sockaddr *)&addr2, 17002);
    rc = bind(fd, (struct sockaddr *)&addr2, sizeof(addr2));
    EXPECT_EQ(EINVAL, errno);
    EXPECT_GT(0, rc);

    close(fd);
}

/**
 * @test tcp_bind.ti_4
 * @brief
 *    bind(SOCK_STREAM) two sockets on the same ip
 * @details
 */
TEST_F(tcp_bind, ti_4)
{
    int rc = EOK;
    int fd;
    int fd2;
    sockaddr_store_t addr;

    fd = tcp_base::sock_create();
    ASSERT_LE(0, fd);

    errno = EOK;
    memcpy(&addr, &client_addr, sizeof(addr));
    sys_set_port((struct sockaddr *)&addr, 17003);
    rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    fd2 = tcp_base::sock_create();
    ASSERT_LE(0, fd);

    errno = EOK;
    rc = bind(fd2, (struct sockaddr *)&addr, sizeof(addr));
    EXPECT_EQ(EADDRINUSE, errno);
    EXPECT_GT(0, rc);

    close(fd);
    close(fd2);
}

/**
 * @test tcp_bind.ti_5
 * @brief
 *    bind(SOCK_STREAM) bind with twice listen
 * @details
 */
TEST_F(tcp_bind, ti_5)
{
    int fd = tcp_base::sock_create();
    ASSERT_LE(0, fd);

    sockaddr_store_t addr;
    memcpy(&addr, &client_addr, sizeof(addr));
    sys_set_port((struct sockaddr *)&addr, 17004);
    int rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    EXPECT_EQ(0, rc);

    rc = listen(fd, 100);
    EXPECT_EQ(0, rc);

    rc = listen(fd, 200);
    EXPECT_EQ(0, rc);

    rc = close(fd);
    EXPECT_EQ(0, rc);
}

/**
 * @test tcp_bind.bind_IP4_6_dual_stack_no_reuse_addr
 * @brief
 *    Bind to the same port IPv4 then IPv6-Dual-socket.
 *    SO_REUSEADDR = false.
 * @details
 */
TEST_F(tcp_bind, bind_IP4_6_dual_stack_no_reuse_addr)
{
    ASSERT_TRUE(create_ipv4_ipv6_sockets(false));
    ASSERT_TRUE(set_ipv6only(false));

    EXPECT_EQ(0, bind_all4());
    EXPECT_NE(0, bind_all6());
    EXPECT_EQ(EADDRINUSE, errno);
    ASSERT_TRUE(set_ipv6only(true));
    EXPECT_EQ(0, bind_all6());

    EXPECT_TRUE(close_ipv4_ipv6_sockets());
}

/**
 * @test tcp_bind.bind_IP6_4_dual_stack_no_reuse_addr
 * @brief
 *    Bind to the same port IPv6-Dual-socket then IPv4.
 *    SO_REUSEADDR = false.
 * @details
 */
TEST_F(tcp_bind, bind_IP6_4_dual_stack_no_reuse_addr)
{
    ASSERT_TRUE(create_ipv4_ipv6_sockets(false));
    ASSERT_TRUE(set_ipv6only(false));

    EXPECT_EQ(0, bind_all6());
    EXPECT_NE(0, bind_all4());
    EXPECT_EQ(EADDRINUSE, errno);
    ASSERT_TRUE(recreate_ipv6_socket(false));
    ASSERT_TRUE(set_ipv6only(true));
    EXPECT_EQ(0, bind_all6());
    EXPECT_EQ(0, bind_all4());

    EXPECT_TRUE(close_ipv4_ipv6_sockets());
}

/**
 * @test tcp_bind.bind_IP4_6_dual_stack_reuse_addr
 * @brief
 *    Bind to the same port IPv4 then IPv6-Dual-socket.
 *    SO_REUSEADDR = true.
 * @details
 */
TEST_F(tcp_bind, bind_IP4_6_dual_stack_reuse_addr)
{
    ASSERT_TRUE(create_ipv4_ipv6_sockets(true));
    ASSERT_TRUE(set_ipv6only(false));

    EXPECT_EQ(0, bind_all4());
    EXPECT_EQ(0, bind_all6());
    EXPECT_EQ(0, listen4());
    EXPECT_NE(0, listen6());
    EXPECT_EQ(EADDRINUSE, errno);
    ASSERT_TRUE(recreate_ipv6_socket(true));
    ASSERT_TRUE(set_ipv6only(true));
    EXPECT_EQ(0, bind_all6());
    EXPECT_EQ(0, listen6());

    EXPECT_TRUE(close_ipv4_ipv6_sockets());
}

/**
 * @test tcp_bind.bind_IP6_4_dual_stack_reuse_addr
 * @brief
 *    Bind to the same port IPv6-Dual-socket then IPv4.
 *    SO_REUSEADDR = true.
 * @details
 */
TEST_F(tcp_bind, bind_IP6_4_dual_stack_reuse_addr)
{
    ASSERT_TRUE(create_ipv4_ipv6_sockets(true));
    ASSERT_TRUE(set_ipv6only(false));

    EXPECT_EQ(0, bind_all6());
    EXPECT_EQ(0, bind_all4());
    EXPECT_EQ(0, listen6());
    EXPECT_NE(0, listen4());
    EXPECT_EQ(EADDRINUSE, errno);
    ASSERT_TRUE(recreate_ipv6_socket(true));
    ASSERT_TRUE(set_ipv6only(true));
    EXPECT_EQ(0, bind_all6());
    EXPECT_EQ(0, listen6());
    EXPECT_EQ(0, listen4());

    EXPECT_TRUE(close_ipv4_ipv6_sockets());
}

/**
 * @test tcp_bind.bind_IP4_6_dual_stack_reuse_addr_listen
 * @brief
 *    Bind to the same port IPv4 then IPv6-Dual-socket with listen.
 *    SO_REUSEADDR = true.
 * @details
 */
TEST_F(tcp_bind, bind_IP4_6_dual_stack_reuse_addr_listen)
{
    ASSERT_TRUE(create_ipv4_ipv6_sockets(true));
    ASSERT_TRUE(set_ipv6only(false));

    EXPECT_EQ(0, bind_all4());
    EXPECT_EQ(0, listen4());
    EXPECT_NE(0, bind_all6());
    EXPECT_EQ(EADDRINUSE, errno);
    ASSERT_TRUE(recreate_ipv6_socket(true));
    ASSERT_TRUE(set_ipv6only(true));
    EXPECT_EQ(0, bind_all6());
    EXPECT_EQ(0, listen6());

    EXPECT_TRUE(close_ipv4_ipv6_sockets());
}

/**
 * @test tcp_bind.bind_IP6_4_dual_stack_reuse_addr_listen
 * @brief
 *    Bind to the same port IPv6-Dual-socket then IPv4 with listen.
 *    SO_REUSEADDR = true.
 * @details
 */
TEST_F(tcp_bind, bind_IP6_4_dual_stack_reuse_addr_listen)
{
    ASSERT_TRUE(create_ipv4_ipv6_sockets(true));
    ASSERT_TRUE(set_ipv6only(false));

    EXPECT_EQ(0, bind_all6());
    EXPECT_EQ(0, listen6());
    EXPECT_NE(0, bind_all4());
    EXPECT_EQ(EADDRINUSE, errno);
    ASSERT_TRUE(recreate_ipv6_socket(true));
    ASSERT_TRUE(set_ipv6only(true));
    EXPECT_EQ(0, bind_all6());
    EXPECT_EQ(0, listen6());
    EXPECT_EQ(0, listen4());

    EXPECT_TRUE(close_ipv4_ipv6_sockets());
}

/**
 * @test tcp_bind.mapped_ipv4_bind
 * @brief
 *    IPv6 mapped IPv4 bind
 *
 * @details
 */
TEST_F(tcp_bind, mapped_ipv4_bind)
{
    if (!test_mapped_ipv4()) {
        return;
    }

    auto check_bind = [this](bool bindtodevice) {
        int pid = fork();
        if (0 == pid) { // Child
            barrier_fork(pid);

            int fd = tcp_base::sock_create_fa(AF_INET, false);
            EXPECT_LE_ERRNO(0, fd);
            if (0 <= fd) {
                int rc = bind(fd, &client_addr.addr, sizeof(client_addr));
                EXPECT_EQ_ERRNO(0, rc);
                if (0 == rc) {
                    log_trace("Bound client: fd=%d\n", fd);

                    rc = connect(fd, &server_addr.addr, sizeof(server_addr));
                    EXPECT_EQ_ERRNO(0, rc);
                    if (0 == rc) {
                        log_trace("Established connection: fd=%d to %s from %s\n", fd,
                                  SOCK_STR(server_addr), SOCK_STR(client_addr));

                        char buffer[8] = {0};
                        send(fd, buffer, sizeof(buffer), 0);

                        peer_wait(fd);
                    }
                }

                close(fd);
            }

            // This exit is very important, otherwise the fork
            // keeps running and may duplicate other tests.
            exit(testing::Test::HasFailure());
        } else { // Parent
            int l_fd = tcp_base::sock_create_to(AF_INET6, false, 10);
            EXPECT_LE_ERRNO(0, l_fd);
            if (0 <= l_fd) {
                sockaddr_store_t server_ipv4 = server_addr;
                ipv4_to_mapped(server_ipv4);

                log_trace("Binding: fd=%d, %s\n", l_fd, SOCK_STR(server_ipv4));

                int rc = 0;
                if (bindtodevice) {
                    rc = bind_to_device(l_fd, server_addr);
                }
                EXPECT_EQ_ERRNO(0, rc);
                if (0 == rc) {
                    rc = bind(l_fd, &server_ipv4.addr, sizeof(server_ipv4));
                    EXPECT_EQ_ERRNO(0, rc);
                    if (0 == rc) {
                        log_trace("Bound server: fd=%d\n", l_fd);

                        rc = listen(l_fd, 5);
                        EXPECT_EQ_ERRNO(0, rc);
                        if (0 == rc) {
                            barrier_fork(pid);

                            log_trace("Listening: fd=%d\n", l_fd);

                            int fd = accept(l_fd, nullptr, 0U);
                            EXPECT_LE_ERRNO(0, fd);
                            if (0 <= fd) {
                                log_trace("Accepted connection: fd=%d\n", fd);

                                char buffer[8] = {0};
                                rc = recv(fd, buffer, sizeof(buffer), 0);
                                EXPECT_EQ_ERRNO(8, rc);

                                close(fd);
                            }
                        }
                    }
                }

                close(l_fd);
            }

            EXPECT_EQ(0, wait_fork(pid));
        }
    };

    log_trace("Checking bind()\n");
    check_bind(false);
    // Disabled for CI, XLIO inconformability.
    // log_trace("Checking bind() with SO_BINDTODEVICE\n");
    // check_bind(true);
}

/**
 * @test tcp_bind.mapped_ipv4_bind_v6only
 * @brief
 *    IPv6 mapped IPv4 connect IPv6-Only socket
 * @details
 */
TEST_F(tcp_bind, mapped_ipv4_bind_v6only)
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

        rc = bind(fd, &server_ipv4.addr, sizeof(server_ipv4));
        EXPECT_LE_ERRNO(rc, -1);
        EXPECT_EQ(errno, EINVAL);

        close(fd);
    }
}
