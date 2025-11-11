/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <functional>
#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "common/cmn.h"
#include "src/core/util/sock_addr.h"
#include "udp_base.h"

class udp_bind : public udp_base {
public:
    udp_bind()
        : m_src_port(server_addr.addr.sa_family == AF_INET ? server_addr.addr4.sin_port
                                                           : server_addr.addr6.sin6_port)
        , m_addr_all_ipv4(AF_INET, &ip_address::any_addr().get_in4_addr(), m_src_port)
        , m_addr_all_ipv6(AF_INET6, &ip_address::any_addr().get_in6_addr(), m_src_port)
    {
    }

protected:
    bool create_ipv4_ipv6_sockets(bool reuse_addr)
    {
        m_fd4 = udp_base::sock_create_fa(AF_INET, reuse_addr);
        m_fd6 = udp_base::sock_create_fa(AF_INET6, reuse_addr);
        EXPECT_LE(0, m_fd4);
        EXPECT_LE(0, m_fd6);
        return (m_fd4 > 0 && m_fd6 > 0);
    }

    bool recreate_ipv6_socket(bool reuse_addr)
    {
        int rc = close(m_fd6);
        EXPECT_EQ(0, rc);
        m_fd6 = udp_base::sock_create_fa(AF_INET6, reuse_addr);
        EXPECT_LE(0, m_fd6);
        return (m_fd6 > 0);
    }

    bool close_ipv4_ipv6_sockets()
    {
        int rc4 = close(m_fd4);
        EXPECT_EQ(0, rc4);
        int rc6 = close(m_fd6);
        EXPECT_EQ(0, rc6);
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

private:
    int m_fd4 = 0;
    int m_fd6 = 0;
    in_port_t m_src_port;
    sock_addr m_addr_all_ipv4;
    sock_addr m_addr_all_ipv6;
};

/**
 * @test udp_bind.ti_1
 * @brief
 *    bind(SOCK_DGRAM) socket to local ip
 * @details
 */
TEST_F(udp_bind, ti_1)
{
    int rc = EOK;
    int fd;

    fd = udp_base::sock_create();
    ASSERT_LE(0, fd);

    errno = EOK;
    rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    close(fd);
}

/**
 * @test udp_bind.ti_2
 * @brief
 *    bind(SOCK_DGRAM) socket to remote ip
 * @details
 */
TEST_F(udp_bind, ti_2)
{
    int rc = EOK;
    int fd;

    fd = udp_base::sock_create();
    ASSERT_LE(0, fd);

    errno = EOK;
    rc = bind(fd, (struct sockaddr *)&remote_unreachable_addr, sizeof(remote_unreachable_addr));
    EXPECT_EQ(EADDRNOTAVAIL, errno);
    EXPECT_GT(0, rc);

    close(fd);
}

/**
 * @test udp_bind.ti_3
 * @brief
 *    bind(SOCK_DGRAM) socket twice
 * @details
 */
TEST_F(udp_bind, ti_3)
{
    int rc = EOK;
    int fd;
    sockaddr_store_t addr1;
    sockaddr_store_t addr2;

    fd = udp_base::sock_create();
    ASSERT_LE(0, fd);

    memcpy(&addr1, &client_addr, sizeof(addr1));
    sys_set_port((struct sockaddr *)&addr1, 17001);

    errno = EOK;
    rc = bind(fd, (struct sockaddr *)&addr1, sizeof(addr1));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    memcpy(&addr2, &client_addr, sizeof(addr2));
    sys_set_port((struct sockaddr *)&addr2, 17002);

    errno = EOK;
    rc = bind(fd, (struct sockaddr *)&addr2, sizeof(addr2));
    EXPECT_EQ(EINVAL, errno);
    EXPECT_GT(0, rc);

    close(fd);
}

/**
 * @test udp_bind.ti_4
 * @brief
 *    bind(SOCK_DGRAM) two sockets on the same ip
 * @details
 */
TEST_F(udp_bind, ti_4)
{
    int rc = EOK;
    int fd;
    int fd2;
    sockaddr_store_t addr;

    fd = udp_base::sock_create();
    ASSERT_LE(0, fd);

    memcpy(&addr, &client_addr, sizeof(addr));
    sys_set_port((struct sockaddr *)&addr, 17001);

    errno = EOK;
    rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    fd2 = udp_base::sock_create();
    ASSERT_LE(0, fd);

    errno = EOK;
    rc = bind(fd2, (struct sockaddr *)&addr, sizeof(addr));
    EXPECT_EQ(EADDRINUSE, errno);
    EXPECT_GT(0, rc);

    close(fd);
    close(fd2);
}

/**
 * @test udp_bind.bind_IP4_6_dual_stack_no_reuse_addr
 * @brief
 *    Bind to the same port IPv4 then IPv6-Dual-socket.
 *    SO_REUSEADDR = false.
 * @details
 */
TEST_F(udp_bind, bind_IP4_6_dual_stack_no_reuse_addr)
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
 * @test udp_bind.bind_IP6_4_dual_stack_no_reuse_addr
 * @brief
 *    Bind to the same port IPv6-Dual-socket then IPv4.
 *    SO_REUSEADDR = false.
 * @details
 */
TEST_F(udp_bind, bind_IP6_4_dual_stack_no_reuse_addr)
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
 * @test udp_bind.bind_IP4_6_dual_stack_reuse_addr
 * @brief
 *    Bind to the same port IPv4 then IPv6-Dual-socket.
 *    SO_REUSEADDR = true.
 * @details
 */
TEST_F(udp_bind, bind_IP4_6_dual_stack_reuse_addr)
{
    ASSERT_TRUE(create_ipv4_ipv6_sockets(true));
    ASSERT_TRUE(set_ipv6only(false));

    EXPECT_EQ(0, bind_all4());
    EXPECT_EQ(0, bind_all6());

    EXPECT_TRUE(close_ipv4_ipv6_sockets());
}

/**
 * @test tcp_bind.bind_IP6_4_dual_stack_reuse_addr
 * @brief
 *    Bind to the same port IPv6-Dual-socket then IPv4.
 *    SO_REUSEADDR = true.
 * @details
 */
TEST_F(udp_bind, bind_IP6_4_dual_stack_reuse_addr)
{
    ASSERT_TRUE(create_ipv4_ipv6_sockets(true));
    ASSERT_TRUE(set_ipv6only(false));

    EXPECT_EQ(0, bind_all6());
    EXPECT_EQ(0, bind_all4());

    EXPECT_TRUE(close_ipv4_ipv6_sockets());
}

/**
 * @test udp_bind.mapped_ipv4_bind_recv
 * @brief
 *    IPv6 mapped IPv4 bounded receiver
 *
 * @details
 */
TEST_F(udp_bind, mapped_ipv4_bind_recv)
{
    if (!test_mapped_ipv4()) {
        return;
    }

    int pid = fork();

    if (0 == pid) { // Child
        barrier_fork(pid);

        int fd = udp_base::sock_create_fa(AF_INET, false);
        EXPECT_LE_ERRNO(0, fd);
        if (0 <= fd) {
            int rc = bind(fd, &client_addr.addr, sizeof(client_addr));
            EXPECT_EQ_ERRNO(0, rc);
            if (0 == rc) {
                rc = connect(fd, &server_addr.addr, sizeof(server_addr));
                EXPECT_EQ_ERRNO(0, rc);
                if (0 == rc) {
                    log_trace("Established connection: fd=%d to %s from %s\n", fd,
                              SOCK_STR(server_addr), SOCK_STR(client_addr));

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
        int fd = udp_base::sock_create_to(AF_INET6, false, 10);
        EXPECT_LE_ERRNO(0, fd);
        if (0 <= fd) {
            sockaddr_store_t client_ipv4 = client_addr;
            sockaddr_store_t server_ipv4 = server_addr;
            ipv4_to_mapped(client_ipv4);
            ipv4_to_mapped(server_ipv4);

            int rc = bind(fd, &server_ipv4.addr, sizeof(server_ipv4));
            EXPECT_EQ_ERRNO(0, rc);
            if (0 == rc) {
                barrier_fork(pid);

                char buffer[8] = {0};
                rc = recv(fd, buffer, sizeof(buffer), 0);
                EXPECT_EQ_ERRNO(8, rc);
            }

            close(fd);
        }

        EXPECT_EQ(0, wait_fork(pid));
    }
}

/**
 * @test udp_bind.mapped_ipv4_bind_send
 * @brief
 *    IPv6 mapped IPv4 bounded sender
 *
 * @details
 */
TEST_F(udp_bind, mapped_ipv4_bind_send)
{
    if (!test_mapped_ipv4()) {
        return;
    }

    auto check_bind = [this](bool bindtodevice) {
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
                if (bindtodevice) {
                    rc = bind_to_device(fd, client_addr);
                }
                EXPECT_EQ_ERRNO(0, rc);
                if (0 == rc) {
                    rc = bind(fd, &client_ipv4.addr, sizeof(client_ipv4));
                    EXPECT_EQ_ERRNO(0, rc);
                    if (0 == rc) {
                        char buffer[8] = {0};
                        rc = sendto(fd, buffer, sizeof(buffer), 0, &server_ipv4.addr,
                                    sizeof(server_ipv4));
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
                    rc = recv(fd, buffer, sizeof(buffer), 0);
                    EXPECT_EQ_ERRNO(8, rc);
                }

                close(fd);
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
 * @test udp_bind.mapped_ipv4_bind_v6only
 * @brief
 *    IPv6 mapped IPv4 connect IPv6-Only socket
 * @details
 */
TEST_F(udp_bind, mapped_ipv4_bind_v6only)
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

        rc = bind(fd, &server_ipv4.addr, sizeof(server_ipv4));
        EXPECT_LE_ERRNO(rc, -1);
        EXPECT_EQ(errno, EINVAL);

        close(fd);
    }
}

const std::string to_str(int family, const void *addr)
{
    char buffer[INET6_ADDRSTRLEN];

    return std::string(inet_ntop(family, addr, buffer, sizeof(buffer)));
}

class pktinfo : public udp_base {
public:
    char buffer[100] = {0};
    const std::string expected_server_addr_string;

    pktinfo()
        : udp_base()
        , expected_server_addr_string(server_addr.addr.sa_family == AF_INET6
                                          ? to_str(AF_INET6, &server_addr.addr6.sin6_addr)
                                          : to_str(AF_INET, &server_addr.addr4.sin_addr)) {};

    void server_func(int child_pid, std::function<void(int)> code_under_test)
    {
        /* The server socket is an IPv6 socket that can accept both IPv6 and IPv4 connections */
        int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);
        EXPECT_GT(fd, 0) << "Socket failed to open";

        /* Set receive timeout to prevent indefinite blocking */
        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        EXPECT_EQ(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)), 0)
            << "Failed to set receive timeout";

        sockaddr_store_t server_any_sockaddr = {
            .addr6 = {
                .sin6_family = AF_INET6,
                .sin6_port = server_addr.addr.sa_family == AF_INET ? server_addr.addr4.sin_port
                                                                   : server_addr.addr6.sin6_port,
                .sin6_flowinfo = 0,
                .sin6_addr = IN6ADDR_ANY_INIT, // in6addr_any;
                .sin6_scope_id = 0,
            }};

        EXPECT_EQ(bind(fd, &server_any_sockaddr.addr, sizeof(server_any_sockaddr)), 0)
            << "Address not bound";

        barrier_fork(child_pid);

        code_under_test(fd);

        close(fd);
    };

    void client_func()
    {
        barrier_fork(0);
        int fd = socket(client_addr.addr.sa_family, SOCK_DGRAM, IPPROTO_IP);

        EXPECT_GT(fd, 0) << "Socket failed to open";
        EXPECT_EQ(bind(fd, &client_addr.addr, sizeof(client_addr)), 0) << "Address not bound";
        EXPECT_EQ(connect(fd, &server_addr.addr, sizeof(server_addr)), 0)
            << "Connection not established";

        EXPECT_GT(send(fd, buffer, sizeof(buffer), 0), 0) << "Failed to send data";

        close(fd);
        exit(testing::Test::HasFailure());
    };
};

/**
 * @test pktinfo.check_recvmsg_returns_expected_pktinfo
 * @brief
 * @details
 */
TEST_F(pktinfo, check_recvmsg_returns_expected_pktinfo)
{
    int pid = fork();
    if (0 == pid) { /* Child-client code */
        client_func();
    } else { /* parent-server */
        std::function<void(int)> server_code_under_test = [&](int fd) {
            int on = 1;
            ASSERT_EQ(setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)), 0)
                << "Setsockopt failed";

            char cbuf[40];
            iovec vec {.iov_base = buffer, .iov_len = sizeof(buffer)};
            struct msghdr msg {
                &client_addr.addr, sizeof(client_addr.addr), &vec, 1U, cbuf, sizeof(cbuf), 0
            };

            ssize_t ret;
            do {
                ret = recvmsg(fd, &msg, 0);
            } while (ret < 0 && errno == EINTR);
            ASSERT_GT(ret, 0) << "Failed to receive the msg, errno=" << errno;

            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

            ASSERT_NE(cmsg, nullptr) << "No cmsg";
            ASSERT_EQ(cmsg->cmsg_level, SOL_IPV6) << "Wrong cmsg level";
            ASSERT_EQ(cmsg->cmsg_type, IPV6_PKTINFO) << "Wrong cmsg type";

            auto actual_server_addr_string = to_str(
                AF_INET6, &reinterpret_cast<struct in6_pktinfo *>(CMSG_DATA(cmsg))->ipi6_addr);

            ASSERT_TRUE(actual_server_addr_string.find(expected_server_addr_string) !=
                        std::string::npos)
                << "Wrong address expected = " << expected_server_addr_string
                << "actual = " << actual_server_addr_string;
        };

        server_func(pid, server_code_under_test);

        /* Wait for child process to complete and validate exit status */
        ASSERT_EQ(0, wait_fork(pid));
    }
}
