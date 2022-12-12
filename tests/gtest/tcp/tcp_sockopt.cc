/*
 * Copyright (c) 2001-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include <sys/socket.h>
#include <sys/types.h> /* See NOTES */
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "googletest/include/gtest/gtest.h"
#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "tcp_base.h"

#define HELLO_STR "hello"

class tcp_sockopt : public tcp_base {
};

/**
 * @test tcp_sockopt.ti_1_getsockopt_tcp_info
 * @brief
 *    getsockopt(TCP_INFO).
 * @details
 */
TEST_F(tcp_sockopt, ti_1_getsockopt_tcp_info)
{
    auto test_lambda = [this]() {
        int rc = EOK;
        int pid = fork();

        if (0 == pid) { /* I am the child */
            barrier_fork(pid);

            int fd = tcp_base::sock_create();
            ASSERT_LE(0, fd);

            rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
            ASSERT_EQ(0, rc);

            rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            ASSERT_EQ(0, rc);

            static char buf[] = HELLO_STR;
            ssize_t len = send(fd, (void *)buf, sizeof(buf), 0);
            EXPECT_EQ(static_cast<ssize_t>(sizeof(buf)), len);

            /* Case #0.
             * EFAULT error.
             */
            rc = getsockopt(fd, IPPROTO_TCP, TCP_INFO, nullptr, nullptr);
            ASSERT_EQ(-1, rc);
            ASSERT_EQ(EFAULT, errno);

            /* Case #1.
             * TCP_INFO can return partial structure due to backward compatibility guarantees.
             */
            struct tcp_info ti;
            socklen_t optlen = sizeof(ti) - 1U;
            rc = getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &optlen);
            ASSERT_EQ(0, rc);
            ASSERT_EQ(sizeof(ti) - 1U, optlen);

            /* Case #2.
             * Established connection.
             */
            optlen = sizeof(ti);
            rc = getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &optlen);
            ASSERT_EQ(0, rc);
            ASSERT_EQ(TCP_ESTABLISHED, ti.tcpi_state);
            ASSERT_EQ(0U, ti.tcpi_retransmits);
            ASSERT_EQ(0U, ti.tcpi_total_retrans);
            ASSERT_LT(0U, ti.tcpi_snd_cwnd);
            /* We cannot rely on 1460 MSS value since kernel sends traffic to loopback. */

            peer_wait(fd);

            /* Case #3.
             * Call getsockopt(TCP_INFO) after the parent process closes connection.
             */
            optlen = sizeof(ti);
            rc = getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &optlen);
            ASSERT_EQ(0, rc);
            ASSERT_NE(TCP_ESTABLISHED, ti.tcpi_state);

            close(fd);

            /* This exit is very important, otherwise the fork
             * keeps running and may duplicate other tests.
             */
            exit(testing::Test::HasFailure());
        } else { /* I am the parent */
            struct sockaddr_storage peer_addr;
            socklen_t socklen;
            char buf[sizeof(HELLO_STR) + 1];

            int l_fd = tcp_base::sock_create();
            ASSERT_LE(0, l_fd);

            rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            ASSERT_EQ(0, rc);

            rc = listen(l_fd, 5);
            ASSERT_EQ(0, rc);

            barrier_fork(pid);

            socklen = sizeof(peer_addr);
            int fd = accept(l_fd, (struct sockaddr *)&peer_addr, &socklen);
            ASSERT_LE(0, fd);
            log_trace("Accepted connection: fd=%d from %s\n", fd,
                      sys_addr2str((struct sockaddr *)&peer_addr));

            ssize_t len = recv(fd, buf, sizeof(buf), 0);
            EXPECT_LE(static_cast<ssize_t>(sizeof(HELLO_STR)), len);
            EXPECT_EQ(0, strncmp(HELLO_STR, buf, sizeof(HELLO_STR)));

            /* Case #4.
             * Incoming connection.
             */
            struct tcp_info ti;
            socklen_t optlen = sizeof(ti);
            rc = getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &optlen);
            ASSERT_EQ(0, rc);
            ASSERT_EQ(TCP_ESTABLISHED, ti.tcpi_state);

            /* Case #5.
             * Listen socket.
             */
            optlen = sizeof(ti);
            rc = getsockopt(l_fd, IPPROTO_TCP, TCP_INFO, &ti, &optlen);
            ASSERT_EQ(0, rc);
            ASSERT_EQ(TCP_LISTEN, ti.tcpi_state);

            /* Let the child process to call getsockopt() on established socket. */
            usleep(500);

            close(fd);
            close(l_fd);

            ASSERT_EQ(0, wait_fork(pid));
        }
    };

    test_lambda();
}

/**
 * @test tcp_sockopt.ti_2_tcp_congestion
 * @brief
 *    TCP_CONGESTION option to change and check congestion control mechanism.
 * @details
 */
TEST_F(tcp_sockopt, ti_2_tcp_congestion)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_LE(0, fd);

    char buf[16];
    socklen_t len = 0;
    int rc = getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, buf, &len);
    EXPECT_EQ(0, rc);
    EXPECT_EQ(0U, len);

#if 0
    // XLIO isn't complient with kernel in this case
    rc = getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, NULL, &len);
    EXPECT_EQ(0, rc);
    EXPECT_EQ(0U, len);
#endif

    rc = getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, buf, NULL);
    EXPECT_EQ(-1, rc);
    EXPECT_EQ(EFAULT, errno);

    rc = setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, buf, 0);
    EXPECT_EQ(-1, rc);
    EXPECT_EQ(EINVAL, errno);

#if 0
    // XLIO isn't complient with kernel in this case
    rc = setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, NULL, 0);
    EXPECT_EQ(-1, rc);
    EXPECT_EQ(EINVAL, errno);
#endif

    rc = setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, NULL, 5);
    EXPECT_EQ(-1, rc);
    EXPECT_EQ(EFAULT, errno);

    // Assume reno is supported everywhere
    snprintf(buf, sizeof(buf), "reno");
    // Note, len doesn't include terminating '\0'
    len = strlen(buf);
    rc = setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, buf, len);
    EXPECT_EQ(0, rc);
    if (rc == 0) {
        len = sizeof(buf);
        rc = getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, buf, &len);
        EXPECT_EQ(0, rc);
        EXPECT_LT(0U, len);
    }
    if (rc == 0) {
        std::string cc_name(buf, strnlen(buf, len));
        EXPECT_EQ(std::string("reno"), cc_name);
    }
}

class tcp_set_get_sockopt : public ::testing::Test {
protected:
    void SetUp() override
    {
        m_ipv4_tcp_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        m_ipv6_tcp_socket_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_IP);
        EXPECT_GE(m_ipv4_tcp_socket_fd, 0);
        EXPECT_GE(m_ipv6_tcp_socket_fd, 0);
    }

    void TearDown() override
    {
        close(m_ipv4_tcp_socket_fd);
        close(m_ipv6_tcp_socket_fd);
    }
    int m_ipv4_tcp_socket_fd = -1;
    int m_ipv6_tcp_socket_fd = -1;
};

class tcp_set_get_sockopt_on_udp_socket : public ::testing::Test {
protected:
    void SetUp() override
    {
        m_ipv4_udp_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        m_ipv6_udp_socket_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);
        EXPECT_GE(m_ipv4_udp_socket_fd, 0);
        EXPECT_GE(m_ipv6_udp_socket_fd, 0);
    }

    void TearDown() override
    {
        close(m_ipv4_udp_socket_fd);
        close(m_ipv6_udp_socket_fd);
    }
    int m_ipv4_udp_socket_fd = -1;
    int m_ipv6_udp_socket_fd = -1;
};

TEST_F(tcp_set_get_sockopt_on_udp_socket, set_and_get_tcp_ipv4_user_timeout_fails)
{
    unsigned int user_timeout_ms = 5000U;
    int result = setsockopt(m_ipv4_udp_socket_fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_ms,
                            sizeof(user_timeout_ms));
    EXPECT_EQ(result, -1) << "IPPROTO_TCP is unsupported for UDP sockets";

    socklen_t optlen;
    result =
        getsockopt(m_ipv4_udp_socket_fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_ms, &optlen);
    EXPECT_EQ(result, -1) << "IPPROTO_TCP is unsupported for UDP sockets";
}

TEST_F(tcp_set_get_sockopt_on_udp_socket, set_and_get_tcp_ipv6_user_timeout_fails)
{
    unsigned int user_timeout_ms = 5000U;
    int result = setsockopt(m_ipv6_udp_socket_fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_ms,
                            sizeof(user_timeout_ms));
    EXPECT_EQ(result, -1) << "IPPROTO_TCP is unsupported for UDP sockets";

    socklen_t optlen;
    result =
        getsockopt(m_ipv6_udp_socket_fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_ms, &optlen);
    EXPECT_EQ(result, -1) << "IPPROTO_TCP is unsupported for UDP sockets";
}

TEST_F(tcp_set_get_sockopt, set_and_get_tcp_ipv4_user_timeout)
{
    const unsigned int user_timeout_ms = 5000U;
    int result = setsockopt(m_ipv4_tcp_socket_fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_ms,
                            sizeof(user_timeout_ms));
    EXPECT_EQ(result, 0) << "IPPROTO_TCP is unsupported for UDP sockets";

    socklen_t optlen = -1;
    unsigned int output_user_timeout_ms = -1;

    result = getsockopt(m_ipv4_tcp_socket_fd, IPPROTO_TCP, TCP_USER_TIMEOUT,
                        &output_user_timeout_ms, &optlen);
    EXPECT_EQ(result, 0) << "getsockopt failed for TCP_USER_TIMEOUT";
    EXPECT_EQ(optlen, sizeof(output_user_timeout_ms)) << "Unexpected parameter size";
    EXPECT_EQ(output_user_timeout_ms, user_timeout_ms) << "Unexpected timeout value";
}

TEST_F(tcp_set_get_sockopt, set_and_get_tcp_ipv6_user_timeout)
{
    const unsigned int user_timeout_ms = 5000U;
    int result = setsockopt(m_ipv6_tcp_socket_fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_ms,
                            sizeof(user_timeout_ms));
    EXPECT_EQ(result, 0) << "IPPROTO_TCP is unsupported for UDP sockets";

    socklen_t optlen = -1;
    unsigned int output_user_timeout_ms = -1;

    result = getsockopt(m_ipv6_tcp_socket_fd, IPPROTO_TCP, TCP_USER_TIMEOUT,
                        &output_user_timeout_ms, &optlen);
    EXPECT_EQ(result, 0) << "getsockopt failed for TCP_USER_TIMEOUT";
    EXPECT_EQ(optlen, sizeof(output_user_timeout_ms)) << "Unexpected parameter size";
    EXPECT_EQ(output_user_timeout_ms, user_timeout_ms) << "Unexpected timeout value";
}

TEST_F(tcp_set_get_sockopt, set_ipv6_ulp_nvme)
{
    const std::string option = "nvme";
    /* int result = setsockopt(m_ipv6_tcp_socket_fd, IPPROTO_TCP, TCP_ULP, "tls", */
    /*                         3); */
    int result =
        setsockopt(m_ipv6_tcp_socket_fd, IPPROTO_TCP, TCP_ULP, option.c_str(), option.length());
    ASSERT_EQ(result, 0) << "TCP_ULP is unsupported for TCP sockets";
}

TEST_F(tcp_set_get_sockopt, set_ipv4_ulp_nvme)
{
    const std::string option = "nvme";
    /* int result = setsockopt(m_ipv4_tcp_socket_fd, IPPROTO_TCP, TCP_ULP, "tls", */
    /*                         3); */
    int result =
        setsockopt(m_ipv4_tcp_socket_fd, IPPROTO_TCP, TCP_ULP, option.c_str(), option.length());
    ASSERT_EQ(result, 0) << "TCP_ULP is unsupported for TCP sockets";
}
