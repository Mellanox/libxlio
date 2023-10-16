/*
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

#include <fstream>
#include <limits>
#include <stdexcept>
#include <tuple>

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

#include "core/lwip/opt.h"
#include "core/xlio_extra.h"

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

/**
 * @test tcp_sockopt.ti_1_getsockopt_tcp_info
 * @brief
 *    getsockopt(TCP_INFO).
 * @details
 */
TEST_F(tcp_sockopt, ti_3_setsockopt_isolate)
{
    struct xlio_api_t *xlio_api = xlio_get_api();
    pid_t pid;

    SKIP_TRUE(xlio_api != NULL, "XLIO API not found. Run the test under XLIO.");
    SKIP_TRUE(server_addr.addr.sa_family == AF_INET && client_addr.addr.sa_family == AF_INET,
              "This test supports only IPv4");

    auto test_client = [&]() {
        char buf[64];
        sockaddr_store_t addr;
        sockaddr_store_t local_addr;
        ssize_t len;
        int sock;
        int sock2;
        int val = SO_XLIO_ISOLATE_SAFE;
        int valdef = SO_XLIO_ISOLATE_DEFAULT;
        int rc;

        sock = tcp_base::sock_create();
        ASSERT_LE(0, sock);
        sock2 = tcp_base::sock_create();
        ASSERT_LE(0, sock2);

        rc = setsockopt(sock, SOL_SOCKET, SO_XLIO_ISOLATE, &val, sizeof(val));
        ASSERT_EQ(0, rc);
        rc = setsockopt(sock, SOL_SOCKET, SO_XLIO_ISOLATE, &valdef, sizeof(valdef));
        ASSERT_EQ(-1, rc);
        ASSERT_EQ(EINVAL, errno);

        memcpy(&local_addr, &client_addr, sizeof(local_addr));
        sys_set_port((struct sockaddr *)&local_addr, 0);
        rc = bind(sock, (struct sockaddr *)&local_addr, sizeof(local_addr));
        ASSERT_EQ(0, rc);
        rc = bind(sock2, (struct sockaddr *)&local_addr, sizeof(local_addr));
        ASSERT_EQ(0, rc);

        memcpy(&addr, &server_addr, sizeof(addr));
        sys_set_port((struct sockaddr *)&addr, 8080);
        rc = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        ASSERT_EQ(0, rc);

        sys_set_port((struct sockaddr *)&addr, 8081);
        rc = connect(sock2, (struct sockaddr *)&addr, sizeof(addr));
        ASSERT_EQ(0, rc);

        rc = setsockopt(sock2, SOL_SOCKET, SO_XLIO_ISOLATE, &val, sizeof(val));
        ASSERT_EQ(-1, rc);
        ASSERT_EQ(EINVAL, errno);

        int xlio_ring_fds[3];
        int xlio_ring_fds2[3];
        rc = xlio_api->get_socket_rings_fds(sock, xlio_ring_fds, ARRAY_SIZE(xlio_ring_fds));
        ASSERT_EQ(1, rc);
        rc = xlio_api->get_socket_rings_fds(sock2, xlio_ring_fds2, ARRAY_SIZE(xlio_ring_fds2));
        ASSERT_EQ(1, rc);
        ASSERT_NE(xlio_ring_fds[0], xlio_ring_fds2[0]);

        len = write(sock, HELLO_STR, sizeof(HELLO_STR));
        ASSERT_LT(0, len);
        EXPECT_EQ(static_cast<ssize_t>(sizeof(HELLO_STR)), len);

        do {
            len = read(sock, buf, sizeof(buf));
        } while (len == -1 && errno == EINTR);
        ASSERT_LT(0, len);
        EXPECT_LE(static_cast<ssize_t>(sizeof(HELLO_STR)), len);
        EXPECT_EQ(0, strncmp(HELLO_STR, buf, sizeof(HELLO_STR)));

        usleep(100);

        rc = close(sock);
        ASSERT_EQ(0, rc);
        rc = close(sock2);
        ASSERT_EQ(0, rc);
    };

    auto test_server = [&]() {
        char buf[64];
        sockaddr_store_t addr;
        sockaddr_store_t peer_addr;
        socklen_t socklen;
        ssize_t len;
        int sock;
        int sock2;
        int sock3;
        int sock_in;
        int sock_in2;
        int val = SO_XLIO_ISOLATE_SAFE;
        int rc;

        /*
         * Socket create
         */

        sock = tcp_base::sock_create();
        ASSERT_LE(0, sock);
        sock2 = tcp_base::sock_create();
        ASSERT_LE(0, sock2);
        sock3 = tcp_base::sock_create();
        ASSERT_LE(0, sock3);

        rc = setsockopt(sock, SOL_SOCKET, SO_XLIO_ISOLATE, &val, sizeof(val));
        ASSERT_EQ(0, rc);

        /*
         * Socket bind
         */

        memcpy(&addr, &server_addr, sizeof(addr));
        sys_set_port((struct sockaddr *)&addr, 8080);
        rc = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
        ASSERT_EQ(0, rc);

        sys_set_port((struct sockaddr *)&addr, 8081);
        rc = bind(sock2, (struct sockaddr *)&addr, sizeof(addr));
        ASSERT_EQ(0, rc);

        sys_set_port((struct sockaddr *)&addr, 8082);
        rc = bind(sock3, (struct sockaddr *)&addr, sizeof(addr));
        ASSERT_EQ(0, rc);

        rc = setsockopt(sock2, SOL_SOCKET, SO_XLIO_ISOLATE, &val, sizeof(val));
        ASSERT_EQ(0, rc);

        /*
         * Socket listen
         */

        rc = listen(sock, 5);
        ASSERT_EQ(0, rc);

        rc = listen(sock2, 5);
        ASSERT_EQ(0, rc);

        rc = listen(sock3, 5);
        ASSERT_EQ(0, rc);

        rc = setsockopt(sock3, SOL_SOCKET, SO_XLIO_ISOLATE, &val, sizeof(val));
        ASSERT_EQ(-1, rc);
        ASSERT_EQ(EINVAL, errno);

        /*
         * Check rings
         */

        int xlio_ring_fds[3];
        int xlio_ring_fds2[3];
        int xlio_ring_fds3[3];
        rc = xlio_api->get_socket_rings_fds(sock, xlio_ring_fds, ARRAY_SIZE(xlio_ring_fds));
        ASSERT_EQ(1, rc);
        rc = xlio_api->get_socket_rings_fds(sock2, xlio_ring_fds2, ARRAY_SIZE(xlio_ring_fds2));
        ASSERT_EQ(1, rc);
        rc = xlio_api->get_socket_rings_fds(sock3, xlio_ring_fds3, ARRAY_SIZE(xlio_ring_fds3));
        ASSERT_EQ(1, rc);
        ASSERT_EQ(xlio_ring_fds[0], xlio_ring_fds2[0]);
        ASSERT_NE(xlio_ring_fds[0], xlio_ring_fds3[0]);

        // Notify client to proceed with connect()
        barrier_fork(pid);

        /*
         * Socket accept
         */

        do {
            socklen = sizeof(peer_addr);
            sock_in = accept(sock, (struct sockaddr *)&peer_addr, &socklen);
        } while (sock_in == -1 && errno == EINTR);
        ASSERT_LE(0, sock_in);
        log_trace("Accepted connection: fd=%d from %s\n", sock_in,
                  sys_addr2str((struct sockaddr *)&peer_addr));

        do {
            socklen = sizeof(peer_addr);
            sock_in2 = accept(sock2, (struct sockaddr *)&peer_addr, &socklen);
        } while (sock_in2 == -1 && errno == EINTR);
        ASSERT_LE(0, sock_in2);
        log_trace("Accepted connection: fd=%d from %s\n", sock_in2,
                  sys_addr2str((struct sockaddr *)&peer_addr));

        rc = xlio_api->get_socket_rings_fds(sock_in, xlio_ring_fds2, ARRAY_SIZE(xlio_ring_fds2));
        ASSERT_EQ(1, rc);
        rc = xlio_api->get_socket_rings_fds(sock_in2, xlio_ring_fds3, ARRAY_SIZE(xlio_ring_fds3));
        ASSERT_EQ(1, rc);
        // Incoming TCP sockets inherit ring allocation logic from their parents
        ASSERT_EQ(xlio_ring_fds[0], xlio_ring_fds2[0]);
        ASSERT_EQ(xlio_ring_fds[0], xlio_ring_fds3[0]);

        /*
         * Socket read / write
         */

        len = write(sock_in, HELLO_STR, sizeof(HELLO_STR));
        ASSERT_LT(0, len);
        EXPECT_EQ(static_cast<ssize_t>(sizeof(HELLO_STR)), len);

        do {
            len = read(sock_in, buf, sizeof(buf));
        } while (len == -1 && errno == EINTR);
        ASSERT_LT(0, len);
        EXPECT_LE(static_cast<ssize_t>(sizeof(HELLO_STR)), len);
        EXPECT_EQ(0, strncmp(HELLO_STR, buf, sizeof(HELLO_STR)));

        /*
         * Socket close
         */

        usleep(100);

        rc = close(sock_in);
        ASSERT_EQ(0, rc);
        rc = close(sock_in2);
        ASSERT_EQ(0, rc);
        rc = close(sock);
        ASSERT_EQ(0, rc);
        rc = close(sock2);
        ASSERT_EQ(0, rc);
        rc = close(sock3);
        ASSERT_EQ(0, rc);
    };

    pid = fork();
    if (0 == pid) { /* I am the child */
        barrier_fork(pid);
        test_client();
        /* This exit is very important, otherwise the fork
         * keeps running and may duplicate other tests.
         */
        exit(testing::Test::HasFailure());
    } else { /* I am the parent */
        test_server();
        if (testing::Test::HasFailure()) {
            usleep(500);
            kill(pid, SIGTERM);
        }
        ASSERT_EQ(0, wait_fork(pid));
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

struct reusable_cleanable_test_socket {
    int m_fd;
    reusable_cleanable_test_socket(int domain, int type, int protocol)
    {
        m_fd = socket(domain, type, protocol);
        EXPECT_GE(m_fd, 0) << "Unable to open the socket";
        int reuse = 1;
        auto result = setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        EXPECT_EQ(result, 0) << "setsockopt failed to set reuse addr";

        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(m_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    explicit reusable_cleanable_test_socket(int fd)
        : m_fd {fd}
    {
        EXPECT_GE(m_fd, 0) << "Unable to open the socket";
    };
    ~reusable_cleanable_test_socket() { close(m_fd); }

    operator int() const { return m_fd; }
};

struct ipc {
    enum FifoDirection : size_t { ReadSide, WriteSide };
    int m_pipe[2];
    ipc()
        : m_pipe {-1, -1}
    {
    }

    ~ipc() { reset(); }
    void create()
    {
        if (pipe(m_pipe) != 0) {
            throw std::runtime_error("Pipe not created");
        }
    }
    void reset()
    {
        if (m_pipe[ReadSide] != -1) {
            close(m_pipe[ReadSide]);
        }
        if (m_pipe[WriteSide] != -1) {
            close(m_pipe[WriteSide]);
        }
    }
    bool wait_peer()
    {
        if (m_pipe[ReadSide] == -1) {
            return false;
        }

        if (m_pipe[WriteSide] != -1) {
            if (close(m_pipe[WriteSide]) != 0) {
                return false;
            }
            m_pipe[WriteSide] = -1;
        }

        char buffer[16];
        auto result = read(m_pipe[ReadSide], buffer, 1) == 1;
        return result;
    }

    bool signal_to_peer()
    {
        if (m_pipe[WriteSide] == -1) {
            return false;
        }

        if (m_pipe[ReadSide] != -1) {
            if (close(m_pipe[ReadSide]) != 0) {
                return false;
            }
            m_pipe[ReadSide] = -1;
        }

        return write(m_pipe[WriteSide], "X", 1) == 1;
    }
};

using sockopt_parameters = std::tuple<int, int, int, int>;
using tcp_sockopt_positive = testing::TestWithParam<sockopt_parameters>;
/*
 * @test tcp_sockopt_positive.set_and_get_value
 * @brief
 *    This is a parameterized test requiring sockopt_parameters. The parameters in the
 *    sockopt_parameters are the socket domain, setsockopt/getsockopt level, optname,
 *    and value.
 *    The test sets the value and checks the value with the setsockopt/getsockopt syscalls.
 * @details
 */
TEST_P(tcp_sockopt_positive, set_and_get_value)
{
    int socket_domain, level, optname, value;
    std::tie(socket_domain, level, optname, value) = GetParam();

    auto fd = reusable_cleanable_test_socket(socket_domain, static_cast<int>(SOCK_STREAM), 0);
    EXPECT_GE(fd, 0) << "socket syscall failed";
    auto result = setsockopt(fd, level, optname, &value, sizeof(value));
    EXPECT_EQ(result, 0) << "setsockopt failed to set the value";

    int actual_value = -1;
    socklen_t actual_len = sizeof(actual_value);
    result = getsockopt(fd, level, optname, &actual_value, &actual_len);
    EXPECT_EQ(result, 0) << "getsockopt failed to get the value";
    EXPECT_EQ(actual_len, sizeof(actual_value)) << "Got unexpected size of agument";
    ASSERT_EQ(actual_value, value);
}

/* The valid ranges are dictated by the Linux Kernel and not the TCP RFC 9293
 * There may be multiple instantiations of the tcp_sockopt_positive class and
 * it's test cases.
 */
INSTANTIATE_TEST_CASE_P(
    keep_alive, tcp_sockopt_positive,
    testing::Values(
#if LWIP_TCP_KEEPALIVE
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPINTVL, 1),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPINTVL, std::numeric_limits<int16_t>::max()),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPCNT, 1),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPCNT, std::numeric_limits<int8_t>::max()),
#endif
        std::make_tuple(AF_INET, SOL_SOCKET, SO_KEEPALIVE, 1),
        std::make_tuple(AF_INET, SOL_SOCKET, SO_KEEPALIVE, 0),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPIDLE, 1),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPIDLE, std::numeric_limits<int16_t>::max()),
#if LWIP_TCP_KEEPALIVE
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPINTVL, 1),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPINTVL, std::numeric_limits<int16_t>::max()),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPCNT, 1),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPCNT, std::numeric_limits<int8_t>::max()),
#endif
        std::make_tuple(AF_INET6, SOL_SOCKET, SO_KEEPALIVE, 1),
        std::make_tuple(AF_INET6, SOL_SOCKET, SO_KEEPALIVE, 0),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPIDLE, 1),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPIDLE, std::numeric_limits<int16_t>::max())));

using tcp_setsockopt_negative = testing::TestWithParam<sockopt_parameters>;
/*
 * @test tcp_setsockopt_negative.set_invalid_value
 * @brief
 *    This is a parameterized test requiring sockopt_parameters. The parameters in the
 *    sockopt_parameters are the socket domain, setsockopt/getsockopt level, optname,
 *    and value.
 *    The test attempts setting an invalid value via setsockopt syscall.
 * @details
 */
TEST_P(tcp_setsockopt_negative, set_invalid_value)
{
    int socket_domain, level, optname, value;
    std::tie(socket_domain, level, optname, value) = GetParam();

    auto fd = reusable_cleanable_test_socket(socket_domain, SOCK_STREAM, 0);
    EXPECT_GE(fd, 0) << "socket syscall failed to setup a socket";

    auto result = setsockopt(fd, level, optname, &value, sizeof(value));
    EXPECT_NE(result, 0) << "setsockopt didn't fail to set the value";
}

/* The valid ranges are dictated by the Linux Kernel and not the TCP RFC 9293
 * There may be multiple instantiations of the tcp_setsockopt_negative class and
 * it's test cases.
 */
INSTANTIATE_TEST_CASE_P(
    keep_alive, tcp_setsockopt_negative,
    testing::Values(
#if LWIP_TCP_KEEPALIVE
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPINTVL, -1),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPINTVL, 0),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPINTVL,
                        std::numeric_limits<int16_t>::max() + 1),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPCNT, -1),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPCNT, 0),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPCNT, std::numeric_limits<int8_t>::max() + 1),
#endif
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPIDLE, -1),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPIDLE,
                        std::numeric_limits<int16_t>::max() + 1),
#if LWIP_TCP_KEEPALIVE
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPINTVL, -1),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPINTVL, 0),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPINTVL,
                        std::numeric_limits<int16_t>::max() + 1),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPCNT, -1),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPCNT, 0),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPCNT, std::numeric_limits<int8_t>::max() + 1),
#endif
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPIDLE, -1),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPIDLE,
                        std::numeric_limits<int16_t>::max() + 1)));

using getscokopt_params = std::tuple<int, int, int, const char *>;
using tcp_sockopt_default = testing::TestWithParam<getscokopt_params>;
/*
 * @test tcp_sockopt_default.matches_the_value_in_the_file
 * @brief
 *    This is a parameterized test requiring sockopt_parameters. The parameters in the
 *    sockopt_parameters are the socket domain, setsockopt/getsockopt level, optname,
 *    and file path containing the default value.
 *    The test verifies that the default value of a newly creates socket match file.
 * @details
 */
TEST_P(tcp_sockopt_default, matches_the_value_in_the_file)
{
    int socket_domain, level, optname;
    const char *file_path;
    std::tie(socket_domain, level, optname, file_path) = GetParam();

    auto fd = reusable_cleanable_test_socket(socket_domain, SOCK_STREAM, 0);
    EXPECT_GE(fd, 0) << "socket syscall failed to setup a socket";

    /* Get the value via getsockopt */
    int getsockopt_value = -1;
    socklen_t actual_len = sizeof(getsockopt_value);
    auto result = getsockopt(fd, level, optname, &getsockopt_value, &actual_len);
    EXPECT_EQ(result, 0) << "getsockopt failed";
    EXPECT_EQ(actual_len, sizeof(getsockopt_value)) << "Got unexpected size of agument";

    /* Get the value from the file */
    int file_value = -1;
    EXPECT_TRUE(bool(std::ifstream {file_path} >> file_value)) << "Failed reading the file";

    ASSERT_EQ(getsockopt_value, file_value) << "The values in the file and the getsockopt differ";
    close(fd);
}

INSTANTIATE_TEST_CASE_P(keep_alive, tcp_sockopt_default,
                        testing::Values(
#if LWIP_TCP_KEEPALIVE
                            std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPINTVL,
                                            "/proc/sys/net/ipv4/tcp_keepalive_intvl"),
                            std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPCNT,
                                            "/proc/sys/net/ipv4/tcp_keepalive_probes"),
                            std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPINTVL,
                                            "/proc/sys/net/ipv4/tcp_keepalive_intvl"),
                            std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPCNT,
                                            "/proc/sys/net/ipv4/tcp_keepalive_probes"),
#endif
                            std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPIDLE,
                                            "/proc/sys/net/ipv4/tcp_keepalive_time"),
                            std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPIDLE,
                                            "/proc/sys/net/ipv4/tcp_keepalive_time")));

using setsockopt_param = std::tuple<int, int, int>;
class tcp_with_fifo : public testing::TestWithParam<setsockopt_param> {
protected:
    ipc m_ipc_server_to_client {};

    void SetUp() override { m_ipc_server_to_client.create(); }

    void TearDown() override { m_ipc_server_to_client.reset(); }
};

/*
 * @test tcp_with_fifo.set_listen_get_accept_socket
 * @brief
 *    This is a parameterized test requiring sockopt_parameters. The parameters in the
 *    sockopt_parameters are the socket domain, setsockopt level, optname, and value.
 *    The test verifies that the set value is inherited by the accepted socket.
 * @details
 */
TEST_P(tcp_with_fifo, accepted_socket_inherits_the_setsockopt_param)
{
    SKIP_TRUE(!getenv("XLIO_TCP_CTL_THREAD"), "Skip non default XLIO_TCP_CTL_THREAD");

    int level, optname, value;
    std::tie(level, optname, value) = GetParam();
    pid_t pid = fork();

    if (pid > 0) { // Parent process (the "server" process)

        auto family = ((struct sockaddr *)&gtest_conf.server_addr)->sa_family;
        auto listen_fd = reusable_cleanable_test_socket(family, SOCK_STREAM, 0);
        EXPECT_GE(listen_fd, 0) << "socket syscall failed to setup a socket";

        EXPECT_EQ(bind(listen_fd, (struct sockaddr *)&gtest_conf.server_addr,
                       sizeof(gtest_conf.server_addr)),
                  0);
        EXPECT_EQ(listen(listen_fd, 5), 0);

        auto result = setsockopt(listen_fd, level, optname, &value, sizeof(value));
        EXPECT_EQ(result, 0) << "setsockopt failed to set the value";

        m_ipc_server_to_client.signal_to_peer();

        reusable_cleanable_test_socket accepted_fd {accept(listen_fd, nullptr, 0)};
        EXPECT_GE(accepted_fd, 0) << "Invalid accepted_fd";

        int actual_value = -1;
        socklen_t actual_len = sizeof(actual_value);
        result = getsockopt(accepted_fd, level, optname, &actual_value, &actual_len);
        m_ipc_server_to_client.signal_to_peer();

        int status;
        EXPECT_EQ(pid, waitpid(pid, &status, 0));
        EXPECT_TRUE(WIFEXITED(status));
        EXPECT_EQ(result, 0) << "getsockopt failed to get the value";
        EXPECT_EQ(actual_len, sizeof(actual_value)) << "Got unexpected size of agument";

        ASSERT_EQ(actual_value, value);
    } else if (pid == 0) { // Child process (the "client" process)
        auto family = ((struct sockaddr *)&gtest_conf.server_addr)->sa_family;
        auto client_fd = reusable_cleanable_test_socket(family, SOCK_STREAM, 0);
        EXPECT_GE(client_fd, 0) << "socket syscall failed to setup a socket";
        EXPECT_EQ(bind(client_fd, (struct sockaddr *)&gtest_conf.client_addr,
                       sizeof(gtest_conf.client_addr)),
                  0);
        m_ipc_server_to_client.wait_peer();

        auto result = connect(client_fd, (struct sockaddr *)&gtest_conf.server_addr,
                              sizeof(gtest_conf.server_addr));
        EXPECT_EQ(result, 0);

        m_ipc_server_to_client.wait_peer();

        // This exit stops the process from inerfering with other tests.
        exit(testing::Test::HasFailure());
    } else {
        FAIL() << "Fork failed";
    }
}

INSTANTIATE_TEST_CASE_P(keep_alive, tcp_with_fifo,
                        testing::Values(
#if LWIP_TCP_KEEPALIVE
                            std::make_tuple(static_cast<int>(IPPROTO_TCP), TCP_KEEPINTVL, 12345),
                            std::make_tuple(static_cast<int>(IPPROTO_TCP), TCP_KEEPCNT, 123),
#endif
                            std::make_tuple(SOL_SOCKET, SO_KEEPALIVE, 0),
                            std::make_tuple(SOL_SOCKET, SO_KEEPALIVE, 1),
                            std::make_tuple(static_cast<int>(IPPROTO_TCP), TCP_KEEPIDLE, 1234)));
