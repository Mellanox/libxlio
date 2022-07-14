/*
 * Copyright (c) 2001-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
