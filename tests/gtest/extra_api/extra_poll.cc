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
#include "common/cmn.h"

#include "tcp/tcp_base.h"
#include "udp/udp_base.h"
#include "core/xlio_base.h"

#if defined(EXTRA_API_ENABLED) && (EXTRA_API_ENABLED == 1)

class socketxtreme_poll : public xlio_base {
protected:
    void SetUp()
    {
        xlio_base::SetUp();

        SKIP_TRUE((getenv("XLIO_SOCKETXTREME")), "This test requires XLIO_SOCKETXTREME=1");
        SKIP_TRUE(m_family == PF_INET, "sockextreme API supports IPv4 only");
    }
    void TearDown() { xlio_base::TearDown(); }

    uint64_t timestamp_ms()
    {
        struct timespec ts;
        int rc = clock_gettime(CLOCK_MONOTONIC, &ts);
        return rc != 0 ? 0LU : ts.tv_sec * 1000LU + ts.tv_nsec / 1000000LU;
    }
    bool timestamp_ms_elapsed(uint64_t start_ts, uint64_t timeout)
    {
        struct timespec ts;
        int rc = clock_gettime(CLOCK_MONOTONIC, &ts);
        return rc != 0 ? false : (ts.tv_sec * 1000LU + ts.tv_nsec / 1000000LU - start_ts > timeout);
    }

    tcp_base_sock m_tcp_base;
    udp_base_sock m_udp_base;
};

/**
 * @test socketxtreme_poll.ti_1
 * @brief
 *    Check TCP connection acceptance (XLIO_SOCKETXTREME_NEW_CONNECTION_ACCEPTED)
 * @details
 */
TEST_F(socketxtreme_poll, ti_1)
{
    int rc = EOK;
    int fd;

    errno = EOK;

    int pid = fork();

    if (0 == pid) { /* I am the child */
        barrier_fork(pid);

        fd = m_tcp_base.sock_create_fa_nb(m_family);
        ASSERT_LE(0, fd);

        rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
        ASSERT_EQ(0, rc);

        rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(EINPROGRESS, errno);
        ASSERT_EQ((-1), rc);

        // Wait for connect to complete.
        struct xlio_socketxtreme_completion_t xlio_comps;
        int xlio_ring_fd[2] = {-1, -1};
        rc = xlio_api->get_socket_rings_fds(fd, xlio_ring_fd, 2);
        ASSERT_LE(1, rc);

        rc = 0;
        while (rc == 0) {
            if (xlio_ring_fd[0] > 0) {
                rc = xlio_api->socketxtreme_poll(xlio_ring_fd[0], &xlio_comps, 1, 0);
                ASSERT_LE(0, rc);
                if (rc > 0) {
                    ASSERT_LT(0U, (xlio_comps.events & EPOLLOUT));
                    break;
                }
            }

            if (xlio_ring_fd[1] > 0) {
                rc = xlio_api->socketxtreme_poll(xlio_ring_fd[1], &xlio_comps, 1, 0);
                ASSERT_LE(0, rc);
                if (rc > 0) {
                    ASSERT_LT(0U, (xlio_comps.events & EPOLLOUT));
                }
            }
        }

        log_trace("Established connection: fd=%d to %s\n", fd,
                  sys_addr2str((struct sockaddr *)&server_addr));

        close(fd);

        /* This exit is very important, otherwise the fork
         * keeps running and may duplicate other tests.
         */
        exit(testing::Test::HasFailure());
    } else { /* I am the parent */
        int _xlio_ring_fd = -1;
        struct xlio_socketxtreme_completion_t xlio_comps;
        int fd_peer;
        struct sockaddr peer_addr;

        fd = m_tcp_base.sock_create_fa_nb(m_family);
        ASSERT_LE(0, fd);

        rc = bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        CHECK_ERR_OK(rc);

        rc = listen(fd, 5);
        CHECK_ERR_OK(rc);

        rc = xlio_api->get_socket_rings_fds(fd, &_xlio_ring_fd, 1);
        ASSERT_EQ(1, rc);
        ASSERT_LE(0, _xlio_ring_fd);

        barrier_fork(pid);
        rc = 0;
        while (rc == 0 && !child_fork_exit()) {
            rc = xlio_api->socketxtreme_poll(_xlio_ring_fd, &xlio_comps, 1, 0);
            if (rc > 0 && xlio_comps.events & XLIO_SOCKETXTREME_NEW_CONNECTION_ACCEPTED) {
                EXPECT_EQ(fd, (int)xlio_comps.listen_fd);
                fd_peer = (int)xlio_comps.user_data;
                EXPECT_LE(0, fd_peer);
                memcpy(&peer_addr, &xlio_comps.src, sizeof(peer_addr));
                log_trace("Accepted connection: fd=%d from %s\n", fd_peer,
                          sys_addr2str((struct sockaddr *)&peer_addr));
                rc = 0;
            }
        }

        close(fd_peer);
        close(fd);

        ASSERT_EQ(0, wait_fork(pid));
        sleep(1U); // XLIO timers to clean fd.
    }
}

/**
 * @test socketxtreme_poll.ti_2
 * @brief
 *    Check TCP connection data receiving (XLIO_SOCKETXTREME_PACKET)
 * @details
 */
TEST_F(socketxtreme_poll, ti_2)
{
    int rc = EOK;
    int fd;
    char msg[] = "Hello";

    errno = EOK;

    int pid = fork();

    if (0 == pid) { /* I am the child */
        barrier_fork(pid);

        fd = m_tcp_base.sock_create_fa(m_family);
        ASSERT_LE(0, fd);

        rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
        ASSERT_EQ(0, rc);

        rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        log_trace("Established connection: fd=%d to %s\n", fd,
                  sys_addr2str((struct sockaddr *)&server_addr));

        rc = send(fd, (void *)msg, sizeof(msg), 0);
        EXPECT_EQ(static_cast<int>(sizeof(msg)), rc);

        close(fd);

        /* This exit is very important, otherwise the fork
         * keeps running and may duplicate other tests.
         */
        exit(testing::Test::HasFailure());
    } else { /* I am the parent */
        int _xlio_ring_fd = -1;
        struct xlio_socketxtreme_completion_t xlio_comps;
        int fd_peer;
        struct sockaddr peer_addr;

        fd = m_tcp_base.sock_create_fa_nb(m_family);
        ASSERT_LE(0, fd);

        rc = bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        CHECK_ERR_OK(rc);

        rc = listen(fd, 5);
        CHECK_ERR_OK(rc);

        rc = xlio_api->get_socket_rings_fds(fd, &_xlio_ring_fd, 1);
        ASSERT_EQ(1, rc);
        ASSERT_LE(0, _xlio_ring_fd);

        barrier_fork(pid);
        rc = 0;
        while (rc == 0 && !child_fork_exit()) {
            rc = xlio_api->socketxtreme_poll(_xlio_ring_fd, &xlio_comps, 1, 0);
            if (rc == 0) {
                continue;
            }
            if ((xlio_comps.events & EPOLLERR) || (xlio_comps.events & EPOLLHUP) ||
                (xlio_comps.events & EPOLLRDHUP)) {
                log_trace("Close connection: fd=%d event: 0x%lx\n", (int)xlio_comps.user_data,
                          xlio_comps.events);
                rc = 0;
                break;
            }
            if (xlio_comps.events & XLIO_SOCKETXTREME_NEW_CONNECTION_ACCEPTED) {
                EXPECT_EQ(fd, (int)xlio_comps.listen_fd);
                fd_peer = (int)xlio_comps.user_data;
                EXPECT_LE(0, fd_peer);
                memcpy(&peer_addr, &xlio_comps.src, sizeof(peer_addr));
                log_trace("Accepted connection: fd=%d from %s\n", fd_peer,
                          sys_addr2str((struct sockaddr *)&peer_addr));
                rc = 0;
            }
            if (xlio_comps.events & XLIO_SOCKETXTREME_PACKET) {
                EXPECT_EQ(1U, xlio_comps.packet.num_bufs);
                EXPECT_LE(0, (int)xlio_comps.user_data);
                EXPECT_EQ(sizeof(msg), xlio_comps.packet.total_len);
                EXPECT_TRUE(xlio_comps.packet.buff_lst->payload);
                log_trace("Received data: fd=%d data: %s\n", (int)xlio_comps.user_data,
                          (char *)xlio_comps.packet.buff_lst->payload);
                rc = 0;
            }
        }

        close(fd_peer);
        close(fd);

        ASSERT_EQ(0, wait_fork(pid));
        sleep(1U); // XLIO timers to clean fd.
    }
}

/**
 * @test socketxtreme_poll.ti_3
 * @brief
 *    Check TCP connection data receiving (SO_XLIO_USER_DATA)
 * @details
 */
TEST_F(socketxtreme_poll, ti_3)
{
    int rc = EOK;
    int fd;
    char msg[] = "Hello";

    errno = EOK;

    int pid = fork();

    if (0 == pid) { /* I am the child */
        barrier_fork(pid);

        fd = m_tcp_base.sock_create_fa(m_family);
        ASSERT_LE(0, fd);

        rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
        ASSERT_EQ(0, rc);

        rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        log_trace("Established connection: fd=%d to %s\n", fd,
                  sys_addr2str((struct sockaddr *)&server_addr));

        rc = send(fd, (void *)msg, sizeof(msg), 0);
        EXPECT_EQ(static_cast<int>(sizeof(msg)), rc);

        close(fd);

        /* This exit is very important, otherwise the fork
         * keeps running and may duplicate other tests.
         */
        exit(testing::Test::HasFailure());
    } else { /* I am the parent */
        int _xlio_ring_fd = -1;
        struct xlio_socketxtreme_completion_t xlio_comps;
        int fd_peer = -1;
        struct sockaddr peer_addr;
        const char *user_data = "This is a data";

        fd = m_tcp_base.sock_create_fa_nb(m_family);
        ASSERT_LE(0, fd);

        rc = bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        CHECK_ERR_OK(rc);

        rc = listen(fd, 5);
        CHECK_ERR_OK(rc);

        rc = xlio_api->get_socket_rings_fds(fd, &_xlio_ring_fd, 1);
        ASSERT_EQ(1, rc);
        ASSERT_LE(0, _xlio_ring_fd);

        barrier_fork(pid);
        rc = 0;
        while (rc == 0 && !child_fork_exit()) {
            rc = xlio_api->socketxtreme_poll(_xlio_ring_fd, &xlio_comps, 1, 0);
            if (rc == 0) {
                continue;
            }
            if ((xlio_comps.events & EPOLLERR) || (xlio_comps.events & EPOLLHUP) ||
                (xlio_comps.events & EPOLLRDHUP)) {
                log_trace("Close connection: event: 0x%lx\n", xlio_comps.events);
                rc = 0;
                break;
            }
            if (xlio_comps.events & XLIO_SOCKETXTREME_NEW_CONNECTION_ACCEPTED) {
                EXPECT_EQ(fd, (int)xlio_comps.listen_fd);
                fd_peer = (int)xlio_comps.user_data;
                memcpy(&peer_addr, &xlio_comps.src, sizeof(peer_addr));
                log_trace("Accepted connection: fd: %d from %s\n", fd_peer,
                          sys_addr2str((struct sockaddr *)&peer_addr));

                errno = EOK;
                rc = setsockopt(fd_peer, SOL_SOCKET, SO_XLIO_USER_DATA, &user_data, sizeof(void *));
                EXPECT_EQ(0, rc);
                EXPECT_EQ(EOK, errno);
                log_trace("Set data: %p\n", user_data);
                rc = 0;
            }
            if (xlio_comps.events & XLIO_SOCKETXTREME_PACKET) {
                EXPECT_EQ(1U, xlio_comps.packet.num_bufs);
                EXPECT_EQ((uintptr_t)user_data, (uintptr_t)xlio_comps.user_data);
                EXPECT_EQ(sizeof(msg), xlio_comps.packet.total_len);
                EXPECT_TRUE(xlio_comps.packet.buff_lst->payload);
                log_trace("Received data: user_data: %p data: %s\n",
                          (void *)((uintptr_t)xlio_comps.user_data),
                          (char *)xlio_comps.packet.buff_lst->payload);
                rc = 0;
            }
        }

        close(fd_peer);
        close(fd);

        ASSERT_EQ(0, wait_fork(pid));
        sleep(1U); // XLIO timers to clean fd.
    }
}

/**
 * @test socketxtreme_poll.ti_4_socket_isolation
 * @brief
 *    Check TCP connection data receiving on isolated socket (SO_XLIO_ISOLATE_SAFE)
 * @details
 */
TEST_F(socketxtreme_poll, ti_4_socket_isolation)
{
    int rc = EOK;
    int fd;
    int optval = SO_XLIO_ISOLATE_SAFE;
    bool received_data = false;
    char msg[] = "Hello";

    int ring_fd[3] = {-1, -1, -1};
    int peer_ring_fd[3] = {-1, -1, -1};
    int ring_fd_nr;
    int peer_ring_fd_nr = 0;
    struct xlio_socketxtreme_completion_t xlio_comps;
    int fd_peer = -1;
    struct sockaddr peer_addr;

    auto poll_rings = [&](int *rings, int rings_nr) {
        for (int i = 0; i < rings_nr; ++i) {
            rc = xlio_api->socketxtreme_poll(rings[i], &xlio_comps, 1, SOCKETXTREME_POLL_TX);
            if (rc == 0) {
                continue;
            }
            if ((xlio_comps.events & EPOLLERR) || (xlio_comps.events & EPOLLHUP) ||
                (xlio_comps.events & EPOLLRDHUP)) {
                log_trace("Close connection: event: 0x%lx\n", xlio_comps.events);
                rc = -1;
                return;
            }
            if (xlio_comps.events & XLIO_SOCKETXTREME_NEW_CONNECTION_ACCEPTED) {
                EXPECT_EQ(fd, (int)xlio_comps.listen_fd);
                fd_peer = (int)xlio_comps.user_data;
                memcpy(&peer_addr, &xlio_comps.src, sizeof(peer_addr));
                log_trace("Accepted connection: fd: %d from %s\n", fd_peer,
                          sys_addr2str((struct sockaddr *)&peer_addr));

                rc = xlio_api->get_socket_rings_num(fd);
                ASSERT_GE((int)ARRAY_SIZE(peer_ring_fd), rc);

                peer_ring_fd_nr =
                    xlio_api->get_socket_rings_fds(fd_peer, peer_ring_fd, ARRAY_SIZE(peer_ring_fd));
                ASSERT_LT(0, peer_ring_fd_nr);

                rc = send(fd_peer, (void *)msg, sizeof(msg), 0);
                EXPECT_EQ(static_cast<int>(sizeof(msg)), rc);
            }
            if (xlio_comps.events & XLIO_SOCKETXTREME_PACKET) {
                EXPECT_EQ(1U, xlio_comps.packet.num_bufs);
                EXPECT_EQ(sizeof(msg), xlio_comps.packet.total_len);
                EXPECT_TRUE(xlio_comps.packet.buff_lst->payload);
                EXPECT_EQ(0,
                          strncmp(msg, (const char *)xlio_comps.packet.buff_lst->payload,
                                  xlio_comps.packet.total_len));
                log_trace("Received data: user_data: %p data: %s\n",
                          (void *)((uintptr_t)xlio_comps.user_data),
                          (char *)xlio_comps.packet.buff_lst->payload);
                received_data = true;
            }
        }
        rc = 0;
    };

    errno = EOK;

    pid_t pid = fork();

    if (0 == pid) { /* I am the child */
        barrier_fork(pid);

        fd = m_tcp_base.sock_create_fa(m_family);
        ASSERT_LE(0, fd);

        rc = setsockopt(fd, SOL_SOCKET, SO_XLIO_ISOLATE, &optval, sizeof(optval));
        ASSERT_EQ(0, rc);

        rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
        ASSERT_EQ(0, rc);

        rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        log_trace("Established connection: fd=%d to %s\n", fd,
                  sys_addr2str((struct sockaddr *)&server_addr));

        rc = send(fd, (void *)msg, sizeof(msg), 0);
        EXPECT_EQ(static_cast<int>(sizeof(msg)), rc);

        rc = sock_noblock(fd);
        ASSERT_EQ(0, rc);

        rc = xlio_api->get_socket_rings_num(fd);
        ASSERT_GE((int)ARRAY_SIZE(ring_fd), rc);

        ring_fd_nr = xlio_api->get_socket_rings_fds(fd, ring_fd, ARRAY_SIZE(ring_fd));
        ASSERT_LT(0, ring_fd_nr);

        uint64_t ts = timestamp_ms();
        ASSERT_NE(0LU, ts);
        rc = 0;
        while (rc == 0 && !received_data && !testing::Test::HasFailure()) {
            poll_rings(ring_fd, ring_fd_nr);
            if (timestamp_ms_elapsed(ts, 500UL)) {
                log_trace("No data received by client within time limit\n");
                break;
            }
        }

        usleep(100);
        close(fd);

        EXPECT_EQ(true, received_data);

        /* This exit is very important, otherwise the fork
         * keeps running and may duplicate other tests.
         */
        exit(testing::Test::HasFailure());
    } else { /* I am the parent */
        fd = m_tcp_base.sock_create_fa_nb(m_family);
        ASSERT_LE(0, fd);

        rc = setsockopt(fd, SOL_SOCKET, SO_XLIO_ISOLATE, &optval, sizeof(optval));
        ASSERT_EQ(0, rc);

        rc = bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        CHECK_ERR_OK(rc);

        rc = listen(fd, 5);
        CHECK_ERR_OK(rc);

        rc = xlio_api->get_socket_rings_num(fd);
        ASSERT_GE((int)ARRAY_SIZE(ring_fd), rc);

        ring_fd_nr = xlio_api->get_socket_rings_fds(fd, ring_fd, ARRAY_SIZE(ring_fd));
        ASSERT_LT(0, ring_fd_nr);

        barrier_fork(pid);
        rc = 0;

        while (rc == 0 && !child_fork_exit() && !testing::Test::HasFailure()) {
            poll_rings(ring_fd, ring_fd_nr);
            if (peer_ring_fd_nr > 0 && rc == 0 && !testing::Test::HasFailure()) {
                poll_rings(peer_ring_fd, peer_ring_fd_nr);
            }
        }

        close(fd_peer);
        close(fd);

        EXPECT_EQ(true, received_data);
        ASSERT_EQ(0, wait_fork(pid));
    }
}

#endif /* EXTRA_API_ENABLED */
