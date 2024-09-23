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
#include "src/xlio/util/sock_addr.h"

#if defined(EXTRA_API_ENABLED) && (EXTRA_API_ENABLED == 1)

#include "tcp/tcp_base.h"
#include "udp/udp_base.h"
#include "xlio_base.h"

class xlio_tcp_recvfrom_zcopy : public xlio_base, public tcp_base {
protected:
    void SetUp()
    {
        uint64_t xlio_extra_api_cap =
            XLIO_EXTRA_API_RECVFROM_ZCOPY | XLIO_EXTRA_API_RECVFROM_ZCOPY_FREE_PACKETS;

        xlio_base::SetUp();
        tcp_base::SetUp();

        SKIP_TRUE((xlio_api->cap_mask & xlio_extra_api_cap) == xlio_extra_api_cap,
                  "This test requires XLIO capabilities as XLIO_EXTRA_API_RECVFROM_ZCOPY | "
                  "XLIO_EXTRA_API_RECVFROM_ZCOPY_FREE_PACKETS");

        m_fd = -1;
        m_test_buf = NULL;
        m_test_buf_size = 0;
    }
    void TearDown()
    {
        if (m_test_buf) {
            free_tmp_buffer(m_test_buf, m_test_buf_size);
        }

        tcp_base::TearDown();
        xlio_base::TearDown();
    }
    void *create_tmp_buffer(size_t size, int *alloc_size = NULL)
    {
        char *ptr = NULL;
        int page_size = 0x200000;
        size_t i = 0;

        size = (size + page_size - 1) & (~(page_size - 1));
        ptr = (char *)memalign(page_size, size);
        if (ptr) {
            for (i = 0; i < size; i++) {
                ptr[i] = 'a' + (i % ('z' - 'a' + 1));
            }
            if (alloc_size) {
                *alloc_size = size;
            }
        } else {
            ptr = NULL;
        }

        return ptr;
    }
    void free_tmp_buffer(void *ptr, size_t size)
    {
        UNREFERENCED_PARAMETER(size);
        free(ptr);
    }

protected:
    int m_fd;
    char *m_test_buf;
    int m_test_buf_size;

    udp_base_sock m_udp_base_sock;
};

/**
 * @test xlio_tcp_recvfrom_zcopy.ti_1
 * @brief
 *    Check for passing small receive buffer
 * @details
 */
TEST_F(xlio_tcp_recvfrom_zcopy, ti_1)
{
    int rc = EOK;
    char test_msg[] = "Hello test";

    m_test_buf = (char *)create_tmp_buffer(sizeof(test_msg));
    ASSERT_TRUE(m_test_buf);
    m_test_buf_size = sizeof(test_msg);

    memcpy(m_test_buf, test_msg, sizeof(test_msg));

    int pid = fork();

    if (0 == pid) { /* I am the child */
        struct epoll_event event;

        barrier_fork(pid);

        m_fd = tcp_base::sock_create();
        ASSERT_LE(0, m_fd);

        rc = bind(m_fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
        ASSERT_EQ(0, rc);

        rc = connect(m_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        log_trace("Established connection: fd=%d to %s\n", m_fd,
                  sys_addr2str((struct sockaddr *)&server_addr));

        rc = send(m_fd, (void *)m_test_buf, m_test_buf_size, MSG_DONTWAIT);
        EXPECT_EQ(m_test_buf_size, rc);

        event.events = EPOLLOUT;
        event.data.fd = m_fd;
        rc = test_base::event_wait(&event);
        EXPECT_LT(0, rc);
        EXPECT_TRUE(EPOLLOUT | event.events);

        peer_wait(m_fd);

        close(m_fd);

        /* This exit is very important, otherwise the fork
         * keeps running and may duplicate other tests.
         */
        exit(testing::Test::HasFailure());
    } else { /* I am the parent */
        int l_fd;
        struct sockaddr peer_addr;
        socklen_t socklen;
        int flags = 0;
        size_t xlio_header_size = sizeof(xlio_recvfrom_zcopy_packets_t) +
            sizeof(xlio_recvfrom_zcopy_packet_t) + sizeof(iovec);
        char buf[m_test_buf_size + xlio_header_size];

        l_fd = tcp_base::sock_create();
        ASSERT_LE(0, l_fd);

        rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        rc = listen(l_fd, 5);
        ASSERT_EQ(0, rc);

        barrier_fork(pid);

        socklen = sizeof(peer_addr);
        m_fd = accept(l_fd, &peer_addr, &socklen);
        ASSERT_LE(0, m_fd);
        close(l_fd);

        log_trace("Accepted connection: fd=%d from %s\n", m_fd,
                  sys_addr2str((struct sockaddr *)&peer_addr));

        rc = xlio_api->recvfrom_zcopy(m_fd, (void *)buf, xlio_header_size - 1, &flags, NULL, NULL);
        EXPECT_EQ(-1, rc);
        EXPECT_TRUE(ENOBUFS == errno);

        rc = xlio_api->recvfrom_zcopy(m_fd, (void *)buf, xlio_header_size, &flags, NULL, NULL);
        EXPECT_EQ(m_test_buf_size, rc);
        EXPECT_TRUE(flags & MSG_XLIO_ZCOPY);

        close(m_fd);

        ASSERT_EQ(0, wait_fork(pid));
    }
}

/**
 * @test xlio_tcp_recvfrom_zcopy.ti_2
 * @brief
 *    Exchange single buffer
 * @details
 */
TEST_F(xlio_tcp_recvfrom_zcopy, ti_2_recv_once)
{
    int rc = EOK;
    char test_msg[] = "Hello test";

    m_test_buf = (char *)create_tmp_buffer(sizeof(test_msg));
    ASSERT_TRUE(m_test_buf);
    m_test_buf_size = sizeof(test_msg);

    memcpy(m_test_buf, test_msg, sizeof(test_msg));

    int pid = fork();

    if (0 == pid) { /* I am the child */
        struct epoll_event event;

        barrier_fork(pid);

        m_fd = tcp_base::sock_create();
        ASSERT_LE(0, m_fd);

        rc = bind(m_fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
        ASSERT_EQ(0, rc);

        rc = connect(m_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        log_trace("Established connection: fd=%d to %s\n", m_fd,
                  sys_addr2str((struct sockaddr *)&server_addr));

        rc = send(m_fd, (void *)m_test_buf, m_test_buf_size, MSG_DONTWAIT);
        EXPECT_EQ(m_test_buf_size, rc);

        event.events = EPOLLOUT;
        event.data.fd = m_fd;
        rc = test_base::event_wait(&event);
        EXPECT_LT(0, rc);
        EXPECT_TRUE(EPOLLOUT | event.events);

        peer_wait(m_fd);

        close(m_fd);

        /* This exit is very important, otherwise the fork
         * keeps running and may duplicate other tests.
         */
        exit(testing::Test::HasFailure());
    } else { /* I am the parent */
        int l_fd;
        struct sockaddr peer_addr;
        socklen_t socklen;
        int flags = 0;
        char buf[m_test_buf_size + sizeof(xlio_recvfrom_zcopy_packets_t) +
                 sizeof(xlio_recvfrom_zcopy_packet_t) + sizeof(iovec)];
        struct xlio_recvfrom_zcopy_packets_t *xlio_packets;
        struct xlio_recvfrom_zcopy_packet_t *xlio_packet;

        l_fd = tcp_base::sock_create();
        ASSERT_LE(0, l_fd);

        rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        rc = listen(l_fd, 5);
        ASSERT_EQ(0, rc);

        barrier_fork(pid);

        socklen = sizeof(peer_addr);
        m_fd = accept(l_fd, &peer_addr, &socklen);
        ASSERT_LE(0, m_fd);
        close(l_fd);

        log_trace("Accepted connection: fd=%d from %s\n", m_fd,
                  sys_addr2str((struct sockaddr *)&peer_addr));

        rc = xlio_api->recvfrom_zcopy(m_fd, (void *)buf, sizeof(buf), &flags, NULL, NULL);
        EXPECT_EQ(m_test_buf_size, rc);
        EXPECT_TRUE(flags & MSG_XLIO_ZCOPY);
        xlio_packets = (struct xlio_recvfrom_zcopy_packets_t *)buf;
        EXPECT_EQ(1U, xlio_packets->n_packet_num);
        xlio_packet =
            (struct xlio_recvfrom_zcopy_packet_t *)(buf +
                                                    sizeof(struct xlio_recvfrom_zcopy_packets_t));
        EXPECT_EQ(1U, xlio_packet->sz_iov);
        EXPECT_EQ(static_cast<size_t>(m_test_buf_size), xlio_packet->iov[0].iov_len);

        log_trace("Test check: expected: '%s' actual: '%s'\n", m_test_buf,
                  (char *)xlio_packet->iov[0].iov_base);

        EXPECT_EQ(memcmp(xlio_packet->iov[0].iov_base, m_test_buf, m_test_buf_size), 0);

        rc = xlio_api->recvfrom_zcopy_free_packets(m_fd, xlio_packets->pkts,
                                                   xlio_packets->n_packet_num);
        EXPECT_EQ(0, rc);

        close(m_fd);

        ASSERT_EQ(0, wait_fork(pid));
    }
}

/**
 * @test xlio_tcp_recvfrom_zcopy.ti_3
 * @brief
 *    Exchange large data
 * @details
 */
TEST_F(xlio_tcp_recvfrom_zcopy, ti_3_large_data)
{
    int rc = EOK;
    struct {
        int buf_size;
    } test_scenario[] = {{1024}, {8192}, {12288}, {4096}, {1869}, {40960}};
    int i = 0;

    for (i = 0; (i < (int)(sizeof(test_scenario) / sizeof(test_scenario[0]))); i++) {
        int test_buf_size = test_scenario[i].buf_size;
        char *test_buf = (char *)create_tmp_buffer(test_buf_size);
        ASSERT_TRUE(test_buf);

        log_trace("Test case [%d]: data size: %d\n", i, test_buf_size);
        sys_set_port((struct sockaddr *)&server_addr, m_port + i);

        int pid = fork();
        if (0 == pid) { /* I am the child */
            int opt_val = 1;
            struct iovec vec[1];
            struct msghdr msg;

            barrier_fork(pid);

            m_fd = tcp_base::sock_create();
            ASSERT_LE(0, m_fd);

            opt_val = 1 << 21;
            rc = setsockopt(m_fd, SOL_SOCKET, SO_SNDBUF, &opt_val, sizeof(opt_val));
            ASSERT_EQ(0, rc);

            rc = bind(m_fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
            ASSERT_EQ(0, rc);

            rc = connect(m_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            ASSERT_EQ(0, rc);

            log_trace("Established connection: fd=%d to %s\n", m_fd,
                      sys_addr2str((struct sockaddr *)&server_addr));

            vec[0].iov_base = (void *)test_buf;
            vec[0].iov_len = test_buf_size;

            memset(&msg, 0, sizeof(struct msghdr));
            msg.msg_iov = vec;
            msg.msg_iovlen = sizeof(vec) / sizeof(vec[0]);
            rc = sendmsg(m_fd, &msg, MSG_DONTWAIT);
            EXPECT_EQ(static_cast<int>(vec[0].iov_len), rc);

            sleep(1);
            peer_wait(m_fd);

            close(m_fd);

            /* This exit is very important, otherwise the fork
             * keeps running and may duplicate other tests.
             */
            exit(testing::Test::HasFailure());
        } else { /* I am the parent */
            int l_fd;
            struct sockaddr peer_addr;
            socklen_t socklen;
            int flags = 0;
            char buf[1024];
            struct xlio_recvfrom_zcopy_packets_t *xlio_packets;
            struct xlio_recvfrom_zcopy_packet_t *xlio_packet;
            struct iovec *vec;
            int efd;
            struct epoll_event event;
            int total_len = 0;

            efd = epoll_create1(0);
            ASSERT_LE(0, efd);

            l_fd = tcp_base::sock_create();
            ASSERT_LE(0, l_fd);

            rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            ASSERT_EQ(0, rc);

            rc = listen(l_fd, 5);
            ASSERT_EQ(0, rc);

            barrier_fork(pid);

            socklen = sizeof(peer_addr);
            m_fd = accept(l_fd, &peer_addr, &socklen);
            ASSERT_LE(0, m_fd);
            close(l_fd);

            log_trace("Accepted connection: fd=%d from %s\n", m_fd,
                      sys_addr2str((struct sockaddr *)&peer_addr));

            rc = test_base::sock_noblock(m_fd);
            ASSERT_EQ(0, rc);

            event.data.fd = m_fd;
            event.events = EPOLLIN | EPOLLET;
            epoll_ctl(efd, EPOLL_CTL_ADD, m_fd, &event);

            while (!child_fork_exit() && (total_len < test_buf_size)) {
                if (epoll_wait(efd, &event, 1, -1)) {
                    if (event.events & EPOLLIN) {
                        char *ptr = buf;
                        int n = 0;
                        int j = 0;
                        int packet_len = 0;

                        rc = xlio_api->recvfrom_zcopy(m_fd, (void *)buf, sizeof(buf), &flags, NULL,
                                                      NULL);
                        EXPECT_LT(0, rc);
                        EXPECT_TRUE(flags & MSG_XLIO_ZCOPY);
                        total_len += rc;
                        xlio_packets = (struct xlio_recvfrom_zcopy_packets_t *)ptr;
                        for (n = 0; n < (int)xlio_packets->n_packet_num; n++) {
                            packet_len = 0;
                            ptr += sizeof(struct xlio_recvfrom_zcopy_packets_t);
                            xlio_packet = (struct xlio_recvfrom_zcopy_packet_t *)ptr;
                            ptr += sizeof(struct xlio_recvfrom_zcopy_packet_t);
                            vec = (struct iovec *)ptr;
                            for (j = 0; j < (int)xlio_packet->sz_iov; j++) {
                                packet_len += vec[j].iov_len;
                            }
                            log_trace("packet[%d]: packet_id=%p sz_iov=%ld len=%d\n", n,
                                      xlio_packet->packet_id, xlio_packet->sz_iov, packet_len);
                        }

                        rc = xlio_api->recvfrom_zcopy_free_packets(m_fd, xlio_packets->pkts,
                                                                   xlio_packets->n_packet_num);
                        EXPECT_EQ(0, rc);
                    }
                }
            }
            EXPECT_EQ(test_buf_size, total_len);

            close(m_fd);
            free_tmp_buffer(test_buf, test_buf_size);
            test_buf = NULL;

            ASSERT_EQ(0, wait_fork(pid));
        }
    }
}

/**
 * @test xlio_tcp_recvfrom_zcopy.mapped_ipv4
 * @brief
 *    IPv6 mapped IPv4 receive
 *
 * @details
 */
TEST_F(xlio_tcp_recvfrom_zcopy, ti5_mapped_ipv4)
{
    if (!test_mapped_ipv4()) {
        return;
    }

    int pid = fork();

    if (0 == pid) { // Child
        barrier_fork(pid);

        int fd = tcp_base::sock_create_fa(AF_INET, false);
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
                    send(fd, buffer, sizeof(buffer), 0);
                }
            }

            close(fd);
        }

        // This exit is very important, otherwise the fork
        // keeps running and may duplicate other tests.
        exit(testing::Test::HasFailure());
    } else { // Parent
        sockaddr_store_t any_addr;
        memset(&any_addr, 0, sizeof(any_addr));
        any_addr.addr6.sin6_family = AF_INET6;
        any_addr.addr6.sin6_port = server_addr.addr6.sin6_port;

        int l_fd = tcp_base::sock_create_to(AF_INET6, false, 10);
        EXPECT_LE_ERRNO(0, l_fd);
        if (0 <= l_fd) {
            int rc = bind(l_fd, &any_addr.addr, sizeof(any_addr));
            EXPECT_EQ_ERRNO(0, rc);
            if (0 == rc) {
                log_trace("Bound server: fd=%d\n", l_fd);

                rc = listen(l_fd, 5);
                EXPECT_EQ_ERRNO(0, rc);
                if (0 == rc) {
                    barrier_fork(pid);

                    int fd = accept(l_fd, nullptr, 0U);
                    EXPECT_LE_ERRNO(0, fd);
                    if (0 <= fd) {
                        log_trace("Accepted connection: fd=%d\n", fd);

                        size_t xlio_header_size = sizeof(xlio_recvfrom_zcopy_packets_t) +
                            sizeof(xlio_recvfrom_zcopy_packet_t) + sizeof(iovec);
                        char buf[8 + xlio_header_size];

                        int flags = 0;
                        sockaddr_store_t peer_addr;
                        struct sockaddr *ppeer = &peer_addr.addr;
                        socklen_t socklen = sizeof(peer_addr);
                        memset(&peer_addr, 0, socklen);

                        rc =
                            xlio_api->recvfrom_zcopy(fd, buf, sizeof(buf), &flags, ppeer, &socklen);
                        EXPECT_EQ(8, rc);
                        EXPECT_TRUE(flags & MSG_XLIO_ZCOPY);
                        if (rc > 0) {
                            xlio_recvfrom_zcopy_packets_t *xlio_packets =
                                reinterpret_cast<xlio_recvfrom_zcopy_packets_t *>(buf);

                            rc = xlio_api->recvfrom_zcopy_free_packets(fd, xlio_packets->pkts,
                                                                       xlio_packets->n_packet_num);
                            EXPECT_EQ(0, rc);
                        }

                        close(fd);
                    }
                }
            }

            close(l_fd);
        }

        EXPECT_EQ(0, wait_fork(pid));
    }
}

/**
 * @test xlio_tcp_recvfrom_zcopy.mapped_ipv4_udp
 * @brief
 *    IPv6 mapped IPv4 receive
 *
 * @details
 */
TEST_F(xlio_tcp_recvfrom_zcopy, ti5_mapped_ipv4_udp)
{
    if (!test_mapped_ipv4()) {
        return;
    }

    int pid = fork();

    if (0 == pid) { // Child
        barrier_fork(pid);

        int fd = m_udp_base_sock.sock_create_fa(AF_INET, false);
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
                    send(fd, buffer, sizeof(buffer), 0);
                }
            }

            close(fd);
        }

        // This exit is very important, otherwise the fork
        // keeps running and may duplicate other tests.
        exit(testing::Test::HasFailure());
    } else { // Parent
        sockaddr_store_t any_addr;
        memset(&any_addr, 0, sizeof(any_addr));
        any_addr.addr6.sin6_family = AF_INET6;
        any_addr.addr6.sin6_port = server_addr.addr6.sin6_port;

        int fd = m_udp_base_sock.sock_create_to(AF_INET6, false, 10);
        EXPECT_LE_ERRNO(0, fd);
        if (0 <= fd) {
            int rc = bind(fd, &any_addr.addr, sizeof(any_addr));
            EXPECT_EQ_ERRNO(0, rc);
            if (0 == rc) {
                log_trace("Bound server: fd=%d\n", fd);

                barrier_fork(pid);

                size_t xlio_header_size = sizeof(xlio_recvfrom_zcopy_packets_t) +
                    sizeof(xlio_recvfrom_zcopy_packet_t) + sizeof(iovec);
                char buf[8 + xlio_header_size];

                int flags = 0;
                sockaddr_store_t peer_addr;
                struct sockaddr *ppeer = &peer_addr.addr;
                socklen_t socklen = sizeof(peer_addr);
                memset(&peer_addr, 0, socklen);

                rc = xlio_api->recvfrom_zcopy(fd, buf, sizeof(buf), &flags, ppeer, &socklen);
                EXPECT_EQ(8, rc);
                EXPECT_TRUE(flags & MSG_XLIO_ZCOPY);
                if (rc > 0) {
                    xlio_recvfrom_zcopy_packets_t *xlio_packets =
                        reinterpret_cast<xlio_recvfrom_zcopy_packets_t *>(buf);

                    rc = xlio_api->recvfrom_zcopy_free_packets(fd, xlio_packets->pkts,
                                                               xlio_packets->n_packet_num);
                    EXPECT_EQ(0, rc);
                }
            }

            close(fd);
        }

        EXPECT_EQ(0, wait_fork(pid));
    }
}

#endif /* EXTRA_API_ENABLED */
