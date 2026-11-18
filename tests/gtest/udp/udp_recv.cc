/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2022-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <set>
#include <sys/mman.h>
#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "src/core/util/sock_addr.h"
#include "udp_base.h"

class udp_recv : public udp_base {};

/**
 * @test udp_recv.mapped_ipv4_recv
 * @brief
 *    IPv6 mapped IPv4 receive
 *
 * @details
 */
TEST_F(udp_recv, mapped_ipv4_recv)
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
                    send(fd, buffer, sizeof(buffer), 0);
                    send(fd, buffer, sizeof(buffer), 0);
                    send(fd, buffer, sizeof(buffer), 0);
#if __USE_FORTIFY_LEVEL > 0 && defined __fortify_function && defined HAVE___RECVFROM_CHK
                    send(fd, buffer, sizeof(buffer), 0);
#endif
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

        int fd = udp_base::sock_create_to(AF_INET6, false, 10);
        EXPECT_LE_ERRNO(0, fd);
        if (0 <= fd) {
            int rc = bind(fd, &any_addr.addr, sizeof(any_addr));
            EXPECT_EQ_ERRNO(0, rc);
            if (0 == rc) {
                barrier_fork(pid);

                sockaddr_store_t peer_addr;
                struct sockaddr *ppeer = &peer_addr.addr;
                socklen_t socklen = sizeof(peer_addr);
                memset(&peer_addr, 0, socklen);

                char buffer[8];
                auto clear_sockaddr = [&socklen, &peer_addr]() {
                    socklen = sizeof(peer_addr);
                    memset(&peer_addr, 0, socklen);
                };

                clear_sockaddr();
                recvfrom(fd, buffer, sizeof(buffer), 0, ppeer, &socklen);
                EXPECT_EQ_MAPPED_IPV4(peer_addr.addr6, client_addr.addr4.sin_addr.s_addr);

#if __USE_FORTIFY_LEVEL > 0 && defined __fortify_function && defined HAVE___RECVFROM_CHK
                clear_sockaddr();
                __recvfrom_chk(fd, buffer, sizeof(buffer), sizeof(buffer), 0, ppeer, &socklen);
                EXPECT_EQ_MAPPED_IPV4(peer_addr.addr6, client_addr.addr4.sin_addr.s_addr);
#endif // HAVE___RECVFROM_CHK

                clear_sockaddr();
                iovec vec = {.iov_base = buffer, .iov_len = sizeof(buffer)};
                msghdr msg;
                msg.msg_iov = &vec;
                msg.msg_iovlen = 1U;
                msg.msg_name = ppeer;
                msg.msg_namelen = socklen;
                msg.msg_control = nullptr;
                msg.msg_controllen = 0;
                recvmsg(fd, &msg, 0);
                EXPECT_EQ_MAPPED_IPV4(peer_addr.addr6, client_addr.addr4.sin_addr.s_addr);

                clear_sockaddr();
                mmsghdr mmsg;
                mmsg.msg_hdr = msg;
                mmsg.msg_len = 0;
                recvmmsg(fd, &mmsg, 1, 0, nullptr);
                EXPECT_EQ_MAPPED_IPV4(peer_addr.addr6, client_addr.addr4.sin_addr.s_addr);
            }

            close(fd);
        }

        EXPECT_EQ(0, wait_fork(pid));
    }
}

/**
 * @test udp_recv.lt_maxevents_round_robin
 * @brief
 *    With more level-triggered ready sockets than maxevents, successive epoll_wait()
 *    calls report every ready socket in turn, as epoll_wait(2) describes.
 */
TEST_F(udp_recv, lt_maxevents_round_robin)
{
    const int N = 8;
    const int M = 2;
    int fds[N];
    int efd = epoll_create1(0);
    sockaddr_store_t addr = server_addr;

    for (int k = 0; k < N; ++k) { // N receivers, level-triggered EPOLLIN, never read
        fds[k] = udp_base::sock_create();
        sys_set_port(&addr.addr, m_port + k);
        EXPECT_EQ(0, bind(fds[k], &addr.addr, sizeof(addr)));
        struct epoll_event ev = {};
        ev.events = EPOLLIN;
        ev.data.u32 = k;
        EXPECT_EQ(0, epoll_ctl(efd, EPOLL_CTL_ADD, fds[k], &ev));
    }

    int tx = udp_base::sock_create(); // One sender, one datagram to each receiver
    EXPECT_EQ(0, bind(tx, &client_addr.addr, sizeof(client_addr)));
    for (int k = 0; k < N; ++k) {
        sys_set_port(&addr.addr, m_port + k);
        EXPECT_EQ(1, sendto(tx, "x", 1, 0, &addr.addr, sizeof(addr)));
    }

    // Wait until one call reports all N sockets. Room for 2 * N events also checks that no
    // socket is reported twice in one call. FIONREAD makes XLIO poll for the datagrams and
    // does not consume them.
    struct epoll_event evs[2 * N];
    int n = 0;
    for (int t = 0; n < N && t < 10000; ++t) {
        int bytes;
        for (int k = 0; k < N; ++k) {
            ioctl(fds[k], FIONREAD, &bytes);
        }
        n = epoll_wait(efd, evs, 2 * N, 1);
    }
    EXPECT_EQ(N, n);

    // Nothing is read, so N / M calls of M events must report all N sockets.
    std::set<uint32_t> reported;
    for (int call = 0; call < N / M; ++call) {
        n = epoll_wait(efd, evs, M, 0);
        EXPECT_EQ(M, n);
        for (int e = 0; e < n; ++e) {
            reported.insert(evs[e].data.u32);
        }
    }
    EXPECT_EQ(static_cast<size_t>(N), reported.size())
        << "ready sockets reported in " << N / M << " calls of maxevents " << M;

    close(tx);
    close(efd);
    for (int k = 0; k < N; ++k) {
        close(fds[k]);
    }
}
