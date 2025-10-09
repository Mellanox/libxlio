/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2022-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <sys/mman.h>
#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "src/core/util/sock_addr.h"
#include "tcp_base.h"

class tcp_accept : public tcp_base {};

/**
 * @test tcp_accept.mapped_ipv4_accept
 * @brief
 *    IPv6 mapped IPv4 accept
 *
 * @details
 */
TEST_F(tcp_accept, mapped_ipv4_accept)
{
    if (!test_mapped_ipv4()) {
        return;
    }

    auto check_accpet = [this](bool api4) {
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
                    printf("connect rc: %d\n", rc);
                    printf("connect errno: %d\n", errno);

                    EXPECT_TRUE(rc == 0 || (rc < 0 && errno == EINPROGRESS));
                    if (0 == rc) {
                        log_trace("Established connection: fd=%d to %s from %s\n", fd,
                                  SOCK_STR(server_addr), SOCK_STR(client_addr));
                    }
                    if (rc < 0 && errno == EINPROGRESS) {
                        // Wait for connection with epoll (drives timers in delegate mode)
                        struct epoll_event ev = {.events = EPOLLOUT, .data = {.fd = fd}};
                        int epfd = epoll_create1(0);
                        epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
                        epoll_wait(epfd, &ev, 1, 30000);  // 30 sec timeout
                        close(epfd);
                        
                        // Check if connected
                        int error = 0;
                        socklen_t len = sizeof(error);
                        getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
                        EXPECT_EQ(0, error);
                    }

                    peer_wait(fd);
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
                    rc = listen(l_fd, 5);
                    EXPECT_EQ_ERRNO(0, rc);
                    if (0 == rc) {
                        barrier_fork(pid);

                        int fd = -1;
                        sockaddr_store_t peer_addr;
                        struct sockaddr *ppeer = &peer_addr.addr;
                        socklen_t socklen = sizeof(peer_addr);
                        memset(&peer_addr, 0, socklen);
                        if (api4) {
                            fd = accept4(l_fd, ppeer, &socklen, 0);
                        } else {
                            fd = accept(l_fd, ppeer, &socklen);
                        }
                        EXPECT_LE_ERRNO(0, fd);
                        if (0 <= fd) {
                            log_trace("Accepted connection: fd=%d from %s\n", fd, SOCK_STR(ppeer));

                            EXPECT_EQ_MAPPED_IPV4(peer_addr.addr6,
                                                  client_addr.addr4.sin_addr.s_addr);

                            auto clear_sockaddr = [&socklen, &peer_addr]() {
                                socklen = sizeof(peer_addr);
                                memset(&peer_addr, 0, socklen);
                            };

                            clear_sockaddr();
                            getpeername(fd, ppeer, &socklen);
                            EXPECT_EQ_MAPPED_IPV4(peer_addr.addr6,
                                                  client_addr.addr4.sin_addr.s_addr);

                            clear_sockaddr();
                            getsockname(fd, ppeer, &socklen);
                            EXPECT_EQ_MAPPED_IPV4(peer_addr.addr6,
                                                  server_addr.addr4.sin_addr.s_addr);

                            close(fd);
                        }
                    }
                }

                close(l_fd);
            }

            EXPECT_EQ(0, wait_fork(pid));
        }
    };

    log_trace("Checking accept()\n");
    check_accpet(false);
    log_trace("Checking accept4()\n");
    check_accpet(true);
}
