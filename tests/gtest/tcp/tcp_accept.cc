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

                    EXPECT_EQ(0, rc);
                    if (0 == rc) {
                        log_trace("Established connection: fd=%d to %s from %s\n", fd,
                                  SOCK_STR(server_addr), SOCK_STR(client_addr));
                        peer_wait(fd);
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

/**
 * @test tcp_accept.delegate_mode_fork_debug
 * @brief
 *    Debug test for delegate mode + fork() issue
 *    This test is designed to produce debug output to diagnose
 *    why delegate mode fails in containers but works on bare-metal.
 *
 * @details
 *    Simplified version of mapped_ipv4_accept specifically for debugging.
 *    Will be removed once the issue is fixed.
 */
TEST_F(tcp_accept, delegate_mode_fork_debug)
{
    const char* ctl_thread = getenv("XLIO_TCP_CTL_THREAD");
    if (!ctl_thread || (strcmp(ctl_thread, "delegate") != 0 && strcmp(ctl_thread, "1") != 0)) {
        GTEST_SKIP() << "This debug test only runs in delegate mode";
        return;
    }

    log_trace("=== DELEGATE MODE FORK DEBUG TEST ===\n");
    log_trace("Testing fork() + IPv4 connect in delegate mode\n");
    
    int pid = fork();

    if (0 == pid) { // Child
        log_trace("CHILD: Started, PID=%d\n", getpid());
        barrier_fork(pid);

        log_trace("CHILD: Creating IPv4 client socket\n");
        int fd = tcp_base::sock_create_fa(AF_INET, false);
        EXPECT_LE_ERRNO(0, fd);
        
        if (0 <= fd) {
            log_trace("CHILD: Binding to client address\n");
            int rc = bind(fd, &client_addr.addr, sizeof(client_addr));
            EXPECT_EQ_ERRNO(0, rc);
            
            if (0 == rc) {
                log_trace("CHILD: Calling connect() to server address\n");
                log_trace("CHILD: From %s to %s\n", 
                         SOCK_STR(client_addr), SOCK_STR(server_addr));
                
                struct timespec start, end;
                clock_gettime(CLOCK_MONOTONIC, &start);
                
                rc = connect(fd, &server_addr.addr, sizeof(server_addr));
                
                clock_gettime(CLOCK_MONOTONIC, &end);
                long elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 + 
                                  (end.tv_nsec - start.tv_nsec) / 1000000;
                
                if (rc < 0) {
                    log_trace("CHILD: connect() FAILED after %ld ms: rc=%d, errno=%d (%s)\n",
                             elapsed_ms, rc, errno, strerror(errno));
                } else {
                    log_trace("CHILD: connect() SUCCESS after %ld ms\n", elapsed_ms);
                    
                    // Simple keepalive
                    char byte = 'X';
                    send(fd, &byte, 1, 0);
                }
                
                EXPECT_EQ_ERRNO(0, rc);
            }
            
            close(fd);
        }

        log_trace("CHILD: Exiting\n");
        exit(testing::Test::HasFailure());
        
    } else { // Parent
        log_trace("PARENT: Started, PID=%d, child PID=%d\n", getpid(), pid);
        
        sockaddr_store_t any_addr;
        memset(&any_addr, 0, sizeof(any_addr));
        any_addr.addr6.sin6_family = AF_INET6;
        any_addr.addr6.sin6_port = server_addr.addr6.sin6_port;

        log_trace("PARENT: Creating IPv6 listening socket\n");
        int l_fd = tcp_base::sock_create_to(AF_INET6, false, 10);
        EXPECT_LE_ERRNO(0, l_fd);
        
        if (0 <= l_fd) {
            log_trace("PARENT: Binding to [::]:port\n");
            int rc = bind(l_fd, &any_addr.addr, sizeof(any_addr));
            EXPECT_EQ_ERRNO(0, rc);
            
            if (0 == rc) {
                log_trace("PARENT: Calling listen()\n");
                rc = listen(l_fd, 5);
                EXPECT_EQ_ERRNO(0, rc);
                
                if (0 == rc) {
                    barrier_fork(pid);

                    log_trace("PARENT: Calling accept() (10s timeout)\n");
                    struct timespec start, end;
                    clock_gettime(CLOCK_MONOTONIC, &start);
                    
                    int fd = -1;
                    sockaddr_store_t peer_addr;
                    struct sockaddr *ppeer = &peer_addr.addr;
                    socklen_t socklen = sizeof(peer_addr);
                    memset(&peer_addr, 0, socklen);
                    
                    fd = accept(l_fd, ppeer, &socklen);
                    
                    clock_gettime(CLOCK_MONOTONIC, &end);
                    long elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 + 
                                      (end.tv_nsec - start.tv_nsec) / 1000000;
                    
                    if (fd < 0) {
                        log_trace("PARENT: accept() FAILED after %ld ms: errno=%d (%s)\n",
                                 elapsed_ms, errno, strerror(errno));
                    } else {
                        log_trace("PARENT: accept() SUCCESS after %ld ms from %s\n",
                                 elapsed_ms, SOCK_STR(ppeer));
                        
                        // Read the byte
                        char byte = 0;
                        recv(fd, &byte, 1, 0);
                        
                        close(fd);
                    }
                    
                    EXPECT_LE_ERRNO(0, fd);
                }
            }
            
            close(l_fd);
        }

        log_trace("PARENT: Waiting for child to exit\n");
        EXPECT_EQ(0, wait_fork(pid));
    }
    
    log_trace("=== DELEGATE MODE FORK DEBUG TEST COMPLETE ===\n");
}
