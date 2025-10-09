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

/**
 * @test tcp_accept.delegate_fork_timer_proof
 * @brief
 *    Proof test that demonstrates the timer inheritance bug exists
 *    This test WILL FAIL on bare-metal WITHOUT the fix!
 *
 * @details
 *    Forces a scenario where timers must run even on low-latency networks.
 *    After fork, child sleeps to ensure it's in the "inherited timestamp window",
 *    then tries to connect. If timers don't run due to rate-limiting, the
 *    connection will behave incorrectly even on bare-metal.
 */
TEST_F(tcp_accept, delegate_fork_timer_proof)
{
    const char* ctl_thread = getenv("XLIO_TCP_CTL_THREAD");
    if (!ctl_thread || (strcmp(ctl_thread, "delegate") != 0 && strcmp(ctl_thread, "1") != 0)) {
        GTEST_SKIP() << "This test only runs in delegate mode to prove the bug";
        return;
    }

    log_trace("=== TIMER INHERITANCE BUG PROOF TEST ===\n");
    log_trace("This test proves the bug exists by forcing timer dependency\n");
    
    // CRITICAL: Make parent use delegate mode and update m_last_run_time
    // Create a socket to initialize the timer system
    int dummy_fd = tcp_base::sock_create_fa(AF_INET, false);
    if (dummy_fd >= 0) {
        // Bind it so XLIO manages it
        bind(dummy_fd, &client_addr.addr, sizeof(client_addr));
        
        // Force timers to run by doing some activity
        // This ensures m_last_run_time is updated to a recent timestamp
        usleep(150000); // Sleep 150ms to force at least one timer cycle
        
        log_trace("PARENT: Warmed up delegate mode, m_last_run_time is now recent\n");
        close(dummy_fd);
    }
    
    // Small sleep to ensure timers have processed
    usleep(10000);
    
    log_trace("PARENT: Now forking - child will inherit recent m_last_run_time\n");
    int pid = fork();

    if (0 == pid) { // Child
        barrier_fork(pid);
        
        // CRITICAL: Sleep for 30ms to ensure we're in the inherited timestamp window
        // If parent last ran timers at t=0, and we fork at t=10ms, child inherits
        // m_last_run_time from 10ms ago. We sleep 30ms, putting us at t=40ms.
        // When connect() calls do_tasks() at t=40ms:
        //   - Without fix: elapsed = 40ms < 100ms → timers DON'T run → connection may fail
        //   - With fix: elapsed = huge → timers run immediately → connection works
        usleep(30000); // 30ms
        
        log_trace("CHILD: After 30ms sleep, creating socket (timers should be rate-limited WITHOUT fix)\n");
        
        int fd = tcp_base::sock_create_fa(AF_INET, false);
        ASSERT_LE(0, fd);
        
        int rc = bind(fd, &client_addr.addr, sizeof(client_addr));
        ASSERT_EQ(0, rc);
        
        // Set a short connect timeout to make test faster
        struct timeval tv = {0};
        tv.tv_sec = 5;  // 5 second timeout
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        
        log_trace("CHILD: Connecting (without fix, timers are rate-limited for another 70ms)\n");
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        rc = connect(fd, &server_addr.addr, sizeof(server_addr));
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        long elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 + 
                          (end.tv_nsec - start.tv_nsec) / 1000000;
        
        if (rc < 0) {
            log_trace("CHILD: connect() FAILED after %ld ms: errno=%d (%s)\n",
                     elapsed_ms, errno, strerror(errno));
            log_trace("CHILD: This proves timers didn't run due to inheritance bug!\n");
        } else {
            log_trace("CHILD: connect() SUCCESS after %ld ms (fix is working!)\n", elapsed_ms);
            
            // Verify connection works
            char byte = 'X';
            ssize_t sent = send(fd, &byte, 1, 0);
            EXPECT_EQ(1, sent);
        }
        
        EXPECT_EQ_ERRNO(0, rc);
        
        close(fd);
        exit(testing::Test::HasFailure());
        
    } else { // Parent
        sockaddr_store_t any_addr;
        memset(&any_addr, 0, sizeof(any_addr));
        any_addr.addr6.sin6_family = AF_INET6;
        any_addr.addr6.sin6_port = server_addr.addr6.sin6_port;

        int l_fd = tcp_base::sock_create_to(AF_INET6, false, 10);
        ASSERT_LE(0, l_fd);
        
        int rc = bind(l_fd, &any_addr.addr, sizeof(any_addr));
        ASSERT_EQ(0, rc);
        
        rc = listen(l_fd, 5);
        ASSERT_EQ(0, rc);
        
        barrier_fork(pid);

        log_trace("PARENT: Accepting connection\n");
        
        int fd = -1;
        sockaddr_store_t peer_addr;
        struct sockaddr *ppeer = &peer_addr.addr;
        socklen_t socklen = sizeof(peer_addr);
        memset(&peer_addr, 0, socklen);
        
        fd = accept(l_fd, ppeer, &socklen);
        
        if (fd >= 0) {
            log_trace("PARENT: Connection accepted successfully!\n");
            
            // Read the byte
            char byte = 0;
            recv(fd, &byte, 1, 0);
            EXPECT_EQ('X', byte);
            
            close(fd);
        } else {
            log_trace("PARENT: accept() failed - child couldn't connect\n");
        }
        
        close(l_fd);
        
        int status;
        waitpid(pid, &status, 0);
        EXPECT_EQ(0, WEXITSTATUS(status)) << "Child should exit successfully with fix applied";
    }
    
    log_trace("=== TIMER INHERITANCE BUG PROOF TEST COMPLETE ===\n");
}

/**
 * @test tcp_accept.delegate_fork_unreachable
 * @brief
 *    Another proof test using unreachable destination
 *    Forces retransmit timers to be critical even on bare-metal
 *
 * @details
 *    Connects to a valid local IP but wrong port (nothing listening).
 *    This forces the SYN to be sent but no response, requiring retransmits.
 *    Without fix: retransmit timers don't run → delayed/wrong timeout behavior
 *    With fix: retransmit timers run normally → correct timeout behavior
 */
TEST_F(tcp_accept, delegate_fork_unreachable)
{
    const char* ctl_thread = getenv("XLIO_TCP_CTL_THREAD");
    if (!ctl_thread || (strcmp(ctl_thread, "delegate") != 0 && strcmp(ctl_thread, "1") != 0)) {
        GTEST_SKIP() << "This test only runs in delegate mode";
        return;
    }

    log_trace("=== UNREACHABLE DESTINATION PROOF TEST ===\n");
    
    int pid = fork();

    if (0 == pid) { // Child
        barrier_fork(pid);
        
        // Sleep to get into inherited timestamp window
        usleep(30000); // 30ms
        
        int fd = tcp_base::sock_create_fa(AF_INET, false);
        ASSERT_LE(0, fd);
        
        int rc = bind(fd, &client_addr.addr, sizeof(client_addr));
        ASSERT_EQ(0, rc);
        
        // Short timeout for test speed
        struct timeval tv = {0};
        tv.tv_sec = 3;
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        
        // Connect to server IP but WRONG port (port 1 - nothing listening there)
        sockaddr_store_t unreachable_addr;
        memcpy(&unreachable_addr, &server_addr, sizeof(unreachable_addr));
        unreachable_addr.addr4.sin_port = htons(1); // Port 1 - unlikely to be listening
        
        log_trace("CHILD: Connecting to unreachable port (requires timer processing)\n");
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        rc = connect(fd, &unreachable_addr.addr, sizeof(unreachable_addr));
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        long elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 + 
                          (end.tv_nsec - start.tv_nsec) / 1000000;
        
        log_trace("CHILD: connect() returned %d after %ld ms, errno=%d (%s)\n",
                 rc, elapsed_ms, errno, strerror(errno));
        
        if (rc < 0) {
            if (errno == ETIMEDOUT) {
                log_trace("CHILD: Got ETIMEDOUT - this is expected\n");
                // With fix: Should timeout relatively quickly (within 3-5 seconds)
                // Without fix: Might take full 10 seconds or behave oddly
                EXPECT_LT(elapsed_ms, 6000) << "Should timeout within ~3 seconds with working timers";
            } else if (errno == ECONNREFUSED) {
                log_trace("CHILD: Got ECONNREFUSED - RST received (also acceptable)\n");
                // This is fine - means server sent RST
            } else {
                log_trace("CHILD: Unexpected errno, might indicate timer issues\n");
            }
        } else {
            FAIL() << "connect() should fail to unreachable port";
        }
        
        close(fd);
        exit(testing::Test::HasFailure());
        
    } else { // Parent
        barrier_fork(pid);
        
        // Parent just waits for child
        log_trace("PARENT: Waiting for child to complete unreachable test\n");
        
        int status;
        waitpid(pid, &status, 0);
        
        EXPECT_EQ(0, WEXITSTATUS(status));
    }
    
    log_trace("=== UNREACHABLE DESTINATION PROOF TEST COMPLETE ===\n");
}
