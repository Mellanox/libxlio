/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2022-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#include "tcp_base.h"

class tcp_listen_connect_nb : public tcp_base {};

/**
 * @test tcp_listen_connect_nb.server_client_nb
 * @brief
 *    Non-blocking TCP server/client connection establishment
 *
 * @details
 *    This test validates non-blocking socket operations :
 *    - Server/client non-blocking socket creation and connection establishment
 *    - Data exchange using peer_wait() mechanism
 *    - Proper cleanup and synchronization in forked processes
 */
TEST_F(tcp_listen_connect_nb, server_client_nb)
{
    int pid = fork();

    if (0 == pid) { // Child
        int fd, rc;
        int optval;
        socklen_t optlen;

        barrier_fork(pid);

        fd = tcp_base::sock_create_nb();
        EXPECT_LE_ERRNO(0, fd);
        if (fd <= 0) {
            goto child_error;
        }

        rc = bind(fd, &client_addr.addr, sizeof(client_addr));
        EXPECT_EQ_ERRNO(0, rc);
        if (rc != 0) {
            goto child_cleanup;
        }

        rc = connect(fd, &server_addr.addr, sizeof(server_addr));
        EXPECT_EQ(EINPROGRESS, errno);
        EXPECT_EQ((-1), rc);
        if (rc != -1 || errno != EINPROGRESS) {
            goto child_cleanup;
        }

        rc = wait_for_event(fd, EPOLLOUT);
        if (rc <= 0) {
            goto child_cleanup;
        }

        // Verify connection is established using getsockopt
        optval = 0;
        optlen = sizeof(optval);
        rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &optval, &optlen);
        EXPECT_EQ(0, rc);
        EXPECT_EQ(0, optval);
        if (rc != 0 || optval != 0) {
            goto child_cleanup;
        }

        log_trace("Established connection: fd=%d to %s from %s\n", fd, SOCK_STR(server_addr),
                  SOCK_STR(client_addr));
        peer_wait(fd);

    child_cleanup:
        close(fd);
    child_error:
        // This exit is very important, otherwise the fork
        // keeps running and may duplicate other tests.
        exit(testing::Test::HasFailure());
    } else { // Parent
        int l_fd, rc, fd;
        sockaddr_store_t peer_addr;
        struct sockaddr *ppeer;
        socklen_t socklen;
        char buffer[64];
        ssize_t bytes_read;

        l_fd = tcp_base::sock_create_nb();
        EXPECT_LE_ERRNO(0, l_fd);
        if (l_fd < 0) {
            goto parent_error;
        }

        rc = bind(l_fd, &server_addr.addr, sizeof(server_addr));
        EXPECT_EQ_ERRNO(0, rc);
        if (rc != 0) {
            goto parent_cleanup;
        }

        rc = listen(l_fd, 5);
        EXPECT_EQ_ERRNO(0, rc);
        if (rc != 0) {
            goto parent_cleanup;
        }

        barrier_fork(pid);

        rc = wait_for_event(l_fd, EPOLLIN);
        if (rc <= 0) {
            goto parent_cleanup;
        }

        fd = -1;
        ppeer = &peer_addr.addr;
        socklen = sizeof(peer_addr);
        memset(&peer_addr, 0, socklen);
        fd = accept(l_fd, ppeer, &socklen);
        EXPECT_LE_ERRNO(0, fd);
        if (fd < 0) {
            goto parent_cleanup;
        }

        log_trace("Accepted connection: fd=%d from %s\n", fd, SOCK_STR(ppeer));

        // Read data from client (peer_wait sends multiple 1-byte messages)
        rc = wait_for_event(fd, EPOLLIN);

        bytes_read = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);
        EXPECT_GT(bytes_read, 0);
        if (bytes_read > 0) {
            EXPECT_EQ(1, buffer[0]);
        }

        close(fd);

    parent_cleanup:
        close(l_fd);
    parent_error:
        EXPECT_EQ(0, wait_fork(pid));
    }
}
