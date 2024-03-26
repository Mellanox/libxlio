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
