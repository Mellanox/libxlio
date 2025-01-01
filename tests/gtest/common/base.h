/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef TESTS_GTEST_COMMON_BASE_H_
#define TESTS_GTEST_COMMON_BASE_H_

#define DO_WHILE0(x)                                                                               \
    do {                                                                                           \
        x                                                                                          \
    } while (0)

#define EXPECT_LE_ERRNO(val1, val2)                                                                \
    DO_WHILE0(EXPECT_LE((val1), (val2));                                                           \
              if (val1 > val2) { log_trace("Failed. errno = %d\n", errno); })

#define EXPECT_EQ_ERRNO(val1, val2)                                                                \
    DO_WHILE0(EXPECT_EQ((val1), (val2));                                                           \
              if (val1 != val2) { log_trace("Failed. errno = %d\n", errno); })

#define EXPECT_EQ_MAPPED_IPV4(addr6, sin_addr)                                                     \
    DO_WHILE0(EXPECT_EQ(AF_INET6, (addr6).sin6_family);                                            \
              const in_addr_t *addrp = reinterpret_cast<const in_addr_t *>(&(addr6).sin6_addr);    \
              EXPECT_EQ(0U, addrp[0]); EXPECT_EQ(0U, addrp[1]);                                    \
              EXPECT_EQ(0xFFFFU, ntohl(addrp[2])); EXPECT_EQ(sin_addr, addrp[3]);)

#define EXPECT_EQ_IPV6(addr6_1, addr6_2)                                                           \
    DO_WHILE0(EXPECT_EQ((addr6_1).sin6_family, (addr6_2).sin6_family);                             \
              const uint64_t *addrp1 = reinterpret_cast<const uint64_t *>(&(addr6_1).sin6_addr);   \
              const uint64_t *addrp2 = reinterpret_cast<const uint64_t *>(&(addr6_2).sin6_addr);   \
              EXPECT_EQ(addrp1[0], addrp2[0]); EXPECT_EQ(addrp1[1], addrp2[1]);)

#define SOCK_STR(x) sockaddr2str(reinterpret_cast<const sockaddr *>(&x), sizeof(x)).c_str()

class test_base_sock {
public:
    virtual int get_sock_type() const = 0;

    int sock_create_fa(sa_family_t family, bool reuse_addr = false) const
    {
        return sock_create_typed(family, get_sock_type(), reuse_addr);
    }

    int sock_create_fa_nb(sa_family_t family) const;
    int sock_create_to(sa_family_t family, bool reuse_addr, int timeout_sec) const;

protected:
    static int sock_create_typed(sa_family_t family, int type, bool reuse_addr);
    static int set_socket_rcv_timeout(int fd, int timeout_sec);
    static int bind_to_device(int fd, const sockaddr_store_t &addr_store);
};

/**
 * Base class for tests
 */
class test_base {
public:
    static int sock_noblock(int fd);
    static int event_wait(struct epoll_event *event);
    static int wait_fork(int pid);
    static void handle_signal(int signo);

protected:
    test_base();
    virtual ~test_base();

    virtual void cleanup();
    virtual void init();
    bool barrier();
    void barrier_fork(int pid = 0, bool sync_parent = false);
    bool child_fork_exit() { return m_break_signal; }
    bool test_mapped_ipv4() const;

    static void ipv4_to_mapped(sockaddr_store_t &inout);

    sockaddr_store_t client_addr;
    sockaddr_store_t server_addr;
    sockaddr_store_t remote_addr;
    sockaddr_store_t bogus_addr;
    bool def_gw_exists;
    static uint16_t m_port;
    static int m_family;

private:
    static void *thread_func(void *arg);

    pthread_barrier_t m_barrier;
    int m_efd;
    uint64_t m_efd_signal;
    static int m_break_signal;
};

#endif /* TESTS_GTEST_COMMON_BASE_H_ */
