/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/*
 * Shared plumbing for the listener regression-test helper binaries
 * (tcp_listener_churn_helper, tcp_listener_cosink_helper): address parsing,
 * reuse_port listener setup and option-value fetching.
 */

#ifndef TESTS_GTEST_TCP_LISTENER_TEST_UTILS_H_
#define TESTS_GTEST_TCP_LISTENER_TEST_UTILS_H_

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

namespace listener_test {

// Parse an IPv4 or IPv6 literal with the given port into ss and return the
// sockaddr length. An unparseable address exits the helper loudly: a zeroed
// address would bind/connect the wildcard and run the scenario over kernel
// loopback, a false result either way.
inline socklen_t fill_addr(sockaddr_storage &ss, const std::string &ip, uint16_t port)
{
    memset(&ss, 0, sizeof(ss));
    auto *sa4 = reinterpret_cast<sockaddr_in *>(&ss);
    auto *sa6 = reinterpret_cast<sockaddr_in6 *>(&ss);
    if (inet_pton(AF_INET, ip.c_str(), &sa4->sin_addr) == 1) {
        sa4->sin_family = AF_INET;
        sa4->sin_port = htons(port);
        return sizeof(sockaddr_in);
    }
    if (inet_pton(AF_INET6, ip.c_str(), &sa6->sin6_addr) == 1) {
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons(port);
        return sizeof(sockaddr_in6);
    }
    fprintf(stderr, "FAIL: cannot parse '%s' as an IPv4 or IPv6 address\n", ip.c_str());
    exit(EXIT_FAILURE);
}

// Open a TCP listener on ip:port with SO_REUSEADDR and SO_REUSEPORT (reuse_port
// listeners of one 3-tuple share one offloaded rfs sink list). Returns the
// listening fd, or -1 on any setup failure.
inline int open_listener(const std::string &ip, uint16_t port, int backlog)
{
    sockaddr_storage sa;
    socklen_t sa_len = fill_addr(sa, ip, port);
    int fd = socket(sa.ss_family, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) != 0) {
        close(fd);
        return -1;
    }
    if (bind(fd, reinterpret_cast<sockaddr *>(&sa), sa_len) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, backlog) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// Fetch the value of option 'name' sitting at argv[i], advancing i past it.
// Returns nullptr (and prints a FAIL line) when the value is missing.
inline const char *arg_value(int argc, char **argv, int &i, const char *name)
{
    if (i + 1 >= argc) {
        fprintf(stderr, "FAIL: %s needs a value\n", name);
        return nullptr;
    }
    return argv[++i];
}

} // namespace listener_test

#endif /* TESTS_GTEST_TCP_LISTENER_TEST_UTILS_H_ */
