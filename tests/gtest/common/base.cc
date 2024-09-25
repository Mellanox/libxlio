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
#include "base.h"

uint16_t test_base::m_port = 0;
int test_base::m_family = PF_INET;
int test_base::m_break_signal = 0;

test_base::test_base()
{
    m_port = gtest_conf.port;
    if (((struct sockaddr *)&gtest_conf.server_addr)->sa_family ==
        ((struct sockaddr *)&gtest_conf.client_addr)->sa_family) {
        m_family = ((struct sockaddr *)&gtest_conf.server_addr)->sa_family;
    } else {
        m_family = PF_INET6;
    }

    if (((struct sockaddr *)&gtest_conf.client_addr)->sa_family != m_family) {
        memset(&client_addr, 0, sizeof(client_addr));
        ((struct sockaddr *)&client_addr)->sa_family = m_family;
        sys_ipv4_to_ipv6(&((struct sockaddr_in *)&gtest_conf.client_addr)->sin_addr,
                         &((struct sockaddr_in6 *)&client_addr)->sin6_addr);
        sys_set_port((struct sockaddr *)&client_addr,
                     sys_get_port((struct sockaddr *)&gtest_conf.client_addr));
    } else {
        memcpy(&client_addr, &gtest_conf.client_addr, sizeof(client_addr));
    }

    if (((struct sockaddr *)&gtest_conf.server_addr)->sa_family != m_family) {
        memset(&server_addr, 0, sizeof(server_addr));
        ((struct sockaddr *)&server_addr)->sa_family = m_family;
        sys_ipv4_to_ipv6(&((struct sockaddr_in *)&gtest_conf.server_addr)->sin_addr,
                         &((struct sockaddr_in6 *)&server_addr)->sin6_addr);
        sys_set_port((struct sockaddr *)&server_addr,
                     sys_get_port((struct sockaddr *)&gtest_conf.server_addr));
    } else {
        memcpy(&server_addr, &gtest_conf.server_addr, sizeof(server_addr));
    }

    if (((struct sockaddr *)&gtest_conf.remote_addr)->sa_family != m_family) {
        memset(&remote_addr, 0, sizeof(remote_addr));
        ((struct sockaddr *)&remote_addr)->sa_family = m_family;
        sys_ipv4_to_ipv6(&((struct sockaddr_in *)&gtest_conf.remote_addr)->sin_addr,
                         &((struct sockaddr_in6 *)&remote_addr)->sin6_addr);
        sys_set_port((struct sockaddr *)&remote_addr,
                     sys_get_port((struct sockaddr *)&gtest_conf.remote_addr));
    } else {
        memcpy(&remote_addr, &gtest_conf.remote_addr, sizeof(remote_addr));
    }

    memset(&bogus_addr, 0, sizeof(bogus_addr));
    ((struct sockaddr *)&bogus_addr)->sa_family = m_family;
    sys_set_port((struct sockaddr *)&bogus_addr, 0);
    if (m_family == AF_INET) {
        inet_pton(AF_INET, "1.1.1.1", &(((struct sockaddr_in *)&bogus_addr)->sin_addr));
    }
    if (m_family == AF_INET6) {
        inet_pton(AF_INET6, "2001:1:1:1:1:1:1:1",
                  &(((struct sockaddr_in6 *)&bogus_addr)->sin6_addr));
    }

    def_gw_exists = gtest_conf.def_gw_exists;

    m_efd_signal = 0;
    m_efd = eventfd(m_efd_signal, 0);

    m_break_signal = 0;
}

test_base::~test_base()
{
    m_break_signal = 0;
}

void *test_base::thread_func(void *arg)
{
    test_base *self = reinterpret_cast<test_base *>(arg);
    self->barrier(); /* Let all threads start in the same time */
    return NULL;
}

void test_base::init()
{
}

void test_base::cleanup()
{
}

bool test_base::test_mapped_ipv4() const
{
    return (m_family != AF_INET6);
}

void test_base::ipv4_to_mapped(sockaddr_store_t &inout)
{
    in_port_t port = inout.addr4.sin_port;
    in_addr addr = inout.addr4.sin_addr;
    memset(&inout, 0, sizeof(inout));
    inout.addr6.sin6_family = AF_INET6;
    inout.addr6.sin6_port = port;
    reinterpret_cast<uint16_t *>(&inout.addr6.sin6_addr)[5] = 0xFFFFU;
    reinterpret_cast<in_addr *>(&inout.addr6.sin6_addr)[3] = addr;
}

int test_base_sock::set_socket_rcv_timeout(int fd, int timeout_sec)
{
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

int test_base_sock::sock_create_to(sa_family_t family, bool reuse_addr, int timeout_sec) const
{
    int fd = sock_create_fa(family, reuse_addr);
    if (fd >= 0 && 0 != set_socket_rcv_timeout(fd, timeout_sec)) {
        close(fd);
        fd = -1;
    }

    return fd;
}

int test_base_sock::sock_create_fa_nb(sa_family_t family) const
{
    int fd = sock_create_fa(family, false);
    if (fd < 0) {
        return fd;
    }

    int rc = test_base::sock_noblock(fd);
    if (rc < 0) {
        log_error("failed sock_noblock() %s\n", strerror(errno));
        goto err;
    }

    return fd;

err:
    close(fd);

    return (-1);
}

int test_base_sock::sock_create_typed(sa_family_t family, int type, bool reuse_addr)
{
    int rc;
    int fd;
    int opt_val = (reuse_addr ? 1 : 0);

    fd = socket(family, type, IPPROTO_IP);
    if (fd < 0) {
        log_error("failed socket(%hu) %s\n", family, strerror(errno));
        return -1;
    }

    rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));
    if (rc < 0) {
        log_error("failed setsockopt(SO_REUSEADDR) %s\n", strerror(errno));
        goto err;
    }

    return fd;

err:
    close(fd);

    return (-1);
}

int test_base_sock::bind_to_device(int fd, const sockaddr_store_t &addr_store)
{
    char ifname[128] = {0};
    char *rcs = sys_addr2dev(&addr_store.addr, ifname, sizeof(ifname));
    if (rcs) {
        log_trace("SO_BINDTODEVICE: fd=%d as %s on %s\n", fd, sys_addr2str(&addr_store.addr),
                  ifname);

        return setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
    }

    errno = ENOMEDIUM;
    return -1;
}

bool test_base::barrier()
{
    int ret = pthread_barrier_wait(&m_barrier);
    if (ret == 0) {
        return false;
    } else if (ret == PTHREAD_BARRIER_SERIAL_THREAD) {
        return true;
    } else {
        log_fatal("pthread_barrier_wait() failed\n");
    }
    return false;
}

int test_base::sock_noblock(int fd)
{
    int rc = 0;
    int flag;

    flag = fcntl(fd, F_GETFL);
    if (flag < 0) {
        rc = -errno;
        log_error("failed to get socket flags errno: %s\n", strerror(errno));
    }
    flag |= O_NONBLOCK;
    rc = fcntl(fd, F_SETFL, flag);
    if (rc < 0) {
        rc = -errno;
        log_error("failed to set socket flags errno: %s\n", strerror(errno));
    }

    return rc;
}

int test_base::event_wait(struct epoll_event *event)
{
    int rc = 0;
    int fd;
    int efd = -1;
    int timeout = 10 * 1000;

    if (!event) {
        return -1;
    }

    fd = event->data.fd;
    efd = epoll_create1(0);
    rc = epoll_ctl(efd, EPOLL_CTL_ADD, fd, event);
    if (rc < 0) {
        log_error("failed epoll_ctl() errno: %s\n", strerror(errno));
        goto err;
    }

    event->events = 0;
    rc = epoll_wait(efd, event, 1, timeout);
    if (rc < 0) {
        log_error("failed epoll_wait() errno: %s\n", strerror(errno));
    }

    epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);

err:
    close(efd);

    return rc;
}

int test_base::wait_fork(int pid)
{
    int status = 0;

    pid = waitpid(pid, &status, 0);
    if (0 > pid) {
        log_error("failed waitpid() errno: %s\n", strerror(errno));
        return (-1);
    }
    if (WIFEXITED(status)) {
        const int exit_status = WEXITSTATUS(status);
        if (exit_status != 0) {
            log_trace("non-zero exit status: %d from waitpid() errno: %s\n", exit_status,
                      strerror(errno));
        }
        return exit_status;
    } else if (WIFSIGNALED(status)) {
        log_error("child process killed by signal: %d\n", WTERMSIG(status));
        return (-2);
    } else {
        log_error("non-normal exit from child process status: %d\n", status);
        return (-3);
    }
}

void test_base::barrier_fork(int pid, bool sync_parent)
{
    ssize_t ret;

    m_break_signal = 0;
    if ((0 == pid && !sync_parent) || (0 != pid && sync_parent)) {
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        do {
            ret = read(m_efd, &m_efd_signal, sizeof(m_efd_signal));
            if (ret == -1 && errno == EINTR) {
                continue;
            }
        } while (0 == m_efd_signal);
        m_efd_signal = 0;
        ret = write(m_efd, &m_efd_signal, sizeof(m_efd_signal));
    } else {
        signal(SIGCHLD, handle_signal);
        m_efd_signal++;
        ret = write(m_efd, &m_efd_signal, sizeof(m_efd_signal));
    }
    if (ret != sizeof(m_efd_signal)) {
        log_error("write() failed\n");
    }
}

void test_base::handle_signal(int signo)
{
    switch (signo) {
    case SIGCHLD:
        /* Child is exiting so parent should complete test too */
        m_break_signal++;
        break;
    default:
        return;
    }
}
