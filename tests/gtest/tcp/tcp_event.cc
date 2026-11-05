/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "common/cmn.h"
#include "tcp_base.h"

#include <set>

class tcp_event : public tcp_base {};

TEST_F(tcp_event, DISABLED_ti_1)
{
    int rc = EOK;
    int fd;
    struct epoll_event event;

    fd = tcp_base::sock_create_nb();
    ASSERT_LE(0, fd);

    rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    ASSERT_EQ(EINPROGRESS, errno);
    ASSERT_EQ((-1), rc);

    event.events = 0;
    event.data.fd = fd;
    rc = test_base::event_wait(&event);
    EXPECT_LT(0, rc);
    /*	EXPECT_EQ(EPOLLHUP, event.events); TODO: UNDER XLIO */
    EXPECT_EQ((uint32_t)(EPOLLERR | EPOLLHUP), event.events);

    close(fd);
}

TEST_F(tcp_event, ti_2)
{
    int rc = EOK;
    int fd;
    struct epoll_event event;
    sockaddr_store_t addr;

    static const std::string FREE_PORT = std::to_string(8889);
    const std::string localhost =
        (m_family == AF_INET6) ? "::1[" + FREE_PORT + "]" : "127.0.0.1[" + FREE_PORT + "]";
    sys_str2addr(localhost.c_str(), (struct sockaddr *)&addr, true);

    fd = tcp_base::sock_create_nb();
    ASSERT_LE(0, fd);

    rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    ASSERT_EQ(EINPROGRESS, errno);
    ASSERT_EQ((-1), rc);

    event.events = 0;
    event.data.fd = fd;
    rc = test_base::event_wait(&event);
    EXPECT_LT(0, rc);
    EXPECT_EQ((uint32_t)(EPOLLERR | EPOLLHUP), event.events);

    close(fd);
}

TEST_F(tcp_event, DISABLED_ti_3)
{
    int rc = EOK;
    int fd;
    struct epoll_event event;

    fd = tcp_base::sock_create_nb();
    ASSERT_LE(0, fd);

    rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    ASSERT_EQ(EINPROGRESS, errno);
    ASSERT_EQ((-1), rc);

    event.events = EPOLLOUT | EPOLLIN;
    event.data.fd = fd;
    rc = test_base::event_wait(&event);
    EXPECT_LT(0, rc);
    /*	EXPECT_EQ((EPOLLHUP | EPOLLIN), event.events); TODO: UNDER XLIO */
    EXPECT_EQ((uint32_t)(EPOLLERR | EPOLLHUP | EPOLLOUT | EPOLLIN), event.events);

    close(fd);
}

TEST_F(tcp_event, DISABLED_ti_4)
{
    int rc = EOK;
    int fd;
    struct epoll_event event;

    fd = tcp_base::sock_create_nb();
    ASSERT_LE(0, fd);

    rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    ASSERT_EQ(EINPROGRESS, errno);
    ASSERT_EQ((-1), rc);

    event.events = EPOLLOUT | EPOLLIN;
    event.data.fd = fd;
    rc = test_base::event_wait(&event);
    EXPECT_LT(0, rc);
    /*	EXPECT_EQ((EPOLLERR | EPOLLHUP | EPOLLIN), event.events); TODO: UNDER XLIO */
    EXPECT_EQ((uint32_t)(EPOLLERR | EPOLLHUP | EPOLLOUT | EPOLLIN), event.events);

    close(fd);
}

/**
 * @test tcp_event.lt_maxevents_round_robin
 * @brief
 *    With more level-triggered ready sockets than maxevents, successive epoll_wait()
 *    calls report every ready socket in turn, as epoll_wait(2) describes.
 */
TEST_F(tcp_event, lt_maxevents_round_robin)
{
    const int N = 8;
    const int M = 2;
    int fds[N];
    int pid = fork();

    if (0 == pid) { // Child: N clients, one byte on each
        barrier_fork(pid);
        for (int k = 0; k < N; ++k) {
            fds[k] = tcp_base::sock_create_nb();
            bind(fds[k], &client_addr.addr, sizeof(client_addr));
            connect(fds[k], &server_addr.addr, sizeof(server_addr));
            wait_for_event(fds[k], EPOLLOUT);
        }
        barrier_fork(pid); // Send only after the parent added the sockets to epoll
        for (int k = 0; k < N; ++k) {
            send(fds[k], "x", 1, MSG_NOSIGNAL);
        }
        barrier_fork(pid);
        for (int k = 0; k < N; ++k) {
            close(fds[k]); // The client closes first: no TIME_WAIT on the server port
        }
        exit(testing::Test::HasFailure()); // The child must not run other tests
    }

    // Parent: server. Level-triggered EPOLLIN, never reads.
    int efd = epoll_create1(0);
    int l_fd = tcp_base::sock_create_nb();
    EXPECT_EQ(0, bind(l_fd, &server_addr.addr, sizeof(server_addr)));
    EXPECT_EQ(0, listen(l_fd, N));
    barrier_fork(pid);

    int accepted = 0;
    for (int t = 0; accepted < N && t < 10000; ++t) { // Non-blocking accept, 10 s limit
        int fd = accept(l_fd, nullptr, nullptr);
        if (fd < 0) {
            usleep(1000);
            continue;
        }
        struct epoll_event ev = {};
        ev.events = EPOLLIN;
        ev.data.u32 = accepted;
        epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
        fds[accepted++] = fd;
    }
    barrier_fork(pid);

    // Wait until one call reports all N sockets. FIONREAD lets XLIO receive the bytes in
    // every mode and does not consume them.
    struct epoll_event evs[N];
    int n = 0;
    for (int t = 0; n < N && t < 10000; ++t) {
        int bytes;
        for (int k = 0; k < accepted; ++k) {
            ioctl(fds[k], FIONREAD, &bytes);
        }
        n = epoll_wait(efd, evs, N, 1);
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

    barrier_fork(pid);
    EXPECT_EQ(0, wait_fork(pid));
    for (int k = 0; k < accepted; ++k) {
        close(fds[k]);
    }
    close(l_fd);
    close(efd);
}

/* XLIO does not work as server/client from single process
 * in addition gcc 8.x reports 'cast between incompatible function types' warning
 * but _proc_server() and _proc_client() can not return void* due to google test
 * limitations as all functions using EXPECT_X, ASSERT_X should return void
 */
#if 0
static void _proc_server(void *ptr)
{
	int rc = EOK;
	int fd;
	int fd_peer;
	struct sockaddr peer_addr;
	socklen_t socklen;

	UNREFERENCED_PARAMETER(ptr);

	fd = tcp_base::sock_create();
	ASSERT_LE(0, fd);

	rc = bind(fd, (struct sockaddr *)&gtest_conf.server_addr, sizeof(gtest_conf.server_addr));
	ASSERT_EQ(EOK, errno);
	ASSERT_EQ(0, rc);

	rc = listen(fd, 5);
	ASSERT_EQ(EOK, errno);
	ASSERT_EQ(0, rc);

	socklen = sizeof(peer_addr);
	fd_peer = accept(fd, &peer_addr, &socklen);
	EXPECT_EQ(EOK, errno);
	EXPECT_LE(0, fd_peer);
	EXPECT_EQ(sizeof(peer_addr), socklen);

	log_trace("Accepted connection: fd=%d from %s\n",
			fd_peer, sys_addr2str((struct sockaddr *) &peer_addr));

	close(fd_peer);
	close(fd);
}

static void _proc_client(void *ptr)
{
	int rc = EOK;
	int fd;
	struct epoll_event event;

	UNREFERENCED_PARAMETER(ptr);

	fd = tcp_base::sock_create_nb();
	ASSERT_LE(0, fd);

	rc = bind(fd, (struct sockaddr *)&gtest_conf.client_addr, sizeof(gtest_conf.client_addr));
	ASSERT_EQ(EOK, errno);
	ASSERT_EQ(0, rc);

	rc = connect(fd, (struct sockaddr *)&gtest_conf.server_addr, sizeof(gtest_conf.server_addr));
	ASSERT_EQ(EINPROGRESS, errno);
	ASSERT_EQ((-1), rc);

	event.events = EPOLLOUT | EPOLLIN;
	event.data.fd = fd;
	rc = test_base::event_wait(&event);
	EXPECT_LT(0, rc);
	EXPECT_EQ((uint32_t)(EPOLLOUT), event.events);

	log_trace("Established connection: fd=%d to %s\n",
			fd, sys_addr2str((struct sockaddr *) &gtest_conf.server_addr));

	close(fd);
}

TEST_F(tcp_event, DISABLED_ti_5) {
	pthread_t server_thread = 0;
	pthread_t client_thread = 0;

	pthread_create(&server_thread, NULL, (void *(*) (void *))_proc_server, NULL);
	sleep(1);
	pthread_create(&client_thread, NULL, (void *(*) (void *))_proc_client, NULL);

	pthread_join(server_thread, NULL);
	pthread_join(client_thread, NULL);
}
#endif
