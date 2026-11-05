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

class tcp_event : public tcp_base {};

static void ignore_sigint(int signo)
{
    UNREFERENCED_PARAMETER(signo);
}

/**
 * @test tcp_event.ready_event_precedes_shutdown_interrupt
 * @brief
 *    epoll_wait() returns an already-ready event ahead of the shutdown EINTR
 *
 * @details
 */
TEST_F(tcp_event, ready_event_precedes_shutdown_interrupt)
{
    int pid = fork();
    ASSERT_LE(0, pid);

    if (pid == 0) {
        int efd = eventfd(0, EFD_NONBLOCK);
        EXPECT_LE_ERRNO(0, efd);

        int epfd = epoll_create1(0);
        EXPECT_LE_ERRNO(0, epfd);

        struct epoll_event event = {};
        event.events = EPOLLIN | EPOLLET;
        event.data.fd = efd;
        EXPECT_EQ_ERRNO(0, epoll_ctl(epfd, EPOLL_CTL_ADD, efd, &event));

        uint64_t value = 1;
        EXPECT_EQ_ERRNO(static_cast<ssize_t>(sizeof(value)), write(efd, &value, sizeof(value)));

        struct sigaction action = {};
        action.sa_handler = ignore_sigint;
        sigemptyset(&action.sa_mask);
        EXPECT_EQ_ERRNO(0, sigaction(SIGINT, &action, nullptr));
        EXPECT_EQ_ERRNO(0, raise(SIGINT));

        event = {};
        int rc = epoll_wait(epfd, &event, 1, 0);
        EXPECT_EQ_ERRNO(1, rc);
        if (rc == 1) {
            EXPECT_EQ(efd, event.data.fd);
            EXPECT_NE(0U, event.events & EPOLLIN);
        }

        close(epfd);
        close(efd);
        exit(testing::Test::HasFailure());
    }

    EXPECT_EQ(0, wait_fork(pid));
}

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
