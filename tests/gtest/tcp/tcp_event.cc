/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "common/cmn.h"
#include "tcp_base.h"

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
    GTEST_SKIP() << "Skipping this test";
    int rc = EOK;
    int fd;
    struct epoll_event event;

    SKIP_TRUE(def_gw_exists, "No Default Gateway");

    fd = tcp_base::sock_create_nb();
    ASSERT_LE(0, fd);

    rc = connect(fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
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

    rc = connect(fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
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
