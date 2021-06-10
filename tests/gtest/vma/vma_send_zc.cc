/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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

#include <time.h>
#include <linux/errqueue.h>
#include <linux/if_packet.h>

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "common/cmn.h"

#if defined(EXTRA_API_ENABLED) && (EXTRA_API_ENABLED == 1)

#ifdef SO_ZEROCOPY

#include <infiniband/verbs.h>

#include "tcp/tcp_base.h"
#include "vma_base.h"


class vma_send_zc : public vma_base, public tcp_base {
protected:
	void SetUp() {
		int fd = -1;
		int rc = EOK;
		int opt_val = 1;

		tcp_base::SetUp();

		fd = tcp_base::sock_create();
		ASSERT_LE(0, fd);

		rc = setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &opt_val, sizeof(opt_val));
		SKIP_TRUE((0 == rc), "TX zero copy is not supported");

		close(fd);

		errno = EOK;
		m_fd = -1;
		m_test_buf = NULL;
		m_test_buf_size = 0;
		m_test_buf_chunk = 0;
		m_test_file = -1;
	}
	void TearDown()	{
		if (m_test_buf) {
			free_tmp_buffer(m_test_buf, m_test_buf_size);
		}
		if (m_test_file >= 0) {
			close(m_test_file);
		}

		tcp_base::TearDown();
	}
	int do_recv_completion(int fd, uint32_t &lo, uint32_t &hi) {
		int ret = 0;
		struct sock_extended_err *serr;
		struct msghdr msg = {};
		struct cmsghdr *cmsg;
		uint32_t range;
		char cbuf[100];
		static uint32_t next_completion = 0;

		lo = hi = range = 0;
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);

		ret = recvmsg(fd, &msg, MSG_ERRQUEUE);
		if (ret == -1 && errno == EAGAIN) {
			return 0;
		}
		if (ret == -1) {
			log_error("recvmsg notification failed errno: %d\n", errno);
		}
		if (msg.msg_flags & MSG_CTRUNC) {
			log_error("recvmsg notification: truncated errno: %d\n", errno);
		}

		cmsg = CMSG_FIRSTHDR(&msg);
		if (!cmsg) {
			log_error("no cmsg\n");
		}
		if (!((cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR) ||
		      (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_RECVERR) ||
		      (cmsg->cmsg_level == SOL_PACKET && cmsg->cmsg_type == PACKET_TX_TIMESTAMP))) {
			log_error("cmsg: wrong type: %d.%d\n",
					cmsg->cmsg_level, cmsg->cmsg_type);
		}

		serr = (sock_extended_err*)CMSG_DATA(cmsg);

		if (serr->ee_origin != SO_EE_ORIGIN_ZEROCOPY) {
			log_error("serr: wrong origin: %u\n", serr->ee_origin);
		}
		if (serr->ee_errno != 0) {
			log_error("serr: wrong error code: %u\n", serr->ee_errno);
		}

		hi = serr->ee_data;
		lo = serr->ee_info;
		range = hi - lo + 1;

		/* Notification gaps due to drops,
		 * reordering and retransmissions.
		 */
		if (lo != next_completion) {
			log_trace("gap: %u..%u does not append to %u\n",
				lo, hi, next_completion);
		}
		next_completion = hi + 1;

		log_trace("completed as %s: %u (l=%u h=%u)\n",
				(serr->ee_code & SO_EE_CODE_ZEROCOPY_COPIED ? "copy" : "zero copy"), range, lo, hi);

		return range;
	}
	int do_recv_expected_completion(int fd, uint32_t &lo, uint32_t &hi, int expected) {
		int ret = 0;
		int wait_ms = 500;
		uint32_t _lo = 0;
		uint32_t _hi = 0;
		int completion = 0;

		lo = (uint32_t)(-1);
		hi = 0;
		while ((completion < expected) && (wait_ms--)) {
			ret = do_recv_completion(fd, _lo, _hi);
			if (ret > 0) {
				completion += ret;
				lo = sys_min(lo, _lo);
				hi = _hi;
			} else {
				usleep(1000);
			}
		}
		return completion;
	}
	int create_tmp_file(size_t size) {
		char filename[] = "/tmp/mytemp.XXXXXX";
		int fd = mkstemp(filename);

		if (fd >= 0) {
			unlink(filename);
			while (size--) {
				char buf = size % 255;
				write(fd, &buf, sizeof(buf));
			}
			fsync(fd);
		}
		return fd;
	}
	void* create_tmp_buffer(size_t size, int *alloc_size = NULL) {
		char *ptr = NULL;
		int page_size = 0x200000;
		size_t i = 0;

		size = (size + page_size - 1) & (~(page_size - 1));
		ptr = (char *)memalign(page_size, size);
		if (ptr) {
			for (i = 0; i < size; i++) {
				ptr[i] = 'a' + (i % ('z' - 'a' + 1));
			}
			if (alloc_size) {
				*alloc_size = size;
			}
		} else {
			ptr = NULL;
		}

		return ptr;
	}
	void free_tmp_buffer(void *ptr, size_t size) {
		UNREFERENCED_PARAMETER(size);
		free(ptr);
	}

protected:
	int m_fd;
	char *m_test_buf;
	int m_test_file;
	int m_test_buf_size;
	int m_test_buf_chunk;
};

/**
 * @test vma_send_zc.ti_1
 * @brief
 *    Wrong parameter getsockopt(SO_XLIO_PD)
 * @details
 */
TEST_F(vma_send_zc, ti_1) {
	int rc = EOK;

	int pid = fork();

	if (0 == pid) {  /* I am the child */
		int opt_val = 1;
		struct xlio_pd_attr xlio_pd_attr;
		socklen_t op_len = (socklen_t)(sizeof(xlio_pd_attr) - 1);

		barrier_fork(pid);

		m_fd = tcp_base::sock_create();
		ASSERT_LE(0, m_fd);

		rc = bind(m_fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
		ASSERT_EQ(0, rc);

		rc = connect(m_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		log_trace("Established connection: fd=%d to %s\n",
				m_fd, sys_addr2str((struct sockaddr_in *)&server_addr));

		rc = setsockopt(m_fd, SOL_SOCKET, SO_ZEROCOPY, &opt_val, sizeof(opt_val));
		ASSERT_EQ(0, rc);

		errno = EOK;
		rc = getsockopt(m_fd, SOL_SOCKET, SO_XLIO_PD, &xlio_pd_attr, &op_len);
		EXPECT_EQ(EINVAL, errno);
		EXPECT_GT(0, rc);

		peer_wait(m_fd);

		close(m_fd);

		/* This exit is very important, otherwise the fork
		 * keeps running and may duplicate other tests.
		 */
		exit(testing::Test::HasFailure());
	} else {  /* I am the parent */
		int l_fd;
		struct sockaddr peer_addr;
		socklen_t socklen;

		l_fd = tcp_base::sock_create();
		ASSERT_LE(0, l_fd);

		rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		rc = listen(l_fd, 5);
		ASSERT_EQ(0, rc);

		barrier_fork(pid);

		socklen = sizeof(peer_addr);
		m_fd = accept(l_fd, &peer_addr, &socklen);
		ASSERT_LE(0, m_fd);
		close(l_fd);

		log_trace("Accepted connection: fd=%d from %s\n",
				m_fd, sys_addr2str((struct sockaddr_in *)&peer_addr));

		close(m_fd);

		ASSERT_EQ(0, wait_fork(pid));
	}
}

/**
 * @test vma_send_zc.ti_2
 * @brief
 *    Wrong parameter sendmsg(SOL_VMA_PD)
 * @details
 */
TEST_F(vma_send_zc, ti_2) {
	int rc = EOK;
	char test_msg[] = "Hello test";

	m_test_buf = (char *)create_tmp_buffer(sizeof(test_msg), &m_test_buf_size);
	ASSERT_TRUE(m_test_buf);

	memcpy(m_test_buf, test_msg, sizeof(test_msg));

	int pid = fork();

	if (0 == pid) {  /* I am the child */
		int opt_val = 1;
		struct xlio_pd_key xlio_pd_key[1];
		struct iovec vec[1];
		struct msghdr msg = {};
		int cmsg_len = sizeof(xlio_pd_key);
		struct cmsghdr *cmsg;
		char cbuf[CMSG_SPACE(cmsg_len)];
		struct xlio_pd_attr xlio_pd_attr;
		socklen_t op_len = (socklen_t)sizeof(xlio_pd_attr);

		barrier_fork(pid);

		m_fd = tcp_base::sock_create();
		ASSERT_LE(0, m_fd);

		rc = bind(m_fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
		ASSERT_EQ(0, rc);

		rc = connect(m_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		log_trace("Established connection: fd=%d to %s\n",
				m_fd, sys_addr2str((struct sockaddr_in *)&server_addr));

		rc = setsockopt(m_fd, SOL_SOCKET, SO_ZEROCOPY, &opt_val, sizeof(opt_val));
		ASSERT_EQ(0, rc);

		rc = getsockopt(m_fd, SOL_SOCKET, SO_XLIO_PD, &xlio_pd_attr, &op_len);
		ASSERT_EQ(0, rc);
		ASSERT_EQ(sizeof(xlio_pd_attr), op_len);
		ASSERT_TRUE(xlio_pd_attr.ib_pd);

		xlio_pd_key[0].flags = 0;
		xlio_pd_key[0].mkey = 1111;

		vec[0].iov_base = (void *)m_test_buf;
		vec[0].iov_len = m_test_buf_size;

		memset(&msg, 0, sizeof(struct msghdr));
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_XLIO_PD;
		cmsg->cmsg_len = CMSG_LEN(cmsg_len);
		memcpy(CMSG_DATA(cmsg), &xlio_pd_key[0], sizeof(xlio_pd_key[0]));
		msg.msg_controllen = cmsg->cmsg_len;

		msg.msg_iov = vec;
		msg.msg_iovlen = sizeof(vec) / sizeof(vec[0]);

		/* no MSG_ZEROCOPY */
		rc = sendmsg(m_fd, &msg, MSG_DONTWAIT);
		EXPECT_EQ(EINVAL, errno);
		EXPECT_GT(0, rc);

		/* incorrect msg_controllen */
		cmsg->cmsg_len -= 1;
		rc = sendmsg(m_fd, &msg, MSG_DONTWAIT | MSG_ZEROCOPY);
		EXPECT_EQ(EINVAL, errno);
		EXPECT_GT(0, rc);

		peer_wait(m_fd);

		close(m_fd);

		/* This exit is very important, otherwise the fork
		 * keeps running and may duplicate other tests.
		 */
		exit(testing::Test::HasFailure());
	} else {  /* I am the parent */
		int l_fd;
		struct sockaddr peer_addr;
		socklen_t socklen;

		l_fd = tcp_base::sock_create();
		ASSERT_LE(0, l_fd);

		rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		rc = listen(l_fd, 5);
		ASSERT_EQ(0, rc);

		barrier_fork(pid);

		socklen = sizeof(peer_addr);
		m_fd = accept(l_fd, &peer_addr, &socklen);
		ASSERT_LE(0, m_fd);
		close(l_fd);

		log_trace("Accepted connection: fd=%d from %s\n",
				m_fd, sys_addr2str((struct sockaddr_in *)&peer_addr));

		close(m_fd);

		ASSERT_EQ(0, wait_fork(pid));
	}
}

/**
 * @test vma_send_zc.ti_3
 * @brief
 *    Send data using few sendmsg(MSG_ZEROCOPY)
 * @details
 */
TEST_F(vma_send_zc, ti_3_few_send) {
	int rc = EOK;
	int test_iter = 3;
	int test_msg_size = 16;
	int i = 0;
	char *ptr = NULL;

	m_test_buf = (char *)create_tmp_buffer((test_iter * test_msg_size), &m_test_buf_size);
	ASSERT_TRUE(m_test_buf);

	ptr = m_test_buf;
	for (i = 0; i < test_iter; i++) {
		rc = snprintf(ptr, test_msg_size, "Hello test: #%2d", i);
		ptr += test_msg_size;
	}

	int pid = fork();

	if (0 == pid) {  /* I am the child */
		int opt_val = 1;
		uint32_t lo, hi;
		struct epoll_event event;
		struct xlio_pd_key xlio_pd_key[1];
		struct iovec vec[1];
		struct msghdr msg = {};
		int cmsg_len = sizeof(xlio_pd_key);
		struct cmsghdr *cmsg;
		char cbuf[CMSG_SPACE(cmsg_len)];
		struct ibv_pd *ib_pd = NULL;
		struct ibv_mr *ib_mr = NULL;
		struct xlio_pd_attr xlio_pd_attr;
		socklen_t op_len = (socklen_t)sizeof(xlio_pd_attr);

		barrier_fork(pid);

		m_fd = tcp_base::sock_create();
		ASSERT_LE(0, m_fd);

		rc = bind(m_fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
		ASSERT_EQ(0, rc);

		rc = connect(m_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		log_trace("Established connection: fd=%d to %s\n",
				m_fd, sys_addr2str((struct sockaddr_in *)&server_addr));

		rc = setsockopt(m_fd, SOL_SOCKET, SO_ZEROCOPY, &opt_val, sizeof(opt_val));
		ASSERT_EQ(0, rc);

		rc = getsockopt(m_fd, SOL_SOCKET, SO_XLIO_PD, &xlio_pd_attr, &op_len);
		ASSERT_EQ(0, rc);
		ASSERT_EQ(sizeof(xlio_pd_attr), op_len);
		ASSERT_TRUE(xlio_pd_attr.ib_pd);

		ib_pd = (struct ibv_pd *)xlio_pd_attr.ib_pd;
		ib_mr = ibv_reg_mr(ib_pd, (void *)m_test_buf, (size_t)m_test_buf_size, IBV_ACCESS_LOCAL_WRITE);
		xlio_pd_key[0].flags = 0;
		xlio_pd_key[0].mkey = ib_mr->lkey;

		ptr = m_test_buf;
		for (i = 0; i < test_iter; i++) {
			vec[0].iov_base = (void *)ptr;
			vec[0].iov_len = test_msg_size;

			memset(&msg, 0, sizeof(struct msghdr));
			msg.msg_control = cbuf;
			msg.msg_controllen = sizeof(cbuf);
			cmsg = CMSG_FIRSTHDR(&msg);
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type = SCM_XLIO_PD;
			cmsg->cmsg_len = CMSG_LEN(cmsg_len);
			memcpy(CMSG_DATA(cmsg), &xlio_pd_key[0], sizeof(xlio_pd_key[0]));
			msg.msg_controllen = cmsg->cmsg_len;

			msg.msg_iov = vec;
			msg.msg_iovlen = sizeof(vec) / sizeof(vec[0]);
			rc = sendmsg(m_fd, &msg, MSG_DONTWAIT | MSG_ZEROCOPY);
			EXPECT_EQ(test_msg_size, rc);

			ptr += test_msg_size;
		}

		event.events = EPOLLOUT;
		event.data.fd = m_fd;
		rc = test_base::event_wait(&event);
		EXPECT_LT(0, rc);
		EXPECT_TRUE(EPOLLOUT | event.events);

		rc = do_recv_expected_completion(m_fd, lo, hi, test_iter);
		EXPECT_EQ(test_iter, rc);
		EXPECT_EQ(0, lo);
		EXPECT_EQ((test_iter - 1), hi);

		peer_wait(m_fd);

		ibv_dereg_mr(ib_mr);
		close(m_fd);

		/* This exit is very important, otherwise the fork
		 * keeps running and may duplicate other tests.
		 */
		exit(testing::Test::HasFailure());
	} else {  /* I am the parent */
		int l_fd;
		struct sockaddr peer_addr;
		socklen_t socklen;

		l_fd = tcp_base::sock_create();
		ASSERT_LE(0, l_fd);

		rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		rc = listen(l_fd, 5);
		ASSERT_EQ(0, rc);

		barrier_fork(pid);

		socklen = sizeof(peer_addr);
		m_fd = accept(l_fd, &peer_addr, &socklen);
		ASSERT_LE(0, m_fd);
		close(l_fd);

		log_trace("Accepted connection: fd=%d from %s\n",
				m_fd, sys_addr2str((struct sockaddr_in *)&peer_addr));

		ptr = m_test_buf;
		for (i = 0; i < test_iter; i++) {
			char buf[test_msg_size];
			rc = recv(m_fd, (void *)buf, sizeof(buf), 0);
			EXPECT_EQ(test_msg_size, rc);

			log_trace("Test check #%d: expected: '%s' actual: '%s'\n",
					i, ptr, buf);

			EXPECT_EQ(memcmp(buf, ptr, rc), 0);

			ptr += test_msg_size;
		}

		close(m_fd);

		ASSERT_EQ(0, wait_fork(pid));
	}
}

/**
 * @test vma_send_zc.ti_4
 * @brief
 *    Send large data using sendmsg(MSG_ZEROCOPY) as
 *    single call
 * @details
 */
TEST_F(vma_send_zc, ti_4_large_send) {
	int rc = EOK;

	m_test_buf_chunk = 0x1000;
	m_test_buf_size = 10 * m_test_buf_chunk;

	m_test_buf = (char *)create_tmp_buffer(m_test_buf_size);
	ASSERT_TRUE(m_test_buf);
	ASSERT_TRUE(m_test_buf_chunk <= m_test_buf_size);

	int pid = fork();

	if (0 == pid) {  /* I am the child */
		int opt_val = 1;
		uint32_t lo, hi;
		struct epoll_event event;
		struct xlio_pd_key xlio_pd_key[(m_test_buf_size + (m_test_buf_chunk - 1)) / m_test_buf_chunk];
		struct iovec vec[(m_test_buf_size + (m_test_buf_chunk - 1)) / m_test_buf_chunk];
		struct msghdr msg = {};
		int cmsg_len = sizeof(xlio_pd_key);
		struct cmsghdr *cmsg;
		char cbuf[CMSG_SPACE(cmsg_len)];
		struct ibv_pd *ib_pd = NULL;
		struct ibv_mr *ib_mr = NULL;
		struct xlio_pd_attr xlio_pd_attr;
		socklen_t op_len = (socklen_t)sizeof(xlio_pd_attr);
		int i = 0;

		barrier_fork(pid);

		m_fd = tcp_base::sock_create();
		ASSERT_LE(0, m_fd);

		opt_val = 1 << 21;
		rc = setsockopt(m_fd, SOL_SOCKET, SO_SNDBUF, &opt_val, sizeof(opt_val));
		ASSERT_EQ(0, rc);

		rc = bind(m_fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
		ASSERT_EQ(0, rc);

		rc = connect(m_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		log_trace("Established connection: fd=%d to %s\n",
				m_fd, sys_addr2str((struct sockaddr_in *)&server_addr));

		opt_val = 1;
		rc = setsockopt(m_fd, SOL_SOCKET, SO_ZEROCOPY, &opt_val, sizeof(opt_val));
		ASSERT_EQ(0, rc);

		rc = getsockopt(m_fd, SOL_SOCKET, SO_XLIO_PD, &xlio_pd_attr, &op_len);
		ASSERT_EQ(0, rc);
		ASSERT_EQ(sizeof(xlio_pd_attr), op_len);
		ASSERT_TRUE(xlio_pd_attr.ib_pd);

		ib_pd = (struct ibv_pd *)xlio_pd_attr.ib_pd;
		ib_mr = ibv_reg_mr(ib_pd, (void *)m_test_buf, (size_t)m_test_buf_size, IBV_ACCESS_LOCAL_WRITE);

		while ((i * m_test_buf_chunk) < m_test_buf_size) {
			vec[i].iov_base = (void *)((uintptr_t)m_test_buf + (i * m_test_buf_chunk));
			vec[i].iov_len = sys_min(m_test_buf_chunk, (m_test_buf_size - i * m_test_buf_chunk));
			xlio_pd_key[i].flags = 0;
			xlio_pd_key[i].mkey = ib_mr->lkey;
			i++;
		}

		memset(&msg, 0, sizeof(struct msghdr));
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_XLIO_PD;
		cmsg->cmsg_len = CMSG_LEN(cmsg_len);
		memcpy(CMSG_DATA(cmsg), xlio_pd_key, sizeof(xlio_pd_key));
		msg.msg_controllen = cmsg->cmsg_len;

		msg.msg_iov = vec;
		msg.msg_iovlen = sizeof(vec) / sizeof(vec[0]);

		rc = sendmsg(m_fd, &msg, MSG_DONTWAIT | MSG_ZEROCOPY);
		EXPECT_EQ(m_test_buf_size, rc);

		event.events = EPOLLOUT;
		event.data.fd = m_fd;
		rc = test_base::event_wait(&event);
		EXPECT_LT(0, rc);
		EXPECT_TRUE(EPOLLOUT | event.events);

		rc = do_recv_expected_completion(m_fd, lo, hi, 1);
		EXPECT_EQ(1, rc);
		EXPECT_EQ(0, lo);
		EXPECT_EQ(0, hi);

		peer_wait(m_fd);

		close(m_fd);

		/* This exit is very important, otherwise the fork
		 * keeps running and may duplicate other tests.
		 */
		exit(testing::Test::HasFailure());
	} else {  /* I am the parent */
		int l_fd;
		struct sockaddr peer_addr;
		socklen_t socklen;
		int i = 0;
		char *buf = NULL;

		buf = (char *)malloc(m_test_buf_size);
		ASSERT_TRUE(buf);

		l_fd = tcp_base::sock_create();
		ASSERT_LE(0, l_fd);

		rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		ASSERT_EQ(0, rc);

		rc = listen(l_fd, 5);
		ASSERT_EQ(0, rc);

		barrier_fork(pid);

		socklen = sizeof(peer_addr);
		m_fd = accept(l_fd, &peer_addr, &socklen);
		ASSERT_LE(0, m_fd);
		close(l_fd);

		log_trace("Accepted connection: fd=%d from %s\n",
				m_fd, sys_addr2str((struct sockaddr_in *)&peer_addr));

		i = m_test_buf_size;
		while (i > 0 && !child_fork_exit()) {
			rc = recv(m_fd, (void *)buf, i, MSG_WAITALL);
			EXPECT_GE(rc, 0);
			i -= rc;
		}
		EXPECT_EQ(0, i);
		EXPECT_EQ(memcmp(buf, m_test_buf, m_test_buf_size), 0);

		close(m_fd);

		ASSERT_EQ(0, wait_fork(pid));
	}
}

#endif /* SO_ZEROCOPY */

#endif /* EXTRA_API_ENABLED */
