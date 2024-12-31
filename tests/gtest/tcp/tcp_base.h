/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
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

#ifndef TESTS_GTEST_TCP_BASE_H_
#define TESTS_GTEST_TCP_BASE_H_
#include <linux/errqueue.h>
#include <linux/if_packet.h>

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "common/cmn.h"

#include "tcp_base.h"

class tcp_base_sock : public test_base_sock {
    virtual int get_sock_type() const override { return SOCK_STREAM; }
};

/**
 * TCP Base class for tests
 */
class tcp_base : virtual public testing::Test, virtual public test_base, public tcp_base_sock {
public:
    int sock_create() const { return sock_create_fa(m_family, false); }
    int sock_create_nb() const { return sock_create_fa_nb(m_family); }

protected:
    virtual void SetUp() override { errno = EOK; }
    virtual void TearDown() override {}

    void peer_wait(int fd)
    {
        char keep_alive_check = 1;
        struct timeval tv;

        tv.tv_sec = 3;
        tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof tv);
        while (0 < send(fd, &keep_alive_check, sizeof(keep_alive_check), MSG_NOSIGNAL)) {
            usleep(100);
        }
        return;
    }
};

class tcp_send_zc : public tcp_base {
protected:
    void SetUp()
    {
        SKIP_TRUE(!run_fork_tests, "run_fork_tests was not set");

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
    void TearDown()
    {
        if (m_test_buf) {
            free_tmp_buffer(m_test_buf, m_test_buf_size);
        }
        if (m_test_file >= 0) {
            close(m_test_file);
        }

        tcp_base::TearDown();
    }
    int do_recv_completion(int fd, uint32_t &lo, uint32_t &hi)
    {
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
            log_error("cmsg: wrong type: %d.%d\n", cmsg->cmsg_level, cmsg->cmsg_type);
        }

        serr = (sock_extended_err *)CMSG_DATA(cmsg);

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
            log_trace("gap: %u..%u does not append to %u\n", lo, hi, next_completion);
        }
        next_completion = hi + 1;

        log_trace("completed as %s: %u (l=%u h=%u)\n",
                  (serr->ee_code & SO_EE_CODE_ZEROCOPY_COPIED ? "copy" : "zero copy"), range, lo,
                  hi);

        return range;
    }
    int do_recv_expected_completion(int fd, uint32_t &lo, uint32_t &hi, int expected)
    {
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
    int create_tmp_file(size_t size)
    {
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
    void *create_tmp_buffer(size_t size, int *alloc_size = NULL)
    {
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
    void free_tmp_buffer(void *ptr, size_t size)
    {
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

#endif /* TESTS_GTEST_TCP_BASE_H_ */
