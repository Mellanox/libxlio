/*
 * Copyright (c) 2001-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#endif /* TESTS_GTEST_TCP_BASE_H_ */
