/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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

#endif /* TESTS_GTEST_TCP_BASE_H_ */
