/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef TESTS_GTEST_UDP_BASE_H_
#define TESTS_GTEST_UDP_BASE_H_

class udp_base_sock : public test_base_sock {
    virtual int get_sock_type() const override { return SOCK_DGRAM; }
};

/**
 * UDP Base class for tests
 */
class udp_base : public testing::Test, public test_base, public udp_base_sock {
public:
    int sock_create() const { return sock_create_fa(m_family, false); }
    int sock_create_nb() const { return sock_create_fa_nb(m_family); }

protected:
    virtual void SetUp() override { errno = EOK; }
    virtual void TearDown() override {}
};

#endif /* TESTS_GTEST_UDP_BASE_H_ */
