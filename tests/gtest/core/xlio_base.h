/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef TESTS_GTEST_XLIO_BASE_H_
#define TESTS_GTEST_XLIO_BASE_H_

#include <xlio_extra.h>
#include <xlio_types.h>
/**
 * To enable xlio tests you need to set below EXTRA_API_ENABLED to 1
 * or you can add the following CPPFLAG during compilation 'make CPPFLAGS="-DEXTRA_API_ENABLED=1"'
 */
#ifndef EXTRA_API_ENABLED
#define EXTRA_API_ENABLED 0
#endif

/**
 * XLIO Base class for tests
 */
class xlio_base : virtual public testing::Test, virtual public test_base {
protected:
    virtual void SetUp();
    virtual void TearDown();

protected:
#if defined(EXTRA_API_ENABLED) && (EXTRA_API_ENABLED == 1)
    static struct xlio_api_t *xlio_api;
#endif /* EXTRA_API_ENABLED */
};

#if defined(EXTRA_API_ENABLED) && (EXTRA_API_ENABLED == 1)
class xlio_zc_api_base : public xlio_base {
public:
    virtual void SetUp()
    {
        xlio_base::SetUp();
        errno = EOK;
        base_init_xlio_zc_api();
    };
    void base_create_poll_group(xlio_poll_group_attr *attr, xlio_poll_group_t *group)
    {
        int rc;
        rc = xlio_api->xlio_poll_group_create(attr, group);
        ASSERT_TRUE(rc == 0);
    }
    void base_destroy_poll_group(xlio_poll_group_t group)
    {
        int rc;
        rc = xlio_api->xlio_poll_group_destroy(group);
        ASSERT_TRUE(rc == 0);
    }
    void base_create_socket(xlio_socket_attr *attr, xlio_socket_t *sock)
    {

        int rc;
        rc = xlio_api->xlio_socket_create(attr, sock);
        ASSERT_TRUE(rc == 0);
    }
    void base_destroy_socket(xlio_socket_t sock)
    {
        int rc;
        rc = xlio_api->xlio_socket_destroy(sock);
        ASSERT_TRUE(rc == 0);
    }
    void base_init_xlio_zc_api()
    {
        int rc;
        struct xlio_init_attr iattr = {
            .flags = 0,
            .memory_cb = nullptr,
            .memory_alloc = nullptr,
            .memory_free = nullptr,
        };

        rc = xlio_api->xlio_init_ex(&iattr);
        ASSERT_TRUE(rc == 0);
    };
    void base_cleanup_xlio_zc_api()
    {
        int rc;
        rc = xlio_api->xlio_exit();
        ASSERT_TRUE(rc == 0);
    };
};
#endif /* EXTRA_API_ENABLED */

#endif /* TESTS_GTEST_XLIO_BASE_H_ */
