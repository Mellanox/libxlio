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

#include "xlio_base.h"

#if defined(EXTRA_API_ENABLED) && (EXTRA_API_ENABLED == 1)

class xlio_sockopt : public xlio_base {};

/**
 * @test xlio_sockopt.ti_1
 * @brief
 *    UDP RING_USER_ID good flow
 * @details
 */
TEST_F(xlio_sockopt, ti_1)
{
    int rc = EOK;
    int fd = UNDEFINED_VALUE;
    struct xlio_ring_alloc_logic_attr profile;
    int user_id = 100;

    memset(&profile, 0, sizeof(struct xlio_ring_alloc_logic_attr));

    profile.user_id = user_id;
    profile.ring_alloc_logic = RING_LOGIC_PER_USER_ID;
    profile.engress = 1;
    profile.comp_mask = XLIO_RING_ALLOC_MASK_RING_USER_ID | XLIO_RING_ALLOC_MASK_RING_ENGRESS;

    errno = EOK;
    fd = socket(m_family, SOCK_DGRAM, IPPROTO_IP);
    EXPECT_LE(0, fd);
    EXPECT_EQ(EOK, errno);

    errno = EOK;
    rc = setsockopt(fd, SOL_SOCKET, SO_XLIO_RING_ALLOC_LOGIC, &profile, sizeof(profile));
    EXPECT_EQ(0, rc);
    EXPECT_EQ(EOK, errno);

    close(fd);
}

/**
 * @test xlio_sockopt.ti_2
 * @brief
 *    UDP RING_USER_ID bad flow
 * @details
 */
TEST_F(xlio_sockopt, ti_2)
{
    int rc = EOK;
    int fd = UNDEFINED_VALUE;
    struct xlio_ring_alloc_logic_attr profile;
    int user_id = 100;
    int unsupported_mask = (1 << 4);

    memset(&profile, 0, sizeof(struct xlio_ring_alloc_logic_attr));

    profile.user_id = user_id;
    profile.ring_alloc_logic = RING_LOGIC_PER_USER_ID;
    profile.engress = 1;
    profile.comp_mask = unsupported_mask;

    errno = EOK;
    fd = socket(m_family, SOCK_DGRAM, IPPROTO_IP);
    EXPECT_LE(0, fd);
    EXPECT_EQ(EOK, errno);

    /* Wrong passed value */
    errno = EOK;
    rc = setsockopt(fd, SOL_SOCKET, SO_XLIO_RING_ALLOC_LOGIC, &profile, sizeof(profile));
    EXPECT_GT(0, rc);
    EXPECT_EQ(EINVAL, errno);

    /* Wrong data size */
    errno = EOK;
    rc = setsockopt(fd, SOL_SOCKET, SO_XLIO_RING_ALLOC_LOGIC, &profile, sizeof(profile) - 1);
    EXPECT_GT(0, rc);
    EXPECT_EQ(EINVAL, errno);

    close(fd);
}

#endif /* EXTRA_API_ENABLED */
