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

#include "xliod_base.h"

#include "tools/daemon/bitmap.h"

class xliod_bitmap : public ::testing::Test {};

TEST_F(xliod_bitmap, ti_1)
{
    ASSERT_EQ(4U, sizeof(bitmap_item_t));
}

TEST_F(xliod_bitmap, ti_2)
{
    bitmap_t *bm = NULL;

    bitmap_create(&bm, 10);
    ASSERT_TRUE(bm);
    ASSERT_EQ(10U, bitmap_size(bm));

    bitmap_destroy(bm);
}

TEST_F(xliod_bitmap, ti_3)
{
    bitmap_t *bm = NULL;

    bitmap_create(&bm, 0x7ff);
    ASSERT_TRUE(bm);

    ASSERT_EQ(0x7ffU, bitmap_size(bm));

    EXPECT_EQ(0U, elem_idx(0));
    EXPECT_EQ(0U, elem_idx(31));
    EXPECT_EQ(1U, elem_idx(32));
    EXPECT_EQ(2U, elem_idx(64));
    EXPECT_EQ(32U, elem_idx(0x400));
    EXPECT_EQ(63U, elem_idx(0x7ff));

    bitmap_destroy(bm);
}

TEST_F(xliod_bitmap, ti_4)
{
    bitmap_t *bm = NULL;
    int bits[] = {0, 7, 31, 32, 64};
    size_t i;

    bitmap_create(&bm, 64);
    ASSERT_TRUE(bm);

    for (i = 0; i < ARRAY_SIZE(bits); i++) {
        EXPECT_EQ(0, bitmap_test(bm, i));
        bitmap_set(bm, i);
        EXPECT_EQ(1, bitmap_test(bm, i));
    }

    bitmap_destroy(bm);
}

TEST_F(xliod_bitmap, ti_5)
{
    bitmap_t *bm = NULL;
    int bits[] = {0, 7, 31, 32, 64};
    size_t i;

    bitmap_create(&bm, 64);
    ASSERT_TRUE(bm);

    for (i = 0; i < ARRAY_SIZE(bits); i++) {
        EXPECT_EQ(0, bitmap_test(bm, i));
        bitmap_set(bm, i);
        EXPECT_EQ(1, bitmap_test(bm, i));
        bitmap_clear(bm, i);
        EXPECT_EQ(0, bitmap_test(bm, i));
    }

    bitmap_destroy(bm);
}

TEST_F(xliod_bitmap, ti_6)
{
    bitmap_t *bm = NULL;
    int bits[] = {0, 7, 31, 32, 64};
    size_t i;

    bitmap_create(&bm, 64);
    ASSERT_TRUE(bm);

    for (i = 0; i < ARRAY_SIZE(bits); i++) {
        EXPECT_EQ(0, bitmap_test(bm, i));
        bitmap_flip(bm, i);
        EXPECT_EQ(1, bitmap_test(bm, i));
    }

    for (i = 0; i < ARRAY_SIZE(bits); i++) {
        EXPECT_EQ(1, bitmap_test(bm, i));
        bitmap_flip(bm, i);
        EXPECT_EQ(0, bitmap_test(bm, i));
    }

    bitmap_destroy(bm);
}

TEST_F(xliod_bitmap, ti_7)
{
    bitmap_t *bm = NULL;

    bitmap_create(&bm, 64);
    ASSERT_TRUE(bm);

    ASSERT_EQ(64U, bitmap_size(bm));

    EXPECT_EQ(0, bitmap_test_group(bm, 0, 7));
    EXPECT_EQ(0, bitmap_test_group(bm, 0, 64));

    bitmap_set(bm, 7);
    bitmap_set(bm, 8);
    EXPECT_EQ(1, bitmap_test_group(bm, 7, 2));

    EXPECT_EQ(-1, bitmap_test_group(bm, 6, 3));
    EXPECT_EQ(-1, bitmap_test_group(bm, 0, 64));

    bitmap_destroy(bm);
}

TEST_F(xliod_bitmap, ti_8)
{
    bitmap_t *bm = NULL;

    bitmap_create(&bm, 64);
    ASSERT_TRUE(bm);

    ASSERT_EQ(64U, bitmap_size(bm));

    EXPECT_EQ(0, bitmap_find_group(bm, 0, 2, 0));
    EXPECT_EQ(32, bitmap_find_group(bm, 32, 7, 0));

    EXPECT_EQ(-1, bitmap_find_group(bm, 0, 7, 1));
    EXPECT_EQ(-1, bitmap_find_group(bm, 32, 7, 1));

    bitmap_set(bm, 7);
    bitmap_set(bm, 8);
    EXPECT_EQ(7, bitmap_find_group(bm, 0, 2, 1));

    bitmap_destroy(bm);
}

TEST_F(xliod_bitmap, ti_9)
{
    bitmap_t *bm = NULL;
    int i;

    bitmap_create(&bm, 64);
    ASSERT_TRUE(bm);

    ASSERT_EQ(64U, bitmap_size(bm));

    EXPECT_EQ(0, bitmap_find_first_zero(bm));

    bitmap_set(bm, 0);
    bitmap_set(bm, 1);
    bitmap_set(bm, 2);
    EXPECT_EQ(3, bitmap_find_first_zero(bm));

    bitmap_set(bm, 4);
    EXPECT_EQ(3, bitmap_find_first_zero(bm));

    bitmap_set(bm, 3);
    EXPECT_EQ(5, bitmap_find_first_zero(bm));

    for (i = 0; i < 33; i++) {
        bitmap_set(bm, i);
    }
    EXPECT_EQ(33, bitmap_find_first_zero(bm));

    for (i = 0; i < 64; i++) {
        bitmap_set(bm, i);
    }
    EXPECT_EQ(-1, bitmap_find_first_zero(bm));

    bitmap_destroy(bm);
}
