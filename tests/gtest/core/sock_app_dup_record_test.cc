/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/*
 * app_conf dup-record bookkeeping (record_dup/forget_fd). Compiles only in
 * --enable-envoy builds. No socket, ring, NIC, or XLIO preload.
 */

#include "common/def.h"

#if defined(DEFINED_ENVOY)

#include "sock/sock-app.h"

// Same loop shape as proc_envoy()'s original_listen_count initializer.
static int count_self_entries(const app_conf &conf)
{
    int count = 0;
    for (const auto &itr : conf.map_dup_fd) {
        if (itr.first == itr.second) {
            count++;
        }
    }
    return count;
}

TEST(sock_app_dup_record, dup_record_adds_fid_and_source_self_entry)
{
    app_conf conf(APP_ENVOY, 4);

    conf.record_dup(7, 3, /*src_is_reuseport=*/false);

    EXPECT_EQ(2U, conf.map_dup_fd.size());
    ASSERT_EQ(1U, conf.map_dup_fd.count(7));
    EXPECT_EQ(3, conf.map_dup_fd.at(7));
    ASSERT_EQ(1U, conf.map_dup_fd.count(3));
    EXPECT_EQ(3, conf.map_dup_fd.at(3));
}

TEST(sock_app_dup_record, reuseport_source_is_not_recorded)
{
    app_conf conf(APP_ENVOY, 4);

    conf.record_dup(7, 3, /*src_is_reuseport=*/true);

    EXPECT_EQ(0U, conf.map_dup_fd.size());
}

TEST(sock_app_dup_record, failed_dup_is_not_recorded)
{
    app_conf conf(APP_ENVOY, 4);

    conf.record_dup(-1, 3, /*src_is_reuseport=*/false);

    EXPECT_EQ(0U, conf.map_dup_fd.size());
}

TEST(sock_app_dup_record, forget_fd_erases_only_the_given_fd)
{
    app_conf conf(APP_ENVOY, 4);
    conf.record_dup(7, 3, /*src_is_reuseport=*/false);

    conf.forget_fd(7);

    EXPECT_EQ(1U, conf.map_dup_fd.size());
    EXPECT_EQ(0U, conf.map_dup_fd.count(7));
    ASSERT_EQ(1U, conf.map_dup_fd.count(3));
    EXPECT_EQ(3, conf.map_dup_fd.at(3));

    conf.forget_fd(3);

    EXPECT_EQ(0U, conf.map_dup_fd.size());
}

TEST(sock_app_dup_record, self_entry_count_tracks_recorded_sources_only)
{
    app_conf conf(APP_ENVOY, 4);

    conf.record_dup(8, 4, /*src_is_reuseport=*/true);
    conf.record_dup(7, 3, /*src_is_reuseport=*/false);

    EXPECT_EQ(1, count_self_entries(conf));
    EXPECT_EQ(2U, conf.map_dup_fd.size());
}

TEST(sock_app_dup_record, repeated_dup_record_is_idempotent)
{
    app_conf conf(APP_ENVOY, 4);

    conf.record_dup(7, 3, /*src_is_reuseport=*/false);
    conf.record_dup(7, 3, /*src_is_reuseport=*/false);

    EXPECT_EQ(2U, conf.map_dup_fd.size());
    EXPECT_EQ(3, conf.map_dup_fd.at(7));
    EXPECT_EQ(3, conf.map_dup_fd.at(3));
    EXPECT_EQ(1, count_self_entries(conf));
}

#endif /* DEFINED_ENVOY */
