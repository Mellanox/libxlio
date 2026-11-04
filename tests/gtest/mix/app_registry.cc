/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#include "common/def.h"

#include "mix_base.h"

#include "src/core/sock/sock-app.h"

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)

#include <set>
#include <thread>
#include <vector>

#include <sys/syscall.h>
#include <unistd.h>

#ifndef HAVE_GETTID
/* glibc < 2.30 has no gettid() wrapper and the suite links no libxlio
 * objects, so provide the syscall fallback the header-inline registry
 * methods call (the product's lives in vlogger.cpp) */
pid_t gettid(void)
{
    return syscall(__NR_gettid);
}
#endif

class app_registry : public mix_base {
protected:
    app_worker_registry m_reg;
};

TEST_F(app_registry, worker_id_unknown_is_minus_one)
{
    EXPECT_EQ(-1, m_reg.worker_id(gettid()));
    EXPECT_EQ(-1, m_reg.listen_fd_owner(42));
    EXPECT_EQ(-1, m_reg.dup_parent_fd(42));
}

TEST_F(app_registry, publish_worker_assigns_then_reuses)
{
    int first = m_reg.publish_worker(10);
    int second = m_reg.publish_worker(11);

    EXPECT_EQ(0, first);
    EXPECT_EQ(first, second);
    EXPECT_EQ(first, m_reg.worker_id(gettid()));
    EXPECT_EQ(gettid(), m_reg.listen_fd_owner(10));
    EXPECT_EQ(gettid(), m_reg.listen_fd_owner(11));
}

TEST_F(app_registry, publish_worker_ids_are_unique_per_thread)
{
    std::set<int> ids;
    int id_a = -1;
    int id_b = -1;

    std::thread ta([&] { id_a = m_reg.publish_worker(20); });
    std::thread tb([&] { id_b = m_reg.publish_worker(21); });
    ta.join();
    tb.join();

    ids.insert(id_a);
    ids.insert(id_b);
    EXPECT_EQ(2U, ids.size());
    EXPECT_TRUE(ids.count(0) && ids.count(1));
}

TEST_F(app_registry, record_and_erase_listen_fd)
{
    m_reg.record_listen_fd(30, 1234);
    EXPECT_EQ(1234, m_reg.listen_fd_owner(30));
    m_reg.erase_listen_fd(30);
    EXPECT_EQ(-1, m_reg.listen_fd_owner(30));
}

TEST_F(app_registry, dup_records_resolve_to_the_original)
{
    m_reg.record_dup(41, 40);

    EXPECT_EQ(40, m_reg.dup_parent_fd(41));
    EXPECT_EQ(40, m_reg.dup_parent_fd(40));
    EXPECT_EQ(1, m_reg.count_original_listeners());

    m_reg.record_dup(42, 40);
    EXPECT_EQ(40, m_reg.dup_parent_fd(42));
    EXPECT_EQ(1, m_reg.count_original_listeners());
}

TEST_F(app_registry, erase_worker_drops_fd_and_thread_mappings)
{
    int id = m_reg.publish_worker(50);
    EXPECT_EQ(id, m_reg.worker_id(gettid()));

    m_reg.erase_worker(50, gettid());
    EXPECT_EQ(-1, m_reg.listen_fd_owner(50));
    EXPECT_EQ(-1, m_reg.worker_id(gettid()));
}

TEST_F(app_registry, pop_distinguishes_empty_from_recycled_vacancy)
{
    int id = 12345;

    EXPECT_FALSE(m_reg.pop_unused_worker_id(id));
    EXPECT_EQ(12345, id);

    /* recycling an unknown tid stores the -1 vacancy marker, and a later
     * pop must hand it back rather than report an empty pool */
    m_reg.recycle_worker(99999, 99999);
    EXPECT_TRUE(m_reg.pop_unused_worker_id(id));
    EXPECT_EQ(-1, id);
    EXPECT_FALSE(m_reg.pop_unused_worker_id(id));
}

TEST_F(app_registry, recycle_returns_the_worker_id_to_the_pool)
{
    m_reg.publish_thread_worker(777, 5);
    EXPECT_EQ(5, m_reg.worker_id(777));

    m_reg.recycle_worker(777, 777);
    EXPECT_EQ(-1, m_reg.worker_id(777));

    int id = -2;
    EXPECT_TRUE(m_reg.pop_unused_worker_id(id));
    EXPECT_EQ(5, id);
}

TEST_F(app_registry, concurrent_ops_stay_consistent)
{
    const int threads = 4;
    const int iters = 5000;
    std::vector<std::thread> workers;

    for (int t = 0; t < threads; t++) {
        workers.emplace_back([&, t] {
            for (int i = 0; i < iters; i++) {
                int fd = t * iters + i;
                m_reg.record_listen_fd(fd, t + 1);
                m_reg.publish_thread_worker(t + 1, t);
                (void)m_reg.worker_id(t + 1);
                (void)m_reg.listen_fd_owner(fd);
                m_reg.erase_listen_fd(fd);
            }
        });
    }
    for (auto &w : workers) {
        w.join();
    }

    for (int t = 0; t < threads; t++) {
        EXPECT_EQ(t, m_reg.worker_id(t + 1));
        EXPECT_EQ(-1, m_reg.listen_fd_owner(t * iters));
    }
}

#endif /* DEFINED_NGINX || DEFINED_ENVOY */
