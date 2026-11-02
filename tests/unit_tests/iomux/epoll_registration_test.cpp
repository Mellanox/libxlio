/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/*
 * After building XLIO:
 *   make -C tests/unit_tests
 *   tests/unit_tests/unit_tests --gtest_filter=epoll_registration.*
 *
 * Exercise the real epfd ready lists without a connection or packet generator.
 * Only the virtual readiness probe is controlled to schedule a notification
 * precisely between the MOD readiness snapshot and its cleanup.
 */
#include "../xlio_test_init.h"
#include <atomic>
#include <gtest/gtest.h>
#include <thread>

#include "core/xlio.h"
#include "event/entity_context.h"
#include "sock/fd_collection.h"
#include "sock/sockinfo_tcp.h"

class registration_socket : public sockinfo_tcp {
public:
    using sockinfo::insert_epoll_event;

    explicit registration_socket(entity_context *owner)
        : sockinfo_tcp(SOCKET_FAKE_FD, AF_INET)
    {
        m_entity_context = owner;
        g_p_fd_collection->set_socket(get_fd(), this);
    }

    ~registration_socket() override
    {
        g_p_fd_collection->clear_socket(get_fd());
        m_entity_context = nullptr;
        m_n_rx_pkt_ready_list_count.store(0, std::memory_order_relaxed);
    }

    bool skip_os_select() override { return true; }
    bool is_writeable() override { return false; }

    bool is_readable(bool, fd_array_t * = nullptr) override
    {
        bool ready = m_n_rx_pkt_ready_list_count != 0;
        if (notify_during_probe) {
            notify_during_probe = false;
            std::thread worker([this] { publish_data(); });
            worker.join();
        }
        return ready;
    }

    void publish_data()
    {
        add_rx_ready_count(1);
        insert_epoll_event(EPOLLIN);
    }

    void clear_data() { m_n_rx_pkt_ready_list_count.store(0, std::memory_order_relaxed); }

    bool notify_during_probe = false;
};

class epoll_registration : public testing::Test {
protected:
    static void SetUpTestCase() { ASSERT_EQ(0, initialize_xlio_unit_tests()); }

    void SetUp() override { ASSERT_TRUE(safe_mce_sys().is_threads_mode()); }
};

TEST_F(epoll_registration, mod_preserves_notification_after_empty_snapshot)
{
    entity_context owner(0);
    registration_socket socket(&owner);
    int fd = ::epoll_create1(EPOLL_CLOEXEC);
    ASSERT_GE(fd, 0);
    {
        epfd_info epfd(fd, 16);
        epoll_event event = {};
        event.events = EPOLLIN;
        ASSERT_EQ(0, epfd.ctl(EPOLL_CTL_ADD, socket.get_fd(), &event));
        socket.notify_during_probe = true;
        EXPECT_EQ(0, epfd.ctl(EPOLL_CTL_MOD, socket.get_fd(), &event));
        EXPECT_TRUE(epfd.move_entity_context_ready_events());
        EXPECT_TRUE(epfd.m_ready_fds.is_member(&socket));
        EXPECT_EQ(0, epfd.ctl(EPOLL_CTL_DEL, socket.get_fd(), nullptr));
    }
    ::close(fd);
}

TEST_F(epoll_registration, oneshot_rearm_preserves_notification_after_empty_snapshot)
{
    entity_context owner(0);
    registration_socket socket(&owner);
    int fd = ::epoll_create1(EPOLL_CLOEXEC);
    ASSERT_GE(fd, 0);
    {
        epfd_info epfd(fd, 16);
        epoll_event event = {};
        event.events = EPOLLONESHOT; // EPOLLIN has been consumed.
        ASSERT_EQ(0, epfd.ctl(EPOLL_CTL_ADD, socket.get_fd(), &event));
        event.events |= EPOLLIN;
        socket.notify_during_probe = true;
        EXPECT_EQ(0, epfd.ctl(EPOLL_CTL_MOD, socket.get_fd(), &event));
        EXPECT_TRUE(epfd.move_entity_context_ready_events());
        EXPECT_TRUE(epfd.m_ready_fds.is_member(&socket));
        EXPECT_EQ(0, epfd.ctl(EPOLL_CTL_DEL, socket.get_fd(), nullptr));
    }
    ::close(fd);
}

TEST_F(epoll_registration, add_reports_data_published_before_registration_without_owner)
{
    registration_socket socket(nullptr); // Parent listeners also have no entity owner.
    int fd = ::epoll_create1(EPOLL_CLOEXEC);
    ASSERT_GE(fd, 0);
    {
        epfd_info epfd(fd, 16);
        std::thread worker([&socket] { socket.publish_data(); });
        worker.join();
        epoll_event event = {};
        event.events = EPOLLIN;
        EXPECT_EQ(0, epfd.ctl(EPOLL_CTL_ADD, socket.get_fd(), &event));
        EXPECT_TRUE(epfd.m_ready_fds.is_member(&socket));
        EXPECT_EQ(0, epfd.ctl(EPOLL_CTL_DEL, socket.get_fd(), nullptr));
    }
    ::close(fd);
}

TEST_F(epoll_registration, mod_disabling_read_does_not_keep_a_stale_ready_hint)
{
    entity_context owner(0);
    registration_socket socket(&owner);
    int fd = ::epoll_create1(EPOLL_CLOEXEC);
    ASSERT_GE(fd, 0);
    {
        epfd_info epfd(fd, 16);
        epoll_event event = {};
        event.events = EPOLLIN;
        ASSERT_EQ(0, epfd.ctl(EPOLL_CTL_ADD, socket.get_fd(), &event));
        socket.publish_data();
        event.events = 0;
        EXPECT_EQ(0, epfd.ctl(EPOLL_CTL_MOD, socket.get_fd(), &event));
        EXPECT_FALSE(epfd.move_entity_context_ready_events());
        EXPECT_TRUE(epfd.m_ready_fds.empty());
        EXPECT_EQ(0, epfd.ctl(EPOLL_CTL_DEL, socket.get_fd(), nullptr));
    }
    ::close(fd);
}

TEST_F(epoll_registration, disabled_mask_still_reports_error_and_hangup)
{
    entity_context owner(0);
    registration_socket socket(&owner);
    int fd = ::epoll_create1(EPOLL_CLOEXEC);
    ASSERT_GE(fd, 0);
    {
        epfd_info epfd(fd, 16);
        epoll_event event = {};
        ASSERT_EQ(0, epfd.ctl(EPOLL_CTL_ADD, socket.get_fd(), &event));
        socket.insert_epoll_event(EPOLLERR | EPOLLHUP);
        EXPECT_TRUE(epfd.move_entity_context_ready_events());
        EXPECT_EQ(uint32_t(EPOLLERR | EPOLLHUP), socket.get_epoll_event_flags());
        EXPECT_EQ(0, epfd.ctl(EPOLL_CTL_DEL, socket.get_fd(), nullptr));
    }
    ::close(fd);
}

static void check_concurrent_add(entity_context *owner)
{
    registration_socket socket(owner);
    int fd = ::epoll_create1(EPOLL_CLOEXEC);
    ASSERT_GE(fd, 0);
    {
        epfd_info epfd(fd, 16);
        epoll_event event = {};
        event.events = EPOLLIN;
        for (int iteration = 0; iteration < 1000; ++iteration) {
            socket.clear_data();
            std::atomic<bool> start {false};
            std::thread worker([&] {
                while (!start.load(std::memory_order_acquire)) {
                    std::this_thread::yield();
                }
                socket.publish_data();
            });
            start.store(true, std::memory_order_release);
            int result = epfd.ctl(EPOLL_CTL_ADD, socket.get_fd(), &event);
            worker.join();
            ASSERT_EQ(0, result);
            EXPECT_TRUE(epfd.move_entity_context_ready_events()) << iteration;
            EXPECT_TRUE(epfd.m_ready_fds.is_member(&socket)) << iteration;
            ASSERT_EQ(0, epfd.ctl(EPOLL_CTL_DEL, socket.get_fd(), nullptr));
        }
    }
    ::close(fd);
}

TEST_F(epoll_registration, add_racing_with_worker_notification)
{
    entity_context owner(0);
    check_concurrent_add(&owner);
}

TEST_F(epoll_registration, add_racing_with_notification_without_entity_owner)
{
    check_concurrent_add(nullptr);
}
