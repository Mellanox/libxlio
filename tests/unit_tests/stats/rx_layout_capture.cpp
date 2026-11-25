/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#include "util/rx_layout_capture.h"
#include <chrono>
#include <gtest/gtest.h>
#include <new>
#include <sys/mman.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
using namespace xlio_rx_layout;

TEST(rx_layout_capture, idle_then_exact_bounded_batch)
{
    slot s;
    ASSERT_TRUE(register_slot(s, 7));
    const auto ring_id = s.ring_id;
    EXPECT_EQ(0U, begin(s));
    ASSERT_TRUE(arm(s, s.control.load(), 2));
    record r {};
    r.sw_time_ns = 8960;
    auto token = begin(s);
    ASSERT_NE(0U, token);
    publish_attempt(s, token, &r);
    EXPECT_EQ(1U, captured(s.control.load()));
    batch b;
    EXPECT_FALSE(reader_copy(s, b));
    token = begin(s);
    ASSERT_NE(0U, token);
    r.sw_time_ns = 17920;
    publish_attempt(s, token, &r);
    EXPECT_EQ(0U, begin(s));
    ASSERT_TRUE(reader_copy(s, b));
    EXPECT_EQ(2U, b.count);
    EXPECT_EQ(8960U, b.records[0].sw_time_ns);
    EXPECT_EQ(17920U, b.records[1].sw_time_ns);
    EXPECT_EQ(ring_id, b.ring_id);
    EXPECT_EQ(7U, b.if_index);
    EXPECT_EQ(phase::idle, state(s.control.load()));
}
TEST(rx_layout_capture, cannot_rearm_or_read_partial_capture)
{
    slot s;
    ASSERT_TRUE(register_slot(s, 1));
    ASSERT_FALSE(arm(s, s.control.load(), 0));
    ASSERT_FALSE(arm(s, s.control.load(), capacity + 1));
    ASSERT_TRUE(arm(s, s.control.load(), 3));
    EXPECT_FALSE(arm(s, s.control.load(), 2));
    record r {};
    publish_attempt(s, begin(s), &r);
    EXPECT_FALSE(arm(s, s.control.load(), 2));
    batch b;
    EXPECT_FALSE(reader_copy(s, b));
    EXPECT_EQ(1U, captured(s.control.load()));
}
TEST(rx_layout_capture, excluded_packets_also_fill_the_requested_batch)
{
    slot s;
    ASSERT_TRUE(register_slot(s, 1));
    ASSERT_TRUE(arm(s, s.control.load(), 2));
    record r {};
    r.incomplete = 1;
    publish_attempt(s, begin(s), &r);
    publish_attempt(s, begin(s), &r);
    EXPECT_EQ(0U, begin(s));
    batch b;
    ASSERT_TRUE(reader_copy(s, b));
    EXPECT_EQ(2U, b.count);
    EXPECT_TRUE(b.records[0].incomplete);
}
TEST(rx_layout_capture, close_publishes_partial_and_reuse_changes_generation)
{
    slot s;
    ASSERT_TRUE(register_slot(s, 1));
    auto old = s.control.load();
    ASSERT_TRUE(arm(s, old, 2));
    record r {};
    r.sw_time_ns = 42;
    publish_attempt(s, begin(s), &r);
    xlio_rx_layout::close(s);
    EXPECT_FALSE(register_slot(s, 2));
    batch b;
    ASSERT_TRUE(reader_copy(s, b));
    EXPECT_TRUE(b.closed);
    EXPECT_EQ(1U, b.count);
    EXPECT_EQ(42U, b.records[0].sw_time_ns);
    ASSERT_TRUE(register_slot(s, 2));
    EXPECT_FALSE(arm(s, old, 1));
    EXPECT_NE(old >> 32, s.control.load() >> 32);
}
TEST(rx_layout_capture, close_unstarted_request_does_not_publish_previous_records)
{
    slot s;
    ASSERT_TRUE(register_slot(s, 1));
    ASSERT_TRUE(arm(s, s.control.load(), 1));
    record r {};
    publish_attempt(s, begin(s), &r);
    batch b;
    ASSERT_TRUE(reader_copy(s, b));
    ASSERT_TRUE(arm(s, s.control.load(), 1));
    xlio_rx_layout::close(s);
    ASSERT_TRUE(reader_copy(s, b));
    EXPECT_EQ(0U, b.count);
    EXPECT_TRUE(b.closed);
}
TEST(rx_layout_capture, close_during_read_keeps_records_pinned)
{
    slot s;
    ASSERT_TRUE(register_slot(s, 1));
    ASSERT_TRUE(arm(s, s.control.load(), 1));
    record r {};
    r.sw_time_ns = 99;
    publish_attempt(s, begin(s), &r);
    uint64_t token;
    ASSERT_TRUE(reader_claim(s, token));
    xlio_rx_layout::close(s);
    EXPECT_FALSE(register_slot(s, 2));
    EXPECT_EQ(99U, s.records[0].sw_time_ns);
    reader_release(s);
    EXPECT_TRUE(register_slot(s, 2));
}
TEST(rx_layout_capture, new_exclusive_reader_recovers_interrupted_copy)
{
    slot s;
    ASSERT_TRUE(register_slot(s, 1));
    ASSERT_TRUE(arm(s, s.control.load(), 1));
    record r {};
    publish_attempt(s, begin(s), &r);
    uint64_t token;
    ASSERT_TRUE(reader_claim(s, token));
    EXPECT_EQ(phase::ready, state(s.control.load()));
    batch b;
    ASSERT_TRUE(reader_copy(s, b));
    EXPECT_EQ(1U, b.count);
    EXPECT_EQ(1U, b.sequence);
}
TEST(rx_layout_capture, shared_mapping_publishes_complete_records_between_processes)
{
    void *memory =
        mmap(nullptr, sizeof(slot), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(MAP_FAILED, memory);
    auto *s = new (memory) slot;
    ASSERT_TRUE(register_slot(*s, 7));
    ASSERT_TRUE(arm(*s, s->control.load(), capacity));
    pid_t child = fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        for (unsigned i = 0; i < capacity; ++i) {
            record r {};
            r.frame_bytes = i;
            r.sw_time_ns = i ^ 0x12345678U;
            r.cqe[0] = (i ^ 0x87654321U) & 255U;
            publish_attempt(*s, begin(*s), &r);
        }
        _exit(0);
    }
    batch b;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    bool copied = false;
    while (!(copied = reader_copy(*s, b)) && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::yield();
    }
    int status;
    ASSERT_EQ(child, waitpid(child, &status, 0));
    ASSERT_TRUE(copied);
    EXPECT_EQ(0, status);
    ASSERT_EQ(capacity, b.count);
    for (unsigned i = 0; i < capacity; ++i) {
        EXPECT_EQ(i, b.records[i].frame_bytes);
        EXPECT_EQ(i ^ 0x12345678U, b.records[i].sw_time_ns);
        EXPECT_EQ((i ^ 0x87654321U) & 255U, b.records[i].cqe[0]);
    }
    s->~slot();
    EXPECT_EQ(0, munmap(memory, sizeof(slot)));
}

TEST(rx_layout_capture, repeated_process_handoffs_do_not_mix_batches)
{
    void *memory =
        mmap(nullptr, sizeof(slot), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(MAP_FAILED, memory);
    auto *s = new (memory) slot;
    ASSERT_TRUE(register_slot(*s, 7));
    constexpr unsigned rounds = 512;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    pid_t child = fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        for (unsigned round = 0; round < rounds; ++round) {
            uint64_t token = 0;
            while (!(token = begin(*s))) {
                if (std::chrono::steady_clock::now() >= deadline) {
                    _exit(2);
                }
                std::this_thread::yield();
            }
            for (unsigned i = 0; i < capacity; ++i) {
                record r {};
                r.frame_bytes = round;
                r.sw_time_ns = i;
                r.cqe[0] = ((round ^ i ^ 0x87654321U) & 255U);
                publish_attempt(*s, begin(*s), &r);
            }
        }
        _exit(0);
    }
    bool valid = true;
    for (unsigned round = 0; round < rounds && valid; ++round) {
        valid = arm(*s, s->control.load(), capacity);
        batch b;
        bool copied = false;
        while (valid && !(copied = reader_copy(*s, b)) &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::yield();
        }
        valid = valid && copied && b.count == capacity && b.sequence == round + 1;
        for (unsigned i = 0; i < b.count && valid; ++i) {
            const auto &r = b.records[i];
            valid = r.frame_bytes == round && r.sw_time_ns == i &&
                r.cqe[0] == (((round ^ i ^ 0x87654321U) & 255U));
        }
    }
    if (!valid) {
        kill(child, SIGKILL);
    }
    int status = 0;
    EXPECT_EQ(child, waitpid(child, &status, 0));
    EXPECT_EQ(0, status);
    EXPECT_TRUE(valid);
    s->~slot();
    EXPECT_EQ(0, munmap(memory, sizeof(slot)));
}

TEST(rx_layout_capture, fast_predicate_is_true_only_for_recording)
{
    slot s;
    EXPECT_FALSE(recording_requested(*recording_control(nullptr)));
    EXPECT_EQ(&s.control, recording_control(&s));
    for (auto p : {phase::free, phase::initializing, phase::idle, phase::recording, phase::ready}) {
        for (auto closed : {uint64_t(0), closed_bit}) {
            s.control.store((uint64_t(123) << 32) | closed | (uint64_t(256) << 8) |
                            (uint64_t(256) << 17) | uint64_t(p));
            EXPECT_EQ(p == phase::recording, recording_requested(s.control));
        }
    }
}
TEST(rx_layout_capture, request_atomically_resets_progress_at_both_capacity_limits)
{
    slot s;
    ASSERT_TRUE(register_slot(s, 7));
    for (unsigned requested : {256U, 1U, 256U}) {
        ASSERT_TRUE(arm(s, s.control.load(), requested));
        auto token = s.control.load();
        EXPECT_EQ(phase::recording, state(token));
        EXPECT_EQ(requested, target(token));
        EXPECT_EQ(requested, remaining(token));
        EXPECT_EQ(0U, captured(token));
        record r {};
        for (unsigned i = 0; i < requested; ++i) {
            r.frame_bytes = requested + i;
            publish_attempt(s, begin(s), &r);
            EXPECT_EQ(i + 1, captured(s.control.load()));
            EXPECT_EQ(i + 1 != requested, recording_requested(s.control));
        }
        batch b;
        ASSERT_TRUE(reader_copy(s, b));
        EXPECT_EQ(requested, b.count);
        EXPECT_EQ(requested, b.requested);
        EXPECT_EQ(requested, b.inspected);
        EXPECT_EQ(0U, b.excluded);
        EXPECT_EQ(requested, b.records[0].frame_bytes);
    }
}
TEST(rx_layout_capture, ready_stays_immutable_until_reader_releases_it)
{
    slot s;
    ASSERT_TRUE(register_slot(s, 7));
    ASSERT_TRUE(arm(s, s.control.load(), 1));
    record r {};
    r.frame_bytes = 100;
    publish_attempt(s, begin(s), &r);
    uint64_t first, replacement;
    ASSERT_TRUE(reader_claim(s, first));
    EXPECT_EQ(phase::ready, state(s.control.load()));
    // Simulate an interrupted copy and replacement under the exclusive file lock.
    ASSERT_TRUE(reader_claim(s, replacement));
    EXPECT_EQ(first, replacement);
    EXPECT_FALSE(arm(s, replacement, 1));
    xlio_rx_layout::close(s);
    EXPECT_FALSE(register_slot(s, 8));
    EXPECT_EQ(100U, s.records[0].frame_bytes);
    EXPECT_TRUE(reader_release(s));
    EXPECT_EQ(phase::free, state(s.control.load()));
    EXPECT_TRUE(register_slot(s, 8));
}
TEST(rx_layout_capture, closing_before_first_record_advances_sequence_once)
{
    slot s;
    ASSERT_TRUE(register_slot(s, 7));
    ASSERT_TRUE(arm(s, s.control.load(), 256));
    EXPECT_NE(0U, begin(s));
    xlio_rx_layout::close(s);
    xlio_rx_layout::close(s);
    batch b;
    ASSERT_TRUE(reader_copy(s, b));
    EXPECT_EQ(0U, b.count);
    EXPECT_EQ(1U, b.sequence);
    EXPECT_TRUE(b.closed);
}

TEST(rx_layout_capture, rejects_previous_capture_abi)
{
    region r;
    EXPECT_TRUE(valid_region(r));
    r.abi_version = 2;
    EXPECT_FALSE(valid_region(r));
}
