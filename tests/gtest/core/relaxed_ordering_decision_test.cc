/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/*
 * util/relaxed_ordering.h decision table. No socket, ring, NIC, or XLIO preload.
 * Matrix rows M1-M5 for the relaxed ordering contract.
 * caps_ro_supported is the device relaxed_ordering_write capability. The verbs
 * API passes one relaxed ordering access flag. The kernel sets each mkey
 * ordering bit from its own device capability.
 * The build arm is a function parameter, so one build covers both flag states.
 *
 * Enforcement points of the verdicts:
 * - mce_sys_var::validate_config() stops the process on FATAL_RO_UNSUPPORTED_BUILD.
 * - ib_ctx_handler::check_capabilities() stores the per device verdict and logs a
 *   fatal device verdict at debug level.
 * - ib_ctx_handler::abort_on_relaxed_ordering_mismatch() stops the process when a
 *   ring binds the device to offloaded traffic, with mem_reg() as the backstop.
 * - sockinfo::attach_as_uc_receiver_anyip() skips a fatal verdict device on a
 *   wildcard attach and warns once per device.
 */

#include "common/def.h"

#include "util/relaxed_ordering.h"

// M1: requested, device supports relaxed ordering, build has the flag.
TEST(relaxed_ordering_decision, m1_requested_supported_returns_ro)
{
    EXPECT_EQ(ro_decision::RO,
              decide_relaxed_ordering(/*requested=*/true, /*caps_ro_supported=*/true,
                                      /*caps_ro_only=*/false, /*build_has_flag=*/true));
}

// M1 on relaxed-ordering-only firmware: the request matches the device.
TEST(relaxed_ordering_decision, m1_requested_on_ro_only_device_returns_ro)
{
    EXPECT_EQ(ro_decision::RO,
              decide_relaxed_ordering(/*requested=*/true, /*caps_ro_supported=*/true,
                                      /*caps_ro_only=*/true, /*build_has_flag=*/true));
}

// M2: requested, device lacks the relaxed ordering write capability.
TEST(relaxed_ordering_decision, m2_requested_unsupported_device_returns_fatal_device)
{
    EXPECT_EQ(ro_decision::FATAL_RO_UNSUPPORTED_DEVICE,
              decide_relaxed_ordering(/*requested=*/true, /*caps_ro_supported=*/false,
                                      /*caps_ro_only=*/false, /*build_has_flag=*/true));
}

// M3: requested, build lacks IBV_ACCESS_RELAXED_ORDERING.
TEST(relaxed_ordering_decision, m3_requested_without_build_flag_returns_fatal_build)
{
    EXPECT_EQ(ro_decision::FATAL_RO_UNSUPPORTED_BUILD,
              decide_relaxed_ordering(/*requested=*/true, /*caps_ro_supported=*/true,
                                      /*caps_ro_only=*/false, /*build_has_flag=*/false));
}

// M3 precedence: the build gap reports before the device gap.
TEST(relaxed_ordering_decision, m3_build_gap_wins_over_device_gap)
{
    EXPECT_EQ(ro_decision::FATAL_RO_UNSUPPORTED_BUILD,
              decide_relaxed_ordering(/*requested=*/true, /*caps_ro_supported=*/false,
                                      /*caps_ro_only=*/false, /*build_has_flag=*/false));
}

// M4: not requested, device allows strict ordering.
TEST(relaxed_ordering_decision, m4_not_requested_returns_strict)
{
    EXPECT_EQ(ro_decision::STRICT,
              decide_relaxed_ordering(/*requested=*/false, /*caps_ro_supported=*/false,
                                      /*caps_ro_only=*/false, /*build_has_flag=*/true));
}

// M4 on a device that also supports relaxed ordering: the override stands.
TEST(relaxed_ordering_decision, m4_not_requested_supported_device_returns_strict)
{
    EXPECT_EQ(ro_decision::STRICT,
              decide_relaxed_ordering(/*requested=*/false, /*caps_ro_supported=*/true,
                                      /*caps_ro_only=*/false, /*build_has_flag=*/true));
}

// M4 without the build flag: strict needs no flag.
TEST(relaxed_ordering_decision, m4_not_requested_without_build_flag_returns_strict)
{
    EXPECT_EQ(ro_decision::STRICT,
              decide_relaxed_ordering(/*requested=*/false, /*caps_ro_supported=*/false,
                                      /*caps_ro_only=*/false, /*build_has_flag=*/false));
}

// M5: not requested, device supports relaxed ordering only.
TEST(relaxed_ordering_decision, m5_not_requested_ro_only_device_returns_fatal)
{
    EXPECT_EQ(ro_decision::FATAL_STRICT_UNSUPPORTED_DEVICE,
              decide_relaxed_ordering(/*requested=*/false, /*caps_ro_supported=*/true,
                                      /*caps_ro_only=*/true, /*build_has_flag=*/true));
}

// M5 holds without the build flag: the device rules out strict mkeys.
TEST(relaxed_ordering_decision, m5_ro_only_fatal_without_build_flag)
{
    EXPECT_EQ(ro_decision::FATAL_STRICT_UNSUPPORTED_DEVICE,
              decide_relaxed_ordering(/*requested=*/false, /*caps_ro_supported=*/true,
                                      /*caps_ro_only=*/true, /*build_has_flag=*/false));
}

// M2 on contradictory capabilities: a device that reports relaxed ordering only
// without relaxed ordering mkey support still fails the request as unsupported.
TEST(relaxed_ordering_decision, m2_contradictory_caps_returns_fatal_device)
{
    EXPECT_EQ(ro_decision::FATAL_RO_UNSUPPORTED_DEVICE,
              decide_relaxed_ordering(/*requested=*/true, /*caps_ro_supported=*/false,
                                      /*caps_ro_only=*/true, /*build_has_flag=*/true));
}

// M5 on contradictory capabilities: relaxed ordering only stays fatal for a
// strict request even when the write capability is false.
TEST(relaxed_ordering_decision, m5_contradictory_caps_returns_fatal_strict)
{
    EXPECT_EQ(ro_decision::FATAL_STRICT_UNSUPPORTED_DEVICE,
              decide_relaxed_ordering(/*requested=*/false, /*caps_ro_supported=*/false,
                                      /*caps_ro_only=*/true, /*build_has_flag=*/true));
}

// ro_verdict_is_fatal() is the shared predicate of the wildcard attach skip and
// the global registration skip. Fatal verdicts skip, working verdicts attach.
TEST(relaxed_ordering_decision, fatal_predicate_matches_fatal_verdicts)
{
    EXPECT_FALSE(ro_verdict_is_fatal(ro_decision::RO));
    EXPECT_FALSE(ro_verdict_is_fatal(ro_decision::STRICT));
    EXPECT_TRUE(ro_verdict_is_fatal(ro_decision::FATAL_RO_UNSUPPORTED_BUILD));
    EXPECT_TRUE(ro_verdict_is_fatal(ro_decision::FATAL_RO_UNSUPPORTED_DEVICE));
    EXPECT_TRUE(ro_verdict_is_fatal(ro_decision::FATAL_STRICT_UNSUPPORTED_DEVICE));
}
