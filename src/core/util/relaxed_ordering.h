/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef RELAXED_ORDERING_H
#define RELAXED_ORDERING_H

/*
 * Startup decision for mkey relaxed ordering.
 *
 * Pure decision table with no hardware, logging, or configuration access.
 * caps_ro_supported is the device relaxed_ordering_write capability.
 * The verbs API passes one relaxed ordering access flag. The kernel sets
 * each mkey ordering bit from its own device capability. The write
 * capability alone decides device compatibility.
 * mce_sys_var::validate_config() evaluates the build arm and
 * ib_ctx_handler::check_capabilities() evaluates the device arms.
 * tests/gtest/core covers every row.
 */
enum class ro_decision {
    RO, // request relaxed ordering on every XLIO memory registration
    STRICT, // keep strict ordering, the legacy behavior
    FATAL_RO_UNSUPPORTED_BUILD, // requested, build lacks IBV_ACCESS_RELAXED_ORDERING
    FATAL_RO_UNSUPPORTED_DEVICE, // requested, device lacks the write capability
    FATAL_STRICT_UNSUPPORTED_DEVICE, // not requested, device supports relaxed ordering only
};

static inline ro_decision decide_relaxed_ordering(bool requested, bool caps_ro_supported,
                                                  bool caps_ro_only, bool build_has_flag)
{
    if (requested) {
        if (!build_has_flag) {
            return ro_decision::FATAL_RO_UNSUPPORTED_BUILD;
        }
        if (!caps_ro_supported) {
            return ro_decision::FATAL_RO_UNSUPPORTED_DEVICE;
        }
        return ro_decision::RO;
    }
    if (caps_ro_only) {
        return ro_decision::FATAL_STRICT_UNSUPPORTED_DEVICE;
    }
    return ro_decision::STRICT;
}

/*
 * Fatal-verdict predicate for the skip paths.
 * A wildcard (INADDR_ANY) attach creates receive flows on every IP-bearing
 * interface. sockinfo::attach_as_uc_receiver_anyip() skips a fatal-verdict
 * device on that path. xlio_registrator::register_memory() skips such a
 * device during global registration. An explicit bind or connect keeps the
 * fatal verdict in the ring constructor.
 */
static inline bool ro_verdict_is_fatal(ro_decision verdict)
{
    return verdict == ro_decision::FATAL_RO_UNSUPPORTED_BUILD ||
        verdict == ro_decision::FATAL_RO_UNSUPPORTED_DEVICE ||
        verdict == ro_decision::FATAL_STRICT_UNSUPPORTED_DEVICE;
}

#endif /* RELAXED_ORDERING_H */
