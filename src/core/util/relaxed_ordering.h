/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef RELAXED_ORDERING_H
#define RELAXED_ORDERING_H

// Per device decision for mkey relaxed ordering. No hardware, logging, or configuration access.
enum class ro_decision {
    RO,
    NOT_REQUESTED,
    // Requested, and the device does not report the write capability. Pass the flag:
    // it covers the read direction too.
    RO_WRITE_CAP_NOT_REPORTED,
    RO_REQUIRED_BY_DEVICE,
};

static inline ro_decision decide_relaxed_ordering(bool requested, bool caps_ro_write,
                                                  bool caps_ro_only)
{
    if (!requested && !caps_ro_only) {
        return ro_decision::NOT_REQUESTED;
    }
    if (!requested) {
        return ro_decision::RO_REQUIRED_BY_DEVICE;
    }
    if (!caps_ro_write) {
        return ro_decision::RO_WRITE_CAP_NOT_REPORTED;
    }
    return ro_decision::RO;
}

static inline bool ro_decision_passes_flag(ro_decision verdict)
{
    return verdict == ro_decision::RO || verdict == ro_decision::RO_WRITE_CAP_NOT_REPORTED ||
        verdict == ro_decision::RO_REQUIRED_BY_DEVICE;
}

#endif /* RELAXED_ORDERING_H */
