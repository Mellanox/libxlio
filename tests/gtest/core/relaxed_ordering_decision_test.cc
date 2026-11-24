/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

// util/relaxed_ordering.h decision table. No socket, ring, NIC, or XLIO preload.

#include <string>

#include "common/def.h"

#include "util/relaxed_ordering.h"

struct ro_decision_row {
    bool requested;
    bool caps_ro_write;
    bool caps_ro_only;
    ro_decision expected;
};

// Every input combination of decide_relaxed_ordering(). A row with caps_ro_only and
// without caps_ro_write has contradictory capabilities.
static const ro_decision_row ro_decision_table[] = {
    {false, false, false, ro_decision::NOT_REQUESTED},
    {false, true, false, ro_decision::NOT_REQUESTED},
    {false, true, true, ro_decision::RO_REQUIRED_BY_DEVICE},
    {false, false, true, ro_decision::RO_REQUIRED_BY_DEVICE},
    {true, true, false, ro_decision::RO},
    {true, true, true, ro_decision::RO},
    {true, false, false, ro_decision::RO_WRITE_CAP_NOT_REPORTED},
    {true, false, true, ro_decision::RO_WRITE_CAP_NOT_REPORTED},
};

static std::string describe(const ro_decision_row &row)
{
    return std::string("requested=") + (row.requested ? "1" : "0") +
        " caps_ro_write=" + (row.caps_ro_write ? "1" : "0") +
        " caps_ro_only=" + (row.caps_ro_only ? "1" : "0");
}

static ro_decision decide(const ro_decision_row &row)
{
    return decide_relaxed_ordering(row.requested, row.caps_ro_write, row.caps_ro_only);
}

TEST(relaxed_ordering_decision, table_lists_every_input_combination_once)
{
    unsigned seen = 0U;
    for (const ro_decision_row &row : ro_decision_table) {
        const unsigned bit = 1U << ((row.requested ? 4U : 0U) | (row.caps_ro_write ? 2U : 0U) |
                                    (row.caps_ro_only ? 1U : 0U));
        EXPECT_EQ(0U, seen & bit) << "duplicate row: " << describe(row);
        seen |= bit;
    }
    EXPECT_EQ(0xFFU, seen);
}

TEST(relaxed_ordering_decision, every_input_combination_returns_the_table_verdict)
{
    for (const ro_decision_row &row : ro_decision_table) {
        EXPECT_EQ(row.expected, decide(row)) << describe(row);
    }
}

TEST(relaxed_ordering_decision, flag_predicate_matches_each_verdict)
{
    EXPECT_TRUE(ro_decision_passes_flag(ro_decision::RO));
    EXPECT_TRUE(ro_decision_passes_flag(ro_decision::RO_WRITE_CAP_NOT_REPORTED));
    EXPECT_TRUE(ro_decision_passes_flag(ro_decision::RO_REQUIRED_BY_DEVICE));
    EXPECT_FALSE(ro_decision_passes_flag(ro_decision::NOT_REQUESTED));
}

TEST(relaxed_ordering_decision, passes_flag_on_request_or_ro_only_device)
{
    for (const ro_decision_row &row : ro_decision_table) {
        EXPECT_EQ(row.requested || row.caps_ro_only, ro_decision_passes_flag(decide(row)))
            << describe(row);
    }
}
