/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef RULE_ENTRY_H
#define RULE_ENTRY_H

#include "core/infra/cache_subject_observer.h"
#include "core/proto/route_rule_table_key.h"
#include "rule_val.h"

// This class represents an entry in rule table cached history.
class rule_entry : public cache_entry_subject<route_rule_table_key, std::deque<rule_val *> *> {
public:
    friend class rule_table_mgr;

    rule_entry(route_rule_table_key rrk);

    bool get_val(INOUT std::deque<rule_val *> *&val);

    inline bool is_valid() { return !m_val->empty(); }

    inline const std::string to_str() const { return get_key().to_str(); }

private:
    std::deque<rule_val *> values;
};

#endif /* RULE_ENTRY_H */
