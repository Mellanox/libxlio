/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <string.h>

#include "rule_val.h"

#define MODULE_NAME "rrv"

#define rr_val_loginfo __log_info_info
#define rr_val_logdbg  __log_info_dbg
#define rr_val_logfunc __log_info_func

rule_val::rule_val()
    : m_dst_addr(in6addr_any)
    , m_src_addr(in6addr_any)
{
    m_protocol = 0;
    m_tos = 0;
    m_family = 0;
    m_is_valid = false;
    m_priority = 0;
    m_table_id = 0;
    memset(m_oif_name, 0, IFNAMSIZ * sizeof(char));
    memset(m_iif_name, 0, IFNAMSIZ * sizeof(char));
}

const std::string rule_val::to_str() const
{
    std::string rc;

    rc = "Priority: " + std::to_string(m_priority);
    if (!m_src_addr.is_anyaddr()) {
        rc += " from: " + m_src_addr.to_str(m_family);
    }
    if (!m_dst_addr.is_anyaddr()) {
        rc += " to: " + m_dst_addr.to_str(m_family);
    }
    if (m_tos != 0) {
        rc += " tos: " + std::to_string(m_tos);
    }
    if (m_iif_name[0] != '\0') {
        rc += " iff: " + std::string(m_iif_name);
    }
    if (m_oif_name[0] != '\0') {
        rc += " off: " + std::string(m_oif_name);
    }
    rc += " lookup table: ";
    rc += (m_table_id == RT_TABLE_MAIN) ? "main" : std::to_string(m_table_id);

    return rc;
}

// This function prints a string that represent a row in the rule table as debug log.
void rule_val::print_val() const
{
    rr_val_logdbg("%s", to_str().c_str());
}
