/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
    m_fwmark = 0;
    m_fwmask = 0;
    m_dst_pref_len = 0;
    m_src_pref_len = 0;
    memset(m_oif_name, 0, IFNAMSIZ * sizeof(char));
    memset(m_iif_name, 0, IFNAMSIZ * sizeof(char));
}

const std::string rule_val::to_str() const
{
    std::string rc;

    const uint8_t full_pref_len = (m_family == AF_INET) ? 32 : 128;

    rc = "Priority: " + std::to_string(m_priority);
    if (!m_src_addr.is_anyaddr()) {
        rc += " from: " + m_src_addr.to_str(m_family);
        if (m_src_pref_len != full_pref_len) {
            rc += "/" + std::to_string(m_src_pref_len);
        }
    }
    if (!m_dst_addr.is_anyaddr()) {
        rc += " to: " + m_dst_addr.to_str(m_family);
        if (m_dst_pref_len != full_pref_len) {
            rc += "/" + std::to_string(m_dst_pref_len);
        }
    }
    if (m_tos != 0) {
        rc += " tos: " + std::to_string(m_tos);
    }
    if (m_fwmark != 0) {
        char fwmark_str[32];
        snprintf(fwmark_str, sizeof(fwmark_str), " fwmark: 0x%x/0x%x", m_fwmark, m_fwmask);
        rc += fwmark_str;
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
