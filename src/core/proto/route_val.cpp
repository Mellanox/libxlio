/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <string.h>

#include "route_val.h"
#include "core/dev/net_device_table_mgr.h"

#define MODULE_NAME "rtv"

#define rt_val_loginfo __log_info_info
#define rt_val_logdbg  __log_info_dbg
#define rt_val_logfunc __log_info_func

route_val::route_val()
    : m_dst_addr(in6addr_any)
    , m_src_addr(in6addr_any)
    , m_gw_addr(in6addr_any)
{
    m_dst_pref_len = 0;
    m_family = 0;
    m_protocol = 0;
    m_scope = 0;
    m_type = 0;
    m_table_id = 0;
    memset(m_if_name, 0, IFNAMSIZ * sizeof(char));
    m_if_index = 0;
    m_is_valid = false;
    m_b_deleted = false;
    m_mtu = 0;
}

const std::string route_val::to_str() const
{
    std::string rc;

    rc = "dst: ";
    rc += m_dst_addr.is_anyaddr()
        ? "default"
        : m_dst_addr.to_str(m_family) + '/' + std::to_string(m_dst_pref_len);
    if (!m_gw_addr.is_anyaddr()) {
        rc += " gw: " + m_gw_addr.to_str(m_family);
    }
    rc += " dev: " + std::string(m_if_name);
    if (!m_src_addr.is_anyaddr()) {
        rc += " src: " + m_src_addr.to_str(m_family);
    }
    rc += " table: ";
    rc += (m_table_id == RT_TABLE_MAIN) ? "main" : std::to_string(m_table_id);
    rc += " scope " + std::to_string(m_scope);
    rc += " type " + std::to_string(m_type);
    rc += " index " + std::to_string(m_if_index);
    if (m_mtu) {
        rc += " mtu " + std::to_string(m_mtu);
    }
    if (m_b_deleted) {
        rc += " ---> DELETED";
    }

    return rc;
}

void route_val::print_val() const
{
    rt_val_logdbg("%s", to_str().c_str());
}

void route_val::set_mtu(uint32_t mtu)
{
    if (mtu > g_p_net_device_table_mgr->get_max_mtu()) {
        rt_val_logdbg("route mtu cannot be bigger then max mtu set on devices");
    } else {
        m_mtu = mtu;
    }
}
