/*
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "core/util/ip_address.h"
#include "core/dev/net_device_val.h"
#include "core/dev/net_device_entry.h"
#include "core/dev/net_device_table_mgr.h"
#include "rule_entry.h"
#include "rule_table_mgr.h"
#include "route_entry.h"

// debugging macros
#define MODULE_NAME "rte"
#undef MODULE_HDR_INFO
#define MODULE_HDR_INFO MODULE_NAME "[%s]:%d:%s() "
#undef __INFO__
#define __INFO__ to_str().c_str()

#define rt_entry_logdbg  __log_info_dbg
#define rt_entry_logwarn __log_info_warn

route_entry::route_entry(route_rule_table_key rtk)
    : cache_entry_subject<route_rule_table_key, route_val *>(rtk)
    , cache_observer()
    , m_b_offloaded_net_dev(false)
    , m_is_valid(false)
    , m_p_net_dev_entry(nullptr)
    , m_p_net_dev_val(nullptr)
{
    m_val = NULL;
    cache_entry_subject<route_rule_table_key, std::deque<rule_val *> *> *rr_entry = NULL;
    g_p_rule_table_mgr->register_observer(rtk, this, &rr_entry);
    m_p_rr_entry = dynamic_cast<rule_entry *>(rr_entry);
}

route_entry::~route_entry()
{
    unregister_to_net_device();
    if (m_p_rr_entry) {
        g_p_rule_table_mgr->unregister_observer(get_key(), this);
        m_p_rr_entry = nullptr;
    }
}

const std::string route_entry::to_str() const
{
    return get_key().to_str() + " -> " + (m_val ? m_val->get_if_name() : "invalid");
}

bool route_entry::get_val(INOUT route_val *&val)
{
    rt_entry_logdbg("");
    val = m_val;
    return is_valid();
}

void route_entry::set_val(IN route_val *&val)
{
    cache_entry_subject<route_rule_table_key, route_val *>::set_val(val);
}

void route_entry::register_to_net_device()
{
    cache_entry_subject<int, net_device_val *> *net_dev_entry = nullptr;
    if (g_p_net_device_table_mgr->register_observer(m_val->get_if_index(), this, &net_dev_entry)) {
        rt_entry_logdbg("route_entry [%p] is registered to if_index: %d", this,
                        m_val->get_if_index());
        m_p_net_dev_entry = (net_device_entry *)net_dev_entry;
        m_p_net_dev_entry->get_val(m_p_net_dev_val);
        m_b_offloaded_net_dev = true;
    } else {
        // We try to register also non-offloaded devices -> this log should be dbg.
        rt_entry_logdbg("route_entry [%p] failed to register to if_index: %d", this,
                        m_val->get_if_index());
        m_b_offloaded_net_dev = false;
    }
}

void route_entry::unregister_to_net_device()
{
    if (!m_val) {
        rt_entry_logdbg("ERROR: failed to find route val");
        return;
    }

    if (m_p_net_dev_val) {
        rt_entry_logdbg("Unregistering from if_index: %d", m_p_net_dev_val->get_if_idx());
        if (!g_p_net_device_table_mgr->unregister_observer(m_p_net_dev_val->get_if_idx(), this)) {
            rt_entry_logwarn("Failed to unregister net_device_entry (route_entry) if_index %d",
                             m_p_net_dev_val->get_if_idx());
        }
    }

    m_p_net_dev_entry = nullptr;
    m_p_net_dev_val = nullptr;
}

void route_entry::notify_cb()
{
    // got addr_change event from net_device_entry --> does not change the validity of route_entry!
    rt_entry_logdbg("");
    if (m_p_net_dev_entry->is_valid()) {
        m_p_net_dev_entry->get_val(m_p_net_dev_val);
    } else {
        m_p_net_dev_val = nullptr;
    }
    notify_observers();
}

void route_entry::notify_cb(event *ev)
{
    NOT_IN_USE(ev);
    notify_cb();
}
