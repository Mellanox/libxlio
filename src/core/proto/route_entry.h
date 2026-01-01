/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef ROUTE_ENTRY_H
#define ROUTE_ENTRY_H

#include "core/proto/route_rule_table_key.h"
#include "core/infra/cache_subject_observer.h"
#include "route_val.h"

// Forward declarations
class net_device_entry;
class net_device_val;
class rule_entry;

class route_entry : public cache_entry_subject<route_rule_table_key, route_val *>,
                    public cache_observer {
public:
    friend class route_table_mgr;

    route_entry(route_rule_table_key rtk);
    virtual ~route_entry();

    bool get_val(INOUT route_val *&val);
    void set_val(IN route_val *&val);

    inline net_device_val *get_net_dev_val() { return m_p_net_dev_val; }
    inline rule_entry *get_rule_entry() const { return m_p_rr_entry; }

    inline void set_entry_valid() { m_is_valid = true; }
    inline bool is_valid() { return m_is_valid && m_val && m_val->is_valid(); }

    const std::string to_str() const;

    virtual void notify_cb();
    virtual void notify_cb(event *ev);

private:
    void register_to_net_device();
    void unregister_to_net_device();

    bool m_b_offloaded_net_dev;
    bool m_is_valid;

    net_device_entry *m_p_net_dev_entry;
    net_device_val *m_p_net_dev_val;
    rule_entry *m_p_rr_entry;
};

#endif /* ROUTE_ENTRY_H */
