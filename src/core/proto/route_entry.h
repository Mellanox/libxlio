/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-3-Clause
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
