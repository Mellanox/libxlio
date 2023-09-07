/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
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

#ifndef ROUTE_VAL_H
#define ROUTE_VAL_H

#include "core/util/if.h" // IFNAMSIZ
#include "core/util/ip_address.h"

#include <string>

class route_val {
public:
    route_val();

    inline void set_dst_pref_len(uint8_t dst_pref_len) { m_dst_pref_len = dst_pref_len; };
    inline void set_dst_addr(ip_address const &dst_addr) { m_dst_addr = dst_addr; };
    inline void set_src_addr(ip_address const &src_addr) { m_src_addr = src_addr; };
    inline void set_gw(ip_address const &gw) { m_gw_addr = gw; };
    inline void set_family(sa_family_t family) { m_family = family; };
    inline void set_protocol(unsigned char protocol) { m_protocol = protocol; };
    inline void set_scope(unsigned char scope) { m_scope = scope; };
    inline void set_type(unsigned char type) { m_type = type; };
    inline void set_table_id(uint32_t table_id) { m_table_id = table_id; };
    void set_mtu(uint32_t mtu);
    inline void set_if_index(int if_index) { m_if_index = if_index; };
    inline void set_if_name(char *if_name) { memcpy(m_if_name, if_name, IFNAMSIZ); };

    inline uint8_t get_dst_pref_len() const { return m_dst_pref_len; };
    inline const ip_address &get_dst_addr() const { return m_dst_addr; };
    inline const ip_address &get_src_addr() const { return m_src_addr; };
    inline const ip_address &get_gw_addr() const { return m_gw_addr; };
    inline sa_family_t get_family() const { return m_family; };
    inline unsigned char get_protocol() const { return m_protocol; };
    inline unsigned char get_scope() const { return m_scope; };
    inline unsigned char get_type() const { return m_type; };
    inline uint32_t get_table_id() const { return m_table_id; };
    inline int get_if_index() const { return m_if_index; };
    inline const char *get_if_name() const { return m_if_name; };
    inline uint32_t get_mtu() const { return m_mtu; };

    inline void set_state(bool state) { m_is_valid = state; };
    inline bool is_valid() const { return m_is_valid; };

    inline void set_deleted(bool deleted) { m_b_deleted = deleted; };
    inline bool is_deleted() const { return m_b_deleted; };

    const std::string to_str() const;
    void print_val() const;

    bool operator==(const route_val &val) const
    {
        return m_dst_addr == val.m_dst_addr && m_gw_addr == val.m_gw_addr &&
            m_dst_pref_len == val.m_dst_pref_len && m_family == val.m_family &&
            m_table_id == val.m_table_id && m_if_index == val.m_if_index;
    };

private:
    ip_address m_dst_addr;
    ip_address m_src_addr;
    ip_address m_gw_addr;

    unsigned char m_family;
    unsigned char m_protocol;
    unsigned char m_scope;
    unsigned char m_type;
    uint32_t m_table_id;

    char m_if_name[IFNAMSIZ];
    int m_if_index;
    uint32_t m_mtu;

    uint8_t m_dst_pref_len;

    bool m_is_valid;
    bool m_b_deleted;
};

#endif /* ROUTE_VAL_H */
