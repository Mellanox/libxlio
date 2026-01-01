/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef DST_ENTRY_UDP_MC_H
#define DST_ENTRY_UDP_MC_H

#include "core/proto/dst_entry_udp.h"

class dst_entry_udp_mc : public dst_entry_udp {
public:
    dst_entry_udp_mc(const sock_addr &dst, uint16_t src_port, const ip_address &mc_tx_if_ip,
                     bool mc_b_loopback, socket_data &sock_data,
                     resource_allocation_key &ring_alloc_logic);
    virtual ~dst_entry_udp_mc();

protected:
    ip_address m_mc_tx_src_ip;
    bool m_b_mc_loopback_enabled;

    virtual void set_src_addr();
    virtual bool resolve_net_dev();
};

#endif /* DST_ENTRY_UDP_MC_H */
