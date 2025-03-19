/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef NEIGHBOUR_TABLE_MGR_H
#define NEIGHBOUR_TABLE_MGR_H

#include "core/proto/neighbour.h"
#include "core/infra/cache_subject_observer.h"

class neigh_table_mgr : public cache_table_mgr<neigh_key, class neigh_val *>, public observer {
public:
    neigh_table_mgr();
    ~neigh_table_mgr();
    virtual void notify_cb(event *event);
    int create_rdma_id_and_register(rdma_cm_id *&cma_id, enum rdma_port_space port_space,
                                    event_handler_rdma_cm *context);
    bool register_observer(neigh_key, const cache_observer *,
                           cache_entry_subject<neigh_key, class neigh_val *> **);

private:
    /* This function will retrieve neigh transport type by the following actions:
     * 1. go to route manager table and get route entry according to the peer ip
     * 2. get netdev from route entry
     * 3. get transport type from netdev
     */
    neigh_entry *create_new_entry(neigh_key neigh_key, const observer *dst);
    void create_rdma_channel();

    rdma_event_channel *m_neigh_cma_event_channel = nullptr;
    rdma_event_channel *m_neigh_cma_event_channel_prev = nullptr;
    lock_rw m_channel_lock;
};

extern neigh_table_mgr *g_p_neigh_table_mgr;

#endif /* NEIGHBOUR_TABLE_MGR_H */
