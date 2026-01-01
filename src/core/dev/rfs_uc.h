/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef RFS_UC_H
#define RFS_UC_H

#include "dev/rfs.h"

/**
 * @class rfs_uc
 *
 * Object to manages the sink list of a UC flow
 * This object is used for maintaining the sink list and dispatching packets
 *
 */

class rfs_uc : public rfs {
public:
    rfs_uc(flow_tuple *flow_spec_5t, ring_slave *p_ring, rfs_rule_filter *rule_filter = nullptr,
           uint32_t flow_tag_id = 0, int steering_index = -1);

    virtual bool rx_dispatch_packet(mem_buf_desc_t *p_rx_wc_buf_desc,
                                    void *pv_fd_ready_array) override;
    virtual void prepare_flow_spec_worker_thread_mode() override;
    virtual void prepare_flow_spec_secondary_rule() override;
    virtual bool if_secondary_rule_needed() override;

protected:
    virtual void prepare_flow_spec() override;

    // RSS child listen socket - Threads mode parameter
    int m_steering_index = -1; // -1 means not a rss_child listen socket
};

#endif /* RFS_UC_H */
