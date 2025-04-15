/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef NET_DEVICE_TABLE_MGR_H
#define NET_DEVICE_TABLE_MGR_H

#include <list>
#include <string>
#include <unordered_map>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "util/sys_vars.h"
#include "util/ip_address.h"
#include "event/timer_handler.h"
#include "infra/cache_subject_observer.h"
#include "net_device_val.h"
#include "net_device_entry.h"

typedef std::unordered_map<ip_address, net_device_val *> net_device_map_addr;
typedef std::unordered_map<int, net_device_val *> net_device_map_index_t;
typedef std::list<std::reference_wrapper<const ip_data>> local_ip_list_t;
typedef std::vector<std::reference_wrapper<const net_device_val>> local_dev_vector;

class net_device_table_mgr : public cache_table_mgr<int, net_device_val *>, public observer {
public:
    net_device_table_mgr();
    virtual ~net_device_table_mgr();

    void update_tbl();
    void print_val_tbl();

    virtual void notify_cb(event *ev);
    net_device_entry *create_new_entry(int if_index, const observer *dst);

    net_device_val *get_net_device_val(const ip_addr &if_addr);
    net_device_val *get_net_device_val(int if_index);

    // return list of the table_mgr managed ips by family
    void get_ip_list(local_ip_list_t &iplist, sa_family_t family, int if_index = 0);

    /**
     * Polling RX and TX of all ring on all devices.
     * @return >0 All CQs were drained. ==0 All CQs were drained.
     */
    bool global_ring_poll_and_process_element(uint64_t *p_poll_sn_rx, uint64_t *p_poll_sn_tx,
                                              void *pv_fd_ready_array = nullptr);

    /**
     * This will poll one time on the ALL the managed CQ's
     * If a wce was found 'processing' will occur.
     */
    void global_ring_wait_for_notification_and_process_element(uint64_t *p_poll_sn,
                                                               void *pv_fd_ready_array = nullptr);

    int global_ring_request_notification(uint64_t poll_sn_rx, uint64_t poll_sn_tx);

    /**
     * This will poll one time on the ALL the managed CQ's
     * If a wce was found 'processing' will occur.
     * Returns: >=0 the total number of wce processed
     *          < 0 error
     */
    int global_ring_drain_and_procces();

    void global_ring_adapt_cq_moderation();

    void global_ring_wakeup();

    int global_ring_epfd_get();

    /*
     * This will get accumlated RX out of buffer drops
     * for all net devices.
     */
    uint64_t global_get_rx_drop_counter(void);
    void print_report(vlog_levels_t log_level, bool print_only_critical = false);

    void handle_timer_expired(void *user_data);

    uint32_t get_max_mtu() const { return m_max_mtu; }

    inline ts_conversion_mode_t get_ctx_time_conversion_mode() { return m_time_conversion_mode; };

    void get_net_devices(local_dev_vector &vec);

    void increase_closed_rings_rx_cq_drop_counter(uint64_t count)
    {
        m_closed_rings_rx_cq_drop_counter_lock.lock();
        m_closed_rings_rx_cq_drop_counter += count;
        m_closed_rings_rx_cq_drop_counter_lock.unlock();
    }

private:
    void del_link_event(const netlink_link_info *info);
    void new_link_event(const netlink_link_info *info);

    void free_ndtm_resources();
    void set_max_mtu(uint32_t mtu) { m_max_mtu = mtu; }

    lock_mutex m_lock;
    ts_conversion_mode_t m_time_conversion_mode;
    net_device_map_addr m_net_device_map_addr_v4;
    net_device_map_addr m_net_device_map_addr_v6;
    net_device_map_index_t m_net_device_map_index;
    int m_num_devices;

    int m_global_ring_epfd;
    int m_global_ring_pipe_fds[2];

    uint32_t m_max_mtu;
    lock_mutex m_closed_rings_rx_cq_drop_counter_lock;
    uint64_t m_closed_rings_rx_cq_drop_counter;
};

extern net_device_table_mgr *g_p_net_device_table_mgr;

#endif
