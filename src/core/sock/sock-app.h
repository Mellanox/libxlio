/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2023-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef _SOCK_APP_H_
#define _SOCK_APP_H_

#include <core/util/sys_vars.h>
#include <core/util/utils.h>
#include <utils/lock_wrapper.h>

#include <vlogger/vlogger.h>
#include <climits>
#include <unordered_map>
#include <mutex>
#include <set>

#if defined(DEFINED_NGINX)
// uint32_t stands for sa_family on the 16 MSB bits, and port number on 16 LSB.
typedef std::unordered_map<uint32_t, bool> map_udp_reuse_port_t;

extern map_udp_reuse_port_t g_map_udp_resue_port;
#endif

class sockinfo;

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
struct app_conf {
    app_type_t type;
    /* Lock-order contract: m_map_lock is a leaf protecting the maps and
     * counters below - never held across init_worker()/listen()/bind() or any
     * other call that can reach device-layer locks (ring creation calls
     * get_worker_id() under net_device_val::m_lock, so holding m_map_lock
     * across the device layer is an ABBA deadlock). proc_nginx() keeps it
     * across init_worker() only because nginx workers are single-threaded.
     * m_init_lock serializes the proc_envoy() EPOLL_CTL_ADD path and is taken
     * with no other XLIO locks held, so it may be held across both m_map_lock
     * and device-layer locks. */
    lock_spin_recursive m_map_lock;
    lock_mutex m_init_lock;
    int workers_num;
    int workers_pow2;
    bool add_second_4t_rule;
    /* Map listen fd with thread(process) */
    std::unordered_map<int, pid_t> map_listen_fd;
    /* Associate thread(process) with unique identifier */
    std::unordered_map<pid_t, int> map_thread_id;
    /* Store duplicated fdwith related original fd */
    std::unordered_map<int, int> map_dup_fd;
    /* Collection of unused unique identifiers limited by workers_num */
    std::set<int> unused_worker_id;
    void *context;
    /* Next worker id to hand to a thread that has none yet */
    int m_total_worker_id;
    /* enable_reuse_port=false ordering gate: number of worker-0 original
     * listeners still pending; INT_MAX until first computed */
    int m_original_listen_count;

    app_conf()
        : m_init_lock("app_conf_init")
    {
        type = APP_NONE;
        m_map_lock = lock_spin_recursive("app_conf");
        workers_num = 0;
        workers_pow2 = 0;
        add_second_4t_rule = false;
        m_total_worker_id = 0;
        m_original_listen_count = INT_MAX;
        map_listen_fd.clear();
        map_thread_id.clear();
        map_dup_fd.clear();
        unused_worker_id.clear();
        context = nullptr;

        setup();
    }

    ~app_conf() = default;

    void setup()
    {
        type = safe_mce_sys().app.type;
        workers_num = safe_mce_sys().app.workers_num;

        // Round up to a power of 2 value. Assume the number doesn't exceed 32bit.
        workers_pow2 = workers_num - 1;
        workers_pow2 |= workers_pow2 >> 1;
        workers_pow2 |= workers_pow2 >> 2;
        workers_pow2 |= workers_pow2 >> 4;
        workers_pow2 |= workers_pow2 >> 8;
        workers_pow2 |= workers_pow2 >> 16;
        workers_pow2++;
    }

    inline int get_worker_id()
    {
        std::lock_guard<decltype(this->m_map_lock)> lock(m_map_lock);
        auto itr = map_thread_id.find(gettid());
        if (itr != map_thread_id.end()) {
            return itr->second;
        }
        return -1;
    }

    /* Owning tid recorded in map_listen_fd for a tracked listen fd, or -1 */
    pid_t listen_fd_owner(int fd);
    /* Assign (or reuse) the calling thread's worker id, maintain the
     * enable_reuse_port=false ordering gate and publish the fd->tid and
     * tid->worker-id mappings, all under m_map_lock */
    int assign_worker_and_publish(int fd, sockinfo *si);

#if defined(DEFINED_NGINX)
    int proc_nginx();
#endif /* DEFINED_NGINX */

#if defined(DEFINED_ENVOY)
    int proc_envoy(int op, int fd);
#endif /* DEFINED_ENVOY */
};

extern struct app_conf *g_p_app;
#endif

#endif /* _SOCK_APP_H_ */
