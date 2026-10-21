/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2023-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef _SOCK_APP_H_
#define _SOCK_APP_H_

#include <core/util/sys_vars.h>
#include <core/util/utils.h>
#include <core/util/sock_addr.h>
#include <utils/lock_wrapper.h>

#include <vlogger/vlogger.h>
#include <unordered_map>
#include <mutex>
#include <set>

#if defined(DEFINED_NGINX)
// uint32_t stands for sa_family on the 16 MSB bits, and port number on 16 LSB.
typedef std::unordered_map<uint32_t, bool> map_udp_reuse_port_t;

extern map_udp_reuse_port_t g_map_udp_resue_port;
#endif

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
/* Snapshot of the parent listen socket's properties, captured by the dup()
 * intercept on Envoy's main thread while the parent is still alive. init_worker()
 * clones the child listener from this snapshot on the worker thread, so the clone
 * never dereferences the (possibly already freed) draining parent sockinfo. */
struct dup_listen_snapshot {
    sock_addr sa;
    socklen_t sa_len = 0;
    sa_family_t family = AF_UNSPEC;
    bool is_ipv6only = false;
    bool is_blocking = true;
    int back_log = 0;
    bool valid = false;
};

struct app_conf {
    app_type_t type;
    /* Lock-order contract:
     * - m_init_lock serializes worker/listener initialization (the proc_envoy()
     *   EPOLL_CTL_ADD path). It is acquired only from the epoll_ctl() intercept,
     *   where the calling thread holds no other XLIO locks, so it may be held
     *   while acquiring m_lock or device-layer locks (net_device_val, ring and
     *   CQ creation).
     * - m_lock is a leaf lock protecting the maps and counters below. In the
     *   Envoy path it is never held across init_worker()/listen()/bind()/ring/
     *   CQ creation or any other call that can reach device-layer locks such as
     *   net_device_val::m_lock. Ring creation calls get_worker_id() while
     *   holding net_device_val::m_lock, so holding m_lock across the device
     *   layer inverts the lock order (ABBA deadlock). proc_nginx() does keep
     *   m_lock across init_worker(); that is safe only because NGINX workers are
     *   single-threaded, so no concurrent device-layer acquirer forms the cycle.
     */
    lock_spin_recursive m_lock;
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
    /* Snapshot of the parent listen socket's properties for a duplicated child
     * fd, keyed by the child fd. Captured at dup() time so init_worker() can
     * clone without dereferencing the parent sockinfo. */
    std::unordered_map<int, dup_listen_snapshot> map_dup_listen;
    /* Collection of unused unique identifiers limited by workers_num */
    std::set<int> unused_worker_id;
    void *context;

    app_conf()
        : m_init_lock("app_conf_init")
    {
        type = APP_NONE;
        m_lock = lock_spin_recursive("app_conf");
        workers_num = 0;
        workers_pow2 = 0;
        add_second_4t_rule = false;
        map_listen_fd.clear();
        map_thread_id.clear();
        map_dup_fd.clear();
        map_dup_listen.clear();
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
        std::lock_guard<decltype(this->m_lock)> lock(m_lock);
        auto itr = map_thread_id.find(gettid());
        if (itr != map_thread_id.end()) {
            return itr->second;
        }
        return -1;
    }

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
