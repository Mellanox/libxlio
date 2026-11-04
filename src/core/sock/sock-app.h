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
    /* m_map_lock: leaf over the maps and m_total_worker_id; never held into
     * the device layer (ABBA vs get_worker_id() under device locks) */
    lock_spin_recursive m_map_lock;
    int workers_num;
    int workers_pow2;
    bool add_second_4t_rule;
    /* Map listen fd with thread(process) */
    std::unordered_map<int, pid_t> map_listen_fd;
    /* Associate thread(process) with unique identifier */
    std::unordered_map<pid_t, int> map_thread_id;
    /* Store duplicated fd with related original fd */
    std::unordered_map<int, int> map_dup_fd;
    /* Collection of unused unique identifiers limited by workers_num */
    std::set<int> unused_worker_id;
    void *context;
    /* Next worker id to hand to a thread that has none yet */
    int m_total_worker_id;

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
    /* Original fd recorded in map_dup_fd for a duplicated fd, or -1 */
    int dup_parent_fd(int fd);
    void record_listen_fd(int fd, pid_t tid);
    void publish_thread_worker(pid_t tid, int worker_id);
    /* Assign (or reuse) the calling thread's worker id and publish the fd->tid
     * and tid->worker-id mappings in one m_map_lock critical section */
    int publish_worker(int fd);
    /* Number of original listen fds: map_dup_fd entries mapping to themselves */
    int count_original_listeners();
    /* publish_worker() plus the enable_reuse_port=false gate accounting */
    int assign_worker_and_publish(int fd, sockinfo *si);

#if defined(DEFINED_NGINX)
    int proc_nginx();
#endif /* DEFINED_NGINX */

#if defined(DEFINED_ENVOY)
    int proc_envoy(int op, int fd);
#endif /* DEFINED_ENVOY */

private:
    /* Serializes the EPOLL_CTL_ADD init path; taken with no other XLIO locks
     * held; write regime of m_original_listen_count */
    lock_mutex m_init_lock;
    /* enable_reuse_port=false gate: worker-0 originals still pending (INT_MAX
     * until computed); written under m_init_lock, read unlocked by the
     * ordering wait */
    int m_original_listen_count;
};

extern struct app_conf *g_p_app;
#endif

#endif /* _SOCK_APP_H_ */
