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
#include <unordered_map>
#include <mutex>
#include <set>

#if defined(DEFINED_NGINX)
// uint32_t stands for sa_family on the 16 MSB bits, and port number on 16 LSB.
typedef std::unordered_map<uint32_t, bool> map_udp_reuse_port_t;

extern map_udp_reuse_port_t g_map_udp_resue_port;
#endif

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
struct app_conf {
    app_type_t type;
    lock_spin_recursive m_lock;
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

    app_conf()
        : app_conf(safe_mce_sys().app.type, safe_mce_sys().app.workers_num)
    {
    }

    /* Constructs from explicit values instead of the safe_mce_sys() config
     * read, so a unit test can instantiate app_conf without global state. */
    app_conf(app_type_t app_type, int app_workers_num)
    {
        type = app_type;
        m_lock = lock_spin_recursive("app_conf");
        workers_num = app_workers_num;
        add_second_4t_rule = false;
        map_listen_fd.clear();
        map_thread_id.clear();
        map_dup_fd.clear();
        unused_worker_id.clear();
        context = nullptr;

        // Round up to a power of 2 value. Assume the number doesn't exceed 32bit.
        workers_pow2 = workers_num - 1;
        workers_pow2 |= workers_pow2 >> 1;
        workers_pow2 |= workers_pow2 >> 2;
        workers_pow2 |= workers_pow2 >> 4;
        workers_pow2 |= workers_pow2 >> 8;
        workers_pow2 |= workers_pow2 >> 16;
        workers_pow2++;
    }

    ~app_conf() = default;

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

    /* Record only non-reuse_port sources: a reuse_port dup is never resolved
     * by init_worker(), and its self-entry inflates the ordering gate count. */
    void record_dup(int fid, int src_fd, bool src_is_reuseport)
    {
        if (fid < 0 || src_is_reuseport) {
            return;
        }
        std::lock_guard<decltype(m_lock)> lock(m_lock);
        map_dup_fd[fid] = src_fd;
        map_dup_fd[src_fd] = src_fd;
    }

    /* Only the Envoy-gated dup() interposer populates map_dup_fd; nginx workers
     * inherit listener fds across fork(), so only Envoy mode has records to drop. */
    void forget_fd(int fd)
    {
        std::lock_guard<decltype(m_lock)> lock(m_lock);
        map_dup_fd.erase(fd);
    }
#endif /* DEFINED_ENVOY */
};

extern struct app_conf *g_p_app;
#endif

#endif /* _SOCK_APP_H_ */
