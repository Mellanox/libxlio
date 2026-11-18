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
#include <atomic>
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
/* Worker/listen-fd state and the leaf lock guarding it. The lock is private,
 * so it is never held into the device layer (the ABBA guard), and every
 * access to the maps is one short critical section that never nests. */
class app_worker_registry {
public:
    app_worker_registry()
        : m_lock("app_conf")
    {
    }

    /* Owning tid recorded for a tracked listen fd, or -1 */
    pid_t listen_fd_owner(int fd)
    {
        std::lock_guard<decltype(m_lock)> lock(m_lock);
        auto iter = map_listen_fd.find(fd);
        return iter != map_listen_fd.end() ? iter->second : -1;
    }

    /* Original fd recorded for a duplicated fd, or -1 */
    int dup_parent_fd(int fd)
    {
        std::lock_guard<decltype(m_lock)> lock(m_lock);
        auto iter = map_dup_fd.find(fd);
        return iter != map_dup_fd.end() ? iter->second : -1;
    }

    /* Worker id of a thread(process), or -1 if it has none */
    int worker_id(pid_t tid)
    {
        std::lock_guard<decltype(m_lock)> lock(m_lock);
        auto iter = map_thread_id.find(tid);
        return iter != map_thread_id.end() ? iter->second : -1;
    }

    void record_listen_fd(int fd, pid_t tid)
    {
        std::lock_guard<decltype(m_lock)> lock(m_lock);
        map_listen_fd[fd] = tid;
    }

    void erase_listen_fd(int fd)
    {
        std::lock_guard<decltype(m_lock)> lock(m_lock);
        map_listen_fd.erase(fd);
    }

    /* dup() intercept: remember dup->original and original->itself. Skips a
     * failed dup and an original init_worker() cannot resolve as a clone
     * parent; such self-entries inflate count_original_listeners(). */
    void record_dup(int dup_fd, int orig_fd, bool orig_can_be_parent)
    {
        if (dup_fd < 0 || !orig_can_be_parent) {
            return;
        }
        std::lock_guard<decltype(m_lock)> lock(m_lock);
        map_dup_fd[dup_fd] = orig_fd;
        map_dup_fd[orig_fd] = orig_fd;
    }

    /* close() teardown: a dup record must not outlive its fd */
    void erase_dup_fd(int fd)
    {
        std::lock_guard<decltype(m_lock)> lock(m_lock);
        map_dup_fd.erase(fd);
    }

    void publish_thread_worker(pid_t tid, int worker_id)
    {
        std::lock_guard<decltype(m_lock)> lock(m_lock);
        map_thread_id[tid] = worker_id;
    }

    /* Assign (or reuse) the calling thread's worker id and publish the
     * fd->tid and tid->worker-id mappings in one critical section */
    int publish_worker(int fd)
    {
        std::lock_guard<decltype(m_lock)> lock(m_lock);

        /* m_total_worker_id is unique for all threads */
        int worker_id;
        auto iter = map_thread_id.find(gettid());
        if (iter != map_thread_id.end()) {
            worker_id = iter->second;
        } else {
            worker_id = m_total_worker_id;
            m_total_worker_id++;
        }

        map_listen_fd[fd] = gettid();
        map_thread_id[gettid()] = worker_id;
        return worker_id;
    }

    /* Number of original listen fds: map_dup_fd entries mapping to themselves */
    int count_original_listeners()
    {
        std::lock_guard<decltype(m_lock)> lock(m_lock);
        int originals = 0;
        for (const auto &itr : map_dup_fd) {
            if (itr.first == itr.second) {
                originals++;
            }
        }
        return originals;
    }

    /* ADD-failure cleanup: drop the fd mapping and the caller's thread
     * mapping in one critical section */
    void erase_worker(int fd, pid_t tid)
    {
        std::lock_guard<decltype(m_lock)> lock(m_lock);
        map_listen_fd.erase(fd);
        map_thread_id.erase(tid);
    }

    /* Pop a recycled worker id into id; false when none is available */
    bool pop_unused_worker_id(int &id)
    {
        std::lock_guard<decltype(m_lock)> lock(m_lock);
        if (unused_worker_id.empty()) {
            return false;
        }
        auto iter = unused_worker_id.begin();
        id = *iter;
        unused_worker_id.erase(iter);
        return true;
    }

    /* Return lookup_tid's worker id to the unused pool and drop erase_pid */
    void recycle_worker(pid_t lookup_tid, pid_t erase_pid)
    {
        std::lock_guard<decltype(m_lock)> lock(m_lock);
        auto iter = map_thread_id.find(lookup_tid);
        unused_worker_id.insert(iter != map_thread_id.end() ? iter->second : -1);
        map_thread_id.erase(erase_pid);
    }

private:
    lock_spin m_lock;
    /* Map listen fd with thread(process) */
    std::unordered_map<int, pid_t> map_listen_fd;
    /* Associate thread(process) with unique identifier */
    std::unordered_map<pid_t, int> map_thread_id;
    /* Store duplicated fd with related original fd */
    std::unordered_map<int, int> map_dup_fd;
    /* Collection of unused unique identifiers limited by workers_num */
    std::set<int> unused_worker_id;
    /* Next worker id to hand to a thread that has none yet */
    int m_total_worker_id = 0;
};

struct app_conf {
    app_type_t type;
    int workers_num;
    int workers_pow2;
    bool add_second_4t_rule;
    app_worker_registry workers;
    void *context;

    app_conf()
        : m_init_lock("app_conf_init")
    {
        type = APP_NONE;
        workers_num = 0;
        workers_pow2 = 0;
        add_second_4t_rule = false;
        m_original_listen_count = INT_MAX;
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

    inline int get_worker_id() { return workers.worker_id(gettid()); }

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
     * ordering wait (hence atomic) */
    std::atomic<int> m_original_listen_count;
};

extern struct app_conf *g_p_app;
#endif

#endif /* _SOCK_APP_H_ */
