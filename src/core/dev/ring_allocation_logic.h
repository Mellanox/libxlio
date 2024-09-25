/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-3-Clause
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

#ifndef RING_ALLOCATION_LOGIC_H_
#define RING_ALLOCATION_LOGIC_H_

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "dev/net_device_table_mgr.h"
#include "util/sys_vars.h"
#include "xlio_extra.h"

#define CANDIDATE_STABILITY_ROUNDS 20
#define RAL_STR_MAX_LENGTH         100

#define MAX_CPU CPU_SETSIZE
#define NO_CPU  -1

class source_t {
public:
    int m_fd;
    ip_address m_ip;
    const void *m_object;

    source_t(int fd)
        : m_fd(fd)
        , m_ip(ip_address::any_addr())
        , m_object(nullptr)
    {
    }
    source_t(const ip_address &ip)
        : m_fd(-1)
        , m_ip(ip)
        , m_object(nullptr)
    {
    }
    source_t(const void *object)
        : m_fd(-1)
        , m_ip(ip_address::any_addr())
        , m_object(object)
    {
    }
    source_t(const source_t &other)
        : m_fd(other.m_fd)
        , m_ip(other.m_ip)
        , m_object(other.m_object)
    {
    }
    source_t &operator=(const source_t &other)
    {
        if (this == &other) {
            return *this;
        }
        m_fd = other.m_fd;
        m_ip = other.m_ip;
        m_object = other.m_object;

        return *this;
    }
    source_t(source_t &&other) noexcept
        : m_fd(std::move(other.m_fd))
        , m_ip(std::move(other.m_ip))
        , m_object(std::move(other.m_object))
    {
        other.m_fd = -1;
        other.m_object = nullptr;
    }
};

/**
 * this class is responsible for the AL (allocation logic).
 * i gets the AL from the socket\environment variable and return
 * a key which represent the resource behind the allocation logic, it can
 * be the cpu witch the thread runs on or the threadID...
 * this key is part of the ring key configured in ring_alloc_logic_attr
 */
class ring_allocation_logic {
protected:
    ring_allocation_logic();
    ring_allocation_logic(int ring_migration_ratio, source_t source,
                          const resource_allocation_key &ring_profile);

    void debug_print_type(const char *type);

public:
    /* careful, you'll lose the previous key !! */
    resource_allocation_key *create_new_key(const ip_address &addr, int suggested_cpu = NO_CPU);

    resource_allocation_key *get_key() { return &m_res_key; }

    bool should_migrate_ring();
    bool is_logic_support_migration()
    {
        return m_ring_migration_ratio > 0 &&
            m_res_key.get_ring_alloc_logic() >= RING_LOGIC_PER_THREAD &&
            m_res_key.get_ring_alloc_logic() < RING_LOGIC_PER_OBJECT;
    }
    uint64_t calc_res_key_by_logic();
    inline ring_logic_t get_alloc_logic_type() { return m_res_key.get_ring_alloc_logic(); }
    inline void disable_migration() { m_ring_migration_ratio = -1; }

    const std::string to_str() const;

private:
    int m_ring_migration_ratio;
    int m_migration_try_count;
    source_t m_source;
    uint64_t m_migration_candidate;
    resource_allocation_key m_res_key;
};

class ring_allocation_logic_rx : public ring_allocation_logic {
public:
    ring_allocation_logic_rx()
        : ring_allocation_logic()
    {
        debug_print_type("Rx");
    }
    ring_allocation_logic_rx(source_t source, resource_allocation_key &ring_profile)
        : ring_allocation_logic(safe_mce_sys().ring_migration_ratio_rx, std::move(source),
                                ring_profile)
    {
        debug_print_type("Rx");
    }
};

class ring_allocation_logic_tx : public ring_allocation_logic {
public:
    ring_allocation_logic_tx()
        : ring_allocation_logic()
    {
        debug_print_type("Tx");
    }
    ring_allocation_logic_tx(source_t source, resource_allocation_key &ring_profile)
        : ring_allocation_logic(safe_mce_sys().ring_migration_ratio_tx, std::move(source),
                                ring_profile)
    {
        debug_print_type("Tx");
    }
};

class cpu_manager;
extern cpu_manager g_cpu_manager;

class cpu_manager : public lock_mutex {
public:
    cpu_manager();
    void reset();
    int reserve_cpu_for_thread(pthread_t tid, int suggested_cpu = NO_CPU);

private:
    int m_cpu_thread_count[MAX_CPU];
};

#endif /* RING_ALLOCATION_LOGIC_H_ */
