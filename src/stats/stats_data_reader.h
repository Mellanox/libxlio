/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef STATS_DATA_READER_H
#define STATS_DATA_READER_H

#include <algorithm>
#include <chrono>
#include <ctime>
#include <fstream>
#include <map>
#include <numeric>
#include <string>
#include "utils/lock_wrapper.h"
#include "core/event/timer_handler.h"
#include "core/util/xlio_stats.h"

typedef std::map<void *, std::pair<void *, int>> stats_read_map_t;

typedef struct {
    int size;
    void *shm_addr;
} data_addr_and_size_t;

class stats_data_reader : public timer_handler {
public:
    stats_data_reader();
    void handle_timer_expired(void *ctx);
    void register_to_timer();
    void add_data_reader(void *local_addr, void *shm_addr, int size);
    void *pop_data_reader(void *local_addr);

private:
    void *m_timer_handler;
    stats_read_map_t m_data_map;
    lock_spin m_lock_data_map;
};

using std::ostream;
using std::string;

struct tls_context_counters_show {
    tls_context_counters_show(bool is_delta_mode = false)
        : m_is_delta_mode(is_delta_mode) {};
    bool m_is_delta_mode = false;
    struct tls_contxts_num {
        uint32_t tx = 0, rx = 0;
    };
    tls_contxts_num curr, prev;

    tls_context_counters_show &update(const sh_mem_t *mem)
    {
        return (mem) ? update(mem->ring_inst_arr) : *this;
    }

#ifdef DEFINED_UTLS
    tls_context_counters_show &update(const ring_instance_block_t (&rings)[NUM_OF_SUPPORTED_RINGS])
    {
        auto count_if_enabled = [](tls_contxts_num &val, const ring_instance_block_t &ring_stat) {
            // coverity[missing_lock:FALSE] /* Turn off coverity missing_lock check*/
            if (ring_stat.b_enabled) {
                val.tx += ring_stat.ring_stats.n_tx_tls_contexts;
                val.rx += ring_stat.ring_stats.n_rx_tls_contexts;
            }
            return val;
        };
        std::swap(curr, prev);
        curr = std::accumulate(&rings[0], &rings[NUM_OF_SUPPORTED_RINGS], tls_contxts_num(),
                               count_if_enabled);
        return *this;
    }
    static const constexpr char *hdr_val = "TLS TX contexts,TLS RX contexts,";
#else
    static const constexpr char *hdr_val = "";
    tls_context_counters_show &update(const ring_instance_block_t (&)[NUM_OF_SUPPORTED_RINGS])
    {
        return *this;
    }
#endif /* DEFINED_UTLS */
};

struct global_counters_show {
    global_counters_show(bool is_delta_mode = false)
        : m_is_delta_mode(is_delta_mode)
        , curr {}
        , prev {} {};
    bool m_is_delta_mode = false;
    struct destructed_sockets {
        uint32_t tcp = 0, udp = 0;
    };
    destructed_sockets curr, prev;

    global_counters_show &update(const sh_mem_t *mem)
    {
        return (mem) ? update(mem->global_inst_arr) : *this;
    }

    global_counters_show &update(const global_instance_block_t (&globals)[NUM_OF_SUPPORTED_GLOBALS])
    {
        auto count_if_enabled = [](destructed_sockets &val,
                                   const global_instance_block_t &global_stat) {
            if (global_stat.b_enabled) {
                val.tcp += global_stat.global_stats.socket_tcp_destructor_counter.load();
                val.udp += global_stat.global_stats.socket_udp_destructor_counter.load();
            }
            return val;
        };
        std::swap(curr, prev);
        curr = std::accumulate(&globals[0], &globals[NUM_OF_SUPPORTED_GLOBALS],
                               destructed_sockets(), count_if_enabled);
        return *this;
    }
    static const constexpr char *hdr_val = "TCP Destructed,UDP Destructed,";
};

std::ostream &operator<<(std::ostream &os, const global_counters_show &obj)
{
    if (obj.m_is_delta_mode) {
        os << obj.curr.tcp - obj.prev.tcp << "," << obj.curr.udp - obj.prev.udp << ",";
    } else {
        os << obj.curr.tcp << "," << obj.curr.udp << ",";
    }
    return os;
}

class cpu_stats {
public:
    enum cpu_context {
        USER = 0,
        NICE,
        SYSTEM,
        IDLE,
        IOWAIT,
        IRQ,
        SOFTIRQ,
        STEAL,
        GUEST,
        GUEST_NICE,
        TOTAL_CONTEXTS
    };

    void capture();
    void read(const std::string &line);
    size_t get_total_time() const;
    size_t get_active_time() const;
    size_t get_context_time(enum cpu_context context) const;
    bool enabled = true;

private:
    size_t times[TOTAL_CONTEXTS];
};

struct cpu_usage_show {
    struct contexts {
        size_t usr = 0, sys = 0, active = 0, total = 0;
    };
    contexts curr, prev;
    cpu_stats snapshot;

    cpu_usage_show &update()
    {
        if (snapshot.enabled) {
            std::swap(curr, prev);
            snapshot.capture();
            curr.active = snapshot.get_active_time();
            curr.total = snapshot.get_total_time();
            curr.usr = snapshot.get_context_time(cpu_stats::USER);
            curr.sys = snapshot.get_context_time(cpu_stats::SYSTEM);
        } else {
            curr.total = prev.total = 0;
        }
        return *this;
    }
    static const constexpr char *hdr_val = "CPU Usage,%usr,%sys";
};

std::ostream &operator<<(std::ostream &os, const cpu_usage_show &obj)
{

    if (obj.curr.total == obj.prev.total) {
        os << "NaN,NaN,NaN,";
    } else {
        char str[16];
        const float diff_active = obj.curr.active - obj.prev.active;
        const float diff_usr = obj.curr.usr - obj.prev.usr;
        const float diff_sys = obj.curr.sys - obj.prev.sys;
        const float diff_total = obj.curr.total - obj.prev.total;
        snprintf(str, 7, "%.2f", 100.f * diff_active / diff_total);
        os << str << ",";
        snprintf(str, 7, "%.2f", 100.f * diff_usr / diff_total);
        os << str << ",";
        snprintf(str, 7, "%.2f", 100.f * diff_sys / diff_total);
        os << str << ",";
    }
    return os;
}

struct ring_packet_aggregate {
    ring_packet_aggregate(bool is_delta_mode = false)
        : m_is_delta_mode(is_delta_mode) {};
    bool m_is_delta_mode = false;
    struct pkt_cnt {
        uint64_t tx = 0, rx = 0;
    };
    pkt_cnt curr, prev;

    ring_packet_aggregate &update(const sh_mem_t *mem)
    {
        return (mem) ? update(mem->ring_inst_arr) : *this;
    }

    ring_packet_aggregate &update(const ring_instance_block_t (&rings)[NUM_OF_SUPPORTED_RINGS])
    {
        auto count_if_enabled = [](pkt_cnt &val, const ring_instance_block_t &ring_stat) {
            // coverity[missing_lock:FALSE] /* Turn off coverity missing_lock check*/
            if (ring_stat.b_enabled) {
                val.tx += ring_stat.hwq_tx_stats.n_tx_pkt_count;
                val.rx += ring_stat.hwq_rx_stats.n_rx_pkt_count;
            }
            return val;
        };
        std::swap(curr, prev);
        curr =
            std::accumulate(&rings[0], &rings[NUM_OF_SUPPORTED_RINGS], pkt_cnt(), count_if_enabled);
        return *this;
    }
    static const constexpr char *hdr_val = "TX packets,RX packets,";
};

std::ostream &operator<<(std::ostream &os, const tls_context_counters_show &obj)
{
#ifdef DEFINED_UTLS
    if (obj.m_is_delta_mode) {
        os << obj.curr.tx - obj.prev.tx << "," << obj.curr.rx - obj.prev.rx << ",";
    } else {
        os << obj.curr.tx << "," << obj.curr.rx << ",";
    }
#else
    NOT_IN_USE(obj);
#endif /* DEFINED_UTLS */
    return os;
}

std::ostream &operator<<(std::ostream &os, const ring_packet_aggregate &obj)
{
    if (obj.m_is_delta_mode) {
        os << obj.curr.tx - obj.prev.tx << "," << obj.curr.rx - obj.prev.rx << ",";
    } else {
        os << obj.curr.tx << "," << obj.curr.rx << ",";
    }
    return os;
}

struct listen_counters {
    socket_listen_counters_t ipv4;
    socket_listen_counters_t ipv6;
};

std::ostream &operator<<(std::ostream &os, const listen_counters &obj);
listen_counters operator-(listen_counters lhs, const listen_counters &rhs);

struct socket_listen_counter_aggregate {
    socket_listen_counter_aggregate(bool is_delta_mode = false)
        : m_is_delta_mode(is_delta_mode)
        , curr()
        , prev() {};

    socket_listen_counter_aggregate &update(const sh_mem_t *mem)
    {
        if (mem) {
            std::swap(curr, prev);
            curr = summarize_listen_counters(*mem);
        }
        return *this;
    }
    bool m_is_delta_mode = false;
    listen_counters curr, prev;

    static const constexpr char *hdr_val =
        "IP4_RX_SYN,IP4_RX_SYN_TW,IP4_RX_FIN,IP4_NUM_ESTAB_CONN,IP4_NUM_ACCEP_CONN,"
        "IP4_NUM_DROPPED_CONN,IP4_BACKLOG,"
        "IP6_RX_SYN,IP6_RX_SYN_TW,IP6_RX_FIN,IP6_NUM_ESTAB_CONN,IP6_NUM_ACCEP_CONN,"
        "IP6_NUM_DROPPED_CONN,IP6_BACKLOG,";

private:
    listen_counters summarize_listen_counters(const sh_mem_t &mem)
    {
        listen_counters lc {.ipv4 = {0, 0, 0, 0, 0, 0, 0}, .ipv6 = {0, 0, 0, 0, 0, 0, 0}};
        for (size_t i = 0; i < mem.max_skt_inst_num; i++) {
            if (!mem.skt_inst_arr[i].b_enabled) {
                continue;
            }

            if (mem.skt_inst_arr[i].skt_stats.sa_family == AF_INET) {
                lc.ipv4 += mem.skt_inst_arr[i].skt_stats.listen_counters;
            } else {
                lc.ipv6 += mem.skt_inst_arr[i].skt_stats.listen_counters;
            }
        }
        return lc;
    }
};

std::ostream &operator<<(std::ostream &os, const socket_listen_counter_aggregate &obj)
{
    /* No need for trailing comma since listen_counters handles it */
    if (!obj.m_is_delta_mode) {
        os << obj.curr;
    } else {
        os << obj.curr - obj.prev;
    }
    return os;
}

std::ostream &operator<<(std::ostream &os, const listen_counters &obj)
{
    return os << obj.ipv4.n_rx_syn << "," << obj.ipv4.n_rx_syn_tw << "," << obj.ipv4.n_rx_fin << ","
              << obj.ipv4.n_conn_established << "," << obj.ipv4.n_conn_accepted << ","
              << obj.ipv4.n_conn_dropped << "," << obj.ipv4.n_conn_backlog << ","
              << obj.ipv6.n_rx_syn << "," << obj.ipv6.n_rx_syn_tw << "," << obj.ipv6.n_rx_fin << ","
              << obj.ipv6.n_conn_established << "," << obj.ipv6.n_conn_accepted << ","
              << obj.ipv6.n_conn_dropped << "," << obj.ipv6.n_conn_backlog << ",";
}

listen_counters operator-(listen_counters lhs, const listen_counters &rhs)
{
    return {lhs.ipv4 - rhs.ipv4, lhs.ipv6 - rhs.ipv6};
}
#endif // STATS_DATA_READER_H
