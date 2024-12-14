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

#ifndef SYSCNTL_READER_H_
#define SYSCNTL_READER_H_

#include "vlogger/vlogger.h"
#include "utils.h"

struct sysctl_tcp_mem {
    int min_value;
    int default_value;
    int max_value;
};

struct tcp_keepalive_info {
    int idle_secs;
    int interval_secs;
    int num_probes;
};

class sysctl_reader_t {

private:
    sysctl_reader_t() { this->update_all(); }

public:
    int tcp_max_syn_backlog;
    int listen_maxconn;
    sysctl_tcp_mem tcp_wmem;
    sysctl_tcp_mem tcp_rmem;
    tcp_keepalive_info tcp_keepalive_infos;
    int tcp_window_scaling;
    int net_core_rmem_max;
    int net_core_wmem_max;
    int net_ipv4_tcp_timestamps;
    int net_ipv4_ttl;
    int igmp_max_membership;
    int igmp_max_source_membership;
    int mld_max_source_membership;
    int net_ipv6_hop_limit;
    int ipv6_bindv6only;
    int ipv6_conf_all_optimistic_dad;
    int ipv6_conf_all_use_optimistic;

    static sysctl_reader_t &instance()
    {
        static sysctl_reader_t the_instance;
        return the_instance;
    }
    void update_all()
    {
        // get_tcp_max_syn_backlog(true);
        // get_listen_maxconn(true);
        // get_tcp_wmem(true);
        // get_tcp_rmem(true);
        // get_tcp_window_scaling(true);
        // get_net_core_rmem_max(true);
        // get_net_core_wmem_max(true);
        // get_net_ipv4_tcp_timestamps(true);

        //keep behaviour params
        // Assign values to variables by reading from the appropriate paths or using default values
        net_ipv4_ttl = tmp_read_file_to_int("/proc/sys/net/ipv4/ip_default_ttl", 64);
        igmp_max_membership = tmp_read_file_to_int("/proc/sys/net/ipv4/igmp_max_memberships", 1024);
        igmp_max_source_membership = tmp_read_file_to_int("/proc/sys/net/ipv4/igmp_max_msf", 1024);
        mld_max_source_membership = tmp_read_file_to_int("/proc/sys/net/ipv6/mld_max_msf", 64);
        net_ipv6_hop_limit = tmp_read_file_to_int("/proc/sys/net/ipv6/conf/default/hop_limit", 64);
        ipv6_bindv6only = tmp_read_file_to_int("/proc/sys/net/ipv6/bindv6only", 0);
        ipv6_conf_all_optimistic_dad =
            tmp_read_file_to_int("/proc/sys/net/ipv6/conf/all/optimistic_dad", 0);
        ipv6_conf_all_use_optimistic =
            tmp_read_file_to_int("/proc/sys/net/ipv6/conf/all/use_optimistic", 0);
    }

    int tmp_read_file_to_int(const char *path, int default_value)
    {
        int value = -1;
        std::ifstream file_stream(path);
        if (!file_stream || !(file_stream >> value)) {
            return default_value;
        }
        return value;
    }

    int get_ipv6_if_optimistic_dad(const char *if_name)
    {
        if (!if_name) {
            vlog_printf(VLOG_DEBUG, "get_ipv6_if_optimistic_dad if_name is null\n");
            return 0;
        }

        std::string conf_name = "/proc/sys/net/ipv6/conf/";
        conf_name += if_name;
        conf_name += "/optimistic_dad";
        int val = read_file_to_int(conf_name.c_str(), 0, VLOG_DEBUG);
        if (0 > val) {
            vlog_printf(VLOG_DEBUG, "failed to read ipv6/conf/%s/optimistic_dad value\n", if_name);
        }
        return val;
    }

    int get_ipv6_if_use_optimistic(const char *if_name)
    {
        if (!if_name) {
            vlog_printf(VLOG_DEBUG, "get_ipv6_if_use_optimistic if_name is null\n");
            return 0;
        }

        std::string conf_name = "/proc/sys/net/ipv6/conf/";
        conf_name += if_name;
        conf_name += "/use_optimistic";
        int val = read_file_to_int(conf_name.c_str(), 0, VLOG_DEBUG);
        if (0 > val) {
            vlog_printf(VLOG_DEBUG, "failed to read ipv6/conf/%s/use_optimistic value\n", if_name);
        }
        return val;
    }

    int get_ipv6_if_use_tempaddr(const char *if_name)
    {
        if (!if_name) {
            vlog_printf(VLOG_DEBUG, "get_ipv6_if_use_tempaddr if_name is null\n");
            return 0;
        }

        std::string conf_name = "/proc/sys/net/ipv6/conf/";
        conf_name += if_name;
        conf_name += "/use_tempaddr";
        int val = read_file_to_int(conf_name.c_str(), 0, VLOG_DEBUG);
        if (0 > val) {
            vlog_printf(VLOG_DEBUG, "failed to read ipv6/conf/%s/use_tempaddr value\n", if_name);
        }
        return val;
    }
};

#endif /* SYSCNTL_READER_H_ */
