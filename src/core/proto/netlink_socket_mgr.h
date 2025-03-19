/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef NETLINK_SOCKET_MGR_H
#define NETLINK_SOCKET_MGR_H

// Forward declarations
struct nlmsghdr;

// This enum specify the type of data to be retrieve using netlink socket.
enum nl_data_t { RULE_DATA_TYPE, ROUTE_DATA_TYPE };

// This class manages retrieving data (Rule, Route) from kernel using netlink socket.
class netlink_socket_mgr {
protected:
    virtual void parse_entry(struct nlmsghdr *nl_header) = 0;
    virtual void update_tbl(nl_data_t data_type);

private:
    void build_request(nl_data_t data_type, uint32_t pid, uint32_t seq, char *buf,
                       struct nlmsghdr **nl_msg);
    bool query(const struct nlmsghdr *nl_msg, char *buf, int &len);
    int recv_info(int sockfd, uint32_t pid, uint32_t seq, char *buf);
    void parse_tbl(char *buf, int len);
};

#endif /* NETLINK_SOCKET_MGR_H */
