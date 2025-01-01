/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
