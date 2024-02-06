/*
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

#include "core/sock/sock-redirect.h"
#include "core/util/utils.h"
#include "vlogger/vlogger.h"
#include "utils/bullseye.h"
#include "netlink_socket_mgr.h"

#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <unistd.h> // getpid()

#ifndef MODULE_NAME
#define MODULE_NAME "netlink_socket_mgr:"
#endif

#define MSG_BUFF_SIZE 81920

// This function builds Netlink request to retrieve data (Rule, Route) from kernel.
// Parameters :
//      data_type   : either RULE_DATA_TYPE or ROUTE_DATA_TYPE
//      pid         : opaque pid for netlink request
//      seq         : opaque seq for netlink request
//      buf         : buffer for the request
//      nl_msg      : [out] pointer to request
void netlink_socket_mgr::build_request(nl_data_t data_type, uint32_t pid, uint32_t seq, char *buf,
                                       struct nlmsghdr **nl_msg)
{
    struct rtmsg *rt_msg;

    assert(MSG_BUFF_SIZE >= NLMSG_SPACE(sizeof(struct rtmsg)));
    memset(buf, 0, NLMSG_SPACE(sizeof(struct rtmsg)));

    // point the header and the msg structure pointers into the buffer
    *nl_msg = (struct nlmsghdr *)buf;
    rt_msg = (struct rtmsg *)NLMSG_DATA(*nl_msg);

    // Fill in the nlmsg header
    (*nl_msg)->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    (*nl_msg)->nlmsg_seq = seq;
    (*nl_msg)->nlmsg_pid = pid;
    (*nl_msg)->nlmsg_type = data_type == RULE_DATA_TYPE ? RTM_GETRULE : RTM_GETROUTE;
    (*nl_msg)->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;

    rt_msg->rtm_family = AF_UNSPEC;
}

// Query built request and receive requested data (Rule, Route)
// Parameters:
//      nl_msg  : request that is built previously.
//      buf     : [out] buffer for the reply
//      len     : [out] length of received data.
bool netlink_socket_mgr::query(const struct nlmsghdr *nl_msg, char *buf, int &len)
{
    int sockfd;

    // Opaque information in the request. To track expected reply.
    uint32_t nl_pid = nl_msg->nlmsg_pid;
    uint32_t nl_seq = nl_msg->nlmsg_seq;

    BULLSEYE_EXCLUDE_BLOCK_START
    if ((sockfd = SYSCALL(socket, PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) {
        __log_err("NL socket creation failed, errno = %d", errno);
        return false;
    }
    if (SYSCALL(fcntl, sockfd, F_SETFD, FD_CLOEXEC) != 0) {
        __log_warn("Fail in fcntl, errno = %d", errno);
    }
    if ((len = SYSCALL(send, sockfd, nl_msg, nl_msg->nlmsg_len, 0)) < 0) {
        __log_err("Write to NL socket failed, errno = %d", errno);
    }
    if (len > 0 && (len = recv_info(sockfd, nl_pid, nl_seq, buf)) < 0) {
        __log_err("Read from NL socket failed...");
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    close(sockfd);
    return len > 0;
}

// Receive requested data and save it to buffer.
// Return length of received data.
// Parameters:
//      sockfd  : netlink socket
//      pid     : expected opaque pid value
//      seq     : expected opaque seq value
//      buf     : [out] read reply
int netlink_socket_mgr::recv_info(int sockfd, uint32_t pid, uint32_t seq, char *buf)
{
    struct nlmsghdr *nlHdr;
    int readLen;
    int msgLen = 0;
    char *buf_ptr = buf;

    do {
        // Receive response from the kernel
        BULLSEYE_EXCLUDE_BLOCK_START
        if ((readLen = SYSCALL(recv, sockfd, buf_ptr, MSG_BUFF_SIZE - msgLen, 0)) < 0) {
            __log_err("NL socket read failed, errno = %d", errno);
            return -1;
        }

        nlHdr = (struct nlmsghdr *)buf_ptr;

        // Check if the header is valid
        if ((NLMSG_OK(nlHdr, (u_int)readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR)) {
            __log_err("Error in received packet, readLen = %d, msgLen = %d, type=%d, bufLen = %d",
                      readLen, nlHdr->nlmsg_len, nlHdr->nlmsg_type, MSG_BUFF_SIZE);
            if ((int)nlHdr->nlmsg_len >= MSG_BUFF_SIZE - msgLen) {
                __log_err("The buffer we pass to netlink is too small for reading the whole table");
            }
            return -1;
        }
        BULLSEYE_EXCLUDE_BLOCK_END

        if ((nlHdr->nlmsg_seq != seq) || (nlHdr->nlmsg_pid != pid)) {
            // Skip not expected messages
            continue;
        }

        buf_ptr += readLen;
        msgLen += readLen;

        // Loop until this is the last message of expected reply
    } while (nlHdr->nlmsg_type != NLMSG_DONE && (nlHdr->nlmsg_flags & NLM_F_MULTI));

    return msgLen;
}

// Update data in a table
void netlink_socket_mgr::update_tbl(nl_data_t data_type)
{
    struct nlmsghdr *nl_msg = nullptr;
    char *buf;
    int len = 0;

    // Opaque netlink information
    uint32_t nl_pid = getpid();
    uint32_t nl_seq = static_cast<uint32_t>(data_type);

    __log_dbg("");

    buf = new char[MSG_BUFF_SIZE];
    if (!buf) {
        __log_err("NL message buffer allocation failed");
        return;
    }

    build_request(data_type, nl_pid, nl_seq, buf, &nl_msg);
    if (query(nl_msg, buf, len)) {
        parse_tbl(buf, len);
    }

    delete[] buf;
    __log_dbg("Done");
}

// Parse received data in a table
// Parameters:
//      buf : buffer with netlink reply.
//      len : length of received data.
void netlink_socket_mgr::parse_tbl(char *buf, int len)
{
    struct nlmsghdr *nl_header = (struct nlmsghdr *)buf;

    for (; NLMSG_OK(nl_header, (u_int)len); nl_header = NLMSG_NEXT(nl_header, len)) {
        parse_entry(nl_header);
    }
}

#undef MODULE_NAME
