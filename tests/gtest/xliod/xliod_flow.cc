/*
 * Copyright (c) 2001-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "common/cmn.h"

#include "xliod_base.h"

#include "src/core/util/agent_def.h"

class xliod_flow : public xliod_base {
protected:
    struct xlio_msg_flow m_data;
    pid_t m_pid;
    int m_if;
    int m_tap;
    xliod_flow()
    {

        char opt_val[IF_NAMESIZE];
        socklen_t opt_len;

        m_pid = 0x464C4F57;
        memset(&m_data, 0, sizeof(m_data));
        m_data.hdr.code = XLIO_MSG_FLOW;
        m_data.hdr.ver = XLIO_AGENT_VER;
        m_data.hdr.pid = m_pid;

        opt_val[0] = '\0';
        opt_len = sizeof(opt_val);
        sys_addr2dev((struct sockaddr *)&server_addr, opt_val, opt_len);
        m_if = if_nametoindex(opt_val);
        sys_addr2dev((struct sockaddr *)&client_addr, opt_val, opt_len);
        m_tap = if_nametoindex(opt_val);
        m_data.if_id = m_if;
        m_data.tap_id = m_tap;
    }
};

/**
 * @test xliod_flow.ti_1
 * @brief
 *    Send valid TCP 3tuple XLIO_MSG_FLOW(ADD)
 * @details
 */
TEST_F(xliod_flow, ti_1)
{
    int rc = 0;
    struct xlio_hdr answer;

    rc = xliod_base::msg_init(m_pid);
    ASSERT_LT(0, rc);

    m_data.hdr.status = 1;
    m_data.action = XLIO_MSG_FLOW_ADD;
    m_data.type = XLIO_MSG_FLOW_TCP_3T;
    m_data.flow.dst.family = m_family;
    if (m_family == PF_INET) {
        m_data.flow.dst.addr.ipv4 = ((struct sockaddr_in *)&server_addr)->sin_addr.s_addr;
    } else {
        memcpy(&m_data.flow.dst.addr.ipv6[0],
               &((struct sockaddr_in6 *)&server_addr)->sin6_addr.s6_addr[0],
               sizeof(m_data.flow.dst.addr.ipv6));
    }
    m_data.flow.dst.port = htons(sys_get_port((struct sockaddr *)&server_addr));

    errno = 0;
    rc = send(m_sock_fd, &m_data, sizeof(m_data), 0);
    EXPECT_EQ(0, errno);
    EXPECT_EQ((int)sizeof(m_data), rc);

    memset(&answer, 0, sizeof(answer));
    rc = recv(m_sock_fd, &answer, sizeof(answer), 0);
    EXPECT_EQ((int)sizeof(answer), rc);

    EXPECT_EQ((XLIO_MSG_FLOW | XLIO_MSG_ACK), answer.code);
    EXPECT_LE(XLIO_AGENT_VER, answer.ver);
    EXPECT_EQ(m_pid, answer.pid);
    EXPECT_EQ(0, answer.status);

    rc = xliod_base::msg_exit(m_pid);
    ASSERT_LT(0, rc);
}

/**
 * @test xliod_flow.ti_2
 * @brief
 *    Send valid TCP 5tuple XLIO_MSG_FLOW(ADD)
 * @details
 */
TEST_F(xliod_flow, ti_2)
{
    int rc = 0;
    struct xlio_hdr answer;

    rc = xliod_base::msg_init(m_pid);
    ASSERT_LT(0, rc);

    m_data.hdr.status = 1;
    m_data.action = XLIO_MSG_FLOW_ADD;
    m_data.type = XLIO_MSG_FLOW_TCP_5T;
    m_data.flow.src.family = m_family;
    if (m_family == PF_INET) {
        m_data.flow.src.addr.ipv4 = ((struct sockaddr_in *)&client_addr)->sin_addr.s_addr;
    } else {
        memcpy(&m_data.flow.src.addr.ipv6[0],
               &((struct sockaddr_in6 *)&client_addr)->sin6_addr.s6_addr[0],
               sizeof(m_data.flow.src.addr.ipv6));
    }
    m_data.flow.src.port = htons(sys_get_port((struct sockaddr *)&client_addr));
    m_data.flow.dst.family = m_family;
    if (m_family == PF_INET) {
        m_data.flow.dst.addr.ipv4 = ((struct sockaddr_in *)&server_addr)->sin_addr.s_addr;
    } else {
        memcpy(&m_data.flow.dst.addr.ipv6[0],
               &((struct sockaddr_in6 *)&server_addr)->sin6_addr.s6_addr[0],
               sizeof(m_data.flow.dst.addr.ipv6));
    }
    m_data.flow.dst.port = htons(sys_get_port((struct sockaddr *)&server_addr));

    errno = 0;
    rc = send(m_sock_fd, &m_data, sizeof(m_data), 0);
    EXPECT_EQ(0, errno);
    EXPECT_EQ((int)sizeof(m_data), rc);

    memset(&answer, 0, sizeof(answer));
    rc = recv(m_sock_fd, &answer, sizeof(answer), 0);
    EXPECT_EQ((int)sizeof(answer), rc);

    EXPECT_EQ((XLIO_MSG_FLOW | XLIO_MSG_ACK), answer.code);
    EXPECT_LE(XLIO_AGENT_VER, answer.ver);
    EXPECT_EQ(m_pid, answer.pid);
    EXPECT_EQ(0, answer.status);

    rc = xliod_base::msg_exit(m_pid);
    ASSERT_LT(0, rc);
}

/**
 * @test xliod_flow.ti_3
 * @brief
 *    Send valid 3tuple XLIO_MSG_FLOW(ADD) and XLIO_MSG_FLOW(DEL)
 * @details
 */
TEST_F(xliod_flow, ti_3)
{
    int rc = 0;
    struct xlio_hdr answer;

    rc = xliod_base::msg_init(m_pid);
    ASSERT_LT(0, rc);

    m_data.hdr.status = 1;
    m_data.action = XLIO_MSG_FLOW_ADD;
    m_data.type = XLIO_MSG_FLOW_TCP_3T;
    m_data.flow.dst.family = m_family;
    if (m_family == PF_INET) {
        m_data.flow.dst.addr.ipv4 = ((struct sockaddr_in *)&server_addr)->sin_addr.s_addr;
    } else {
        memcpy(&m_data.flow.dst.addr.ipv6[0],
               &((struct sockaddr_in6 *)&server_addr)->sin6_addr.s6_addr[0],
               sizeof(m_data.flow.dst.addr.ipv6));
    }
    m_data.flow.dst.port = htons(sys_get_port((struct sockaddr *)&server_addr));

    errno = 0;
    rc = send(m_sock_fd, &m_data, sizeof(m_data), 0);
    EXPECT_EQ(0, errno);
    EXPECT_EQ((int)sizeof(m_data), rc);

    memset(&answer, 0, sizeof(answer));
    rc = recv(m_sock_fd, &answer, sizeof(answer), 0);
    EXPECT_EQ((int)sizeof(answer), rc);

    EXPECT_EQ((XLIO_MSG_FLOW | XLIO_MSG_ACK), answer.code);
    EXPECT_LE(XLIO_AGENT_VER, answer.ver);
    EXPECT_EQ(m_pid, answer.pid);
    EXPECT_EQ(0, answer.status);

    m_data.hdr.status = 1;
    m_data.action = XLIO_MSG_FLOW_DEL;

    errno = 0;
    rc = send(m_sock_fd, &m_data, sizeof(m_data), 0);
    EXPECT_EQ(0, errno);
    EXPECT_EQ((int)sizeof(m_data), rc);

    memset(&answer, 0, sizeof(answer));
    rc = recv(m_sock_fd, &answer, sizeof(answer), 0);
    EXPECT_EQ((int)sizeof(answer), rc);

    EXPECT_EQ((XLIO_MSG_FLOW | XLIO_MSG_ACK), answer.code);
    EXPECT_LE(XLIO_AGENT_VER, answer.ver);
    EXPECT_EQ(m_pid, answer.pid);
    EXPECT_EQ(0, answer.status);

    rc = xliod_base::msg_exit(m_pid);
    ASSERT_LT(0, rc);
}

/**
 * @test xliod_flow.ti_4
 * @brief
 *    Send valid 5tuple XLIO_MSG_FLOW(ADD) and XLIO_MSG_FLOW(DEL)
 * @details
 */
TEST_F(xliod_flow, ti_4)
{
    int rc = 0;
    struct xlio_hdr answer;

    rc = xliod_base::msg_init(m_pid);
    ASSERT_LT(0, rc);

    m_data.hdr.status = 1;
    m_data.action = XLIO_MSG_FLOW_ADD;
    m_data.type = XLIO_MSG_FLOW_TCP_5T;
    m_data.flow.src.family = m_family;
    if (m_family == PF_INET) {
        m_data.flow.src.addr.ipv4 = ((struct sockaddr_in *)&client_addr)->sin_addr.s_addr;
    } else {
        memcpy(&m_data.flow.src.addr.ipv6[0],
               &((struct sockaddr_in6 *)&client_addr)->sin6_addr.s6_addr[0],
               sizeof(m_data.flow.src.addr.ipv6));
    }
    m_data.flow.src.port = htons(sys_get_port((struct sockaddr *)&client_addr));
    m_data.flow.dst.family = m_family;
    if (m_family == PF_INET) {
        m_data.flow.dst.addr.ipv4 = ((struct sockaddr_in *)&server_addr)->sin_addr.s_addr;
    } else {
        memcpy(&m_data.flow.dst.addr.ipv6[0],
               &((struct sockaddr_in6 *)&server_addr)->sin6_addr.s6_addr[0],
               sizeof(m_data.flow.dst.addr.ipv6));
    }
    m_data.flow.dst.port = htons(sys_get_port((struct sockaddr *)&server_addr));

    errno = 0;
    rc = send(m_sock_fd, &m_data, sizeof(m_data), 0);
    EXPECT_EQ(0, errno);
    EXPECT_EQ((int)sizeof(m_data), rc);

    memset(&answer, 0, sizeof(answer));
    rc = recv(m_sock_fd, &answer, sizeof(answer), 0);
    EXPECT_EQ((int)sizeof(answer), rc);

    EXPECT_EQ((XLIO_MSG_FLOW | XLIO_MSG_ACK), answer.code);
    EXPECT_LE(XLIO_AGENT_VER, answer.ver);
    EXPECT_EQ(m_pid, answer.pid);
    EXPECT_EQ(0, answer.status);

    m_data.hdr.status = 1;
    m_data.action = XLIO_MSG_FLOW_DEL;

    errno = 0;
    rc = send(m_sock_fd, &m_data, sizeof(m_data), 0);
    EXPECT_EQ(0, errno);
    EXPECT_EQ((int)sizeof(m_data), rc);

    memset(&answer, 0, sizeof(answer));
    rc = recv(m_sock_fd, &answer, sizeof(answer), 0);
    EXPECT_EQ((int)sizeof(answer), rc);

    EXPECT_EQ((XLIO_MSG_FLOW | XLIO_MSG_ACK), answer.code);
    EXPECT_LE(XLIO_AGENT_VER, answer.ver);
    EXPECT_EQ(m_pid, answer.pid);
    EXPECT_EQ(0, answer.status);

    rc = xliod_base::msg_exit(m_pid);
    ASSERT_LT(0, rc);
}

/**
 * @test xliod_flow.ti_51
 * @brief
 *    Send valid UDP 3tuple XLIO_MSG_FLOW(ADD)
 * @details
 */
TEST_F(xliod_flow, ti_5)
{
    int rc = 0;
    struct xlio_hdr answer;

    rc = xliod_base::msg_init(m_pid);
    ASSERT_LT(0, rc);

    m_data.hdr.status = 1;
    m_data.action = XLIO_MSG_FLOW_ADD;
    m_data.type = XLIO_MSG_FLOW_UDP_3T;
    m_data.flow.dst.family = m_family;
    if (m_family == PF_INET) {
        m_data.flow.dst.addr.ipv4 = ((struct sockaddr_in *)&server_addr)->sin_addr.s_addr;
    } else {
        memcpy(&m_data.flow.dst.addr.ipv6[0],
               &((struct sockaddr_in6 *)&server_addr)->sin6_addr.s6_addr[0],
               sizeof(m_data.flow.dst.addr.ipv6));
    }
    m_data.flow.dst.port = htons(sys_get_port((struct sockaddr *)&server_addr));

    errno = 0;
    rc = send(m_sock_fd, &m_data, sizeof(m_data), 0);
    EXPECT_EQ(0, errno);
    EXPECT_EQ((int)sizeof(m_data), rc);

    memset(&answer, 0, sizeof(answer));
    rc = recv(m_sock_fd, &answer, sizeof(answer), 0);
    EXPECT_EQ((int)sizeof(answer), rc);

    EXPECT_EQ((XLIO_MSG_FLOW | XLIO_MSG_ACK), answer.code);
    EXPECT_LE(XLIO_AGENT_VER, answer.ver);
    EXPECT_EQ(m_pid, answer.pid);
    EXPECT_EQ(0, answer.status);

    rc = xliod_base::msg_exit(m_pid);
    ASSERT_LT(0, rc);
}

/**
 * @test xliod_flow.ti_6
 * @brief
 *    Send valid UDP 5tuple XLIO_MSG_FLOW(ADD)
 * @details
 */
TEST_F(xliod_flow, ti_6)
{
    int rc = 0;
    struct xlio_hdr answer;

    rc = xliod_base::msg_init(m_pid);
    ASSERT_LT(0, rc);

    m_data.hdr.status = 1;
    m_data.action = XLIO_MSG_FLOW_ADD;
    m_data.type = XLIO_MSG_FLOW_UDP_5T;
    m_data.flow.src.family = m_family;
    if (m_family == PF_INET) {
        m_data.flow.src.addr.ipv4 = ((struct sockaddr_in *)&client_addr)->sin_addr.s_addr;
    } else {
        memcpy(&m_data.flow.src.addr.ipv6[0],
               &((struct sockaddr_in6 *)&client_addr)->sin6_addr.s6_addr[0],
               sizeof(m_data.flow.src.addr.ipv6));
    }
    m_data.flow.src.port = htons(sys_get_port((struct sockaddr *)&client_addr));
    m_data.flow.dst.family = m_family;
    if (m_family == PF_INET) {
        m_data.flow.dst.addr.ipv4 = ((struct sockaddr_in *)&server_addr)->sin_addr.s_addr;
    } else {
        memcpy(&m_data.flow.dst.addr.ipv6[0],
               &((struct sockaddr_in6 *)&server_addr)->sin6_addr.s6_addr[0],
               sizeof(m_data.flow.dst.addr.ipv6));
    }
    m_data.flow.dst.port = htons(sys_get_port((struct sockaddr *)&server_addr));

    errno = 0;
    rc = send(m_sock_fd, &m_data, sizeof(m_data), 0);
    EXPECT_EQ(0, errno);
    EXPECT_EQ((int)sizeof(m_data), rc);

    memset(&answer, 0, sizeof(answer));
    rc = recv(m_sock_fd, &answer, sizeof(answer), 0);
    EXPECT_EQ((int)sizeof(answer), rc);

    EXPECT_EQ((XLIO_MSG_FLOW | XLIO_MSG_ACK), answer.code);
    EXPECT_LE(XLIO_AGENT_VER, answer.ver);
    EXPECT_EQ(m_pid, answer.pid);
    EXPECT_EQ(0, answer.status);

    rc = xliod_base::msg_exit(m_pid);
    ASSERT_LT(0, rc);
}
