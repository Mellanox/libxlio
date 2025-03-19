/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "common/cmn.h"

#include "xliod_base.h"

#include "src/core/util/agent_def.h"
#include "src/core/lwip/tcp.h"

class xliod_state : public xliod_base {
protected:
    void SetUp()
    {
        xliod_base::SetUp();

        m_pid = 0x53544154;
        memset(&m_data, 0, sizeof(m_data));
        m_data.hdr.code = XLIO_MSG_STATE;
        m_data.hdr.ver = XLIO_AGENT_VER;
        m_data.hdr.pid = m_pid;
    }
    void TearDown() { xliod_base::TearDown(); }

protected:
    struct xlio_msg_state m_data;
    pid_t m_pid;
};

/**
 * @test xliod_state.ti_1
 * @brief
 *    Send valid XLIO_MSG_STATE
 * @details
 */
TEST_F(xliod_state, ti_1)
{
    int rc = 0;

    rc = xliod_base::msg_init(m_pid);
    ASSERT_LT(0, rc);

    m_data.fid = 0;
    m_data.state = ESTABLISHED;
    m_data.type = SOCK_STREAM;
    m_data.src.family = m_family;
    if (m_family == PF_INET) {
        m_data.src.addr.ipv4 = ((struct sockaddr_in *)&client_addr)->sin_addr.s_addr;
    } else {
        memcpy(&m_data.src.addr.ipv6[0],
               &((struct sockaddr_in6 *)&client_addr)->sin6_addr.s6_addr[0],
               sizeof(m_data.src.addr.ipv6));
    }
    m_data.src.port = htons(sys_get_port((struct sockaddr *)&client_addr));
    m_data.dst.family = m_family;
    if (m_family == PF_INET) {
        m_data.dst.addr.ipv4 = ((struct sockaddr_in *)&server_addr)->sin_addr.s_addr;
    } else {
        memcpy(&m_data.dst.addr.ipv6[0],
               &((struct sockaddr_in6 *)&server_addr)->sin6_addr.s6_addr[0],
               sizeof(m_data.dst.addr.ipv6));
    }
    m_data.dst.port = htons(sys_get_port((struct sockaddr *)&server_addr));

    errno = 0;
    rc = send(m_sock_fd, &m_data, sizeof(m_data), 0);
    EXPECT_EQ(0, errno);
    EXPECT_EQ((int)sizeof(m_data), rc);

    rc = xliod_base::msg_exit(m_pid);
    ASSERT_LT(0, rc);
}
