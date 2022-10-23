/*
 * Copyright (c) 2001-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
