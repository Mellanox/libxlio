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

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "common/cmn.h"

#include "xliod_base.h"

#include "src/core/util/agent_def.h"
#include "config.h"

class xliod_init : public xliod_base {
protected:
    void SetUp()
    {
        uint8_t *version;

        xliod_base::SetUp();

        m_pid = 0x494E4954;
        memset(&m_data, 0, sizeof(m_data));
        version = (uint8_t *)&m_data.ver;
        version[0] = PRJ_LIBRARY_MAJOR;
        // DOCA minor is 9XY where XY is XLIO minor
        // putting the XLIO minor in these tests
        version[1] = PRJ_LIBRARY_MINOR % 100;

        version[2] = PRJ_LIBRARY_RELEASE;
        version[3] = PRJ_LIBRARY_REVISION;
    }
    void TearDown() { xliod_base::TearDown(); }

protected:
    struct xlio_msg_init m_data;
    pid_t m_pid;
};

/**
 * @test xliod_init.ti_1
 * @brief
 *    Send data less than (struct xlio_hdr)
 * @details
 */
TEST_F(xliod_init, ti_1)
{
    int rc = 0;
    struct xlio_msg_init data;

    errno = 0;
    rc = send(m_sock_fd, &m_data, sizeof(m_data.hdr) - 1, 0);
    EXPECT_EQ(0, errno);
    ASSERT_EQ((int)sizeof(m_data.hdr) - 1, rc);

    memset(&data, 0, sizeof(data));
    rc = recv(m_sock_fd, &data, sizeof(data), 0);
    EXPECT_EQ(EAGAIN, errno);
    EXPECT_EQ((-1), rc);
}

/**
 * @test xliod_init.ti_2
 * @brief
 *    Send data less than (struct xlio_msg_init)
 * @details
 */
TEST_F(xliod_init, ti_2)
{
    int rc = 0;
    struct xlio_msg_init data;

    errno = 0;
    rc = send(m_sock_fd, &m_data, sizeof(m_data) - 1, 0);
    EXPECT_EQ(0, errno);
    ASSERT_EQ((int)sizeof(m_data) - 1, rc);

    memset(&data, 0, sizeof(data));
    rc = recv(m_sock_fd, &data, sizeof(data), 0);
    EXPECT_EQ(EAGAIN, errno);
    EXPECT_EQ((-1), rc);
}

/**
 * @test xliod_init.ti_3
 * @brief
 *    Send data with invalid header version
 * @details
 */
TEST_F(xliod_init, ti_3)
{
    int rc = 0;
    struct xlio_msg_init data;

    errno = 0;
    m_data.hdr.ver = 0xFF;
    rc = send(m_sock_fd, &m_data, sizeof(m_data) - 1, 0);
    EXPECT_EQ(0, errno);
    ASSERT_EQ((int)sizeof(m_data) - 1, rc);

    memset(&data, 0, sizeof(data));
    rc = recv(m_sock_fd, &data, sizeof(data), 0);
    EXPECT_EQ(EAGAIN, errno);
    EXPECT_EQ((-1), rc);
}

/**
 * @test xliod_init.ti_4
 * @brief
 *    Send valid XLIO_MSG_INIT
 * @details
 */
TEST_F(xliod_init, ti_4)
{
    int rc = 0;
    struct xlio_msg_init data;

    errno = 0;
    rc = send(m_sock_fd, &m_data, sizeof(m_data), 0);
    EXPECT_EQ(0, errno);
    ASSERT_EQ((int)sizeof(m_data), rc);

    memset(&data, 0, sizeof(data));
    rc = recv(m_sock_fd, &data, sizeof(data), 0);
    EXPECT_EQ((int)sizeof(data), rc);

    EXPECT_EQ((XLIO_MSG_INIT | XLIO_MSG_ACK), data.hdr.code);
    EXPECT_LE(XLIO_AGENT_VER, data.hdr.ver);
    EXPECT_EQ(m_pid, data.hdr.pid);
}

/**
 * @test xliod_init.ti_5
 * @brief
 *    Send valid XLIO_MSG_EXIT
 * @details
 */
TEST_F(xliod_init, ti_5)
{
    int rc = 0;
    struct xlio_msg_exit data;

    memset(&data, 0, sizeof(data));
    data.hdr.code = XLIO_MSG_EXIT;
    data.hdr.ver = XLIO_AGENT_VER;
    data.hdr.pid = m_pid;

    errno = 0;
    rc = send(m_sock_fd, &data, sizeof(data), 0);
    EXPECT_EQ(0, errno);
    ASSERT_EQ((int)sizeof(data), rc);
}
