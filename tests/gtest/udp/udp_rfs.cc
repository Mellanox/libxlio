/*
 * Copyright (c) 2001-2022 Mellanox Technologies, Ltd. All rights reserved.
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

#include "udp_base.h"

class udp_rfs : public udp_base {
};

/**
 * @test udp_rfs.single_rule_send
 * @brief
 *    Check single RFS rule per ring.
 * @details
 */
TEST_F(udp_rfs, single_rule_send)
{
    int rc = EOK;
    int fd;
    char buf[] = "hello";

    int pid = fork();

    if (0 == pid) { /* I am the child */
        barrier_fork(pid);

        fd = udp_base::sock_create();
        ASSERT_LE(0, fd);

        rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
        ASSERT_EQ(0, rc);

        log_trace("Client bound: fd=%d to %s\n", fd, sys_addr2str((struct sockaddr *)&client_addr));

        rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        rc = send(fd, (const void *)buf, sizeof(buf), 0);
        EXPECT_GE(rc, 0);

        close(fd);

        /* This exit is very important, otherwise the fork
         * keeps running and may duplicate other tests.
         */
        exit(testing::Test::HasFailure());
    } else { /* I am the parent */
        memset(buf, 0, sizeof(buf));

        fd = udp_base::sock_create();
        ASSERT_LE(0, fd);

        rc = bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        log_trace("Server bound: fd=%d to %s\n", fd, sys_addr2str((struct sockaddr *)&server_addr));

        barrier_fork(pid);

        int i = sizeof(buf);
        while (i > 0 && !child_fork_exit()) {
            rc = recv(fd, (void *)buf, i, MSG_WAITALL);
            EXPECT_GE(rc, 0);
            i -= rc;
        }
        EXPECT_EQ(0, i);

        close(fd);

        ASSERT_EQ(0, wait_fork(pid));
    }
}
