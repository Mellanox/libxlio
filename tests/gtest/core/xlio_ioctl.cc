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

#if defined(EXTRA_API_ENABLED) && (EXTRA_API_ENABLED == 1)

#include "xlio_base.h"

class xlio_ioctl : public xlio_base {
protected:
    void SetUp()
    {
        uint64_t xlio_extra_api_cap = XLIO_EXTRA_API_IOCTL;

        xlio_base::SetUp();

        SKIP_TRUE((xlio_api->cap_mask & xlio_extra_api_cap) == xlio_extra_api_cap,
                  "This test requires XLIO capabilities as XLIO_EXTRA_API_IOCTL");
    }
    void TearDown() { xlio_base::TearDown(); }
};

/**
 * @test xlio_ioctl.ti_1
 * @brief
 *    CMSG_XLIO_IOCTL_USER_ALLOC command message format check
 * @details
 */
TEST_F(xlio_ioctl, ti_1)
{
    int rc = EOK;
    int fd;
#pragma pack(push, 1)
    struct {
        uint8_t flags;
        void *(*alloc_func)(size_t);
        void (*free_func)(void *);
    } data;
#pragma pack(pop)
    struct cmsghdr *cmsg;
    char cbuf[CMSG_SPACE(sizeof(data))];

    ASSERT_TRUE((sizeof(uint8_t) + sizeof(uintptr_t) + sizeof(uintptr_t)) == sizeof(data));

    /* scenario #1: Wrong cmsg length */
    errno = EOK;
    cmsg = (struct cmsghdr *)cbuf;
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = CMSG_XLIO_IOCTL_USER_ALLOC;
    cmsg->cmsg_len = CMSG_LEN(sizeof(data)) - 1;
    data.flags = 0x01;
    data.alloc_func = malloc;
    data.free_func = free;
    memcpy(CMSG_DATA(cmsg), &data, sizeof(data));

    rc = xlio_api->ioctl(cmsg, cmsg->cmsg_len);
    EXPECT_EQ(-1, rc);
    EXPECT_TRUE(EINVAL == errno);

    /* scenario #2: invalid function pointer */
    errno = EOK;
    cmsg = (struct cmsghdr *)cbuf;
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = CMSG_XLIO_IOCTL_USER_ALLOC;
    cmsg->cmsg_len = CMSG_LEN(sizeof(data));
    data.flags = 0x01;
    data.alloc_func = malloc;
    data.free_func = NULL;
    memcpy(CMSG_DATA(cmsg), &data, sizeof(data));

    rc = xlio_api->ioctl(cmsg, cmsg->cmsg_len);
    EXPECT_EQ(-1, rc);
    EXPECT_TRUE(EINVAL == errno);

    /* scenario #3: Command can not be used after initialization of internals */
    fd = socket(m_family, SOCK_DGRAM, IPPROTO_IP);
    ASSERT_LE(0, fd);

    errno = EOK;
    cmsg = (struct cmsghdr *)cbuf;
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = CMSG_XLIO_IOCTL_USER_ALLOC;
    cmsg->cmsg_len = CMSG_LEN(sizeof(data));
    data.flags = 0x01;
    data.alloc_func = malloc;
    data.free_func = free;
    memcpy(CMSG_DATA(cmsg), &data, sizeof(data));

    rc = xlio_api->ioctl(cmsg, cmsg->cmsg_len);
    EXPECT_EQ(-1, rc);
    EXPECT_TRUE(EINVAL == errno);
}

#endif /* EXTRA_API_ENABLED */
