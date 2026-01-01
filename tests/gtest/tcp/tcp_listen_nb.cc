/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2022-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#include "tcp_base.h"

class tcp_listen_nb : public tcp_base {};

/**
 * @test tcp_listen_nb.basic_listen_nb
 * @brief
 *    Basic non-blocking TCP listen functionality test
 *
 * @details
 *    Tests basic non-blocking TCP socket creation, bind, and listen operations.
 */
TEST_F(tcp_listen_nb, basic_listen_nb)
{
    int fd = tcp_base::sock_create_nb();
    ASSERT_LE(0, fd);

    int rc = bind(fd, &server_addr.addr, sizeof(server_addr));
    EXPECT_EQ_ERRNO(0, rc);
    if (rc != 0) {
        goto cleanup;
    }

    rc = listen(fd, 5);
    EXPECT_EQ_ERRNO(0, rc);

cleanup:
    close(fd);
}
