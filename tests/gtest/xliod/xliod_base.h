/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef _XLIOD_BASE_H_
#define _XLIOD_BASE_H_

/**
 * XLIOD Base class for tests
 */
class xliod_base : public testing::Test, public test_base {
protected:
    virtual void SetUp();
    virtual void TearDown();

    int msg_init(pid_t pid);
    int msg_exit(pid_t pid);

protected:
    pid_t m_self_pid;
    pid_t m_xliod_pid;

    const char *m_base_name;

    /* socket used for communication with daemon */
    int m_sock_fd;

    /* file descriptor that is tracked by daemon */
    int m_pid_fd;

    /* unix socket name
     * size should be less than sockaddr_un.sun_path
     */
    char m_sock_file[100];

    /* name of pid file */
    char m_pid_file[100];

    /* server address */
    struct sockaddr_un m_server_addr;
};

#endif /* _XLIOD_BASE_H_ */
