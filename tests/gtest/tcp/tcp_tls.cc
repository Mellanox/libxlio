/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "common/cmn.h"

#ifdef HAVE_LINUX_TLS_H
#include <algorithm>
#include <linux/tls.h>
#include <vector>

#include "tcp_base.h"

#define TLS_PAYLOAD_MAX_LEN 16384
#define SOL_TLS             282

#ifndef TCP_ULP
#define TCP_ULP 31
#endif

class tcp_tls : public tcp_base {
public:
    static int create_tmp_file(size_t size)
    {
        char filename[] = "/tmp/mytemp.XXXXXX";
        int fd = mkstemp(filename);
        ssize_t ret;

        if (fd >= 0) {
            unlink(filename);
            while (size--) {
                char buf = size % 255;
                ret = write(fd, &buf, sizeof(buf));
                (void)ret;
            }
            fsync(fd);
        }
        return fd;
    }

    static ssize_t send_all(int fd, const uint8_t *buffer, size_t length)
    {
        size_t offset = 0;

        while (offset < length) {
            ssize_t rc = send(fd, buffer + offset, length - offset, 0);
            if (rc < 0 && errno == EINTR) {
                continue;
            }
            if (rc <= 0) {
                return rc;
            }
            offset += static_cast<size_t>(rc);
        }
        return static_cast<ssize_t>(offset);
    }

    static ssize_t recv_all(int fd, uint8_t *buffer, size_t length)
    {
        size_t offset = 0;

        while (offset < length) {
            ssize_t rc = recv(fd, buffer + offset, length - offset, 0);
            if (rc < 0 && errno == EINTR) {
                continue;
            }
            if (rc <= 0) {
                break;
            }
            offset += static_cast<size_t>(rc);
        }
        return static_cast<ssize_t>(offset);
    }

    static int wait_for_queued_bytes(int fd, size_t minimum)
    {
        for (int attempt = 0; attempt < 500; ++attempt) {
            int available = 0;
            if (ioctl(fd, FIONREAD, &available) < 0) {
                return -1;
            }
            if (static_cast<size_t>(available) >= minimum) {
                return available;
            }
            usleep(10000);
        }

        errno = ETIMEDOUT;
        return -1;
    }

protected:
    void SetUp()
    {
        tcp_base::SetUp();

        errno = EOK;
        fd = -1;
        test_buf = NULL;
    }
    void TearDown()
    {
        if (test_buf) {
            free(test_buf);
        }
        if (test_file >= 0) {
            close(test_file);
        }

        tcp_base::TearDown();
    }

protected:
    int fd;
    char *test_buf;
    int test_file;
};

/**
 * @test tcp_tls.ti_1
 * @brief
 *    tls setsockopt(TCP_ULP, "tls") should fail
 *    without established connection
 * @details
 */
TEST_F(tcp_tls, DISABLED_ti_1)
{
    int rc = EOK;

    fd = tcp_base::sock_create();
    ASSERT_LE(0, fd);

    rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
    EXPECT_EQ(-1, rc);
    /* There is a bug in kernel as
     * "Bug 1778348 - Kernel TLS and "Unknown error 524" during setsockopt"
     */
    EXPECT_TRUE(ENOTCONN == errno || 524 == errno);

    rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
    ASSERT_EQ(0, rc);

    rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
    EXPECT_EQ(-1, rc);
    /* There is a bug in kernel as
     * "Bug 1778348 - Kernel TLS and "Unknown error 524" during setsockopt"
     */
    EXPECT_TRUE(ENOTCONN == errno || 524 == errno);

    close(fd);
}

/**
 * @test tcp_tls.ti_2
 * @brief
 *    Exchange data without TLS key
 * @details
 */
TEST_F(tcp_tls, ti_2)
{
    int rc = EOK;
    char test_msg[] = "Hello test";

    int pid = fork();

    if (0 == pid) { /* I am the child */
        barrier_fork(pid);

        fd = tcp_base::sock_create();
        ASSERT_LE(0, fd);

        rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
        ASSERT_EQ(0, rc);

        rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        log_trace("Established connection: fd=%d to %s\n", fd,
                  sys_addr2str((struct sockaddr *)&server_addr));

        rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
        SKIP_TRUE((0 == rc), "TLS is not supported");

        rc = send(fd, (void *)test_msg, sizeof(test_msg), 0);
        EXPECT_EQ(sizeof(test_msg), static_cast<size_t>(rc));

        peer_wait(fd);

        close(fd);

        /* This exit is very important, otherwise the fork
         * keeps running and may duplicate other tests.
         */
        exit(testing::Test::HasFailure());
    } else { /* I am the parent */
        int l_fd;
        struct sockaddr peer_addr;
        socklen_t socklen;
        char buf[sizeof(test_msg)];

        l_fd = tcp_base::sock_create();
        ASSERT_LE(0, l_fd);

        rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        rc = listen(l_fd, 5);
        ASSERT_EQ(0, rc);

        barrier_fork(pid);

        socklen = sizeof(peer_addr);
        fd = accept(l_fd, &peer_addr, &socklen);
        ASSERT_LE(0, fd);
        close(l_fd);

        log_trace("Accepted connection: fd=%d from %s\n", fd,
                  sys_addr2str((struct sockaddr *)&peer_addr));

        rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
        SKIP_TRUE((0 == rc), "TLS is not supported");

        rc = recv(fd, (void *)buf, sizeof(buf), 0);
        EXPECT_EQ(sizeof(test_msg), static_cast<size_t>(rc));

        log_trace("Test check: expected: '%s' actual: '%s'\n", test_msg, buf);

        EXPECT_EQ(memcmp(buf, test_msg, rc), 0);

        close(fd);

        ASSERT_EQ(0, wait_fork(pid));
    }
}

/**
 * @test tcp_tls.ti_3
 * @brief
 *    Exchange data by send(<TLS_PAYLOAD_MAX_LEN) using
 *     .tls_version = TLS_1_2_VERSION
 *     .cipher_type = TLS_CIPHER_AES_GCM_128
 *
 * @details
 */
TEST_F(tcp_tls, ti_3_12_gcm_send_small)
{
    int rc = EOK;
    char test_msg[] = "Hello test";
    struct tls12_crypto_info_aes_gcm_128 crypto_info;

    memset(&crypto_info, 0, sizeof(crypto_info));
    crypto_info.info.version = TLS_1_2_VERSION;
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

    int pid = fork();

    if (0 == pid) { /* I am the child */
        barrier_fork(pid);

        fd = tcp_base::sock_create();
        ASSERT_LE(0, fd);

        rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
        ASSERT_EQ(0, rc);

        rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        log_trace("Established connection: fd=%d to %s\n", fd,
                  sys_addr2str((struct sockaddr *)&server_addr));

        rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
        SKIP_TRUE((0 == rc), "TLS is not supported");

        rc = setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
        EXPECT_EQ(0, rc);

        rc = send(fd, (void *)test_msg, sizeof(test_msg), 0);
        EXPECT_EQ(sizeof(test_msg), static_cast<size_t>(rc));

        peer_wait(fd);

        close(fd);

        /* This exit is very important, otherwise the fork
         * keeps running and may duplicate other tests.
         */
        exit(testing::Test::HasFailure());
    } else { /* I am the parent */
        int l_fd;
        struct sockaddr peer_addr;
        socklen_t socklen;
        char buf[sizeof(test_msg)];

        l_fd = tcp_base::sock_create();
        ASSERT_LE(0, l_fd);

        rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        rc = listen(l_fd, 5);
        ASSERT_EQ(0, rc);

        barrier_fork(pid);

        socklen = sizeof(peer_addr);
        fd = accept(l_fd, &peer_addr, &socklen);
        ASSERT_LE(0, fd);
        close(l_fd);

        log_trace("Accepted connection: fd=%d from %s\n", fd,
                  sys_addr2str((struct sockaddr *)&peer_addr));

        rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
        SKIP_TRUE((0 == rc), "TLS is not supported");

        rc = setsockopt(fd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info));
        EXPECT_EQ(0, rc);

        rc = recv(fd, (void *)buf, sizeof(buf), 0);
        EXPECT_EQ(sizeof(test_msg), static_cast<size_t>(rc));

        log_trace("Test check: expected: '%s' actual: '%s'\n", test_msg, buf);

        EXPECT_EQ(memcmp(buf, test_msg, rc), 0);

        close(fd);

        ASSERT_EQ(0, wait_fork(pid));
    }
}

/**
 * @test tcp_tls.ti_4
 * @brief
 *    Exchange data by send(==TLS_PAYLOAD_MAX_LEN) using
 *     .tls_version = TLS_1_2_VERSION
 *     .cipher_type = TLS_CIPHER_AES_GCM_128
 *
 * @details
 */
TEST_F(tcp_tls, DISABLED_ti_4_12_gcm_send_max)
{
    int rc = EOK;
    char test_msg[TLS_PAYLOAD_MAX_LEN] = "Maximum TLS record";
    struct tls12_crypto_info_aes_gcm_128 crypto_info;

    memset(&crypto_info, 0, sizeof(crypto_info));
    crypto_info.info.version = TLS_1_2_VERSION;
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

    int pid = fork();

    if (0 == pid) { /* I am the child */
        barrier_fork(pid);

        fd = tcp_base::sock_create();
        ASSERT_LE(0, fd);

        rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
        ASSERT_EQ(0, rc);

        rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        log_trace("Established connection: fd=%d to %s\n", fd,
                  sys_addr2str((struct sockaddr *)&server_addr));

        rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
        SKIP_TRUE((0 == rc), "TLS is not supported");

        rc = setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
        EXPECT_EQ(0, rc);

        rc = send(fd, (void *)test_msg, sizeof(test_msg), 0);
        EXPECT_EQ(sizeof(test_msg), static_cast<size_t>(rc));

        peer_wait(fd);

        close(fd);

        /* This exit is very important, otherwise the fork
         * keeps running and may duplicate other tests.
         */
        exit(testing::Test::HasFailure());
    } else { /* I am the parent */
        int l_fd;
        struct sockaddr peer_addr;
        socklen_t socklen;
        char buf[sizeof(test_msg)];

        l_fd = tcp_base::sock_create();
        ASSERT_LE(0, l_fd);

        rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        rc = listen(l_fd, 5);
        ASSERT_EQ(0, rc);

        barrier_fork(pid);

        socklen = sizeof(peer_addr);
        fd = accept(l_fd, &peer_addr, &socklen);
        ASSERT_LE(0, fd);
        close(l_fd);

        log_trace("Accepted connection: fd=%d from %s\n", fd,
                  sys_addr2str((struct sockaddr *)&peer_addr));

        rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
        SKIP_TRUE((0 == rc), "TLS is not supported");

        rc = setsockopt(fd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info));
        EXPECT_EQ(0, rc);

        rc = recv(fd, (void *)buf, sizeof(buf), 0);
        EXPECT_EQ(sizeof(test_msg), static_cast<size_t>(rc));

        log_trace("Test check: expected: '%s' actual: '%s'\n", test_msg, buf);

        EXPECT_EQ(memcmp(buf, test_msg, rc), 0);

        close(fd);

        ASSERT_EQ(0, wait_fork(pid));
    }
}

/**
 * @test tcp_tls.ti_5
 * @brief
 *    Exchange data by send(MSG_MORE) using
 *     .tls_version = TLS_1_2_VERSION
 *     .cipher_type = TLS_CIPHER_AES_GCM_128
 *
 * @details
 */
TEST_F(tcp_tls, ti_5_12_gcm_send_more)
{
    int rc = EOK;
    char test_msg[] = "Test check";
    struct tls12_crypto_info_aes_gcm_128 crypto_info;

    memset(&crypto_info, 0, sizeof(crypto_info));
    crypto_info.info.version = TLS_1_2_VERSION;
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

    int pid = fork();

    if (0 == pid) { /* I am the child */
        barrier_fork(pid);

        fd = tcp_base::sock_create();
        ASSERT_LE(0, fd);

        rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
        ASSERT_EQ(0, rc);

        rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        log_trace("Established connection: fd=%d to %s\n", fd,
                  sys_addr2str((struct sockaddr *)&server_addr));

        rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
        SKIP_TRUE((0 == rc), "TLS is not supported");

        rc = setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
        EXPECT_EQ(0, rc);

        rc = send(fd, (void *)test_msg, sizeof(test_msg), MSG_MORE);
        EXPECT_EQ(sizeof(test_msg), static_cast<size_t>(rc));

        rc = send(fd, (void *)test_msg, sizeof(test_msg), 0);
        EXPECT_EQ(sizeof(test_msg), static_cast<size_t>(rc));

        peer_wait(fd);

        close(fd);

        /* This exit is very important, otherwise the fork
         * keeps running and may duplicate other tests.
         */
        exit(testing::Test::HasFailure());
    } else { /* I am the parent */
        int l_fd;
        struct sockaddr peer_addr;
        socklen_t socklen;
        char buf[2 * sizeof(test_msg)];

        l_fd = tcp_base::sock_create();
        ASSERT_LE(0, l_fd);

        rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        rc = listen(l_fd, 5);
        ASSERT_EQ(0, rc);

        barrier_fork(pid);

        socklen = sizeof(peer_addr);
        fd = accept(l_fd, &peer_addr, &socklen);
        ASSERT_LE(0, fd);
        close(l_fd);

        log_trace("Accepted connection: fd=%d from %s\n", fd,
                  sys_addr2str((struct sockaddr *)&peer_addr));

        rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
        SKIP_TRUE((0 == rc), "TLS is not supported");

        rc = setsockopt(fd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info));
        EXPECT_EQ(0, rc);

        rc = recv(fd, (void *)buf, sizeof(buf), MSG_WAITALL);
        EXPECT_EQ(2 * sizeof(test_msg), static_cast<size_t>(rc));

        log_trace("Test check: expected: '%s' actual: '%s'\n", test_msg, buf);

        EXPECT_EQ(memcmp(buf, test_msg, sizeof(test_msg)), 0);

        close(fd);

        ASSERT_EQ(0, wait_fork(pid));
    }
}

/**
 * @test tcp_tls.ti_6
 * @brief
 *    Exchange data by sendfile() using
 *     .tls_version = TLS_1_2_VERSION
 *     .cipher_type = TLS_CIPHER_AES_GCM_128
 *
 * @details
 */
TEST_F(tcp_tls, DISABLED_ti_6_12_gcm_sendfile)
{
    int rc = EOK;
    struct tls12_crypto_info_aes_gcm_128 crypto_info;
    int test_file_size = 0x10000;
    test_file = create_tmp_file(test_file_size);

    EXPECT_GE(test_file, 0);

    memset(&crypto_info, 0, sizeof(crypto_info));
    crypto_info.info.version = TLS_1_2_VERSION;
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

    int pid = fork();

    if (0 == pid) { /* I am the child */
        off_t test_file_offset = 0;

        barrier_fork(pid);

        fd = tcp_base::sock_create();
        ASSERT_LE(0, fd);

        rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
        ASSERT_EQ(0, rc);

        rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        log_trace("Established connection: fd=%d to %s\n", fd,
                  sys_addr2str((struct sockaddr *)&server_addr));

        rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
        SKIP_TRUE((0 == rc), "TLS is not supported");

        rc = setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
        EXPECT_EQ(0, rc);

        while (test_file_size > 0) {
            rc = sendfile(fd, test_file, &test_file_offset, test_file_size);
            EXPECT_GE(rc, 0);
            test_file_size -= rc;
        }
        EXPECT_EQ(0, test_file_size);

        peer_wait(fd);

        close(fd);

        /* This exit is very important, otherwise the fork
         * keeps running and may duplicate other tests.
         */
        exit(testing::Test::HasFailure());
    } else { /* I am the parent */
        int l_fd;
        struct sockaddr peer_addr;
        socklen_t socklen;

        test_buf = (char *)malloc(test_file_size);
        ASSERT_TRUE(test_buf);

        l_fd = tcp_base::sock_create();
        ASSERT_LE(0, l_fd);

        rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        rc = listen(l_fd, 5);
        ASSERT_EQ(0, rc);

        barrier_fork(pid);

        socklen = sizeof(peer_addr);
        fd = accept(l_fd, &peer_addr, &socklen);
        ASSERT_LE(0, fd);
        close(l_fd);

        log_trace("Accepted connection: fd=%d from %s\n", fd,
                  sys_addr2str((struct sockaddr *)&peer_addr));

        rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
        SKIP_TRUE((0 == rc), "TLS is not supported");

        rc = setsockopt(fd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info));
        EXPECT_EQ(0, rc);

        while (test_file_size > 0 && !child_fork_exit()) {
            rc = recv(fd, (void *)test_buf, test_file_size, MSG_WAITALL);
            EXPECT_GE(rc, 0);
            test_file_size -= rc;
        }
        EXPECT_EQ(0, test_file_size);

        close(fd);

        ASSERT_EQ(0, wait_fork(pid));
    }
}

/**
 * @test tcp_tls.ti_7
 * @brief
 *    Exchange data by sendfile() with chunks using
 *     .tls_version = TLS_1_2_VERSION
 *     .cipher_type = TLS_CIPHER_AES_GCM_128
 *
 * @details
 */
TEST_F(tcp_tls, DISABLED_ti_7_12_gcm_sendfile_chunk)
{
    int rc = EOK;
    struct tls12_crypto_info_aes_gcm_128 crypto_info;
    struct {
        int chunk_size;
        int extra_size;
    } test_scenario[] = {{4096, 4096},  {4096, 0},    {4096, 1},     {4096, 2048},  {4096, 8192},
                         {8192, 2048},  {8192, 4096}, {12288, 1024}, {12288, 2000}, {15360, 100},
                         {15360, 300},  {1, 4096},    {2048, 4096},  {2048, 8192},  {1024, 12288},
                         {2000, 12288}, {100, 15360}, {300, 15360}};
    int i = 0;

    memset(&crypto_info, 0, sizeof(crypto_info));
    crypto_info.info.version = TLS_1_2_VERSION;
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

    for (i = 0; (i < (int)(sizeof(test_scenario) / sizeof(test_scenario[0]))); i++) {
        int test_chunk = test_scenario[i].chunk_size;
        int test_file_size = test_scenario[i].chunk_size + test_scenario[i].extra_size;
        test_file = create_tmp_file(test_file_size);
        EXPECT_GE(test_file, 0);

        log_trace("Test case [%d]: chunk size: %d file size: %d\n", i, test_chunk, test_file_size);
        sys_set_port((struct sockaddr *)&server_addr, m_port + i);

        int pid = fork();
        if (0 == pid) { /* I am the child */
            off_t test_file_offset = 0;

            barrier_fork(pid);

            fd = tcp_base::sock_create();
            ASSERT_LE(0, fd);

            rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
            ASSERT_EQ(0, rc);

            rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            ASSERT_EQ(0, rc);

            log_trace("Established connection: fd=%d to %s\n", fd,
                      sys_addr2str((struct sockaddr *)&server_addr));

            rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
            SKIP_TRUE((0 == rc), "TLS is not supported");

            rc = setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
            EXPECT_EQ(0, rc);

            while (test_file_size > 0) {
                rc = sendfile(fd, test_file, &test_file_offset, test_chunk);
                EXPECT_GE(rc, 0);
                test_file_size -= rc;
            }
            EXPECT_EQ(0, test_file_size);

            peer_wait(fd);

            close(fd);
            close(test_file);

            /* This exit is very important, otherwise the fork
             * keeps running and may duplicate other tests.
             */
            exit(testing::Test::HasFailure());
        } else { /* I am the parent */
            int l_fd;
            struct sockaddr peer_addr;
            socklen_t socklen;

            test_buf = (char *)malloc(test_file_size);
            ASSERT_TRUE(test_buf);

            l_fd = tcp_base::sock_create();
            ASSERT_LE(0, l_fd);

            rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            ASSERT_EQ(0, rc);

            rc = listen(l_fd, 5);
            ASSERT_EQ(0, rc);

            barrier_fork(pid);

            socklen = sizeof(peer_addr);
            fd = accept(l_fd, &peer_addr, &socklen);
            ASSERT_LE(0, fd);
            close(l_fd);

            log_trace("Accepted connection: fd=%d from %s\n", fd,
                      sys_addr2str((struct sockaddr *)&peer_addr));

            rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
            SKIP_TRUE((0 == rc), "TLS is not supported");

            rc = setsockopt(fd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info));
            EXPECT_EQ(0, rc);

            while (test_file_size > 0 && !child_fork_exit()) {
                rc = recv(fd, (void *)test_buf, test_file_size, MSG_WAITALL);
                EXPECT_GE(rc, 0);
                test_file_size -= rc;
            }
            EXPECT_EQ(0, test_file_size);

            close(fd);
            free(test_buf);
            test_buf = NULL;

            ASSERT_EQ(0, wait_fork(pid));
        }
    }
}

/**
 * @test tcp_tls.ti_8
 * @brief
 *    Exchange data by sendmsg() using
 *     .tls_version = TLS_1_2_VERSION
 *     .cipher_type = TLS_CIPHER_AES_GCM_128
 *
 * @details
 */
TEST_F(tcp_tls, ti_8_12_gcm_sendmsg)
{
    int rc = EOK;
    char test_msg[] = "Hello test";
    struct tls12_crypto_info_aes_gcm_128 crypto_info;
    int frags_num = 12;
    int i = 0;

    memset(&crypto_info, 0, sizeof(crypto_info));
    crypto_info.info.version = TLS_1_2_VERSION;
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

    for (i = 1; i < frags_num; i++) {
        int j = 0;
        struct iovec vec[frags_num];
        struct msghdr msg;
        int test_msg_size = i * sizeof(test_msg);
        for (j = 0; j < i; j++) {
            vec[j].iov_base = (char *)test_msg;
            vec[j].iov_len = sizeof(test_msg);
        }

        memset(&msg, 0, sizeof(struct msghdr));
        msg.msg_iov = vec;
        msg.msg_iovlen = i;

        log_trace("Test case [%d]: fragments: %d total size: %d\n", i, i, test_msg_size);
        sys_set_port((struct sockaddr *)&server_addr, m_port + i);

        int pid = fork();
        if (0 == pid) { /* I am the child */
            barrier_fork(pid);

            fd = tcp_base::sock_create();
            ASSERT_LE(0, fd);

            rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
            ASSERT_EQ(0, rc);

            rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            ASSERT_EQ(0, rc);

            log_trace("Established connection: fd=%d to %s\n", fd,
                      sys_addr2str((struct sockaddr *)&server_addr));

            rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
            SKIP_TRUE((0 == rc), "TLS is not supported");

            rc = setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
            EXPECT_EQ(0, rc);

            rc = sendmsg(fd, &msg, 0);
            EXPECT_EQ(test_msg_size, rc);

            peer_wait(fd);

            close(fd);

            /* This exit is very important, otherwise the fork
             * keeps running and may duplicate other tests.
             */
            exit(testing::Test::HasFailure());
        } else { /* I am the parent */
            int l_fd;
            struct sockaddr peer_addr;
            socklen_t socklen;

            test_buf = (char *)malloc(test_msg_size);
            ASSERT_TRUE(test_buf);

            l_fd = tcp_base::sock_create();
            ASSERT_LE(0, l_fd);

            rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            ASSERT_EQ(0, rc);

            rc = listen(l_fd, 5);
            ASSERT_EQ(0, rc);

            barrier_fork(pid);

            socklen = sizeof(peer_addr);
            fd = accept(l_fd, &peer_addr, &socklen);
            ASSERT_LE(0, fd);
            close(l_fd);

            log_trace("Accepted connection: fd=%d from %s\n", fd,
                      sys_addr2str((struct sockaddr *)&peer_addr));

            rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
            SKIP_TRUE((0 == rc), "TLS is not supported");

            rc = setsockopt(fd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info));
            EXPECT_EQ(0, rc);

            while (test_msg_size > 0 && !child_fork_exit()) {
                rc = recv(fd, (void *)test_buf, test_msg_size, MSG_WAITALL);
                EXPECT_GE(rc, 0);
                test_msg_size -= rc;
            }
            EXPECT_EQ(0, test_msg_size);

            close(fd);
            free(test_buf);
            test_buf = NULL;

            ASSERT_EQ(0, wait_fork(pid));
        }
    }
}

/**
 * @test tcp_tls.ti_9
 * @brief
 *    Exchange data by send(<TLS_PAYLOAD_MAX_LEN) using
 *     .tls_version = TLS_1_2_VERSION
 *     .cipher_type = TLS_CIPHER_AES_GCM_128
 *
 * @details
 */
TEST_F(tcp_tls, ti_9_12_gcm_send_bidirect)
{
    int rc = EOK;
    char test_msg[] = "Hello test";
    struct tls12_crypto_info_aes_gcm_128 crypto_info;

    memset(&crypto_info, 0, sizeof(crypto_info));
    crypto_info.info.version = TLS_1_2_VERSION;
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

    int pid = fork();

    if (0 == pid) { /* I am the child */
        char buf[sizeof(test_msg)];

        barrier_fork(pid);

        fd = tcp_base::sock_create();
        ASSERT_LE(0, fd);

        rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
        ASSERT_EQ(0, rc);

        rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        log_trace("Established connection: fd=%d to %s\n", fd,
                  sys_addr2str((struct sockaddr *)&server_addr));

        rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
        SKIP_TRUE((0 == rc), "TLS is not supported");

        rc = setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
        EXPECT_EQ(0, rc);

        rc = setsockopt(fd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info));
        EXPECT_EQ(0, rc);

        rc = send(fd, (void *)test_msg, sizeof(test_msg), 0);
        EXPECT_EQ(sizeof(test_msg), static_cast<size_t>(rc));

        rc = recv(fd, (void *)buf, sizeof(buf), 0);
        EXPECT_EQ(sizeof(test_msg), static_cast<size_t>(rc));

        log_trace("Test check: expected: '%s' actual: '%s'\n", test_msg, buf);

        EXPECT_EQ(memcmp(buf, test_msg, rc), 0);

        close(fd);

        /* This exit is very important, otherwise the fork
         * keeps running and may duplicate other tests.
         */
        exit(testing::Test::HasFailure());
    } else { /* I am the parent */
        int l_fd;
        struct sockaddr peer_addr;
        socklen_t socklen;
        char buf[sizeof(test_msg)];

        l_fd = tcp_base::sock_create();
        ASSERT_LE(0, l_fd);

        rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        rc = listen(l_fd, 5);
        ASSERT_EQ(0, rc);

        barrier_fork(pid);

        socklen = sizeof(peer_addr);
        fd = accept(l_fd, &peer_addr, &socklen);
        ASSERT_LE(0, fd);
        close(l_fd);

        log_trace("Accepted connection: fd=%d from %s\n", fd,
                  sys_addr2str((struct sockaddr *)&peer_addr));

        rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
        SKIP_TRUE((0 == rc), "TLS is not supported");

        rc = setsockopt(fd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info));
        EXPECT_EQ(0, rc);

        rc = setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
        EXPECT_EQ(0, rc);

        rc = recv(fd, (void *)buf, sizeof(buf), 0);
        EXPECT_EQ(sizeof(test_msg), static_cast<size_t>(rc));

        log_trace("Test check: expected: '%s' actual: '%s'\n", test_msg, buf);

        EXPECT_EQ(memcmp(buf, test_msg, rc), 0);

        rc = send(fd, (void *)test_msg, sizeof(test_msg), 0);
        EXPECT_EQ(sizeof(test_msg), static_cast<size_t>(rc));

        peer_wait(fd);

        close(fd);

        ASSERT_EQ(0, wait_fork(pid));
    }
}

/**
 * @test tcp_tls.ti_10
 * @brief
 *    Exchange data by send(<TLS_PAYLOAD_MAX_LEN) using
 *     .tls_version = TLS_1_2_VERSION
 *     .cipher_type = TLS_CIPHER_AES_GCM_128
 *
 * @details
 */
TEST_F(tcp_tls, DISABLED_ti_10_12_gcm_control_msg)
{
    int rc = EOK;
    char test_msg[] = "Hello test";
    struct tls12_crypto_info_aes_gcm_128 crypto_info;
    uint8_t record_type = 100;
    struct msghdr msg;
    int cmsg_len = sizeof(record_type);
    struct cmsghdr *cmsg;
    char cbuf[CMSG_SPACE(cmsg_len)];
    struct iovec msg_iov;

    memset(&crypto_info, 0, sizeof(crypto_info));
    crypto_info.info.version = TLS_1_2_VERSION;
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

    memset(&msg, 0, sizeof(struct msghdr));

    int pid = fork();

    if (0 == pid) { /* I am the child */
        barrier_fork(pid);

        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof(cbuf);
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_TLS;
        cmsg->cmsg_type = TLS_SET_RECORD_TYPE;
        cmsg->cmsg_len = CMSG_LEN(cmsg_len);
        *((unsigned char *)CMSG_DATA(cmsg)) = record_type;
        msg.msg_controllen = cmsg->cmsg_len;

        msg_iov.iov_base = (void *)test_msg;
        msg_iov.iov_len = sizeof(test_msg);
        msg.msg_iov = &msg_iov;
        msg.msg_iovlen = 1;

        fd = tcp_base::sock_create();
        ASSERT_LE(0, fd);

        rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
        ASSERT_EQ(0, rc);

        rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        log_trace("Established connection: fd=%d to %s\n", fd,
                  sys_addr2str((struct sockaddr *)&server_addr));

        rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
        SKIP_TRUE((0 == rc), "TLS is not supported");

        rc = setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
        EXPECT_EQ(0, rc);

        rc = sendmsg(fd, &msg, 0);
        EXPECT_EQ(sizeof(test_msg), static_cast<size_t>(rc));

        peer_wait(fd);

        close(fd);

        /* This exit is very important, otherwise the fork
         * keeps running and may duplicate other tests.
         */
        exit(testing::Test::HasFailure());
    } else { /* I am the parent */
        int l_fd;
        struct sockaddr peer_addr;
        socklen_t socklen;
        char buf[sizeof(test_msg)];

        l_fd = tcp_base::sock_create();
        ASSERT_LE(0, l_fd);

        rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        rc = listen(l_fd, 5);
        ASSERT_EQ(0, rc);

        barrier_fork(pid);

        socklen = sizeof(peer_addr);
        fd = accept(l_fd, &peer_addr, &socklen);
        ASSERT_LE(0, fd);
        close(l_fd);

        log_trace("Accepted connection: fd=%d from %s\n", fd,
                  sys_addr2str((struct sockaddr *)&peer_addr));

        rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
        SKIP_TRUE((0 == rc), "TLS is not supported");

        rc = setsockopt(fd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info));
        EXPECT_EQ(0, rc);

        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof(cbuf);
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_len = CMSG_LEN(cmsg_len);
        msg.msg_controllen = cmsg->cmsg_len;

        msg_iov.iov_base = (void *)buf;
        msg_iov.iov_len = sizeof(buf);
        msg.msg_iov = &msg_iov;
        msg.msg_iovlen = 1;

        rc = recvmsg(fd, &msg, MSG_WAITALL);
        EXPECT_EQ(sizeof(test_msg), static_cast<size_t>(rc));
        cmsg = CMSG_FIRSTHDR(&msg);
        ASSERT_TRUE(cmsg);
        EXPECT_EQ(cmsg->cmsg_level, SOL_TLS);
        EXPECT_EQ(cmsg->cmsg_type, TLS_GET_RECORD_TYPE);
        EXPECT_EQ(record_type, *((unsigned char *)CMSG_DATA(cmsg)));

        log_trace("Test check: expected: '%s' actual: '%s'\n", test_msg, buf);

        EXPECT_EQ(memcmp(buf, test_msg, rc), 0);

        close(fd);

        ASSERT_EQ(0, wait_fork(pid));
    }
}

/**
 * @test tcp_tls.ti_11_12_gcm_late_rx_key
 * @brief
 *    Install TLS_RX after encrypted data is already queued and verify stream integrity
 *    across TLS record boundaries.
 */
TEST_F(tcp_tls, ti_11_12_gcm_late_rx_key)
{
    const size_t test_sizes[] = {
        1U,
        TLS_PAYLOAD_MAX_LEN - 1U,
        TLS_PAYLOAD_MAX_LEN,
        TLS_PAYLOAD_MAX_LEN + 1U,
        4U * TLS_PAYLOAD_MAX_LEN,
        8U * TLS_PAYLOAD_MAX_LEN,
        16U * TLS_PAYLOAD_MAX_LEN,
    };
    struct tls12_crypto_info_aes_gcm_128 crypto_info;

    memset(&crypto_info, 0, sizeof(crypto_info));
    crypto_info.info.version = TLS_1_2_VERSION;
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

    for (size_t test_size : test_sizes) {
        SCOPED_TRACE(testing::Message() << "test_size=" << test_size);

        std::vector<uint8_t> expected(test_size);
        std::vector<uint8_t> actual(test_size);
        for (size_t i = 0; i < test_size; ++i) {
            expected[i] = static_cast<uint8_t>(i % 251U);
        }

        int pid = fork();
        ASSERT_LE(0, pid);

        if (pid == 0) {
            barrier_fork(pid);

            fd = tcp_base::sock_create();
            ASSERT_LE(0, fd);
            ASSERT_EQ(0, bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr)));
            ASSERT_EQ(0, connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)));
            ASSERT_EQ(0, setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")));
            ASSERT_EQ(0, setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info)));

            EXPECT_EQ(static_cast<ssize_t>(test_size),
                      send_all(fd, expected.data(), expected.size()));

            /* Tell the receiver that all encrypted data has been submitted before TLS_RX. */
            barrier_fork(pid, true);
            peer_wait(fd);
            close(fd);
            exit(testing::Test::HasFailure());
        }

        int receive_buffer = 65536;
        int l_fd = sock_create_fa(m_family, true);
        ASSERT_LE(0, l_fd);
        ASSERT_EQ(0,
                  setsockopt(l_fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer, sizeof(receive_buffer)));
        ASSERT_EQ(0, bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)));
        ASSERT_EQ(0, listen(l_fd, 5));

        barrier_fork(pid);
        fd = accept(l_fd, nullptr, nullptr);
        ASSERT_LE(0, fd);
        close(l_fd);

        /* Wait until ciphertext is pending, then switch the established socket to TLS_RX. */
        barrier_fork(pid, true);
        size_t queued_target = std::min(test_size, static_cast<size_t>(7U * TLS_PAYLOAD_MAX_LEN));
        int queued_bytes = wait_for_queued_bytes(fd, queued_target);
        ASSERT_LE(0, queued_bytes);
        ASSERT_LE(queued_target, static_cast<size_t>(queued_bytes));
        ASSERT_EQ(0, setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")));
        ASSERT_EQ(0, setsockopt(fd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info)));
        ASSERT_EQ(0, set_socket_rcv_timeout(fd, 5));

        ssize_t received = recv_all(fd, actual.data(), actual.size());
        EXPECT_EQ(static_cast<ssize_t>(test_size), received);
        if (received == static_cast<ssize_t>(test_size)) {
            EXPECT_EQ(0, memcmp(expected.data(), actual.data(), test_size));
        }

        close(fd);
        ASSERT_EQ(0, wait_fork(pid));
    }
}

#endif /* HAVE_LINUX_TLS_H */
