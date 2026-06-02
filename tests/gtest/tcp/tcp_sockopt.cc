/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2022-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <fstream>
#include <limits>
#include <stdexcept>
#include <tuple>

#include <sys/socket.h>
#include <sys/types.h> /* See NOTES */
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "googletest/include/gtest/gtest.h"
#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "tcp_base.h"

#include "core/lwip/opt.h"
#include "core/xlio_extra.h"

#define HELLO_STR "hello"

class tcp_sockopt : public tcp_base {};

/**
 * @test tcp_sockopt.ti_1_getsockopt_tcp_info
 * @brief
 *    getsockopt(TCP_INFO).
 * @details
 */
TEST_F(tcp_sockopt, ti_1_getsockopt_tcp_info)
{
    auto test_lambda = [this]() {
        int rc = EOK;
        int pid = fork();

        if (0 == pid) { /* I am the child */
            barrier_fork(pid);

            int fd = tcp_base::sock_create();
            ASSERT_LE(0, fd);

            rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
            ASSERT_EQ(0, rc);

            rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            ASSERT_EQ(0, rc);

            static char buf[] = HELLO_STR;
            ssize_t len = send(fd, (void *)buf, sizeof(buf), 0);
            EXPECT_EQ(static_cast<ssize_t>(sizeof(buf)), len);

            /* Case #0.
             * EFAULT error.
             */
            rc = getsockopt(fd, IPPROTO_TCP, TCP_INFO, nullptr, nullptr);
            ASSERT_EQ(-1, rc);
            ASSERT_EQ(EFAULT, errno);

            /* Case #1.
             * TCP_INFO can return partial structure due to backward compatibility guarantees.
             */
            struct tcp_info ti;
            socklen_t optlen = sizeof(ti) - 1U;
            rc = getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &optlen);
            ASSERT_EQ(0, rc);
            ASSERT_EQ(sizeof(ti) - 1U, optlen);

            /* Case #2.
             * Established connection.
             */
            optlen = sizeof(ti);
            rc = getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &optlen);
            ASSERT_EQ(0, rc);
            ASSERT_EQ(TCP_ESTABLISHED, ti.tcpi_state);
            ASSERT_EQ(0U, ti.tcpi_retransmits);
            ASSERT_EQ(0U, ti.tcpi_total_retrans);
            ASSERT_LT(0U, ti.tcpi_snd_cwnd);
            /* We cannot rely on 1460 MSS value since kernel sends traffic to loopback. */

            peer_wait(fd);

            /* Case #3.
             * Call getsockopt(TCP_INFO) after the parent process closes connection.
             */
            optlen = sizeof(ti);
            rc = getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &optlen);
            ASSERT_EQ(0, rc);
            ASSERT_NE(TCP_ESTABLISHED, ti.tcpi_state);

            close(fd);

            /* This exit is very important, otherwise the fork
             * keeps running and may duplicate other tests.
             */
            exit(testing::Test::HasFailure());
        } else { /* I am the parent */
            struct sockaddr_storage peer_addr;
            socklen_t socklen;
            char buf[sizeof(HELLO_STR) + 1];

            int l_fd = tcp_base::sock_create();
            ASSERT_LE(0, l_fd);

            rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            ASSERT_EQ(0, rc);

            rc = listen(l_fd, 5);
            ASSERT_EQ(0, rc);

            barrier_fork(pid);

            socklen = sizeof(peer_addr);
            int fd = accept(l_fd, (struct sockaddr *)&peer_addr, &socklen);
            ASSERT_LE(0, fd);
            log_trace("Accepted connection: fd=%d from %s\n", fd,
                      sys_addr2str((struct sockaddr *)&peer_addr));

            ssize_t len = recv(fd, buf, sizeof(buf), 0);
            EXPECT_LE(static_cast<ssize_t>(sizeof(HELLO_STR)), len);
            EXPECT_EQ(0, strncmp(HELLO_STR, buf, sizeof(HELLO_STR)));

            /* Case #4.
             * Incoming connection.
             */
            struct tcp_info ti;
            socklen_t optlen = sizeof(ti);
            rc = getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &optlen);
            ASSERT_EQ(0, rc);
            ASSERT_EQ(TCP_ESTABLISHED, ti.tcpi_state);

            /* Case #5.
             * Listen socket.
             */
            optlen = sizeof(ti);
            rc = getsockopt(l_fd, IPPROTO_TCP, TCP_INFO, &ti, &optlen);
            ASSERT_EQ(0, rc);
            ASSERT_EQ(TCP_LISTEN, ti.tcpi_state);

            /* Let the child process to call getsockopt() on established socket. */
            usleep(500);

            close(fd);
            close(l_fd);

            ASSERT_EQ(0, wait_fork(pid));
        }
    };

    test_lambda();
}

/**
 * @test tcp_sockopt.ti_1b_tcp_info_low_rtt_us
 * @brief
 *    TCP_INFO microsecond-precision RTT/RTO smoke after a real round trip.
 * @details
 *    Verifies the microsecond-precision TCP_INFO surface
 *    (`tcpi_rto`, `tcpi_rtt`):
 *      - `tcpi_rto >= 200000 us` under default configuration: a unit/scale
 *        sanity floor. A lower value under the default would mean RTO is being
 *        reported in the wrong unit/scale (raw ticks, ms instead of us, or a
 *        bad divide). NOTE: this does NOT by itself prove the us path is live;
 *        the old tick conversion also cleared 200000 us, so this is a scale
 *        tripwire, not a tick-vs-us granularity check.
 *      - `tcpi_rtt > 0` (sa_us >> 3 == SRTT in us): the ACK estimator
 *        must have produced at least one sample. Zero would mean Karn
 *        invalidated every sample or the RX refresh dropped the ack_now_us
 *        capture - both regressions. Read is guarded by
 *        HAVE_STRUCT_TCP_INFO_TCPI_RTT (older toolchains lack the field).
 *
 *    `tcpi_rttvar` is intentionally not asserted: it can legitimately be
 *    zero on a perfect lab link and no useful regression signature lives
 *    in its upper tail.
 *    `tcpi_rto` is intentionally not upper-bounded in default gtest: loaded
 *    or virtualized runners can legitimately inflate wall-clock RTT/RTTVAR.
 *    Low-latency `<600000` legacy-sentinel checks belong in lab gates or
 *    deterministic estimator tests with controlled timing.
 *
 *    The 1-byte reply path forces the client to recv() before reading
 *    TCP_INFO, which guarantees ACK processing has run end-to-end through
 *    the RX refresh + tcp_receive estimator update sequence under test.
 */
TEST_F(tcp_sockopt, ti_1b_tcp_info_low_rtt_us)
{
    auto test_lambda = [this]() {
        int rc = EOK;
        int pid = fork();

        if (0 == pid) { /* I am the child (client) */
            barrier_fork(pid);

            int fd = tcp_base::sock_create();
            ASSERT_LE(0, fd);

            rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
            ASSERT_EQ(0, rc);

            rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            ASSERT_EQ(0, rc);

            /* Drive several small payloads so the ACK estimator gets
             * exercised across more than the initial SYN-ACK round trip.
             */
            static const char payload[] = HELLO_STR;
            for (int i = 0; i < 4; ++i) {
                ssize_t len = send(fd, (void *)payload, sizeof(payload), 0);
                EXPECT_EQ(static_cast<ssize_t>(sizeof(payload)), len);
            }

            /* Wait for the 1-byte reply. recv() returning is the
             * synchronization edge that guarantees the sender's ACK-side
             * estimator has produced at least one sample before TCP_INFO.
             */
            char reply = 0;
            ssize_t got = recv(fd, &reply, sizeof(reply), 0);
            EXPECT_EQ(static_cast<ssize_t>(sizeof(reply)), got);

            struct tcp_info ti;
            socklen_t optlen = sizeof(ti);
            memset(&ti, 0, sizeof(ti));
            rc = getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &optlen);
            ASSERT_EQ(0, rc);
            /* tcpi_state is intentionally NOT pinned to TCP_ESTABLISHED: under
             * the kernel stack softirq/NAPI may not have advanced the FSM, while
             * under XLIO inline CQ draining may have. Both are healthy.
             *
             * What we DO want to flag is TCP_CLOSE - a peer RST or stack abort
             * mid-flow. The server blocks on a "done" byte (sent below) before
             * it closes, so this read always runs while the connection is still
             * up; seeing TCP_CLOSE here therefore means a genuine unexpected
             * abort, not the benign teardown race. Without the sync, an abortive
             * close under XLIO_TCP_ABORT_ON_CLOSE would RST us into TCP_CLOSE
             * here and fail this assertion.
             */
            ASSERT_NE(TCP_CLOSE, ti.tcpi_state);

            EXPECT_GE(ti.tcpi_rto, 200000U)
                << "tcpi_rto below the common XLIO/Linux test lower bound";

            /* tcpi_rtt / tcpi_rttvar are guarded by configure (AC_CHECK_MEMBERS)
             * because pre-2.4-era kernel headers lacked the fields. Production
             * code guards the WRITES; the test guards the READS so we compile
             * cleanly on minimal toolchains. tcpi_rttvar is intentionally NOT
             * upper-bounded: RTTVAR can legitimately be 0 on a perfectly stable
             * link, and no useful regression signature lives in its upper tail.
             */
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_RTT
            EXPECT_GT(ti.tcpi_rtt, 0U) << "tcpi_rtt missing after real ACK";
#endif

            /* Tell the server we are done reading TCP_INFO so it does not close
             * (and, under XLIO_TCP_ABORT_ON_CLOSE, RST) the connection before
             * the read above. */
            static const char done = 'D';
            ssize_t done_sent = send(fd, &done, sizeof(done), 0);
            EXPECT_EQ(static_cast<ssize_t>(sizeof(done)), done_sent);

            close(fd);
            exit(testing::Test::HasFailure());
        } else { /* I am the parent (server) */
            struct sockaddr_storage peer_addr;
            socklen_t socklen;
            char buf[sizeof(HELLO_STR) * 8];

            int l_fd = tcp_base::sock_create();
            ASSERT_LE(0, l_fd);

            rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            ASSERT_EQ(0, rc);

            rc = listen(l_fd, 5);
            ASSERT_EQ(0, rc);

            barrier_fork(pid);

            socklen = sizeof(peer_addr);
            int fd = accept(l_fd, (struct sockaddr *)&peer_addr, &socklen);
            ASSERT_LE(0, fd);

            /* Drain whatever the client sends; we only need the bytes
             * out of the way so the client can block on the 1-byte reply.
             */
            ssize_t total = 0;
            const ssize_t target = static_cast<ssize_t>(sizeof(HELLO_STR) * 4);
            while (total < target) {
                ssize_t len = recv(fd, buf, sizeof(buf), 0);
                if (len <= 0) {
                    break;
                }
                total += len;
            }

            char reply = 'X';
            ssize_t sent = send(fd, &reply, sizeof(reply), 0);
            EXPECT_EQ(static_cast<ssize_t>(sizeof(reply)), sent);

            /* Wait for the client's "done" byte before closing so the client's
             * TCP_INFO read happens while the connection is still ESTABLISHED.
             * This keeps the test deterministic under XLIO_TCP_ABORT_ON_CLOSE,
             * where close() sends an RST that would otherwise tear the client's
             * socket down to TCP_CLOSE mid-read. */
            char done = 0;
            (void)recv(fd, &done, sizeof(done), 0);

            close(fd);
            close(l_fd);

            ASSERT_EQ(0, wait_fork(pid));
        }
    };

    test_lambda();
}

/**
 * @test tcp_sockopt.ti_1c_tcp_info_handshake_seeded_rto
 * @brief
 *    TCP_INFO tcpi_rto is seeded from the SYN/SYN-ACK handshake RTT before any
 *    data is sent, rather than left at the unseeded 1 s initial.
 * @details
 *    Reads TCP_INFO immediately after connect() returns - i.e. right after the
 *    handshake, before the first data segment. With handshake-RTT seeding the
 *    initial RTO reflects the (tiny, lab) handshake round trip clamped to the
 *    stack's floor. XLIO defaults to 600 ms; Linux commonly uses 200 ms.
 *    Without seeding either stack would retain the unseeded 1 s initial RTO.
 *    The shared assertion `200000 <= tcpi_rto < 1000000` distinguishes a
 *    seeded RTO from that unseeded value without requiring kernel and XLIO
 *    defaults to match.
 *
 *    This is a stack-agnostic property: both XLIO (offloaded) and the Linux
 *    kernel seed the initial RTO from the handshake (RFC 6298 2.2), so the test
 *    passes whether the connection is offloaded or not.
 *
 *    A second read after a data round trip confirms the per-ACK recompute did
 *    not clobber the value back to the 1 s initial before the first data sample
 *    drives the estimator.
 */
TEST_F(tcp_sockopt, ti_1c_tcp_info_handshake_seeded_rto)
{
    auto test_lambda = [this]() {
        int rc = EOK;
        int pid = fork();

        if (0 == pid) { /* I am the child (client) */
            barrier_fork(pid);

            int fd = tcp_base::sock_create();
            ASSERT_LE(0, fd);

            /* SO_REUSEADDR so this test can run back-to-back with the other
             * connect tests on the same fixed port without tripping TIME_WAIT
             * at bind(). */
            int reuse = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

            rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
            ASSERT_EQ(0, rc);

            rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            ASSERT_EQ(0, rc);

            /* Read TCP_INFO BEFORE sending any data: rto_us must already be
             * seeded from the handshake RTT, not the unseeded 1 s initial. */
            struct tcp_info ti;
            socklen_t optlen = sizeof(ti);
            memset(&ti, 0, sizeof(ti));
            rc = getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &optlen);
            ASSERT_EQ(0, rc);
            ASSERT_NE(TCP_CLOSE, ti.tcpi_state);

            EXPECT_GE(ti.tcpi_rto, 200000U)
                << "tcpi_rto below the common XLIO/Linux test lower bound";
            EXPECT_LT(ti.tcpi_rto, 1000000U)
                << "tcpi_rto looks like the unseeded 1 s initial; handshake seeding missing";

            /* One data round trip, then re-read as a sanity check: by now the
             * first data sample has seeded the estimator (sa_us != 0), so this
             * verifies steady-state RTO is sane (at least the shared test lower
             * bound, but not the 1 s initial) rather than the sa_us == 0
             * clobber-gate itself - the pre-data read above is the assertion
             * that exercises the seed directly. */
            static const char payload[] = HELLO_STR;
            ssize_t len = send(fd, (void *)payload, sizeof(payload), 0);
            EXPECT_EQ(static_cast<ssize_t>(sizeof(payload)), len);

            char reply = 0;
            ssize_t got = recv(fd, &reply, sizeof(reply), 0);
            EXPECT_EQ(static_cast<ssize_t>(sizeof(reply)), got);

            memset(&ti, 0, sizeof(ti));
            optlen = sizeof(ti);
            rc = getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &optlen);
            ASSERT_EQ(0, rc);
            ASSERT_NE(TCP_CLOSE, ti.tcpi_state);
            EXPECT_GE(ti.tcpi_rto, 200000U);
            EXPECT_LT(ti.tcpi_rto, 1000000U)
                << "steady-state tcpi_rto looks like the 1 s initial after a round trip";

            /* Tell the server we are done reading TCP_INFO. The server blocks on
             * this byte before it closes, so the steady-state read above always
             * runs while the connection is still ESTABLISHED. Without this the
             * peer's teardown races the read: a graceful FIN leaves us in
             * TCP_CLOSE_WAIT (benign), but an abortive close
             * (XLIO_TCP_ABORT_ON_CLOSE) RSTs us into TCP_CLOSE and trips the
             * ASSERT_NE(TCP_CLOSE) above. */
            static const char done = 'D';
            ssize_t done_sent = send(fd, &done, sizeof(done), 0);
            EXPECT_EQ(static_cast<ssize_t>(sizeof(done)), done_sent);

            close(fd);
            exit(testing::Test::HasFailure());
        } else { /* I am the parent (server) */
            struct sockaddr_storage peer_addr;
            socklen_t socklen;
            char buf[sizeof(HELLO_STR) * 8];

            int l_fd = tcp_base::sock_create();
            ASSERT_LE(0, l_fd);

            /* SO_REUSEADDR so the listen bind succeeds even if a prior connect
             * test left this port's 4-tuple in TIME_WAIT. */
            int reuse = 1;
            setsockopt(l_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

            rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            ASSERT_EQ(0, rc);

            rc = listen(l_fd, 5);
            ASSERT_EQ(0, rc);

            barrier_fork(pid);

            socklen = sizeof(peer_addr);
            int fd = accept(l_fd, (struct sockaddr *)&peer_addr, &socklen);
            ASSERT_LE(0, fd);

            ssize_t total = 0;
            const ssize_t target = static_cast<ssize_t>(sizeof(HELLO_STR));
            while (total < target) {
                ssize_t len = recv(fd, buf, sizeof(buf), 0);
                if (len <= 0) {
                    break;
                }
                total += len;
            }

            char reply = 'X';
            ssize_t sent = send(fd, &reply, sizeof(reply), 0);
            EXPECT_EQ(static_cast<ssize_t>(sizeof(reply)), sent);

            /* Wait for the client's "done" byte before closing so the client's
             * steady-state TCP_INFO read happens while the connection is still
             * ESTABLISHED. This keeps the test deterministic under
             * XLIO_TCP_ABORT_ON_CLOSE, where close() sends an RST that would
             * otherwise tear the client's socket down to TCP_CLOSE mid-read. */
            char done = 0;
            (void)recv(fd, &done, sizeof(done), 0);

            close(fd);
            close(l_fd);

            ASSERT_EQ(0, wait_fork(pid));
        }
    };

    test_lambda();
}

/**
 * @test tcp_sockopt.ti_2_tcp_congestion
 * @brief
 *    TCP_CONGESTION option to change and check congestion control mechanism.
 * @details
 */
TEST_F(tcp_sockopt, ti_2_tcp_congestion)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_LE(0, fd);

    char buf[16];
    socklen_t len = 0;
    int rc = getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, buf, &len);
    EXPECT_EQ(0, rc);
    EXPECT_EQ(0U, len);

#if 0
    // XLIO isn't complient with kernel in this case
    rc = getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, NULL, &len);
    EXPECT_EQ(0, rc);
    EXPECT_EQ(0U, len);
#endif

    rc = getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, buf, NULL);
    EXPECT_EQ(-1, rc);
    EXPECT_EQ(EFAULT, errno);

    rc = setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, buf, 0);
    EXPECT_EQ(-1, rc);
    EXPECT_EQ(EINVAL, errno);

#if 0
    // XLIO isn't complient with kernel in this case
    rc = setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, NULL, 0);
    EXPECT_EQ(-1, rc);
    EXPECT_EQ(EINVAL, errno);
#endif

    rc = setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, NULL, 5);
    EXPECT_EQ(-1, rc);
    EXPECT_EQ(EFAULT, errno);

    // Assume reno is supported everywhere
    snprintf(buf, sizeof(buf), "reno");
    // Note, len doesn't include terminating '\0'
    len = strlen(buf);
    rc = setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, buf, len);
    EXPECT_EQ(0, rc);
    if (rc == 0) {
        len = sizeof(buf);
        rc = getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, buf, &len);
        EXPECT_EQ(0, rc);
        EXPECT_LT(0U, len);
    }
    if (rc == 0) {
        std::string cc_name(buf, strnlen(buf, len));
        EXPECT_EQ(std::string("reno"), cc_name);
    }
}

/**
 * @test tcp_sockopt.ti_3_ext_vlan_tag
 * @brief
 *    setsockopt(SO_XLIO_EXT_VLAN_TAG) rejects values that don't fit in the
 *    12-bit VLAN ID part of the VLAN tag.
 * @details
 */
TEST_F(tcp_sockopt, ti_3_ext_vlan_tag)
{
    /* SO_XLIO_EXT_VLAN_TAG is XLIO specific and not recognized by the kernel. */
    SKIP_TRUE(xlio_get_api(), "This test should be launched under libxlio.so");

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_LE(0, fd);

    int val = 4095;
    int rc = setsockopt(fd, SOL_SOCKET, SO_XLIO_EXT_VLAN_TAG, &val, sizeof(val));
    EXPECT_EQ(0, rc);

    val = 4096;
    rc = setsockopt(fd, SOL_SOCKET, SO_XLIO_EXT_VLAN_TAG, &val, sizeof(val));
    EXPECT_EQ(-1, rc);
    EXPECT_EQ(EINVAL, errno);

    val = -1;
    rc = setsockopt(fd, SOL_SOCKET, SO_XLIO_EXT_VLAN_TAG, &val, sizeof(val));
    EXPECT_EQ(-1, rc);
    EXPECT_EQ(EINVAL, errno);

    short short_val = 1;
    rc = setsockopt(fd, SOL_SOCKET, SO_XLIO_EXT_VLAN_TAG, &short_val, sizeof(short_val));
    EXPECT_EQ(-1, rc);
    EXPECT_EQ(EINVAL, errno);

    close(fd);
}

/**
 * @test tcp_sockopt.ti_4_ext_vlan_tag_connect_fail
 * @brief
 *    SO_XLIO_EXT_VLAN_TAG causes connect() to fail with ETIMEDOUT when the
 *    tagged SYN packets are not received by the server.
 * @details
 */
TEST_F(tcp_sockopt, ti_4_ext_vlan_tag_connect_fail)
{
    SKIP_TRUE(xlio_get_api(), "This test should be launched under libxlio.so");

    int pid = fork();
    ASSERT_GE(pid, 0);

    if (pid == 0) { /* child - client */
        barrier_fork(pid);

        int fd = tcp_base::sock_create();
        ASSERT_LE(0, fd);

        int vlan_tag = 1;
        int rc = setsockopt(fd, SOL_SOCKET, SO_XLIO_EXT_VLAN_TAG, &vlan_tag, sizeof(vlan_tag));
        ASSERT_EQ(0, rc);

        unsigned int user_timeout_ms = 200U;
        rc = setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_ms,
                        sizeof(user_timeout_ms));
        ASSERT_EQ(0, rc);

        struct timespec ts_start, ts_end;
        clock_gettime(CLOCK_MONOTONIC, &ts_start);

        rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        EXPECT_EQ(-1, rc);
        EXPECT_EQ(ETIMEDOUT, errno);

        clock_gettime(CLOCK_MONOTONIC, &ts_end);
        long elapsed_ms = (ts_end.tv_sec - ts_start.tv_sec) * 1000L +
            (ts_end.tv_nsec - ts_start.tv_nsec) / 1000000L;
        EXPECT_GE(elapsed_ms, 200L);
        // TCP_USER_TIMEOUT is only evaluated at retransmission ticks. With the RFC 6298
        // 1s initial RTO the abort lands at the first tick (~1s), not at 200ms, so the
        // upper bound must sit above the initial RTO yet below the next retransmit at
        // initial + fallback RTO (~4s), proving the timeout fired early instead of
        // running the full retry chain.
        EXPECT_LT(elapsed_ms, 3000L);

        close(fd);
        exit(testing::Test::HasFailure());
    } else { /* parent - server */
        int l_fd = tcp_base::sock_create();
        ASSERT_LE(0, l_fd);

        int rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        rc = listen(l_fd, 5);
        ASSERT_EQ(0, rc);

        barrier_fork(pid);

        int wait_rc = wait_fork(pid);
        close(l_fd);
        ASSERT_EQ(0, wait_rc);
    }
}

/**
 * @test tcp_sockopt.ti_5_ext_vlan_tag_disable
 * @brief
 *    Setting SO_XLIO_EXT_VLAN_TAG to 0 after a non-zero value disables VLAN
 *    tagging, and a subsequent connect() succeeds normally.
 * @details
 */
TEST_F(tcp_sockopt, ti_5_ext_vlan_tag_disable)
{
    SKIP_TRUE(xlio_get_api(), "This test should be launched under libxlio.so");

    int pid = fork();
    ASSERT_GE(pid, 0);

    if (pid == 0) { /* child - client */
        barrier_fork(pid);

        int fd = tcp_base::sock_create();
        ASSERT_LE(0, fd);

        int vlan_tag = 1;
        int rc = setsockopt(fd, SOL_SOCKET, SO_XLIO_EXT_VLAN_TAG, &vlan_tag, sizeof(vlan_tag));
        ASSERT_EQ(0, rc);

        vlan_tag = 0;
        rc = setsockopt(fd, SOL_SOCKET, SO_XLIO_EXT_VLAN_TAG, &vlan_tag, sizeof(vlan_tag));
        ASSERT_EQ(0, rc);

        unsigned int user_timeout_ms = 5000U;
        rc = setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_ms,
                        sizeof(user_timeout_ms));
        ASSERT_EQ(0, rc);

        rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        EXPECT_EQ(0, rc);

        close(fd);
        exit(testing::Test::HasFailure());
    } else { /* parent - server */
        int l_fd = tcp_base::sock_create();
        ASSERT_LE(0, l_fd);

        int rc = bind(l_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc);

        rc = listen(l_fd, 5);
        ASSERT_EQ(0, rc);

        barrier_fork(pid);

        struct sockaddr_storage peer_addr;
        socklen_t socklen = sizeof(peer_addr);
        int fd = accept(l_fd, (struct sockaddr *)&peer_addr, &socklen);
        ASSERT_LE(0, fd);

        close(fd);
        close(l_fd);
        ASSERT_EQ(0, wait_fork(pid));
    }
}

class tcp_set_get_sockopt : public ::testing::Test {
protected:
    void SetUp() override
    {
        m_ipv4_tcp_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        m_ipv6_tcp_socket_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_IP);
        EXPECT_GE(m_ipv4_tcp_socket_fd, 0);
        EXPECT_GE(m_ipv6_tcp_socket_fd, 0);
    }

    void TearDown() override
    {
        close(m_ipv4_tcp_socket_fd);
        close(m_ipv6_tcp_socket_fd);
    }
    int m_ipv4_tcp_socket_fd = -1;
    int m_ipv6_tcp_socket_fd = -1;
};

class tcp_set_get_sockopt_on_udp_socket : public ::testing::Test {
protected:
    void SetUp() override
    {
        m_ipv4_udp_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        m_ipv6_udp_socket_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);
        EXPECT_GE(m_ipv4_udp_socket_fd, 0);
        EXPECT_GE(m_ipv6_udp_socket_fd, 0);
    }

    void TearDown() override
    {
        close(m_ipv4_udp_socket_fd);
        close(m_ipv6_udp_socket_fd);
    }
    int m_ipv4_udp_socket_fd = -1;
    int m_ipv6_udp_socket_fd = -1;
};

TEST_F(tcp_set_get_sockopt_on_udp_socket, set_and_get_tcp_ipv4_user_timeout_fails)
{
    unsigned int user_timeout_ms = 5000U;
    int result = setsockopt(m_ipv4_udp_socket_fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_ms,
                            sizeof(user_timeout_ms));
    EXPECT_EQ(result, -1) << "IPPROTO_TCP is unsupported for UDP sockets";

    socklen_t optlen;
    result =
        getsockopt(m_ipv4_udp_socket_fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_ms, &optlen);
    EXPECT_EQ(result, -1) << "IPPROTO_TCP is unsupported for UDP sockets";
}

TEST_F(tcp_set_get_sockopt_on_udp_socket, set_and_get_tcp_ipv6_user_timeout_fails)
{
    unsigned int user_timeout_ms = 5000U;
    int result = setsockopt(m_ipv6_udp_socket_fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_ms,
                            sizeof(user_timeout_ms));
    EXPECT_EQ(result, -1) << "IPPROTO_TCP is unsupported for UDP sockets";

    socklen_t optlen;
    result =
        getsockopt(m_ipv6_udp_socket_fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_ms, &optlen);
    EXPECT_EQ(result, -1) << "IPPROTO_TCP is unsupported for UDP sockets";
}

TEST_F(tcp_set_get_sockopt, set_and_get_tcp_ipv4_user_timeout)
{
    const unsigned int user_timeout_ms = 5000U;
    int result = setsockopt(m_ipv4_tcp_socket_fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_ms,
                            sizeof(user_timeout_ms));
    EXPECT_EQ(result, 0) << "IPPROTO_TCP is unsupported for UDP sockets";

    socklen_t optlen = -1;
    unsigned int output_user_timeout_ms = -1;

    result = getsockopt(m_ipv4_tcp_socket_fd, IPPROTO_TCP, TCP_USER_TIMEOUT,
                        &output_user_timeout_ms, &optlen);
    EXPECT_EQ(result, 0) << "getsockopt failed for TCP_USER_TIMEOUT";
    EXPECT_EQ(optlen, sizeof(output_user_timeout_ms)) << "Unexpected parameter size";
    EXPECT_EQ(output_user_timeout_ms, user_timeout_ms) << "Unexpected timeout value";
}

TEST_F(tcp_set_get_sockopt, set_and_get_tcp_ipv6_user_timeout)
{
    const unsigned int user_timeout_ms = 5000U;
    int result = setsockopt(m_ipv6_tcp_socket_fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_ms,
                            sizeof(user_timeout_ms));
    EXPECT_EQ(result, 0) << "IPPROTO_TCP is unsupported for UDP sockets";

    socklen_t optlen = -1;
    unsigned int output_user_timeout_ms = -1;

    result = getsockopt(m_ipv6_tcp_socket_fd, IPPROTO_TCP, TCP_USER_TIMEOUT,
                        &output_user_timeout_ms, &optlen);
    EXPECT_EQ(result, 0) << "getsockopt failed for TCP_USER_TIMEOUT";
    EXPECT_EQ(optlen, sizeof(output_user_timeout_ms)) << "Unexpected parameter size";
    EXPECT_EQ(output_user_timeout_ms, user_timeout_ms) << "Unexpected timeout value";
}

struct reusable_cleanable_test_socket {
    int m_fd;
    reusable_cleanable_test_socket(int domain, int type, int protocol)
    {
        m_fd = socket(domain, type, protocol);
        EXPECT_GE(m_fd, 0) << "Unable to open the socket";
        int reuse = 1;
        auto result = setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        EXPECT_EQ(result, 0) << "setsockopt failed to set reuse addr";

        struct timeval tv;
        tv.tv_sec = 20;
        tv.tv_usec = 0;
        setsockopt(m_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    explicit reusable_cleanable_test_socket(int fd)
        : m_fd {fd}
    {
        EXPECT_GE(m_fd, 0) << "Unable to open the socket";
    };
    ~reusable_cleanable_test_socket() { close(m_fd); }

    operator int() const { return m_fd; }
};

struct ipc {
    enum FifoDirection : size_t { ReadSide, WriteSide };
    int m_pipe[2];
    ipc()
        : m_pipe {-1, -1}
    {
    }

    ~ipc() { reset(); }
    void create()
    {
        if (pipe(m_pipe) != 0) {
            throw std::runtime_error("Pipe not created");
        }
    }
    void reset()
    {
        if (m_pipe[ReadSide] != -1) {
            close(m_pipe[ReadSide]);
            m_pipe[ReadSide] = -1;
        }
        if (m_pipe[WriteSide] != -1) {
            close(m_pipe[WriteSide]);
            m_pipe[WriteSide] = -1;
        }
    }
    bool wait_peer()
    {
        if (m_pipe[ReadSide] == -1) {
            return false;
        }

        if (m_pipe[WriteSide] != -1) {
            if (close(m_pipe[WriteSide]) != 0) {
                return false;
            }
            m_pipe[WriteSide] = -1;
        }

        char buffer[16];
        auto result = read(m_pipe[ReadSide], buffer, 1) == 1;
        return result;
    }

    bool signal_to_peer()
    {
        if (m_pipe[WriteSide] == -1) {
            return false;
        }

        if (m_pipe[ReadSide] != -1) {
            if (close(m_pipe[ReadSide]) != 0) {
                return false;
            }
            m_pipe[ReadSide] = -1;
        }

        return write(m_pipe[WriteSide], "X", 1) == 1;
    }
};

using sockopt_parameters = std::tuple<int, int, int, int>;
using tcp_sockopt_positive = testing::TestWithParam<sockopt_parameters>;
/*
 * @test tcp_sockopt_positive.set_and_get_value
 * @brief
 *    This is a parameterized test requiring sockopt_parameters. The parameters in the
 *    sockopt_parameters are the socket domain, setsockopt/getsockopt level, optname,
 *    and value.
 *    The test sets the value and checks the value with the setsockopt/getsockopt syscalls.
 * @details
 */
TEST_P(tcp_sockopt_positive, set_and_get_value)
{
    int socket_domain, level, optname, value;
    std::tie(socket_domain, level, optname, value) = GetParam();

    auto fd = reusable_cleanable_test_socket(socket_domain, static_cast<int>(SOCK_STREAM), 0);
    EXPECT_GE(fd, 0) << "socket syscall failed";
    auto result = setsockopt(fd, level, optname, &value, sizeof(value));
    EXPECT_EQ(result, 0) << "setsockopt failed to set the value";

    int actual_value = -1;
    socklen_t actual_len = sizeof(actual_value);
    result = getsockopt(fd, level, optname, &actual_value, &actual_len);
    EXPECT_EQ(result, 0) << "getsockopt failed to get the value";
    EXPECT_EQ(actual_len, sizeof(actual_value)) << "Got unexpected size of agument";
    ASSERT_EQ(actual_value, value);
}

/* The valid ranges are dictated by the Linux Kernel and not the TCP RFC 9293
 * There may be multiple instantiations of the tcp_sockopt_positive class and
 * it's test cases.
 */
INSTANTIATE_TEST_CASE_P(
    keep_alive, tcp_sockopt_positive,
    testing::Values(
#if LWIP_TCP_KEEPALIVE
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPINTVL, 1),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPINTVL, std::numeric_limits<int16_t>::max()),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPCNT, 1),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPCNT, std::numeric_limits<int8_t>::max()),
#endif
        std::make_tuple(AF_INET, SOL_SOCKET, SO_KEEPALIVE, 1),
        std::make_tuple(AF_INET, SOL_SOCKET, SO_KEEPALIVE, 0),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPIDLE, 1),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPIDLE, std::numeric_limits<int16_t>::max()),
#if LWIP_TCP_KEEPALIVE
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPINTVL, 1),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPINTVL, std::numeric_limits<int16_t>::max()),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPCNT, 1),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPCNT, std::numeric_limits<int8_t>::max()),
#endif
        std::make_tuple(AF_INET6, SOL_SOCKET, SO_KEEPALIVE, 1),
        std::make_tuple(AF_INET6, SOL_SOCKET, SO_KEEPALIVE, 0),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPIDLE, 1),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPIDLE, std::numeric_limits<int16_t>::max())));

using tcp_setsockopt_negative = testing::TestWithParam<sockopt_parameters>;
/*
 * @test tcp_setsockopt_negative.set_invalid_value
 * @brief
 *    This is a parameterized test requiring sockopt_parameters. The parameters in the
 *    sockopt_parameters are the socket domain, setsockopt/getsockopt level, optname,
 *    and value.
 *    The test attempts setting an invalid value via setsockopt syscall.
 * @details
 */
TEST_P(tcp_setsockopt_negative, set_invalid_value)
{
    int socket_domain, level, optname, value;
    std::tie(socket_domain, level, optname, value) = GetParam();

    auto fd = reusable_cleanable_test_socket(socket_domain, SOCK_STREAM, 0);
    EXPECT_GE(fd, 0) << "socket syscall failed to setup a socket";

    auto result = setsockopt(fd, level, optname, &value, sizeof(value));
    EXPECT_NE(result, 0) << "setsockopt didn't fail to set the value";
}

/* The valid ranges are dictated by the Linux Kernel and not the TCP RFC 9293
 * There may be multiple instantiations of the tcp_setsockopt_negative class and
 * it's test cases.
 */
INSTANTIATE_TEST_CASE_P(
    keep_alive, tcp_setsockopt_negative,
    testing::Values(
#if LWIP_TCP_KEEPALIVE
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPINTVL, -1),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPINTVL, 0),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPINTVL,
                        std::numeric_limits<int16_t>::max() + 1),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPCNT, -1),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPCNT, 0),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPCNT, std::numeric_limits<int8_t>::max() + 1),
#endif
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPIDLE, -1),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPIDLE,
                        std::numeric_limits<int16_t>::max() + 1),
#if LWIP_TCP_KEEPALIVE
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPINTVL, -1),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPINTVL, 0),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPINTVL,
                        std::numeric_limits<int16_t>::max() + 1),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPCNT, -1),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPCNT, 0),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPCNT, std::numeric_limits<int8_t>::max() + 1),
#endif
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPIDLE, -1),
        std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPIDLE,
                        std::numeric_limits<int16_t>::max() + 1)));

using getscokopt_params = std::tuple<int, int, int, const char *>;
using tcp_sockopt_default = testing::TestWithParam<getscokopt_params>;
/*
 * @test tcp_sockopt_default.matches_the_value_in_the_file
 * @brief
 *    This is a parameterized test requiring sockopt_parameters. The parameters in the
 *    sockopt_parameters are the socket domain, setsockopt/getsockopt level, optname,
 *    and file path containing the default value.
 *    The test verifies that the default value of a newly creates socket match file.
 * @details
 */
TEST_P(tcp_sockopt_default, matches_the_value_in_the_file)
{
    int socket_domain, level, optname;
    const char *file_path;
    std::tie(socket_domain, level, optname, file_path) = GetParam();

    auto fd = reusable_cleanable_test_socket(socket_domain, SOCK_STREAM, 0);
    EXPECT_GE(fd, 0) << "socket syscall failed to setup a socket";

    /* Get the value via getsockopt */
    int getsockopt_value = -1;
    socklen_t actual_len = sizeof(getsockopt_value);
    auto result = getsockopt(fd, level, optname, &getsockopt_value, &actual_len);
    EXPECT_EQ(result, 0) << "getsockopt failed";
    EXPECT_EQ(actual_len, sizeof(getsockopt_value)) << "Got unexpected size of agument";

    /* Get the value from the file */
    int file_value = -1;
    EXPECT_TRUE(bool(std::ifstream {file_path} >> file_value)) << "Failed reading the file";

    ASSERT_EQ(getsockopt_value, file_value) << "The values in the file and the getsockopt differ";
    close(fd);
}

INSTANTIATE_TEST_CASE_P(keep_alive, tcp_sockopt_default,
                        testing::Values(
#if LWIP_TCP_KEEPALIVE
                            std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPINTVL,
                                            "/proc/sys/net/ipv4/tcp_keepalive_intvl"),
                            std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPCNT,
                                            "/proc/sys/net/ipv4/tcp_keepalive_probes"),
                            std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPINTVL,
                                            "/proc/sys/net/ipv4/tcp_keepalive_intvl"),
                            std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPCNT,
                                            "/proc/sys/net/ipv4/tcp_keepalive_probes"),
#endif
                            std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPIDLE,
                                            "/proc/sys/net/ipv4/tcp_keepalive_time"),
                            std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPIDLE,
                                            "/proc/sys/net/ipv4/tcp_keepalive_time")));

using setsockopt_param = std::tuple<int, int, int>;
class tcp_with_fifo : public testing::TestWithParam<setsockopt_param> {
protected:
    ipc m_ipc_server_to_client {};

    void SetUp() override { m_ipc_server_to_client.create(); }

    void TearDown() override { m_ipc_server_to_client.reset(); }
};

/*
 * @test tcp_with_fifo.set_listen_get_accept_socket
 * @brief
 *    This is a parameterized test requiring sockopt_parameters. The parameters in the
 *    sockopt_parameters are the socket domain, setsockopt level, optname, and value.
 *    The test verifies that the set value is inherited by the accepted socket.
 * @details
 */
TEST_P(tcp_with_fifo, accepted_socket_inherits_the_setsockopt_param)
{
    SKIP_TRUE(!getenv("XLIO_TCP_CTL_THREAD"), "Skip non default XLIO_TCP_CTL_THREAD");

    int level, optname, value;
    std::tie(level, optname, value) = GetParam();
    pid_t pid = fork();

    if (pid > 0) { // Parent process (the "server" process)

        auto family = ((struct sockaddr *)&gtest_conf.server_addr)->sa_family;
        auto listen_fd = reusable_cleanable_test_socket(family, SOCK_STREAM, 0);
        EXPECT_GE(listen_fd, 0) << "socket syscall failed to setup a socket";

        EXPECT_EQ(bind(listen_fd, (struct sockaddr *)&gtest_conf.server_addr,
                       sizeof(gtest_conf.server_addr)),
                  0);
        EXPECT_EQ(listen(listen_fd, 5), 0);

        auto result = setsockopt(listen_fd, level, optname, &value, sizeof(value));
        EXPECT_EQ(result, 0) << "setsockopt failed to set the value";
        if (result < 0) {
            EXPECT_EQ(errno, 0) << "setsockopt failed with errno";
        }

        m_ipc_server_to_client.signal_to_peer();

        reusable_cleanable_test_socket accepted_fd {accept(listen_fd, nullptr, 0)};
        EXPECT_GE(accepted_fd, 0) << "Invalid accepted_fd";

        int actual_value = -1;
        socklen_t actual_len = sizeof(actual_value);
        result = getsockopt(accepted_fd, level, optname, &actual_value, &actual_len);
        m_ipc_server_to_client.signal_to_peer();

        int status;
        EXPECT_EQ(pid, waitpid(pid, &status, 0));
        EXPECT_TRUE(WIFEXITED(status));
        EXPECT_EQ(result, 0) << "getsockopt failed to get the value";
        EXPECT_EQ(actual_len, sizeof(actual_value)) << "Got unexpected size of agument";

        ASSERT_EQ(actual_value, value);
    } else if (pid == 0) { // Child process (the "client" process)
        auto family = ((struct sockaddr *)&gtest_conf.server_addr)->sa_family;
        auto client_fd = reusable_cleanable_test_socket(family, SOCK_STREAM, 0);
        EXPECT_GE(client_fd, 0) << "socket syscall failed to setup a socket";
        EXPECT_EQ(bind(client_fd, (struct sockaddr *)&gtest_conf.client_addr,
                       sizeof(gtest_conf.client_addr)),
                  0);
        m_ipc_server_to_client.wait_peer();
        auto result = connect(client_fd, (struct sockaddr *)&gtest_conf.server_addr,
                              sizeof(gtest_conf.server_addr));
        EXPECT_EQ(result, 0);
        m_ipc_server_to_client.wait_peer();

        // This exit stops the process from inerfering with other tests.
        exit(testing::Test::HasFailure());
    } else {
        FAIL() << "Fork failed";
    }
}

INSTANTIATE_TEST_CASE_P(keep_alive, tcp_with_fifo,
                        testing::Values(
#if LWIP_TCP_KEEPALIVE
                            std::make_tuple(static_cast<int>(IPPROTO_TCP), TCP_KEEPINTVL, 12345),
                            std::make_tuple(static_cast<int>(IPPROTO_TCP), TCP_KEEPCNT, 123),
#endif
                            std::make_tuple(SOL_SOCKET, SO_KEEPALIVE, 0),
                            std::make_tuple(SOL_SOCKET, SO_KEEPALIVE, 1),
                            std::make_tuple(static_cast<int>(IPPROTO_TCP), TCP_KEEPIDLE, 1234)));
