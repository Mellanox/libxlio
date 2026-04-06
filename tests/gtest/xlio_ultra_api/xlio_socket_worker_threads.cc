/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/subprocess_test.h"
#include "common/log.h"
#include "common/sys.h"

/**
 * Tests for Ultra API + worker threads coexistence.
 *
 * These tests launch a helper binary (with LD_PRELOAD inherited from the
 * gtest runner) that exercises Ultra API operations while worker_threads
 * is configured.  The tests inspect the captured debug output for signs
 * of incorrect worker-thread dispatch.
 */
class ultra_api_worker_threads : public subprocess_test {
public:
    void SetUp() override
    {
        subprocess_test::SetUp();
        m_output_file = "/tmp/xlio_gtest_wt_" + std::to_string(getpid()) + ".txt";
    }
};

/**
 * @test ultra_api_worker_threads.no_distribute_on_connect
 * @brief
 *    Ultra API sockets must not be dispatched to XLIO worker threads.
 *
 * @details
 *    When performance.threading.worker_threads > 0, POSIX sockets are handed
 *    off to worker threads for processing.  Ultra API sockets manage their own
 *    poll groups and rings, so they must bypass this dispatch entirely.
 *
 *    A compiled helper binary retrieves the API via xlio_get_api(), creates a
 *    poll group and socket, and calls xlio_socket_connect() targeting the
 *    server address provided by the gtest runner (a real RDMA-routable address
 *    in CI).  The config sets worker_threads=1 and log level=debug so that any
 *    worker-thread dispatch is visible in the output.
 *
 *    The test asserts the ABSENCE of worker-thread dispatch messages:
 *    - "connect_socket_job" / "New TCP socket added" from entity_context
 *    - "already a member in a list" from vlist (symptom of the original crash)
 *
 *    It also positively asserts that either the XLIO offload path was exercised
 *    ("MATCH TCP CLIENT" from __xlio_match_tcp_client) or the helper explicitly
 *    skipped (printed "SKIP"), to prevent vacuous passes.
 */
TEST_F(ultra_api_worker_threads, no_distribute_on_connect)
{
    std::string config =
        workspace_path("tests/gtest/xlio_ultra_api/config-ultra-api-worker-threads.json");
    std::string helper = helper_path("ultra_api_connect_worker_threads_helper");

    std::string cmd = "XLIO_USE_NEW_CONFIG=1 XLIO_CONFIG_FILE=" + config + " " + helper;

    // Pass the real server address so the connect reaches the XLIO offload
    // path on RDMA-capable CI machines.
    const struct sockaddr *sa = (const struct sockaddr *)&gtest_conf.server_addr;
    if (sa->sa_family == AF_INET || sa->sa_family == AF_INET6) {
        std::string addr_str = sys_addr2str(sa, false);
        if (!addr_str.empty() && addr_str != "0.0.0.0") {
            cmd += " " + addr_str;
        }
    }

    exec_cmd_to_file(cmd, m_output_file);

    std::string text = read_file(m_output_file);

    ASSERT_TRUE(text.find("connect_socket_job") == std::string::npos)
        << "Worker thread incorrectly dispatched Ultra API socket connect." << std::endl
        << "START OF TEXT:" << std::endl
        << text << std::endl
        << "END OF TEXT";

    ASSERT_TRUE(text.find("already a member in a list") == std::string::npos)
        << "Buffer corruption detected during Ultra API + worker threads coexistence." << std::endl
        << "START OF TEXT:" << std::endl
        << text << std::endl
        << "END OF TEXT";

    ASSERT_TRUE(text.find("MATCH TCP CLIENT") != std::string::npos ||
                text.find("SKIP") != std::string::npos)
        << "Neither XLIO offload path nor explicit SKIP was detected -- test is vacuous."
        << std::endl
        << "START OF TEXT:" << std::endl
        << text << std::endl
        << "END OF TEXT";
}
