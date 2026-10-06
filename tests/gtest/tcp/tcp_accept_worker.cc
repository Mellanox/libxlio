/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/subprocess_test.h"
#include "common/log.h"
#include "common/sys.h"
#include <cstring>

class tcp_accept_worker : public subprocess_test {
protected:
    void run_accept_test(const char *mode)
    {
        const sockaddr *client = &gtest_conf.client_addr.addr;
        const sockaddr *server = &gtest_conf.server_addr.addr;
        const std::string client_ip = sys_addr2str(client, false);
        const std::string server_ip = sys_addr2str(server, false);
        if (!std::getenv("LD_PRELOAD") || client_ip == "0.0.0.0" || server_ip == "0.0.0.0" ||
            client_ip == "::" || server_ip == "::" || client_ip.compare(0, 4, "127.") == 0 ||
            server_ip.compare(0, 4, "127.") == 0 || client_ip == "::1" || server_ip == "::1") {
            GTEST_SKIP() << "Requires XLIO preload and two offloadable addresses (--addr)";
        }

        // RM 5324154: accept harvests RSS children under the parent lock, while
        // handshake completion used to wake the parent under the child lock.
        // Burst connections must make progress through that lock inversion.
        // GNU timeout bounds even spinlock deadlocks and kills the helper group.
        const std::string command =
            "env -u XLIO_INLINE_CONFIG XLIO_USE_NEW_CONFIG=1 XLIO_CONFIG_FILE='" +
            workspace_path("tests/gtest/tcp/config-accept-worker.json") +
            "' timeout --kill-after=5s 30s '" + helper_path("tcp_accept_worker_helper") + "' '" +
            client_ip + "' '" + server_ip + "' " + mode;
        const int status = std::system((command + " > '" + m_output_file + "' 2>&1").c_str());
        const std::string output = read_file(m_output_file);
        const std::string tail = output.substr(output.size() > 4096 ? output.size() - 4096 : 0);
        ASSERT_TRUE(status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0)
            << "RSS accept failed or exceeded its 30-second deadline; wait status=" << status
            << '\n'
            << tail;
        const char *completion = std::strcmp(mode, "reconnect") == 0
            ? "completed 128 same-tuple connections"
            : "completed 512 connections";
        ASSERT_NE(std::string::npos, output.find(completion)) << tail;
    }
};

TEST_F(tcp_accept_worker, blocking_accept_makes_progress)
{
    run_accept_test("blocking");
}

TEST_F(tcp_accept_worker, nonblocking_accept_makes_progress)
{
    run_accept_test("nonblocking");
}

TEST_F(tcp_accept_worker, same_tuple_reconnect_with_flowtags)
{
    run_accept_test("reconnect");
}
