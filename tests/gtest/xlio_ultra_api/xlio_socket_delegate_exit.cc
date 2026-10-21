/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/log.h"
#include "common/subprocess_test.h"
#include "common/sys.h"

class ultra_api_delegate_exit : public subprocess_test {};

TEST_F(ultra_api_delegate_exit, unregisters_group_timer_before_socket_delete)
{
    const struct sockaddr *server =
        reinterpret_cast<const struct sockaddr *>(&gtest_conf.server_addr);
    std::string peer = sys_addr2str(server, false);
    if (peer.empty() || peer == "0.0.0.0" || peer == "::") {
        GTEST_SKIP() << "An offloadable server address is required";
    }

    std::string config =
        workspace_path("tests/gtest/xlio_ultra_api/config-ultra-api-delegate.json");
    std::string helper = helper_path("ultra_api_connect_helper");
    std::string cmd = "XLIO_USE_NEW_CONFIG=1 XLIO_CONFIG_FILE=" + config + " " + helper +
        " --exit-with-live-socket " + peer;

    exec_cmd_to_file(cmd, m_output_file);
    std::string output = read_file(m_output_file);

    if (output.find("SKIP:") != std::string::npos) {
        GTEST_SKIP() << output;
    }

    const std::string marker = "LIVE_TIMER_SOCKET ";
    size_t marker_pos = output.find(marker);
    ASSERT_NE(std::string::npos, marker_pos) << output;
    size_t socket_end = output.find('\n', marker_pos);
    ASSERT_NE(std::string::npos, socket_end) << output;
    std::string socket =
        output.substr(marker_pos + marker.size(), socket_end - marker_pos - marker.size());

    ASSERT_NE(std::string::npos, output.find("Registering TCP socket timer: " + socket)) << output;
    ASSERT_NE(std::string::npos,
              output.find("Unregistering TCP socket timer and destroying: " + socket))
        << "The Ultra socket was deleted while its poll-group timer still referred to it.\n"
        << output;
    ASSERT_NE(std::string::npos, output.find("PASS")) << output;
}
