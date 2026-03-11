/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef TESTS_GTEST_COMMON_UTILS_H_
#define TESTS_GTEST_COMMON_UTILS_H_

#include <string>

/**
 * General test utility functions.
 */
class utils {
public:
    /** Run a command, redirecting its stdout and stderr to a file. Throws on failure. */
    static void exec_cmd_to_file(const std::string &cmd, const std::string &file_to_quote);

    /** Run a command, capture stdout+stderr to a temp file, return its content as a string. */
    static std::string exec_cmd_get_output(const std::string &cmd);

    /** Run 'ss -tn' until no connections are open to server address:port. Returns true when closed.
     */
    static bool wait_for_connections_to_close(std::string server_addr_str, int port,
                                              int timeout_sec);
};

#endif /* TESTS_GTEST_COMMON_UTILS_H_ */
