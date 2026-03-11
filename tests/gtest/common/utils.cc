/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <fstream>
#include <string>
#include <unistd.h>

#include "common/def.h"
#include "common/log.h"
#include "common/utils.h"

void utils::exec_cmd_to_file(const std::string &cmd, const std::string &file_to_quote)
{
    // The syntax '[command] > [file] 2>&1' works for both bash and dash
    std::string command = cmd + " > " + file_to_quote + " 2>&1";
    int rc = system(command.c_str());
    if (rc != 0) {
        std::cout << "system('" << command << "') failed!" << std::endl;
        // Show content of the file to quote
        try {
            std::ifstream ifs(file_to_quote);
            std::string text(std::istreambuf_iterator<char>(ifs), {});
            ifs.close();
            std::cout << "Content of '" << file_to_quote << "':\n" << text << std::endl;
        } catch (const std::exception &e) {
            std::cout << "Failed to read file '" << file_to_quote << "': " << e.what() << std::endl;
        }
        throw std::runtime_error("Aborting test due to system command failure");
    }
}

std::string utils::exec_cmd_get_output(const std::string &cmd)
{
    std::string file_path = "/tmp/xlio_gtest_output_" + std::to_string(getpid()) + ".txt";
    exec_cmd_to_file(cmd, file_path);
    std::ifstream ifs(file_path);
    std::string text(std::istreambuf_iterator<char>(ifs), {});
    ifs.close();
    unlink(file_path.c_str());
    return text;
}

bool utils::wait_for_connections_to_close(std::string server_addr_, int port, int timeout_sec)
{
    std::string addr_and_port = server_addr_ + ":" + std::to_string(port);
    std::string cmd = "ss -tn";
    log_trace("wait_for_connections_to_close: waiting for connections to close: Expecting command "
              "'%s' to not have '%s'\n",
              cmd.c_str(), addr_and_port.c_str());
    while (true) {
        std::string output = exec_cmd_get_output(cmd);
        log_trace("wait_for_connections_to_close: Got output: %s\n", output.c_str());
        if (output.find(addr_and_port) == std::string::npos) {
            break;
        }
        log_trace("wait_for_connections_to_close: connections still open: %s\n", output.c_str());
        if (timeout_sec <= 0) {
            log_error("wait_for_connections_to_close: timed out\n");
            return false;
        }
        sleep(1);
        timeout_sec--;
    }
    return true;
}
