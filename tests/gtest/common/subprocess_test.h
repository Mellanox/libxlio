/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2022-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef TESTS_GTEST_COMMON_SUBPROCESS_TEST_H_
#define TESTS_GTEST_COMMON_SUBPROCESS_TEST_H_

#include <cstdlib>
#include <fstream>
#include <string>

#include "common/def.h"

/**
 * Base class for tests that launch helper binaries and inspect their
 * captured output.  Provides workspace detection, command execution
 * with output capture, and automatic cleanup.
 */
class subprocess_test : virtual public testing::Test {
public:
    void SetUp() override
    {
        m_workspace = std::getenv("WORKSPACE");
        if (m_workspace) {
            std::cout << "WORKSPACE: '" << m_workspace << "'" << std::endl;
        } else {
            std::cout << "WORKSPACE is not set" << std::endl;
        }
    }

    void TearDown() override
    {
        if (!m_output_file.empty()) {
            unlink(m_output_file.c_str());
        }
    }

protected:
    /**
     * Resolve a path relative to the workspace root (tests/gtest/...).
     * Falls back to a path relative to CWD when WORKSPACE is not set.
     */
    std::string workspace_path(const std::string &relative) const
    {
        if (m_workspace) {
            return std::string(m_workspace) + "/" + relative;
        }
        return relative;
    }

    /**
     * Return the full path to a helper binary built alongside the gtest.
     * Uses GTEST_BUILDDIR (set by Makefile.am) so the lookup works with
     * out-of-tree builds where the build dir differs from the source tree.
     */
    std::string helper_path(const char *name) const
    {
        return std::string(GTEST_BUILDDIR) + "/" + name;
    }

    /**
     * Run @p cmd, redirecting stdout+stderr to @p output_file.
     * Throws std::runtime_error on non-zero exit to fail the test with
     * diagnostic output.
     */
    void exec_cmd_to_file(const std::string &cmd, const std::string &output_file)
    {
        std::string command = cmd + " > " + output_file + " 2>&1";
        int rc = system(command.c_str());
        if (rc != 0) {
            std::cout << "system('" << command << "') failed!" << std::endl;
            try {
                std::ifstream ifs(output_file);
                std::string text(std::istreambuf_iterator<char>(ifs), {});
                ifs.close();
                std::cout << "Content of '" << output_file << "':\n" << text << std::endl;
            } catch (const std::exception &e) {
                std::cout << "Failed to read file '" << output_file << "': " << e.what()
                          << std::endl;
            }
            throw std::runtime_error("Aborting test due to system command failure");
        }
    }

    /**
     * Read the full contents of a text file into a string.
     */
    std::string read_file(const std::string &path) const
    {
        std::ifstream ifs(path);
        if (!ifs.is_open()) {
            throw std::runtime_error("Failed to open file: " + path);
        }
        std::string text(std::istreambuf_iterator<char>(ifs), {});
        ifs.close();
        return text;
    }

    char *m_workspace {nullptr};
    std::string m_output_file;
};

#endif /* TESTS_GTEST_COMMON_SUBPROCESS_TEST_H_ */
