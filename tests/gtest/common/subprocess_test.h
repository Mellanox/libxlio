/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2022-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef TESTS_GTEST_COMMON_SUBPROCESS_TEST_H_
#define TESTS_GTEST_COMMON_SUBPROCESS_TEST_H_

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <string>
#include <unistd.h>

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
        if (m_workspace && !m_workspace[0]) {
            m_workspace = nullptr;
        }
        if (m_workspace) {
            std::cout << "WORKSPACE: '" << m_workspace << "'" << std::endl;
        } else {
            std::cout << "WORKSPACE is not set" << std::endl;
        }
        // Default capture file; derived fixtures may override with a more
        // specific name. Kept here so the base fully owns the field it cleans
        // up in TearDown().
        m_output_file = "/tmp/xlio_gtest_" + std::to_string(getpid()) + ".txt";
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
     * Without WORKSPACE, support running from either the workspace root or
     * tests/gtest, which was the legacy working directory for output tests.
     */
    std::string workspace_path(const std::string &relative) const
    {
        if (m_workspace) {
            return std::string(m_workspace) + "/" + relative;
        }

        if (access(relative.c_str(), F_OK) == 0) {
            return relative;
        }

        const std::string gtest_prefix = "tests/gtest/";
        if (relative.compare(0, gtest_prefix.size(), gtest_prefix) == 0) {
            return relative.substr(gtest_prefix.size());
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
     * True when @p ip can be an XLIO-offloadable endpoint address: not empty,
     * not the IPv4/IPv6 any-address and not loopback (XLIO serves those on the
     * kernel path by design, so a test that must prove offload skips them).
     * String comparison is sufficient because callers pass canonical
     * inet_ntop() output (sys_addr2str). IPv4-mapped IPv6 literals
     * ("::ffff:...") are deliberately not rejected here.
     */
    static bool addr_offloadable(const std::string &ip)
    {
        return !(ip.empty() || ip == "0.0.0.0" || ip == "::" || ip == "::1" ||
                 ip.rfind("127.", 0) == 0);
    }

    /**
     * Pull a numeric value that follows "<key>" in the report/output text.
     * Returns false if the key is absent.
     */
    static bool find_u64(const std::string &text, const std::string &key, uint64_t &out)
    {
        size_t pos = text.find(key);
        if (pos == std::string::npos) {
            return false;
        }
        pos += key.size();
        out = strtoull(text.c_str() + pos, nullptr, 10);
        return true;
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
