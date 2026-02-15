/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <climits>
#include <cstdlib>
#include <fstream>

#include "common/def.h"

class tuning_report : virtual public testing::Test {
public:
    void SetUp() override
    {
        m_workspace = std::getenv("WORKSPACE");
        if (m_workspace) {
            m_prefix = std::string(m_workspace) + "/tests/gtest/output";
        } else {
            m_prefix = "output";
        }
        m_output_file = m_prefix + "/output.txt";
    }

    void TearDown() override { unlink(m_output_file.c_str()); }

protected:
    // Opens a socket to trigger XLIO's full init/exit lifecycle.
    // Non-networking commands (e.g. 'ls') skip XLIO's deferred global ctors.
    static constexpr const char *SOCKET_CMD =
        "python3 -c 'import socket; s=socket.socket(); s.close()'";

    // Run XLIO with report config via XLIO_INLINE_CONFIG.
    void run_with_report(const std::string &report_path, const std::string &mode = "enable",
                         const std::string &extra_inline = "")
    {
        std::string inline_cfg =
            "monitor.report.mode=" + mode + ",monitor.report.file_path=" + report_path;
        if (!extra_inline.empty()) {
            inline_cfg += "," + extra_inline;
        }
        std::string cmd = "XLIO_USE_NEW_CONFIG=1 XLIO_INLINE_CONFIG=\"" + inline_cfg + "\" " +
            SOCKET_CMD + " > " + m_output_file + " 2>&1";
        int rc = system(cmd.c_str());
        ASSERT_EQ(rc, 0) << "Command failed: " << cmd;
    }

    // Read report file contents. Adds a test failure if the file doesn't exist.
    std::string read_report(const std::string &report_path)
    {
        std::ifstream ifs(report_path);
        if (!ifs.is_open()) {
            std::ifstream err_ifs(m_output_file);
            std::string stderr_text(std::istreambuf_iterator<char>(err_ifs), {});
            ADD_FAILURE() << "Report file not created at " << report_path << std::endl
                          << "XLIO output:" << std::endl
                          << stderr_text;
            return "";
        }
        return std::string(std::istreambuf_iterator<char>(ifs), {});
    }

    // Run XLIO with report enabled, then verify expected/unexpected strings in report.
    void check_report(const std::string &report_path,
                      const std::vector<const char *> &expected_strings,
                      const std::vector<const char *> &unexpected_strings = {},
                      const std::string &extra_inline = "")
    {
        unlink(report_path.c_str());
        run_with_report(report_path, "enable", extra_inline);
        if (HasFatalFailure()) {
            return;
        }

        std::string text = read_report(report_path);
        if (text.empty()) {
            return;
        }

        for (const auto &expected : expected_strings) {
            ASSERT_TRUE(text.find(expected) != std::string::npos)
                << "Did not find '" << expected << "' in tuning report:" << std::endl
                << "START OF REPORT:" << std::endl
                << text << std::endl
                << "END OF REPORT";
        }
        for (const auto &unexpected : unexpected_strings) {
            ASSERT_TRUE(text.find(unexpected) == std::string::npos)
                << "Found unexpected '" << unexpected << "' in tuning report:" << std::endl
                << "START OF REPORT:" << std::endl
                << text << std::endl
                << "END OF REPORT";
        }

        unlink(report_path.c_str());
    }

    char *m_workspace {nullptr};
    std::string m_prefix;
    std::string m_output_file;
};

/**
 * @test tuning_report.basic
 * @brief Verify report is created with expected sections and non-default marking.
 */
TEST_F(tuning_report, basic)
{
    check_report(
        "/tmp/xlio_tuning_report_basic_test.txt",
        {
            // clang-format off
            "# XLIO Tuning Report",
            "# Generated:",
            "PID:",
            "Duration:",
            "## System Context",
            "xlio_version:",
            "kernel:",
            "## Active Profile",
            "## Effective Config",
            "performance.polling.blocking_rx_poll_usec: 500000 *",
            "# default: 100000",
            "# End of XLIO Tuning Report"
            // clang-format on
        },
        {"Config registry not available"}, "performance.polling.blocking_rx_poll_usec=500000");
}

/**
 * @test tuning_report.not_created_when_disabled
 * @brief No report file is created when monitor.report.mode=disable.
 */
TEST_F(tuning_report, not_created_when_disabled)
{
    std::string report_path = "/tmp/xlio_tuning_report_disabled_test.txt";
    unlink(report_path.c_str());

    run_with_report(report_path, "disable");
    if (HasFatalFailure()) {
        return;
    }

    std::ifstream ifs(report_path);
    ASSERT_FALSE(ifs.is_open()) << "Report file should not exist when mode=disable";
}

/**
 * @test tuning_report.auto_mode_no_errors
 * @brief Auto mode does NOT create a report when no anomalies are detected.
 */
TEST_F(tuning_report, auto_mode_no_errors)
{
    std::string report_path = "/tmp/xlio_tuning_report_auto_test.txt";
    unlink(report_path.c_str());

    run_with_report(report_path, "auto");
    if (HasFatalFailure()) {
        return;
    }

    std::ifstream ifs(report_path);
    ASSERT_FALSE(ifs.is_open())
        << "Report should not be created in auto mode when no errors are detected";
}

/**
 * @test tuning_report.unwritable_path
 * @brief An unwritable report path fails gracefully (no crash).
 */
TEST_F(tuning_report, unwritable_path)
{
    run_with_report("/nonexistent_dir_xlio_test/report.txt");
    if (HasFatalFailure()) {
        return;
    }

    std::ifstream ifs("/nonexistent_dir_xlio_test/report.txt");
    ASSERT_FALSE(ifs.is_open());
}

/**
 * @test tuning_report.vlog_summary
 * @brief When a report is written, vlog emits a compact summary line with path and key metrics.
 */
TEST_F(tuning_report, vlog_summary)
{
    std::string report_path = "/tmp/xlio_tuning_report_vlog_test.txt";
    unlink(report_path.c_str());

    run_with_report(report_path);
    if (HasFatalFailure()) {
        return;
    }

    std::ifstream out_ifs(m_output_file);
    ASSERT_TRUE(out_ifs.is_open()) << "XLIO output file not found: " << m_output_file;
    std::string xlio_output(std::istreambuf_iterator<char>(out_ifs), {});

    ASSERT_TRUE(xlio_output.find("Tuning report:") != std::string::npos)
        << "vlog should contain 'Tuning report:' summary line" << std::endl
        << "XLIO output:" << std::endl
        << xlio_output;
    ASSERT_TRUE(xlio_output.find(report_path) != std::string::npos)
        << "vlog summary should contain report path" << std::endl
        << "XLIO output:" << std::endl
        << xlio_output;
    ASSERT_TRUE(xlio_output.find("hw_rx_drops=") != std::string::npos)
        << "vlog summary should contain hw_rx_drops metric" << std::endl
        << "XLIO output:" << std::endl
        << xlio_output;
    ASSERT_TRUE(xlio_output.find("buf_alloc_failures=") != std::string::npos)
        << "vlog summary should contain buf_alloc_failures metric" << std::endl
        << "XLIO output:" << std::endl
        << xlio_output;

    unlink(report_path.c_str());
}

/**
 * @test tuning_report.section_ordering
 * @brief All report sections appear in the correct order.
 */
TEST_F(tuning_report, section_ordering)
{
    std::string report_path = "/tmp/xlio_tuning_report_ordering_test.txt";
    unlink(report_path.c_str());

    run_with_report(report_path);
    if (HasFatalFailure()) {
        return;
    }

    std::string text = read_report(report_path);
    ASSERT_FALSE(text.empty());

    const char *sections[] = {
        "# XLIO Tuning Report",      "## System Context",
        "## Active Profile",         "## Effective Config",
        "## Runtime Stats",          "## Socket Summary",
        "## Performance Indicators", "# End of XLIO Tuning Report",
    };

    size_t prev_pos = 0;
    const char *prev_name = nullptr;
    for (const char *section : sections) {
        size_t pos = text.find(section);
        ASSERT_NE(pos, std::string::npos) << "Missing section: " << section;
        if (prev_name) {
            ASSERT_LT(prev_pos, pos) << prev_name << " must come before " << section;
        }
        prev_pos = pos;
        prev_name = section;
    }

    unlink(report_path.c_str());
}

/**
 * @test tuning_report.pid_substitution
 * @brief %d in the report file path is replaced with the process PID.
 */
TEST_F(tuning_report, pid_substitution)
{
    std::string report_dir = "/tmp/xlio_test_pid_" + std::to_string(getpid());
    ASSERT_EQ(system(("mkdir -p " + report_dir).c_str()), 0) << "Failed to create test directory";

    std::string report_pattern = "xlio_report_";

    // Use legacy env vars: XLIO_INLINE_CONFIG's parser rejects '%' in values.
    std::string cmd = "XLIO_PRINT_REPORT=1 XLIO_REPORT_FILE=" + report_dir + "/" + report_pattern +
        "%d.txt " + SOCKET_CMD + " > " + m_output_file + " 2>&1";
    int rc = system(cmd.c_str());
    ASSERT_EQ(rc, 0) << "Command failed: " << cmd;

    std::string find_cmd = "ls " + report_dir + "/" + report_pattern + "*.txt 2>/dev/null";
    FILE *pipe = popen(find_cmd.c_str(), "r");
    ASSERT_NE(pipe, nullptr);
    char found_path[PATH_MAX];
    bool found = (fgets(found_path, sizeof(found_path), pipe) != nullptr);
    pclose(pipe);

    ASSERT_TRUE(found) << "No report file matching " << report_pattern << "*.txt found in "
                       << report_dir;

    size_t len = strlen(found_path);
    if (len > 0 && found_path[len - 1] == '\n') {
        found_path[len - 1] = '\0';
    }

    std::string found_str(found_path);
    ASSERT_TRUE(found_str.find("%d") == std::string::npos)
        << "Report filename still contains literal %d: " << found_str;

    std::ifstream ifs(found_path);
    ASSERT_TRUE(ifs.is_open()) << "Cannot open report file: " << found_str;
    std::string text(std::istreambuf_iterator<char>(ifs), {});
    ASSERT_TRUE(text.find("# XLIO Tuning Report") != std::string::npos)
        << "Report file is missing preamble";

    int unused __attribute__((unused)) = system(("rm -rf " + report_dir).c_str());
}

/**
 * @test tuning_report.default_file_path
 * @brief Setting mode=enable without explicit file_path uses the schema default.
 */
TEST_F(tuning_report, default_file_path)
{
    // Reproduce: XLIO_USE_NEW_CONFIG=1 XLIO_INLINE_CONFIG=monitor.report.mode=enable
    // Without explicit file_path, the report should go to /tmp/xlio_report_<PID>.txt.
    std::string cmd = "XLIO_USE_NEW_CONFIG=1 "
                      "XLIO_INLINE_CONFIG=\"monitor.report.mode=enable\" " +
        std::string(SOCKET_CMD) + " > " + m_output_file + " 2>&1";
    int rc = system(cmd.c_str());
    ASSERT_EQ(rc, 0) << "Command failed: " << cmd;

    std::ifstream out_ifs(m_output_file);
    ASSERT_TRUE(out_ifs.is_open());
    std::string xlio_output(std::istreambuf_iterator<char>(out_ifs), {});

    ASSERT_TRUE(xlio_output.find("Failed to write tuning report") == std::string::npos)
        << "Report generation failed (empty file path — default not applied)." << std::endl
        << "XLIO output:" << std::endl
        << xlio_output;

    ASSERT_TRUE(xlio_output.find("Tuning report:") != std::string::npos)
        << "Expected success message in XLIO output." << std::endl
        << "XLIO output:" << std::endl
        << xlio_output;

    // Cleanup report file (PID unknown, use glob)
    int unused __attribute__((unused)) = system("rm -f /tmp/xlio_report_*.txt");
}

/**
 * @test tuning_report.legacy_env_vars
 * @brief XLIO_PRINT_REPORT + XLIO_REPORT_FILE work without XLIO_USE_NEW_CONFIG.
 */
TEST_F(tuning_report, legacy_env_vars)
{
    std::string report_path = "/tmp/xlio_tuning_report_legacy_test.txt";
    unlink(report_path.c_str());

    std::string cmd = "XLIO_PRINT_REPORT=1 XLIO_REPORT_FILE=" + report_path + " " + SOCKET_CMD +
        " > " + m_output_file + " 2>&1";
    int rc = system(cmd.c_str());
    ASSERT_EQ(rc, 0) << "Command failed: " << cmd;

    std::string text = read_report(report_path);
    ASSERT_FALSE(text.empty());

    ASSERT_TRUE(text.find("# XLIO Tuning Report") != std::string::npos);
    ASSERT_TRUE(text.find("## System Context") != std::string::npos);
    ASSERT_TRUE(text.find("## Active Profile") != std::string::npos);
    ASSERT_TRUE(text.find("Config registry not available") != std::string::npos)
        << "Expected 'Config registry not available' in legacy mode report";

    unlink(report_path.c_str());
}
