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

        // Minimal JSON config — isolates tests from CI's inherited XLIO_CONFIG_FILE.
        m_minimal_config = m_prefix + "/minimal_config.json";
        std::ofstream(m_minimal_config) << "{}";
    }

    void TearDown() override
    {
        unlink(m_output_file.c_str());
        unlink(m_minimal_config.c_str());
    }

protected:
    // Opens a socket to trigger XLIO's full init/exit lifecycle.
    // Non-networking commands (e.g. 'ls') skip XLIO's deferred global ctors.
    static constexpr const char *SOCKET_CMD =
        "python3 -c 'import socket; s=socket.socket(); s.close()'";

    // Run XLIO with report config via XLIO_INLINE_CONFIG.
    // Uses m_minimal_config to override any inherited XLIO_CONFIG_FILE from CI.
    void run_with_report(const std::string &report_path, const std::string &mode = "enable",
                         const std::string &extra_inline = "", const char *app_cmd = SOCKET_CMD)
    {
        std::string inline_cfg =
            "monitor.report.mode=" + mode + ";monitor.report.file_path=" + report_path;
        if (!extra_inline.empty()) {
            inline_cfg += ";" + extra_inline;
        }
        std::string cmd = "XLIO_USE_NEW_CONFIG=1 XLIO_CONFIG_FILE=" + m_minimal_config +
            " XLIO_INLINE_CONFIG=\"" + inline_cfg + "\" " + std::string(app_cmd) + " > " +
            m_output_file + " 2>&1";
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
                      const std::string &extra_inline = "", const char *app_cmd = SOCKET_CMD)
    {
        unlink(report_path.c_str());
        run_with_report(report_path, "enable", extra_inline, app_cmd);
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
    std::string m_minimal_config;
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
            "## Effective Config (non-default only)",
            "performance.polling.blocking_rx_poll_usec: 500000",
            "# default: 100000",
            "reason: User-configured",
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
        "## Active Profile",         "## Effective Config (non-default only)",
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
 * @test tuning_report.default_file_path
 * @brief Setting mode=enable without explicit file_path uses the schema default.
 */
TEST_F(tuning_report, default_file_path)
{
    // Without explicit file_path, the report should go to /tmp/xlio_report_<PID>.txt.
    // Use m_minimal_config so the test works even when XLIO_CONFIG_FILE is not
    // inherited (e.g. delegate-timer CI run) and /etc/libxlio_config.json is absent.
    std::string cmd = "XLIO_USE_NEW_CONFIG=1 XLIO_CONFIG_FILE=" + m_minimal_config +
        " XLIO_INLINE_CONFIG=\"monitor.report.mode=enable\" " + std::string(SOCKET_CMD) + " > " +
        m_output_file + " 2>&1";
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

    // The default schema path is /tmp/xlio_report_%d.txt — verify %d was
    // resolved to an actual PID, not left as a literal in the filename.
    ASSERT_TRUE(xlio_output.find("xlio_report_%d") == std::string::npos)
        << "Default report path contains literal %d (PID substitution failed)." << std::endl
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

    // Force legacy config path — CI may inherit XLIO_USE_NEW_CONFIG=1 which
    // would skip get_env_params() and ignore XLIO_PRINT_REPORT/XLIO_REPORT_FILE.
    std::string cmd = "XLIO_USE_NEW_CONFIG=0 XLIO_PRINT_REPORT=1 XLIO_REPORT_FILE=" + report_path +
        " " + SOCKET_CMD + " > " + m_output_file + " 2>&1";
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

/**
 * @test tuning_report.change_reason_profile
 * @brief Verify that profile-set parameters show "reason: Profile" in the report.
 */
TEST_F(tuning_report, change_reason_profile)
{
    std::string report_path = "/tmp/xlio_tuning_report_reason_profile_test.txt";
    check_report(report_path, {"reason: Profile"}, {}, "profiles.spec=latency");
}

/**
 * @test tuning_report.no_acceleration_control_when_unset
 * @brief acceleration_control entries must not appear in the report when
 *        the user has not configured any acceleration control parameters.
 */
TEST_F(tuning_report, no_acceleration_control_when_unset)
{
    std::string report_path = "/tmp/xlio_tuning_report_no_accel_test.txt";
    check_report(report_path, {"## Effective Config (non-default only)"}, {"acceleration_control"});
}

/**
 * @test tuning_report.socket_counts_without_stats_pool
 * @brief Verify that socket counts appear in the report even when
 *        monitor.stats.fd_num is 0 (default — no per-socket stats pool).
 */
TEST_F(tuning_report, socket_counts_without_stats_pool)
{
    std::string report_path = m_prefix + "/report_socket_counts.txt";
    check_report(report_path,
                 {"## Socket Summary", "total_sockets:", "tcp_sockets:", "offloaded_sockets:",
                  "non_offloaded_sockets: 0", "monitor.stats.fd_num"},
                 {"# Socket stats not available", "# No sockets were created"});
}

/**
 * @test tuning_report.socket_counts_with_undersized_stats_pool
 * @brief Verify that socket counts are accurate even when stats_fd_num is too
 *        small for the actual number of sockets.
 */
TEST_F(tuning_report, socket_counts_with_undersized_stats_pool)
{
    static constexpr const char *MANY_SOCKETS_CMD = "python3 -c '"
                                                    "import socket;"
                                                    "socks=[socket.socket() for _ in range(5)];"
                                                    "[s.close() for s in socks]"
                                                    "'";

    std::string report_path = m_prefix + "/report_undersized_pool.txt";
    unlink(report_path.c_str());

    run_with_report(report_path, "enable", "monitor.stats.fd_num=1", MANY_SOCKETS_CMD);
    if (HasFatalFailure()) {
        return;
    }

    std::string text = read_report(report_path);
    ASSERT_FALSE(text.empty());

    ASSERT_NE(text.find("## Socket Summary"), std::string::npos);

    std::string key = "total_sockets: ";
    auto pos = text.find(key);
    ASSERT_NE(pos, std::string::npos) << "total_sockets not found in report";
    char *endptr = nullptr;
    long long total = std::strtoll(text.c_str() + pos + key.size(), &endptr, 10);
    ASSERT_NE(endptr, text.c_str() + pos + key.size()) << "Failed to parse total_sockets value";
    EXPECT_GE(total, 5LL) << "Expected total_sockets >= 5 despite stats_fd_num=1, got " << total
                          << std::endl
                          << text;

    unlink(report_path.c_str());
}

/**
 * @test tuning_report.offloaded_and_non_offloaded_counts
 * @brief Verify that destructor counters correctly distinguish offloaded
 *        from non-offloaded sockets. A plain socket stays offloaded;
 *        connecting to loopback forces passthrough (non-offloaded).
 */
TEST_F(tuning_report, offloaded_and_non_offloaded_counts)
{
    static constexpr const char *MIXED_SOCKETS_CMD =
        "python3 -c '\n"
        "import socket\n"
        "s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "s1.close()\n"
        "s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "try:\n"
        "    s2.connect((\"127.0.0.1\", 1))\n"
        "except Exception:\n"
        "    pass\n"
        "s2.close()\n"
        "'";

    std::string report_path = m_prefix + "/report_offload_split.txt";
    unlink(report_path.c_str());

    run_with_report(report_path, "enable", "", MIXED_SOCKETS_CMD);
    if (HasFatalFailure()) {
        return;
    }

    std::string text = read_report(report_path);
    ASSERT_FALSE(text.empty());

    ASSERT_NE(text.find("## Socket Summary"), std::string::npos);

    auto parse_field = [&](const char *field_name) -> long long {
        std::string key = std::string(field_name) + ": ";
        auto pos = text.find(key);
        EXPECT_NE(pos, std::string::npos) << field_name << " not found in report";
        if (pos == std::string::npos) {
            return -1;
        }
        char *endptr = nullptr;
        long long val = std::strtoll(text.c_str() + pos + key.size(), &endptr, 10);
        EXPECT_NE(endptr, text.c_str() + pos + key.size())
            << "Failed to parse " << field_name << " value";
        return val;
    };

    long long offloaded = parse_field("offloaded_sockets");
    long long non_offloaded = parse_field("non_offloaded_sockets");

    EXPECT_GE(offloaded, 1LL) << "Expected at least 1 offloaded socket (plain create+close)"
                              << std::endl
                              << text;
    EXPECT_GE(non_offloaded, 1LL)
        << "Expected at least 1 non-offloaded socket (connect to loopback)" << std::endl
        << text;

    unlink(report_path.c_str());
}
