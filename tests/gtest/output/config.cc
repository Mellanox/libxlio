/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2022-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <climits>
#include <cstdlib>
#include <fstream>

#include "common/def.h"

/**
 * Base class for output tests
 */
class output : virtual public testing::Test {
public:
    void SetUp() override
    {
        m_workspace = std::getenv("WORKSPACE");
        if (m_workspace) {
            std::cout << "WORKSPACE: '" << m_workspace << "'" << std::endl;
            m_prefix = std::string(m_workspace) + "/tests/gtest/output";
        } else {
            std::cout << "WORKSPACE is not set" << std::endl;
            m_prefix = "output";
        }
        m_output_file = m_prefix + "/output.txt";
    }

    void TearDown() override { unlink(m_output_file.c_str()); }

protected:
    static constexpr const char *SOCKET_CMD =
        "python3 -c 'import socket; s=socket.socket(); s.close()'";
    void exec_cmd_to_file(const std::string &cmd, const std::string &file_to_quote)
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
                std::cout << "Failed to read file '" << file_to_quote << "': " << e.what()
                          << std::endl;
            }
            throw std::runtime_error("Aborting test due to system command failure");
        }
    }

    void check_file(const std::string &filename, const std::vector<const char *> &expected_strings,
                    const std::vector<const char *> &unexpected_strings = {})
    {
        std::string full_filename = m_prefix + "/" + filename;

        // LD_PRELOAD is already set for the gtest, it is inherited by the new process, no need
        // to do anything
        std::string cmd = "XLIO_USE_NEW_CONFIG=1 XLIO_CONFIG_FILE=" + full_filename + " ls";
        exec_cmd_to_file(cmd, m_output_file);

        // Read the output file
        std::ifstream ifs(m_output_file);
        std::string text(std::istreambuf_iterator<char>(ifs), {});
        ifs.close();

        for (const auto &expected : expected_strings) {
            // ASSERT and not EXPECT because if there are multiple failures the test output
            // becomes flooded, so we want to stop after the first failure
            ASSERT_TRUE(text.find(expected) != std::string::npos)
                << "Did not find '" << expected << "' in xlio output when using file '" << filename
                << "':" << std::endl
                << "START OF TEXT:" << std::endl
                << text << std::endl
                << "END OF TEXT";
        };
        for (const auto &unexpected : unexpected_strings) {
            ASSERT_TRUE(text.find(unexpected) == std::string::npos)
                << "Found unexpected '" << unexpected << "' in xlio output when using file '"
                << filename << "':" << std::endl
                << "START OF TEXT:" << std::endl
                << text << std::endl
                << "END OF TEXT";
        }
    }

    char *m_workspace {nullptr};
    std::string m_prefix;
    std::string m_output_file;
};

/**
 * @test misc.config_show_sample_values
 * @brief
 *    Tests that various config values are shown at xlio start
 *
 * @details
 *    This test run a new process with LD_PRELOAD and captures the text output from xlio :
 *    - Various config values are set in a json config file
 *    - The test makes sure they are shown properly
 */
TEST_F(output, config_show_sample_values)
{
    check_file(
        "config-sample.json",
        {
            // We want there extra-wide lines for readability, tell clang-format to accept them
            // clang-format off

            // The config sources are shown - we check only the fixed part of the path,
            // because the full path changes depending on the WORKSPACE env var
            "output/config-sample.json",

            // Log level is always shown
            "XLIO INFO   : Log level                      INFO                       [monitor.log.level]",
            // Simple number
            "XLIO INFO   : Source port stride             3                          [applications.nginx.src_port_stride, Reason: User-configured]",
            // Simple string
            "Daemon working directory       /funny-dir                 [core.daemon.dir, Reason: User-configured]",
        #ifdef DEFINED_UTLS
            // Simple boolean
            "Enable TLS RX offload          true                       [hardware_features.tcp.tls_offload.rx_enable, Reason: User-configured]",
            // 4096 is shown as 4K
            "DEK max cache size             4K                         [hardware_features.tcp.tls_offload.dek_cache_max_size, Reason: User-configured]",
        #endif
            "Enable hugepages               false                      [core.resources.hugepages.enable, Reason: User-configured]",
            // Boolean with translation from bool to multilock_t and back
            "Use mutex instead of spinlocks true                       [performance.threading.mutex_over_spinlock, Reason: User-configured]",
            // CONFIG_VAR_PROGRESS_ENGINE_INTERVAL is a special case, 0 is shown as '0 (Disabled)'
            "Periodic drain interval (msec) 0 (Disabled)               [performance.completion_queue.periodic_drain_msec, Reason: Auto-corrected (Forced when performance.threading.internal_handler.behavior=DELEGATE_TCP_TIMERS)]",
            // Another simple string
            "CPU affinity                   1,2,3                      [performance.threading.cpu_affinity, Reason: User-configured]",
            // Enum value is shown as a string
            "XLIO INFO   : Exception handling mode        log_error_undo_offload     [core.exception_handling.mode, Reason: User-configured]",
            // Not a power of 1024, hence shown in full accuracy
            "XLIO INFO   : RX poll duration (µsec)       2049                       [performance.polling.blocking_rx_poll_usec, Reason: User-configured]",
            // The accelaration rules array - Yey, recursion !
            "XLIO INFO   : Acceleration control rules                                [acceleration_control.rules]",
            "XLIO INFO   :                                0                          [acceleration_control.rules[0].id]",
            "XLIO INFO   :                                a                          [acceleration_control.rules[0].name]",
            "XLIO INFO   :                                Action 0 of rule a         [acceleration_control.rules[0].actions[0]]",
            "XLIO INFO   :                                1                          [acceleration_control.rules[1].id]",
            "XLIO INFO   :                                b                          [acceleration_control.rules[1].name]",
            "XLIO INFO   :                                Action 0 of rule b         [acceleration_control.rules[1].actions[0]]",
            "XLIO INFO   :                                xx                         [acceleration_control.rules[1].actions[1]]",
            "XLIO INFO   : 2 element(s) not shown                                    [acceleration_control.rules[2-3]]",
            "XLIO INFO   :                                4                          [acceleration_control.rules[4].id]",
            "XLIO INFO   :                                e                          [acceleration_control.rules[4].name]",
            "XLIO INFO   :                                Action 0 of rule e         [acceleration_control.rules[4].actions[0]]",
            "XLIO INFO   :                                5                          [acceleration_control.rules[5].id]",
            "XLIO INFO   :                                f                          [acceleration_control.rules[5].name]",
            "XLIO INFO   :                                Action 0 of rule f         [acceleration_control.rules[5].actions[0]]",
            // This comes from the NGINX profile, not from the .json - checks that we read runtime values and not from config registry
            "XLIO INFO   : Timer resolution (msec)        32                         [performance.threading.internal_handler.timer_msec, Reason: Profile (Nginx profile)]"
            // clang-format on
        },
        {
            // This should not be shown, despite being set in the json to 10 (= per socket), because
            // setting threading.internal_handler.behavior to "delegate" resets this value to
            // default
            "TX ring allocation logic       per_socket                 "
            "[performance.rings.tx.allocation_logic]",
        });
}

/**
 * @test misc.config_cpu_affinity_invalid_value
 * @brief
 *    Tests that invalid cpu_affinity value triggers a WARNING
 *
 * @details
 *    When setting performance.threading.cpu_affinity to an invalid value like "sdfsdf",
 *    XLIO should emit a WARNING log message and fall back to cpu-0.
 */
TEST_F(output, config_cpu_affinity_invalid_value)
{
    check_file(
        "config-cpu-affinity-invalid.json",
        {
            // We expect a WARNING message for invalid cpu_affinity value
            // clang-format off
            "XLIO WARNING: Failed to set internal thread affinity: sdfsdf...  deferring to cpu-0."
            // clang-format on
        });
}

/**
 * @test misc.config_cpu_affinity_default_value
 * @brief
 *    Tests that default cpu_affinity value "-1" does not trigger any error or warning
 *
 * @details
 *    When setting performance.threading.cpu_affinity to "-1" (which means
 *    "disable internal thread affinity setting"), XLIO should NOT emit any
 *    error or warning. Value of -1 is a valid documented special value.
 *    Note: Since "-1" is the default, XLIO won't print it in the config output.
 */
TEST_F(output, config_cpu_affinity_default_value)
{
    check_file("config-cpu-affinity-default.json",
               {// Just verify the config file is loaded
                "config-cpu-affinity-default.json"},
               {// This should NOT appear - "-1" is a valid value meaning "disabled"
                "Failed to set internal thread affinity"});
}

/**
 * @test misc.config_show_sample_values_2rules
 * @brief
 *    With only 2 acceleration control rules, we should not see the "element(s) not shown" message
 */
TEST_F(output, config_show_sample_values_2rules)
{
    check_file(
        "config-sample-2rules.json",
        {
            // We want there extra-wide lines for readability, tell clang-format to accept them
            // clang-format off

            // The config sources are shown
            "output/config-sample-2rules.json",

            // The accelaration rules array with only 2 rules
            "XLIO INFO   : Acceleration control rules                                [acceleration_control.rules]",
            "XLIO INFO   :                                0                          [acceleration_control.rules[0].id]",
            "XLIO INFO   :                                a                          [acceleration_control.rules[0].name]",
            "XLIO INFO   :                                Action 0 of rule a         [acceleration_control.rules[0].actions[0]]",
            "XLIO INFO   :                                1                          [acceleration_control.rules[1].id]",
            "XLIO INFO   :                                b                          [acceleration_control.rules[1].name]",
            "XLIO INFO   :                                Action 0 of rule b         [acceleration_control.rules[1].actions[0]]",
            "XLIO INFO   :                                xx                         [acceleration_control.rules[1].actions[1]]"
            // clang-format on
        },
        {// This is NOT expected
         "element(s) not shown"});
}

/**
 * @test misc.config_show_sample_values_4rules
 * @brief
 *    With only 4 acceleration control rules, we should not see the "element(s) not shown" message
 */
TEST_F(output, config_show_sample_values_4rules)
{
    check_file(
        "config-sample-4rules.json",
        {
            // We want there extra-wide lines for readability, tell clang-format to accept them
            // clang-format off

            // The config sources are shown
            "output/config-sample-4rules.json",

            // The accelaration rules array with only 4 rules
            "XLIO INFO   : Acceleration control rules                                [acceleration_control.rules]",
            "XLIO INFO   :                                0                          [acceleration_control.rules[0].id]",
            "XLIO INFO   :                                a                          [acceleration_control.rules[0].name]",
            "XLIO INFO   :                                Action 0 of rule a         [acceleration_control.rules[0].actions[0]]",
            "XLIO INFO   :                                1                          [acceleration_control.rules[1].id]",
            "XLIO INFO   :                                b                          [acceleration_control.rules[1].name]",
            "XLIO INFO   :                                Action 0 of rule b         [acceleration_control.rules[1].actions[0]]",
            "XLIO INFO   :                                xx                         [acceleration_control.rules[1].actions[1]]",
            "XLIO INFO   :                                2                          [acceleration_control.rules[2].id]",
            "XLIO INFO   :                                c                          [acceleration_control.rules[2].name]",
            "XLIO INFO   :                                Action 0 of rule c         [acceleration_control.rules[2].actions[0]]",
            "XLIO INFO   :                                3                          [acceleration_control.rules[3].id]",
            "XLIO INFO   :                                d                          [acceleration_control.rules[3].name]",
            "XLIO INFO   :                                Action 0 of rule d         [acceleration_control.rules[3].actions[0]]"
            // clang-format on
        },
        {// This is NOT expected
         "element(s) not shown"});
}

/**
 * @test misc.config_show_sample_values_5rules
 * @brief
 *    With 5 acceleration control rules, we should  see the "element(s) not shown" message with a
 * single element [2]
 */
TEST_F(output, config_show_sample_values_5rules)
{
    check_file(
        "config-sample-5rules.json",
        {
            // We want there extra-wide lines for readability, tell clang-format to accept them
            // clang-format off

            // The config sources are shown
            "output/config-sample-5rules.json",

            // The accelaration rules array with 5 rules
            "XLIO INFO   : Acceleration control rules                                [acceleration_control.rules]",
            "XLIO INFO   :                                0                          [acceleration_control.rules[0].id]",
            "XLIO INFO   :                                a                          [acceleration_control.rules[0].name]",
            "XLIO INFO   :                                Action 0 of rule a         [acceleration_control.rules[0].actions[0]]",
            "XLIO INFO   :                                1                          [acceleration_control.rules[1].id]",
            "XLIO INFO   :                                b                          [acceleration_control.rules[1].name]",
            "XLIO INFO   :                                Action 0 of rule b         [acceleration_control.rules[1].actions[0]]",
            "XLIO INFO   :                                xx                         [acceleration_control.rules[1].actions[1]]",
            "XLIO INFO   : 1 element(s) not shown                                    [acceleration_control.rules[2]]",
            "XLIO INFO   :                                3                          [acceleration_control.rules[3].id]",
            "XLIO INFO   :                                d                          [acceleration_control.rules[3].name]",
            "XLIO INFO   :                                Action 0 of rule d         [acceleration_control.rules[3].actions[0]]",
            "XLIO INFO   :                                4                          [acceleration_control.rules[4].id]",
            "XLIO INFO   :                                e                          [acceleration_control.rules[4].name]",
            "XLIO INFO   :                                Action 0 of rule e         [acceleration_control.rules[4].actions[0]]"
            // clang-format on
        });
}

/**
 * @test misc.config_show_negative_values
 * @brief
 *    Tests that negative config values are displayed correctly (not as huge unsigned values)
 *
 * @details
 *    When setting negative values (like -1 or -2) on integer config parameters that allow them,
 *    XLIO should display the actual negative value, not a huge number from signed-to-unsigned
 *    conversion.
 */
TEST_F(output, config_show_negative_values)
{
    check_file("config-negative-values.json",
               {
                   // clang-format off
            // Negative values should be displayed as-is, not as huge unsigned values
            // -1 should appear as "-1", not as "18446744073709551615"
            "XLIO INFO   : RX poll duration (µsec)       -1                         [performance.polling.blocking_rx_poll_usec, Reason: User-configured]",
            "XLIO INFO   : Select/poll duration (µsec)   -1                         [performance.polling.iomux.poll_usec, Reason: User-configured]",
            "XLIO INFO   : Offload transition poll count  -1                         [performance.polling.offload_transition_poll_count, Reason: User-configured]"
                   // clang-format on
               },
               {// These huge values should NOT appear - they indicate the signed-to-unsigned bug
                "18446744073709551614", "18446744073709551615"});
}

/**
 * @test output.config_pid_substitution_legacy
 * @brief %d in XLIO_REPORT_FILE (legacy env vars) is replaced with the process PID.
 */
TEST_F(output, config_pid_substitution_legacy)
{
    std::string report_dir = "/tmp/xlio_test_pid_" + std::to_string(getpid());
    ASSERT_EQ(system(("mkdir -p " + report_dir).c_str()), 0) << "Failed to create test directory";

    std::string report_pattern = "xlio_report_";

    // Use legacy env vars: XLIO_INLINE_CONFIG's parser rejects '%' in values.
    // Force legacy config path — CI may inherit XLIO_USE_NEW_CONFIG=1 which
    // would skip get_env_params() and ignore XLIO_PRINT_REPORT/XLIO_REPORT_FILE.
    std::string cmd = "XLIO_USE_NEW_CONFIG=0 XLIO_PRINT_REPORT=1 XLIO_REPORT_FILE=" + report_dir +
        "/" + report_pattern + "%d.txt " + SOCKET_CMD + " > " + m_output_file + " 2>&1";
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
 * @test output.config_pid_substitution_new_config
 * @brief %d in monitor.report.file_path (new config system) is replaced with the process PID.
 */
TEST_F(output, config_pid_substitution_new_config)
{
    std::string report_dir = "/tmp/xlio_test_pid_nc_" + std::to_string(getpid());
    ASSERT_EQ(system(("mkdir -p " + report_dir).c_str()), 0) << "Failed to create test directory";

    std::string report_pattern = "xlio_report_";

    // Write a JSON config with %d in the report path.
    // Unlike XLIO_INLINE_CONFIG (which rejects '%'), JSON config files
    // handle '%d' in string values without issue.
    std::string config_file = m_prefix + "/pid_test_config.json";
    {
        std::ofstream cfg(config_file);
        cfg << R"({ "monitor": { "report": { "mode": "enable", "file_path": ")" << report_dir << "/"
            << report_pattern << R"(%d.txt" } } })";
    }

    std::string cmd = "XLIO_USE_NEW_CONFIG=1 XLIO_CONFIG_FILE=" + config_file + " " +
        std::string(SOCKET_CMD) + " > " + m_output_file + " 2>&1";
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

    unlink(config_file.c_str());
    int unused __attribute__((unused)) = system(("rm -rf " + report_dir).c_str());
}

/**
 * @test output.config_reject_worker_threads_with_poll_group
 * @brief
 *    XLIO rejects poll group creation when worker_threads is configured.
 *
 * @details
 *    Setting performance.threading.worker_threads > 0 alongside Ultra API
 *    poll groups is an invalid configuration combination.  XLIO must detect
 *    this at xlio_poll_group_create() time and fail with EINVAL plus a clear
 *    error message.
 *
 *    A compiled helper binary (inheriting LD_PRELOAD from the gtest runner)
 *    retrieves the API via xlio_get_api() and attempts xlio_poll_group_create().
 *    The config file sets worker_threads=1, causing the call to be rejected.
 */
TEST_F(output, config_reject_worker_threads_with_poll_group)
{
    std::string full_config = m_prefix + "/config-ultra-api-worker-threads.json";

    // Locate the helper binary relative to the gtest binary.
    std::string helper;
    if (m_workspace) {
        helper = std::string(m_workspace) + "/tests/gtest/poll_group_worker_threads_helper";
    } else {
        helper = "./poll_group_worker_threads_helper";
    }

    std::string cmd = "XLIO_USE_NEW_CONFIG=1 XLIO_CONFIG_FILE=" + full_config + " " + helper +
        " > " + m_output_file + " 2>&1";

    int rc = system(cmd.c_str());
    ASSERT_NE(rc, 0) << "xlio_poll_group_create should have failed with worker threads configured";

    std::ifstream ifs(m_output_file);
    std::string text(std::istreambuf_iterator<char>(ifs), {});
    ifs.close();

    ASSERT_TRUE(text.find("Cannot create poll group") != std::string::npos)
        << "Expected error about poll group incompatibility with worker threads in output:"
        << std::endl
        << text;
    ASSERT_TRUE(text.find("incompatible with worker threads") != std::string::npos)
        << "Expected specific incompatibility message in output:" << std::endl
        << text;
}

/**
 * @test output.config_reject_worker_threads_with_xlio_init_ex
 * @brief
 *    XLIO rejects xlio_init_ex() when worker_threads is configured.
 *
 * @details
 *    When performance.threading.worker_threads > 0, xlio_init_ex() must
 *    reject the call before any Ultra API initialization proceeds.  The
 *    check runs before the g_init_global_ctors_done early-return gate,
 *    ensuring it fires even when XLIO is already fully initialized via
 *    LD_PRELOAD (as opposed to the defense-in-depth check in
 *    xlio_poll_group_create tested above).
 *
 *    A compiled helper binary (inheriting LD_PRELOAD from the gtest runner)
 *    retrieves the API via xlio_get_api() and calls xlio_init_ex() as the
 *    very first XLIO Ultra API call.  The config file sets worker_threads=1,
 *    causing xlio_init_ex() to detect the incompatibility and return an error.
 */
TEST_F(output, config_reject_worker_threads_with_xlio_init_ex)
{
    std::string full_config = m_prefix + "/config-ultra-api-worker-threads.json";

    std::string helper;
    if (m_workspace) {
        helper = std::string(m_workspace) + "/tests/gtest/xlio_init_ex_worker_threads_helper";
    } else {
        helper = "./xlio_init_ex_worker_threads_helper";
    }

    std::string cmd = "XLIO_USE_NEW_CONFIG=1 XLIO_CONFIG_FILE=" + full_config + " " + helper +
        " > " + m_output_file + " 2>&1";

    int rc = system(cmd.c_str());
    ASSERT_NE(rc, 0) << "xlio_init_ex should have failed with worker threads configured";

    std::ifstream ifs(m_output_file);
    std::string text(std::istreambuf_iterator<char>(ifs), {});
    ifs.close();

    ASSERT_TRUE(text.find("Ultra API (xlio_init_ex)") != std::string::npos)
        << "Expected incompatibility error from xlio_init_ex in output:" << std::endl
        << text;
    ASSERT_TRUE(text.find("incompatible with worker threads") != std::string::npos)
        << "Expected incompatibility message in output:" << std::endl
        << text;
}
