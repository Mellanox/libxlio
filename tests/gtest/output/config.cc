/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2022-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

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
        } else {
            std::cout << "WORKSPACE is not set" << std::endl;
        }
    }

protected:
    void exec_cmd(const std::string &cmd)
    {
        int rc = system(cmd.c_str());
        if (rc != 0) {
            throw std::runtime_error("system('" + cmd + "') failed!");
        }
    }

    void check_file(const std::string &filename, const std::vector<const char *> &expected_strings,
                    const std::vector<const char *> &unexpected_strings = {})
    {
        std::string full_filename = filename;

        std::string prefix;
        if (m_workspace) {
            prefix = std::string(m_workspace) + "/tests/gtest/output";
        } else {
            // Assume we are running from gtest/
            prefix = "output";
        }
        full_filename = prefix + "/" + filename;
        std::string output_file = prefix + "/output.txt";

        // LD_PRELOAD is already set for the gtest, it is inherited by the new process, no need
        // to do anything
        // The syntax '[command] > [file] 2>&1' works for both bash and dash
        std::string cmd = "XLIO_USE_NEW_CONFIG=1 XLIO_CONFIG_FILE=" + full_filename + " ls > " +
            output_file + " 2>&1";
        exec_cmd(cmd);

        // Read the output file
        std::ifstream ifs(output_file);
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

    // nullptr if WORKSPACE env var is not set
    char *m_workspace {nullptr};
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
            "XLIO INFO   : Source port stride             3                          [applications.nginx.src_port_stride]",
            // Simple string
            "Daemon working directory       /funny-dir                 [core.daemon.dir]",
            // Simple boolean
            "Enable TLS RX offload          true                       [hardware_features.tcp.tls_offload.rx_enable]",
            // 4096 is shown as 4K
            "DEK max cache size             4K                         [hardware_features.tcp.tls_offload.dek_cache_max_size]",
            // CONFIG_VAR_PROGRESS_ENGINE_INTERVAL is a special case, 0 is shown as '0 (Disabled)'
            "Periodic drain interval (msec) 0 (Disabled)               [performance.completion_queue.periodic_drain_msec]",
            // Another simple string
            "CPU affinity                   1,2,3                      [performance.threading.cpu_affinity]",
            // Enum value is shown as a string
            "TX ring allocation logic       per_socket                 [performance.rings.tx.allocation_logic]",
            // Not a power of 1024, hence shown in full accuracy
            "XLIO INFO   : RX poll duration (µsec)       2049                       [performance.polling.blocking_rx_poll_usec]",
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
            "XLIO INFO   :                                Action 0 of rule f         [acceleration_control.rules[5].actions[0]]"
            // clang-format on
        });
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
            "XLIO INFO   : RX poll duration (µsec)       -1                         [performance.polling.blocking_rx_poll_usec]",
            "XLIO INFO   : Select/poll duration (µsec)   -1                         [performance.polling.iomux.poll_usec]",
            "XLIO INFO   : Offload transition poll count  -1                         [performance.polling.offload_transition_poll_count]"
                   // clang-format on
               },
               {// These huge values should NOT appear - they indicate the signed-to-unsigned bug
                "18446744073709551614", "18446744073709551615"});
}

/**
 * @test misc.config_periodic_drain_max_cqes_zero
 * @brief
 *    Tests that periodic_drain_max_cqes=0 shows the correct parameter in output
 *
 * @details
 *    When user sets periodic_drain_max_cqes to 0, the log should show that specific
 *    parameter with value 0 and the correct config key, not a different parameter name.
 */
TEST_F(output, config_periodic_drain_max_cqes_zero)
{
    check_file("config-periodic-drain-max-cqes-zero.json",
               {
                   // clang-format off
            // Should show the parameter that was explicitly set to 0 with correct key
            "Periodic drain max CQEs",
            "0 (Disabled)",
            "[performance.completion_queue.periodic_drain_max_cqes]"
                   // clang-format on
               },
               {// Should NOT show the old combined "CQ Drain Thread" message
                "CQ Drain Thread"});
}
