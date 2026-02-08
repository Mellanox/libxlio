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
        std::string cmd = "XLIO_USE_NEW_CONFIG=1 XLIO_CONFIG_FILE=" + full_filename + " ls";
        exec_cmd_to_file(cmd, output_file);

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
            "XLIO INFO   : Source port stride             3                          [applications.nginx.src_port_stride, Reason: Configuration-file]",
            // Simple string
            "Daemon working directory       /funny-dir                 [core.daemon.dir, Reason: Configuration-file]",
        #ifdef DEFINED_UTLS
            // Simple boolean
            "Enable TLS RX offload          true                       [hardware_features.tcp.tls_offload.rx_enable, Reason: Configuration-file]",
            // 4096 is shown as 4K
            "DEK max cache size             4K                         [hardware_features.tcp.tls_offload.dek_cache_max_size, Reason: Configuration-file]",
        #endif
            "Enable hugepages               false                      [core.resources.hugepages.enable, Reason: Configuration-file]",
            // Boolean with translation from bool to multilock_t and back
            "Use mutex instead of spinlocks true                       [performance.threading.mutex_over_spinlock, Reason: Configuration-file]",
            // CONFIG_VAR_PROGRESS_ENGINE_INTERVAL is a special case, 0 is shown as '0 (Disabled)'
            "Periodic drain interval (msec) 0 (Disabled)               [performance.completion_queue.periodic_drain_msec, Reason: Auto-Corrected]",
            // Another simple string
            "CPU affinity                   1,2,3                      [performance.threading.cpu_affinity, Reason: Configuration-file]",
            // Enum value is shown as a string
            "XLIO INFO   : Exception handling mode        log_error_undo_offload     [core.exception_handling.mode, Reason: Configuration-file]",
            // Not a power of 1024, hence shown in full accuracy
            "XLIO INFO   : RX poll duration (µsec)       2049                       [performance.polling.blocking_rx_poll_usec, Reason: Configuration-file]",
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
            "XLIO INFO   : Timer resolution (msec)        32                         [performance.threading.internal_handler.timer_msec, Reason: Profile]"
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
            "XLIO INFO   : RX poll duration (µsec)       -1                         [performance.polling.blocking_rx_poll_usec, Reason: Configuration-file]",
            "XLIO INFO   : Select/poll duration (µsec)   -1                         [performance.polling.iomux.poll_usec, Reason: Configuration-file]",
            "XLIO INFO   : Offload transition poll count  -1                         [performance.polling.offload_transition_poll_count, Reason: Configuration-file]"
                   // clang-format on
               },
               {// These huge values should NOT appear - they indicate the signed-to-unsigned bug
                "18446744073709551614", "18446744073709551615"});
}
