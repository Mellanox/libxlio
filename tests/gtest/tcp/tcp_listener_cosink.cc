/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/*
 * Deterministic regression gate for "detach listener RFS sink at close, not at
 * destructor". reuse_port listeners of one 3-tuple share one rfs_uc sink list
 * with index-0-first dispatch; pre-fix, a closed listener whose destruction is
 * deferred kept its stale sink at index 0 and silently swallowed every new SYN
 * meant for the live replacement listener. The helper fails on a probe timeout
 * (RED); the test also asserts the run stayed offloaded (non_offloaded == 0).
 * Skips without two offloadable mlx5 IPs or when the helper's datapath probe
 * fails. Gotcha: runs by default - every close here is quiescent, clear of the
 * separate sink-path RX-dispatch UAF that keeps tcp_listener_churn opt-in.
 */

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <string>

#include "common/def.h"
#include "common/log.h"
#include "common/subprocess_test.h"
#include "common/sys.h"

class tcp_listener_cosink : public subprocess_test {};

TEST_F(tcp_listener_cosink, replacement_served_after_closing_busy_listener)
{
    const struct sockaddr *server =
        reinterpret_cast<const struct sockaddr *>(&gtest_conf.server_addr);
    const struct sockaddr *client =
        reinterpret_cast<const struct sockaddr *>(&gtest_conf.client_addr);
    std::string server_ip = sys_addr2str(server, false);
    std::string client_ip = sys_addr2str(client, false);

    // XLIO refuses to offload the any-address and loopback by design (and the
    // kernel path hashes reuse_port per-4-tuple, so the bug cannot reproduce
    // there). Skip rather than report a false green; the helper additionally
    // probes the live datapath and emits SKIP: on an incompatible lab.
    if (!addr_offloadable(server_ip) || !addr_offloadable(client_ip)) {
        GTEST_SKIP() << "Two offloadable mlx5 IPs are required (got server='" << server_ip
                     << "' client='" << client_ip << "'); pass --addr=<mlx5>,<mlx5>.";
    }

    // Distinct from the default suite port (55555) and from the churn test's
    // port (+7) so repeated listener open/close does not collide with other
    // suites' TIME_WAIT 4-tuples.
    const uint16_t port = static_cast<uint16_t>(gtest_conf.port + 9);
    const std::string report = "/tmp/xlio_cosink_report_" + std::to_string(getpid()) + ".txt";
    unlink(report.c_str());

    // The new-config json loader always opens a config file (XLIO_CONFIG_FILE, or
    // /etc/libxlio_config.json when unset), so hand the helper a minimal stub to
    // keep the run hermetic on hosts without the default file; the report keys
    // travel via XLIO_INLINE_CONFIG, which takes priority over the file.
    const std::string config = "/tmp/xlio_cosink_config_" + std::to_string(getpid()) + ".json";
    std::ofstream(config) << "{}";

    std::string helper = helper_path("tcp_listener_cosink_helper");
    // Enable the tuning report so the helper's exit path writes the offloaded /
    // non_offloaded destructor counters we assert on. "timeout 120" bounds a
    // wedged helper to a single failed test, not a CI-leg kill.
    std::string inline_cfg = "monitor.report.mode=enable;monitor.report.file_path=" + report;
    std::string cmd = "XLIO_USE_NEW_CONFIG=1 XLIO_CONFIG_FILE=" + config +
        " XLIO_INLINE_CONFIG=\"" + inline_cfg + "\" timeout 120 " + helper + " --server " +
        server_ip + " --client " + client_ip + " --port " + std::to_string(port);

    // exec_cmd_to_file throws (fails the test) if the helper exits non-zero,
    // which is exactly the RED signal: a lost/timed-out new connection (pre-fix
    // black hole) or a crash. A lab-incompatibility (two mlx5 IPs with no
    // same-host datapath) exits zero with SKIP: instead, so it does not throw.
    exec_cmd_to_file(cmd, m_output_file);
    unlink(config.c_str());
    std::string output = read_file(m_output_file);

    // The helper prints SKIP: and exits zero when the datapath is unavailable
    // (not offloadable, or the two IPs cannot carry a same-host round-trip);
    // treat that as a clean skip, not a pass or a failure.
    if (output.find("SKIP:") != std::string::npos) {
        GTEST_SKIP() << output;
    }

    // (1) No crash / no lost connection: the helper ran to completion.
    ASSERT_NE(std::string::npos, output.find("PASS"))
        << "Helper did not reach PASS - a crash, early exit, or a new connection lost to a "
           "stale listener sink (the pre-fix co-sink black hole):\n"
        << output;

    uint64_t listeners_opened = 0, children_held = 0, new_conn_ok = 0, new_conn_timeout = 0;
    ASSERT_TRUE(find_u64(output, "LISTENERS_OPENED ", listeners_opened)) << output;
    ASSERT_TRUE(find_u64(output, "CHILDREN_HELD ", children_held)) << output;
    ASSERT_TRUE(find_u64(output, "NEW_CONN_OK ", new_conn_ok)) << output;
    ASSERT_TRUE(find_u64(output, "NEW_CONN_TIMEOUT ", new_conn_timeout)) << output;

    // The scenario must actually have been set up: multiple reuse_port listeners
    // and at least one held child (so a listener close deferred its destruction),
    // else the assertions below are vacuous.
    ASSERT_GE(listeners_opened, 2U) << "Need >= 2 reuse_port listeners (stale + live):\n" << output;
    ASSERT_GT(children_held, 0U)
        << "No child was held across the close - no listener destruction was deferred, so the "
           "co-sink overlap was never created:\n"
        << output;
    ASSERT_GT(new_conn_ok, 0U) << "No new connections were probed:\n" << output;

    // (2) The core assertion: every new connection to the live replacement
    // listener was served. On a pre-fix build the stale index-0 sink black-holes
    // them and this is non-zero (and the helper already failed non-zero above).
    ASSERT_EQ(0U, new_conn_timeout)
        << "A new connection to the live reuse_port listener was lost/timed out after closing a "
           "co-sink listener that still held a child - the stale sink was not detached at close "
           "(pre-fix co-sink black hole). served="
        << new_conn_ok << " lost=" << new_conn_timeout << ":\n"
        << output;

    std::string rpt = read_file(report);
    unlink(report.c_str());

    uint64_t offloaded = 0, non_offloaded = 0;
    ASSERT_TRUE(find_u64(rpt, "offloaded_sockets: ", offloaded))
        << "offloaded_sockets missing from report:\n"
        << rpt;
    ASSERT_TRUE(find_u64(rpt, "non_offloaded_sockets: ", non_offloaded))
        << "non_offloaded_sockets missing from report:\n"
        << rpt;

    // (3) Offload confirmed: no socket fell back to the kernel path (where the
    // co-sink overlap does not exist and a green would be meaningless). Guards
    // the CAP_NET_RAW silent-fallback / loopback passthrough false-green.
    ASSERT_EQ(0U, non_offloaded)
        << "Run was on the kernel path, not XLIO (non_offloaded=" << non_offloaded
        << "); the co-sink overlap only exists on the offload path. Re-run under CAP_NET_RAW with "
           "two mlx5 --addr IPs.\nReport:\n"
        << rpt;
    ASSERT_GT(offloaded, 0U) << "No offloaded sockets recorded - nothing ran on XLIO:\n" << rpt;

    log_trace("cosink ok: listeners=%llu children_held=%llu new_ok=%llu new_timeout=%llu "
              "offloaded=%llu non_offloaded=%llu\n",
              static_cast<unsigned long long>(listeners_opened),
              static_cast<unsigned long long>(children_held),
              static_cast<unsigned long long>(new_conn_ok),
              static_cast<unsigned long long>(new_conn_timeout),
              static_cast<unsigned long long>(offloaded),
              static_cast<unsigned long long>(non_offloaded));
}
