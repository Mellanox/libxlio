/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/*
 * Deterministic RED->GREEN regression gate for the listener co-sink fix
 * ("tcp: detach listener RFS sink at close, not at destructor").
 *
 * THE FIX: when a listener is closed while it still holds a live accepted child
 * (sockinfo_tcp::m_child_refs > 0, so its destruction is deferred),
 * prepare_listen_to_close() now detaches the listener's RX sink/flow at CLOSE
 * (shutdown_rx), instead of only at the deferred destructor. A replacement
 * listener on the same address then serves new connections immediately. Before
 * the fix the old listener's stale sink stayed at ring sink-list index 0 and
 * SILENTLY DROPPED new SYNs meant for the replacement until the held child
 * closed (the Envoy LDS same-address-update black hole).
 *
 * WHY THIS IS DETERMINISTIC (unlike tcp_listener_churn, which is a flaky
 * leak-balance exerciser gated behind an env var): under SO_REUSEPORT all
 * listeners on one server IP:port share a single offloaded rfs_uc sink list, and
 * rfs_uc::rx_dispatch_packet walks that list index-0-first, giving the packet to
 * the first sink whose rx_input_cb consumes it (NOT a kernel-style per-4-tuple
 * hash). So a stale index-0 sink deterministically swallows EVERY new SYN on a
 * pre-fix build, and the helper reports a lost/timed-out new connection ->
 * this test FAILS (RED). On the fixed build the sink is detached at close, the
 * replacement listener shifts to index 0, every probe is served, and the helper
 * prints PASS (GREEN). See tcp_listener_cosink_helper.cc for the full mechanism.
 *
 * ENABLED BY DEFAULT: the scenario is low-churn (one connection per held
 * listener, a single batch of closes, a bounded number of new connections) with
 * NO concurrent RX flood and with every child closed only after all probing, so
 * it does not trip the separate, still-unfixed sink-path RX-dispatch UAF
 * (ring_slave.cpp:565) that the churn test must guard against - that bug needs a
 * heavy RX flood racing a close. This test closes listeners while quiescent.
 *
 * What it asserts, in a fresh helper process over two offloadable mlx5 IPs
 * (loopback/0.0.0.0 is kernel passthrough and exercises nothing in XLIO, so we
 * skip rather than report a false green):
 *   1. No crash: the helper reached PASS (a crash exits non-zero, never PASS).
 *   2. New connections served: NEW_CONN_TIMEOUT == 0 and NEW_CONN_OK == probes
 *      (the helper itself exits non-zero if any new connection was lost, which
 *      exec_cmd_to_file turns into a test failure - this is the RED signal).
 *   3. Offload confirmed: the tuning report shows non_offloaded_sockets == 0, so
 *      the run was on the XLIO offload path and not a silent kernel fallback
 *      (the CAP_NET_RAW / loopback false-green trap).
 */

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <string>

#include "common/def.h"
#include "common/log.h"
#include "common/subprocess_test.h"
#include "common/sys.h"

class tcp_listener_cosink : public subprocess_test {
protected:
    // Pull a numeric value that follows "<key>" in the report/output text.
    // Returns false if the key is absent.
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
};

TEST_F(tcp_listener_cosink, replacement_served_after_closing_busy_listener)
{
    const struct sockaddr *server =
        reinterpret_cast<const struct sockaddr *>(&gtest_conf.server_addr);
    const struct sockaddr *client =
        reinterpret_cast<const struct sockaddr *>(&gtest_conf.client_addr);
    std::string server_ip = sys_addr2str(server, false);
    std::string client_ip = sys_addr2str(client, false);

    // XLIO refuses to offload the any-address and loopback by design, so without
    // two real mlx5 IPs this would silently exercise the kernel (where the bug
    // does not exist). Skip rather than report a false green. This rejects only
    // the obvious non-offloadable addresses; the helper additionally probes the
    // live datapath and emits SKIP: (handled below) when two real mlx5 IPs still
    // cannot carry a same-host offloaded round-trip, so this test stays a clean
    // skip on an incompatible lab instead of failing as the bug.
    auto not_offloadable = [](const std::string &ip) {
        return ip.empty() || ip == "0.0.0.0" || ip == "::" || ip.rfind("127.", 0) == 0;
    };
    if (not_offloadable(server_ip) || not_offloadable(client_ip)) {
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
    // non_offloaded destructor counters we assert on.
    std::string inline_cfg = "monitor.report.mode=enable;monitor.report.file_path=" + report;
    std::string cmd = "XLIO_USE_NEW_CONFIG=1 XLIO_CONFIG_FILE=" + config +
        " XLIO_INLINE_CONFIG=\"" + inline_cfg + "\" " + helper + " --server " + server_ip +
        " --client " + client_ip + " --port " + std::to_string(port);

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

    // (3) Offload confirmed: no socket fell back to the kernel path. Guards the
    // CAP_NET_RAW silent-fallback / loopback passthrough false-green - on the
    // kernel path reuse_port is hashed per-4-tuple and the bug cannot reproduce,
    // so a kernel run would be a meaningless green.
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
