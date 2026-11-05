/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/*
 * Churn + destructor-balance guard for the listener child reference count
 * (deferred listener delete). A helper process closes and re-opens a listener
 * under load with children held across each close; half-open (RST) clients
 * exercise the handshake-failure callback. Asserts: helper reached PASS, run
 * stayed offloaded, offloaded-destructor count inside [floor, ceiling].
 * Gotcha - opt-in via XLIO_GTEST_RUN_LISTENER_CHURN=1: default-mode churn also
 * trips a separate, still-open sink-path RX-dispatch UAF (check_rx_packet,
 * ring_slave.cpp) that crashes pre-fix and fixed builds alike.
 */

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <string>

#include "common/def.h"
#include "common/log.h"
#include "common/subprocess_test.h"
#include "common/sys.h"

class tcp_listener_churn : public subprocess_test {};

TEST_F(tcp_listener_churn, churn_under_load_no_uaf_no_leak)
{
    // Opt-in only: default-mode listener churn flakily hits a separate, unfixed
    // sink-path UAF that crashes both the fixed and the pre-fix build (see the
    // file header). Keep it out of the default gate until that bug is fixed.
    const char *run = std::getenv("XLIO_GTEST_RUN_LISTENER_CHURN");
    if (!run || run[0] != '1') {
        GTEST_SKIP() << "Disabled by default: default-mode listener churn triggers a separate, "
                        "still-unfixed sink-path RX-dispatch UAF (ring_slave.cpp check_rx_packet) "
                        "that crashes both fixed and pre-fix builds. Set "
                        "XLIO_GTEST_RUN_LISTENER_CHURN=1 to run as a leak-balance exerciser.";
    }

    const struct sockaddr *server =
        reinterpret_cast<const struct sockaddr *>(&gtest_conf.server_addr);
    const struct sockaddr *client =
        reinterpret_cast<const struct sockaddr *>(&gtest_conf.client_addr);
    std::string server_ip = sys_addr2str(server, false);
    std::string client_ip = sys_addr2str(client, false);

    // XLIO refuses to offload the any-address and loopback by design, so without
    // two real mlx5 IPs this would silently exercise the kernel. Skip rather than
    // report a false green.
    if (!addr_offloadable(server_ip) || !addr_offloadable(client_ip)) {
        GTEST_SKIP() << "Two offloadable mlx5 IPs are required (got server='" << server_ip
                     << "' client='" << client_ip << "'); pass --addr=<mlx5>,<mlx5>.";
    }

    // Distinct from the default suite port (55555) so this test's repeated
    // listener churn does not collide with other suites' TIME_WAIT 4-tuples.
    const uint16_t port = static_cast<uint16_t>(gtest_conf.port + 7);
    const std::string report = "/tmp/xlio_churn_report_" + std::to_string(getpid()) + ".txt";
    unlink(report.c_str());

    // The new-config json loader always opens a config file (XLIO_CONFIG_FILE, or
    // /etc/libxlio_config.json when unset), so hand the helper a minimal stub to
    // keep the run hermetic on hosts without the default file; the report keys
    // travel via XLIO_INLINE_CONFIG, which takes priority over the file.
    const std::string config = "/tmp/xlio_churn_config_" + std::to_string(getpid()) + ".json";
    std::ofstream(config) << "{}";

    std::string helper = helper_path("tcp_listener_churn_helper");
    // Enable the tuning report so the helper's exit path writes the destructor
    // counters we assert on. "timeout 120" bounds a wedged helper to a single
    // failed test, not a CI-leg kill. --half-open 1 exercises the
    // handshake-failure callback path, not only the TIME_WAIT one.
    std::string inline_cfg = "monitor.report.mode=enable;monitor.report.file_path=" + report;
    std::string cmd = "XLIO_USE_NEW_CONFIG=1 XLIO_CONFIG_FILE=" + config +
        " XLIO_INLINE_CONFIG=\"" + inline_cfg + "\" timeout 120 " + helper + " --server " +
        server_ip + " --client " + client_ip + " --port " + std::to_string(port) + " --half-open 1";

    // exec_cmd_to_file throws (fails the test) if the helper exits non-zero, which
    // is exactly the signal/crash case for a UAF double-free.
    exec_cmd_to_file(cmd, m_output_file);
    unlink(config.c_str());
    std::string output = read_file(m_output_file);

    if (output.find("SKIP:") != std::string::npos) {
        GTEST_SKIP() << output;
    }

    // (1) No crash: the helper ran to completion.
    ASSERT_NE(std::string::npos, output.find("PASS"))
        << "Helper did not reach PASS - a crash or early exit during churn:\n"
        << output;

    uint64_t listeners_opened = 0, children_accepted = 0;
    uint64_t client_sockets = 0, probe_listeners = 0, connects_initiated = 0;
    ASSERT_TRUE(find_u64(output, "LISTENERS_OPENED ", listeners_opened)) << output;
    ASSERT_TRUE(find_u64(output, "CHILDREN_ACCEPTED ", children_accepted)) << output;
    ASSERT_TRUE(find_u64(output, "CLIENT_SOCKETS_OPENED ", client_sockets)) << output;
    ASSERT_TRUE(find_u64(output, "CONNECTS_INITIATED ", connects_initiated)) << output;
    ASSERT_TRUE(find_u64(output, "PROBE_LISTENERS ", probe_listeners)) << output;
    // The churn must have actually opened listeners and cloned children, else the
    // balance assertions below are vacuous.
    ASSERT_GT(listeners_opened, 0U) << "No listeners were opened:\n" << output;
    ASSERT_GT(children_accepted, 0U) << "No connections were accepted - the load never landed:\n"
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
    // CAP_NET_RAW silent-fallback / loopback passthrough false-green.
    ASSERT_EQ(0U, non_offloaded)
        << "Churn ran on the kernel path, not XLIO (non_offloaded=" << non_offloaded
        << "). Re-run under CAP_NET_RAW with two mlx5 --addr IPs.\nReport:\n"
        << rpt;

    // (2) Destructor balance, two-sided: every opened socket runs one offloaded
    // destructor (floor; an unfired deferred delete breaks it), server clones
    // cannot exceed initiated connects (ceiling; a double-delete overshoots it).
    // A leak below the gap can hide; the lab run under load is the UAF gate.
    const uint64_t floor_count =
        listeners_opened + children_accepted + client_sockets + probe_listeners;
    const uint64_t ceiling =
        listeners_opened + connects_initiated + client_sockets + probe_listeners;
    ASSERT_GE(offloaded, floor_count)
        << "Leaked listen/child sockinfo: " << floor_count << " sockets opened ("
        << listeners_opened << " listeners + " << children_accepted << " accepted + "
        << client_sockets << " clients + " << probe_listeners << " probe), but only " << offloaded
        << " offloaded destructors ran. A deferred delete did not fire.\nReport:\n"
        << rpt;
    ASSERT_LE(offloaded, ceiling) << "Destructor overshoot: " << offloaded
                                  << " offloaded destructors above the ceiling " << ceiling << " ("
                                  << listeners_opened << " listeners + " << connects_initiated
                                  << " connects initiated + " << client_sockets << " clients + "
                                  << probe_listeners
                                  << " probe). A socket was destroyed twice.\nReport:\n"
                                  << rpt;

    log_trace("churn ok: listeners=%llu children=%llu initiated=%llu offloaded_dtors=%llu "
              "non_offloaded=%llu\n",
              static_cast<unsigned long long>(listeners_opened),
              static_cast<unsigned long long>(children_accepted),
              static_cast<unsigned long long>(connects_initiated),
              static_cast<unsigned long long>(offloaded),
              static_cast<unsigned long long>(non_offloaded));
}
