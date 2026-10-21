/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/*
 * Churn + leak-balance regression guard for the listen-socket reference count
 * (sockinfo_tcp::m_child_refs) that fixes the use-after-free during listener
 * teardown under load (the Envoy LDS-update pattern). A listener is closed and
 * re-opened on the same port while cloned children are still alive and holding a
 * reference on it; each accepted child clones off the listener
 * (clone_conn_cb -> child_ref_acquire) and releases its reference in
 * ~sockinfo_tcp. clean_socket_obj() must defer the listener delete until the
 * last child releases, so a close() under load cannot free the listener while a
 * child is still inside handle_incoming_handshake_failure() (the m_parent deref
 * that crashed on the pre-fix build) or syn_received_timewait_cb().
 *
 * What it checks, in a fresh helper process over two offloadable mlx5 IPs
 * (loopback/0.0.0.0 is kernel passthrough and exercises nothing in XLIO):
 *   1. No crash across the churn: a refcount double-free makes the helper die by
 *      signal, so it exits non-zero and never prints PASS.
 *   2. No leaked listen sockinfo: the helper reports how many sockets it opened
 *      (listeners + accepted children); XLIO's offloaded-socket destructor
 *      counter (socket_offloaded_destructor_counter, read back via the tuning
 *      report) must account for at least that many. A listener whose deferred
 *      delete never fires (refcount leak) leaves its destructor uncalled and
 *      drops the count below what was created.
 *   3. The churn ran on the XLIO offload path, not a silent kernel fallback (the
 *      CAP_NET_RAW / loopback false-green trap): the report must show zero
 *      non-offloaded sockets.
 *
 * SCOPE AND WHY THIS IS OPT-IN (XLIO_GTEST_RUN_LISTENER_CHURN=1):
 *
 * The listener-UAF fix is lab-validated by a RED->GREEN under Envoy (worker
 * threads mode): the pre-fix .so crashes within 1-2 aggressive same-address LDS
 * updates under a wrk flood, the fixed .so survives N iterations. That remains
 * the authoritative evidence for the fix.
 *
 * This in-process gtest, run in the DEFAULT (non-worker) XLIO mode that a plain
 * BSD-socket harness uses, reproduces a DIFFERENT and still-unfixed member of
 * the same use-after-free family: a sink-path RX-dispatch UAF on the internal
 * thread -
 *     check_rx_packet (ring_slave.cpp:565)  si->rx_input_cb(...)   <- SEGV
 *     ring_slave::rx_process_buffer -> cq_mgr_rx ... ->
 *     net_device_table_mgr::global_ring_drain_and_procces ->
 *     timer::process_registered_timers -> event_handler_thread
 * The internal-thread ring drain dispatches an RX packet to a socket sink whose
 * sockinfo was freed by the concurrent close. Lab-measured on dor03 (CX7 b2b,
 * two mlx5 ports, one host): it crashes flakily on BOTH the fixed (HEAD) AND the
 * pre-fix build, at loads as low as 1 client thread / 10 connections / 6 churn
 * iterations (~2/8 runs). It is build- and fix-INDEPENDENT (the refcount fix
 * guards the LISTENER against its children; this is a CHILD sink freed under the
 * RX drain - outside that scope), so it is not a regression of this change; it is
 * the separate "sink-path follow-up" already flagged in the fix's own notes.
 *
 * Consequently this test cannot be a crash-based gate for the refcount fix: any
 * default-mode listener churn with offloaded connections flakily hits the unfixed
 * sink-path UAF, which crashes both builds, so it neither stays green on HEAD nor
 * distinguishes fixed from pre-fix. It is therefore DISABLED by default (skips
 * with this explanation) and runs only when XLIO_GTEST_RUN_LISTENER_CHURN=1, as a
 * leak-balance / investigation exerciser. Once the sink-path UAF is fixed, drop
 * the gate so this becomes an always-on leak-balance regression guard.
 */

#include <cstdint>
#include <cstdlib>
#include <string>

#include "common/def.h"
#include "common/log.h"
#include "common/subprocess_test.h"
#include "common/sys.h"

class tcp_listener_churn : public subprocess_test {
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

TEST_F(tcp_listener_churn, churn_under_load_no_uaf_no_leak)
{
    // Opt-in only: default-mode listener churn flakily hits a separate, unfixed
    // sink-path UAF that crashes both the fixed and the pre-fix build (see the
    // file header). Keep it out of the default gate until that bug is fixed.
    const char *run = std::getenv("XLIO_GTEST_RUN_LISTENER_CHURN");
    if (!run || run[0] != '1') {
        GTEST_SKIP() << "Disabled by default: default-mode listener churn triggers a separate, "
                        "still-unfixed sink-path RX-dispatch UAF (ring_slave.cpp:565) that crashes "
                        "both fixed and pre-fix builds. Set XLIO_GTEST_RUN_LISTENER_CHURN=1 to run "
                        "as a leak-balance exerciser. The fix itself is lab-validated by the Envoy "
                        "RED->GREEN.";
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
    auto not_offloadable = [](const std::string &ip) {
        return ip.empty() || ip == "0.0.0.0" || ip == "::" || ip.rfind("127.", 0) == 0;
    };
    if (not_offloadable(server_ip) || not_offloadable(client_ip)) {
        GTEST_SKIP() << "Two offloadable mlx5 IPs are required (got server='" << server_ip
                     << "' client='" << client_ip << "'); pass --addr=<mlx5>,<mlx5>.";
    }

    // Distinct from the default suite port (55555) so this test's repeated
    // listener churn does not collide with other suites' TIME_WAIT 4-tuples.
    const uint16_t port = static_cast<uint16_t>(gtest_conf.port + 7);
    const std::string report = "/tmp/xlio_churn_report_" + std::to_string(getpid()) + ".txt";
    unlink(report.c_str());

    std::string helper = helper_path("tcp_listener_churn_helper");
    // Enable the tuning report so the helper's exit path writes the destructor
    // counters we assert on. A minimal inline config is enough; the destructor
    // counters are always collected (independent of monitor.stats.fd_num).
    std::string inline_cfg = "monitor.report.mode=enable;monitor.report.file_path=" + report;
    std::string cmd = "XLIO_USE_NEW_CONFIG=1 XLIO_INLINE_CONFIG=\"" + inline_cfg + "\" " + helper +
        " --server " + server_ip + " --client " + client_ip + " --port " + std::to_string(port);

    // exec_cmd_to_file throws (fails the test) if the helper exits non-zero, which
    // is exactly the signal/crash case for a UAF double-free.
    exec_cmd_to_file(cmd, m_output_file);
    std::string output = read_file(m_output_file);

    if (output.find("SKIP:") != std::string::npos) {
        GTEST_SKIP() << output;
    }

    // (1) No crash: the helper ran to completion.
    ASSERT_NE(std::string::npos, output.find("PASS"))
        << "Helper did not reach PASS - a crash or early exit during churn:\n"
        << output;

    uint64_t listeners_opened = 0, children_accepted = 0;
    ASSERT_TRUE(find_u64(output, "LISTENERS_OPENED ", listeners_opened)) << output;
    ASSERT_TRUE(find_u64(output, "CHILDREN_ACCEPTED ", children_accepted)) << output;
    // The churn must have actually opened listeners and cloned children, else the
    // leak assertion below is vacuous.
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

    // (2) No leaked listen sockinfo: every socket the helper opened on the server
    // side (listeners + accepted children) must have had its offloaded destructor
    // run. A listener whose deferred delete never fires drops the count below what
    // was created.
    const uint64_t server_side_created = listeners_opened + children_accepted;
    ASSERT_GE(offloaded, server_side_created)
        << "Leaked listen/child sockinfo: opened " << listeners_opened << " listeners + accepted "
        << children_accepted << " children (" << server_side_created << " server-side), but only "
        << offloaded
        << " offloaded destructors ran. A listener's deferred delete did not fire.\nReport:\n"
        << rpt;

    log_trace("churn ok: listeners=%llu children=%llu offloaded_dtors=%llu non_offloaded=%llu\n",
              static_cast<unsigned long long>(listeners_opened),
              static_cast<unsigned long long>(children_accepted),
              static_cast<unsigned long long>(offloaded),
              static_cast<unsigned long long>(non_offloaded));
}
