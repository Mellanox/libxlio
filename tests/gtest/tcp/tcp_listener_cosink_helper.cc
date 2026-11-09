/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/*
 * Helper for tcp_listener_cosink: reuse_port listeners on one 3-tuple share
 * one rfs_uc sink list, dispatched index-0-first. Close the first N-1
 * listeners, each holding one accepted child (destruction defers), then probe
 * fresh connections against the surviving listener. Pre-fix the stale index-0
 * sink swallows every probe SYN: bounded timeout, non-zero exit (RED). Gotcha:
 * all children close only after all probing, so no close ever races an RX.
 * Output contract (parsed by the test): SKIP: <reason> | LISTENERS_OPENED <n>
 * | CHILDREN_HELD <n> | NEW_CONN_OK <n> | NEW_CONN_TIMEOUT <n> | PASS
 */

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "listener_test_utils.h"

namespace {

using listener_test::arg_value;
using listener_test::fill_addr;
using listener_test::open_listener;

struct options {
    std::string server_ip;
    std::string client_ip;
    uint16_t port = 0;
    // Number of reuse_port listeners. The first (listeners - 1) each hold a
    // child open and are closed; the last is the live replacement. >= 2.
    int listeners = 4;
    // Number of fresh connections probed after the close. Each must be served.
    int probes = 8;
    // Per-connection deadline for a new-connection round-trip. On a pre-fix
    // build the SYN is black-holed, so this bounds the hang; long enough that a
    // healthy offloaded connect never spuriously trips it.
    int conn_timeout_ms = 1500;
    int accept_backlog = 128;
};

using clock_type = std::chrono::steady_clock;

int ms_until(clock_type::time_point deadline)
{
    auto now = clock_type::now();
    if (now >= deadline) {
        return 0;
    }
    return static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
}

// Non-blocking client connect from a fresh ephemeral 4-tuple. Returns the
// connecting fd (still in progress) or -1.
int start_client(const options &opt)
{
    sockaddr_storage cli;
    socklen_t cli_len = fill_addr(cli, opt.client_ip, 0);
    int fd = socket(cli.ss_family, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    bind(fd, reinterpret_cast<sockaddr *>(&cli), cli_len);

    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    sockaddr_storage srv;
    socklen_t srv_len = fill_addr(srv, opt.server_ip, opt.port);
    int rc = connect(fd, reinterpret_cast<sockaddr *>(&srv), srv_len);
    if (rc != 0 && errno != EINPROGRESS && errno != EALREADY && errno != EISCONN) {
        close(fd);
        return -1;
    }
    return fd;
}

// Accept any pending child across the given listeners (non-blocking), echo one
// byte if the child sends one, and collect the accepted child fds so the caller
// keeps them open. Returns the number of children accepted this call.
int drain_accepts(const std::vector<int> &lfds, std::vector<int> &accepted_out, bool echo)
{
    int accepted = 0;
    for (int lfd : lfds) {
        for (;;) {
            int cfd = accept(lfd, nullptr, nullptr);
            if (cfd < 0) {
                break;
            }
            ++accepted;
            if (echo) {
                // Best-effort immediate echo: read-and-return one byte if ready.
                int fl = fcntl(cfd, F_GETFL, 0);
                fcntl(cfd, F_SETFL, fl | O_NONBLOCK);
                char b = 0;
                ssize_t n = recv(cfd, &b, 1, 0);
                if (n == 1) {
                    send(cfd, &b, 1, MSG_NOSIGNAL);
                }
            }
            accepted_out.push_back(cfd);
        }
    }
    return accepted;
}

// Drive ONE new connection to a full round-trip, servicing accept+echo on the
// live listener from the same thread. True only if connect -> send -> recv-echo
// completed before the deadline. Accepted children go to new_children; the
// caller keeps them alive until the end (a mid-run close is the separate UAF).
bool probe_once(const options &opt, int live_listener, std::vector<int> &new_children)
{
    int cfd = start_client(opt);
    if (cfd < 0) {
        return false;
    }

    auto deadline = clock_type::now() + std::chrono::milliseconds(opt.conn_timeout_ms);
    std::vector<int> live_list(1, live_listener);

    bool connected = false;
    bool sent = false;
    bool got_echo = false;

    // Make the live listener non-blocking so drain_accepts never blocks.
    {
        int fl = fcntl(live_listener, F_GETFL, 0);
        fcntl(live_listener, F_SETFL, fl | O_NONBLOCK);
    }

    while (ms_until(deadline) > 0 && !got_echo) {
        // Service the server side: accept the new child (if the SYN reached the
        // live listener) and echo its byte.
        drain_accepts(live_list, new_children, true);
        // Echo for children accepted in a previous iteration of this probe that
        // had not yet sent their byte when first accepted.
        for (int ch : new_children) {
            char b = 0;
            ssize_t n = recv(ch, &b, 1, MSG_DONTWAIT);
            if (n == 1) {
                send(ch, &b, 1, MSG_NOSIGNAL);
            }
        }

        struct pollfd pfd;
        pfd.fd = cfd;
        pfd.events = connected ? POLLIN : (POLLOUT | POLLIN);
        pfd.revents = 0;
        // Short poll slice so we keep servicing the listener promptly.
        int slice = ms_until(deadline);
        if (slice > 20) {
            slice = 20;
        }
        poll(&pfd, 1, slice);

        if (!connected) {
            int soerr = 0;
            socklen_t len = sizeof(soerr);
            if (getsockopt(cfd, SOL_SOCKET, SO_ERROR, &soerr, &len) == 0 && soerr == 0) {
                // Writable with no SO_ERROR == connected.
                if (pfd.revents & (POLLOUT | POLLIN)) {
                    connected = true;
                }
            } else if (soerr != 0) {
                break; // connection refused/errored
            }
        }
        if (connected && !sent) {
            char b = 'x';
            if (send(cfd, &b, 1, MSG_NOSIGNAL) == 1) {
                sent = true;
            }
        }
        if (sent && (pfd.revents & POLLIN)) {
            char in = 0;
            ssize_t n = recv(cfd, &in, 1, MSG_DONTWAIT);
            if (n == 1) {
                got_echo = true;
            }
        }
    }

    close(cfd);
    return got_echo;
}

// Baseline connectivity+offload probe: one plain listener, one fresh client,
// one full round-trip over the two --addr IPs. Two mlx5 IPs with no same-host
// NIC-loopback datapath cannot carry it; the caller then SKIPs rather than
// failing the lost probes as the bug. A pass proves the datapath, so any later
// probe loss is the genuine co-sink black hole.
bool datapath_available(const options &opt)
{
    int lfd = open_listener(opt.server_ip, opt.port, opt.accept_backlog);
    if (lfd < 0) {
        return false;
    }
    std::vector<int> baseline_children;
    bool ok = probe_once(opt, lfd, baseline_children);
    for (int fd : baseline_children) {
        close(fd);
    }
    close(lfd);
    return ok;
}

int run(const options &opt)
{
    // Probe bindability first so a host/config issue skips cleanly rather than
    // failing as the bug.
    int probe = open_listener(opt.server_ip, opt.port, opt.accept_backlog);
    if (probe < 0) {
        fprintf(stderr, "SKIP: cannot bind/listen reuse_port on server %s:%u (%s)\n",
                opt.server_ip.c_str(), opt.port, strerror(errno));
        return EXIT_SUCCESS;
    }
    close(probe);

    // Probe the actual datapath next; retry so a slow first-connection setup
    // (ARP/neighbour resolve, ring warm-up) is not mistaken for an unusable lab.
    bool reachable = false;
    for (int attempt = 0; attempt < 3 && !reachable; ++attempt) {
        reachable = datapath_available(opt);
    }
    if (!reachable) {
        fprintf(
            stderr,
            "SKIP: the two addresses (server %s, client %s) do not carry an offloaded "
            "same-host round-trip on port %u; need two mlx5 IPs with a same-host NIC datapath\n",
            opt.server_ip.c_str(), opt.client_ip.c_str(), opt.port);
        return EXIT_SUCCESS;
    }

    // (1) Open N reuse_port listeners on the same 3-tuple; they share one rfs
    //     sink list, listener k at sink index k.
    std::vector<int> listeners;
    listeners.reserve(opt.listeners);
    for (int i = 0; i < opt.listeners; ++i) {
        int lfd = open_listener(opt.server_ip, opt.port, opt.accept_backlog);
        if (lfd < 0) {
            fprintf(stderr, "FAIL: could not open reuse_port listener %d/%d (%s)\n", i + 1,
                    opt.listeners, strerror(errno));
            for (int fd : listeners) {
                close(fd);
            }
            return EXIT_FAILURE;
        }
        listeners.push_back(lfd);
    }
    unsigned listeners_opened = static_cast<unsigned>(listeners.size());

    const int hold_count = opt.listeners - 1;

    // (2) Hold one connection per hold-listener open for the whole test. The
    //     RED invariant needs only the index-0 listener to hold a live child at
    //     close; the frontmost open listener consumes setup SYNs (backlog has
    //     room), so accepting across all first N-1 listeners covers it.
    std::vector<int> held_children; // accepted server-side children
    std::vector<int> held_clients; // their client-side sockets
    held_children.reserve(hold_count);
    held_clients.reserve(hold_count);

    std::vector<int> hold_listeners(listeners.begin(), listeners.begin() + hold_count);
    for (int i = 0; i < hold_count; ++i) {
        int client = start_client(opt);
        if (client < 0) {
            fprintf(stderr, "FAIL: client connect %d (%s)\n", i, strerror(errno));
            break;
        }

        // Wait (bounded) for some hold-listener to produce the child, accepting
        // across all first N-1 listeners.
        auto deadline = clock_type::now() + std::chrono::milliseconds(opt.conn_timeout_ms);
        int accepted_now = 0;
        while (ms_until(deadline) > 0 && accepted_now == 0) {
            // make each hold listener non-blocking for the accept sweep
            for (int lfd : hold_listeners) {
                int fl = fcntl(lfd, F_GETFL, 0);
                fcntl(lfd, F_SETFL, fl | O_NONBLOCK);
            }
            accepted_now = drain_accepts(hold_listeners, held_children, true);
            if (accepted_now == 0) {
                struct timespec ts;
                ts.tv_sec = 0;
                ts.tv_nsec = 2 * 1000 * 1000; // 2ms
                nanosleep(&ts, nullptr);
            }
        }
        held_clients.push_back(client);
        if (accepted_now == 0) {
            fprintf(stderr, "FAIL: no child accepted for hold %d within %d ms\n", i,
                    opt.conn_timeout_ms);
            break;
        }
    }

    unsigned children_held = static_cast<unsigned>(held_children.size());
    if (children_held == 0) {
        fprintf(stderr,
                "FAIL: no children were accepted/held - cannot defer any "
                "listener destruction, scenario not set up\n");
        for (int fd : held_children) {
            close(fd);
        }
        for (int fd : held_clients) {
            close(fd);
        }
        for (int fd : listeners) {
            close(fd);
        }
        return EXIT_FAILURE;
    }

    // (3) Close the first N-1 listeners (those holding children). Their
    //     destruction defers. Pre-fix their stale sinks linger ahead of the live
    //     listener and the index-0 one black-holes new SYNs; fixed, each sink
    //     detaches at close and the live listener shifts to index 0.
    for (int i = 0; i < hold_count; ++i) {
        close(listeners[i]);
    }
    int live_listener = listeners[opt.listeners - 1];

    // Let the close()s settle (sink-list mutation, deferred-delete bookkeeping).
    // No RX is in flight here, so this is ordering, not a correctness crutch.
    {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 50 * 1000 * 1000; // 50ms
        nanosleep(&ts, nullptr);
    }

    // (4) Probe fresh connections; each must round-trip within the deadline.
    //     Pre-fix: every SYN lost at the stale index-0 sink, NEW_CONN_TIMEOUT >
    //     0. Fixed: all served. Probe children are held in new_children and
    //     closed only at the very end (never mid-probe).
    std::vector<int> new_children;
    new_children.reserve(opt.probes * 2);
    unsigned new_conn_ok = 0, new_conn_timeout = 0;
    for (int i = 0; i < opt.probes; ++i) {
        if (probe_once(opt, live_listener, new_children)) {
            ++new_conn_ok;
        } else {
            ++new_conn_timeout;
        }
    }

    // Teardown: release the probe children, then the held children/clients and
    // the live listener. All after probing, so no close races a probe RX.
    for (int fd : new_children) {
        close(fd);
    }
    for (int fd : held_children) {
        close(fd);
    }
    for (int fd : held_clients) {
        close(fd);
    }
    close(live_listener);

    fprintf(stderr, "LISTENERS_OPENED %u\n", listeners_opened);
    fprintf(stderr, "CHILDREN_HELD %u\n", children_held);
    fprintf(stderr, "NEW_CONN_OK %u\n", new_conn_ok);
    fprintf(stderr, "NEW_CONN_TIMEOUT %u\n", new_conn_timeout);

    if (new_conn_timeout != 0 || new_conn_ok != static_cast<unsigned>(opt.probes)) {
        fprintf(stderr,
                "FAIL: %u/%d new connections to the live reuse_port listener were "
                "lost/timed out after closing co-sink listeners that still held children. "
                "A stale listener sink was not detached at close (the pre-fix black hole).\n",
                new_conn_timeout, opt.probes);
        return EXIT_FAILURE;
    }

    fprintf(stderr, "PASS\n");
    return EXIT_SUCCESS;
}

bool parse_args(int argc, char **argv, options &opt)
{
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        const char *v = nullptr;
        if (a == "--server") {
            if (!(v = arg_value(argc, argv, i, "--server"))) {
                return false;
            }
            opt.server_ip = v;
        } else if (a == "--client") {
            if (!(v = arg_value(argc, argv, i, "--client"))) {
                return false;
            }
            opt.client_ip = v;
        } else if (a == "--port") {
            if (!(v = arg_value(argc, argv, i, "--port"))) {
                return false;
            }
            opt.port = static_cast<uint16_t>(strtoul(v, nullptr, 0));
        } else if (a == "--listeners") {
            if (!(v = arg_value(argc, argv, i, "--listeners"))) {
                return false;
            }
            opt.listeners = static_cast<int>(strtol(v, nullptr, 0));
        } else if (a == "--probes") {
            if (!(v = arg_value(argc, argv, i, "--probes"))) {
                return false;
            }
            opt.probes = static_cast<int>(strtol(v, nullptr, 0));
        } else if (a == "--conn-timeout-ms") {
            if (!(v = arg_value(argc, argv, i, "--conn-timeout-ms"))) {
                return false;
            }
            opt.conn_timeout_ms = static_cast<int>(strtol(v, nullptr, 0));
        } else {
            fprintf(stderr, "FAIL: unknown arg '%s'\n", a.c_str());
            return false;
        }
    }
    if (opt.server_ip.empty() || opt.client_ip.empty() || opt.port == 0) {
        fprintf(stderr,
                "FAIL: usage: %s --server <ip> --client <ip> --port <n> "
                "[--listeners <n>] [--probes <n>] [--conn-timeout-ms <n>]\n",
                argv[0]);
        return false;
    }
    if (opt.listeners < 2) {
        fprintf(stderr, "FAIL: --listeners must be >= 2 (need stale + live)\n");
        return false;
    }
    return true;
}

} // namespace

int main(int argc, char **argv)
{
    options opt;
    if (!parse_args(argc, argv, opt)) {
        return EXIT_FAILURE;
    }
    return run(opt);
}
