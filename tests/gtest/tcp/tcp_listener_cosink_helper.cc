/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/*
 * Helper for tcp_listener_cosink: a deterministic RED->GREEN gate for the
 * "detach the listener RFS sink at close, not at the (deferred) destructor" fix
 * (prepare_listen_to_close()).
 *
 * THE BUG (pre-fix):
 *   A listener holds one reference per connection it has accepted
 *   (sockinfo_tcp::m_child_refs, bumped in clone_conn_cb -> child_ref_acquire,
 *   released in ~sockinfo_tcp). A listener closed while any accepted child is
 *   still open has its destruction deferred (clean_socket_obj sees
 *   m_child_refs > 0). Pre-fix, the RX-sink detach (shutdown_rx) lived ONLY in
 *   the destructor, so the closed listener's sink stayed registered on the ring
 *   until that last child closed.
 *
 *   Under SO_REUSEPORT every listener on the same server IP:port maps to the
 *   SAME 3-tuple rfs key, so they all share ONE rfs_uc sink list on the ring
 *   (ring_slave::attach_flow find-or-create by rfs_key -> rfs::add_sink appends
 *   in registration order). The ring dispatches a SYN with
 *   rfs_uc::rx_dispatch_packet, which walks m_sinks_list in order and the FIRST
 *   sink whose rx_input_cb() consumes the packet wins (index 0 first - it is NOT
 *   a kernel-style per-4-tuple hash). The first-registered listener is at index
 *   0. If that index-0 listener has been closed but its destruction deferred,
 *   its stale sink still sits at index 0 and still consumes new SYNs (its
 *   rx_input_cb runs the LISTEN-state handshake path), so a replacement listener
 *   registered behind it at index 1 NEVER sees them: new connections to the live
 *   address are silently black-holed until the held child closes.
 *
 * THE FIX (under test):
 *   prepare_listen_to_close() now calls shutdown_rx() when destruction is
 *   deferred (m_child_refs > 0), detaching the sink (rfs::del_sink shifts the
 *   list down) at CLOSE. The replacement listener moves to index 0 and serves
 *   new connections immediately; the object free stays deferred for the late
 *   by-pointer callbacks.
 *
 * DETERMINISTIC SCENARIO (low-churn co-sink overlap, no RX flood):
 *   1. Open N reuse_port listeners on the SAME server mlx5 IP:port (all offload
 *      and share one rfs sink list; listener k is at sink index k).
 *   2. For each of the first N-1 listeners, make one client connection, accept
 *      the child, and HOLD both the child and the client socket open. Each hold
 *      bumps that listener's m_child_refs, so closing it defers its destruction
 *      (and, pre-fix, its sink detach). The last listener is left as the live
 *      replacement with NO held child.
 *   3. Close the first N-1 listeners (the ones holding children). Their sinks
 *      occupy indices 0..N-2, ahead of the live listener.
 *        - Pre-fix: those stale sinks stay registered; index 0 is a closed
 *          listener that still consumes SYNs -> black hole.
 *        - Fixed:   shutdown_rx() detaches all of them at close; the live
 *          listener shifts to index 0.
 *   4. Make a bounded number of NEW client connections to the same IP:port and
 *      require each to complete a tiny request/response round-trip within a
 *      short timeout.
 *        - Pre-fix: EVERY new SYN is dispatched to the stale index-0 sink and
 *          lost -> connect()/round-trip TIMES OUT -> helper reports
 *          NEW_CONN_TIMEOUT > 0 and exits non-zero (test FAILS / RED).
 *        - Fixed:   every new connection reaches the live listener and is served
 *          -> NEW_CONN_OK == probes, NEW_CONN_TIMEOUT == 0 -> PASS (GREEN).
 *
 * Why deterministic (not statistical): because XLIO funnels all reuse_port
 * listeners of a 3-tuple into ONE shared sink list dispatched index-0-first,
 * the stale index-0 sink deterministically wins for ALL new SYNs regardless of
 * the client 4-tuple. A single probe would already expose the bug; we open
 * several stale listeners and send several probes so the RED build is
 * guaranteed to lose at least one even if any single sink momentarily declines
 * a packet, while the GREEN build must serve all.
 *
 * Why this stays clear of the separate, still-unfixed G6 sink-path RX UAF
 * (ring_slave.cpp:565, which tcp_listener_churn gates behind an env var):
 * that crash needs a heavy concurrent RX flood racing a close so the internal
 * ring-drain dispatches to a child sink freed by the close. Here there is no
 * flood - one connection per held listener, children are closed only at the
 * very end (after all probing), and there is no sustained data path across the
 * close. The listeners are closed while quiescent, so no RX is in flight on the
 * internal thread during any teardown. This test is therefore ENABLED BY
 * DEFAULT.
 *
 * Everything is single-threaded and runs on one host over two offloadable mlx5
 * IPs (loopback/0.0.0.0 is kernel passthrough by design and would be a false
 * green). The single thread drives the client side with non-blocking sockets
 * and interleaves accept()+echo on the server listener, so one process both
 * generates and serves the connections.
 *
 * Before the scenario, a baseline probe (datapath_available) requires one plain
 * client->server round-trip over the two IPs. Two real mlx5 IPs that do not form
 * a same-host NIC-loopback datapath cannot carry it, so the helper emits SKIP
 * rather than failing the lost probes as the bug. A successful baseline proves
 * the datapath, so any later probe loss is the genuine co-sink black hole.
 *
 * Output contract (parsed by the test):
 *   SKIP: <reason>                 - not offloadable, or the two IPs do not carry
 *                                    a same-host round-trip; test skips
 *   LISTENERS_OPENED <n>           - reuse_port listeners this process created
 *   CHILDREN_HELD <n>              - accepted children held open across the close
 *   NEW_CONN_OK <n>                - new connections served after the close
 *   NEW_CONN_TIMEOUT <n>           - new connections lost/timed out (bug signature)
 *   PASS                           - all new connections served, no crash
 */

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace {

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
    // build the SYN is black-holed, so connect()+recv never completes and this
    // bounds the hang; it must be long enough that a healthy offloaded connect
    // never spuriously trips it.
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

void fill_addr(sockaddr_in &sa, const std::string &ip, uint16_t port)
{
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
}

int open_listener(const options &opt)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int on = 1;
    // SO_REUSEPORT is what makes several listeners share one offloaded 3-tuple
    // rfs sink list - the whole point of this test. SO_REUSEADDR alone would
    // make the second bind() fail.
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) != 0) {
        close(fd);
        return -1;
    }

    sockaddr_in sa;
    fill_addr(sa, opt.server_ip, opt.port);
    if (bind(fd, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, opt.accept_backlog) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// Non-blocking client connect from a fresh ephemeral 4-tuple. Returns the
// connecting fd (still in progress) or -1.
int start_client(const options &opt)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    sockaddr_in cli;
    fill_addr(cli, opt.client_ip, 0);
    bind(fd, reinterpret_cast<sockaddr *>(&cli), sizeof(cli));

    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    sockaddr_in srv;
    fill_addr(srv, opt.server_ip, opt.port);
    int rc = connect(fd, reinterpret_cast<sockaddr *>(&srv), sizeof(srv));
    if (rc != 0 && errno != EINPROGRESS && errno != EALREADY && errno != EISCONN) {
        close(fd);
        return -1;
    }
    return fd;
}

// Accept any pending child across the given listeners (non-blocking), echo one
// byte if the child sends one, and collect the accepted child fds so the caller
// can keep them open. Returns the number of children accepted this call.
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

// Drive ONE new connection to a full round-trip while cooperatively serving the
// live listener, all within a single wall-clock deadline. Single-threaded: the
// client fd is non-blocking and we poll it together with servicing accepts on
// the live listener (accept + echo). Returns true only if the client completed
// connect -> send -> recv-echo before the deadline. Accepted server-side
// children for THIS probe are pushed to new_children so the caller keeps them
// alive until the end (closing them mid-run is what the separate G6 UAF needs,
// which we avoid).
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

// Baseline connectivity+offload probe: open ONE plain listener and require a
// single fresh client connection to complete a full round-trip over the two
// --addr IPs. This is the exact minimal datapath the co-sink scenario needs. A
// pair of real mlx5 IPs that do not form a same-host NIC-loopback datapath (no
// route between them, different hosts, offload loopback unsupported) cannot
// carry this round-trip, so the probes further down would all time out and the
// helper would exit non-zero - reported as the bug when it is really a lab
// incompatibility. Probing up front lets us SKIP cleanly instead. If this
// baseline succeeds the datapath is proven, so any later probe failure is the
// genuine co-sink black hole (RED preserved). Returns true iff the round-trip
// completed.
bool datapath_available(const options &opt)
{
    int lfd = open_listener(opt);
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
    int probe = open_listener(opt);
    if (probe < 0) {
        fprintf(stderr, "SKIP: cannot bind/listen reuse_port on server %s:%u (%s)\n",
                opt.server_ip.c_str(), opt.port, strerror(errno));
        return EXIT_SUCCESS;
    }
    close(probe);

    // Then probe the actual datapath: a lab whose two mlx5 --addr IPs cannot
    // carry an offloaded same-host round-trip must SKIP, not fail as the bug.
    // Retry a few times so a slow first-connection setup (ARP/neighbour resolve,
    // ring warm-up) is not mistaken for an unusable datapath.
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
        int lfd = open_listener(opt);
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

    // (2) Establish hold_count connections and hold every accepted child (and its
    //     client socket) open for the whole test. Each accept bumps the accepting
    //     listener's m_child_refs via clone_conn_cb, so that listener's later
    //     close defers its destruction (and, pre-fix, its sink detach).
    //
    //     The critical invariant for RED is only that the INDEX-0 listener (the
    //     first-registered sink) holds at least one live child when it is closed,
    //     so its stale sink persists at index 0 to black-hole the probes. XLIO's
    //     rx_dispatch_packet walks the shared sink list index-0-first and the
    //     front listener consumes a SYN whenever its backlog has room (128 here,
    //     far more than hold_count), so these setup SYNs are taken by the
    //     frontmost open listener(s) - index 0 included - which is exactly what we
    //     need. We accept across all first N-1 listeners rather than assume a
    //     particular distribution. The last listener is the live replacement and
    //     holds no child.
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
    //     destruction defers; pre-fix their sinks linger at indices 0..N-2 ahead
    //     of the live listener - the stale index-0 sink black-holes new SYNs.
    //     Fixed: shutdown_rx() detaches each sink at close and the live listener
    //     shifts to index 0.
    for (int i = 0; i < hold_count; ++i) {
        close(listeners[i]);
    }
    int live_listener = listeners[opt.listeners - 1];

    // Let the close()s settle (sink-list mutation / deferred-delete bookkeeping).
    // No RX is in flight here, so this is ordering, not a correctness crutch.
    {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 50 * 1000 * 1000; // 50ms
        nanosleep(&ts, nullptr);
    }

    // (4) Probe fresh connections. Each must round-trip within the deadline.
    //     Pre-fix: every SYN is lost at the stale index-0 sink ->
    //     NEW_CONN_TIMEOUT > 0. Fixed: all served -> NEW_CONN_OK == probes. The
    //     server-side children for the probes are held in new_children and only
    //     closed at the very end (never mid-probe), keeping the G6 UAF out of
    //     scope.
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
        auto need = [&](const char *name) -> const char * {
            if (i + 1 >= argc) {
                fprintf(stderr, "FAIL: %s needs a value\n", name);
                return nullptr;
            }
            return argv[++i];
        };
        const char *v = nullptr;
        if (a == "--server") {
            if (!(v = need("--server"))) {
                return false;
            }
            opt.server_ip = v;
        } else if (a == "--client") {
            if (!(v = need("--client"))) {
                return false;
            }
            opt.client_ip = v;
        } else if (a == "--port") {
            if (!(v = need("--port"))) {
                return false;
            }
            opt.port = static_cast<uint16_t>(strtoul(v, nullptr, 0));
        } else if (a == "--listeners") {
            if (!(v = need("--listeners"))) {
                return false;
            }
            opt.listeners = static_cast<int>(strtol(v, nullptr, 0));
        } else if (a == "--probes") {
            if (!(v = need("--probes"))) {
                return false;
            }
            opt.probes = static_cast<int>(strtol(v, nullptr, 0));
        } else if (a == "--conn-timeout-ms") {
            if (!(v = need("--conn-timeout-ms"))) {
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
