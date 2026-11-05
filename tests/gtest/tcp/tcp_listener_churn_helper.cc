/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/*
 * Helper for tcp_listener_churn: close and re-open a listener on two mlx5 IPs
 * under accept/connect load, with accepted children held open across every
 * listener close, so each close takes the deferred-delete path. Half-open
 * (RST) clients drive the handshake-failure callback. Gotcha: children must
 * outlive the listener close, or the paths under test are never exercised.
 * Output contract (parsed by the test): SKIP: <reason> | LISTENERS_OPENED <n>
 * | CHILDREN_ACCEPTED <n> | CLIENT_SOCKETS_OPENED <n> | CONNECTS_INITIATED <n>
 * | PROBE_LISTENERS <n> | PASS
 */

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <string>
#include <thread>
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
    int iters = 8;
    int threads = 2;
    int conns = 20; // connections per client thread per iteration
    bool half_open = false; // include RST-before-handshake connections
    int drain_ms = 50; // quiesce RX this long before closing the listener
    int accept_backlog = 128;
};

std::atomic<bool> g_server_run {true};
std::atomic<int> g_listen_fd {-1};
std::atomic<uint64_t> g_children_accepted {0};
std::atomic<uint64_t> g_listeners_opened {0};
std::atomic<uint64_t> g_client_sockets_opened {0};
std::atomic<uint64_t> g_connects_initiated {0};

// Accept loop: hold accepted children (each pins its listener) until the main
// thread signals end-of-iteration by storing -1 into g_listen_fd. The listener
// close in the main thread therefore always lands with child references
// outstanding, forcing the deferred-delete path.
void server_thread()
{
    std::vector<int> children;
    children.reserve(1024);
    while (g_server_run.load(std::memory_order_acquire)) {
        int lfd = g_listen_fd.load(std::memory_order_acquire);
        if (lfd < 0) {
            // Between listeners: drop the children accepted for the previous
            // listener now (their ref-release drives the deferred delete).
            for (int c : children) {
                close(c);
            }
            children.clear();
            std::this_thread::yield();
            continue;
        }
        int cfd = accept(lfd, nullptr, nullptr);
        if (cfd >= 0) {
            g_children_accepted.fetch_add(1, std::memory_order_relaxed);
            children.push_back(cfd);
            continue;
        }
        std::this_thread::yield();
    }
    for (int c : children) {
        close(c);
    }
}

// One client thread: full short-lived connections, optionally interleaved with
// half-open ones (connect, then RST via SO_LINGER{on,0} close before the
// handshake completes) - the trigger for handle_incoming_handshake_failure.
void client_thread(const options &opt, int budget)
{
    sockaddr_storage srv;
    socklen_t srv_len = fill_addr(srv, opt.server_ip, opt.port);
    sockaddr_storage cli;
    socklen_t cli_len = fill_addr(cli, opt.client_ip, 0);

    for (int i = 0; i < budget; ++i) {
        int fd = socket(srv.ss_family, SOCK_STREAM, 0);
        if (fd < 0) {
            continue;
        }
        g_client_sockets_opened.fetch_add(1, std::memory_order_relaxed);
        bind(fd, reinterpret_cast<sockaddr *>(&cli), cli_len);

        if (opt.half_open && (i % 2) == 0) {
            int fl = fcntl(fd, F_GETFL, 0);
            fcntl(fd, F_SETFL, fl | O_NONBLOCK);
            g_connects_initiated.fetch_add(1, std::memory_order_relaxed);
            connect(fd, reinterpret_cast<sockaddr *>(&srv), srv_len);
            struct linger lin;
            lin.l_onoff = 1;
            lin.l_linger = 0; // close() sends an RST instead of a FIN
            setsockopt(fd, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin));
            close(fd);
        } else {
            g_connects_initiated.fetch_add(1, std::memory_order_relaxed);
            if (connect(fd, reinterpret_cast<sockaddr *>(&srv), srv_len) == 0) {
                char b = 'x';
                send(fd, &b, 1, MSG_NOSIGNAL);
            }
            close(fd);
        }
    }
}

// Accept whatever is still queued on lfd (until EWOULDBLOCK) so those children
// are counted before the close - tightens the test's destructor-balance floor.
void drain_pending_accepts(int lfd)
{
    int fl = fcntl(lfd, F_GETFL, 0);
    fcntl(lfd, F_SETFL, fl | O_NONBLOCK);
    for (;;) {
        int cfd = accept(lfd, nullptr, nullptr);
        if (cfd < 0) {
            break;
        }
        g_children_accepted.fetch_add(1, std::memory_order_relaxed);
        close(cfd);
    }
}

int run(const options &opt)
{
    // Resolve both addresses up front: an unparseable one must fail the helper
    // here, before any server or client thread starts.
    sockaddr_storage resolved;
    fill_addr(resolved, opt.server_ip, opt.port);
    fill_addr(resolved, opt.client_ip, 0);

    int probe = open_listener(opt.server_ip, opt.port, opt.accept_backlog);
    if (probe < 0) {
        fprintf(stderr, "SKIP: cannot bind/listen on server %s:%u (%s)\n", opt.server_ip.c_str(),
                opt.port, strerror(errno));
        return EXIT_SUCCESS;
    }
    close(probe);

    std::thread srv(server_thread);

    for (int it = 0; it < opt.iters; ++it) {
        int lfd = open_listener(opt.server_ip, opt.port, opt.accept_backlog);
        if (lfd < 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        g_listeners_opened.fetch_add(1, std::memory_order_relaxed);
        g_listen_fd.store(lfd, std::memory_order_release);

        std::vector<std::thread> clients;
        clients.reserve(opt.threads);
        for (int t = 0; t < opt.threads; ++t) {
            clients.emplace_back(client_thread, opt, opt.conns);
        }
        for (auto &c : clients) {
            c.join();
        }

        // Quiesce: let in-flight RX drain before the close. The reference count
        // (not this drain) is the correctness guarantee.
        std::this_thread::sleep_for(std::chrono::milliseconds(opt.drain_ms));

        // Final iteration: accept the leftover queue first, so those children
        // are counted in CHILDREN_ACCEPTED before the last close.
        if (it == opt.iters - 1) {
            drain_pending_accepts(lfd);
        }

        // Close first, signal -1 second: the server thread still holds this
        // iteration's children, so every close defers the listener delete. An
        // accept() racing the close gets EBADF and retries the load; no fd is
        // created between the close and the -1 store, so the number stays dead.
        close(lfd);
        g_listen_fd.store(-1, std::memory_order_release);
        // Give the server thread a moment to release the children and let the
        // deferred delete complete before the next listener reuses the port.
        std::this_thread::sleep_for(std::chrono::milliseconds(opt.drain_ms));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    g_server_run.store(false, std::memory_order_release);
    srv.join();

    fprintf(stderr, "LISTENERS_OPENED %llu\n",
            static_cast<unsigned long long>(g_listeners_opened.load()));
    fprintf(stderr, "CHILDREN_ACCEPTED %llu\n",
            static_cast<unsigned long long>(g_children_accepted.load()));
    fprintf(stderr, "CLIENT_SOCKETS_OPENED %llu\n",
            static_cast<unsigned long long>(g_client_sockets_opened.load()));
    fprintf(stderr, "CONNECTS_INITIATED %llu\n",
            static_cast<unsigned long long>(g_connects_initiated.load()));
    // Reaching here means the SKIP probe opened (and closed) one listener whose
    // destructor is part of the offloaded count the test bounds against.
    fprintf(stderr, "PROBE_LISTENERS 1\n");
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
        } else if (a == "--iters") {
            if (!(v = arg_value(argc, argv, i, "--iters"))) {
                return false;
            }
            opt.iters = static_cast<int>(strtol(v, nullptr, 0));
        } else if (a == "--threads") {
            if (!(v = arg_value(argc, argv, i, "--threads"))) {
                return false;
            }
            opt.threads = static_cast<int>(strtol(v, nullptr, 0));
        } else if (a == "--conns") {
            if (!(v = arg_value(argc, argv, i, "--conns"))) {
                return false;
            }
            opt.conns = static_cast<int>(strtol(v, nullptr, 0));
        } else if (a == "--half-open") {
            if (!(v = arg_value(argc, argv, i, "--half-open"))) {
                return false;
            }
            opt.half_open = (strtol(v, nullptr, 0) != 0);
        } else if (a == "--drain-ms") {
            if (!(v = arg_value(argc, argv, i, "--drain-ms"))) {
                return false;
            }
            opt.drain_ms = static_cast<int>(strtol(v, nullptr, 0));
        } else {
            fprintf(stderr, "FAIL: unknown arg '%s'\n", a.c_str());
            return false;
        }
    }
    if (opt.server_ip.empty() || opt.client_ip.empty() || opt.port == 0) {
        fprintf(stderr,
                "FAIL: usage: %s --server <ip> --client <ip> --port <n> "
                "[--iters <n>] [--threads <n>] [--conns <n>] [--half-open 0|1] "
                "[--drain-ms <n>]\n",
                argv[0]);
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
