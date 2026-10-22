/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/*
 * Helper for tcp_listener_churn: drive the listener clone / close /
 * deferred-delete paths from a fresh process so the test can supply its own
 * XLIO configuration (it enables the tuning report to read back the destructor
 * counters).
 *
 * This reproduces, in-process and bounded, the Envoy LDS-update teardown
 * pattern that the listen-socket reference count guards: a listen (parent)
 * socket is closed and re-opened on the same port while cloned children are
 * still alive and holding a reference on it. Each accepted child is cloned via
 * clone_conn_cb (child_ref_acquire) and releases its reference in
 * ~sockinfo_tcp; clean_socket_obj() must defer the listener delete until the
 * last child releases. Holding children alive ACROSS the listener close is what
 * forces the deferred-delete path (a listener closed with no outstanding child
 * ref deletes immediately, exercising nothing new).
 *
 * Everything runs on one host over two offloadable mlx5 IPs (loopback/0.0.0.0
 * is kernel passthrough by design). Knobs let the test tune intensity so the
 * run is deterministic and crash-free on the fixed build; see the test comment
 * in tcp_listener_churn.cc for scope.
 *
 * Output contract (parsed by the test):
 *   SKIP: <reason>                 - addresses are not offloadable; test skips
 *   LISTENERS_OPENED <n>           - listen sockets this process created
 *   CHILDREN_ACCEPTED <n>          - connections this process accept()ed
 *   PASS                           - churn completed with no crash
 */

#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

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
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));

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

// Accept loop: holds accepted children in a local list so they stay alive (and
// keep their listener reference) until the main thread signals end-of-iteration
// by storing -1 into g_listen_fd. Only then are the children closed - so the
// listener close() in the main thread lands while child references are still
// outstanding, forcing clean_socket_obj()'s deferred-delete path.
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
// half-open connections (connect then RST via SO_LINGER{on,0} + close before
// the handshake completes) - the sig-A trigger for
// handle_incoming_handshake_failure.
void client_thread(const options &opt, int budget)
{
    sockaddr_in srv;
    fill_addr(srv, opt.server_ip, opt.port);
    sockaddr_in cli;
    fill_addr(cli, opt.client_ip, 0);

    for (int i = 0; i < budget; ++i) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            continue;
        }
        bind(fd, reinterpret_cast<sockaddr *>(&cli), sizeof(cli));

        if (opt.half_open && (i % 2) == 0) {
            int fl = fcntl(fd, F_GETFL, 0);
            fcntl(fd, F_SETFL, fl | O_NONBLOCK);
            connect(fd, reinterpret_cast<sockaddr *>(&srv), sizeof(srv));
            struct linger lin;
            lin.l_onoff = 1;
            lin.l_linger = 0; // close() sends an RST instead of a FIN
            setsockopt(fd, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin));
            close(fd);
        } else {
            if (connect(fd, reinterpret_cast<sockaddr *>(&srv), sizeof(srv)) == 0) {
                char b = 'x';
                send(fd, &b, 1, MSG_NOSIGNAL);
            }
            close(fd);
        }
    }
}

int run(const options &opt)
{
    int probe = open_listener(opt);
    if (probe < 0) {
        fprintf(stderr, "SKIP: cannot bind/listen on server %s:%u (%s)\n", opt.server_ip.c_str(),
                opt.port, strerror(errno));
        return EXIT_SUCCESS;
    }
    close(probe);

    std::thread srv(server_thread);

    for (int it = 0; it < opt.iters; ++it) {
        int lfd = open_listener(opt);
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

        // Quiesce: let in-flight RX drain so the listener close does not race the
        // data path. The reference count (not this drain) is the correctness
        // guarantee; the drain keeps the run deterministic and crash-free.
        std::this_thread::sleep_for(std::chrono::milliseconds(opt.drain_ms));

        // Teardown: detach the listener and close it. Children accepted this
        // iteration are still open in the server thread, so their references are
        // outstanding and the listener delete must defer until the server thread
        // closes them (triggered by the -1 store below).
        g_listen_fd.store(-1, std::memory_order_release);
        close(lfd);
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
        } else if (a == "--iters") {
            if (!(v = need("--iters"))) {
                return false;
            }
            opt.iters = static_cast<int>(strtol(v, nullptr, 0));
        } else if (a == "--threads") {
            if (!(v = need("--threads"))) {
                return false;
            }
            opt.threads = static_cast<int>(strtol(v, nullptr, 0));
        } else if (a == "--conns") {
            if (!(v = need("--conns"))) {
                return false;
            }
            opt.conns = static_cast<int>(strtol(v, nullptr, 0));
        } else if (a == "--half-open") {
            if (!(v = need("--half-open"))) {
                return false;
            }
            opt.half_open = (strtol(v, nullptr, 0) != 0);
        } else if (a == "--drain-ms") {
            if (!(v = need("--drain-ms"))) {
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
