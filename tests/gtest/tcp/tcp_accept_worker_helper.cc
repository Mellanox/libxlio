/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

// Exercise real accept/handshake callbacks in fresh XLIO processes. The driver
// has no worker threads; the server has eight and each independent client one.
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <spawn.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

extern char **environ;

static const unsigned int CLIENTS = 8;
static const unsigned int CONNECTIONS = 512;
// Serial reconnects can need a SYN retransmission while old steering closes.
// Keep this targeted case within the same deadline as the concurrent burst.
static const unsigned int RECONNECT_CONNECTIONS = 128;

static void require(bool ok, const char *operation)
{
    if (!ok) {
        throw std::runtime_error(std::string(operation) + ": " + std::strerror(errno));
    }
}

struct address {
    sockaddr_storage value = {};
    socklen_t length = 0;

    address(const char *ip, const char *port)
    {
        addrinfo hints = {}, *result = nullptr;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
        const int rc = getaddrinfo(ip, port, &hints, &result);
        if (rc != 0) {
            throw std::runtime_error(gai_strerror(rc));
        }
        length = result->ai_addrlen;
        std::memcpy(&value, result->ai_addr, length);
        freeaddrinfo(result);
    }

    sockaddr *ptr() { return reinterpret_cast<sockaddr *>(&value); }
    in_port_t port() const
    {
        return value.ss_family == AF_INET
            ? reinterpret_cast<const sockaddr_in *>(&value)->sin_port
            : reinterpret_cast<const sockaddr_in6 *>(&value)->sin6_port;
    }
};

static void require_offloaded(int fd)
{
    // XLIO's kernel fd is either a non-socket placeholder or an unconnected
    // shadow socket. Compare both views without depending on debug logs.
    sockaddr_storage peer = {};
    socklen_t peer_length = sizeof(peer);
    require(getpeername(fd, reinterpret_cast<sockaddr *>(&peer), &peer_length) == 0,
            "offloaded socket peer");
    peer_length = sizeof(peer);
    const long kernel_rc =
        syscall(SYS_getpeername, fd, reinterpret_cast<sockaddr *>(&peer), &peer_length);
    require(kernel_rc == -1 && (errno == ENOTSOCK || errno == ENOTCONN),
            "socket must be XLIO offloaded (kernel fd must not be connected)");
}

static int serve(const char *ip, bool nonblocking, unsigned int connections)
{
    address local(ip, "0");
    const int listener = socket(local.value.ss_family, SOCK_STREAM, 0);
    require(listener >= 0, "server socket");
    require(bind(listener, local.ptr(), local.length) == 0, "server bind");
    require(listen(listener, connections) == 0, "listen");
    require(getsockname(listener, local.ptr(), &local.length) == 0, "getsockname");
    const unsigned short port = local.value.ss_family == AF_INET
        ? ntohs(reinterpret_cast<sockaddr_in *>(local.ptr())->sin_port)
        : ntohs(reinterpret_cast<sockaddr_in6 *>(local.ptr())->sin6_port);

    int epfd = -1;
    if (nonblocking) {
        require(fcntl(listener, F_SETFL, O_NONBLOCK) == 0, "nonblocking listener");
        epfd = epoll_create1(EPOLL_CLOEXEC);
        require(epfd >= 0, "epoll_create1");
        epoll_event event = {};
        event.events = EPOLLIN;
        event.data.fd = listener;
        require(epoll_ctl(epfd, EPOLL_CTL_ADD, listener, &event) == 0, "epoll_ctl");
    }
    // The controller starts clients only after the listener is ready.
    std::cout << port << std::endl;

    unsigned int accepted = 0;
    while (accepted < connections) {
        if (nonblocking) {
            epoll_event event = {};
            require(epoll_wait(epfd, &event, 1, 10000) == 1, "listener readiness");
        }
        do {
            const int fd = accept(listener, nullptr, nullptr);
            if (nonblocking && fd < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                break;
            }
            require(fd >= 0, "accept");
            require_offloaded(fd);
            char request = 0;
            require(recv(fd, &request, 1, 0) == 1 && request == 'Q', "server receive");
            require(send(fd, "R", 1, MSG_NOSIGNAL) == 1, "server send");
            require(close(fd) == 0, "server close");
            ++accepted;
        } while (nonblocking && accepted < connections);
    }
    if (epfd >= 0) {
        close(epfd);
    }
    close(listener);
    return 0;
}

static void wait_for_release()
{
    char release;
    ssize_t rc;
    do {
        rc = read(STDIN_FILENO, &release, 1);
    } while (rc < 0 && errno == EINTR);
    require(rc == 0, "client release barrier");
}

static int connect_burst(const char *client_ip, const char *server_ip, const char *port)
{
    address local(client_ip, "0"), peer(server_ip, port);
    std::vector<int> sockets;
    // Keep all sockets alive until every client finishes connecting. The
    // controller releases stdin only after the server accepted the whole batch,
    // preventing another client from reusing a port still in server TIME_WAIT.
    for (unsigned int index = 0; index < CONNECTIONS / CLIENTS; ++index) {
        const int fd = socket(peer.value.ss_family, SOCK_STREAM, 0);
        require(fd >= 0, "client socket");
        require(bind(fd, local.ptr(), local.length) == 0, "client bind");
        require(connect(fd, peer.ptr(), peer.length) == 0, "connect");
        require(send(fd, "Q", 1, MSG_NOSIGNAL) == 1, "client send");
        sockets.push_back(fd);
    }
    for (int fd : sockets) {
        char response = 0;
        require(recv(fd, &response, 1, 0) == 1 && response == 'R', "client receive");
    }
    wait_for_release();
    for (int fd : sockets) {
        close(fd);
    }
    return 0;
}

static long long monotonic_ms()
{
    timespec now = {};
    require(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "timestamp clock");
    return now.tv_sec * 1000LL + now.tv_nsec / 1000000;
}

static int reconnect(const char *client_ip, const char *server_ip, const char *port)
{
    address local(client_ip, "0"), peer(server_ip, port);
    int previous_fd = -1;
    unsigned int reused_fds = 0;
    in_port_t source_port = 0;
    for (unsigned int index = 0; index < RECONNECT_CONNECTIONS / CLIENTS; ++index) {
        const int fd = socket(peer.value.ss_family, SOCK_STREAM, 0);
        require(fd >= 0, "reconnect socket");
        reused_fds += fd == previous_fd;
        previous_fd = fd;
        const int reuse = 1;
        require(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == 0,
                "reconnect SO_REUSEADDR");
        // getsockname after the first connect selects a source port; subsequent
        // binds use that exact address/port and the same server tuple.
        require(bind(fd, local.ptr(), local.length) == 0, "reconnect bind");
        require(connect(fd, peer.ptr(), peer.length) == 0, "reconnect connect");
        require(getsockname(fd, local.ptr(), &local.length) == 0, "reconnect getsockname");
        if (index == 0) {
            source_port = local.port();
        }
        require(source_port != 0 && local.port() == source_port, "reconnect same source port");
        require_offloaded(fd);
        require(send(fd, "Q", 1, MSG_NOSIGNAL) == 1, "reconnect send");
        char response = 0;
        require(recv(fd, &response, 1, 0) == 1 && response == 'R', "reconnect response");
        // Server closes first and retains TIME_WAIT steering. Reconnect after
        // FIN, rather than resetting the connection and discarding that state.
        require(recv(fd, &response, 1, 0) == 0, "reconnect server FIN");
        if (index + 1 == RECONNECT_CONNECTIONS / CLIENTS) {
            // Reserve this client's source port until all clients finish. Only
            // the final socket is retained; earlier iterations reuse the tuple.
            wait_for_release();
            require(close(fd) == 0, "reconnect final close");
            break;
        }
        require(close(fd) == 0, "reconnect close");
        // RFC 6191 permits the TIME_WAIT tuple to be reused with a newer TCP
        // timestamp even when the new ISN has not advanced. Wait for the clock
        // condition, not for TIME_WAIT or worker-side steering cleanup.
        const long long closed_ms = monotonic_ms();
        while (monotonic_ms() == closed_ms) {
            const timespec tick = {0, 1000000};
            nanosleep(&tick, nullptr);
        }
    }
    require(reused_fds > 0, "reconnect must reuse a descriptor for stale flow tags");
    std::cerr << "reconnected " << RECONNECT_CONNECTIONS / CLIENTS << " times on source port "
              << ntohs(source_port) << "; reused descriptor " << reused_fds << " times\n";
    return 0;
}

class children {
public:
    ~children()
    {
        for (pid_t pid : pids) {
            if (pid > 0) {
                kill(pid, SIGKILL);
                while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {
                }
            }
        }
    }

    void start(const std::vector<std::string> &args, int workers, int ready_pipe = -1,
               int release_pipe = -1, bool reuse_tuple = false)
    {
        std::vector<std::string> environment;
        for (char **item = environ; *item; ++item) {
            if (std::strncmp(*item, "XLIO_INLINE_CONFIG=", 19) != 0) {
                environment.emplace_back(*item);
            }
        }
        std::string config =
            "XLIO_INLINE_CONFIG=performance.threading.worker_threads=" + std::to_string(workers);
        if (reuse_tuple) {
            config += ";performance.steering_rules.disable_flowtag=false;"
                      "network.protocols.tcp.timestamps=enable";
        }
        environment.push_back(config);
        std::vector<char *> argv, envp;
        for (const auto &arg : args) {
            argv.push_back(const_cast<char *>(arg.c_str()));
        }
        argv.push_back(nullptr);
        for (auto &item : environment) {
            envp.push_back(&item[0]);
        }
        envp.push_back(nullptr);
        posix_spawn_file_actions_t actions;
        require(posix_spawn_file_actions_init(&actions) == 0, "spawn actions");
        if (ready_pipe >= 0) {
            require(posix_spawn_file_actions_adddup2(&actions, ready_pipe, STDOUT_FILENO) == 0,
                    "spawn stdout");
        }
        if (release_pipe >= 0) {
            require(posix_spawn_file_actions_adddup2(&actions, release_pipe, STDIN_FILENO) == 0,
                    "spawn stdin");
        }
        pid_t pid = -1;
        const int rc =
            posix_spawn(&pid, args[0].c_str(), &actions, nullptr, argv.data(), envp.data());
        posix_spawn_file_actions_destroy(&actions);
        errno = rc;
        require(rc == 0, "posix_spawn");
        pids.push_back(pid);
    }

    void wait_all(int release_pipe)
    {
        const pid_t server_pid = pids.front();
        size_t remaining = pids.size();
        while (remaining > 0) {
            int status = 0;
            pid_t rc;
            do {
                // This fresh controller owns all children. Reap whichever
                // finishes first so a client crash cannot hide behind accept().
                rc = waitpid(-1, &status, 0);
            } while (rc < 0 && errno == EINTR);
            require(rc > 0, "waitpid");
            auto child = std::find(pids.begin(), pids.end(), rc);
            require(child != pids.end(), "waitpid owned child");
            *child = -1;
            --remaining;
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                throw std::runtime_error("accept worker helper child failed: status=" +
                                         std::to_string(status));
            }
            if (rc == server_pid && release_pipe >= 0) {
                // All clients retain their final bound
                // sockets until it successfully accepts every connection.
                close(release_pipe);
                release_pipe = -1;
            }
        }
    }

private:
    std::vector<pid_t> pids;
};

int main(int argc, char **argv)
{
    try {
        if (argc == 4 && std::strcmp(argv[1], "server") == 0) {
            return serve(
                argv[2], std::strcmp(argv[3], "nonblocking") == 0,
                std::strcmp(argv[3], "reconnect") == 0 ? RECONNECT_CONNECTIONS : CONNECTIONS);
        }
        if (argc == 5 && std::strcmp(argv[1], "client") == 0) {
            return connect_burst(argv[2], argv[3], argv[4]);
        }
        if (argc == 5 && std::strcmp(argv[1], "reconnect-client") == 0) {
            return reconnect(argv[2], argv[3], argv[4]);
        }
        require(argc == 4, "arguments: client-ip server-ip blocking|nonblocking|reconnect");
        const bool reuse_tuple = std::strcmp(argv[3], "reconnect") == 0;
        int ready[2];
        require(pipe2(ready, O_CLOEXEC) == 0, "ready pipe");
        children processes;
        processes.start({argv[0], "server", argv[2], argv[3]}, 8, ready[1], -1, reuse_tuple);
        close(ready[1]);
        FILE *port_stream = fdopen(ready[0], "r");
        require(port_stream != nullptr, "fdopen");
        unsigned short port = 0;
        const int fields = fscanf(port_stream, "%hu", &port);
        fclose(port_stream);
        require(fields == 1 && port != 0, "server ready");
        int release[2];
        require(pipe2(release, O_CLOEXEC) == 0, "release pipe");
        for (unsigned int index = 0; index < CLIENTS; ++index) {
            processes.start({argv[0], reuse_tuple ? "reconnect-client" : "client", argv[1], argv[2],
                             std::to_string(port)},
                            1, -1, release[0], reuse_tuple);
        }
        close(release[0]);
        processes.wait_all(release[1]);
        std::cout << "completed " << (reuse_tuple ? RECONNECT_CONNECTIONS : CONNECTIONS)
                  << (reuse_tuple ? " same-tuple connections" : " connections") << std::endl;
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << std::endl;
        return 1;
    }
}
