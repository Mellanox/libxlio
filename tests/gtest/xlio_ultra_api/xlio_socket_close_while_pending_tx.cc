/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

// This test is related the xlio_perf server crash reported in RedMine #4997292.
// It makes sure that we reconstruct the delaying of socket destruction to be only after
// all TX ZC buffers were drained.

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include <arpa/inet.h>
#include <dlfcn.h>
#include <infiniband/verbs.h>
#include <unistd.h>
#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits.h>
#include <sstream>
#include <string>
#include <sys/wait.h>
#include <thread>
#include <vector>
#include "core/xlio_base.h"

#if defined(EXTRA_API_ENABLED) && (EXTRA_API_ENABLED == 1)

static const unsigned int num_workers = 1;
static const unsigned int num_sockets = 50;
static const unsigned int queue_depth_in_msgs = 1600;
static const size_t data_size = 102400;
static const unsigned long long receiver_ack_bytes = 2ULL * 1024ULL * 1024ULL * 1024ULL;
static const unsigned long long progress_report_bytes = 1ULL * 1024ULL * 1024ULL * 1024ULL;
static const int stress_timeout_seconds = 300;
static std::atomic<bool> stop_sending {false};
static std::atomic<bool> stop_receiving {false};
static std::chrono::steady_clock::time_point test_log_start_time;
typedef int (*sockinfo_tcp_instance_counter_getter_t)();

static int timestamped_fprintf(FILE *stream, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    if (stream == stderr && format && format[0] == '[') {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - test_log_start_time)
                           .count();
        std::fprintf(stream, "[%lld ms] ", static_cast<long long>(elapsed));
    }

    int ret = std::vfprintf(stream, format, args);
    va_end(args);
    return ret;
}

static bool is_inner_scwpt_run()
{
    return getenv("XLIO_SCWPT") != nullptr;
}

static std::string shell_quote(const std::string &value)
{
    std::string quoted = "'";
    for (char c : value) {
        if (c == '\'') {
            quoted += "'\\''";
        } else {
            quoted += c;
        }
    }
    quoted += "'";
    return quoted;
}

static std::string self_executable_path()
{
    char path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len < 0) {
        return {};
    }
    path[len] = '\0';
    return path;
}

static std::string sockaddr_ip_to_string(const sockaddr_store_t &addr)
{
    char buffer[INET6_ADDRSTRLEN];
    const sockaddr *sa = reinterpret_cast<const sockaddr *>(&addr);
    const void *src = nullptr;

    if (sa->sa_family == AF_INET) {
        src = &addr.addr4.sin_addr;
    } else if (sa->sa_family == AF_INET6) {
        src = &addr.addr6.sin6_addr;
    } else {
        return {};
    }

    return inet_ntop(sa->sa_family, src, buffer, sizeof(buffer)) ? buffer : std::string();
}

static std::string read_file_to_string(const std::string &path)
{
    std::ifstream input(path);
    std::ostringstream content;
    content << input.rdbuf();
    return content.str();
}

struct teardown_log_summary {
    unsigned int step1_count = 0;
    unsigned int step1_nonzero_count = 0;
    std::string unittest_lines;
};

static bool parse_unittest_pending_line(const std::string &line, int &step,
                                        unsigned long long &pending_size)
{
    if (line.find("UNITTEST: Polling group ") == std::string::npos) {
        return false;
    }

    size_t step_pos = line.find(" step ");
    size_t pending_pos = line.find("m_pending_to_remove_lst size=");
    if (step_pos == std::string::npos || pending_pos == std::string::npos) {
        return false;
    }

    step = std::strtol(line.c_str() + step_pos + 6, nullptr, 10);
    pending_size = std::strtoull(
        line.c_str() + pending_pos + strlen("m_pending_to_remove_lst size="), nullptr, 10);
    return true;
}

static teardown_log_summary parse_teardown_log(const std::string &output)
{
    teardown_log_summary summary;
    std::istringstream lines(output);
    std::string line;

    while (std::getline(lines, line)) {
        int step = 0;
        unsigned long long pending_size = 0;
        if (!parse_unittest_pending_line(line, step, pending_size)) {
            continue;
        }

        summary.unittest_lines += line + "\n";
        if (step == 1) {
            summary.step1_count++;
            if (pending_size != 0) {
                summary.step1_nonzero_count++;
            }
        }
    }

    return summary;
}

struct worker_context;

struct socket_context {
    worker_context *worker = nullptr;
    unsigned int index = 0;
    bool connected = false;
    bool terminated = false;
    bool peer_done = false;
    bool listener = false;
};

struct worker_context {
    unsigned int index = 0;
    bool is_client = false;
    std::atomic<bool> ready {false};
    sockaddr_store_t bind_addr;
    sockaddr_store_t peer_addr;
    xlio_poll_group_t group = 0;
    xlio_socket_t listen_sock = 0;
    std::vector<xlio_socket_t> sockets;
    std::vector<socket_context> socket_contexts;
    socket_context listener_context;
    std::vector<struct xlio_buf *> pending_rx_bufs;
    struct ibv_mr *mr_buf = nullptr;
    char sndbuf[data_size];
    unsigned int connected_counter = 0;
    unsigned int terminated_counter = 0;
    unsigned int accepted_counter = 0;
    unsigned int comp_cb_counter = 0;
    unsigned int rx_cb_counter = 0;
    unsigned int peer_done_counter = 0;
    unsigned long long acked_bytes = 0;
    unsigned long long rx_bytes = 0;
    unsigned long long sent_bytes = 0;
    unsigned long long send_counter = 0;
    unsigned long long send_retry_counter = 0;
    bool receiver_done = false;

    void init(unsigned int worker_index, bool client, const sockaddr_store_t &base_server_addr,
              const sockaddr_store_t &base_client_addr)
    {
        index = worker_index;
        is_client = client;
        ready = false;
        bind_addr = client ? base_client_addr : base_server_addr;
        peer_addr = base_server_addr;
        sys_set_port((struct sockaddr *)&bind_addr,
                     sys_get_port((struct sockaddr *)&bind_addr) + worker_index);
        sys_set_port((struct sockaddr *)&peer_addr,
                     sys_get_port((struct sockaddr *)&peer_addr) + worker_index);
        group = 0;
        listen_sock = 0;
        sockets.clear();
        socket_contexts.clear();
        pending_rx_bufs.clear();
        mr_buf = nullptr;
        connected_counter = 0;
        terminated_counter = 0;
        accepted_counter = 0;
        comp_cb_counter = 0;
        rx_cb_counter = 0;
        peer_done_counter = 0;
        acked_bytes = 0;
        rx_bytes = 0;
        sent_bytes = 0;
        send_counter = 0;
        send_retry_counter = 0;
        receiver_done = false;
        listener_context = {};
        listener_context.worker = this;
        listener_context.listener = true;
        memset(sndbuf, 'A', sizeof(sndbuf));
    };
};

class ultra_api_socket_close_while_pending_tx : public ultra_api_base {
public:
    void SetUp() override
    {
        if (is_inner_scwpt_run()) {
            xlio_base::SetUp();
        }

        m_workspace = std::getenv("WORKSPACE");
        if (m_workspace) {
            std::cout << "WORKSPACE: '" << m_workspace << "'" << std::endl;
            m_prefix = std::string(m_workspace) + "/tests/gtest/xlio_ultra_api";
        } else {
            std::cout << "WORKSPACE is not set" << std::endl;
            m_prefix = "xlio_ultra_api";
        }
    }

    void destroy_poll_group(xlio_poll_group_t group) { base_destroy_poll_group(group); }

    void run_inner_test_and_verify_output()
    {
        std::string executable = self_executable_path();
        ASSERT_FALSE(executable.empty()) << "Failed to resolve /proc/self/exe";

        std::string client_ip = sockaddr_ip_to_string(client_addr);
        std::string server_ip = sockaddr_ip_to_string(server_addr);
        ASSERT_FALSE(client_ip.empty()) << "Failed to stringify client address";
        ASSERT_FALSE(server_ip.empty()) << "Failed to stringify server address";

        std::string output_path = "/tmp/xlio_scwpt_" + std::to_string(getpid()) + ".log";
        std::string addr_arg = client_ip + "," + server_ip;
        std::string command = "XLIO_SCWPT=1 XLIO_USE_NEW_CONFIG=1 XLIO_CONFIG_FILE=" + m_prefix +
            "/config.json" + " XLIO_INLINE_CONFIG=" + shell_quote("monitor.log.level=details") +
            " " + shell_quote(executable) + " --addr " + shell_quote(addr_arg) + " --port " +
            std::to_string(m_port) +
            " --gtest_filter=ultra_api_socket_close_while_pending_tx.ti_1 > " +
            shell_quote(output_path) + " 2>&1";

        int status = system(command.c_str());
        std::string output = read_file_to_string(output_path);

        ASSERT_NE(-1, status) << "Failed to run command: " << command << "\n"
                              << "Output file: " << output_path << "\n"
                              << "----- child output begin -----\n"
                              << output << "----- child output end -----\n";
        ASSERT_TRUE(WIFEXITED(status)) << "Command did not exit normally: " << command << "\n"
                                       << "Output file: " << output_path << "\n"
                                       << "----- child output begin -----\n"
                                       << output << "----- child output end -----\n";
        ASSERT_EQ(0, WEXITSTATUS(status)) << "Command failed: " << command << "\n"
                                          << "Output file: " << output_path << "\n"
                                          << "----- child output begin -----\n"
                                          << output << "----- child output end -----\n";

        teardown_log_summary summary = parse_teardown_log(output);
        EXPECT_GT(summary.step1_count, 0U)
            << "Missing UNITTEST step 1 lines in " << output_path << "\n"
            << summary.unittest_lines << "\n"
            << "----- child output begin -----\n"
            << output << "----- child output end -----\n";
        // In order not to contaminate our output with multiple copied of the child output,
        // Run this expect only if the prev one was OK
        if (summary.step1_count > 0) {
            EXPECT_GT(summary.step1_nonzero_count, 0U)
                << "Expected at least one UNITTEST step 1 line with pending sockets\n"
                << summary.unittest_lines << "\n"
                << "----- child output begin -----\n"
                << output << "----- child output end -----\n";
        }
        if (!HasFailure()) {
            unlink(output_path.c_str());
        }
    }

    static bool should_stop_sending() { return stop_sending.load(); }

    static void signal_stop_sending() { stop_sending.store(true); }

    static bool is_expected_close_error(int value)
    {
        return value == ECONNRESET || value == EPIPE || value == ECONNABORTED || value == ENOTCONN;
    }

    static void socket_event_cb(xlio_socket_t sock, uintptr_t userdata_sq, int event, int value)
    {
        UNREFERENCED_PARAMETER(sock);

        socket_context *ctx = reinterpret_cast<socket_context *>(userdata_sq);
        if (!ctx || !ctx->worker) {
            ADD_FAILURE() << "Missing socket callback context";
            return;
        }
        worker_context *worker = ctx->worker;

        if (event == XLIO_SOCKET_EVENT_ESTABLISHED) {
            if (!ctx->connected) {
                ctx->connected = true;
                worker->connected_counter++;
            }
        } else if (event == XLIO_SOCKET_EVENT_CLOSED) {
            if (!ctx->peer_done) {
                ctx->peer_done = true;
                worker->peer_done_counter++;
            }
            if (!worker->is_client) {
                signal_stop_sending();
            }
        } else if (event == XLIO_SOCKET_EVENT_TERMINATED) {
            if (!ctx->terminated) {
                ctx->terminated = true;
                worker->terminated_counter++;
            }
            if (!worker->is_client) {
                signal_stop_sending();
            }
        } else if (event == XLIO_SOCKET_EVENT_ERROR) {
            EXPECT_TRUE(is_expected_close_error(value))
                << "Unexpected socket error event, worker=" << worker->index
                << ", socket=" << ctx->index << ", error=" << value;
            if (!ctx->peer_done) {
                ctx->peer_done = true;
                worker->peer_done_counter++;
            }
            if (!worker->is_client) {
                signal_stop_sending();
            }
        }
    }

    static void socket_comp_cb(xlio_socket_t sock, uintptr_t userdata_sq, uintptr_t userdata_op)
    {
        UNREFERENCED_PARAMETER(sock);
        UNREFERENCED_PARAMETER(userdata_op);

        socket_context *ctx = reinterpret_cast<socket_context *>(userdata_sq);
        if (!ctx || !ctx->worker) {
            ADD_FAILURE() << "Missing completion callback context";
            return;
        }
        ctx->worker->comp_cb_counter++;
    }

    static void socket_rx_cb(xlio_socket_t sock, uintptr_t userdata_sq, void *data, size_t len,
                             struct xlio_buf *buf)
    {
        UNREFERENCED_PARAMETER(data);

        socket_context *ctx = reinterpret_cast<socket_context *>(userdata_sq);
        if (!ctx || !ctx->worker) {
            ADD_FAILURE() << "Missing RX callback context";
            xlio_api->xlio_socket_buf_free(sock, buf);
            return;
        }
        worker_context *worker = ctx->worker;
        worker->rx_cb_counter++;
        if (worker->is_client) {
            worker->rx_bytes += len;
            if (!worker->receiver_done) {
                worker->acked_bytes += len;
                xlio_api->xlio_socket_buf_free(sock, buf);
                if ((worker->acked_bytes / progress_report_bytes) !=
                    ((worker->acked_bytes - len) / progress_report_bytes)) {
                    timestamped_fprintf(stderr, "[client %u] ack done for %llu bytes total\n",
                                        worker->index, worker->acked_bytes);
                }
                if (worker->acked_bytes >= receiver_ack_bytes) {
                    worker->receiver_done = true;
                    stop_receiving.store(true);
                    timestamped_fprintf(
                        stderr, "[client %u] acknowledged %llu bytes, retaining later RX buffers\n",
                        worker->index, worker->acked_bytes);
                }
                return;
            }

            worker->pending_rx_bufs.push_back(buf);
            return;
        }

        xlio_api->xlio_socket_buf_free(sock, buf);
    }

    static void socket_accept_cb(xlio_socket_t sock, xlio_socket_t parent_sock,
                                 uintptr_t parent_userdata)
    {
        UNREFERENCED_PARAMETER(parent_sock);

        socket_context *listen_ctx = reinterpret_cast<socket_context *>(parent_userdata);
        ASSERT_TRUE(listen_ctx != nullptr);
        worker_context *worker = listen_ctx->worker;
        ASSERT_TRUE(worker != nullptr);
        ASSERT_LT(worker->accepted_counter, num_sockets);

        socket_context *accepted_ctx = &worker->socket_contexts[worker->accepted_counter];
        int rc = xlio_api->xlio_socket_update(sock, 0, reinterpret_cast<uintptr_t>(accepted_ctx));
        ASSERT_EQ(rc, 0);
        worker->sockets.push_back(sock);
        worker->accepted_counter++;
    }

    template <typename Predicate>
    static bool poll_until(xlio_poll_group_t group, Predicate done, const char *condition,
                           int timeout_seconds = 300)
    {
        auto timeout = std::chrono::seconds(timeout_seconds);
        auto start_time = std::chrono::steady_clock::now();
        do {
            xlio_api->xlio_poll_group_poll(group);
            if (done()) {
                return true;
            }
        } while (std::chrono::steady_clock::now() - start_time < timeout);

        ADD_FAILURE() << "Timed out waiting for " << condition;
        return false;
    }

    static void poll_for(xlio_poll_group_t group, int timeout_seconds)
    {
        auto timeout = std::chrono::seconds(timeout_seconds);
        auto start_time = std::chrono::steady_clock::now();
        do {
            xlio_api->xlio_poll_group_poll(group);
        } while (std::chrono::steady_clock::now() - start_time < timeout);
    }

    static void create_poll_group(worker_context &worker)
    {
        xlio_poll_group_attr gattr = {
            .flags = XLIO_GROUP_FLAG_DIRTY,
            .socket_event_cb = &socket_event_cb,
            .socket_comp_cb = &socket_comp_cb,
            .socket_rx_cb = &socket_rx_cb,
            .socket_accept_cb = &socket_accept_cb,
        };
        int rc = xlio_api->xlio_poll_group_create(&gattr, &worker.group);
        ASSERT_EQ(0, rc);
    }

    static void destroy_socket(xlio_socket_t sock)
    {
        int rc = xlio_api->xlio_socket_destroy(sock);
        ASSERT_EQ(0, rc);
    }

    static void destroy_poll_group_static(xlio_poll_group_t group)
    {
        int rc = xlio_api->xlio_poll_group_destroy(group);
        ASSERT_EQ(0, rc);
    }

    static void server_worker(worker_context *worker)
    {
        int rc;

        create_poll_group(*worker);
        timestamped_fprintf(stderr, "[server %u] poll group created\n", worker->index);
        xlio_socket_attr sattr = {
            .flags = 0,
            .domain = worker->bind_addr.addr.sa_family,
            .group = worker->group,
            .userdata_sq = reinterpret_cast<uintptr_t>(&worker->listener_context),
        };
        rc = xlio_api->xlio_socket_create(&sattr, &worker->listen_sock);
        ASSERT_EQ(0, rc);

        rc = xlio_api->xlio_socket_bind(worker->listen_sock, (struct sockaddr *)&worker->bind_addr,
                                        sizeof(worker->bind_addr));
        ASSERT_EQ(0, rc);

        rc = xlio_api->xlio_socket_listen(worker->listen_sock);
        ASSERT_EQ(0, rc);
        timestamped_fprintf(stderr, "[server %u] listening on port %u\n", worker->index,
                            sys_get_port((struct sockaddr *)&worker->bind_addr));

        worker->socket_contexts.resize(num_sockets);
        for (unsigned int i = 0; i < num_sockets; ++i) {
            worker->socket_contexts[i].worker = worker;
            worker->socket_contexts[i].index = i;
        }

        worker->ready = true;
        ASSERT_TRUE(poll_until(
            worker->group, [worker] { return worker->accepted_counter == num_sockets; },
            "all server accepts"));
        timestamped_fprintf(stderr, "[server %u] accepted %u sockets\n", worker->index,
                            worker->accepted_counter);

        struct ibv_pd *pd = xlio_api->xlio_socket_get_pd(worker->sockets.front());
        ASSERT_TRUE(pd != NULL);
        worker->mr_buf =
            ibv_reg_mr(pd, worker->sndbuf, sizeof(worker->sndbuf), IBV_ACCESS_LOCAL_WRITE);
        ASSERT_TRUE(worker->mr_buf != NULL);

        xlio_socket_send_attr send_attr = {
            .flags = 0,
            .mkey = worker->mr_buf->lkey,
            .userdata_op = 0x1,
        };
        timestamped_fprintf(
            stderr, "[server %u] sending continuously: %zu-byte messages across %u sockets\n",
            worker->index, data_size, num_sockets);
        auto send_start_time = std::chrono::steady_clock::now();
        auto send_timeout = std::chrono::seconds(stress_timeout_seconds);
        unsigned int socket_index = 0;
        unsigned long long next_report_bytes = progress_report_bytes;
        // Any server worker close/error event should cause all server send loops to stop.
        while (!should_stop_sending()) {
            // Always poll, to get TX completions and errors.
            xlio_api->xlio_poll_group_poll(worker->group);
            if (should_stop_sending()) {
                break;
            }

            if (worker->send_counter - worker->comp_cb_counter >= queue_depth_in_msgs) {
                continue;
            }
            xlio_socket_t socket = worker->sockets[socket_index];
            int send_rc = xlio_api->xlio_socket_send(socket, worker->sndbuf, data_size, &send_attr);
            if (send_rc == 0) {
                xlio_api->xlio_socket_flush(socket);
                worker->send_counter++;
                worker->sent_bytes += data_size;
                if (worker->sent_bytes >= next_report_bytes) {
                    timestamped_fprintf(
                        stderr,
                        "[server %u] sent %llu bytes in %llu sends, completions=%u, retries=%llu\n",
                        worker->index, worker->sent_bytes, worker->send_counter,
                        worker->comp_cb_counter, worker->send_retry_counter);
                    next_report_bytes += progress_report_bytes;
                }
                socket_index = (socket_index + 1) % worker->sockets.size();
            } else {
                int send_errno = errno;
                if (send_errno == ENOMEM || send_errno == EAGAIN || send_errno == EWOULDBLOCK) {
                    worker->send_retry_counter++;
                } else if (is_expected_close_error(send_errno)) {
                    timestamped_fprintf(
                        stderr, "[server %u] send stopped by socket error %d after %llu bytes\n",
                        worker->index, send_errno, worker->sent_bytes);
                    break;
                } else {
                    ADD_FAILURE() << "Unexpected xlio_socket_send failure, worker=" << worker->index
                                  << ", socket_index=" << socket_index << ", errno=" << send_errno;
                    break;
                }
            }

            if (std::chrono::steady_clock::now() - send_start_time >= send_timeout) {
                ADD_FAILURE() << "Timed out waiting for peer close while sending, worker="
                              << worker->index << ", sent_bytes=" << worker->sent_bytes;
                break;
            }
        }

        signal_stop_sending();
        timestamped_fprintf(
            stderr,
            "[server %u] send loop stopped: sent=%llu bytes, sends=%llu, completions=%u, "
            "peer_done=%u, terminated=%u\n",
            worker->index, worker->sent_bytes, worker->send_counter, worker->comp_cb_counter,
            worker->peer_done_counter, worker->terminated_counter);

        timestamped_fprintf(stderr, "[server %u] closing listener and %zu accepted sockets\n",
                            worker->index, worker->sockets.size());
        destroy_socket(worker->listen_sock);
        for (auto socket : worker->sockets) {
            destroy_socket(socket);
        }

        unsigned long long pending_tx = worker->send_counter - worker->comp_cb_counter;
        timestamped_fprintf(
            stderr,
            "[server %u] destroying poll group with pending_tx=%llu, completions=%u, "
            "terminated=%u\n",
            worker->index, pending_tx, worker->comp_cb_counter, worker->terminated_counter);
        EXPECT_GT(pending_tx, 0ULL);
        EXPECT_GT(worker->comp_cb_counter, 0U);

        destroy_poll_group_static(worker->group);
        pending_tx = worker->send_counter - worker->comp_cb_counter;
        timestamped_fprintf(stderr,
                            "[server %u] After poll group dtored, pending_tx=%llu, completions=%u, "
                            "terminated=%u\n",
                            worker->index, pending_tx, worker->comp_cb_counter,
                            worker->terminated_counter);
        EXPECT_EQ(pending_tx, 0ULL);

        if (worker->mr_buf) {
            ibv_dereg_mr(worker->mr_buf);
            worker->mr_buf = nullptr;
        }
        timestamped_fprintf(stderr, "[server %u] done\n", worker->index);
    }

    static void client_worker(worker_context *worker)
    {
        int rc;

        create_poll_group(*worker);
        timestamped_fprintf(stderr, "[client %u] poll group created, connecting to port %u\n",
                            worker->index, sys_get_port((struct sockaddr *)&worker->peer_addr));
        worker->socket_contexts.resize(num_sockets);
        worker->sockets.resize(num_sockets);

        sockaddr_store_t client_bind_addr = worker->bind_addr;
        sys_set_port((struct sockaddr *)&client_bind_addr, 0);

        for (unsigned int i = 0; i < num_sockets; ++i) {
            worker->socket_contexts[i].worker = worker;
            worker->socket_contexts[i].index = i;
            xlio_socket_attr sattr = {
                .flags = 0,
                .domain = worker->peer_addr.addr.sa_family,
                .group = worker->group,
                .userdata_sq = reinterpret_cast<uintptr_t>(&worker->socket_contexts[i]),
            };
            rc = xlio_api->xlio_socket_create(&sattr, &worker->sockets[i]);
            ASSERT_EQ(0, rc);

            rc = xlio_api->xlio_socket_bind(
                worker->sockets[i], (struct sockaddr *)&client_bind_addr, sizeof(client_bind_addr));
            ASSERT_EQ(0, rc);

            rc = xlio_api->xlio_socket_connect(worker->sockets[i],
                                               (struct sockaddr *)&worker->peer_addr,
                                               sizeof(worker->peer_addr));
            ASSERT_EQ(0, rc);
        }

        ASSERT_TRUE(poll_until(
            worker->group, [worker] { return worker->connected_counter == num_sockets; },
            "all client connections"));
        timestamped_fprintf(stderr, "[client %u] all %u sockets established\n", worker->index,
                            worker->connected_counter);
        timestamped_fprintf(stderr,
                            "[client %u] acknowledging first %llu bytes, then closing sockets\n",
                            worker->index, receiver_ack_bytes);
        ASSERT_TRUE(poll_until(
            worker->group, [worker] { return worker->receiver_done || stop_receiving.load(); },
            "client acknowledged target RX bytes", stress_timeout_seconds));
        timestamped_fprintf(
            stderr,
            "[client %u] receive stage done: rx=%llu bytes, acked=%llu bytes, callbacks=%u, "
            "retained=%zu\n",
            worker->index, worker->rx_bytes, worker->acked_bytes, worker->rx_cb_counter,
            worker->pending_rx_bufs.size());

        timestamped_fprintf(stderr, "[client %u] destroying %zu sockets\n", worker->index,
                            worker->sockets.size());
        for (auto socket : worker->sockets) {
            destroy_socket(socket);
        }

        ASSERT_TRUE(poll_until(
            worker->group, [worker] { return worker->terminated_counter == num_sockets; },
            "all client socket terminations"));
        timestamped_fprintf(stderr, "[client %u] all sockets terminated\n", worker->index);

        destroy_poll_group_static(worker->group);
        timestamped_fprintf(stderr, "[client %u] done\n", worker->index);
    }

    static void wait_workers_ready(worker_context *workers)
    {
        auto timeout = std::chrono::seconds(30);
        auto start_time = std::chrono::steady_clock::now();
        do {
            bool all_ready = true;
            for (unsigned int i = 0; i < num_workers; ++i) {
                all_ready = all_ready && workers[i].ready;
            }
            if (all_ready) {
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        } while (std::chrono::steady_clock::now() - start_time < timeout);

        FAIL() << "Timed out waiting for worker threads to listen";
    }

    char *m_workspace {nullptr};
    std::string m_prefix;
};

/**
 * @test ultra_api_socket_close_while_pending_tx.ti_1
 * @brief
 *    Close TCP sockets from two poll-group workers while sent data is still pending.
 * @details
 */
TEST_F(ultra_api_socket_close_while_pending_tx, ti_1)
{
    test_log_start_time = std::chrono::steady_clock::now();
    if (!is_inner_scwpt_run()) {
        run_inner_test_and_verify_output();
        return;
    }

    stop_sending.store(false);
    stop_receiving.store(false);
    int pid = fork();
    ultra_api_base::SetUp();

    if (pid != 0) {
        worker_context workers[num_workers];
        std::thread threads[num_workers];
        timestamped_fprintf(stderr, "[server] starting %u worker threads\n", num_workers);
        for (unsigned int i = 0; i < num_workers; ++i) {
            workers[i].init(i, false, server_addr, client_addr);
            threads[i] = std::thread(&server_worker, &workers[i]);
        }

        wait_workers_ready(workers);
        timestamped_fprintf(stderr, "[server] all worker threads are listening\n");
        barrier_fork(pid, false); // Tell child that we are listening.

        for (auto &thread : threads) {
            thread.join();
        }
        timestamped_fprintf(stderr, "[server] all worker threads joined\n");
        ASSERT_EQ(0, wait_fork(pid));
    } else {
        barrier_fork(pid, false); // Wait for parent to bind and listen.

        worker_context workers[num_workers];
        std::thread threads[num_workers];
        timestamped_fprintf(stderr, "[client] starting %u worker threads\n", num_workers);
        for (unsigned int i = 0; i < num_workers; ++i) {
            workers[i].init(i, true, server_addr, client_addr);
            threads[i] = std::thread(&client_worker, &workers[i]);
        }

        for (auto &thread : threads) {
            thread.join();
        }
        timestamped_fprintf(stderr, "[client] all worker threads joined\n");
        exit(testing::Test::HasFailure());
    }
}

#endif /* EXTRA_API_ENABLED */
