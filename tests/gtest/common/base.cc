/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "base.h"

uint16_t test_base::m_port = 0;
int test_base::m_family = PF_INET;
int test_base::m_break_signal = 0;

/* Pid of the process that runs the test binary. Set by fork_guard_init(). */
static pid_t g_main_pid;

/*
 * Terminates a forked child that escaped its test body. Doesn't touch the gtest state and
 * doesn't use stdio, both belong to the parent process.
 */
static void fork_escape_exit(const char *test_case_name, const char *test_name)
{
    char buf[256];
    int len = snprintf(buf, sizeof(buf),
                       "[  FORK  ] pid %d escaped its test body and reached %s.%s, terminating\n",
                       static_cast<int>(getpid()), test_case_name, test_name);

    if (len > 0) {
        size_t n =
            (static_cast<size_t>(len) < sizeof(buf) ? static_cast<size_t>(len) : sizeof(buf) - 1);
        ssize_t ret = write(STDERR_FILENO, buf, n);
        UNREFERENCED_PARAMETER(ret);
    }
    _exit(GTEST_FORK_ESCAPE_STATUS);
}

class fork_escape_guard : public testing::EmptyTestEventListener {
    virtual void OnTestStart(const testing::TestInfo &test_info)
    {
        if (getpid() == g_main_pid) {
            return;
        }
        /* The event is delivered before the fixture of the next test is constructed, so the
         * child is stopped before it touches a socket, a port or a counter. */
        fork_escape_exit(test_info.test_case_name(), test_info.name());
    }
    virtual void OnTestProgramEnd(const testing::UnitTest &unit_test)
    {
        UNREFERENCED_PARAMETER(unit_test);
        if (getpid() != g_main_pid) {
            /* A child that escaped on the last test of the run. Terminate it before the
             * reporting listeners overwrite the TAP and XML output files of the parent. */
            fork_escape_exit("", "end of the test program");
        }
    }
};

void fork_guard_init(void)
{
    g_main_pid = getpid();
    testing::UnitTest::GetInstance()->listeners().Append(new fork_escape_guard());
}

static void convert_and_copy_address(const sockaddr_store_t &source, sockaddr_store_t &dest,
                                     sa_family_t target_family)
{
    sa_family_t source_family = ((struct sockaddr *)&source)->sa_family;

    if (source_family != target_family) {
        // Only IPv4→IPv6 conversion is currently supported
        ASSERT_EQ(AF_INET, source_family) << "Address conversion requires IPv4 source";
        ASSERT_EQ(AF_INET6, target_family) << "Address conversion requires IPv6 target";

        memset(&dest, 0, sizeof(dest));
        ((struct sockaddr *)&dest)->sa_family = target_family;
        sys_ipv4_to_ipv6(&((struct sockaddr_in *)&source)->sin_addr,
                         &((struct sockaddr_in6 *)&dest)->sin6_addr);
        sys_set_port((struct sockaddr *)&dest, sys_get_port((struct sockaddr *)&source));
    } else {
        memcpy(&dest, &source, sizeof(dest));
    }
}

test_base::test_base()
{
    m_port = gtest_conf.port;
    if (((struct sockaddr *)&gtest_conf.server_addr)->sa_family ==
        ((struct sockaddr *)&gtest_conf.client_addr)->sa_family) {
        m_family = ((struct sockaddr *)&gtest_conf.server_addr)->sa_family;
    } else {
        m_family = PF_INET6;
    }

    convert_and_copy_address(gtest_conf.client_addr, client_addr, m_family);
    convert_and_copy_address(gtest_conf.server_addr, server_addr, m_family);
    convert_and_copy_address(gtest_conf.remote_unreachable_addr, remote_unreachable_addr, m_family);

    memset(&bogus_addr, 0, sizeof(bogus_addr));
    ((struct sockaddr *)&bogus_addr)->sa_family = m_family;
    sys_set_port((struct sockaddr *)&bogus_addr, 0);
    if (m_family == AF_INET) {
        inet_pton(AF_INET, "1.1.1.1", &(((struct sockaddr_in *)&bogus_addr)->sin_addr));
    }
    if (m_family == AF_INET6) {
        inet_pton(AF_INET6, "2001:1:1:1:1:1:1:1",
                  &(((struct sockaddr_in6 *)&bogus_addr)->sin6_addr));
    }

    m_efd_signal = 0;
    /* Every read is guarded by poll(), and the drain of barrier_fork_wait() must not block. */
    m_efd = eventfd(m_efd_signal, EFD_NONBLOCK);

    m_break_signal = 0;
}

test_base::~test_base()
{
    m_break_signal = 0;
}

void *test_base::thread_func(void *arg)
{
    test_base *self = reinterpret_cast<test_base *>(arg);
    self->barrier(); /* Let all threads start in the same time */
    return NULL;
}

void test_base::init()
{
}

void test_base::cleanup()
{
}

bool test_base::test_mapped_ipv4() const
{
    return (m_family != AF_INET6);
}

void test_base::ipv4_to_mapped(sockaddr_store_t &inout)
{
    in_port_t port = inout.addr4.sin_port;
    in_addr addr = inout.addr4.sin_addr;
    memset(&inout, 0, sizeof(inout));
    inout.addr6.sin6_family = AF_INET6;
    inout.addr6.sin6_port = port;
    reinterpret_cast<uint16_t *>(&inout.addr6.sin6_addr)[5] = 0xFFFFU;
    reinterpret_cast<in_addr *>(&inout.addr6.sin6_addr)[3] = addr;
}

int test_base_sock::set_socket_rcv_timeout(int fd, int timeout_sec)
{
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

int test_base_sock::sock_create_to(sa_family_t family, bool reuse_addr, int timeout_sec) const
{
    int fd = sock_create_fa(family, reuse_addr);
    if (fd >= 0 && 0 != set_socket_rcv_timeout(fd, timeout_sec)) {
        close(fd);
        fd = -1;
    }

    return fd;
}

int test_base_sock::sock_create_fa_nb(sa_family_t family) const
{
    int fd = sock_create_fa(family, false);
    if (fd < 0) {
        return fd;
    }

    int rc = test_base::sock_noblock(fd);
    if (rc < 0) {
        log_error("failed sock_noblock() %s\n", strerror(errno));
        goto err;
    }

    return fd;

err:
    close(fd);

    return (-1);
}

int test_base_sock::sock_create_typed(sa_family_t family, int type, bool reuse_addr)
{
    int rc;
    int fd;
    int opt_val = (reuse_addr ? 1 : 0);

    fd = socket(family, type, IPPROTO_IP);
    if (fd < 0) {
        log_error("failed socket(%hu) %s\n", family, strerror(errno));
        return -1;
    }

    rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));
    if (rc < 0) {
        log_error("failed setsockopt(SO_REUSEADDR) %s\n", strerror(errno));
        goto err;
    }

    return fd;

err:
    close(fd);

    return (-1);
}

int test_base_sock::bind_to_device(int fd, const sockaddr_store_t &addr_store)
{
    char ifname[128] = {0};
    char *rcs = sys_addr2dev(&addr_store.addr, ifname, sizeof(ifname));
    if (rcs) {
        log_trace("SO_BINDTODEVICE: fd=%d as %s on %s\n", fd, sys_addr2str(&addr_store.addr),
                  ifname);

        return setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
    }

    errno = ENOMEDIUM;
    return -1;
}

bool test_base::barrier()
{
    int ret = pthread_barrier_wait(&m_barrier);
    if (ret == 0) {
        return false;
    } else if (ret == PTHREAD_BARRIER_SERIAL_THREAD) {
        return true;
    } else {
        log_fatal("pthread_barrier_wait() failed\n");
    }
    return false;
}

int test_base::sock_noblock(int fd)
{
    int rc = 0;
    int flag;

    flag = fcntl(fd, F_GETFL);
    if (flag < 0) {
        rc = -errno;
        log_error("failed to get socket flags errno: %s\n", strerror(errno));
    }
    flag |= O_NONBLOCK;
    rc = fcntl(fd, F_SETFL, flag);
    if (rc < 0) {
        rc = -errno;
        log_error("failed to set socket flags errno: %s\n", strerror(errno));
    }

    return rc;
}

int test_base::event_wait(struct epoll_event *event)
{
    int rc = 0;
    int fd;
    int efd = -1;
    int timeout = 10 * 1000;

    if (!event) {
        return -1;
    }

    fd = event->data.fd;
    efd = epoll_create1(0);
    rc = epoll_ctl(efd, EPOLL_CTL_ADD, fd, event);
    if (rc < 0) {
        log_error("failed epoll_ctl() errno: %s\n", strerror(errno));
        goto err;
    }

    event->events = 0;
    rc = epoll_wait(efd, event, 1, timeout);
    if (rc < 0) {
        log_error("failed epoll_wait() errno: %s\n", strerror(errno));
    }

    epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);

err:
    close(efd);

    return rc;
}

int test_base::wait_fork(int pid)
{
    int status = 0;

    pid = waitpid(pid, &status, 0);
    if (0 > pid) {
        log_error("failed waitpid() errno: %s\n", strerror(errno));
        return (-1);
    }
    if (WIFEXITED(status)) {
        const int exit_status = WEXITSTATUS(status);
        if (exit_status == GTEST_FORK_ESCAPE_STATUS) {
            log_error("child process %d escaped its test body, likely a fatal assertion "
                      "returned from the test body and skipped the exit() call\n",
                      pid);
        } else if (exit_status != 0) {
            log_trace("non-zero exit status: %d from waitpid() errno: %s\n", exit_status,
                      strerror(errno));
        }
        return exit_status;
    } else if (WIFSIGNALED(status)) {
        log_error("child process killed by signal: %d\n", WTERMSIG(status));
        return (-2);
    } else {
        log_error("non-normal exit from child process status: %d\n", status);
        return (-3);
    }
}

/* Monotonic milliseconds, immune to the wall clock steps of the test machine. */
static uint64_t barrier_time_msec(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return static_cast<uint64_t>(ts.tv_sec) * 1000U + ts.tv_nsec / 1000000U;
}

int test_base::kill_fork(int pid)
{
    int status = 0;

    if (0 >= pid) {
        return (-1);
    }
    if (0 > kill(pid, SIGKILL) && ESRCH != errno) {
        log_error("failed kill() errno: %s\n", strerror(errno));
        return (-1);
    }
    while (0 > waitpid(pid, &status, 0)) {
        if (EINTR == errno) {
            continue;
        }
        /* The child was already reaped, it is gone all the same. */
        if (ECHILD != errno) {
            log_error("failed waitpid() errno: %s\n", strerror(errno));
            return (-1);
        }
        break;
    }

    return 0;
}

bool test_base::peer_alive(pid_t pid)
{
    siginfo_t si;

    memset(&si, 0, sizeof(si));
    /* WNOWAIT leaves the child in a waitable state, so a later wait_fork() still reports its
     * real exit status. kill(pid, 0) is not usable here, a zombie still answers it. */
    if (0 > waitid(P_PID, pid, &si, WEXITED | WNOWAIT | WNOHANG)) {
        /* ECHILD means the process is not our child anymore, i.e. it is gone. Treat any other
         * error as alive and let the deadline bound the wait. */
        return (ECHILD != errno);
    }

    return (0 == si.si_pid);
}

bool test_base::barrier_read()
{
    ssize_t ret = read(m_efd, &m_efd_signal, sizeof(m_efd_signal));

    if (0 > ret) {
        if (EAGAIN != errno && EINTR != errno) {
            log_error("failed read() errno: %s\n", strerror(errno));
        }
        return false;
    }
    if (0 == m_efd_signal) {
        return false;
    }
    m_efd_signal = 0;

    return true;
}

bool test_base::barrier_fork_wait(int pid)
{
    /* The peer of a waiting parent is the child <pid>, the peer of a waiting child is the
     * process which forked it. */
    const bool is_child = (0 == pid);
    const uint64_t deadline = barrier_time_msec() + TEST_BARRIER_TIMEOUT_SEC * 1000ULL;
    pid_t peer = pid;
    bool peer_lost = false;

    if (is_child) {
        peer = getppid();
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        /* Close the window where the parent dies before PDEATHSIG is armed. */
        peer_lost = (getppid() != peer);
    }

    while (!peer_lost) {
        struct pollfd pfd;

        pfd.fd = m_efd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        int rc = poll(&pfd, 1, TEST_BARRIER_TICK_MSEC);
        if (0 > rc && EINTR != errno) {
            log_error("failed poll() errno: %s\n", strerror(errno));
            ADD_FAILURE() << "barrier_fork(): poll() failed, errno " << errno;
            m_break_signal++;
            return false;
        }
        if (0 < rc && barrier_read()) {
            return true;
        }

        peer_lost = (is_child ? (getppid() != peer) : !peer_alive(peer));
        if (!peer_lost && barrier_time_msec() >= deadline) {
            ADD_FAILURE() << "barrier_fork(): " << (is_child ? "child" : "parent")
                          << " gave up after " << TEST_BARRIER_TIMEOUT_SEC << "s, peer " << peer
                          << " is alive but didn't signal the barrier";
            if (!is_child) {
                /* Unwedge the child without reaping it, so that the wait_fork() of the test
                 * still completes and reports the SIGKILL. */
                kill(peer, SIGKILL);
            }
            m_break_signal++;
            return false;
        }
    }

    /* The peer may have signalled the barrier just before it exited. */
    if (barrier_read()) {
        return true;
    }
    ADD_FAILURE() << "barrier_fork(): " << (is_child ? "child" : "parent") << " lost peer " << peer
                  << ", it exited without signalling the barrier";
    m_break_signal++;

    return false;
}

bool test_base::barrier_fork(int pid, bool sync_parent)
{
    ssize_t ret;

    m_break_signal = 0;
    if ((0 == pid && !sync_parent) || (0 != pid && sync_parent)) {
        return barrier_fork_wait(pid);
    }

    signal(SIGCHLD, handle_signal);
    m_efd_signal++;
    ret = write(m_efd, &m_efd_signal, sizeof(m_efd_signal));
    if (ret != static_cast<ssize_t>(sizeof(m_efd_signal))) {
        log_error("write() failed\n");
        return false;
    }

    return true;
}

void test_base::handle_signal(int signo)
{
    switch (signo) {
    case SIGCHLD:
        /* Child is exiting so parent should complete test too */
        m_break_signal++;
        break;
    default:
        return;
    }
}
