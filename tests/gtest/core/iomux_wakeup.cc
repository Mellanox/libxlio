/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/*
 * Regression tests for RM 5397559: newly joined offloaded socket readiness must
 * take precedence over EINTR when an initially empty epoll set wakes up.
 *
 * Each case runs in a child process, re-executed with the test-only library
 * libiomux_wait_hook.so preloaded AFTER libxlio.so. The call path remains:
 *   gtest -> XLIO epoll_wait/epoll_pwait -> helper -> libc -> kernel.
 * XLIO still intercepts the application's call and executes its real iomux code.
 *
 * The test starts with an empty epoll set and arms a one-shot helper callback.
 * After the zero-timeout kernel wait returns, but before XLIO processes its
 * result, the callback adds a real UDP socket and raises a signal. This pins down
 * the race without sleeps or concurrent threads. The kernel returned no user
 * events, so XLIO must collect the newly joined socket's readiness before
 * deciding whether to return EINTR. The helper does not fabricate ready events.
 *
 * EPOLLOUT on an unbound UDP socket supplies readiness without traffic or a peer.
 * The SIGINT cases exercise XLIO's exit flag; the epoll_pwait SIGUSR1 case leaves
 * a blocked signal pending to exercise its signal-mask interruption check.
 * Controls verify that readiness also works without a signal and that an empty
 * EPOLLIN wakeup still returns EINTR. Fork/re-exec confines signal state and the
 * preload helper to these tests. Cases skip when XLIO is not loaded. The pending
 * signal variant skips epoll_wait because only epoll_pwait accepts a signal mask.
 *
 * Build and run from the repository root:
 *   make -C tests/gtest
 *   LD_PRELOAD=<path>/libxlio.so tests/gtest/gtest --gtest_filter='shutdown/iomux_wakeup.*'
 * Keep .libs/libiomux_wait_hook.so in the gtest build directory: the child loads
 * it from GTEST_BUILDDIR, which is recorded when the test binary is compiled.
 */

#include <dlfcn.h>
#include <functional>
#include <string>

#include "common/def.h"
#include "common/log.h"
#include "common/cmn.h"
#include "common/base.h"
#include "xlio_extra.h"

namespace {
using arm_hook_t = void (*)(int, void (*)());
std::function<void()> on_wait_return;
volatile sig_atomic_t delivered_signal;

void signal_handler(int signo)
{
    delivered_signal = signo;
}
void wait_callback()
{
    on_wait_return();
}
} // namespace

class iomux_wakeup : public testing::TestWithParam<bool> {
protected:
    void run(bool ready, int signo)
    {
        auto api = xlio_get_api();
        if (!api) {
            GTEST_SKIP() << "Requires libxlio preloaded";
        }

        auto arm = reinterpret_cast<arm_hook_t>(dlsym(RTLD_DEFAULT, "iomux_arm_wait_hook"));
        pid_t pid = fork();
        ASSERT_LE(0, pid);
        if (pid != 0) {
            EXPECT_EQ(0, test_base::wait_fork(pid));
            return;
        }
        alarm(15);

        // Re-exec once to put the helper after XLIO in the dynamic linker's search order.
        // No helper is injected into other suites, and SIGINT state stays in the child.
        if (!arm) {
            if (getenv("XLIO_GTEST_WAIT_HOOK")) {
                fprintf(stderr, "The iomux wait helper did not export its hook\n");
                _exit(2);
            }
            setenv("XLIO_GTEST_WAIT_HOOK", "1", 1);
            Dl_info info = {};
            if (!dladdr(reinterpret_cast<void *>(api->dump_fd_stats), &info)) {
                _exit(2);
            }
            const char *preload = getenv("LD_PRELOAD");
            std::string libraries = preload && *preload ? preload : info.dli_fname;
            libraries += ":" GTEST_BUILDDIR "/.libs/libiomux_wait_hook.so";
            setenv("LD_PRELOAD", libraries.c_str(), 1);
            const auto *test = testing::UnitTest::GetInstance()->current_test_info();
            std::string filter =
                std::string("--gtest_filter=") + test->test_case_name() + "." + test->name();
            execl("/proc/self/exe", "gtest", filter.c_str(), nullptr);
            _exit(2);
        }

        exercise(arm, ready, signo);
        fflush(nullptr);
        _exit(testing::Test::HasFailure() ? 1 : 0);
    }

    void exercise(arm_hook_t arm, bool ready, int signo)
    {
        // An unbound UDP socket is writable without traffic or a peer. XLIO must track
        // it as offloaded for this test to pass; kernel fallback cannot harvest it here.
        int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        ASSERT_LE(0, fd);
        int epfd = epoll_create1(EPOLL_CLOEXEC);
        ASSERT_LE(0, epfd);
        sigset_t mask;
        sigemptyset(&mask);
        if (signo) {
            struct sigaction action = {};
            action.sa_handler = signal_handler;
            sigemptyset(&action.sa_mask);
            ASSERT_EQ(0, sigaction(signo, &action, nullptr));
        }
        if (signo == SIGUSR1) {
            sigset_t blocked;
            sigemptyset(&blocked);
            sigaddset(&blocked, SIGUSR1);
            ASSERT_EQ(0, sigprocmask(SIG_BLOCK, &blocked, nullptr));
        }
        bool hook_called = false;
        on_wait_return = [&]() {
            hook_called = true;
            epoll_event added = {};
            added.events = (ready ? EPOLLOUT : EPOLLIN) | EPOLLET;
            added.data.u64 = 0x5397559;
            ASSERT_EQ(0, epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &added));
            if (signo) {
                ASSERT_EQ(0, raise(signo));
            }
        };
        arm(epfd, wait_callback);
        epoll_event event = {};
        errno = 0;
        int rc =
            GetParam() ? epoll_pwait(epfd, &event, 1, 0, &mask) : epoll_wait(epfd, &event, 1, 0);
        int wait_errno = errno;
        ASSERT_TRUE(hook_called) << "The test did not reach XLIO's OS-wait boundary";
        if (ready) {
            ASSERT_EQ(1, rc) << "errno=" << wait_errno;
            EXPECT_EQ(0x5397559U, event.data.u64);
            EXPECT_EQ(static_cast<uint32_t>(EPOLLOUT), event.events);
        } else {
            EXPECT_EQ(-1, rc);
            EXPECT_EQ(EINTR, wait_errno);
        }
        if (signo == SIGINT) {
            EXPECT_EQ(SIGINT, delivered_signal);
        }
        close(epfd);
        close(fd);
    }
};

TEST_P(iomux_wakeup, newly_joined_ready_socket_survives_sigint)
{
    run(true, SIGINT);
}
TEST_P(iomux_wakeup, empty_wakeup_still_reports_eintr)
{
    run(false, SIGINT);
}
TEST_P(iomux_wakeup, newly_joined_ready_socket_without_signal)
{
    run(true, 0);
}
TEST_P(iomux_wakeup, newly_joined_ready_socket_survives_pending_signal)
{
    if (!GetParam()) {
        GTEST_SKIP() << "A signal mask requires epoll_pwait";
    }
    run(true, SIGUSR1);
}

INSTANTIATE_TEST_CASE_P(shutdown, iomux_wakeup, testing::Bool());
