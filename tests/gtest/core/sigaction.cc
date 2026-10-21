/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <functional>

#include "common/def.h"
#include "common/log.h"
#include "common/cmn.h"
#include "common/base.h"

/*
 * XLIO interposes SIGINT to set g_b_exit and then chains the application action. From the
 * application point of view the interposition must be transparent, therefore the
 * expectations below hold both with and without libxlio preloaded.
 *
 * A SIGINT disposition is a process wide side effect, so every test configures it in a child
 * process and reports the verdict with the exit status.
 */

static const int HANDLER_NONE = 0;
static const int HANDLER_A = 1;
static const int HANDLER_B = 2;
static const int HANDLER_SIGINFO = 3;

static volatile sig_atomic_t g_handler_id;
static volatile sig_atomic_t g_handler_signo;
static volatile sig_atomic_t g_handler_si_pid;

static void handler_a(int signo)
{
    g_handler_id = HANDLER_A;
    g_handler_signo = signo;
}

static void handler_b(int signo)
{
    g_handler_id = HANDLER_B;
    g_handler_signo = signo;
}

static void handler_siginfo(int signo, siginfo_t *info, void *context)
{
    UNREFERENCED_PARAMETER(context);
    g_handler_id = HANDLER_SIGINFO;
    g_handler_signo = signo;
    g_handler_si_pid = (info ? info->si_pid : -1);
}

/* Runs the body in a child process. The child never returns to the test body. */
static pid_t fork_child(const std::function<void()> &body)
{
    pid_t pid = fork();

    if (pid == 0) {
        g_handler_id = HANDLER_NONE;
        body();
        fflush(nullptr);
        _exit(testing::Test::HasFailure() ? 1 : 0);
    }
    return pid;
}

/*
 * oldact must be filled even when the saved disposition is SIG_DFL, and a query must report
 * the application action with its flags and mask - not the XLIO trampoline.
 */
TEST(sigaction_test, oldact_reports_application_action)
{
    pid_t pid = fork_child([]() {
        struct sigaction action = {};
        action.sa_handler = SIG_DFL;
        sigemptyset(&action.sa_mask);
        EXPECT_EQ(0, sigaction(SIGINT, &action, nullptr));

        struct sigaction old_action = {};
        old_action.sa_handler = SIG_ERR;
        action.sa_handler = handler_a;
        action.sa_flags = SA_RESTART;
        sigaddset(&action.sa_mask, SIGUSR1);
        EXPECT_EQ(0, sigaction(SIGINT, &action, &old_action));
        EXPECT_EQ(SIG_DFL, old_action.sa_handler);

        old_action.sa_handler = SIG_ERR;
        old_action.sa_flags = 0;
        EXPECT_EQ(0, sigaction(SIGINT, nullptr, &old_action));
        EXPECT_EQ(&handler_a, old_action.sa_handler);
        EXPECT_EQ(SA_RESTART, old_action.sa_flags & SA_RESTART);
        EXPECT_EQ(1, sigismember(&old_action.sa_mask, SIGUSR1));
    });

    ASSERT_LE(0, pid);
    EXPECT_EQ(0, test_base::wait_fork(pid));
}

/* A plain application handler is chained from the XLIO SIGINT trampoline. */
TEST(sigaction_test, chains_application_handler)
{
    pid_t pid = fork_child([]() {
        struct sigaction action = {};
        action.sa_handler = handler_a;
        sigemptyset(&action.sa_mask);
        EXPECT_EQ(0, sigaction(SIGINT, &action, nullptr));

        EXPECT_EQ(0, raise(SIGINT));
        EXPECT_EQ(HANDLER_A, static_cast<int>(g_handler_id));
        EXPECT_EQ(SIGINT, static_cast<int>(g_handler_signo));
    });

    ASSERT_LE(0, pid);
    EXPECT_EQ(0, test_base::wait_fork(pid));
}

/* An SA_SIGINFO action keeps its 3-argument calling convention and receives a valid siginfo. */
TEST(sigaction_test, chains_siginfo_handler)
{
    pid_t pid = fork_child([]() {
        struct sigaction action = {};
        action.sa_sigaction = handler_siginfo;
        sigemptyset(&action.sa_mask);
        action.sa_flags = SA_SIGINFO;
        EXPECT_EQ(0, sigaction(SIGINT, &action, nullptr));

        struct sigaction old_action = {};
        EXPECT_EQ(0, sigaction(SIGINT, nullptr, &old_action));
        EXPECT_EQ(SA_SIGINFO, old_action.sa_flags & SA_SIGINFO);
        EXPECT_EQ(&handler_siginfo, old_action.sa_sigaction);

        EXPECT_EQ(0, raise(SIGINT));
        EXPECT_EQ(HANDLER_SIGINFO, static_cast<int>(g_handler_id));
        EXPECT_EQ(SIGINT, static_cast<int>(g_handler_signo));
        EXPECT_EQ(getpid(), static_cast<pid_t>(g_handler_si_pid));
    });

    ASSERT_LE(0, pid);
    EXPECT_EQ(0, test_base::wait_fork(pid));
}

/* SIG_DFL is not trampolined - SIGINT terminates the process as usual. */
TEST(sigaction_test, default_disposition_terminates_process)
{
    pid_t pid = fork_child([]() {
        struct sigaction action = {};
        action.sa_handler = SIG_DFL;
        sigemptyset(&action.sa_mask);
        EXPECT_EQ(0, sigaction(SIGINT, &action, nullptr));

        raise(SIGINT);
        ADD_FAILURE() << "SIGINT did not terminate the process";
    });

    ASSERT_LE(0, pid);
    int status = 0;
    ASSERT_EQ(pid, waitpid(pid, &status, 0));
    ASSERT_TRUE(WIFSIGNALED(status)) << "status=" << status;
    EXPECT_EQ(SIGINT, WTERMSIG(status));
}

/* SIG_IGN is not trampolined - SIGINT is dropped and the disposition is reported back. */
TEST(sigaction_test, ignored_disposition_drops_signal)
{
    pid_t pid = fork_child([]() {
        struct sigaction action = {};
        action.sa_handler = SIG_IGN;
        sigemptyset(&action.sa_mask);
        EXPECT_EQ(0, sigaction(SIGINT, &action, nullptr));

        EXPECT_EQ(0, raise(SIGINT));
        EXPECT_EQ(HANDLER_NONE, static_cast<int>(g_handler_id));

        struct sigaction old_action = {};
        EXPECT_EQ(0, sigaction(SIGINT, nullptr, &old_action));
        EXPECT_EQ(SIG_IGN, old_action.sa_handler);
    });

    ASSERT_LE(0, pid);
    EXPECT_EQ(0, test_base::wait_fork(pid));
}

/* signal() and sigaction() share a single saved action, and the latest handler is dispatched. */
TEST(sigaction_test, signal_and_sigaction_share_state)
{
    pid_t pid = fork_child([]() {
        signal(SIGINT, SIG_DFL);
        EXPECT_EQ(SIG_DFL, signal(SIGINT, handler_a));
        EXPECT_EQ(&handler_a, signal(SIGINT, handler_b));

        struct sigaction old_action = {};
        EXPECT_EQ(0, sigaction(SIGINT, nullptr, &old_action));
        EXPECT_EQ(&handler_b, old_action.sa_handler);

        EXPECT_EQ(0, raise(SIGINT));
        EXPECT_EQ(HANDLER_B, static_cast<int>(g_handler_id));
    });

    ASSERT_LE(0, pid);
    EXPECT_EQ(0, test_base::wait_fork(pid));
}

/* Only SIGINT is interposed - any other signal is a plain pass-through. */
TEST(sigaction_test, other_signals_are_not_interposed)
{
    pid_t pid = fork_child([]() {
        struct sigaction action = {};
        action.sa_handler = handler_a;
        sigemptyset(&action.sa_mask);
        EXPECT_EQ(0, sigaction(SIGUSR1, &action, nullptr));

        struct sigaction old_action = {};
        EXPECT_EQ(0, sigaction(SIGUSR1, nullptr, &old_action));
        EXPECT_EQ(&handler_a, old_action.sa_handler);

        EXPECT_EQ(0, raise(SIGUSR1));
        EXPECT_EQ(HANDLER_A, static_cast<int>(g_handler_id));
        EXPECT_EQ(SIGUSR1, static_cast<int>(g_handler_signo));
    });

    ASSERT_LE(0, pid);
    EXPECT_EQ(0, test_base::wait_fork(pid));
}

/* signal() rejects SIG_ERR with EINVAL, like glibc does, and keeps the current action. */
TEST(sigaction_test, signal_rejects_sig_err)
{
    pid_t pid = fork_child([]() {
        EXPECT_NE(SIG_ERR, signal(SIGINT, handler_a));

        errno = EOK;
        EXPECT_EQ(SIG_ERR, signal(SIGINT, SIG_ERR));
        EXPECT_EQ(EINVAL, errno);

        /* The rejected call must not clobber the installed action. */
        struct sigaction old_action = {};
        EXPECT_EQ(0, sigaction(SIGINT, nullptr, &old_action));
        EXPECT_EQ(&handler_a, old_action.sa_handler);
    });

    ASSERT_LE(0, pid);
    EXPECT_EQ(0, test_base::wait_fork(pid));
}

/* A one-shot action is consumed by the first delivery and leaves SIG_DFL behind. */
TEST(sigaction_test, one_shot_action_resets_to_default)
{
    pid_t pid = fork_child([]() {
        struct sigaction action = {};
        action.sa_handler = handler_a;
        sigemptyset(&action.sa_mask);
        action.sa_flags = SA_RESETHAND;
        EXPECT_EQ(0, sigaction(SIGINT, &action, nullptr));

        EXPECT_EQ(0, raise(SIGINT));
        EXPECT_EQ(HANDLER_A, static_cast<int>(g_handler_id));

        struct sigaction old_action = {};
        old_action.sa_handler = SIG_ERR;
        EXPECT_EQ(0, sigaction(SIGINT, nullptr, &old_action));
        EXPECT_EQ(SIG_DFL, old_action.sa_handler);
    });

    ASSERT_LE(0, pid);
    EXPECT_EQ(0, test_base::wait_fork(pid));
}

/*
 * SIG_ERR is not a callback, but sigaction() takes it as a regular handler address, while
 * signal() rejects it with EINVAL. XLIO must reproduce both.
 *
 * The fault on delivery is not checked: raising SIGINT would kill the child, and a piped
 * kernel.core_pattern hands the dump to a system service regardless of RLIMIT_CORE.
 */
TEST(sigaction_test, sig_err_is_accepted_by_sigaction_only)
{
    pid_t pid = fork_child([]() {
        struct sigaction action = {};
        action.sa_handler = SIG_ERR;
        sigemptyset(&action.sa_mask);
        EXPECT_EQ(0, sigaction(SIGINT, &action, nullptr));

        struct sigaction old_action = {};
        EXPECT_EQ(0, sigaction(SIGINT, nullptr, &old_action));
        EXPECT_EQ(SIG_ERR, old_action.sa_handler);

        errno = EOK;
        EXPECT_EQ(SIG_ERR, signal(SIGINT, SIG_ERR));
        EXPECT_EQ(EINVAL, errno);
    });

    ASSERT_LE(0, pid);
    EXPECT_EQ(0, test_base::wait_fork(pid));
}
