/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/*
 * Test-only preload helper used by iomux_wakeup.cc. That gtest re-executes its
 * selected case with LD_PRELOAD=libxlio.so:libiomux_wait_hook.so, placing this
 * library between XLIO and libc, not between the application and XLIO.
 *
 * XLIO's saved OS epoll_wait/epoll_pwait functions resolve to these wrappers.
 * Each wrapper forwards the actual wait to libc through RTLD_NEXT, then invokes
 * an armed callback before returning to XLIO. The test uses this boundary to add
 * a socket and raise a signal deterministically while XLIO's call is in progress.
 * The kernel return value and event buffer are passed through unchanged; errno
 * is preserved across the callback. Only the armed descriptor on the arming
 * thread triggers the callback, which is disarmed before invocation to prevent
 * nested waits from triggering it again. Other waits simply pass through.
 */

#include <dlfcn.h>
#include <cerrno>
#include <sys/epoll.h>

// Loaded after XLIO: its saved OS functions resolve here, and we forward to libc.
// Only the explicitly armed epoll descriptor on this thread invokes the callback.
static thread_local int target_epfd = -1;
static thread_local void (*after_wait)() = nullptr;

extern "C" __attribute__((visibility("default"))) void iomux_arm_wait_hook(int epfd,
                                                                           void (*callback)())
{
    target_epfd = epfd;
    after_wait = callback;
}

static void run_hook(int epfd)
{
    if (epfd == target_epfd && after_wait) {
        int saved_errno = errno;
        auto callback = after_wait;
        after_wait = nullptr;
        callback();
        errno = saved_errno;
    }
}

extern "C" __attribute__((visibility("default"))) int epoll_wait(int epfd, epoll_event *events,
                                                                 int count, int timeout)
{
    static auto next = reinterpret_cast<decltype(&epoll_wait)>(dlsym(RTLD_NEXT, "epoll_wait"));
    int rc = next(epfd, events, count, timeout);
    run_hook(epfd);
    return rc;
}

extern "C" __attribute__((visibility("default"))) int epoll_pwait(int epfd, epoll_event *events,
                                                                  int count, int timeout,
                                                                  const sigset_t *mask)
{
    static auto next = reinterpret_cast<decltype(&epoll_pwait)>(dlsym(RTLD_NEXT, "epoll_pwait"));
    int rc = next(epfd, events, count, timeout, mask);
    run_hook(epfd);
    return rc;
}
