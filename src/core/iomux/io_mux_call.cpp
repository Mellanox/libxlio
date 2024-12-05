/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "io_mux_call.h"

#include "utils/clock.h"
#include "vlogger/vlogger.h"
#include <util/sys_vars.h>
#include <sock/fd_collection.h>
#include <dev/net_device_table_mgr.h>
#include "util/instrumentation.h"

//#define IOMUX_DEBUG
#ifdef IOMUX_DEBUG
#define __if_dbg(_log_args_...) __log_dbg(_log_args_)
#else
#define __if_dbg(_log_args_...)
#endif

uint64_t g_polling_time_usec = 0; // polling time in the last second in usec
timeval g_last_zero_polling_time; // the last time g_polling_time_usec was zeroed
int g_n_last_checked_index = 0; // save the last fd index we checked in check_offloaded_rsockets()

#define MODULE_NAME "io_mux_call"
DOCA_LOG_REGISTER(io_mux_call);

int io_mux_call::m_n_skip_os_count = 0;

inline void io_mux_call::timer_update()
{
    if (!tv_isset(&m_start)) {
        // after first loop - set
        gettime(&m_start);
        __log_func("start timer");
    } else {
        timeval current;
        gettime(&current);
        tv_sub(&current, &m_start, &m_elapsed);
        __log_funcall("update timer (elapsed time: %d sec, %d usec)", m_elapsed.tv_sec,
                      m_elapsed.tv_usec);
    }
}

inline void io_mux_call::check_rfd_ready_array(fd_array_t *fd_ready_array)
{
    int fd_index;

    for (fd_index = 0; fd_index < fd_ready_array->fd_count; ++fd_index) {
        set_rfd_ready(fd_ready_array->fd_list[fd_index]);
    }
    if (m_n_ready_rfds) {
        m_p_stats->n_iomux_rx_ready += m_n_ready_rfds;
        __log_func("found ready_fds=%d", m_n_ready_rfds);
        // return true;
    }
    // return false;
}

inline void io_mux_call::check_offloaded_wsockets()
{
    for (int offloaded_index = 0; offloaded_index < *m_p_num_all_offloaded_fds; ++offloaded_index) {
        if (m_p_offloaded_modes[offloaded_index] & OFF_WRITE) {
            int fd = m_p_all_offloaded_fds[offloaded_index];
            sockinfo *p_socket_object = fd_collection_get_sockfd(fd);
            if (!p_socket_object) {
                // If we can't find this previously mapped offloaded socket
                // then it was probably closed. We need to get out with error code
                errno = EBADF;
                xlio_throw_object(io_mux_call::io_error);
            }

            // Poll the socket object
            if (p_socket_object->is_writeable()) {
                set_wfd_ready(fd);
            }
        }
    }
}

inline void io_mux_call::check_offloaded_esockets()
{
    for (int offloaded_index = 0; offloaded_index < *m_p_num_all_offloaded_fds; ++offloaded_index) {
        if (m_p_offloaded_modes[offloaded_index] & OFF_RDWR) {
            int fd = m_p_all_offloaded_fds[offloaded_index];
            sockinfo *p_socket_object = fd_collection_get_sockfd(fd);
            if (!p_socket_object) {
                // If we can't find this previously mapped offloaded socket
                // then it was probably closed. We need to get out with error code
                errno = EBADF;
                xlio_throw_object(io_mux_call::io_error);
            }

            // Poll the socket object
            int errors = 0;
            if (p_socket_object->is_errorable(&errors)) {
                set_efd_ready(fd, errors);
            }
        }
    }
}

inline bool io_mux_call::check_all_offloaded_sockets()
{
    check_offloaded_rsockets();

    // If m_n_ready_rfds is not empty and so m_n_all_ready_fds,
    // we will exit the polling_loop/blocking_loop anyway.
    bool all_drained = true;
    if (!m_n_ready_rfds) {
        // check cq for acks
        all_drained = ring_poll_and_process_element();
        check_offloaded_wsockets();
        check_offloaded_esockets();
    }

    __log_func("m_n_all_ready_fds=%d, m_n_ready_rfds=%d, m_n_ready_wfds=%d, m_n_ready_efds=%d",
               m_n_all_ready_fds, m_n_ready_rfds, m_n_ready_wfds, m_n_ready_efds);
    return all_drained;
}

inline void io_mux_call::zero_polling_cpu(timeval current)
{
    timeval delta;
    int delta_time; // in usec

    // check if it's time to zero g_polling_time_usec
    tv_sub(&current, &g_last_zero_polling_time, &delta);
    delta_time = tv_to_usec(&delta);

    if (delta_time >= USEC_PER_SEC) {
        m_p_stats->n_iomux_polling_time = (g_polling_time_usec * 100) / delta_time;

        __log_funcall("zero polling time: accumulated: %d usec delta=%d (%d%))",
                      g_polling_time_usec, delta_time, m_p_stats->n_iomux_polling_time);
        g_polling_time_usec = 0;
        g_last_zero_polling_time = current;
    }
}

io_mux_call::io_mux_call(int *off_fds_buffer, offloaded_mode_t *off_modes_buffer, int num_fds,
                         const sigset_t *sigmask)
    : m_check_sig_pending_ratio(0)
    , m_p_all_offloaded_fds(off_fds_buffer)
    , m_p_offloaded_modes(off_modes_buffer)
    , m_num_all_offloaded_fds(0)
    , m_cqepfd(-1)
    , m_p_stats(nullptr)
    , m_n_all_ready_fds(0)
    , m_n_ready_rfds(0)
    , m_n_ready_wfds(0)
    , m_n_ready_efds(0)
    , m_sigmask(sigmask)
{
    m_p_num_all_offloaded_fds = &m_num_all_offloaded_fds;
    tv_clear(&m_start);
    tv_clear(&m_elapsed);

    if (m_p_all_offloaded_fds) {
        memset(m_p_all_offloaded_fds, 0, num_fds * sizeof(m_p_all_offloaded_fds[0]));
    }
    if (m_p_offloaded_modes) {
        memset(m_p_offloaded_modes, 0, num_fds * sizeof(m_p_offloaded_modes[0]));
    }

    m_fd_ready_array.fd_max = FD_ARRAY_MAX;
    m_fd_ready_array.fd_count = 0;
}

void io_mux_call::check_offloaded_rsockets()
{
    int fd, offloaded_index, num_all_offloaded_fds;
    fd_array_t fd_ready_array;
    sockinfo *p_socket_object;

    fd_ready_array.fd_max = FD_ARRAY_MAX;

    offloaded_index = g_n_last_checked_index;
    num_all_offloaded_fds = *m_p_num_all_offloaded_fds;

    for (int i = 0; i < num_all_offloaded_fds; ++i) {

        ++offloaded_index %= num_all_offloaded_fds;

        if (m_p_offloaded_modes[offloaded_index] & OFF_READ) {
            fd = m_p_all_offloaded_fds[offloaded_index];
            p_socket_object = fd_collection_get_sockfd(fd);
            if (!p_socket_object) {
                // If we can't find this previously mapped offloaded socket
                // then it was probably closed. We need to get out with error code
                errno = EBADF;
                g_n_last_checked_index = offloaded_index;
                xlio_throw_object(io_mux_call::io_error);
            }

            fd_ready_array.fd_count = 0;

            // Poll the socket object
            if (p_socket_object->is_readable(false, &fd_ready_array)) {
                set_offloaded_rfd_ready(offloaded_index);
                // We have offloaded traffic. Don't sample the OS immediately
                p_socket_object->unset_immediate_os_sample();
            }

            check_rfd_ready_array(&fd_ready_array);

            // TODO: consider - m_n_all_ready_fds
            if (m_n_ready_rfds) {
                g_n_last_checked_index = offloaded_index;
                return;
            }
        }
    }
    g_n_last_checked_index = offloaded_index;
}

bool io_mux_call::handle_os_countdown(int &poll_os_countdown)
{
    /*
     * Poll OS when count down reaches zero. This honors CQ-OS ratio.
     * This also handles the 0 ratio case - do not poll OS at all.
     */
    if (poll_os_countdown-- <= 0 && safe_mce_sys().select_poll_os_ratio > 0) {
        if (wait_os(true)) {
            // TODO: [DOCA WA] Unclearable manual triggered events generate false PE events.
            clear_false_cq_events();
        }
        /* Before we exit with ready OS fd's we'll check the CQs once more and exit
         * below after calling check_all_offloaded_sockets();
         * IMPORTANT : We cannot do an opposite with current code,
         * means we cannot poll cq and then poll os (for epoll) - because poll os
         * will delete ready offloaded fds.
         */
        if (m_n_all_ready_fds) {
            // TODO: fix it - we only know all counter, not read counter
            m_p_stats->n_iomux_os_rx_ready += m_n_all_ready_fds;
            return true;
        }
        poll_os_countdown = safe_mce_sys().select_poll_os_ratio - 1;
    }

    return false;
}

void io_mux_call::polling_loops()
{
    int poll_os_countdown = 0;
    if (immidiate_return(poll_os_countdown)) {
        return;
    }

    timeval before_polling_timer = TIMEVAL_INITIALIZER;
    timeval after_polling_timer = TIMEVAL_INITIALIZER;
    timeval delta;
    int check_timer_countdown = 1; // Poll once before checking the time
    int check_timer_countdown_step = MAX(*m_p_num_all_offloaded_fds, 1U);
    int check_timer_countdown_init = (safe_mce_sys().select_poll_num == 0 ? 1 : 512);
    bool all_drained = false;
    bool finite_polling = (safe_mce_sys().select_poll_num != -1);

    timeval poll_duration;
    tv_clear(&poll_duration);
    poll_duration.tv_usec = safe_mce_sys().select_poll_num;

    __if_dbg("2nd scenario start");

    if (safe_mce_sys().select_handle_cpu_usage_stats) {
        // handle polling cpu statistics
        if (!tv_isset(&g_last_zero_polling_time)) {
            // after first loop - set
            gettime(&g_last_zero_polling_time);
        }

        gettime(&before_polling_timer);
        zero_polling_cpu(before_polling_timer);
    }

    do {
        __log_funcall("poll_os_countdown=%d, check_timer_countdown=%d, m_num_offloaded_rfds=%d, "
                      "m_n_all_ready_fds=%d, m_n_ready_rfds=%d, m_n_ready_wfds=%d, "
                      "m_n_ready_efds=%d",
                      poll_os_countdown, check_timer_countdown, *m_p_num_all_offloaded_fds,
                      m_n_all_ready_fds, m_n_ready_rfds, m_n_ready_wfds, m_n_ready_efds);

        if (handle_os_countdown(poll_os_countdown)) {
            // Break if non-offloaded data was found.
            break;
        }

        // Poll offloaded sockets.
        // If this is successful we must exit - wait_os() might mess the results.
        all_drained = check_all_offloaded_sockets();
        if (m_n_all_ready_fds) { // We have events.
            break;
        }

        /*
         * Update elapsed time & Check for timeout or expiry of polling loops duration
         * Update start time on first entry
         */
        if (check_timer_countdown <= 1) {
            timer_update();
            if (is_timeout(m_elapsed)) {
                __if_dbg("2nd scenario timeout (elapsed %d)", m_elapsed.tv_usec);
                break;
            }

            // If polled_cqes != 0 it means there can be more CQEs in the CQ and we should not go
            // to sleep.
            /* cppcheck-suppress syntaxError */
            if (all_drained && finite_polling && (tv_cmp(&poll_duration, &m_elapsed, <=))) {
                __if_dbg("2nd scenario reached max poll duration (elapsed %d)", m_elapsed.tv_usec);
                break;
            }

            // Check the timer each X offloaded fds checked
            check_timer_countdown = check_timer_countdown_init;

            __if_dbg("2nd scenario timer update (elapsed %d)", m_elapsed.tv_usec);
        }

        // update timer check with referance to number of offlaoded sockets in loop
        check_timer_countdown -= check_timer_countdown_step;

        if (g_b_exit || is_sig_pending()) {
            errno = EINTR;
            xlio_throw_object(io_mux_call::io_error);
        }
    } while (!m_n_all_ready_fds);

    if (safe_mce_sys().select_handle_cpu_usage_stats) {
        // handle polling cpu statistics
        gettime(&after_polling_timer);

        // calc accumulated polling time
        tv_sub(&after_polling_timer, &before_polling_timer, &delta);
        g_polling_time_usec += tv_to_usec(&delta);

        zero_polling_cpu(after_polling_timer);
    }

    if (m_n_all_ready_fds) { // TODO: verify!
        ++m_p_stats->n_iomux_poll_hit;
        __log_func("polling_loops found %d ready fds (rfds=%d, wfds=%d, efds=%d)",
                   m_n_all_ready_fds, m_n_ready_rfds, m_n_ready_wfds, m_n_ready_efds);
    } else {
        ++m_p_stats->n_iomux_poll_miss;
    }

    __if_dbg("2nd scenario exit (elapsed %d)", m_elapsed.tv_usec);
}

void io_mux_call::blocking_loops()
{
    prepare_to_block();

    /*
     * Loop as long as no fd's are found, and cq is ready.
     * If wait() returns without cq ready - timeout expired.
     */
    do {
        if (g_b_exit || is_sig_pending()) {
            errno = EINTR;
            xlio_throw_object(io_mux_call::io_error);
        }

        __log_func("Arming PE");
        if (!ring_request_notification()) {
            xlio_throw_object(io_mux_call::io_error);
        } else {
            timer_update();

            // arming was successful - block on cq
            __log_func("going to sleep (elapsed time: %d sec, %d usec)", m_elapsed.tv_sec,
                       m_elapsed.tv_usec);

            if (wait(m_elapsed)) {
                __log_func("before check_all_offloaded_sockets");
                ring_clear_rx_notification();
                check_all_offloaded_sockets();
            } else if (!m_n_all_ready_fds && !is_timeout(m_elapsed)) {
                __log_func("woke up by wake up mechanism, check current events");
                check_all_offloaded_sockets();
            }
        }
    } while (!m_n_all_ready_fds && !is_timeout(m_elapsed));
}

int io_mux_call::call()
{
    // TODO: need stats adjustments for write...

    __log_funcall(LOG_FUNCTION_CALL);

    if (0 == *m_p_num_all_offloaded_fds) {
        // 1st scenario
        timer_update();
        wait_os(false);
        if (g_b_exit || is_sig_pending()) {
            errno = EINTR;
            xlio_throw_object(io_mux_call::io_error);
        }
        m_p_stats->n_iomux_os_rx_ready += m_n_ready_rfds; // TODO: check

        // wake up mechanism can bring up events of later joined offloaded sockets
        if (*m_p_num_all_offloaded_fds) {
            check_all_offloaded_sockets();
            if (m_n_all_ready_fds) {
                goto done;
            } else { // false wake-up, and we already discovered that we should be in 2nd scenario
                timer_update();
                if (is_timeout(m_elapsed)) {
                    goto done;
                }
            }
        } else {
            goto done;
        }
    }

    // 2nd scenario
    polling_loops();

    // 3rd scenario
    if (!m_n_all_ready_fds && !is_timeout(m_elapsed)) {
        blocking_loops();
    }

done:

    if (m_n_all_ready_fds == 0) { // TODO: check
        // An error throws an exception
        ++m_p_stats->n_iomux_timeouts;
    }

    __log_func("return %d", m_n_all_ready_fds);
    return m_n_all_ready_fds; // TODO: consider sum r + w
}

// check if we found anything in the constructor of select and poll
// override in epoll
bool io_mux_call::immidiate_return(int &poll_os_countdown)
{
    prepare_to_poll();

    if (m_n_all_ready_fds) {
        m_n_ready_rfds = 0; // will be counted again in check_rfd_ready_array()
        m_n_all_ready_fds = 0;
        check_rfd_ready_array(&m_fd_ready_array);
        ring_poll_and_process_element();
        return true;
    }

    /*
     * Give OS priority in 1 of SELECT_SKIP_OS times
     * In all other times, OS is never polled first (even if ratio is 1).
     */
    if (--m_n_skip_os_count <= 0) {
        m_n_skip_os_count = safe_mce_sys().select_skip_os_fd_check;
        poll_os_countdown = 0;
    } else {
        poll_os_countdown = safe_mce_sys().select_poll_os_ratio;
    }

    return false;
}

bool io_mux_call::ring_poll_and_process_element()
{
    // TODO: (select, poll) this access all CQs, it is better to check only relevant ones
    return g_p_net_device_table_mgr->global_ring_poll_and_process_element(nullptr);
}

bool io_mux_call::ring_request_notification()
{
    return g_p_net_device_table_mgr->global_ring_request_notification();
}

void io_mux_call::ring_clear_rx_notification()
{
    g_p_net_device_table_mgr->global_ring_clear_rx_notification();
}

bool io_mux_call::is_sig_pending()
{
    if (!m_sigmask) {
        return false;
    }

    if (m_check_sig_pending_ratio >= CHECK_INTERRUPT_RATIO) {
        m_check_sig_pending_ratio = 0;
    } else {
        m_check_sig_pending_ratio++;
        return false;
    }

    sigset_t set_pending, set_andn;
    sigemptyset(&set_pending);
    sigemptyset(&set_andn);

    if (sigpending(&set_pending)) {
        __log_err("sigpending() failed (errno = %d %m)", errno);
        return false;
    }

    sigandnset(&set_andn, &set_pending, m_sigmask);

    // good flow - first option - no signals
    if (sigisemptyset(&set_andn)) {
        __log_funcall("no pending signals which the user is waiting for");
        return false;
    }

    // good flow - second options - pending signals - deliver them
    sigsuspend(m_sigmask);

    return true;
}
