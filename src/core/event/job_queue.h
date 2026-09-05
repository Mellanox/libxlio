/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-3-Clause
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

#ifndef JOB_QUEUE_H
#define JOB_QUEUE_H

#include <vector>
#include <atomic>
#include "utils/lock_wrapper.h"

template <typename T> class job_queue {
public:
    typedef std::vector<T> queue_type;

    job_queue();

    // Returns true if the caller must signal the consumer.
    bool insert_job(const T &job);

    queue_type &get_all();

    // Marks the consumer as sleeping. Returns false if a job is already
    // pending, in which case the consumer must not sleep.
    bool try_sleep();

    // Clears the sleeping state.
    void wake();

private:
    queue_type m_queue_insert;
    queue_type m_queue_fetch;
    lock_spin m_queue_lock;
    // Lock-free hint for the polling consumer. It may read stale-false while a
    // producer is inside insert_job(), which costs one poll iteration. The
    // sleep transition must not use it - see try_sleep().
    std::atomic<bool> m_has_pending {false};
    // Guarded by m_queue_lock. Owning the sleep state here lets a producer take
    // the wakeup decision inside the critical section it already holds.
    bool m_sleeping = false;
};

template <typename T> job_queue<T>::job_queue()
{
    m_queue_insert.reserve(32);
    m_queue_fetch.reserve(32);
}

// Should be called only from the producer.
template <typename T> bool job_queue<T>::insert_job(const T &job)
{
    std::lock_guard<decltype(m_queue_lock)> lock(m_queue_lock);
    m_queue_insert.push_back(job);
    m_has_pending.store(true, std::memory_order_release);

    // Claim the wakeup. Producers that follow rely on the signal already sent
    // and on the consumer draining the whole queue.
    bool claimed = m_sleeping;
    m_sleeping = false;
    return claimed;
}

// Should be called only from a single consumer.
template <typename T> typename job_queue<T>::queue_type &job_queue<T>::get_all()
{
    // Avoid heavy lock activity in case of busy loop and empty queue.
    if (!m_has_pending.load(std::memory_order_acquire)) {
        return m_queue_fetch;
    }

    std::lock_guard<decltype(m_queue_lock)> lock(m_queue_lock);
    m_queue_insert.swap(m_queue_fetch);
    m_has_pending.store(false, std::memory_order_release);
    return m_queue_fetch;
}

// Should be called only from a single consumer, after it drained the jobs
// returned by the last get_all() call.
template <typename T> bool job_queue<T>::try_sleep()
{
    std::lock_guard<decltype(m_queue_lock)> lock(m_queue_lock);
    if (!m_queue_insert.empty()) {
        return false;
    }
    // The producer takes its wakeup decision under this lock, so either the
    // check above observes the job or insert_job() observes the sleeping state.
    m_sleeping = true;
    return true;
}

// Should be called only from a single consumer.
template <typename T> void job_queue<T>::wake()
{
    std::lock_guard<decltype(m_queue_lock)> lock(m_queue_lock);
    m_sleeping = false;
}

#endif // JOB_QUEUE_H
