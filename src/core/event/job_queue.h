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

    void insert_job(const T &job);

    queue_type &get_all();

private:
    queue_type m_queue_insert;
    queue_type m_queue_fetch;
    lock_spin m_queue_lock;
};

template <typename T> job_queue<T>::job_queue()
{
    m_queue_insert.reserve(32);
    m_queue_fetch.reserve(32);
}

// Should be called only from the producer.
template <typename T> void job_queue<T>::insert_job(const T &job)
{
    std::lock_guard<decltype(m_queue_lock)> lock(m_queue_lock);
    m_queue_insert.push_back(job);
}

// Should be called only from a single consumer.
template <typename T> typename job_queue<T>::queue_type &job_queue<T>::get_all()
{
    // Avoid heavy lock activity in case of busy loop and empty queue.
    std::atomic_thread_fence(std::memory_order::memory_order_acquire);
    if (m_queue_insert.size() <= 0U) {
        return m_queue_fetch;
    }

    std::lock_guard<decltype(m_queue_lock)> lock(m_queue_lock);
    m_queue_insert.swap(m_queue_fetch);
    return m_queue_fetch;
}

#endif // JOB_QUEUE_H
