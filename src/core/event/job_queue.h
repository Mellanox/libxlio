/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include <deque>
#include "utils/lock_wrapper.h"

template <typename T> class job_queue {
public:
    typedef std::deque<T> queue_type;

    void insert_job(T &&job);
    void insert_job(const T &job);

    template <typename... Args> void insert_job(Args &&...args);

    queue_type get_all();

private:
    queue_type m_queue;
    lock_spin m_queue_lock;
};

template <typename T> void job_queue<T>::insert_job(T &&job)
{
    std::lock_guard<decltype(m_queue_lock)> lock(m_queue_lock);
    m_queue.push_back(job);
}

template <typename T> void job_queue<T>::insert_job(const T &job)
{
    std::lock_guard<decltype(m_queue_lock)> lock(m_queue_lock);
    m_queue.push_back(job);
}

template <typename T> template <typename... Args> void job_queue<T>::insert_job(Args &&...args)
{
    std::lock_guard<decltype(m_queue_lock)> lock(m_queue_lock);
    m_queue.empalce_back(std::forward<Args>(args)...);
}

template <typename T> typename job_queue<T>::queue_type job_queue<T>::get_all()
{
    typename job_queue<T>::queue_type out;
    std::lock_guard<decltype(m_queue_lock)> lock(m_queue_lock);
    m_queue.swap(out);
    return out; // RVO should kick in and avoid copy to return value.
}

#endif // JOB_QUEUE_H
