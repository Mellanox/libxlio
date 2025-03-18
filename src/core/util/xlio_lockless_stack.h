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

#ifndef XLIO_LOCKLESS_STACK_H
#define XLIO_LOCKLESS_STACK_H

#include <atomic>
#include "core/util/list.h"
#include "vlogger/vlogger.h"

#define vstack_logwarn(log_fmt, log_args...)                                                        \
    vlog_printf(VLOG_WARNING, "vstack[%p]:%d:%s() " log_fmt "\n", this, __LINE__, __FUNCTION__,     \
                ##log_args)
#define vstack_logerr(log_fmt, log_args...)                                                         \
    vlog_printf(VLOG_ERROR, "vstack[%p]:%d:%s() " log_fmt "\n", this, __LINE__, __FUNCTION__,       \
                ##log_args)

#define GET_STACK_NODE(_obj, _obj_type, _offset_func)                                               \
    ((stack_node<_obj_type, _offset_func> *)((size_t)(_obj) + (size_t)(_offset_func())))

template <class T, size_t offset(void)> class stack_node {
public:
    stack_node<T, offset> *next_node;

    stack_node() { reset(); }

    T *obj_ptr() { return reinterpret_cast<T *>(reinterpret_cast<uintptr_t>(this) - offset()); }

    bool is_stack_member() const { return this->next_node != this; }
    void reset() { next_node = this; }
};

template <class T, size_t offset(void)> class xlio_stack {
public:
    using node_type = stack_node<T, offset>;
    using this_type = xlio_stack<T, offset>;

    xlio_stack() {}
    xlio_stack(node_type *node): m_list(node) {}

    xlio_stack(const this_type &other) = delete;
    xlio_stack(this_type &&other) {
        m_list = other.m_list;
        other.m_list = nullptr;
    }

    this_type &operator=(const this_type &other) = delete;
    this_type &operator=(this_type &&other) {
        m_list = other.m_list;
        other.m_list = nullptr;
        return *this;
    }

    bool empty() const { return (nullptr == m_list); }

    T *get() const
    {
        if (unlikely(empty())) {
            return nullptr;
        }
        return m_list->obj_ptr();
    }

    T *next(T *obj) const
    {
        node_type *node = GET_STACK_NODE(obj, T, offset)->next_node;
        return node ? node->obj_ptr() : nullptr;
    }

    T *get_and_pop()
    {
        if (unlikely(empty())) {
            return nullptr;
        }

        node_type *obj_node = m_list;
        m_list = obj_node->next_node;
        obj_node->reset();
        return obj_node->obj_ptr();
    }

private:

    node_type *m_list = nullptr;
};

template <class T, size_t offset(void)> class xlio_lockless_stack {
public:
    using node_type = stack_node<T, offset>;
    using this_type = xlio_lockless_stack<T, offset>;

    xlio_lockless_stack() {}

    xlio_lockless_stack(const this_type &other) = delete;
    xlio_lockless_stack(this_type &&other) = delete;

    this_type &operator=(const this_type &other) = delete;
    this_type &operator=(this_type &&other) = delete;

    bool empty() const { return (nullptr == m_list.load(std::memory_order::memory_order_relaxed)); }

    xlio_stack<T, offset> pop_all() {
        return m_list.exchange(nullptr, std::memory_order::memory_order_relaxed);
    }

    // @return True if was empty at point of push, False, otherwise. 
    bool push(T *obj)
    {
        if (unlikely(!obj)) {
            vstack_logwarn("Got NULL object - ignoring");
            return false;
        }

        node_type *node_obj = GET_STACK_NODE(obj, T, offset);
        if (unlikely(node_obj->is_stack_member())) {
            vstack_logerr("Object is already a member in a stack!");
            return false;
        }

        node_obj->next_node = m_list.load(std::memory_order::memory_order_relaxed);
        while (!m_list.compare_exchange_weak(node_obj->next_node, node_obj, std::memory_order::memory_order_relaxed)) {
            node_obj->next_node = m_list.load(std::memory_order::memory_order_relaxed);
        }

        return (node_obj->next_node == nullptr);
    }

private:
    std::atomic<node_type *> m_list {nullptr};
};

#endif /* XLIO_LOCKLESS_STACK_H */
