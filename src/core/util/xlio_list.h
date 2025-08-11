/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef XLIO_LIST_H
#define XLIO_LIST_H

#include "core/util/list.h"
#include "vlogger/vlogger.h"

#define VLIST_DEBUG   0
#define VLIST_ID_SIZE 200

#define vlist_logwarn(log_fmt, log_args...)                                                        \
    vlog_printf(VLOG_WARNING, "vlist[%p]:%d:%s() " log_fmt "\n", this, __LINE__, __FUNCTION__,     \
                ##log_args)
#define vlist_logerr(log_fmt, log_args...)                                                         \
    vlog_printf(VLOG_ERROR, "vlist[%p]:%d:%s() " log_fmt "\n", this, __LINE__, __FUNCTION__,       \
                ##log_args)

#if VLIST_DEBUG
template <class T, size_t offset(void)> class xlio_list_t;
#define VLIST_DEBUG_PRINT_ERROR_IS_MEMBER                                                          \
    vlist_logerr("Buff is already a member in a list! parent.id=[%s], this.id=[%s]",               \
                 node_obj->list_id(), this->list_id())
#define VLIST_DEBUG_SET_PARENT(node_obj, val) node_obj->parent = val
#else
#define VLIST_DEBUG_PRINT_ERROR_IS_MEMBER vlist_logerr("Buff is already a member in a list!")
#define VLIST_DEBUG_SET_PARENT(node_obj, val)
#endif

#define NODE_OFFSET(_obj_type, _node_name) ((size_t)(&(char &)(((_obj_type *)1)->_node_name)) - 1)
#define GET_NODE(_obj, _obj_type, _offset_func)                                                    \
    ((list_node<_obj_type, _offset_func> *)((size_t)(_obj) + (size_t)(_offset_func())))

template <class T, size_t offset(void)> class list_node {
public:
    /* head must be the first field! */
    struct list_head head;

#if VLIST_DEBUG
    xlio_list_t<T, offset> *parent;

    char *list_id() { return this->parent->list_id(); }

#endif

    list_node()
    {
        this->head.next = &this->head;
        this->head.prev = &this->head;
        VLIST_DEBUG_SET_PARENT(this, NULL);
    }

    T *obj_ptr() { return reinterpret_cast<T *>(reinterpret_cast<uintptr_t>(this) - offset()); }

    /* is_list_member - check if the node is already a member in a list. */
    bool is_list_member() const
    {
        return this->head.next != &this->head || this->head.prev != &this->head;
    }
};

template <class T, size_t offset(void)> class xlio_list_t {
public:
    xlio_list_t() { init_list(); }

    void set_id(const char *format, ...)
    {
        if (format) {
#if VLIST_DEBUG
            va_list arg;
            va_start(arg, format);
            vsnprintf(id, sizeof(id), format, arg);
            va_end(arg);
#endif
        }
    }

    ~xlio_list_t()
    {
        if (!empty()) {
            vlist_logwarn("Destructor is not supported for non-empty list! size=%zu", m_size);
        }
    }

    xlio_list_t(const xlio_list_t<T, offset> &other)
    {
        if (!other.empty()) {
            vlist_logwarn("Copy constructor is not supported for non-empty list! other.size=%zu",
                          other.m_size);
        }
        init_list();
    }

    xlio_list_t<T, offset> &operator=(const xlio_list_t<T, offset> &other)
    {
        if (!empty() || !other.empty()) {
            vlist_logwarn("Operator= is not supported for non-empty list! size=%zu, other.size=%zu",
                          m_size, other.m_size);
        }
        if (this != &other) {
            init_list();
        }
        return *this;
    }

    T *operator[](size_t idx) const { return get(idx); }

    inline bool empty() const { return m_size == 0; }

    inline size_t size() const { return m_size; }

    inline T *front() const
    {
        if (unlikely(empty())) {
            return NULL;
        }
        return ((list_node<T, offset> *)m_list.head.next)->obj_ptr();
    }

    inline T *back() const
    {
        if (unlikely(empty())) {
            return NULL;
        }
        return ((list_node<T, offset> *)m_list.head.prev)->obj_ptr();
    }

    inline T *next(T *obj) const
    {
        list_node<T, offset> *node = (list_node<T, offset> *)GET_NODE(obj, T, offset)->head.next;
        return node == &m_list ? NULL : node->obj_ptr();
    }

    inline T *prev(T *obj) const
    {
        list_node<T, offset> *node = (list_node<T, offset> *)GET_NODE(obj, T, offset)->head.prev;
        return node == &m_list ? NULL : node->obj_ptr();
    }

    inline void pop_front() { erase(front()); }

    inline void pop_back() { erase(back()); }

    inline T *get_and_pop_front()
    {
        T *list_front = front();
        pop_front();
        return list_front;
    }

    inline T *get_and_pop_back()
    {
        T *list_back = back();
        pop_back();
        return list_back;
    }

    void erase(T *obj)
    {
        if (unlikely(!obj)) {
            vlist_logwarn("Got NULL object - ignoring");
            return;
        }

        list_node<T, offset> *node_obj = GET_NODE(obj, T, offset);
        VLIST_DEBUG_SET_PARENT(node_obj, NULL);
        list_del_init(&node_obj->head);
        m_size--;
    }

    /**
     * Clear content
     * Removes all elements from the list container (which are NOT destroyed), and leaving the
     * container with a size of 0.
     *
     * NOTE: we don't expect calling this method in normal situations (it is workaround at
     * application shutdown); Hence, there is no cleanup of node.parent
     */
    void clear_without_cleanup() { init_list(); }

    // This method enables easy cleanup of the list.
    // Each object that resides in the list must be seperately cleared.
    // Becuase, the next,prev members are part of the inserted object and should be
    // treated accordingly, otherwise the removed object cannot be reinserted.
    void clear()
    {
        while (!empty()) {
            pop_front();
        }
    }

    void push_back_impl(T *obj, bool err_print)
    {
        if (unlikely(!obj)) {
            vlist_logwarn("Got NULL object - ignoring");
            return;
        }

        list_node<T, offset> *node_obj = GET_NODE(obj, T, offset);
        if (unlikely(node_obj->is_list_member())) {
            if (err_print) {
                VLIST_DEBUG_PRINT_ERROR_IS_MEMBER;
            }
            return;
        }

        VLIST_DEBUG_SET_PARENT(node_obj, this);
        list_add_tail(&node_obj->head, &m_list.head);
        m_size++;
    }

    void push_back(T *obj) { push_back_impl(obj, true); }

    void push_back_if_absent(T *obj) { push_back_impl(obj, false); }

    void push_front(T *obj)
    {
        if (unlikely(!obj)) {
            vlist_logwarn("Got NULL object - ignoring");
            return;
        }

        list_node<T, offset> *node_obj = GET_NODE(obj, T, offset);
        if (unlikely(node_obj->is_list_member())) {
            VLIST_DEBUG_PRINT_ERROR_IS_MEMBER;
        }

        VLIST_DEBUG_SET_PARENT(node_obj, this);
        list_add(&node_obj->head, &m_list.head);
        m_size++;
    }

    T *get(size_t index) const
    {
        if (m_size <= index) {
            return NULL;
        } else {
            list_head *ans = m_list.head.next;
            for (size_t i = 0; i < index; i++) {
                ans = ans->next;
            }
            return ((list_node<T, offset> *)ans)->obj_ptr();
        }
    }

    // concatenate 'from' at the head of this list
    void splice_head(xlio_list_t<T, offset> &from)
    {

        this->m_size += from.m_size;
        list_splice(&from.m_list.head, &this->m_list.head);
        from.init_list();
        // TODO: in case VLIST_DEBUG, this invalidates parent list of all nodes in the list
    }

    // concatenate 'from' at the tail of this list
    void splice_tail(xlio_list_t<T, offset> &from)
    {
        this->m_size += from.m_size;
        list_splice_tail(&from.m_list.head, &this->m_list.head);
        from.init_list();
        // TODO: in case VLIST_DEBUG, this invalidates parent list of all nodes in the list
    }

    /**
     * Swap content
     * Exchanges the content of the container by the content of x, which is another list of the same
     * type. Sizes may differ.
     *
     * After the call to this member function, the elements in this container are those which were
     * in x before the call, and the elements of x are those which were in this. All references and
     * pointers remain valid for the swapped objects.
     */
    void swap(xlio_list_t<T, offset> &x)
    {
        xlio_list_t<T, offset> temp_list;
        this->move_to_empty(temp_list);
        x.move_to_empty(*this);
        temp_list.move_to_empty(x);
    }

    bool is_member(const T *obj) const
    {
        if (likely(obj)) {
            list_node<T, offset> *node_obj = GET_NODE(obj, T, offset);
            return node_obj->is_list_member();
        }

        return false;
    }

#if VLIST_DEBUG
    char *list_id() { return (char *)&id; }
#endif

private:
    list_node<T, offset> m_list;
    size_t m_size;

#if VLIST_DEBUG
    char id[VLIST_ID_SIZE];
#endif

    void move_to_empty(xlio_list_t<T, offset> &to)
    {
        assert(to.empty());
        to.m_size = this->m_size;
        list_splice_tail(&this->m_list.head, &to.m_list.head);
        this->init_list();
        // TODO: in case VLIST_DEBUG, this invalidates parent list of all nodes in the list
    }

    void init_list()
    {
        m_size = 0;
        INIT_LIST_HEAD(&m_list.head);
#if VLIST_DEBUG
        id[0] = '\0';
#endif
    }
};

#endif /* XLIO_LIST_H */
