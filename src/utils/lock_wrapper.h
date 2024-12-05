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

#ifndef LOCK_WRAPPER_H
#define LOCK_WRAPPER_H

#include <pthread.h>
#include <execinfo.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <memory>
#include "types.h"
#include "utils/bullseye.h"
#include "utils/rdtsc.h"
#include <functional>
#include <vlogger/vlogger.h>
#include <core/util/sys_vars.h>

// TODO: disable assert
#define ASSERT_LOCKED(lock)     assert((lock).is_locked_by_me())
#define ASSERT_NOT_LOCKED(lock) assert(!(lock).is_locked_by_me())

/* coverity[missing_move_assignment] */
class lock_base {
public:
    lock_base(const char *_lock_name = NULL)
        : m_lock_name(_lock_name) {};
    virtual ~lock_base() {};
    virtual void delete_obj() { delete this; }
    virtual int lock() = 0;
    virtual int trylock() = 0;
    virtual int unlock() = 0;
    virtual int is_locked_by_me() = 0;

    const char *to_str() { return m_lock_name; }

private:
    const char *m_lock_name;
};

// Based on pthread spinlock
/* coverity[missing_move_assignment] */
class lock_spin : public lock_base {
public:
    lock_spin(const char *name = "lock_spin")
        : lock_base(name)
    {
        pthread_spin_init(&m_lock, 0);
    }
    ~lock_spin() override { pthread_spin_destroy(&m_lock); }
    int lock() override { return pthread_spin_lock(&m_lock); }
    int trylock() override { return pthread_spin_trylock(&m_lock); }
    int unlock() override { return pthread_spin_unlock(&m_lock); }
    int is_locked_by_me() override
    {
        assert(!"lock_spin::is_locked_by_me is unsupported");
        return 0; // Unsupported
    }

protected:
    pthread_spinlock_t m_lock;
};

// Based on pthread spinlock
// This lock has no base, no virtual methods and requires less memory.
/* coverity[missing_move_assignment] */
class lock_spin_simple {
public:
    lock_spin_simple() { pthread_spin_init(&m_lock, 0); };
    ~lock_spin_simple() { pthread_spin_destroy(&m_lock); };
    int lock() { return pthread_spin_lock(&m_lock); };
    int trylock() { return pthread_spin_trylock(&m_lock); };
    int unlock() { return pthread_spin_unlock(&m_lock); };
    int is_locked_by_me()
    {
        assert(!"lock_spin_simple::is_locked_by_me is unsupported");
        return 0; // Unsupported
    }

protected:
    pthread_spinlock_t m_lock;
};

// Based on pthread spinlock
/* coverity[missing_move_assignment] */
class lock_spin_recursive : public lock_spin {
public:
    lock_spin_recursive(const char *name = "lock_spin_recursive")
        : lock_spin(name)
        , m_lock_count(0)
    {
        memset(&m_invalid_owner, 0xff, sizeof(m_invalid_owner));
        m_owner = m_invalid_owner;
    }

    int lock() override
    {
        pthread_t self = pthread_self();
        /* coverity[use_same_locks_for_read_and_modify:FALSE] */
        if (m_owner == self) {
            ++m_lock_count;
            return 0;
        }
        int ret = lock_spin::lock();
        if (likely(ret == 0)) {
            ++m_lock_count;
            m_owner = self;
        }
        return ret;
    }

    int trylock() override
    {
        pthread_t self = pthread_self();
        if (m_owner == self) {
            ++m_lock_count;
            return 0;
        }
        int ret = lock_spin::trylock();
        if (ret == 0) {
            ++m_lock_count;
            m_owner = self;
        }
        return ret;
    }

    int unlock() override
    {
        if (--m_lock_count == 0) {
            m_owner = m_invalid_owner;
            return lock_spin::unlock();
        }
        return 0;
    }

    int is_locked_by_me() override
    {
        pthread_t self = pthread_self();
        return ((m_owner == self && m_lock_count) ? m_lock_count : 0);
    }

protected:
    pthread_t m_owner;
    pthread_t m_invalid_owner;
    int m_lock_count;
};

// Based on pthread mutex
class lock_mutex : public lock_base {
public:
    lock_mutex(const char *name = "lock_mutex", int mtx_type = PTHREAD_MUTEX_DEFAULT)
        : lock_base(name)
    {
        pthread_mutexattr_t mtx_attr;
        pthread_mutexattr_init(&mtx_attr);
        pthread_mutexattr_settype(&mtx_attr, mtx_type);
        pthread_mutex_init(&m_lock, &mtx_attr);
    };
    ~lock_mutex() override { pthread_mutex_destroy(&m_lock); }
    int lock() override { return pthread_mutex_lock(&m_lock); }
    int trylock() override { return pthread_mutex_trylock(&m_lock); }
    int unlock() override { return pthread_mutex_unlock(&m_lock); }
    int is_locked_by_me() override
    {
        assert(!"lock_mutex::is_locked_by_me is unsupported");
        return 0; // Unsupported
    }

protected:
    pthread_mutex_t m_lock;
};

// Based on pthread mutex
class lock_mutex_recursive : public lock_mutex {
public:
    lock_mutex_recursive(const char *name = "lock_mutex_recursive")
        : lock_mutex(name, PTHREAD_MUTEX_RECURSIVE)
        , m_lock_count(0)
    {
        memset(&m_invalid_owner, 0xff, sizeof(m_invalid_owner));
        m_owner = m_invalid_owner;
    };

    int lock() override
    {
        pthread_t self = pthread_self();
        /* coverity[use_same_locks_for_read_and_modify:FALSE] */
        if (m_owner == self) {
            ++m_lock_count;
            return 0;
        }
        int ret = lock_mutex::lock();
        if (likely(ret == 0)) {
            ++m_lock_count;
            m_owner = self;
        }
        return ret;
    }

    int trylock() override
    {
        pthread_t self = pthread_self();
        if (m_owner == self) {
            ++m_lock_count;
            return 0;
        }
        int ret = lock_mutex::trylock();
        if (ret == 0) {
            ++m_lock_count;
            m_owner = self;
        }
        return ret;
    }

    int unlock() override
    {
        if (--m_lock_count == 0) {
            m_owner = m_invalid_owner;
            return lock_mutex::unlock();
        }
        return 0;
    }

    int is_locked_by_me() override
    {
        pthread_t self = pthread_self();
        return ((m_owner == self && m_lock_count) ? m_lock_count : 0);
    }

protected:
    pthread_t m_owner;
    pthread_t m_invalid_owner;
    int m_lock_count;
};

// Based on pthread rwlock
class lock_rw {
public:
#ifdef HAVE_PTHREAD_RWLOCK_NP
    enum {
        LOCK_RW_PREFER_READ = PTHREAD_RWLOCK_PREFER_READER_NP,
        LOCK_RW_PREFER_WRITE = PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP,
    };

    lock_rw(int rw_type = LOCK_RW_PREFER_WRITE)
#else
    lock_rw()
#endif
    {
        pthread_rwlockattr_t rw_attr;
        pthread_rwlockattr_init(&rw_attr);
#ifdef HAVE_PTHREAD_RWLOCK_NP
        pthread_rwlockattr_setkind_np(&rw_attr, rw_type);
#endif
        pthread_rwlock_init(&m_lock, &rw_attr);
    };
    ~lock_rw() { pthread_rwlock_destroy(&m_lock); }
    int lock_rd() { return pthread_rwlock_rdlock(&m_lock); }
    int lock_wr() { return pthread_rwlock_wrlock(&m_lock); }
    int unlock() { return pthread_rwlock_unlock(&m_lock); }

protected:
    pthread_rwlock_t m_lock;
};

class lock_dummy : public lock_base {
public:
    lock_dummy(const char *name = "lock_dummy")
        : lock_base(name)
    {
    }

    void delete_obj() override {}
    int lock() override { return 0; }
    int trylock() override { return 0; }
    int unlock() override { return 0; }
    int is_locked_by_me() override { return 1; }
};

static inline void lock_deleter_func(lock_base *lock)
{
    lock->delete_obj();
}

class multilock {
public:
    multilock(lock_base *_lock)
        : m_lock(_lock, lock_deleter_func)
    {
    }

    multilock(multilock_recursive_t _recursive, const char *_str)
        : m_lock(create_new_lock(_recursive, _str), lock_deleter_func)
    {
    }

    static lock_base *create_new_lock(multilock_recursive_t _recursive, const char *_str)
    {
        lock_base *lock = nullptr;
        switch (safe_mce_sys().multilock) {
        case MULTILOCK_SPIN:
            lock = (_recursive == MULTILOCK_RECURSIVE) ? new lock_spin_recursive(_str)
                                                       : new lock_spin(_str);
            break;
        case MULTILOCK_MUTEX:
            lock = (_recursive == MULTILOCK_RECURSIVE) ? new lock_mutex_recursive(_str)
                                                       : new lock_mutex(_str);
            break;
        default:
            __log_header_err("multilock type is not supported.\n");
            return nullptr;
        }

        return lock;
    }

    int lock() { return m_lock->lock(); }
    int trylock() { return m_lock->trylock(); }
    int unlock() { return m_lock->unlock(); }
    lock_base &get_lock_base() { return *m_lock; }
    int is_locked_by_me() { return m_lock->is_locked_by_me(); }
    const char *to_str() { return m_lock->to_str(); }

private:
    typedef std::function<void(lock_base *)> lock_deleter;
    std::unique_ptr<lock_base, lock_deleter> m_lock;
};

#endif // LOCK_WRAPPER_H
