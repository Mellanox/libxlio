/*
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

// todo disable assert
#define ASSERT_LOCKED(lock)     assert((lock).is_locked_by_me())
#define ASSERT_NOT_LOCKED(lock) assert(!(lock).is_locked_by_me())

#ifdef DEFINED_NO_THREAD_LOCK
#define DEFINED_NO_THREAD_LOCK_RETURN_0 return 0;
#define DEFINED_NO_THREAD_LOCK_RETURN_1 return 1;
#else
#define DEFINED_NO_THREAD_LOCK_RETURN_0
#define DEFINED_NO_THREAD_LOCK_RETURN_1
#endif

#define NO_LOCK_STATS

#ifdef NO_LOCK_STATS
#define LOCK_BASE_LOCK
#define LOCK_BASE_TRYLOCK
#define LOCK_BASE_UNLOCK
#define LOCK_BASE_START_LOCK_WAIT
#define LOCK_BASE_END_LOCK_WAIT
#else
#define LOCK_BASE_LOCK            lock_base::lock();
#define LOCK_BASE_TRYLOCK         lock_base::trylock();
#define LOCK_BASE_UNLOCK          lock_base::unlock();
#define LOCK_BASE_START_LOCK_WAIT tscval_t timeval = start_lock_wait();
#define LOCK_BASE_END_LOCK_WAIT   end_lock_wait(timeval);
#endif

#ifdef NO_LOCK_STATS

// pthread lock stats counter for debugging
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
    virtual int is_locked_by_me()
    {
        vlog_printf(VLOG_ERROR, "is_locked_by_me() used for not supported class.\n");
        return 0;
    }

    const char *to_str() { return m_lock_name; }

private:
    const char *m_lock_name;
};
#else // NO_LOCK_STATS

#include <stdlib.h>
#include <stdio.h>

//
// pthread counting mutex
//
class lock_base {
public:
    lock_base(const char *name)
    {
        m_lock_count = 0;
        m_lock_wait_time = 0;
        m_lock_name = name;
        m_prev_print_time = 0;
        m_print_interval = get_tsc_rate_per_second() * 5;
    };

    virtual ~lock_base()
    {
        if (m_lock_count > 1000) {
            print_stats();
        }
    };

    virtual inline int lock()
    {
        m_lock_count++;
        return 0;
    };

    virtual inline int trylock()
    {
        m_lock_count++;
        return 0;
    }

    virtual inline int unlock() { return 0; };

    virtual inline int is_locked_by_me() { return 0; }

    const char *to_str() { return m_lock_name; }

private:
    void print_stats()
    {
        printf("[lock %s %p] --- locked %d times average wait %.2f us ---\n", to_str(), this,
               m_lock_count, avg_lock_wait() * 1000000.0);
    }

    const char *m_lock_name;
    int m_lock_count;
    tscval_t m_lock_wait_time;
    tscval_t m_prev_print_time;
    tscval_t m_print_interval;

protected:
    tscval_t start_lock_wait()
    {
        tscval_t t;
        gettimeoftsc(&t);
        return t;
    }

    void end_lock_wait(tscval_t start_time)
    {
        tscval_t t;
        gettimeoftsc(&t);
        m_lock_wait_time += (t - start_time);
        if (t - m_prev_print_time > m_print_interval) {
            print_stats();
            m_prev_print_time = t;
        }
    }

    double avg_lock_wait()
    {
        return (m_lock_wait_time / static_cast<double>(get_tsc_rate_per_second())) / m_lock_count;
    }
};
#endif // NO_LOCK_STATS

/**
 * pthread spinlock
 */
/* coverity[missing_move_assignment] */
class lock_spin : public lock_base {
public:
    lock_spin(const char *name = "lock_spin")
        : lock_base(name)
    {
        pthread_spin_init(&m_lock, 0);
    };
    ~lock_spin() { pthread_spin_destroy(&m_lock); };
    inline int lock()
    {
        DEFINED_NO_THREAD_LOCK_RETURN_0
        LOCK_BASE_START_LOCK_WAIT
        int ret = pthread_spin_lock(&m_lock);
        LOCK_BASE_LOCK
        LOCK_BASE_END_LOCK_WAIT
        return ret;
    };
    inline int trylock()
    {
        DEFINED_NO_THREAD_LOCK_RETURN_0
        int ret = pthread_spin_trylock(&m_lock);
        LOCK_BASE_TRYLOCK
        return ret;
    };
    inline int unlock()
    {
        DEFINED_NO_THREAD_LOCK_RETURN_0
        LOCK_BASE_UNLOCK
        return pthread_spin_unlock(&m_lock);
    };
    inline int is_locked_by_me()
    {
        assert(!"lock_spin::is_locked_by_me is unsupported");
        return 0; // Unsupported
    }

protected:
    pthread_spinlock_t m_lock;
};

/**
 * pthread spinlock
 */
/* coverity[missing_move_assignment] */
class lock_spin_recursive : public lock_spin {
public:
    lock_spin_recursive(const char *name = "lock_spin_recursive")
        : lock_spin(name)
        , m_lock_count(0)
    {
        memset(&m_invalid_owner, 0xff, sizeof(m_invalid_owner));
        m_owner = m_invalid_owner;
    };
    ~lock_spin_recursive() {};

    inline int lock()
    {
        DEFINED_NO_THREAD_LOCK_RETURN_0
        pthread_t self = pthread_self();
        if (m_owner == self) {
            ++m_lock_count;
            return 0;
        }
        LOCK_BASE_START_LOCK_WAIT
        int ret = lock_spin::lock();
        if (likely(ret == 0)) {
            ++m_lock_count;
            m_owner = self;
        }
        LOCK_BASE_END_LOCK_WAIT
        return ret;
    };
    inline int trylock()
    {
        DEFINED_NO_THREAD_LOCK_RETURN_0
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
    };
    inline int unlock()
    {
        DEFINED_NO_THREAD_LOCK_RETURN_0
        if (--m_lock_count == 0) {
            m_owner = m_invalid_owner;
            return lock_spin::unlock();
        }
        return 0;
    };
    inline int is_locked_by_me()
    {
        DEFINED_NO_THREAD_LOCK_RETURN_1
        pthread_t self = pthread_self();
        return ((m_owner == self && m_lock_count) ? m_lock_count : 0);
    };

protected:
    pthread_t m_owner;
    pthread_t m_invalid_owner;
    int m_lock_count;
};

/**
 * pthread mutex
 */
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
    ~lock_mutex() { pthread_mutex_destroy(&m_lock); };
    inline int lock()
    {
        DEFINED_NO_THREAD_LOCK_RETURN_0
        LOCK_BASE_START_LOCK_WAIT
        int ret = pthread_mutex_lock(&m_lock);
        LOCK_BASE_LOCK
        LOCK_BASE_END_LOCK_WAIT
        return ret;
    };
    inline int trylock()
    {
        DEFINED_NO_THREAD_LOCK_RETURN_0
        int ret = pthread_mutex_trylock(&m_lock);
        LOCK_BASE_TRYLOCK
        return ret;
    };
    inline int unlock()
    {
        DEFINED_NO_THREAD_LOCK_RETURN_0
        LOCK_BASE_UNLOCK
        return pthread_mutex_unlock(&m_lock);
    };
    inline int is_locked_by_me()
    {
        assert(!"lock_mutex::is_locked_by_me is unsupported");
        return 0; // Unsupported
    }

protected:
    pthread_mutex_t m_lock;
};

/**
 * pthread recursive mutex
 */
class lock_mutex_recursive : public lock_mutex {
public:
    lock_mutex_recursive(const char *name = "lock_mutex_recursive")
        : lock_mutex(name, PTHREAD_MUTEX_RECURSIVE)
        , m_lock_count(0)
    {
        memset(&m_invalid_owner, 0xff, sizeof(m_invalid_owner));
        m_owner = m_invalid_owner;
    };
    ~lock_mutex_recursive() {};

    inline int lock()
    {
        DEFINED_NO_THREAD_LOCK_RETURN_0
        pthread_t self = pthread_self();
        if (m_owner == self) {
            ++m_lock_count;
            return 0;
        }
        LOCK_BASE_START_LOCK_WAIT
        int ret = lock_mutex::lock();
        if (likely(ret == 0)) {
            ++m_lock_count;
            m_owner = self;
        }
        LOCK_BASE_END_LOCK_WAIT
        return ret;
    };
    inline int trylock()
    {
        DEFINED_NO_THREAD_LOCK_RETURN_0
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
    };
    inline int unlock()
    {
        DEFINED_NO_THREAD_LOCK_RETURN_0
        if (--m_lock_count == 0) {
            m_owner = m_invalid_owner;
            return lock_mutex::unlock();
        }
        return 0;
    };
    inline int is_locked_by_me()
    {
        DEFINED_NO_THREAD_LOCK_RETURN_1
        pthread_t self = pthread_self();
        return ((m_owner == self && m_lock_count) ? m_lock_count : 0);
    };

protected:
    pthread_t m_owner;
    pthread_t m_invalid_owner;
    int m_lock_count;
};

/**
 * pthread rwlock
 */
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
    ~lock_rw() { pthread_rwlock_destroy(&m_lock); };
    inline int lock_rd()
    {
        DEFINED_NO_THREAD_LOCK_RETURN_0
        return pthread_rwlock_rdlock(&m_lock);
    };
    inline int lock_wr()
    {
        DEFINED_NO_THREAD_LOCK_RETURN_0
        return pthread_rwlock_wrlock(&m_lock);
    };
    inline int unlock()
    {
        DEFINED_NO_THREAD_LOCK_RETURN_0
        return pthread_rwlock_unlock(&m_lock);
    };

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
            vlog_printf(VLOG_ERROR, "multilock type is not supported.\n");
            return nullptr;
        }

        return lock;
    }

    inline int lock() { return m_lock->lock(); }
    inline int trylock() { return m_lock->trylock(); }
    inline int unlock() { return m_lock->unlock(); }
    lock_base &get_lock_base() { return *m_lock; }
    inline int is_locked_by_me() { return m_lock->is_locked_by_me(); }
    inline const char *to_str() { return m_lock->to_str(); }

private:
    typedef std::function<void(lock_base *)> lock_deleter;
    std::unique_ptr<lock_base, lock_deleter> m_lock;
};

#endif // LOCK_WRAPPER_H
