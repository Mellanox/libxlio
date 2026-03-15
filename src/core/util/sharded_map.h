/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef SHARDED_MAP_H
#define SHARDED_MAP_H

#include <unordered_map>
#include <functional>
#include <utils/lock_wrapper.h>

/**
 * A sharded map that distributes entries across multiple buckets to reduce lock contention.
 * Each bucket has its own lock, so operations on different buckets can proceed in parallel.
 *
 * @tparam Key    The key type
 * @tparam Value  The value type
 * @tparam N      Number of buckets
 */
template <typename Key, typename Value, size_t N = 1024> class sharded_map {
public:
    sharded_map() = default;
    ~sharded_map() = default;

    /**
     * Adds a key->value mapping.
     * If key already exists with the same value, does nothing.
     * If key already exists with a different value, replaces its value with replace_with.
     * @return true if this is a new entry, false if key already existed
     */
    bool add_or_replace(const Key &key, Value value, Value replace_with)
    {
        size_t idx = bucket_index(key);
        bucket_t &b = m_buckets[idx];

        b.lock.lock();
        auto it = b.map.find(key);
        if (it == b.map.end()) {
            b.map[key] = value;
            b.lock.unlock();
            return true;
        } else if (it->second != value && it->second != replace_with) {
            it->second = replace_with;
        }
        b.lock.unlock();
        return false;
    }

    /**
     * Remove a specific key->value mapping.
     * Only removes if the current value equals the specified value.
     * @return true if entry was removed, false otherwise
     */
    bool remove_if_equals(const Key &key, Value value)
    {
        size_t idx = bucket_index(key);
        bucket_t &b = m_buckets[idx];

        b.lock.lock();
        auto it = b.map.find(key);
        if (it != b.map.end() && it->second == value) {
            b.map.erase(it);
            b.lock.unlock();
            return true;
        }
        b.lock.unlock();
        return false;
    }

    /**
     * Atomically remove and return the value for a key.
     * @param not_found Value to return if key is not found
     * @return The value that was stored, or not_found if key was not present
     */
    Value remove_and_get(const Key &key, Value not_found)
    {
        size_t idx = bucket_index(key);
        bucket_t &b = m_buckets[idx];

        b.lock.lock();
        auto it = b.map.find(key);
        if (it == b.map.end()) {
            b.lock.unlock();
            return not_found;
        }
        Value result = it->second;
        b.map.erase(it);
        b.lock.unlock();
        return result;
    }

    /**
     * Remove all entries that have a specific value.
     * @param value The value to remove
     * @return Number of entries removed
     */
    size_t remove_all_for_value(Value value)
    {
        size_t removed = 0;
        for (size_t i = 0; i < N; ++i) {
            bucket_t &b = m_buckets[i];
            b.lock.lock();
            for (auto it = b.map.begin(); it != b.map.end();) {
                if (it->second == value) {
                    it = b.map.erase(it);
                    ++removed;
                } else {
                    ++it;
                }
            }
            b.lock.unlock();
        }
        return removed;
    }

private:
    struct bucket_t {
        std::unordered_map<Key, Value> map;
        lock_mutex lock;
    };

    bucket_t m_buckets[N];

    static size_t bucket_index(const Key &key) { return std::hash<Key> {}(key) % N; }
};

#endif // SHARDED_MAP_H
