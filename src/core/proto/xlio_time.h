/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef XLIO_TIME_H_
#define XLIO_TIME_H_

#include <stdint.h>
#include <time.h>
#include <assert.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) && (((__GNUC__ == 4) && (__GNUC_MINOR__ >= 4)) || (__GNUC__ > 4))
#pragma GCC visibility push(hidden)
#endif

/* Per-thread RX-batch timestamp in monotonic microseconds; 0 means unavailable. */
extern __thread int64_t g_xlio_tls_now_us;

/* Debug-build counters for clock placement and empty RX batches. */
#if !defined(XLIO_TIME_DEBUG_COUNTERS) && !defined(NDEBUG)
#define XLIO_TIME_DEBUG_COUNTERS 1
#endif

#ifdef XLIO_TIME_DEBUG_COUNTERS
struct xlio_time_debug_counters_t {
    uint64_t refresh_rx_batch; /* xlio_now_us_refresh() calls: one per non-empty RX batch */
    uint64_t empty_polls; /* RX poll/drain batches that refreshed zero times (no packet
                             delivered; includes filler-only strq passes, not just empty CQ) */
    uint64_t tx_rtt_start_read; /* tcp_output_segment() RTT-sample-start clock read */
    uint64_t tx_arm_idle_read; /* cold-path deadline-arm clock read */
    uint64_t timer_pass_read; /* handle_timer_expired() per-pass clock read */
    uint64_t fallback_reads; /* direct clock reads when the RX-batch timestamp is unavailable */
};
extern __thread struct xlio_time_debug_counters_t g_xlio_time_debug_counters;

static inline void xlio_time_dbg_inc_refresh_rx_batch(void)
{
    g_xlio_time_debug_counters.refresh_rx_batch++;
}
static inline void xlio_time_dbg_inc_empty_poll(void)
{
    g_xlio_time_debug_counters.empty_polls++;
}
static inline void xlio_time_dbg_inc_tx_rtt_start(void)
{
    g_xlio_time_debug_counters.tx_rtt_start_read++;
}
static inline void xlio_time_dbg_inc_tx_arm_idle(void)
{
    g_xlio_time_debug_counters.tx_arm_idle_read++;
}
static inline void xlio_time_dbg_inc_timer_pass(void)
{
    g_xlio_time_debug_counters.timer_pass_read++;
}
static inline void xlio_time_dbg_inc_fallback(void)
{
    g_xlio_time_debug_counters.fallback_reads++;
}
/* Debug counter accessors. */
static inline struct xlio_time_debug_counters_t xlio_time_debug_counters_get(void)
{
    return g_xlio_time_debug_counters;
}
static inline void xlio_time_debug_counters_reset(void)
{
    memset(&g_xlio_time_debug_counters, 0, sizeof(g_xlio_time_debug_counters));
}
#else
static inline void xlio_time_dbg_inc_refresh_rx_batch(void)
{
}
static inline void xlio_time_dbg_inc_empty_poll(void)
{
}
static inline void xlio_time_dbg_inc_tx_rtt_start(void)
{
}
static inline void xlio_time_dbg_inc_tx_arm_idle(void)
{
}
static inline void xlio_time_dbg_inc_timer_pass(void)
{
}
static inline void xlio_time_dbg_inc_fallback(void)
{
}
#endif /* XLIO_TIME_DEBUG_COUNTERS */

/* Monotonic microsecond clock. */
static inline int64_t clock_gettime_monotonic_us(void)
{
    struct timespec ts;
    int rc = clock_gettime(CLOCK_MONOTONIC, &ts);
    assert(rc == 0);
    (void)rc;
    /* Force 64-bit conversion on 32-bit time_t targets. */
    return (int64_t)ts.tv_sec * 1000000LL + ts.tv_nsec / 1000LL;
}

/* Refresh and return the RX-batch timestamp. */
static inline int64_t xlio_now_us_refresh(void)
{
    xlio_time_dbg_inc_refresh_rx_batch();
    return g_xlio_tls_now_us = clock_gettime_monotonic_us();
}

/* Return the cached RX-batch timestamp. */
static inline int64_t xlio_now_us(void)
{
    return g_xlio_tls_now_us;
}

#if defined(__GNUC__) && (((__GNUC__ == 4) && (__GNUC_MINOR__ >= 4)) || (__GNUC__ > 4))
#pragma GCC visibility pop
#endif

#ifdef __cplusplus
} /* extern "C" */

/* RX-batch timestamp guard. Empty batches avoid clock and TLS writes. */
class xlio_now_us_batch {
public:
    xlio_now_us_batch()
        : m_previous_now_us(xlio_now_us())
    {
    }
    ~xlio_now_us_batch()
    {
        if (m_armed) {
            g_xlio_tls_now_us = m_previous_now_us;
        } else {
            /* No refresh denotes an empty batch. */
            xlio_time_dbg_inc_empty_poll();
        }
    }
    int64_t refresh()
    {
        m_armed = true;
        return xlio_now_us_refresh();
    }
    bool armed() const { return m_armed; }

private:
    int64_t m_previous_now_us;
    bool m_armed = false;
};
#endif /* __cplusplus */

#endif /* XLIO_TIME_H_ */
