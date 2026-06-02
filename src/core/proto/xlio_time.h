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

/* Per-thread cached "now" in microseconds. RX poll is the only writer (via
 * xlio_now_us_refresh(), once per non-empty batch before the first packet
 * reaches TCP). Readers: tcp_receive() (the ACK RTT sample) and the two
 * tcp_process() establishment seeds. TX and timer paths bypass TLS and call
 * clock_gettime_monotonic_us() directly.
 *
 * The slot is cleared to 0 at the end of every non-empty RX batch (via the
 * xlio_now_us_batch guard). Combined with the per-batch refresh this is a
 * fail-safe invariant: a read without a same-batch refresh - reachable only on
 * an RX-refresh coverage bug - always sees 0, so the zero-sample clamp drops it
 * (plus a dev-build assert and debug log), never a stale value from an earlier batch.
 * See the RM#4930789 microsecond RTT/RTO design.
 */
extern __thread int64_t g_xlio_tls_now_us;

/* --- Debug/test-build clock-read counters (design invariant I2) ---
 *
 * I2: at most one monotonic-clock read per non-empty RX batch, zero on empty
 * polls, one per non-empty timer bucket pass; the defensive direct-clock
 * fallbacks stay at zero. These per-thread counters make that invariant
 * observable so unit tests, gtest, and lab runs can assert it directly.
 *
 * Compiled only when NDEBUG is undefined (unit/gtest and --enable-debug
 * builds), exactly like the assert() in clock_gettime_monotonic_us() below;
 * release builds (-DNDEBUG, see config/m4/compiler.m4) carry zero storage and
 * every xlio_time_dbg_inc_*() is an empty inline the optimizer deletes. The
 * g_xlio_time_debug_counters symbol is therefore absent from the shipped .so
 * (checkable with `nm`), which is the compile-out proof.
 *
 * The counters are hidden-visibility and reached only through the inlined
 * accessors, so the unit test recompiles the sources into its own binary; it
 * never links the shipped library.
 *
 * Auto-enabled whenever asserts are (NDEBUG undefined), and the unit-test
 * Makefile force-defines XLIO_TIME_DEBUG_COUNTERS=1 so the counter tests run
 * even though configure builds the tree with -DNDEBUG - a release .so still
 * carries neither the storage nor the increments.
 */
#if !defined(XLIO_TIME_DEBUG_COUNTERS) && !defined(NDEBUG)
#define XLIO_TIME_DEBUG_COUNTERS 1
#endif

#ifdef XLIO_TIME_DEBUG_COUNTERS
struct xlio_time_debug_counters_t {
    uint64_t refresh_rx_batch; /* xlio_now_us_refresh() calls: one per non-empty RX batch */
    uint64_t empty_polls; /* RX poll/drain batches that refreshed zero times (no packet
                             delivered; includes filler-only strq passes, not just empty CQ) */
    uint64_t tx_rtt_start_read; /* tcp_output_segment() RTT-sample-start clock read */
    uint64_t tx_arm_idle_read; /* tcp_output_segment() cold-path deadline-arm clock read */
    uint64_t timer_pass_read; /* handle_timer_expired() per-pass clock read */
    uint64_t fallback_reads; /* defensive direct-clock rearm fallbacks; MUST stay 0 */
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

/* Test-only snapshot / reset of the per-thread counters. Recompiled into the
 * unit-test binary; never linked into the shipped .so (release defines NDEBUG).
 */
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

/* vDSO-inlined monotonic microsecond clock. Every TU that includes this
 * header inlines the call site. The clock_gettime rc check is a standard
 * assert(): checked when NDEBUG is undefined, DCE'd otherwise. No bespoke
 * XLIO_TIME_* build flag.
 */
static inline int64_t clock_gettime_monotonic_us(void)
{
    struct timespec ts;
    int rc = clock_gettime(CLOCK_MONOTONIC, &ts);
    assert(rc == 0);
    (void)rc;
    /* Suffix the literals to make the int64_t-wide multiply explicit
     * regardless of where the cast binds. tv_sec is time_t (typically
     * int64_t on 64-bit ABIs but only int32_t on Y2038-vulnerable 32-bit
     * ABIs); the LL suffix forces 64-bit math even if a future refactor
     * relocates the cast.
     */
    return (int64_t)ts.tv_sec * 1000000LL + ts.tv_nsec / 1000LL;
}

/* Refresh the per-thread cached "now" and return the freshly-read value.
 * Called only from the RX CQ refresh hook
 * (cq_mgr_rx_*::poll_and_process_element_rx, drain_and_proccess).
 */
static inline int64_t xlio_now_us_refresh(void)
{
    xlio_time_dbg_inc_refresh_rx_batch();
    return g_xlio_tls_now_us = clock_gettime_monotonic_us();
}

/* Return the per-thread cached "now". Called only from tcp_receive() to
 * consume the RX-batch timestamp for ACK-side RTT sampling.
 */
static inline int64_t xlio_now_us(void)
{
    return g_xlio_tls_now_us;
}

/* Clear the per-thread cache (0 = "not armed"). Called at the end of each
 * non-empty RX batch via the xlio_now_us_batch guard so a later read without a
 * refresh - only reachable on an RX-refresh coverage bug - sees the detectable
 * 0 sentinel and drops the sample, instead of consuming a stale value left over
 * from an earlier batch.
 */
static inline void xlio_now_us_clear(void)
{
    g_xlio_tls_now_us = 0;
}

#if defined(__GNUC__) && (((__GNUC__ == 4) && (__GNUC_MINOR__ >= 4)) || (__GNUC__ > 4))
#pragma GCC visibility pop
#endif

#ifdef __cplusplus
} /* extern "C" */

/* RAII guard for one RX poll/drain batch. Refresh through it (refresh()); on
 * scope exit it clears the per-thread cache, but only if this batch actually
 * refreshed - so empty polls pay a single predictable branch (no TLS write) and
 * stay on the zero-clock-read hot path. It covers every return path of the CQ
 * poll/drain functions without a clear at each one.
 */
class xlio_now_us_batch {
public:
    ~xlio_now_us_batch()
    {
        if (m_armed) {
            xlio_now_us_clear();
        } else {
            /* No refresh this batch: an empty poll/drain. Counting it here (one
             * xlio_now_us_batch per poll/drain call) keeps the "refresh on a
             * non-empty batch vs. empty poll" partition in one place - no
             * per-site instrumentation in the CQ managers. No-op in release. */
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
    bool m_armed = false;
};
#endif /* __cplusplus */

#endif /* XLIO_TIME_H_ */
