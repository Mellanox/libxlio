/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "core/proto/xlio_time.h"

/* TLS storage for the per-thread cached monotonic microsecond clock.
 * Defined in C++ but exposed through the extern "C" header so lwIP C
 * translation units can read it via the inlined accessor functions.
 */
__thread int64_t g_xlio_tls_now_us = 0;

#ifdef XLIO_TIME_DEBUG_COUNTERS
/* TLS storage for the debug/test clock-read counters (design invariant I2).
 * Present only when NDEBUG is undefined; the shipped .so (release, -DNDEBUG)
 * carries no such symbol - that absence is the compile-out proof.
 */
__thread struct xlio_time_debug_counters_t g_xlio_time_debug_counters = {};
#endif
