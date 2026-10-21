/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "core/proto/xlio_time.h"

/* Per-thread cached monotonic timestamp in microseconds. */
__thread int64_t g_xlio_tls_now_us = 0;

#ifdef XLIO_TIME_DEBUG_COUNTERS
/* Debug-build per-thread clock-read counters. */
__thread struct xlio_time_debug_counters_t g_xlio_time_debug_counters = {};
#endif
