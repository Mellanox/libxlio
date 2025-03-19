/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "config.h"
#include "instrumentation.h"

#if defined(DEFINED_PROF)
atomic_t ibprof_handle::m_current_id = atomic_t {1};
#endif /* DEFINED_PROF */
