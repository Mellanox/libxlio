/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef V_INSTRUMENTATION_H
#define V_INSTRUMENTATION_H

#include <stdint.h>
#include "utils/atomic.h"

#if defined(DEFINED_PROF)
#include <ibprof_api.h>

class ibprof_handle {
public:
    ibprof_handle(int id, const char *name)
    {
        m_id = id;
        ibprof_interval_start(id, name);
    }
    ~ibprof_handle() { ibprof_interval_end(m_id); }
    static atomic_t m_current_id;

private:
    int m_id; // unique id for measurement
};

#define PROFILE_FUNC                                                                               \
    static int ibprof_func_id = atomic_fetch_and_inc(&ibprof_handle::m_current_id);                \
    ibprof_handle prof_value_##__LINE__(ibprof_func_id, __FUNCTION__);
#define PROFILE_BLOCK(name)                                                                        \
    static int ibprof_block_id = atomic_fetch_and_inc(&ibprof_handle::m_current_id);               \
    ibprof_handle prof_value_##__LINE__(ibprof_block_id, name);
#else
#define PROFILE_FUNC
#define PROFILE_BLOCK(name)
#endif /* DEFINED_PROF */

#endif // INSTRUMENTATION
