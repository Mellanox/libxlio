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
