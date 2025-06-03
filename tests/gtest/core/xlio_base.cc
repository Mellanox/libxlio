/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "common/cmn.h"

#include "xlio_base.h"

#if defined(EXTRA_API_ENABLED) && (EXTRA_API_ENABLED == 1)
struct xlio_api_t *xlio_base::xlio_api = nullptr;
#endif /* EXTRA_API_ENABLED */

void xlio_base::SetUp()
{
    errno = EOK;

#if defined(EXTRA_API_ENABLED) && (EXTRA_API_ENABLED == 1)
    xlio_api = xlio_get_api();
    SKIP_TRUE(xlio_api, "This test suite should be launched under libxlio.so");
#else
    SKIP_TRUE(0, "Tests should be compiled as make CPPFLAGS=-DEXTRA_API_ENABLED=1")
#endif /* EXTRA_API_ENABLED */
}

void xlio_base::TearDown()
{
}
