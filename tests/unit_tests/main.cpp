/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "core/sock/sock-redirect.h"
#include "core/util/sys_vars.h"
#include "core/xlio.h"
#include "xlio_test_init.h"
#include <gtest/gtest.h>

int initialize_xlio_unit_tests()
{
    static bool configured = false;
    if (!configured) {
        // Some static core objects read configuration before main().
        auto &config = mce_sys_var::safe_instance_non_const();
        config.worker_threads = 1;
        config.mem_alloc_type = option_alloc_type::ANON;
        configured = true;
    }
    int result = xlio_init();
    return result == 0 ? do_global_ctors() : result;
}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
    return xlio_exit() == 0 ? result : 1;
}
