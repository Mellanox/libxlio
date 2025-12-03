/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef MAIN_H
#define MAIN_H

#include <util/vtypes.h>
#include <util/sys_vars.h>
#include <util/utils.h>
#include <sock/sock-redirect.h>
#include <infiniband/verbs.h>

void print_xlio_global_settings();
void check_locked_mem();
void set_env_params();
void prepare_fork();

extern "C" void sock_redirect_main(void);
extern "C" void sock_redirect_exit(void);

extern bool g_init_ibv_fork_done;

/* Cached to avoid calling ibv_is_fork_initialized() at runtime, which internally calls close()
 * and can cause reentrancy deadlock when called from within mapping_cache's locked section
 */
extern enum ibv_fork_status g_ibv_fork_status;

#endif // MAIN_H
