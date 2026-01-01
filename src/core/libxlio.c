/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

extern int xlio_init(void);
extern int xlio_exit(void);

#ifndef XLIO_STATIC_BUILD
int __attribute__((constructor)) sock_redirect_lib_load_constructor(void)
{
    return xlio_init();
}

int __attribute__((destructor)) sock_redirect_lib_load_destructor(void)
{
    return xlio_exit();
}
#endif /* XLIO_STATIC_BUILD */
