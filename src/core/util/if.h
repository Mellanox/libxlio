/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef _IF_H_
#define _IF_H_

#include <sys/socket.h>
#include <linux/if.h>

/* defined in net/if.h but that conflicts with linux/if.h... */
extern "C" unsigned int if_nametoindex(__const char *__ifname) __THROW;
extern "C" char *if_indextoname(unsigned int __ifindex, char *__ifname) __THROW;

#endif
