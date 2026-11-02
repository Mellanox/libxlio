/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef XLIO_UNIT_TEST_INIT_H
#define XLIO_UNIT_TEST_INIT_H

// Initialize lazily for suites using the core runtime. main() owns cleanup.
int initialize_xlio_unit_tests();

#endif
