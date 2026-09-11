/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef XLIO_CACHE_H_
#define XLIO_CACHE_H_

/* CPU data-cache line size (bytes). 64 on x86_64 and ARMv8 / BlueField-3.
 *
 * Promoted out of src/core/util/utils.h (which is C++-only) into a
 * C-compat header so lwIP C translation units can use it for cache-line
 * layout enforcement via static_assert. Future targets with non-64-byte
 * cache lines become a single edit here, not a hunt for hard-coded
 * literals.
 */
#define CACHELINE_SIZE 64

#endif /* XLIO_CACHE_H_ */
