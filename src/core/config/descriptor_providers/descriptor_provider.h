/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once
#include "../descriptors/config_descriptor.h"

class descriptor_provider {
public:
  virtual ~descriptor_provider() = default;

  // The interface requires a config_descriptor object to be returned.
  virtual config_descriptor load_descriptors() = 0;
};